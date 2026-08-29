use std::{collections::BTreeSet, path::PathBuf};

use ksight_protocol::{
    Ack, AcknowledgeBatches, AgentStatus, Capability, GetStatus, Heartbeat, Hello, HelloAck,
    ListSessions, Message, ProtocolVersion, ReplayBatches, ReplayComplete, SessionInventory,
    CURRENT_PROTOCOL,
};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    retention::SpoolRetention,
    spool::{inspect_root, visit_batches, DirectorySpool, Spool as _},
};

const MAX_CLIENT_NAME_BYTES: usize = 128;
const MAX_CAPABILITIES: usize = 64;
const MAX_CAPABILITY_NAME_BYTES: usize = 128;

/// Stateful protocol command handler used after transport authentication.
#[derive(Debug)]
pub struct ControlSession {
    spool_root: PathBuf,
    agent_version: String,
    capabilities: Vec<Capability>,
    state: ControlState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ControlState {
    AwaitingHello,
    Ready,
}

impl ControlSession {
    /// Create an unauthenticated protocol state machine.
    ///
    /// The caller must not feed messages into this state machine until its transport peer has been
    /// authenticated by the surrounding local-session layer.
    pub fn new(
        spool_root: impl Into<PathBuf>,
        agent_version: impl Into<String>,
        capabilities: Vec<Capability>,
    ) -> Self {
        Self {
            spool_root: spool_root.into(),
            agent_version: agent_version.into(),
            capabilities,
            state: ControlState::AwaitingHello,
        }
    }

    /// Whether protocol negotiation has completed.
    pub fn is_ready(&self) -> bool {
        self.state == ControlState::Ready
    }

    /// Validate and handle one complete client message.
    ///
    /// Operational spool failures are returned as request-correlated negative acknowledgements.
    /// Ordering, negotiation, and semantic-limit violations fail the connection.
    ///
    /// # Errors
    ///
    /// Returns an error when the client violates protocol state or bounded input rules.
    pub fn handle(&mut self, message: Message) -> Result<Vec<Message>, ControlError> {
        match self.state {
            ControlState::AwaitingHello => self.handle_hello(message),
            ControlState::Ready => self.handle_ready(message),
        }
    }

    fn handle_hello(&mut self, message: Message) -> Result<Vec<Message>, ControlError> {
        let Message::Hello(hello) = message else {
            return Err(ControlError::ExpectedHello);
        };
        validate_hello(&hello)?;
        if hello.protocol.major != CURRENT_PROTOCOL.major {
            return Err(ControlError::IncompatibleProtocol {
                client: hello.protocol,
                agent: CURRENT_PROTOCOL,
            });
        }
        let negotiated = ProtocolVersion {
            major: CURRENT_PROTOCOL.major,
            minor: hello.protocol.minor.min(CURRENT_PROTOCOL.minor),
        };
        self.state = ControlState::Ready;
        Ok(vec![Message::HelloAck(HelloAck {
            protocol: negotiated,
            agent_version: self.agent_version.clone(),
            capabilities: self.capabilities.clone(),
        })])
    }

    fn handle_ready(&mut self, message: Message) -> Result<Vec<Message>, ControlError> {
        match message {
            Message::ListSessions(request) => self.list_sessions(&request),
            Message::ReplayBatches(request) => self.replay_batches(&request),
            Message::AcknowledgeBatches(request) => self.acknowledge_batches(&request),
            Message::GetStatus(request) => self.get_status(&request),
            Message::Heartbeat(_) => Ok(vec![self.heartbeat()]),
            Message::StartSession(request) => Ok(vec![rejected(
                request.session_id,
                "start_session is not implemented on the durable serve path; use ksightd run"
                    .to_owned(),
            )]),
            Message::UpdatePolicy(_) => Ok(vec![rejected(
                Uuid::nil(),
                "update_policy is not implemented on this control session".to_owned(),
            )]),
            Message::Hello(_) => Err(ControlError::DuplicateHello),
            other => Err(ControlError::UnsupportedClientMessage(message_name(&other))),
        }
    }

    fn list_sessions(&self, request: &ListSessions) -> Result<Vec<Message>, ControlError> {
        validate_request_id(request.request_id)?;
        Ok(match inspect_root(&self.spool_root) {
            Ok(sessions) => vec![Message::SessionInventory(SessionInventory {
                request_id: request.request_id,
                sessions,
            })],
            Err(error) => vec![rejected(request.request_id, error.to_string())],
        })
    }

    fn replay_batches(&self, request: &ReplayBatches) -> Result<Vec<Message>, ControlError> {
        validate_request_id(request.request_id)?;
        validate_session_id(request.session_id)?;
        let directory = self.spool_root.join(request.session_id.to_string());
        let mut responses = Vec::new();
        let last_batch_sequence = match visit_batches(
            directory,
            request.session_id,
            request.after_batch_sequence,
            |batch| {
                responses.push(Message::EventBatch(batch));
                Ok(())
            },
        ) {
            Ok(last) => last,
            Err(error) => return Ok(vec![rejected(request.request_id, error.to_string())]),
        };
        responses.push(Message::ReplayComplete(ReplayComplete {
            request_id: request.request_id,
            session_id: request.session_id,
            last_batch_sequence,
        }));
        Ok(responses)
    }

    fn get_status(&self, request: &GetStatus) -> Result<Vec<Message>, ControlError> {
        validate_request_id(request.request_id)?;
        Ok(vec![Message::AgentStatus(
            self.agent_status(request.request_id),
        )])
    }

    fn heartbeat(&self) -> Message {
        let status = self.agent_status(Uuid::nil());
        Message::Heartbeat(Heartbeat {
            monotonic_ns: status.heartbeat_monotonic_ns,
            last_batch_sequence: status.last_batch_sequence,
            dropped_records: 0,
            dropped_records_known: false,
        })
    }

    fn agent_status(&self, request_id: Uuid) -> AgentStatus {
        let sessions = inspect_root(&self.spool_root).unwrap_or_default();
        let latest = sessions
            .iter()
            .max_by_key(|summary| (summary.started_unix_ms.unwrap_or(0), summary.session_id));
        let last_batch_sequence = sessions
            .iter()
            .filter_map(|summary| summary.last_batch_sequence)
            .max()
            .unwrap_or(0);
        let spool_used_bytes = sessions.iter().fold(0_u64, |total, summary| {
            total.saturating_add(summary.used_bytes)
        });
        let last_exit = SpoolRetention {
            root: self.spool_root.clone(),
            max_total_bytes: 0,
            keep_completed: 0,
        }
        .read_last_exit()
        .ok()
        .flatten();
        AgentStatus {
            request_id,
            session_id: latest.map(|summary| summary.session_id),
            last_batch_sequence,
            session_count: u64::try_from(sessions.len()).unwrap_or(u64::MAX),
            spool_used_bytes,
            last_exit,
            heartbeat_monotonic_ns: monotonic_ns(),
            latest_session_state: latest.map(|summary| summary.state),
            dropped_records: None,
        }
    }

    fn acknowledge_batches(
        &self,
        request: &AcknowledgeBatches,
    ) -> Result<Vec<Message>, ControlError> {
        validate_request_id(request.request_id)?;
        validate_session_id(request.session_id)?;
        if request.through_batch_sequence == 0 {
            return Err(ControlError::InvalidBatchSequence);
        }
        let directory = self.spool_root.join(request.session_id.to_string());
        let result = DirectorySpool::open_existing(directory, u64::MAX).and_then(|mut spool| {
            spool.acknowledge_through(request.through_batch_sequence)?;
            Ok(spool.used_bytes())
        });
        Ok(vec![match result {
            Ok(remaining_bytes) => Message::Ack(Ack {
                request_id: request.request_id,
                accepted: true,
                detail: Some(format!("remaining_bytes={remaining_bytes}")),
            }),
            Err(error) => rejected(request.request_id, error.to_string()),
        }])
    }
}

fn monotonic_ns() -> u64 {
    nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC)
        .ok()
        .and_then(|time| {
            let seconds = u64::try_from(time.tv_sec()).ok()?;
            let nanos = u64::try_from(time.tv_nsec()).ok()?;
            seconds.checked_mul(1_000_000_000)?.checked_add(nanos)
        })
        .unwrap_or(0)
}

/// Fatal client protocol violation.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ControlError {
    /// The first client message was not a greeting.
    #[error("first client message must be hello")]
    ExpectedHello,
    /// Client and agent major protocol versions are incompatible.
    #[error("client protocol {client:?} is incompatible with agent protocol {agent:?}")]
    IncompatibleProtocol {
        /// Client requested version.
        client: ProtocolVersion,
        /// Agent supported version.
        agent: ProtocolVersion,
    },
    /// Client name is empty, excessive, or contains control characters.
    #[error("client name is invalid")]
    InvalidClientName,
    /// Client sent too many capabilities.
    #[error("client capability count exceeds {MAX_CAPABILITIES}")]
    TooManyCapabilities,
    /// Capability name is empty, excessive, duplicated, or contains control characters.
    #[error("client capability name is invalid or duplicated: {0}")]
    InvalidCapabilityName(String),
    /// A second greeting was sent after negotiation.
    #[error("hello may only be sent once")]
    DuplicateHello,
    /// Message is server-originated or unsupported in the current state.
    #[error("unsupported client message: {0}")]
    UnsupportedClientMessage(&'static str),
    /// Nil request identifiers cannot be correlated safely.
    #[error("request identifier must not be nil")]
    NilRequestId,
    /// Nil capture session identifiers are invalid.
    #[error("capture session identifier must not be nil")]
    NilSessionId,
    /// Batch sequences begin at one.
    #[error("batch acknowledgement sequence must be greater than zero")]
    InvalidBatchSequence,
}

fn validate_hello(hello: &Hello) -> Result<(), ControlError> {
    if hello.client_name.is_empty()
        || hello.client_name.len() > MAX_CLIENT_NAME_BYTES
        || hello.client_name.chars().any(char::is_control)
    {
        return Err(ControlError::InvalidClientName);
    }
    if hello.capabilities.len() > MAX_CAPABILITIES {
        return Err(ControlError::TooManyCapabilities);
    }
    let mut names = BTreeSet::new();
    for capability in &hello.capabilities {
        if capability.name.is_empty()
            || capability.name.len() > MAX_CAPABILITY_NAME_BYTES
            || capability.name.chars().any(char::is_control)
            || !names.insert(capability.name.as_str())
        {
            return Err(ControlError::InvalidCapabilityName(capability.name.clone()));
        }
    }
    Ok(())
}

fn validate_request_id(request_id: Uuid) -> Result<(), ControlError> {
    if request_id.is_nil() {
        return Err(ControlError::NilRequestId);
    }
    Ok(())
}

fn validate_session_id(session_id: Uuid) -> Result<(), ControlError> {
    if session_id.is_nil() {
        return Err(ControlError::NilSessionId);
    }
    Ok(())
}

fn rejected(request_id: Uuid, detail: String) -> Message {
    Message::Ack(Ack {
        request_id,
        accepted: false,
        detail: Some(detail),
    })
}

fn message_name(message: &Message) -> &'static str {
    match message {
        Message::Hello(_) => "hello",
        Message::HelloAck(_) => "hello_ack",
        Message::StartSession(_) => "start_session",
        Message::UpdatePolicy(_) => "update_policy",
        Message::EventBatch(_) => "event_batch",
        Message::AcknowledgeBatches(_) => "acknowledge_batches",
        Message::ListSessions(_) => "list_sessions",
        Message::SessionInventory(_) => "session_inventory",
        Message::ReplayBatches(_) => "replay_batches",
        Message::ReplayComplete(_) => "replay_complete",
        Message::GapReport(_) => "gap_report",
        Message::Ack(_) => "ack",
        Message::Heartbeat(_) => "heartbeat",
        Message::GetStatus(_) => "get_status",
        Message::AgentStatus(_) => "agent_status",
    }
}

#[cfg(test)]
mod tests {
    use ksight_protocol::{EventBatch, CURRENT_PROTOCOL};

    use super::*;

    #[test]
    fn negotiates_minor_version_and_requires_hello_first() {
        let root = test_root();
        let mut session = ControlSession::new(&root, "0.1.0", Vec::new());
        assert_eq!(
            session.handle(Message::ListSessions(ListSessions {
                request_id: Uuid::new_v4()
            })),
            Err(ControlError::ExpectedHello)
        );
        let response = session
            .handle(Message::Hello(Hello {
                protocol: ProtocolVersion {
                    major: CURRENT_PROTOCOL.major,
                    minor: CURRENT_PROTOCOL.minor + 10,
                },
                client_name: "test-client".to_owned(),
                capabilities: Vec::new(),
            }))
            .unwrap();
        let Message::HelloAck(ack) = &response[0] else {
            panic!("expected hello acknowledgement");
        };
        assert_eq!(ack.protocol, CURRENT_PROTOCOL);
        assert!(session.is_ready());
    }

    #[test]
    fn inventory_replay_and_acknowledgement_are_correlated() {
        let root = test_root();
        let capture_id = Uuid::new_v4();
        let directory = root.join(capture_id.to_string());
        let mut spool = DirectorySpool::open(&directory, 1024 * 1024).unwrap();
        spool.append(&empty_batch(capture_id, 1)).unwrap();
        spool.append(&empty_batch(capture_id, 2)).unwrap();

        let mut session = ready_session(&root);
        let list_id = Uuid::new_v4();
        let listed = session
            .handle(Message::ListSessions(ListSessions {
                request_id: list_id,
            }))
            .unwrap();
        let Message::SessionInventory(inventory) = &listed[0] else {
            panic!("expected inventory");
        };
        assert_eq!(inventory.request_id, list_id);
        assert_eq!(inventory.sessions[0].batch_count, 2);

        let replay_id = Uuid::new_v4();
        let replayed = session
            .handle(Message::ReplayBatches(ReplayBatches {
                request_id: replay_id,
                session_id: capture_id,
                after_batch_sequence: Some(1),
            }))
            .unwrap();
        assert!(matches!(
            &replayed[..],
            [Message::EventBatch(batch), Message::ReplayComplete(done)]
                if batch.batch_sequence == 2
                    && done.request_id == replay_id
                    && done.last_batch_sequence == Some(2)
        ));

        let acknowledge_id = Uuid::new_v4();
        let acknowledged = session
            .handle(Message::AcknowledgeBatches(AcknowledgeBatches {
                request_id: acknowledge_id,
                session_id: capture_id,
                through_batch_sequence: 1,
            }))
            .unwrap();
        assert!(matches!(
            &acknowledged[..],
            [Message::Ack(ack)] if ack.request_id == acknowledge_id && ack.accepted
        ));
        let remaining = DirectorySpool::open_existing(&directory, u64::MAX)
            .unwrap()
            .pending()
            .unwrap();
        assert_eq!(remaining, vec![empty_batch(capture_id, 2)]);
        std::fs::remove_dir_all(root).unwrap();
    }

    fn ready_session(root: &std::path::Path) -> ControlSession {
        let mut session = ControlSession::new(root, "0.1.0", Vec::new());
        session
            .handle(Message::Hello(Hello {
                protocol: CURRENT_PROTOCOL,
                client_name: "test-client".to_owned(),
                capabilities: Vec::new(),
            }))
            .unwrap();
        session
    }

    fn empty_batch(session_id: Uuid, batch_sequence: u64) -> EventBatch {
        EventBatch {
            session_id,
            batch_sequence,
            events: Vec::new(),
        }
    }

    fn test_root() -> PathBuf {
        std::env::temp_dir().join(format!("ksight-control-test-{}", Uuid::new_v4()))
    }
}
