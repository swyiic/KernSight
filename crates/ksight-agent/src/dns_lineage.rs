//! Join UDP/53 DNS answers to later `connect()` peers of the same process.

use std::collections::HashMap;

use ksight_model::{EventPayload, SocketConnect};

/// Maps `(tgid, peer_ip)` to the DNS QNAME that answered with that address.
/// `global` is last-writer IP→QNAME so netd lookups can stamp later app connects.
#[derive(Debug, Default)]
pub struct DnsLineageTracker {
    answers: HashMap<(u32, String), String>,
    global: HashMap<String, String>,
}

impl DnsLineageTracker {
    /// Record DNS answers and stamp matching connect events.
    pub fn correlate(&mut self, event: &mut ksight_model::Event) {
        let pid = event.header.process.tgid;
        match &mut event.payload {
            EventPayload::DnsDatagram(datagram) => {
                let Some(qname) = datagram.qname.as_ref() else {
                    return;
                };
                if qname.is_empty() {
                    return;
                }
                for address in &datagram.addresses {
                    if self.answers.len() < 16_384 {
                        self.answers
                            .entry((pid, address.clone()))
                            .or_insert_with(|| qname.clone());
                    }
                    if self.global.len() < 16_384 {
                        self.global.insert(address.clone(), qname.clone());
                    }
                }
            }
            EventPayload::SocketConnect(connect) => {
                stamp_connect(&self.answers, &self.global, pid, connect);
            }
            EventPayload::ProcessLifecycle(lifecycle)
                if lifecycle.kind == ksight_model::ProcessLifecycleKind::Exit
                    && event.header.process.tid == event.header.process.tgid =>
            {
                self.answers.retain(|&(owner, _), _| owner != pid);
            }
            _ => {}
        }
    }
}

fn stamp_connect(
    answers: &HashMap<(u32, String), String>,
    global: &HashMap<String, String>,
    pid: u32,
    connect: &mut SocketConnect,
) {
    let Some(peer) = connect.peer_address.as_ref() else {
        return;
    };
    if let Some(name) = answers.get(&(pid, peer.clone())) {
        connect.resolved_name = Some(name.clone());
        return;
    }
    if let Some(name) = global.get(peer) {
        connect.resolved_name = Some(name.clone());
    }
}

#[cfg(test)]
mod tests {
    use ksight_model::{
        CaptureMode, Confidence, DataQuality, DnsDatagram, Event, EventHeader, EventPayload,
        ProcessIdentity, ProcessKey, SensorKind, SocketConnect,
    };
    use uuid::Uuid;

    use super::*;

    fn header(pid: u32) -> EventHeader {
        EventHeader {
            schema: ksight_model::CURRENT_SCHEMA,
            session_id: Uuid::nil(),
            source_sequence: 1,
            monotonic_ns: 1,
            cpu: Some(0),
            process: ProcessIdentity {
                key: ProcessKey {
                    boot_id: Uuid::nil(),
                    pid,
                    start_time_ns: 1,
                },
                tid: pid,
                tgid: pid,
                uid: 1,
                gid: 1,
                comm: "app".to_owned(),
                command_line: None,
                selinux_context: None,
                packages: Vec::new(),
            },
            sensor: SensorKind::Network,
            mode: CaptureMode::Observe,
            quality: DataQuality {
                confidence: Confidence::Partial,
                truncated: false,
                lost_before: 0,
                sample_one_in: 1,
                source: "test".to_owned(),
            },
        }
    }

    #[test]
    fn dns_answer_stamps_later_connect() {
        let mut tracker = DnsLineageTracker::default();
        let mut dns = Event {
            header: header(9),
            payload: EventPayload::DnsDatagram(DnsDatagram {
                file_descriptor: 4,
                result: 32,
                address_family: 2,
                peer_port: 53,
                peer_address: Some("8.8.8.8".to_owned()),
                direction: "response".to_owned(),
                truncated: false,
                qname: Some("example.com".to_owned()),
                addresses: vec!["1.2.3.4".to_owned()],
            }),
        };
        tracker.correlate(&mut dns);
        let mut connect = Event {
            header: header(9),
            payload: EventPayload::SocketConnect(SocketConnect {
                file_descriptor: 5,
                result: 0,
                address_family: 2,
                submitted_address_length: 16,
                captured_address_length: 16,
                peer_address: Some("1.2.3.4".to_owned()),
                peer_port: Some(443),
                scope_id: None,
                resolved_name: None,
            }),
        };
        tracker.correlate(&mut connect);
        let EventPayload::SocketConnect(connect) = connect.payload else {
            panic!("connect");
        };
        assert_eq!(connect.resolved_name.as_deref(), Some("example.com"));
    }

    #[test]
    fn netd_answer_stamps_other_process_connect() {
        let mut tracker = DnsLineageTracker::default();
        let mut dns = Event {
            header: header(1),
            payload: EventPayload::DnsDatagram(DnsDatagram {
                file_descriptor: 4,
                result: 32,
                address_family: 2,
                peer_port: 53,
                peer_address: Some("8.8.8.8".to_owned()),
                direction: "response".to_owned(),
                truncated: false,
                qname: Some("example.com".to_owned()),
                addresses: vec!["1.2.3.4".to_owned()],
            }),
        };
        tracker.correlate(&mut dns);
        let mut connect = Event {
            header: header(9),
            payload: EventPayload::SocketConnect(SocketConnect {
                file_descriptor: 5,
                result: 0,
                address_family: 2,
                submitted_address_length: 16,
                captured_address_length: 16,
                peer_address: Some("1.2.3.4".to_owned()),
                peer_port: Some(443),
                scope_id: None,
                resolved_name: None,
            }),
        };
        tracker.correlate(&mut connect);
        let EventPayload::SocketConnect(connect) = connect.payload else {
            panic!("connect");
        };
        assert_eq!(connect.resolved_name.as_deref(), Some("example.com"));
    }
}
