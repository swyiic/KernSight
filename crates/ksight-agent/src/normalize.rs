use std::fmt::Write as _;

use ksight_abi::{
    RawEventHeader, RawEventType, RawSensorId, EVENT_FLAG_IDENTITY_PARTIAL, EVENT_FLAG_TRUNCATED,
    FILE_PATH_LEN, HANDSHAKE_PAYLOAD_LEN, PROCESS_FILENAME_LEN, RAW_BINDER_EVENT_SIZE,
    RAW_BINDER_FD_EVENT_SIZE, RAW_BINDER_PARCEL_EVENT_SIZE, RAW_DNS_EVENT_SIZE, RAW_FD_EVENT_SIZE,
    RAW_FILE_EVENT_SIZE, RAW_HANDSHAKE_EVENT_SIZE, RAW_MEMORY_EVENT_SIZE, RAW_NETWORK_EVENT_SIZE,
    RAW_NETWORK_IO_EVENT_SIZE, RAW_PROCESS_EVENT_SIZE, RAW_SCHED_EVENT_SIZE, SOCKET_ADDRESS_LEN,
};
use ksight_model::{
    BinderCodeKind, BinderTargetKind, BinderTransaction, BinderTransactionDirection,
    BinderTransactionFlag, BinderTransactionStage, CaptureMode, Confidence, DataQuality,
    DnsDatagram, Event, EventHeader, EventPayload, FileDescriptorChange, FileDescriptorOperation,
    FileOpen, MemoryOperation, MemoryRegionChange, NetworkHandshake, ProcessIdentity,
    ProcessIdentityChange, ProcessIdentityChangeKind, ProcessKey, ProcessLifecycle,
    ProcessLifecycleKind, SchedWakeup, SensorKind, SocketAccept, SocketConnect, SocketIo,
    SocketIoOperation, CURRENT_SCHEMA,
};
use thiserror::Error;
use uuid::Uuid;

use crate::collector::RawRecord;

/// Converts a versioned raw ABI record into a normalized semantic event.
pub trait Normalizer {
    /// Normalization error.
    type Error;

    /// Decode, validate, and enrich one record.
    ///
    /// # Errors
    ///
    /// Returns an implementation-specific error for an invalid or unsupported raw record.
    fn normalize(&mut self, record: RawRecord) -> Result<Event, Self::Error>;
}

/// Validates and normalizes M1 process lifecycle records.
#[derive(Debug, Clone)]
pub struct EventNormalizer {
    boot_id: Uuid,
    session_id: Uuid,
    quic_initials: ksight_core::QuicInitialTable,
}

impl EventNormalizer {
    /// Create an event normalizer for a known boot and capture session.
    #[must_use]
    pub fn new(boot_id: Uuid, session_id: Uuid) -> Self {
        Self {
            boot_id,
            session_id,
            quic_initials: ksight_core::QuicInitialTable::default_table(),
        }
    }

    /// Read the device boot identity and create a new capture session.
    ///
    /// # Errors
    ///
    /// Returns an error if the kernel boot ID cannot be read or parsed.
    pub fn from_system() -> Result<Self, NormalizeError> {
        let value = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
        let boot_id = Uuid::parse_str(value.trim())?;
        Ok(Self::new(boot_id, Uuid::new_v4()))
    }

    /// Capture session assigned to every normalized event.
    #[must_use]
    pub fn session_id(&self) -> Uuid {
        self.session_id
    }

    /// Boot identity assigned to every normalized event.
    #[must_use]
    pub fn boot_id(&self) -> Uuid {
        self.boot_id
    }

    /// Start a new capture session while keeping the same boot identity.
    pub fn rotate_session(&mut self) -> Uuid {
        self.session_id = Uuid::new_v4();
        self.session_id
    }

    /// True when `/proc` reports a different kernel boot identity.
    ///
    /// # Errors
    ///
    /// Returns an error if the boot ID cannot be read or parsed.
    pub fn boot_id_changed(&self) -> Result<bool, NormalizeError> {
        let value = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
        let boot_id = Uuid::parse_str(value.trim())?;
        Ok(boot_id != self.boot_id)
    }
}

/// Process lifecycle normalization failure.
#[derive(Debug, Error)]
pub enum NormalizeError {
    /// Raw ABI validation failed.
    #[error(transparent)]
    Abi(#[from] ksight_abi::DecodeError),
    /// Reading a local identity source failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// A UUID identity source was malformed.
    #[error(transparent)]
    Uuid(#[from] uuid::Error),
    /// The record is not a fixed M1 process lifecycle record.
    #[error("invalid process record size {0}")]
    InvalidProcessRecordSize(usize),
    /// The record is not a fixed M2 file event record.
    #[error("invalid file record size {0}")]
    InvalidFileRecordSize(usize),
    /// The record is not a fixed M2 network event record.
    #[error("invalid network record size {0}")]
    InvalidNetworkRecordSize(usize),
    /// The record is not a fixed M2 memory event record.
    #[error("invalid memory record size {0}")]
    InvalidMemoryRecordSize(usize),
    /// The record is not a fixed M2 Binder event record.
    #[error("invalid Binder record size {0}")]
    InvalidBinderRecordSize(usize),
    /// The record is not a fixed scheduler event record.
    #[error("invalid scheduler record size {0}")]
    InvalidSchedRecordSize(usize),
    /// The event belongs to another sensor.
    #[error("unexpected sensor {0}")]
    UnexpectedSensor(u16),
    /// The process event type is unknown.
    #[error("unexpected process event type {0:#06x}")]
    UnexpectedEventType(u16),
    /// The executable filename length exceeds its fixed ABI capacity.
    #[error("invalid process filename length {0}")]
    InvalidFilenameLength(usize),
    /// The file path length exceeds its fixed ABI capacity.
    #[error("invalid file path length {0}")]
    InvalidPathLength(usize),
    /// The submitted socket-address length exceeds its fixed ABI capacity.
    #[error("invalid socket address length {0}")]
    InvalidSocketAddressLength(usize),
}

impl Normalizer for EventNormalizer {
    type Error = NormalizeError;

    fn normalize(&mut self, record: RawRecord) -> Result<Event, Self::Error> {
        let raw = RawEventHeader::decode(&record.bytes)?;
        if raw.sensor_id == RawSensorId::File as u16 {
            return self.normalize_file(&record.bytes, &raw);
        }
        if raw.sensor_id == RawSensorId::Network as u16 {
            return self.normalize_network(&record.bytes, &raw);
        }
        if raw.sensor_id == RawSensorId::Memory as u16 {
            return self.normalize_memory(&record.bytes, &raw);
        }
        if raw.sensor_id == RawSensorId::Binder as u16 {
            if raw.event_type == RawEventType::BinderParcel as u16 {
                return self.normalize_binder_parcel(&record.bytes, &raw);
            }
            return self.normalize_binder(&record.bytes, &raw);
        }
        if raw.sensor_id == RawSensorId::Sched as u16 {
            return self.normalize_sched(&record.bytes, &raw);
        }
        self.normalize_process(&record.bytes, &raw)
    }
}

impl EventNormalizer {
    fn normalize_process(
        &self,
        bytes: &[u8],
        raw: &RawEventHeader,
    ) -> Result<Event, NormalizeError> {
        if bytes.len() != RAW_PROCESS_EVENT_SIZE {
            return Err(NormalizeError::InvalidProcessRecordSize(bytes.len()));
        }
        if raw.sensor_id != RawSensorId::Process as u16 {
            return Err(NormalizeError::UnexpectedSensor(raw.sensor_id));
        }

        let detail_length = usize::try_from(read_u32(bytes, 100))
            .map_err(|_| NormalizeError::InvalidFilenameLength(usize::MAX))?;
        if detail_length > PROCESS_FILENAME_LEN {
            return Err(NormalizeError::InvalidFilenameLength(detail_length));
        }
        let detail = || String::from_utf8_lossy(&bytes[104..104 + detail_length]).into_owned();

        let (payload, source) = match raw.event_type {
            value if value == RawEventType::ProcessFork as u16 => (
                EventPayload::ProcessLifecycle(ProcessLifecycle {
                    kind: ProcessLifecycleKind::Fork,
                    parent_pid: Some(raw.ppid),
                    filename: None,
                    exit_code: None,
                    zygote_source: None,
                }),
                "sched/sched_process_fork",
            ),
            value if value == RawEventType::ProcessExec as u16 => (
                EventPayload::ProcessLifecycle(ProcessLifecycle {
                    kind: ProcessLifecycleKind::Exec,
                    parent_pid: None,
                    filename: Some(detail()),
                    exit_code: None,
                    zygote_source: None,
                }),
                "sched/sched_process_exec",
            ),
            value if value == RawEventType::ProcessExit as u16 => (
                EventPayload::ProcessLifecycle(ProcessLifecycle {
                    kind: ProcessLifecycleKind::Exit,
                    parent_pid: None,
                    filename: None,
                    exit_code: None,
                    zygote_source: None,
                }),
                "sched/sched_process_exit",
            ),
            value if value == RawEventType::ProcessCredentials as u16 => (
                EventPayload::ProcessIdentityChange(ProcessIdentityChange {
                    kind: ProcessIdentityChangeKind::Credentials,
                    previous_comm: None,
                }),
                "raw_syscalls/sys_exit",
            ),
            value if value == RawEventType::ProcessRename as u16 => (
                EventPayload::ProcessIdentityChange(ProcessIdentityChange {
                    kind: ProcessIdentityChangeKind::Rename,
                    previous_comm: Some(detail()),
                }),
                "task/task_rename",
            ),
            value => return Err(NormalizeError::UnexpectedEventType(value)),
        };
        let partial = raw.flags & EVENT_FLAG_IDENTITY_PARTIAL != 0 || raw.process_start_time == 0;

        Ok(Event {
            header: EventHeader {
                schema: CURRENT_SCHEMA,
                session_id: self.session_id,
                source_sequence: raw.source_sequence,
                monotonic_ns: raw.monotonic_ns,
                cpu: Some(raw.cpu),
                process: ProcessIdentity {
                    key: ProcessKey {
                        boot_id: self.boot_id,
                        pid: raw.pid,
                        start_time_ns: raw.process_start_time,
                    },
                    tid: raw.tid,
                    tgid: raw.tgid,
                    uid: raw.uid,
                    gid: raw.gid,
                    comm: nul_terminated(&raw.comm),
                    command_line: None,
                    selinux_context: None,
                    packages: Vec::new(),
                },
                sensor: SensorKind::Process,
                mode: CaptureMode::Observe,
                quality: DataQuality {
                    confidence: if partial {
                        Confidence::Partial
                    } else {
                        Confidence::Confirmed
                    },
                    truncated: raw.flags & EVENT_FLAG_TRUNCATED != 0,
                    lost_before: 0,
                    sample_one_in: 1,
                    source: source.to_owned(),
                },
            },
            payload,
        })
    }
    fn normalize_file(&self, bytes: &[u8], raw: &RawEventHeader) -> Result<Event, NormalizeError> {
        if raw.event_type == RawEventType::FileDescriptorClose as u16
            || raw.event_type == RawEventType::FileDescriptorDuplicate as u16
            || raw.event_type == RawEventType::FileDescriptorCloseRange as u16
            || raw.event_type == RawEventType::FileDescriptorRightsSend as u16
            || raw.event_type == RawEventType::FileDescriptorRightsReceive as u16
        {
            return self.normalize_fd(bytes, raw);
        }
        if raw.event_type != RawEventType::FileOpen as u16 {
            return Err(NormalizeError::UnexpectedEventType(raw.event_type));
        }
        if bytes.len() != RAW_FILE_EVENT_SIZE {
            return Err(NormalizeError::InvalidFileRecordSize(bytes.len()));
        }
        let path_length = usize::try_from(read_u32(bytes, 116))
            .map_err(|_| NormalizeError::InvalidPathLength(usize::MAX))?;
        if path_length > FILE_PATH_LEN {
            return Err(NormalizeError::InvalidPathLength(path_length));
        }

        Ok(Event {
            header: EventHeader {
                schema: CURRENT_SCHEMA,
                session_id: self.session_id,
                source_sequence: raw.source_sequence,
                monotonic_ns: raw.monotonic_ns,
                cpu: Some(raw.cpu),
                process: ProcessIdentity {
                    key: ProcessKey {
                        boot_id: self.boot_id,
                        pid: raw.pid,
                        start_time_ns: raw.process_start_time,
                    },
                    tid: raw.tid,
                    tgid: raw.tgid,
                    uid: raw.uid,
                    gid: raw.gid,
                    comm: nul_terminated(&raw.comm),
                    command_line: None,
                    selinux_context: None,
                    packages: Vec::new(),
                },
                sensor: SensorKind::File,
                mode: CaptureMode::Observe,
                quality: DataQuality {
                    confidence: Confidence::Partial,
                    truncated: raw.flags & EVENT_FLAG_TRUNCATED != 0,
                    lost_before: 0,
                    sample_one_in: 1,
                    source: "raw_syscalls/openat_exit".to_owned(),
                },
            },
            payload: EventPayload::FileOpen(FileOpen {
                directory_fd: read_i32(bytes, 96),
                file_descriptor: (read_i32(bytes, 100) >= 0).then(|| read_i32(bytes, 100)),
                result: read_i32(bytes, 104),
                flags: read_u32(bytes, 108),
                mode: read_u32(bytes, 112),
                path: String::from_utf8_lossy(&bytes[120..120 + path_length]).into_owned(),
                resolved_path: None,
                content_sha256: None,
                content_bytes: None,
            }),
        })
    }

    fn normalize_fd(&self, bytes: &[u8], raw: &RawEventHeader) -> Result<Event, NormalizeError> {
        if bytes.len() != RAW_FD_EVENT_SIZE {
            return Err(NormalizeError::InvalidFileRecordSize(bytes.len()));
        }
        let operation = match raw.event_type {
            value if value == RawEventType::FileDescriptorClose as u16 => {
                FileDescriptorOperation::Close
            }
            value if value == RawEventType::FileDescriptorDuplicate as u16 => {
                FileDescriptorOperation::Duplicate
            }
            value if value == RawEventType::FileDescriptorCloseRange as u16 => {
                FileDescriptorOperation::CloseRange
            }
            value if value == RawEventType::FileDescriptorRightsSend as u16 => {
                FileDescriptorOperation::RightsSend
            }
            value if value == RawEventType::FileDescriptorRightsReceive as u16 => {
                FileDescriptorOperation::RightsReceive
            }
            value => return Err(NormalizeError::UnexpectedEventType(value)),
        };
        let requested_fd = read_i32(bytes, 100);
        let result = read_i32(bytes, 104);
        let last_fd = read_u32(bytes, 116);
        Ok(Event {
            header: EventHeader {
                schema: CURRENT_SCHEMA,
                session_id: self.session_id,
                source_sequence: raw.source_sequence,
                monotonic_ns: raw.monotonic_ns,
                cpu: Some(raw.cpu),
                process: ProcessIdentity {
                    key: ProcessKey {
                        boot_id: self.boot_id,
                        pid: raw.pid,
                        start_time_ns: raw.process_start_time,
                    },
                    tid: raw.tid,
                    tgid: raw.tgid,
                    uid: raw.uid,
                    gid: raw.gid,
                    comm: nul_terminated(&raw.comm),
                    command_line: None,
                    selinux_context: None,
                    packages: Vec::new(),
                },
                sensor: SensorKind::File,
                mode: CaptureMode::Observe,
                quality: DataQuality {
                    confidence: Confidence::Confirmed,
                    truncated: false,
                    lost_before: 0,
                    sample_one_in: 1,
                    source: "raw_syscalls/fd_lifecycle_exit".to_owned(),
                },
            },
            payload: EventPayload::FileDescriptorChange(FileDescriptorChange {
                operation,
                file_descriptor: read_i32(bytes, 96),
                requested_file_descriptor: (requested_fd >= 0).then_some(requested_fd),
                resulting_file_descriptor: (operation == FileDescriptorOperation::Duplicate
                    && result >= 0)
                    .then_some(result),
                result,
                command: read_u32(bytes, 108),
                flags: read_u32(bytes, 112),
                last_file_descriptor: (operation == FileDescriptorOperation::CloseRange)
                    .then_some(last_fd),
            }),
        })
    }

    fn normalize_network(
        &mut self,
        bytes: &[u8],
        raw: &RawEventHeader,
    ) -> Result<Event, NormalizeError> {
        if raw.event_type == RawEventType::NetworkDns as u16 {
            return self.normalize_dns(bytes, raw);
        }
        if raw.event_type == RawEventType::NetworkHandshake as u16 {
            return self.normalize_handshake(bytes, raw);
        }
        if raw.event_type == RawEventType::NetworkSend as u16
            || raw.event_type == RawEventType::NetworkReceive as u16
        {
            return self.normalize_network_io(bytes, raw);
        }
        if bytes.len() != RAW_NETWORK_EVENT_SIZE {
            return Err(NormalizeError::InvalidNetworkRecordSize(bytes.len()));
        }
        if raw.event_type != RawEventType::NetworkConnect as u16
            && raw.event_type != RawEventType::NetworkAccept as u16
        {
            return Err(NormalizeError::UnexpectedEventType(raw.event_type));
        }
        let address_length = usize::try_from(read_u32(bytes, 104))
            .map_err(|_| NormalizeError::InvalidSocketAddressLength(usize::MAX))?;
        if address_length > SOCKET_ADDRESS_LEN {
            return Err(NormalizeError::InvalidSocketAddressLength(address_length));
        }
        let address_family = read_u16(bytes, 108);
        let address = &bytes[112..112 + address_length];
        let (peer_address, peer_port, scope_id) = decode_peer(address_family, address);

        let source = if raw.event_type == RawEventType::NetworkAccept as u16 {
            "raw_syscalls/accept_exit"
        } else {
            "raw_syscalls/connect_exit"
        };
        let payload = if raw.event_type == RawEventType::NetworkAccept as u16 {
            let result = read_i32(bytes, 100);
            EventPayload::SocketAccept(SocketAccept {
                listening_file_descriptor: read_i32(bytes, 96),
                accepted_file_descriptor: (result >= 0).then_some(result),
                result,
                address_family,
                returned_address_length: read_u16(bytes, 110),
                captured_address_length: u16::try_from(address_length).unwrap_or(u16::MAX),
                peer_address,
                peer_port,
                scope_id,
            })
        } else {
            EventPayload::SocketConnect(SocketConnect {
                file_descriptor: read_i32(bytes, 96),
                result: read_i32(bytes, 100),
                address_family,
                submitted_address_length: read_u16(bytes, 110),
                captured_address_length: u16::try_from(address_length).unwrap_or(u16::MAX),
                peer_address,
                peer_port,
                scope_id,
                resolved_name: None,
            })
        };

        Ok(Event {
            header: EventHeader {
                schema: CURRENT_SCHEMA,
                session_id: self.session_id,
                source_sequence: raw.source_sequence,
                monotonic_ns: raw.monotonic_ns,
                cpu: Some(raw.cpu),
                process: ProcessIdentity {
                    key: ProcessKey {
                        boot_id: self.boot_id,
                        pid: raw.pid,
                        start_time_ns: raw.process_start_time,
                    },
                    tid: raw.tid,
                    tgid: raw.tgid,
                    uid: raw.uid,
                    gid: raw.gid,
                    comm: nul_terminated(&raw.comm),
                    command_line: None,
                    selinux_context: None,
                    packages: Vec::new(),
                },
                sensor: SensorKind::Network,
                mode: CaptureMode::Observe,
                quality: DataQuality {
                    confidence: Confidence::Partial,
                    truncated: raw.flags & EVENT_FLAG_TRUNCATED != 0,
                    lost_before: 0,
                    sample_one_in: 1,
                    source: source.to_owned(),
                },
            },
            payload,
        })
    }

    fn normalize_dns(&self, bytes: &[u8], raw: &RawEventHeader) -> Result<Event, NormalizeError> {
        if bytes.len() != RAW_DNS_EVENT_SIZE {
            return Err(NormalizeError::InvalidNetworkRecordSize(bytes.len()));
        }
        let captured = usize::from(read_u16(bytes, 108)).min(512);
        let payload_start = 128_usize;
        let payload_end = payload_start.saturating_add(captured);
        let payload = bytes
            .get(payload_start..payload_end)
            .unwrap_or(&[])
            .to_vec();
        let parsed = ksight_core::parse_dns_message(&payload);
        let family = read_u16(bytes, 104);
        let address = &bytes[112..128];
        let peer_address = match family {
            2 => Some(format!(
                "{}.{}.{}.{}",
                address[0], address[1], address[2], address[3]
            )),
            10 => {
                let mut octets = [0_u8; 16];
                octets.copy_from_slice(&address[..16]);
                Some(std::net::Ipv6Addr::from(octets).to_string())
            }
            _ => None,
        };
        Ok(Event {
            header: EventHeader {
                schema: CURRENT_SCHEMA,
                session_id: self.session_id,
                source_sequence: raw.source_sequence,
                monotonic_ns: raw.monotonic_ns,
                cpu: Some(raw.cpu),
                process: ProcessIdentity {
                    key: ProcessKey {
                        boot_id: self.boot_id,
                        pid: raw.pid,
                        start_time_ns: raw.process_start_time,
                    },
                    tid: raw.tid,
                    tgid: raw.tgid,
                    uid: raw.uid,
                    gid: raw.gid,
                    comm: nul_terminated(&raw.comm),
                    command_line: None,
                    selinux_context: None,
                    packages: Vec::new(),
                },
                sensor: SensorKind::Network,
                mode: CaptureMode::Observe,
                quality: DataQuality {
                    confidence: Confidence::Partial,
                    truncated: raw.flags & EVENT_FLAG_TRUNCATED != 0 || bytes[111] != 0,
                    lost_before: 0,
                    sample_one_in: 1,
                    source: "raw_syscalls/dns_datagram".to_owned(),
                },
            },
            payload: EventPayload::DnsDatagram(DnsDatagram {
                file_descriptor: read_i32(bytes, 96),
                result: read_i32(bytes, 100),
                address_family: family,
                peer_port: read_u16(bytes, 106),
                peer_address,
                direction: if bytes[110] == 0 {
                    "query".to_owned()
                } else {
                    "response".to_owned()
                },
                truncated: bytes[111] != 0,
                qname: parsed.as_ref().map(|record| record.qname.clone()),
                addresses: parsed.map(|record| record.addresses).unwrap_or_default(),
            }),
        })
    }

    /// Combine parsed first-write metadata with RFC 9001 `Initial` decryption.
    ///
    /// QUIC client hellos split across datagrams are reassembled in
    /// `quic_initials`; the recovered SNI/ALPN fill the same fields a TLS
    /// `ClientHello` would, plus the destination connection ID.
    fn recover_handshake_names(
        &mut self,
        bpf_kind: u8,
        payload: &[u8],
        parsed: Option<&ksight_core::HandshakeMeta>,
    ) -> (Option<String>, Option<String>, Option<String>) {
        let mut sni = parsed.and_then(|meta| meta.sni.clone());
        let mut alpn = parsed.and_then(|meta| meta.alpn.clone());
        let mut quic_dcid = None;
        if bpf_kind == 3 && payload.len() >= 64 {
            // User-space Initial decryption: no hook, no process change.
            if let Some(hello) = self.quic_initials.feed(payload) {
                sni = hello.sni;
                alpn = hello.alpn;
                quic_dcid = Some(hello.dcid_hex);
            }
        }
        (sni, alpn, quic_dcid)
    }

    fn normalize_handshake(
        &mut self,
        bytes: &[u8],
        raw: &RawEventHeader,
    ) -> Result<Event, NormalizeError> {
        if bytes.len() != RAW_HANDSHAKE_EVENT_SIZE {
            return Err(NormalizeError::InvalidNetworkRecordSize(bytes.len()));
        }
        let captured = usize::from(read_u16(bytes, 108)).min(HANDSHAKE_PAYLOAD_LEN);
        let payload_start = 128_usize;
        let payload_end = payload_start.saturating_add(captured);
        let payload = bytes
            .get(payload_start..payload_end)
            .unwrap_or(&[])
            .to_vec();
        let parsed = ksight_core::parse_handshake(&payload);
        let (sni, alpn, quic_dcid) =
            self.recover_handshake_names(bytes[110], &payload, parsed.as_ref());
        let family = read_u16(bytes, 104);
        let address = &bytes[112..128];
        let peer_address = match family {
            2 => Some(format!(
                "{}.{}.{}.{}",
                address[0], address[1], address[2], address[3]
            )),
            10 => {
                let mut octets = [0_u8; 16];
                octets.copy_from_slice(&address[..16]);
                Some(std::net::Ipv6Addr::from(octets).to_string())
            }
            _ => None,
        };
        let bpf_kind = match bytes[110] {
            1 => "tls",
            2 => "http",
            3 => "quic",
            _ => "unknown",
        };
        Ok(Event {
            header: EventHeader {
                schema: CURRENT_SCHEMA,
                session_id: self.session_id,
                source_sequence: raw.source_sequence,
                monotonic_ns: raw.monotonic_ns,
                cpu: Some(raw.cpu),
                process: ProcessIdentity {
                    key: ProcessKey {
                        boot_id: self.boot_id,
                        pid: raw.pid,
                        start_time_ns: raw.process_start_time,
                    },
                    tid: raw.tid,
                    tgid: raw.tgid,
                    uid: raw.uid,
                    gid: raw.gid,
                    comm: nul_terminated(&raw.comm),
                    command_line: None,
                    selinux_context: None,
                    packages: Vec::new(),
                },
                sensor: SensorKind::Network,
                mode: CaptureMode::Observe,
                quality: DataQuality {
                    confidence: Confidence::Partial,
                    truncated: raw.flags & EVENT_FLAG_TRUNCATED != 0 || bytes[111] != 0,
                    lost_before: 0,
                    sample_one_in: 1,
                    source: "raw_syscalls/handshake_first_write".to_owned(),
                },
            },
            payload: EventPayload::NetworkHandshake(NetworkHandshake {
                file_descriptor: read_i32(bytes, 96),
                result: read_i32(bytes, 100),
                address_family: family,
                peer_port: read_u16(bytes, 106),
                peer_address,
                truncated: bytes[111] != 0,
                kind: parsed
                    .as_ref()
                    .map_or_else(|| bpf_kind.to_owned(), |meta| meta.kind.to_owned()),
                sni,
                alpn,
                ech: parsed.as_ref().is_some_and(|meta| meta.ech),
                http_method: parsed.as_ref().and_then(|meta| meta.http_method.clone()),
                http_path: parsed.as_ref().and_then(|meta| meta.http_path.clone()),
                http_host: parsed.as_ref().and_then(|meta| meta.http_host.clone()),
                request_prefix: parsed
                    .as_ref()
                    .filter(|meta| meta.kind == "http")
                    .and_then(|_| {
                        let text = String::from_utf8_lossy(&payload);
                        (!text.is_empty()).then(|| text.into_owned())
                    }),
                quic_version: parsed.as_ref().and_then(|meta| meta.quic_version.clone()),
                quic_packet: parsed.as_ref().and_then(|meta| meta.quic_packet.clone()),
                quic_dcid,
            }),
        })
    }

    fn normalize_network_io(
        &self,
        bytes: &[u8],
        raw: &RawEventHeader,
    ) -> Result<Event, NormalizeError> {
        if bytes.len() != RAW_NETWORK_IO_EVENT_SIZE {
            return Err(NormalizeError::InvalidNetworkRecordSize(bytes.len()));
        }
        let operation = if raw.event_type == RawEventType::NetworkSend as u16 {
            SocketIoOperation::Send
        } else if raw.event_type == RawEventType::NetworkReceive as u16 {
            SocketIoOperation::Receive
        } else {
            return Err(NormalizeError::UnexpectedEventType(raw.event_type));
        };
        let syscall = read_u32(bytes, 100);
        // sendto/recvfrom/read/write 直接给出请求字节数；sendmsg 系列与
        // sendmmsg/recvmmsg 批量调用不提供单次字节数。
        let requested_bytes = matches!(syscall, 206 | 207 | 63 | 64).then(|| read_u64(bytes, 112));
        let source = match operation {
            SocketIoOperation::Send => "raw_syscalls/socket_send_exit",
            SocketIoOperation::Receive => "raw_syscalls/socket_receive_exit",
        };

        Ok(Event {
            header: EventHeader {
                schema: CURRENT_SCHEMA,
                session_id: self.session_id,
                source_sequence: raw.source_sequence,
                monotonic_ns: raw.monotonic_ns,
                cpu: Some(raw.cpu),
                process: ProcessIdentity {
                    key: ProcessKey {
                        boot_id: self.boot_id,
                        pid: raw.pid,
                        start_time_ns: raw.process_start_time,
                    },
                    tid: raw.tid,
                    tgid: raw.tgid,
                    uid: raw.uid,
                    gid: raw.gid,
                    comm: nul_terminated(&raw.comm),
                    command_line: None,
                    selinux_context: None,
                    packages: Vec::new(),
                },
                sensor: SensorKind::Network,
                mode: CaptureMode::Observe,
                quality: DataQuality {
                    confidence: Confidence::Confirmed,
                    truncated: false,
                    lost_before: 0,
                    sample_one_in: 1,
                    source: source.to_owned(),
                },
            },
            payload: EventPayload::SocketIo(SocketIo {
                file_descriptor: read_i32(bytes, 96),
                operation,
                result: read_i64(bytes, 104),
                requested_bytes,
                syscall,
            }),
        })
    }

    fn normalize_memory(
        &self,
        bytes: &[u8],
        raw: &RawEventHeader,
    ) -> Result<Event, NormalizeError> {
        if bytes.len() != RAW_MEMORY_EVENT_SIZE {
            return Err(NormalizeError::InvalidMemoryRecordSize(bytes.len()));
        }
        let operation = match raw.event_type {
            value if value == RawEventType::MemoryMap as u16 => MemoryOperation::Map,
            value if value == RawEventType::MemoryProtect as u16 => MemoryOperation::Protect,
            value if value == RawEventType::MemoryUnmap as u16 => MemoryOperation::Unmap,
            value if value == RawEventType::MemoryRemap as u16 => MemoryOperation::Remap,
            value if value == RawEventType::MemoryBrk as u16 => MemoryOperation::Brk,
            value => return Err(NormalizeError::UnexpectedEventType(value)),
        };
        let mapping = operation == MemoryOperation::Map || operation == MemoryOperation::Remap;
        let fd = read_i32(bytes, 128);

        Ok(Event {
            header: EventHeader {
                schema: CURRENT_SCHEMA,
                session_id: self.session_id,
                source_sequence: raw.source_sequence,
                monotonic_ns: raw.monotonic_ns,
                cpu: Some(raw.cpu),
                process: ProcessIdentity {
                    key: ProcessKey {
                        boot_id: self.boot_id,
                        pid: raw.pid,
                        start_time_ns: raw.process_start_time,
                    },
                    tid: raw.tid,
                    tgid: raw.tgid,
                    uid: raw.uid,
                    gid: raw.gid,
                    comm: nul_terminated(&raw.comm),
                    command_line: None,
                    selinux_context: None,
                    packages: Vec::new(),
                },
                sensor: SensorKind::Memory,
                mode: CaptureMode::Observe,
                quality: DataQuality {
                    confidence: Confidence::Partial,
                    truncated: false,
                    lost_before: 0,
                    sample_one_in: 1,
                    source: "raw_syscalls/memory_exit".to_owned(),
                },
            },
            payload: EventPayload::MemoryRegionChange(MemoryRegionChange {
                operation,
                address: read_u64(bytes, 96),
                length: read_u64(bytes, 104),
                result: read_i64(bytes, 112),
                protection: read_u32(bytes, 132),
                mapping_flags: mapping.then(|| read_u32(bytes, 136)),
                file_descriptor: (mapping && fd >= 0).then_some(fd),
                backing_path: None,
                offset: mapping.then(|| read_u64(bytes, 120)),
            }),
        })
    }

    #[allow(clippy::too_many_lines)] // The fixed Binder ABI stages share one validated decoder.
    fn normalize_binder(
        &self,
        bytes: &[u8],
        raw: &RawEventHeader,
    ) -> Result<Event, NormalizeError> {
        let fd_stage = raw.event_type == RawEventType::BinderFdSent as u16
            || raw.event_type == RawEventType::BinderFdReceived as u16;
        let expected_size = if fd_stage {
            RAW_BINDER_FD_EVENT_SIZE
        } else {
            RAW_BINDER_EVENT_SIZE
        };
        if bytes.len() != expected_size {
            return Err(NormalizeError::InvalidBinderRecordSize(bytes.len()));
        }
        let stage = match raw.event_type {
            value if value == RawEventType::BinderTransaction as u16 => {
                BinderTransactionStage::Submitted
            }
            value if value == RawEventType::BinderTransactionReceived as u16 => {
                BinderTransactionStage::Received
            }
            value if value == RawEventType::BinderBufferAllocated as u16 => {
                BinderTransactionStage::BufferAllocated
            }
            value if value == RawEventType::BinderFdSent as u16 => BinderTransactionStage::FdSent,
            value if value == RawEventType::BinderFdReceived as u16 => {
                BinderTransactionStage::FdReceived
            }
            value => return Err(NormalizeError::UnexpectedEventType(value)),
        };
        let submitted = stage == BinderTransactionStage::Submitted;
        let buffer = stage == BinderTransactionStage::BufferAllocated;
        let target_node = if submitted { read_i32(bytes, 100) } else { 0 };
        let destination_process = if submitted { read_i32(bytes, 104) } else { 0 };
        let destination_thread = if submitted { read_i32(bytes, 108) } else { 0 };
        let is_reply = submitted && read_u32(bytes, 112) != 0;
        let code = if submitted { read_u32(bytes, 116) } else { 0 };
        let flags = if submitted { read_u32(bytes, 120) } else { 0 };
        let direction = if is_reply {
            BinderTransactionDirection::Reply
        } else {
            BinderTransactionDirection::Request
        };
        let decoded_flags = if submitted {
            decode_binder_flags(flags)
        } else {
            Vec::new()
        };
        let code_kind = submitted.then(|| classify_binder_code(code));
        let target_kind = submitted.then(|| classify_binder_target(target_node, is_reply));
        let source = match stage {
            BinderTransactionStage::Submitted => "binder/binder_transaction",
            BinderTransactionStage::Received => "binder/binder_transaction_received",
            BinderTransactionStage::BufferAllocated => "binder/binder_transaction_alloc_buf",
            BinderTransactionStage::FdSent => "binder/binder_transaction_fd_send",
            BinderTransactionStage::FdReceived => "binder/binder_transaction_fd_recv",
            BinderTransactionStage::ParcelPrefix => "kprobe/binder_transaction",
        };

        Ok(Event {
            header: EventHeader {
                schema: CURRENT_SCHEMA,
                session_id: self.session_id,
                source_sequence: raw.source_sequence,
                monotonic_ns: raw.monotonic_ns,
                cpu: Some(raw.cpu),
                process: ProcessIdentity {
                    key: ProcessKey {
                        boot_id: self.boot_id,
                        pid: raw.pid,
                        start_time_ns: raw.process_start_time,
                    },
                    tid: raw.tid,
                    tgid: raw.tgid,
                    uid: raw.uid,
                    gid: raw.gid,
                    comm: nul_terminated(&raw.comm),
                    command_line: None,
                    selinux_context: None,
                    packages: Vec::new(),
                },
                sensor: SensorKind::Binder,
                mode: CaptureMode::Observe,
                quality: DataQuality {
                    confidence: Confidence::Partial,
                    truncated: false,
                    lost_before: 0,
                    sample_one_in: 1,
                    source: source.to_owned(),
                },
            },
            payload: EventPayload::BinderTransaction(BinderTransaction {
                stage,
                transaction_id: read_i32(bytes, 96),
                target_node: (target_node > 0).then_some(target_node),
                target_process_id: u32::try_from(destination_process)
                    .ok()
                    .filter(|value| *value != 0),
                target_thread_id: u32::try_from(destination_thread)
                    .ok()
                    .filter(|value| *value != 0),
                target_kind,
                reply: is_reply,
                direction,
                reply_to_request_id: if is_reply {
                    let request = read_u32(bytes, 124);
                    i32::try_from(request).ok().filter(|value| *value != 0)
                } else {
                    None
                },
                reply_latency_ns: None,
                code,
                code_kind,
                flags,
                decoded_flags,
                data_size: buffer.then(|| read_u64(bytes, 104)),
                offsets_size: buffer.then(|| read_u64(bytes, 112)),
                extra_buffers_size: buffer.then(|| read_u64(bytes, 120)),
                file_descriptor: fd_stage.then(|| read_i32(bytes, 100)),
                object_offset: fd_stage.then(|| read_u64(bytes, 104)),
                transferred_fd_origin: None,
                transferred_fd_source_pid: None,
                transferred_fd_source_fd: None,
                interface_token: None,
                binder_method: None,
                binder_method_source: None,
                parcel_prefix_hex: None,
            }),
        })
    }

    fn normalize_binder_parcel(
        &self,
        bytes: &[u8],
        raw: &RawEventHeader,
    ) -> Result<Event, NormalizeError> {
        if bytes.len() != RAW_BINDER_PARCEL_EVENT_SIZE {
            return Err(NormalizeError::InvalidBinderRecordSize(bytes.len()));
        }
        let copied = usize::try_from(read_u32(bytes, 104)).unwrap_or(0).min(128);
        let prefix = &bytes[112..112 + copied];
        let token = parse_parcel_interface_token(prefix);
        let parcel_prefix_hex = prefix_hex(prefix);
        let code = read_u32(bytes, 100);
        let binder_method = token
            .as_deref()
            .and_then(|interface| crate::binder_aidl::aidl_method(interface, code))
            .map(str::to_owned);
        let binder_method_source = binder_method.is_some().then(|| "aosp_stub".to_owned());
        Ok(Event {
            header: EventHeader {
                schema: CURRENT_SCHEMA,
                session_id: self.session_id,
                source_sequence: raw.source_sequence,
                monotonic_ns: raw.monotonic_ns,
                cpu: Some(raw.cpu),
                process: ProcessIdentity {
                    key: ProcessKey {
                        boot_id: self.boot_id,
                        pid: raw.pid,
                        start_time_ns: raw.process_start_time,
                    },
                    tid: raw.tid,
                    tgid: raw.tgid,
                    uid: raw.uid,
                    gid: raw.gid,
                    comm: nul_terminated(&raw.comm),
                    command_line: None,
                    selinux_context: None,
                    packages: Vec::new(),
                },
                sensor: SensorKind::Binder,
                mode: CaptureMode::Observe,
                quality: DataQuality {
                    confidence: Confidence::Partial,
                    truncated: raw.flags & EVENT_FLAG_TRUNCATED != 0 || read_u32(bytes, 108) != 0,
                    lost_before: 0,
                    sample_one_in: 1,
                    source: "kprobe/binder_transaction".to_owned(),
                },
            },
            payload: EventPayload::BinderTransaction(BinderTransaction {
                stage: BinderTransactionStage::ParcelPrefix,
                transaction_id: read_i32(bytes, 96),
                target_node: None,
                target_process_id: None,
                target_thread_id: None,
                target_kind: None,
                reply: false,
                direction: BinderTransactionDirection::Request,
                reply_to_request_id: None,
                reply_latency_ns: None,
                code,
                code_kind: Some(classify_binder_code(code)),
                flags: 0,
                decoded_flags: Vec::new(),
                data_size: Some(u64::from(read_u32(bytes, 104))),
                offsets_size: None,
                extra_buffers_size: None,
                file_descriptor: None,
                object_offset: None,
                transferred_fd_origin: None,
                transferred_fd_source_pid: None,
                transferred_fd_source_fd: None,
                interface_token: token,
                binder_method,
                binder_method_source,
                parcel_prefix_hex,
            }),
        })
    }

    fn normalize_sched(&self, bytes: &[u8], raw: &RawEventHeader) -> Result<Event, NormalizeError> {
        if bytes.len() != RAW_SCHED_EVENT_SIZE {
            return Err(NormalizeError::InvalidSchedRecordSize(bytes.len()));
        }
        if raw.event_type != RawEventType::SchedWakeup as u16 {
            return Err(NormalizeError::UnexpectedEventType(raw.event_type));
        }

        Ok(Event {
            header: EventHeader {
                schema: CURRENT_SCHEMA,
                session_id: self.session_id,
                source_sequence: raw.source_sequence,
                monotonic_ns: raw.monotonic_ns,
                cpu: Some(raw.cpu),
                process: ProcessIdentity {
                    key: ProcessKey {
                        boot_id: self.boot_id,
                        pid: raw.pid,
                        start_time_ns: raw.process_start_time,
                    },
                    tid: raw.tid,
                    tgid: raw.tgid,
                    uid: raw.uid,
                    gid: raw.gid,
                    comm: nul_terminated(&raw.comm),
                    command_line: None,
                    selinux_context: None,
                    packages: Vec::new(),
                },
                sensor: SensorKind::Sched,
                mode: CaptureMode::Observe,
                quality: DataQuality {
                    confidence: Confidence::Partial,
                    truncated: false,
                    lost_before: 0,
                    sample_one_in: 1,
                    source: "sched/sched_wakeup".to_owned(),
                },
            },
            payload: EventPayload::SchedWakeup(SchedWakeup {
                wakee_tid: read_u32(bytes, 100),
                wakee_prio: read_i32(bytes, 104),
                target_cpu: read_i32(bytes, 108),
            }),
        })
    }
}

fn decode_peer(family: u16, address: &[u8]) -> (Option<String>, Option<u16>, Option<u32>) {
    match family {
        0 if address.is_empty() => (Some("empty-sockaddr".to_owned()), None, None),
        0 => (Some("af-unspec".to_owned()), None, None),
        1 if address.len() > 2 => {
            let path = &address[2..];
            let abstract_socket = path.first() == Some(&0);
            let name = if abstract_socket { &path[1..] } else { path };
            let length = name
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(name.len());
            let name = String::from_utf8_lossy(&name[..length]);
            let peer = if name.is_empty() {
                None
            } else if abstract_socket {
                Some(format!("@{name}"))
            } else {
                Some(name.into_owned())
            };
            (peer, None, None)
        }
        2 if address.len() >= 8 => {
            let port = u16::from_be_bytes([address[2], address[3]]);
            let ip = std::net::Ipv4Addr::new(address[4], address[5], address[6], address[7]);
            (Some(ip.to_string()), Some(port), None)
        }
        10 if address.len() >= 28 => {
            let port = u16::from_be_bytes([address[2], address[3]]);
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&address[8..24]);
            let scope_id = u32::from_le_bytes(address[24..28].try_into().expect("fixed address"));
            (
                Some(std::net::Ipv6Addr::from(octets).to_string()),
                Some(port),
                (scope_id != 0).then_some(scope_id),
            )
        }
        16 if address.len() >= 12 => {
            let pid = u32::from_le_bytes(address[4..8].try_into().expect("netlink pid"));
            (Some(format!("netlink:{pid}")), None, None)
        }
        17 => (Some("af-packet".to_owned()), None, None),
        38 => (Some("af-alg".to_owned()), None, None),
        40 if address.len() >= 12 => {
            let port = u32::from_le_bytes(address[4..8].try_into().expect("vsock port"));
            let cid = u32::from_le_bytes(address[8..12].try_into().expect("vsock cid"));
            (Some(format!("vsock:{cid}")), u16::try_from(port).ok(), None)
        }
        42 => (Some("af-qipcrtr".to_owned()), None, None),
        _ => (None, None, None),
    }
}

fn nul_terminated(bytes: &[u8]) -> String {
    let length = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..length]).into_owned()
}

fn decode_binder_flags(flags: u32) -> Vec<BinderTransactionFlag> {
    let mut decoded = Vec::new();
    if flags & 0x01 != 0 {
        decoded.push(BinderTransactionFlag::OneWay);
    }
    if flags & 0x04 != 0 {
        decoded.push(BinderTransactionFlag::RootObject);
    }
    if flags & 0x08 != 0 {
        decoded.push(BinderTransactionFlag::StatusCode);
    }
    if flags & 0x10 != 0 {
        decoded.push(BinderTransactionFlag::AcceptFds);
    }
    if flags & 0x20 != 0 {
        decoded.push(BinderTransactionFlag::ClearBuf);
    }
    if flags & 0x40 != 0 {
        decoded.push(BinderTransactionFlag::UpdateTxn);
    }
    decoded
}

fn classify_binder_code(code: u32) -> BinderCodeKind {
    match code {
        0x0000_0001 => BinderCodeKind::FirstCallTransaction,
        0x00ff_ffff => BinderCodeKind::LastCallTransaction,
        0x5f50_4e47 => BinderCodeKind::PingTransaction,
        0x5f44_4d50 => BinderCodeKind::DumpTransaction,
        0x5f4e_5446 => BinderCodeKind::InterfaceTransaction,
        0x5f54_5754 => BinderCodeKind::TweetTransaction,
        0x5f4c_494b => BinderCodeKind::LikeTransaction,
        _ => BinderCodeKind::Method,
    }
}

fn classify_binder_target(target_node: i32, is_reply: bool) -> BinderTargetKind {
    if is_reply {
        BinderTargetKind::Reply
    } else if target_node > 0 {
        BinderTargetKind::LocalNode
    } else {
        BinderTargetKind::RemoteHandle
    }
}

/// Parcel layout: optional `StrictMode` / work-source int32s, then String16.
fn parse_parcel_interface_token(data: &[u8]) -> Option<String> {
    for offset in [4_usize, 8, 12, 16, 20, 24, 28, 0] {
        if let Some(value) = parse_parcel_string16_at(data, offset)
            .filter(|value| looks_like_parcel_interface(value))
        {
            return Some(value);
        }
    }
    None
}

fn parse_parcel_string16_at(data: &[u8], offset: usize) -> Option<String> {
    let len_bytes = data.get(offset..offset + 4)?;
    let len = i32::from_le_bytes(len_bytes.try_into().ok()?);
    if !(1..=96).contains(&len) {
        return None;
    }
    let units = usize::try_from(len).ok()?;
    let start = offset.checked_add(4)?;
    let end = start.checked_add(units.checked_mul(2)?)?;
    let bytes = data.get(start..end)?;
    let mut units16 = Vec::with_capacity(units);
    for chunk in bytes.chunks_exact(2) {
        let unit = u16::from_le_bytes([chunk[0], chunk[1]]);
        if unit == 0 {
            break;
        }
        units16.push(unit);
    }
    let value = String::from_utf16(&units16).ok()?;
    (!value.is_empty()).then_some(value)
}

fn looks_like_parcel_interface(value: &str) -> bool {
    (3..=192).contains(&value.len())
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '$' | '/'))
        && value.contains('.')
}

fn prefix_hex(data: &[u8]) -> Option<String> {
    if data.is_empty() {
        return None;
    }
    let take = data.len().min(32);
    let mut out = String::with_capacity(take * 2);
    for byte in &data[..take] {
        let _ = write!(&mut out, "{byte:02x}");
    }
    Some(out)
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("fixed process record"),
    )
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("fixed event record"),
    )
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(
        bytes[offset..offset + 2]
            .try_into()
            .expect("fixed event record"),
    )
}

fn read_i32(bytes: &[u8], offset: usize) -> i32 {
    i32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("fixed event record"),
    )
}

fn read_i64(bytes: &[u8], offset: usize) -> i64 {
    i64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("fixed event record"),
    )
}
