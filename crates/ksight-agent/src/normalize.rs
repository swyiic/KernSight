use ksight_abi::{
    RawEventHeader, RawEventType, RawSensorId, EVENT_FLAG_IDENTITY_PARTIAL, EVENT_FLAG_TRUNCATED,
    PROCESS_FILENAME_LEN, RAW_PROCESS_EVENT_SIZE,
};
use ksight_model::{
    CaptureMode, Confidence, DataQuality, Event, EventHeader, EventPayload, ProcessIdentity,
    ProcessKey, ProcessLifecycle, ProcessLifecycleKind, SensorKind, CURRENT_SCHEMA,
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
pub struct ProcessNormalizer {
    boot_id: Uuid,
    session_id: Uuid,
}

impl ProcessNormalizer {
    /// Create a process normalizer for a known boot and capture session.
    pub fn new(boot_id: Uuid, session_id: Uuid) -> Self {
        Self {
            boot_id,
            session_id,
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
    /// The event belongs to another sensor.
    #[error("unexpected sensor {0}")]
    UnexpectedSensor(u16),
    /// The process event type is unknown.
    #[error("unexpected process event type {0:#06x}")]
    UnexpectedEventType(u16),
    /// The executable filename length exceeds its fixed ABI capacity.
    #[error("invalid process filename length {0}")]
    InvalidFilenameLength(usize),
}

impl Normalizer for ProcessNormalizer {
    type Error = NormalizeError;

    fn normalize(&mut self, record: RawRecord) -> Result<Event, Self::Error> {
        let raw = RawEventHeader::decode(&record.bytes)?;
        if record.bytes.len() != RAW_PROCESS_EVENT_SIZE {
            return Err(NormalizeError::InvalidProcessRecordSize(record.bytes.len()));
        }
        if raw.sensor_id != RawSensorId::Process as u16 {
            return Err(NormalizeError::UnexpectedSensor(raw.sensor_id));
        }

        let (kind, source) = match raw.event_type {
            value if value == RawEventType::ProcessFork as u16 => {
                (ProcessLifecycleKind::Fork, "sched/sched_process_fork")
            }
            value if value == RawEventType::ProcessExec as u16 => {
                (ProcessLifecycleKind::Exec, "sched/sched_process_exec")
            }
            value if value == RawEventType::ProcessExit as u16 => {
                (ProcessLifecycleKind::Exit, "sched/sched_process_exit")
            }
            value => return Err(NormalizeError::UnexpectedEventType(value)),
        };

        let filename_length = usize::try_from(read_u32(&record.bytes, 100))
            .map_err(|_| NormalizeError::InvalidFilenameLength(usize::MAX))?;
        if filename_length > PROCESS_FILENAME_LEN {
            return Err(NormalizeError::InvalidFilenameLength(filename_length));
        }
        let filename = (kind == ProcessLifecycleKind::Exec).then(|| {
            String::from_utf8_lossy(&record.bytes[104..104 + filename_length]).into_owned()
        });
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
                    source: source.to_owned(),
                },
            },
            payload: EventPayload::ProcessLifecycle(ProcessLifecycle {
                kind,
                parent_pid: (kind == ProcessLifecycleKind::Fork).then_some(raw.ppid),
                filename,
                exit_code: None,
            }),
        })
    }
}

fn nul_terminated(bytes: &[u8]) -> String {
    let length = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..length]).into_owned()
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("fixed process record"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_exec_filename_and_identity() {
        let mut bytes = vec![0_u8; RAW_PROCESS_EVENT_SIZE];
        put_u16(&mut bytes, 0, ksight_abi::RAW_ABI_VERSION);
        put_u16(&mut bytes, 2, 96);
        put_u16(&mut bytes, 4, RawSensorId::Process as u16);
        put_u16(&mut bytes, 6, RawEventType::ProcessExec as u16);
        put_u32(&mut bytes, 8, 360);
        put_u64(&mut bytes, 16, 7);
        put_u64(&mut bytes, 24, 900);
        put_u64(&mut bytes, 32, 500);
        put_u32(&mut bytes, 44, 10_123);
        put_u32(&mut bytes, 52, 321);
        put_u32(&mut bytes, 56, 321);
        put_u32(&mut bytes, 60, 321);
        bytes[68..72].copy_from_slice(b"demo");
        put_u32(&mut bytes, 100, 11);
        bytes[104..115].copy_from_slice(b"/system/bin");

        let record = RawRecord::from_bytes(&bytes).expect("raw record");
        let id = Uuid::nil();
        let mut normalizer = ProcessNormalizer::new(id, id);
        let event = normalizer.normalize(record).expect("normalized event");

        assert_eq!(event.header.process.key.pid, 321);
        assert_eq!(event.header.process.key.start_time_ns, 500);
        assert_eq!(event.header.process.comm, "demo");
        let EventPayload::ProcessLifecycle(payload) = event.payload else {
            panic!("expected process lifecycle payload");
        };
        assert_eq!(payload.kind, ProcessLifecycleKind::Exec);
        assert_eq!(payload.filename.as_deref(), Some("/system/bin"));
    }

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
}
