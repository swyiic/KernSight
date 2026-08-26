//! Fixed-layout raw ABI shared conceptually with `bpf/include/ksight_abi.h`.
//!
//! This crate models layout and identifiers. Safe byte decoding is added with the selected BPF
//! loader so this crate can continue to forbid unsafe code.

/// Current eBPF-to-agent raw ABI generation.
pub const RAW_ABI_VERSION: u16 = 1;

/// Fixed kernel task-name capacity.
pub const TASK_COMM_LEN: usize = 16;
/// Fixed raw event header size.
pub const RAW_EVENT_HEADER_SIZE: usize = 96;
/// Maximum executable filename bytes carried by the M1 process sensor.
pub const PROCESS_FILENAME_LEN: usize = 256;
/// Fixed process lifecycle record size.
pub const RAW_PROCESS_EVENT_SIZE: usize = RAW_EVENT_HEADER_SIZE + 8 + PROCESS_FILENAME_LEN;

/// Numeric raw sensor identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum RawSensorId {
    /// Process lifecycle and credentials.
    Process = 1,
    /// Filesystem operations.
    File = 2,
    /// Virtual memory operations.
    Memory = 3,
    /// Socket and packet metadata.
    Network = 4,
    /// Binder driver activity.
    Binder = 5,
    /// Capture integrity facts.
    Integrity = 6,
    /// Scoped syscall supplement.
    Syscall = 7,
}

/// Numeric raw event type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum RawEventType {
    /// Process or thread creation.
    ProcessFork = 0x0101,
    /// Process image replacement.
    ProcessExec = 0x0102,
    /// Process or thread exit.
    ProcessExit = 0x0103,
}

/// Raw event was truncated at its configured bound.
pub const EVENT_FLAG_TRUNCATED: u32 = 1 << 0;
/// Raw event was produced under a sampling policy.
pub const EVENT_FLAG_SAMPLED: u32 = 1 << 1;
/// Raw event contains only partial identity.
pub const EVENT_FLAG_IDENTITY_PARTIAL: u32 = 1 << 2;

/// Fixed 96-byte prefix for every kernel-to-agent record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct RawEventHeader {
    /// Raw ABI generation.
    pub abi_version: u16,
    /// Size of this fixed header.
    pub header_size: u16,
    /// [`RawSensorId`] numeric value.
    pub sensor_id: u16,
    /// [`RawEventType`] or future sensor-specific value.
    pub event_type: u16,
    /// Complete record size including variable payload.
    pub total_size: u32,
    /// Raw event flags.
    pub flags: u32,
    /// Source-local ordering sequence.
    pub source_sequence: u64,
    /// Kernel monotonic timestamp in nanoseconds.
    pub monotonic_ns: u64,
    /// Kernel process start-time representation for the negotiated ABI.
    pub process_start_time: u64,
    /// Emitting CPU.
    pub cpu: u32,
    /// Linux user ID.
    pub uid: u32,
    /// Linux group ID.
    pub gid: u32,
    /// Linux process ID.
    pub pid: u32,
    /// Linux thread ID.
    pub tid: u32,
    /// Linux thread-group ID.
    pub tgid: u32,
    /// Parent process ID.
    pub ppid: u32,
    /// Fixed kernel task name bytes.
    pub comm: [u8; TASK_COMM_LEN],
    /// Reserved zeroed words for compatible expansion.
    pub reserved: [u32; 3],
}

const _: [(); 96] = [(); core::mem::size_of::<RawEventHeader>()];

/// Error returned while validating a byte-oriented raw ABI record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// The record is shorter than the fixed header.
    HeaderTooShort,
    /// The record declares an unsupported ABI generation.
    UnsupportedAbi(u16),
    /// The header-size field is not the fixed size for this ABI.
    InvalidHeaderSize(u16),
    /// The declared total size does not match the supplied record.
    InvalidTotalSize(u32),
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::HeaderTooShort => formatter.write_str("raw record is shorter than its header"),
            Self::UnsupportedAbi(version) => write!(formatter, "unsupported raw ABI {version}"),
            Self::InvalidHeaderSize(size) => write!(formatter, "invalid raw header size {size}"),
            Self::InvalidTotalSize(size) => write!(formatter, "invalid raw total size {size}"),
        }
    }
}

impl std::error::Error for DecodeError {}

impl RawEventHeader {
    /// Decode and validate a little-endian fixed header without unaligned memory access.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] when the input is truncated or declares an incompatible layout.
    pub fn decode(record: &[u8]) -> Result<Self, DecodeError> {
        if record.len() < RAW_EVENT_HEADER_SIZE {
            return Err(DecodeError::HeaderTooShort);
        }

        let mut comm = [0_u8; TASK_COMM_LEN];
        comm.copy_from_slice(&record[68..84]);
        let header = Self {
            abi_version: read_u16(record, 0),
            header_size: read_u16(record, 2),
            sensor_id: read_u16(record, 4),
            event_type: read_u16(record, 6),
            total_size: read_u32(record, 8),
            flags: read_u32(record, 12),
            source_sequence: read_u64(record, 16),
            monotonic_ns: read_u64(record, 24),
            process_start_time: read_u64(record, 32),
            cpu: read_u32(record, 40),
            uid: read_u32(record, 44),
            gid: read_u32(record, 48),
            pid: read_u32(record, 52),
            tid: read_u32(record, 56),
            tgid: read_u32(record, 60),
            ppid: read_u32(record, 64),
            comm,
            reserved: [
                read_u32(record, 84),
                read_u32(record, 88),
                read_u32(record, 92),
            ],
        };

        if header.abi_version != RAW_ABI_VERSION {
            return Err(DecodeError::UnsupportedAbi(header.abi_version));
        }
        if usize::from(header.header_size) != RAW_EVENT_HEADER_SIZE {
            return Err(DecodeError::InvalidHeaderSize(header.header_size));
        }
        if usize::try_from(header.total_size).ok() != Some(record.len()) {
            return Err(DecodeError::InvalidTotalSize(header.total_size));
        }
        Ok(header)
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().expect("fixed offset"))
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("fixed offset"))
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("fixed offset"))
}
