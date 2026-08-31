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
/// Maximum path bytes carried by the M2 file sensor.
pub const FILE_PATH_LEN: usize = 256;
/// Fixed file-open record size.
pub const RAW_FILE_EVENT_SIZE: usize = RAW_EVENT_HEADER_SIZE + 24 + FILE_PATH_LEN;
/// Fixed file-descriptor lifecycle record size.
pub const RAW_FD_EVENT_SIZE: usize = RAW_EVENT_HEADER_SIZE + 24;
/// Fixed memory-region record size.
pub const RAW_MEMORY_EVENT_SIZE: usize = RAW_EVENT_HEADER_SIZE + 48;
/// Maximum submitted socket-address bytes carried by the M2 network sensor.
pub const SOCKET_ADDRESS_LEN: usize = 128;
/// Fixed socket-connect record size.
pub const RAW_NETWORK_EVENT_SIZE: usize = RAW_EVENT_HEADER_SIZE + 16 + SOCKET_ADDRESS_LEN;
/// Fixed socket send/receive byte-count record size.
pub const RAW_NETWORK_IO_EVENT_SIZE: usize = RAW_EVENT_HEADER_SIZE + 32;
/// Fixed bounded DNS datagram record size.
pub const RAW_DNS_EVENT_SIZE: usize = RAW_EVENT_HEADER_SIZE + 32 + 512;
/// Fixed bounded first-write handshake record size (same layout as DNS).
pub const RAW_HANDSHAKE_EVENT_SIZE: usize = RAW_DNS_EVENT_SIZE;
/// Fixed Binder transaction record size.
pub const RAW_BINDER_EVENT_SIZE: usize = RAW_EVENT_HEADER_SIZE + 32;
/// Fixed Binder file-descriptor transfer record size.
pub const RAW_BINDER_FD_EVENT_SIZE: usize = RAW_EVENT_HEADER_SIZE + 16;
/// Bounded Binder parcel-prefix bytes copied at `binder_transaction()`.
pub const BINDER_PARCEL_BYTES: usize = 128;
/// Fixed Binder parcel-prefix record size.
pub const RAW_BINDER_PARCEL_EVENT_SIZE: usize = RAW_EVENT_HEADER_SIZE + 16 + BINDER_PARCEL_BYTES;
/// Fixed scheduler wakeup record size.
pub const RAW_SCHED_EVENT_SIZE: usize = RAW_EVENT_HEADER_SIZE + 16;

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
    /// Scheduler wakeup relationships.
    Sched = 8,
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
    /// Process credentials changed successfully.
    ProcessCredentials = 0x0104,
    /// Process task name changed.
    ProcessRename = 0x0105,
    /// File open attempt completed.
    FileOpen = 0x0201,
    /// File descriptor close attempt completed.
    FileDescriptorClose = 0x0202,
    /// File descriptor duplication attempt completed.
    FileDescriptorDuplicate = 0x0203,
    /// `close_range` attempt completed.
    FileDescriptorCloseRange = 0x0204,
    /// Unix `SCM_RIGHTS` descriptors were submitted.
    FileDescriptorRightsSend = 0x0205,
    /// Unix `SCM_RIGHTS` descriptors were installed.
    FileDescriptorRightsReceive = 0x0206,
    /// Memory mapping attempt completed.
    MemoryMap = 0x0301,
    /// Memory protection change attempt completed.
    MemoryProtect = 0x0302,
    /// Memory unmap attempt completed.
    MemoryUnmap = 0x0303,
    /// Memory remap attempt completed.
    MemoryRemap = 0x0304,
    /// Program-break adjustment completed.
    MemoryBrk = 0x0305,
    /// Socket connect attempt completed.
    NetworkConnect = 0x0401,
    /// Inbound socket accept attempt completed.
    NetworkAccept = 0x0402,
    /// Socket send operation completed.
    NetworkSend = 0x0403,
    /// Socket receive operation completed.
    NetworkReceive = 0x0404,
    /// Bounded DNS datagram copied from UDP/53 sendto or recvfrom.
    NetworkDns = 0x0405,
    /// Bounded first-write handshake copy (TLS `ClientHello` / HTTP/1 / QUIC long header).
    NetworkHandshake = 0x0406,
    /// Binder transaction was submitted.
    BinderTransaction = 0x0501,
    /// Binder transaction reached its destination thread.
    BinderTransactionReceived = 0x0502,
    /// Binder transaction buffer sizes were allocated.
    BinderBufferAllocated = 0x0503,
    /// Source file descriptor was attached to a Binder transaction.
    BinderFdSent = 0x0504,
    /// Destination file descriptor was installed from a Binder transaction.
    BinderFdReceived = 0x0505,
    /// Bounded parcel prefix copied at kernel `binder_transaction()` (32-bit and 64-bit clients).
    BinderParcel = 0x0506,
    /// A task was woken by the current task.
    SchedWakeup = 0x0801,
    /// A scheduler context switch occurred.
    SchedSwitch = 0x0802,
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
