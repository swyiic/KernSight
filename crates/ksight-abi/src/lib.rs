//! Fixed-layout raw ABI shared conceptually with `bpf/include/ksight_abi.h`.
//!
//! This crate models layout and identifiers. Safe byte decoding is added with the selected BPF
//! loader so this crate can continue to forbid unsafe code.

/// Current eBPF-to-agent raw ABI generation.
pub const RAW_ABI_VERSION: u16 = 1;

/// Fixed kernel task-name capacity.
pub const TASK_COMM_LEN: usize = 16;

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
