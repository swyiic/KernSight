use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{DataQuality, ProcessIdentity};

/// Version of the normalized semantic event schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaVersion {
    /// Breaking schema generation.
    pub major: u16,
    /// Backward-compatible schema feature level.
    pub minor: u16,
}

/// Visibility and collection impact of an event source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureMode {
    /// Low-impact, whole-device collection.
    Observe,
    /// Explicit, selected-process semantic inspection.
    Inspect,
    /// Explicit laboratory debugger session.
    Debug,
}

/// Capture subsystem that produced an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensorKind {
    /// Process lifecycle and credentials.
    Process,
    /// Filesystem operations.
    File,
    /// Virtual memory and executable mappings.
    Memory,
    /// Socket and packet metadata.
    Network,
    /// Android Binder IPC.
    Binder,
    /// Capture and boot integrity telemetry.
    Integrity,
    /// Optional low-level syscall supplement.
    Syscall,
    /// Scheduler wakeup relationships.
    Sched,
}

/// Metadata shared by every normalized event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventHeader {
    /// Normalized schema version.
    pub schema: SchemaVersion,
    /// Unique capture session.
    pub session_id: Uuid,
    /// Source-local monotonically increasing sequence number.
    pub source_sequence: u64,
    /// Kernel monotonic timestamp in nanoseconds.
    pub monotonic_ns: u64,
    /// CPU that emitted the raw record, if known.
    pub cpu: Option<u32>,
    /// Process identity known at normalization time.
    pub process: ProcessIdentity,
    /// Producing sensor.
    pub sensor: SensorKind,
    /// Collection mode in effect at emission time.
    pub mode: CaptureMode,
    /// Confidence, truncation, and loss metadata.
    pub quality: DataQuality,
}

/// Normalized event with a stable header and an extensible payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Event metadata.
    pub header: EventHeader,
    /// Sensor-specific facts.
    pub payload: EventPayload,
}

/// Sensor-specific normalized facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum EventPayload {
    /// Process lifecycle transition.
    ProcessLifecycle(ProcessLifecycle),
    /// Runtime process identity transition.
    ProcessIdentityChange(ProcessIdentityChange),
    /// File open attempt and kernel result.
    FileOpen(FileOpen),
    /// File-descriptor close or duplication result.
    FileDescriptorChange(FileDescriptorChange),
    /// Socket connect attempt and submitted peer endpoint.
    SocketConnect(SocketConnect),
    /// Inbound socket accepted from a listening descriptor.
    SocketAccept(SocketAccept),
    /// Completed socket send or receive operation with byte counts only.
    SocketIo(SocketIo),
    /// Bounded DNS datagram copied from UDP/53.
    DnsDatagram(DnsDatagram),
    /// Bounded first-write handshake metadata (TLS `ClientHello`, HTTP/1, QUIC long header).
    NetworkHandshake(NetworkHandshake),
    /// Memory mapping or protection transition.
    MemoryRegionChange(MemoryRegionChange),
    /// Binder IPC transaction metadata.
    BinderTransaction(BinderTransaction),
    /// Scheduler wakeup relationship.
    SchedWakeup(SchedWakeup),
    /// Session-start procfs FD snapshot for the scoped process.
    SessionFdBaseline(SessionFdBaseline),
    /// Session-start procfs VMA snapshot for the scoped process.
    SessionVmaBaseline(SessionVmaBaseline),
    /// Session-start device environment and collector independence facts.
    SessionEnvironment(SessionEnvironment),
    /// Normal capture termination and loss summary.
    SessionCompletion(SessionCompletion),
    /// Explicit Inspect adapter decision or hit. Never an Observe fact.
    InspectObservation(InspectObservation),
    /// Bounded TLS plaintext copied at an authorized `SSL_write` boundary.
    InspectPlaintext(InspectPlaintext),
    /// Forward-compatible bounded bytes for an unknown event type.
    Opaque {
        /// Source type identifier.
        type_id: u32,
        /// Bounded raw payload.
        bytes: Vec<u8>,
    },
}

/// Completed `openat` or `openat2` attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileOpen {
    /// Directory file descriptor supplied to the syscall.
    pub directory_fd: i32,
    /// New file descriptor when the operation succeeded.
    pub file_descriptor: Option<i32>,
    /// Raw non-negative descriptor or negative errno result.
    pub result: i32,
    /// Open flags supplied by userspace.
    pub flags: u32,
    /// Creation mode supplied by userspace.
    pub mode: u32,
    /// Bounded userspace path as submitted to the kernel.
    pub path: String,
    /// Best-effort absolute path resolved from `dirfd` and procfs.
    pub resolved_path: Option<String>,
    /// SHA-256 of a bounded regular file when the path looks like DEX/ELF.
    #[serde(default)]
    pub content_sha256: Option<String>,
    /// Hashed byte length when `content_sha256` is present.
    #[serde(default)]
    pub content_bytes: Option<u64>,
}

/// Completed close or duplication operation on a file descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileDescriptorChange {
    /// Descriptor lifecycle operation.
    pub operation: FileDescriptorOperation,
    /// Source descriptor supplied by userspace.
    pub file_descriptor: i32,
    /// Requested destination or minimum descriptor, when supplied.
    pub requested_file_descriptor: Option<i32>,
    /// New descriptor when duplication succeeded.
    pub resulting_file_descriptor: Option<i32>,
    /// Zero, a new descriptor, or a negative errno result.
    pub result: i32,
    /// Raw syscall or fcntl command used to produce the event.
    pub command: u32,
    /// Operation-specific flags such as dup3 flags.
    pub flags: u32,
    /// Inclusive last descriptor for `close_range`; absent for single-fd operations.
    #[serde(default)]
    pub last_file_descriptor: Option<u32>,
}

/// File-descriptor lifecycle operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileDescriptorOperation {
    /// Close one descriptor.
    Close,
    /// Create another reference to an existing descriptor.
    Duplicate,
    /// Close or mark a contiguous descriptor range.
    CloseRange,
    /// Pass descriptors over a Unix socket with `SCM_RIGHTS`.
    RightsSend,
    /// Receive descriptors over a Unix socket with `SCM_RIGHTS`.
    RightsReceive,
}

/// Completed `connect` attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SocketConnect {
    /// Socket file descriptor supplied to the syscall.
    pub file_descriptor: i32,
    /// Zero on success or a negative errno result.
    pub result: i32,
    /// Linux socket-address family number.
    pub address_family: u16,
    /// Socket-address length supplied by userspace.
    pub submitted_address_length: u16,
    /// Socket-address bytes successfully copied by the kernel sensor.
    pub captured_address_length: u16,
    /// Numeric IP address or bounded Unix-domain socket name, when decoded.
    pub peer_address: Option<String>,
    /// Network-byte-order peer port for IPv4 or IPv6.
    pub peer_port: Option<u16>,
    /// IPv6 scope identifier when present.
    pub scope_id: Option<u32>,
    /// DNS QNAME that resolved to this peer, when a prior UDP/53 answer matched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_name: Option<String>,
}

/// Bounded DNS query or response copied from sendto/recvfrom on port 53.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsDatagram {
    /// Socket descriptor used for the datagram.
    pub file_descriptor: i32,
    /// Bytes transferred, or a negative errno.
    pub result: i32,
    /// Address family of the DNS peer.
    pub address_family: u16,
    /// Peer UDP port (53 when identified).
    pub peer_port: u16,
    /// Presentation form of the DNS server address when decoded.
    pub peer_address: Option<String>,
    /// `query` for sendto, `response` for recvfrom.
    pub direction: String,
    /// True when the kernel copy truncated the payload at 512 bytes.
    pub truncated: bool,
    /// First question name when parsed.
    pub qname: Option<String>,
    /// A/AAAA answers when parsed from a response.
    pub addresses: Vec<String>,
}

/// Bounded first-send handshake metadata copied from write/sendto/sendmsg.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkHandshake {
    /// Socket descriptor used for the first write.
    pub file_descriptor: i32,
    /// Bytes transferred, or a negative errno.
    pub result: i32,
    /// Address family of the peer when sendto/sendmsg carried a destination.
    pub address_family: u16,
    /// Peer port when decoded from the destination address.
    pub peer_port: u16,
    /// Presentation form of the peer address when decoded.
    pub peer_address: Option<String>,
    /// True when the kernel copy truncated the payload at 512 bytes.
    pub truncated: bool,
    /// `tls`, `http`, or `quic`.
    pub kind: String,
    /// TLS `ClientHello` SNI hostname.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    /// Comma-joined ALPN protocols from the `ClientHello`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,
    /// True when `encrypted_client_hello` (`0xfe0d`) was present. Inner SNI is not recovered.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ech: bool,
    /// HTTP/1 method or HTTP/2 preface `PRI`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_method: Option<String>,
    /// HTTP request-target, bounded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_path: Option<String>,
    /// HTTP `Host` header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_host: Option<String>,
    /// QUIC version as `0x` plus eight hex digits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quic_version: Option<String>,
    /// QUIC long-header packet type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quic_packet: Option<String>,
}

/// Completed `accept` or `accept4` attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SocketAccept {
    /// Listening socket descriptor supplied to the syscall.
    pub listening_file_descriptor: i32,
    /// New connected descriptor when the operation succeeded.
    pub accepted_file_descriptor: Option<i32>,
    /// New descriptor or a negative errno result.
    pub result: i32,
    /// Linux socket-address family number, when returned by the kernel.
    pub address_family: u16,
    /// Socket-address length returned to userspace.
    pub returned_address_length: u16,
    /// Socket-address bytes successfully copied by the kernel sensor.
    pub captured_address_length: u16,
    /// Numeric IP address or bounded Unix-domain peer name, when decoded.
    pub peer_address: Option<String>,
    /// Network-byte-order peer port for IPv4 or IPv6.
    pub peer_port: Option<u16>,
    /// IPv6 scope identifier when present.
    pub scope_id: Option<u32>,
}

/// Completed socket I/O operation without buffer contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SocketIo {
    /// Socket descriptor supplied to the syscall.
    pub file_descriptor: i32,
    /// Transfer direction.
    pub operation: SocketIoOperation,
    /// Bytes transferred, completed messages for `sendmmsg`/`recvmmsg`, or a negative errno.
    pub result: i64,
    /// Requested byte count when directly available from the syscall ABI.
    pub requested_bytes: Option<u64>,
    /// Raw syscall number for versioned interpretation.
    pub syscall: u32,
}

/// Direction of one socket transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SocketIoOperation {
    /// Bytes submitted to a socket.
    Send,
    /// Bytes returned from a socket.
    Receive,
}

/// Completed memory mapping or protection syscall.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryRegionChange {
    /// Operation that produced the event.
    pub operation: MemoryOperation,
    /// Requested base address.
    pub address: u64,
    /// Requested byte length.
    pub length: u64,
    /// Returned mapping address, zero, or negative errno.
    pub result: i64,
    /// Linux `PROT_*` bitset.
    pub protection: u32,
    /// Linux `MAP_*` bitset for mapping operations.
    pub mapping_flags: Option<u32>,
    /// Backing file descriptor for mapping operations, when present.
    pub file_descriptor: Option<i32>,
    /// Best-effort path resolved from the process file descriptor.
    pub backing_path: Option<String>,
    /// Backing file offset for mapping operations.
    pub offset: Option<u64>,
}

/// Memory-region operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryOperation {
    /// Create or replace a virtual-memory mapping.
    Map,
    /// Change access permissions on an existing region.
    Protect,
    /// Remove one virtual-memory address range.
    Unmap,
    /// Move or resize an existing mapping.
    Remap,
    /// Adjust the process program break.
    Brk,
}

/// Binder driver transaction metadata without parcel contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinderTransaction {
    /// Driver lifecycle stage represented by this event.
    #[serde(default)]
    pub stage: BinderTransactionStage,
    /// Kernel Binder debug transaction identifier.
    pub transaction_id: i32,
    /// Target Binder node identifier, when present.
    pub target_node: Option<i32>,
    /// Destination process ID, when resolved by the driver.
    pub target_process_id: Option<u32>,
    /// Destination thread ID, when resolved by the driver.
    pub target_thread_id: Option<u32>,
    /// Kind of Binder target, when the driver resolved one.
    #[serde(default)]
    pub target_kind: Option<BinderTargetKind>,
    /// Whether this transaction is a reply.
    pub reply: bool,
    /// Client-to-server or server-to-client direction.
    #[serde(default)]
    pub direction: BinderTransactionDirection,
    /// Reply direction: the paired request transaction identifier (reply only).
    #[serde(default)]
    pub reply_to_request_id: Option<i32>,
    /// Kernel-side request-to-reply latency (reply only, when paired).
    #[serde(default)]
    pub reply_latency_ns: Option<u64>,
    /// Interface-specific Binder transaction code.
    pub code: u32,
    /// Semantic classification of the raw transaction code.
    #[serde(default)]
    pub code_kind: Option<BinderCodeKind>,
    /// Binder transaction flags.
    pub flags: u32,
    /// Decoded `TF_*` transaction flags.
    #[serde(default)]
    pub decoded_flags: Vec<BinderTransactionFlag>,
    /// Parcel data bytes allocated by the Binder driver, when observed.
    #[serde(default)]
    pub data_size: Option<u64>,
    /// Binder object-offset table bytes, when observed.
    #[serde(default)]
    pub offsets_size: Option<u64>,
    /// Extra Binder buffer bytes, when observed.
    #[serde(default)]
    pub extra_buffers_size: Option<u64>,
    /// File descriptor transferred at this Binder stage, when observed.
    #[serde(default)]
    pub file_descriptor: Option<i32>,
    /// Offset of the Binder FD object inside the transaction buffer.
    #[serde(default)]
    pub object_offset: Option<u64>,
    /// End-to-end lineage of a Binder-transferred FD, resolved when the
    /// receiving side installs the descriptor (best-effort).
    #[serde(default)]
    pub transferred_fd_origin: Option<String>,
    /// Source process that attached the descriptor, when lineage paired.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transferred_fd_source_pid: Option<u32>,
    /// Source descriptor number on the sending process, when lineage paired.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transferred_fd_source_fd: Option<i32>,
    /// Interface token parsed from a bounded kernel parcel prefix (32-bit and 64-bit clients).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface_token: Option<String>,
    /// AIDL method resolved from `interface_token` and `code` (`aosp_stub` only here).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binder_method: Option<String>,
    /// `aosp_stub` when the method came from the on-device Stub table.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binder_method_source: Option<String>,
    /// First 32 bytes of the kernel parcel prefix as lowercase hex. Present when
    /// the prefix was copied, including native protocols without a String16 token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parcel_prefix_hex: Option<String>,
}

/// Kernel-observable Binder transaction lifecycle stage.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BinderTransactionStage {
    /// Transaction was submitted to the Binder driver.
    #[default]
    Submitted,
    /// Transaction was delivered to its destination thread.
    Received,
    /// Driver allocated the transaction payload buffers.
    BufferAllocated,
    /// Source process attached a file descriptor to the transaction.
    FdSent,
    /// Destination process installed a file descriptor from the transaction.
    FdReceived,
    /// Bounded parcel prefix copied at kernel `binder_transaction()` before submit.
    ParcelPrefix,
}

/// Direction of a Binder transaction relative to the emitting process.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BinderTransactionDirection {
    /// Client-to-server request.
    #[default]
    Request,
    /// Server-to-client reply.
    Reply,
}

/// Decoded Binder driver transaction flag (`TF_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BinderTransactionFlag {
    /// Asynchronous one-way call with no reply.
    OneWay,
    /// Contents are the component's root object.
    RootObject,
    /// Contents are a 32-bit status code.
    StatusCode,
    /// Replies may carry file descriptors.
    AcceptFds,
    /// Clear the transaction buffer on completion.
    ClearBuf,
    /// Update the outdated pending async transaction.
    UpdateTxn,
}

/// Semantic classification of a Binder transaction `code`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BinderCodeKind {
    /// First user-callable transaction code (`FIRST_CALL_TRANSACTION`).
    FirstCallTransaction,
    /// Last user-callable transaction code (`LAST_CALL_TRANSACTION`).
    LastCallTransaction,
    /// `IBinder` `PING_TRANSACTION`.
    PingTransaction,
    /// `IBinder` `DUMP_TRANSACTION`.
    DumpTransaction,
    /// `IBinder` `INTERFACE_TRANSACTION`.
    InterfaceTransaction,
    /// `IBinder` `TWEET_TRANSACTION`.
    TweetTransaction,
    /// `IBinder` `LIKE_TRANSACTION`.
    LikeTransaction,
    /// Interface-specific method number.
    Method,
}

/// Kind of Binder transaction target resolved by the driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BinderTargetKind {
    /// Local Binder node targeted directly.
    LocalNode,
    /// Remote object reached through a handle/ref.
    RemoteHandle,
    /// Reply directed at the requesting thread.
    Reply,
}

/// Scheduler wakeup relationship between the waker (header process) and a wakee.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedWakeup {
    /// Woken thread identifier.
    pub wakee_tid: u32,
    /// Woken task priority.
    pub wakee_prio: i32,
    /// Target CPU for the woken task.
    pub target_cpu: i32,
}

/// One descriptor in a session-start FD baseline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineFd {
    /// Descriptor number.
    pub fd: i32,
    /// Best-effort descriptor kind derived from the procfs target.
    pub kind: BaselineFdKind,
    /// procfs `/proc/<pid>/fd/<n>` readlink target (bounded).
    pub target: String,
}

/// Best-effort descriptor classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineFdKind {
    /// Regular file or directory.
    File,
    /// Socket identified by a `socket:[inode]` target.
    Socket,
    /// Pipe identified by a `pipe:[inode]` target.
    Pipe,
    /// Unresolved or other descriptor kind.
    Other,
}

/// One virtual-memory area in a session-start VMA baseline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineVma {
    /// Inclusive start address.
    pub start: u64,
    /// Exclusive end address.
    pub end: u64,
    /// Linux `PROT_*` bitset decoded from the maps permission column.
    pub protection: u32,
    /// Backing file path when the mapping is file-backed.
    pub path: Option<String>,
}

/// Session-start FD snapshot payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionFdBaseline {
    /// Process that owns the descriptors.
    pub process_id: u32,
    /// Bounded descriptor list.
    #[serde(default)]
    pub fds: Vec<BaselineFd>,
    /// Zero-based chunk when a process FD table is split across events.
    #[serde(default)]
    pub chunk_index: u32,
    /// Total chunks for this process; zero means a legacy single event.
    #[serde(default)]
    pub chunk_count: u32,
}

/// Session-start VMA snapshot payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionVmaBaseline {
    /// Process that owns the mappings.
    pub process_id: u32,
    /// Bounded virtual-memory area list.
    #[serde(default)]
    pub vmas: Vec<BaselineVma>,
    /// Zero-based chunk when a process map table is split across events.
    #[serde(default)]
    pub chunk_index: u32,
    /// Total chunks for this process; zero means a legacy single event.
    #[serde(default)]
    pub chunk_count: u32,
}

/// Whether an Android environment switch was established at session start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentState {
    /// The switch was observed enabled.
    Enabled,
    /// The switch was observed disabled.
    Disabled,
    /// The current security domain could not establish its state.
    Unknown,
}

/// How the collector process was launched for this session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectorMode {
    /// Capture is attached to an interactive ADB command.
    ForegroundAdb,
    /// Capture runs as a detached device-side service.
    DetachedDaemon,
}

/// Device state that may affect target behavior or collection independence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionEnvironment {
    /// Collector launch mode.
    pub collector_mode: CollectorMode,
    /// Android developer-options state.
    pub developer_options: EnvironmentState,
    /// ADB debugging state.
    pub usb_debugging: EnvironmentState,
    /// Wireless-debugging state.
    pub wireless_debugging: EnvironmentState,
    /// Whether the agent has effective UID zero.
    pub root_authorized: bool,
    /// `SELinux` enforcing state when readable.
    pub selinux_enforcing: Option<bool>,
    /// Android verified-boot state property.
    pub verified_boot_state: Option<String>,
    /// Bootloader lock state when exposed by Android properties.
    pub bootloader_locked: Option<bool>,
    /// True when the observed environment may make an application change behavior.
    pub target_behavior_may_be_altered: bool,
    /// Bounded operator-facing reasons for the altered-behavior marker.
    #[serde(default)]
    pub warnings: Vec<String>,
    /// Collector monotonic clock at session start.
    #[serde(default)]
    pub monotonic_ns: Option<u64>,
    /// Collector realtime clock at session start, for wall-clock correlation.
    #[serde(default)]
    pub wall_clock_ns: Option<u64>,
}

/// Why a normally completed capture loop stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureStopReason {
    /// Requested duration elapsed.
    DurationElapsed,
    /// Requested live-event count was reached.
    EventLimitReached,
    /// SIGINT or SIGTERM requested graceful shutdown.
    Signal,
    /// A long-running service was asked to stop normally.
    ServiceStop,
    /// Durable storage reached a configured global or reserved limit.
    StorageLimitReached,
    /// The collector sealed this session and continued in a new session directory.
    SessionRotated,
    /// Kernel boot identity changed while the collector was running.
    BootChanged,
}

/// Auditable Inspect adapter decision or a single authorized hit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct InspectObservation {
    /// Adapter identifier, for example `linker_so_load`.
    pub adapter: String,
    /// Whether a probe was actually attached.
    pub attached: bool,
    /// Whether a hit was observed.
    pub hit: bool,
    /// Target ELF path.
    pub library: String,
    /// Observed or required GNU build-id.
    pub build_id: Option<String>,
    /// File offset used for the uprobe, when attached.
    pub offset: Option<u64>,
    /// Best-effort argument string, such as a `dlopen` path.
    pub path_hint: Option<String>,
    /// Why attach was refused, revoked, or limited.
    pub detail: String,
    /// Operator-visible detectability statement.
    pub detectability_notice: String,
    /// Binder handle from `IPCThreadState::transact` x1 when the adapter recorded it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binder_handle: Option<u32>,
    /// Binder transaction code from x2. Not an AIDL name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binder_code: Option<u32>,
    /// Interface token from exported `Parcel::writeInterfaceToken` on the same TID, when paired.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binder_interface: Option<String>,
    /// AIDL method from the AOSP Stub table or a process DEX Stub. App names are never hardcoded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binder_method: Option<String>,
    /// `aosp_stub` or `process_dex`. Absent when the method is unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binder_method_source: Option<String>,
    /// Bounded UTF-16/UTF-8 strings from exported Parcel string writers on the same TID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binder_strings: Option<Vec<String>>,
    /// Last `Parcel::writeInt32` values on the same TID. Not Parcel object fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binder_ints: Option<Vec<i32>>,
    /// Last `Parcel::writeInt64` / `writeUint32` / `writeUint64` values on the same TID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binder_int64s: Option<Vec<i64>>,
    /// Last `Parcel::writeBool` values on the same TID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binder_bools: Option<Vec<bool>>,
    /// Last `Parcel::writeFileDescriptor` fds on the same TID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binder_fds: Option<Vec<i32>>,
    /// Bounded `Parcel::writeByteArray` previews (`len=` + hex) on the same TID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binder_blobs: Option<Vec<String>>,
    /// `IBinder*` from exported `Parcel::writeStrongBinder(sp<IBinder> const&)`.
    /// The 8-byte `sp` payload at x1; `IBinder` C++ fields are not read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binder_binders: Option<Vec<String>>,
}

/// Bounded plaintext copied from an authorized TLS write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InspectPlaintext {
    /// Adapter identifier, `tls_ssl_write`.
    pub adapter: String,
    /// `send` for `SSL_write`.
    pub direction: String,
    /// Target ELF path.
    pub library: String,
    /// Observed GNU build-id.
    pub build_id: Option<String>,
    /// File offset of the probe.
    pub offset: Option<u64>,
    /// Length argument supplied to `SSL_write`.
    pub requested_bytes: u64,
    /// Bytes actually copied into the event.
    pub captured_bytes: u32,
    /// True when `requested_bytes` exceeded the copy budget.
    pub truncated: bool,
    /// SHA-256 of the captured bytes, not of the unseen remainder.
    pub sha256: String,
    /// Lossy UTF-8 or hex preview of the captured bytes.
    pub preview: String,
    /// `utf8_lossy` or `hex`.
    pub preview_encoding: String,
    /// `text`, `tls_record`, or `binary`. TLS records are ciphertext, not HTTP.
    #[serde(default)]
    pub content_class: String,
}

/// End-of-session evidence used to distinguish complete execution from a broken capture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionCompletion {
    /// Normal stop condition.
    pub stop_reason: CaptureStopReason,
    /// True only when the event loop and durable flush completed normally.
    pub capture_complete: bool,
    /// Raw records consumed before normalization.
    pub raw_records: u64,
    /// Live kernel events retained after filtering.
    pub live_events: u64,
    /// Records rejected by ABI or semantic validation.
    pub invalid_records: u64,
    /// Events excluded by capture scope.
    pub filtered_scope: u64,
    /// Thread events excluded by presentation policy.
    pub filtered_threads: u64,
    /// Collector self-events excluded from whole-device evidence.
    #[serde(default)]
    pub filtered_collector: u64,
    /// Final per-sensor kernel ring-buffer drop counters.
    #[serde(default)]
    pub dropped_by_sensor: BTreeMap<SensorKind, u64>,
}

/// A change that makes an Android process identifiable after it was forked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessIdentityChange {
    /// Identity transition type.
    pub kind: ProcessIdentityChangeKind,
    /// Previous kernel task name for rename events.
    pub previous_comm: Option<String>,
}

/// Kind of runtime identity transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessIdentityChangeKind {
    /// Effective user or group credentials changed.
    Credentials,
    /// Kernel task name changed.
    Rename,
}

/// Process lifecycle transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessLifecycle {
    /// Transition type.
    pub kind: ProcessLifecycleKind,
    /// Parent PID where meaningful.
    pub parent_pid: Option<u32>,
    /// Executed filename where meaningful.
    pub filename: Option<String>,
    /// Exit code where meaningful.
    pub exit_code: Option<i32>,
    /// Zygote lineage when the fork parent was a recognized Zygote process.
    #[serde(default)]
    pub zygote_source: Option<String>,
}

/// Kind of process lifecycle transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessLifecycleKind {
    /// Process or thread creation.
    Fork,
    /// Image replacement by exec.
    Exec,
    /// Process or thread exit.
    Exit,
}
