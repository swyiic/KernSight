use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use ksight_model::{
    BaselineFdKind, BinderTransactionFlag, BinderTransactionStage, Event, EventPayload,
    FileDescriptorOperation, MemoryOperation, SensorKind, SocketIoOperation,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Data-quality totals for one normalized session report.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QualitySummary {
    /// Sum of source records explicitly reported lost before emitted events.
    pub lost_records: u64,
    /// Number of events carrying a truncation marker.
    pub truncated_events: u64,
    /// Truncated-event counts by stable capture source.
    #[serde(default)]
    pub truncated_by_source: BTreeMap<String, u64>,
    /// Explicit loss counts attributed to each sensor.
    #[serde(default)]
    pub lost_by_sensor: BTreeMap<SensorKind, u64>,
    /// Number of events emitted under a sampling rate greater than one.
    pub sampled_events: u64,
    /// Largest observed one-in-N sampling denominator.
    pub max_sample_one_in: u32,
    /// Number of payloads preserved without a known semantic decoder.
    pub opaque_events: u64,
}

/// Activity grouped by an Android package or unresolved process label.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessActivity {
    /// Best available application or process label.
    pub label: String,
    /// High-confidence Android package when resolved.
    pub package: Option<String>,
    /// Observed process IDs belonging to this group.
    pub process_ids: Vec<u32>,
    /// Distinct process instances (`boot_id:pid:start_time_ns`) in this group.
    #[serde(default)]
    pub instances: Vec<ProcessInstanceRef>,
    /// Total normalized events for this group.
    pub event_count: u64,
    /// Counts split by capture sensor.
    pub sensor_counts: BTreeMap<SensorKind, u64>,
}

/// One process instance that survives PID reuse within a boot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessInstanceRef {
    /// `boot_id:pid:start_time_ns`.
    pub process_instance_id: String,
    /// Device boot identifier.
    #[serde(default)]
    pub boot_id: Uuid,
    /// Linux process ID.
    pub pid: u32,
    /// Kernel monotonic start time in nanoseconds, or zero when unobserved.
    pub start_time_ns: u64,
}

/// Aggregated selected-process Inspect adapter activity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InspectHitActivity {
    /// Adapter identifier, for example `binder_userspace`.
    pub adapter: String,
    /// ELF that the adapter attached to, when known.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub library: String,
    /// Process ID that produced the hit.
    pub process_id: u32,
    /// Process instance id when start time was known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_instance_id: Option<String>,
    /// Whether the probe attached.
    pub attached: bool,
    /// Hit count in the report range.
    pub hits: u64,
    /// Last adapter detail string.
    pub last_detail: String,
    /// Binder handle from `IPCThreadState::transact` x1, when the adapter recorded it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binder_handle: Option<u32>,
    /// Binder transaction code from x2, when recorded. Not an AIDL method name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binder_code: Option<u32>,
    /// Interface token paired from `Parcel::writeInterfaceToken` on the same TID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binder_interface: Option<String>,
    /// AIDL method from the AOSP Stub table or a process DEX Stub.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binder_method: Option<String>,
    /// `aosp_stub` or `process_dex`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binder_method_source: Option<String>,
    /// Last transact's bounded Parcel string arguments on the same TID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binder_strings: Option<Vec<String>>,
    /// Last `writeInt32` values on the same TID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binder_ints: Option<Vec<i32>>,
    /// Last `writeInt64` / `writeUint32` / `writeUint64` values on the same TID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binder_int64s: Option<Vec<i64>>,
    /// Last `writeBool` values on the same TID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binder_bools: Option<Vec<bool>>,
    /// Last `writeFileDescriptor` values on the same TID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binder_fds: Option<Vec<i32>>,
    /// Last `writeByteArray` previews on the same TID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binder_blobs: Option<Vec<String>>,
    /// Last `writeStrongBinder` binder-object pointers on the same TID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binder_binders: Option<Vec<String>>,
    /// L0 Binder request `debug_id` joined by tid+code. Correlated, not the reply clock.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binder_transaction_id: Option<i32>,
    /// Kernel request-to-reply latency copied from the paired L0 reply, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_latency_ns: Option<u64>,
}

/// Aggregated Binder traffic between two process endpoints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinderRelation {
    /// Source process label.
    pub source: String,
    /// Source process ID.
    pub source_process_id: u32,
    /// Target process label when known.
    pub target: String,
    /// Target process ID when the Binder driver resolved it.
    pub target_process_id: Option<u32>,
    /// Non-reply transactions observed on this edge.
    pub requests: u64,
    /// Reply transactions observed on this edge.
    pub replies: u64,
    /// Interface-specific transaction codes and their counts.
    pub codes: BTreeMap<u32, u64>,
    /// Replies on this edge that named a request `debug_id`.
    #[serde(default)]
    pub paired_replies: u64,
    /// Interface tokens parsed from kernel parcel prefixes on this edge.
    #[serde(default)]
    pub interfaces: BTreeMap<String, u64>,
}

/// Aggregated code, system, or data path activity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactActivity {
    /// Conservative path-derived category.
    pub category: String,
    /// Observed path.
    pub path: String,
    /// File-open syscall attempts.
    pub open_attempts: u64,
    /// File-open attempts returning a descriptor.
    pub successful_opens: u64,
    /// File-open attempts returning a negative errno.
    pub failed_opens: u64,
    /// Memory-map or protection observations referencing the path.
    pub mappings: u64,
    /// SHA-256 of the opened regular file when it was hashed (DEX/ELF/forensic logs ≤ 1 MiB).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_sha256: Option<String>,
    /// Byte length that produced `content_sha256`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_bytes: Option<u64>,
}

/// Aggregated network connection target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkPeerActivity {
    /// Best available source label.
    pub source: String,
    /// Source process ID.
    pub source_process_id: u32,
    /// Numeric peer or bounded Unix socket name.
    pub peer: String,
    /// Network port when meaningful.
    pub port: Option<u16>,
    /// Connect events observed for this tuple.
    pub attempts: u64,
    /// Connect events whose syscall result was zero.
    pub successful: u64,
    /// Connect events that returned `EINPROGRESS` (-115).
    #[serde(default)]
    pub in_progress: u64,
    /// Inbound connections accepted from this peer.
    #[serde(default)]
    pub accepted: u64,
    /// Successfully submitted bytes associated with this observed peer descriptor.
    #[serde(default)]
    pub sent_bytes: u64,
    /// Successfully received bytes associated with this observed peer descriptor.
    #[serde(default)]
    pub received_bytes: u64,
    /// Messages completed by observed `sendmmsg` calls.
    #[serde(default)]
    pub sent_messages: u64,
    /// Messages completed by observed `recvmmsg` calls.
    #[serde(default)]
    pub received_messages: u64,
    /// DNS QNAME that answered this peer IP, when a UDP/53 datagram matched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_name: Option<String>,
    /// TLS `ClientHello` SNI observed on a first write of this flow.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    /// TLS ALPN list observed on a first write of this flow.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,
    /// HTTP `Host` header from a cleartext first write.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_host: Option<String>,
    /// HTTP method from a cleartext first write.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_method: Option<String>,
    /// `tls`, `http`, `quic`, or a comma-joined mix when more than one kind was seen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handshake_kind: Option<String>,
}

/// One QNAME observed on UDP/53, with any A/AAAA answers copied from the datagram.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsNameActivity {
    /// Process that issued or received the datagram.
    pub process_id: u32,
    /// First question name, lowercased.
    pub qname: String,
    /// A/AAAA presentation strings from the same message.
    #[serde(default)]
    pub addresses: Vec<String>,
}

/// One first-write handshake observation (TLS `ClientHello`, HTTP/1, or QUIC long header).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeNameActivity {
    /// Process that issued the first write.
    pub process_id: u32,
    /// `tls`, `http`, or `quic`.
    pub kind: String,
    /// TLS SNI, when parsed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    /// TLS ALPN, when parsed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,
    /// HTTP `Host`, when parsed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_host: Option<String>,
    /// HTTP method, when parsed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_method: Option<String>,
    /// Peer address copied from sendto/sendmsg, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
    /// Peer port copied from sendto/sendmsg, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

/// File-descriptor lifecycle consistency within the observed session.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FdLifecycleSummary {
    /// True when at least one close/dup/rights event proves that FD lifecycle
    /// collection was enabled for this session.
    #[serde(default)]
    pub lineage_observed: bool,
    /// Successful opens that returned a descriptor.
    pub successful_opens: u64,
    /// Successful close operations.
    pub successful_closes: u64,
    /// Successful duplication operations.
    pub successful_duplicates: u64,
    /// Failed close or duplication operations.
    pub failed_operations: u64,
    /// Successful closes for descriptors whose origin was not observed.
    pub closes_without_observed_origin: u64,
    /// Successful duplications whose source descriptor was not observed.
    pub duplicates_without_observed_origin: u64,
    /// Descriptor instances still known at the end of the report range.
    pub active_at_end: u64,
    /// False when sampling, loss, or missing origins prevent a complete lineage claim.
    pub lineage_complete: bool,
    /// Successful `close_range` syscalls that actually closed descriptors.
    #[serde(default)]
    pub successful_close_ranges: u64,
}

/// A dump-package catalog joined into an L0 session report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergedDumpRef {
    /// Android package name.
    pub package: String,
    /// dump-package UUID. Distinct from the capture session id.
    pub dump_id: String,
}

/// One observed virtual-memory interval from L0 mmap/remap or a VMA baseline.
///
/// Unmap does not remove these rows. Dump VMA overlap uses the full observed set and is
/// always correlated: a later snapshot does not prove the mapping existed at mmap time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedMapping {
    /// Process that owned the interval.
    pub process_id: u32,
    /// Inclusive start address.
    pub start: u64,
    /// Exclusive end address.
    pub end: u64,
    /// Backing path when the syscall or baseline recorded one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backing_path: Option<String>,
    /// How this interval was observed.
    pub source: MappingSource,
    /// Per-process mmap generation. Zero when the interval came from a snapshot.
    #[serde(default)]
    pub mapping_generation: u32,
}

/// Origin of an [`ObservedMapping`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MappingSource {
    /// Successful `mmap` or `mremap` syscall.
    Mmap,
    /// Session-start `/proc/<pid>/maps` baseline.
    VmaBaseline,
    /// Dump-time `/proc/<pid>/maps` snapshot. Not an L0 mmap syscall.
    ProcMaps,
}

impl MappingSource {
    /// Stable graph-key prefix for this origin.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mmap => "mmap",
            Self::VmaBaseline => "vma_baseline",
            Self::ProcMaps => "proc_maps",
        }
    }
}

impl ObservedMapping {
    /// Graph entity key: `{source}:{pid}:{start:x}-{end:x}`.
    #[must_use]
    pub fn graph_key(&self) -> String {
        format!(
            "{}:{}:{:x}-{:x}",
            self.source.as_str(),
            self.process_id,
            self.start,
            self.end
        )
    }

    /// Half-open interval overlap. Degenerate ranges never overlap.
    #[must_use]
    pub fn overlaps(&self, start: u64, end: u64) -> bool {
        crate::graph::ranges_overlap(self.start, self.end, start, end)
    }
}

/// Rank mappings so dump/L0 join keeps mmap facts and large heaps instead of the lowest addresses.
pub fn rank_observed_mappings(mappings: &mut [ObservedMapping]) {
    mappings.sort_by(|left, right| {
        mapping_keep_score(right)
            .cmp(&mapping_keep_score(left))
            .then(left.process_id.cmp(&right.process_id))
            .then(left.start.cmp(&right.start))
    });
}

fn mapping_keep_score(mapping: &ObservedMapping) -> (u8, u8, u64) {
    let source = match mapping.source {
        MappingSource::Mmap => 2,
        MappingSource::VmaBaseline | MappingSource::ProcMaps => 1,
    };
    let path = mapping.backing_path.as_deref().unwrap_or("");
    let interesting =
        if path.contains("scudo") || path.contains("dex") || path.contains("code_cache") {
            2
        } else {
            u8::from(path.is_empty())
        };
    let size = mapping.end.saturating_sub(mapping.start);
    (source, interesting, size)
}

/// Virtual-memory lifecycle totals within the observed session.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryLifecycleSummary {
    /// Successful mapping operations.
    pub successful_maps: u64,
    /// Successful protection changes.
    pub successful_protects: u64,
    /// Successful unmap operations.
    pub successful_unmaps: u64,
    /// Requested bytes across successful maps.
    pub mapped_bytes: u64,
    /// Requested bytes across successful unmaps.
    pub unmapped_bytes: u64,
    /// Failed map, protect, or unmap operations.
    pub failed_operations: u64,
    /// Unmaps overlapping at least one mapping observed in this report range.
    pub unmaps_with_observed_mapping: u64,
    /// Unmaps whose origin predates or falls outside retained evidence.
    pub unmaps_without_observed_mapping: u64,
    /// Mapping intervals still known at the end of the report range.
    pub active_regions_at_end: u64,
    /// Successful `mremap` operations.
    #[serde(default)]
    pub successful_remaps: u64,
    /// Successful `brk` adjustments.
    #[serde(default)]
    pub successful_brk: u64,
}

/// Binder driver lifecycle pairing totals.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinderLifecycleSummary {
    /// Submitted transaction events.
    pub submitted: u64,
    /// Delivery events matched to a submitted transaction ID.
    pub delivered: u64,
    /// Buffer-allocation events matched to a submitted transaction ID.
    pub buffers_observed: u64,
    /// Delivery events whose submission was outside the retained evidence.
    pub delivery_without_submission: u64,
    /// Buffer events whose submission was outside the retained evidence.
    pub buffer_without_submission: u64,
    /// Sum of driver-observed Parcel data bytes.
    pub parcel_data_bytes: u64,
    /// Source descriptors attached to tracked transactions.
    pub file_descriptors_sent: u64,
    /// Destination descriptors installed from tracked transactions.
    pub file_descriptors_received: u64,
    /// FD transfer stages without a retained submission event.
    pub fd_transfer_without_submission: u64,
    /// Minimum submitted-to-delivered latency.
    pub minimum_delivery_ns: Option<u64>,
    /// Maximum submitted-to-delivered latency.
    pub maximum_delivery_ns: Option<u64>,
    /// Integer average submitted-to-delivered latency.
    pub average_delivery_ns: Option<u64>,
    /// Two-way (not `TF_ONE_WAY`) request submissions.
    #[serde(default)]
    pub two_way_submitted: u64,
    /// One-way request submissions.
    #[serde(default)]
    pub one_way_submitted: u64,
    /// Reply submissions (`reply=true`).
    #[serde(default)]
    pub reply_submitted: u64,
    /// Replies whose `reply_to_request_id` matched a retained request.
    #[serde(default)]
    pub paired_replies: u64,
    /// Reply submissions with no matching request `debug_id`.
    #[serde(default)]
    pub reply_without_request: u64,
    /// Minimum request-submit to reply-submit latency for paired replies.
    #[serde(default)]
    pub minimum_reply_ns: Option<u64>,
    /// Maximum request-submit to reply-submit latency for paired replies.
    #[serde(default)]
    pub maximum_reply_ns: Option<u64>,
    /// Integer average paired request-to-reply latency.
    #[serde(default)]
    pub average_reply_ns: Option<u64>,
}

/// One two-way Binder RPC whose reply named the request `debug_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinderReplyPair {
    /// Client request transaction identifier.
    pub request_transaction_id: i32,
    /// Server reply transaction identifier.
    pub reply_transaction_id: i32,
    /// Process that submitted the request.
    pub client_process_id: u32,
    /// Process that submitted the reply.
    pub server_process_id: u32,
    /// Transaction code from the request.
    pub code: u32,
    /// Request-submit to reply-submit latency in nanoseconds.
    pub latency_ns: u64,
}

/// One Binder-transferred file descriptor paired from send to receive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinderFdTransfer {
    /// Driver transaction identifier that carried the descriptor.
    pub transaction_id: i32,
    /// Sending process.
    pub source_process_id: u32,
    /// Descriptor number on the sender.
    pub source_fd: i32,
    /// Receiving process.
    pub target_process_id: u32,
    /// Descriptor number installed on the receiver.
    pub target_fd: i32,
    /// Best-effort origin path or socket peer of the sender descriptor.
    pub origin: String,
}

/// Socket descriptor lifetime reconstructed from connect and FD events.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SocketLifecycleSummary {
    /// Connect syscalls observed.
    pub connect_attempts: u64,
    /// Successful or asynchronously in-progress connects associated with an FD.
    pub connected_or_in_progress: u64,
    /// Inbound accept/accept4 syscalls observed.
    pub accept_attempts: u64,
    /// Accept operations that produced a connected descriptor.
    pub accepted_descriptors: u64,
    /// Explicit socket send syscalls observed under `network-io` policy.
    pub send_calls: u64,
    /// Explicit socket receive syscalls observed under `network-io` policy.
    pub receive_calls: u64,
    /// Successful bytes submitted by observed socket I/O syscalls.
    pub sent_bytes: u64,
    /// Successful bytes returned by observed socket I/O syscalls.
    pub received_bytes: u64,
    /// Messages completed by observed `sendmmsg` calls.
    #[serde(default)]
    pub sent_messages: u64,
    /// Messages completed by observed `recvmmsg` calls.
    #[serde(default)]
    pub received_messages: u64,
    /// Socket I/O syscalls returning a negative errno.
    pub failed_io: u64,
    /// Socket I/O events whose connect/accept origin was outside retained evidence.
    pub io_without_observed_lifecycle: u64,
    /// Connected socket descriptors duplicated through FD operations.
    pub duplicated_descriptors: u64,
    /// Connected socket descriptors closed during the report range.
    pub closed_descriptors: u64,
    /// Connected socket descriptors still known at the end of the report range.
    pub active_at_end: u64,
}

/// Deterministic, presentation-neutral aggregation of one capture session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionReport {
    /// Versioned report document consumed by CLI and `MobileE`.
    pub schema_version: String,
    /// Session identifier from the first event.
    pub session_id: Option<Uuid>,
    /// True when input unexpectedly contained more than one session identifier.
    pub mixed_sessions: bool,
    /// Total events consumed.
    pub total_events: u64,
    /// First observed monotonic timestamp.
    pub first_monotonic_ns: Option<u64>,
    /// Last observed monotonic timestamp.
    pub last_monotonic_ns: Option<u64>,
    /// Per-sensor event totals.
    pub sensor_counts: BTreeMap<SensorKind, u64>,
    /// Capture-mode totals using stable serialized names.
    pub mode_counts: BTreeMap<String, u64>,
    /// Loss, truncation, sampling, and opaque payload summary.
    pub quality: QualitySummary,
    /// Latest observed environment that may alter target behavior.
    pub environment: Option<ksight_model::SessionEnvironment>,
    /// Number of material environment state changes observed after session
    /// start (for example a lab workflow toggling ADB settings).
    #[serde(default)]
    pub environment_transitions: u64,
    /// Normal termination evidence, absent after crashes or forced termination.
    pub completion: Option<ksight_model::SessionCompletion>,
    /// True when completion was recorded without kernel drops or invalid records.
    pub execution_complete: bool,
    /// Application and unresolved-process groups, descending by activity.
    pub processes: Vec<ProcessActivity>,
    /// Binder edges, descending by total transactions.
    pub binder_relations: Vec<BinderRelation>,
    /// Interesting paths, descending by observations.
    pub artifacts: Vec<ArtifactActivity>,
    /// Network targets, descending by attempts.
    pub network_peers: Vec<NetworkPeerActivity>,
    /// UDP/53 datagrams copied this session.
    #[serde(default)]
    pub dns_datagrams: u64,
    /// Distinct QNAMEs parsed from those datagrams.
    #[serde(default)]
    pub dns_names: Vec<DnsNameActivity>,
    /// First-write handshake copies this session.
    #[serde(default)]
    pub handshake_events: u64,
    /// Distinct handshake names (SNI / HTTP Host / QUIC Initial) parsed from those copies.
    #[serde(default)]
    pub handshake_names: Vec<HandshakeNameActivity>,
    /// File-descriptor lifetime consistency.
    pub fd_lifecycle: FdLifecycleSummary,
    /// Memory-region syscall lifetime totals.
    pub memory_lifecycle: MemoryLifecycleSummary,
    /// Observed mapping intervals retained for dump VMA join. Unmap does not drop them.
    #[serde(default)]
    pub observed_mappings: Vec<ObservedMapping>,
    /// Binder transaction delivery and buffer correlation.
    pub binder_lifecycle: BinderLifecycleSummary,
    /// Source-to-destination descriptor transfers paired by transaction ID.
    #[serde(default)]
    pub binder_fd_transfers: Vec<BinderFdTransfer>,
    /// Two-way RPCs whose reply named the request `debug_id` (bounded).
    #[serde(default)]
    pub binder_reply_pairs: Vec<BinderReplyPair>,
    /// Socket connect-to-close reconstruction through process FD identity.
    pub socket_lifecycle: SocketLifecycleSummary,
    /// Aggregated scoped wakeup counts, descending by frequency.
    #[serde(default)]
    pub sched_wakeups: Vec<SchedWakeupActivity>,
    /// Bounded TLS plaintext fragments from Inspect `SSL_write`.
    #[serde(default)]
    pub plaintext: Vec<PlaintextActivity>,
    /// HTTP/1, HTTP/2 HPACK, JSON, and embedded URL rows parsed from Inspect previews. Token values are redacted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub http_calls: Vec<HttpCallActivity>,
    /// DEX strings/methods that name the same host or path. Correlated, not JNI execution.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub http_code_refs: Vec<HttpCodeRef>,
    /// Selected-process Inspect adapter attach/hit summaries. Never Observe events.
    #[serde(default)]
    pub inspect_hits: Vec<InspectHitActivity>,
    /// Collapsed loopback connect storms (for example 127.0.0.1:20000-29999).
    #[serde(default)]
    pub loopback_scans: Vec<LoopbackScanActivity>,
    /// dump-package catalogs merged into this session graph.
    #[serde(default)]
    pub merged_dumps: Vec<MergedDumpRef>,
    /// L0 entity/edge reconstruction. Time proximity is never a confirmed edge.
    #[serde(default)]
    pub graph: crate::SessionGraph,
    /// Semantic limits that apply to this report.
    pub limitations: Vec<String>,
}

/// Aggregated scheduler wakeup edge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedWakeupActivity {
    /// Waker process label.
    pub waker: String,
    /// Waker thread-group ID.
    pub waker_process_id: u32,
    /// Woken thread ID.
    pub wakee_tid: u32,
    /// Observed wakeup count in the report range.
    pub count: u64,
}

/// Aggregated bounded TLS plaintext from one process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlaintextActivity {
    /// Process label.
    pub source: String,
    /// Process ID.
    pub process_id: u32,
    /// Inspect adapter.
    pub adapter: String,
    /// `send` for `SSL_write`, `recv` for `SSL_read`.
    pub direction: String,
    /// Number of captured writes.
    pub count: u64,
    /// Sum of requested `SSL_write` lengths.
    pub requested_bytes: u64,
    /// Sum of bytes actually copied.
    pub captured_bytes: u64,
    /// Sample SHA-256 digests of captured fragments.
    pub sha256_samples: Vec<String>,
    /// Best URL/JSON/HTTP preview retained for operator triage.
    pub preview: Option<String>,
    /// `http(s)://` hosts and paths taken from every fragment, not only the kept preview.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub urls: Vec<String>,
    /// Dominant `content_class`: `text`, `tls_record`, or `binary`.
    #[serde(default)]
    pub content_class: String,
}

/// One HTTP/1, HTTP/2 HPACK, JSON, or URL row aggregated from Inspect/heap plaintext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpCallActivity {
    /// Process label.
    pub source: String,
    /// Process ID.
    pub process_id: u32,
    /// `send` for `SSL_write`, `recv` for `SSL_read`.
    pub direction: String,
    /// `http1_request`, `http1_response`, `http2_request`, `http2_response`, `json`, or `url`.
    pub kind: String,
    /// `GET` / `POST` / `HTTP` / `PRI` / `JSON`.
    pub method: String,
    /// Host header, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Path without query.
    pub path: String,
    /// Response status, when this is a response line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// Query parameter names, in first-seen order.
    #[serde(default)]
    pub query_keys: Vec<String>,
    /// Header names as they appeared.
    #[serde(default)]
    pub header_names: Vec<String>,
    /// Sensitive headers as `Name=[REDACTED]`.
    #[serde(default)]
    pub redacted_headers: Vec<String>,
    /// Form/JSON body keys.
    #[serde(default)]
    pub body_keys: Vec<String>,
    /// Sensitive body keys that were redacted.
    #[serde(default)]
    pub redacted_body_keys: Vec<String>,
    /// Content-Type, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// True when the host looks like ads/risk/telemetry rather than app API.
    #[serde(default)]
    pub third_party: bool,
    /// Number of matching Inspect previews.
    pub count: u64,
    /// `inspect` from TLS buffers, `heap` from dump plaintext windows.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub origin: String,
}

/// Correlated DEX string/method that names the same host or path as an HTTP call.
///
/// This is dump-side string matching, not an ART/JNI execution trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpCodeRef {
    /// HTTP method from the catalog.
    pub http_method: String,
    /// Host, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Path or empty for responses.
    pub path: String,
    /// DEX SHA-256 that contained the match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dex_sha256: Option<String>,
    /// Evidence path of that DEX.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relative_path: Option<String>,
    /// Matching DEX API strings or `class->method` names.
    #[serde(default)]
    pub matches: Vec<String>,
}

/// Collapsed connect storm against loopback ports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoopbackScanActivity {
    /// Process label.
    pub source: String,
    /// Process ID.
    pub process_id: u32,
    /// Loopback address.
    pub address: String,
    /// Lowest observed port.
    pub port_min: u16,
    /// Highest observed port.
    pub port_max: u16,
    /// Distinct destination ports.
    pub unique_ports: u64,
    /// Connect attempts in the scan.
    pub attempts: u64,
}

/// Incremental builder for [`SessionReport`].
#[derive(Debug, Default)]
pub struct SessionReportBuilder {
    session_id: Option<Uuid>,
    mixed_sessions: bool,
    total_events: u64,
    first_monotonic_ns: Option<u64>,
    last_monotonic_ns: Option<u64>,
    sensor_counts: BTreeMap<SensorKind, u64>,
    mode_counts: BTreeMap<String, u64>,
    quality: QualitySummary,
    environment: Option<ksight_model::SessionEnvironment>,
    environment_transitions: u64,
    completion: Option<ksight_model::SessionCompletion>,
    identities: BTreeMap<u32, ObservedIdentity>,
    processes: BTreeMap<String, MutableProcessActivity>,
    binder: BTreeMap<(u32, Option<u32>), MutableBinderRelation>,
    artifacts: BTreeMap<(String, String), MutableArtifactActivity>,
    network: BTreeMap<(u32, String, Option<u16>), MutableNetworkPeerActivity>,
    active_fds: BTreeSet<(u32, i32)>,
    fd_lifecycle: FdLifecycleSummary,
    memory_lifecycle: MemoryLifecycleSummary,
    memory_regions: BTreeMap<(u32, u64), u64>,
    observed_spans: BTreeMap<(u32, u64, u64), ObservedMapping>,
    binder_transactions: BTreeMap<i32, MutableBinderTransaction>,
    binder_lifecycle: BinderLifecycleSummary,
    binder_latency_total_ns: u64,
    binder_fd_transfers: Vec<BinderFdTransfer>,
    binder_reply_pairs: Vec<BinderReplyPair>,
    binder_reply_latency_total_ns: u64,
    socket_fds: BTreeSet<(u32, i32)>,
    socket_peers: BTreeMap<(u32, i32), (String, Option<u16>)>,
    sched_wakeups: BTreeMap<(u32, u32), u64>,
    plaintext: BTreeMap<(u32, String, String), MutablePlaintext>,
    http_calls: BTreeMap<HttpCallKey, MutableHttpCall>,
    inspect_hits: BTreeMap<(u32, String, String), MutableInspectHit>,
    pending_inspect_transacts: HashMap<(u32, u32), VecDeque<u32>>,
    unmatched_binder_submits: HashMap<(u32, u32), VecDeque<i32>>,
    inspect_joined_txns: HashMap<i32, u32>,
    mapping_generations: BTreeMap<u32, u32>,
    socket_lifecycle: SocketLifecycleSummary,
    dns_datagrams: u64,
    dns_names: BTreeMap<(u32, String), BTreeSet<String>>,
    dns_by_ip: BTreeMap<(u32, String), String>,
    dns_by_ip_global: BTreeMap<String, String>,
    handshake_events: u64,
    handshake_names: Vec<HandshakeNameActivity>,
    handshake_by_fd: BTreeMap<(u32, i32), MutableHandshake>,
    http2: BTreeMap<(u32, String, String), crate::http2::Http2Assembler>,
}

#[derive(Debug, Default)]
struct MutableInspectHit {
    attached: bool,
    hits: u64,
    last_detail: String,
    process_instance_id: Option<String>,
    binder_handle: Option<u32>,
    binder_code: Option<u32>,
    binder_interface: Option<String>,
    binder_method: Option<String>,
    binder_method_source: Option<String>,
    binder_strings: Option<Vec<String>>,
    binder_ints: Option<Vec<i32>>,
    binder_int64s: Option<Vec<i64>>,
    binder_bools: Option<Vec<bool>>,
    binder_fds: Option<Vec<i32>>,
    binder_blobs: Option<Vec<String>>,
    binder_binders: Option<Vec<String>>,
    binder_transaction_id: Option<i32>,
    reply_latency_ns: Option<u64>,
}

#[derive(Debug, Default)]
struct MutablePlaintext {
    count: u64,
    requested_bytes: u64,
    captured_bytes: u64,
    sha256_samples: Vec<String>,
    preview: Option<String>,
    urls: Vec<String>,
    content_class: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct HttpCallKey {
    process_id: u32,
    direction: String,
    origin: String,
    kind: String,
    method: String,
    host: String,
    path: String,
}

#[derive(Debug, Default)]
struct MutableHttpCall {
    status: Option<u16>,
    query_keys: Vec<String>,
    header_names: Vec<String>,
    redacted_headers: Vec<String>,
    body_keys: Vec<String>,
    redacted_body_keys: Vec<String>,
    content_type: Option<String>,
    third_party: bool,
    count: u64,
}

#[derive(Debug, Default)]
struct ObservedIdentity {
    comm: String,
    command_line: Option<String>,
    package: Option<String>,
}

#[derive(Debug, Default)]
struct MutableProcessActivity {
    package: Option<String>,
    process_ids: BTreeSet<u32>,
    instances: BTreeMap<(u32, u64), ProcessInstanceRef>,
    event_count: u64,
    sensor_counts: BTreeMap<SensorKind, u64>,
}

#[derive(Debug, Default)]
struct MutableBinderRelation {
    requests: u64,
    replies: u64,
    paired_replies: u64,
    codes: BTreeMap<u32, u64>,
    interfaces: BTreeMap<String, u64>,
}

#[derive(Debug, Default)]
struct MutableArtifactActivity {
    open_attempts: u64,
    successful_opens: u64,
    failed_opens: u64,
    mappings: u64,
    content_sha256: Option<String>,
    content_bytes: Option<u64>,
}

#[derive(Debug, Default)]
struct MutableNetworkPeerActivity {
    attempts: u64,
    successful: u64,
    in_progress: u64,
    accepted: u64,
    sent_bytes: u64,
    received_bytes: u64,
    sent_messages: u64,
    received_messages: u64,
    resolved_name: Option<String>,
    sni: Option<String>,
    alpn: Option<String>,
    http_host: Option<String>,
    http_method: Option<String>,
    handshake_kind: Option<String>,
}

#[derive(Debug, Default, Clone)]
struct MutableHandshake {
    kind: String,
    sni: Option<String>,
    alpn: Option<String>,
    http_host: Option<String>,
    http_method: Option<String>,
}

#[derive(Debug, Default)]
struct MutableBinderTransaction {
    submitted_ns: u64,
    delivered: bool,
    buffer_observed: bool,
    source_pid: u32,
    code: u32,
    two_way: bool,
    interface_token: Option<String>,
    binder_method: Option<String>,
}

impl SessionReportBuilder {
    /// Add one normalized event to this report.
    #[allow(clippy::too_many_lines)]
    pub fn record(&mut self, event: &Event) {
        let header = &event.header;
        match self.session_id {
            None => self.session_id = Some(header.session_id),
            Some(session_id) if session_id != header.session_id => self.mixed_sessions = true,
            Some(_) => {}
        }
        self.total_events += 1;
        self.first_monotonic_ns = Some(
            self.first_monotonic_ns
                .map_or(header.monotonic_ns, |value| value.min(header.monotonic_ns)),
        );
        self.last_monotonic_ns = Some(
            self.last_monotonic_ns
                .map_or(header.monotonic_ns, |value| value.max(header.monotonic_ns)),
        );
        *self.sensor_counts.entry(header.sensor).or_default() += 1;
        *self
            .mode_counts
            .entry(mode_name(header.mode).to_owned())
            .or_default() += 1;
        self.record_quality(event);

        match &event.payload {
            EventPayload::SessionEnvironment(environment) => {
                if self
                    .environment
                    .as_ref()
                    .is_some_and(|previous| !same_environment_state(previous, environment))
                {
                    self.environment_transitions = self.environment_transitions.saturating_add(1);
                }
                self.environment = Some(environment.clone());
                return;
            }
            EventPayload::SessionCompletion(completion) => {
                for (sensor, count) in &completion.dropped_by_sensor {
                    *self.quality.lost_by_sensor.entry(*sensor).or_default() += count;
                    self.quality.lost_records = self.quality.lost_records.saturating_add(*count);
                }
                self.completion = Some(completion.clone());
                return;
            }
            _ => {}
        }

        let pid = header.process.tgid;
        let package = best_package(event);
        let label = package.clone().unwrap_or_else(|| fallback_label(event));
        self.identities.insert(
            pid,
            ObservedIdentity {
                comm: header.process.comm.clone(),
                command_line: header.process.command_line.clone(),
                package: package.clone(),
            },
        );
        let activity = self.processes.entry(label).or_default();
        activity.package = package;
        activity.process_ids.insert(pid);
        let start_time_ns = header.process.key.start_time_ns;
        let boot_id = header.process.key.boot_id;
        activity
            .instances
            .entry((pid, start_time_ns))
            .or_insert_with(|| ProcessInstanceRef {
                process_instance_id: format!("{boot_id}:{pid}:{start_time_ns}"),
                boot_id,
                pid,
                start_time_ns,
            });
        activity.event_count += 1;
        *activity.sensor_counts.entry(header.sensor).or_default() += 1;

        match &event.payload {
            EventPayload::BinderTransaction(transaction) => {
                self.record_binder(event, transaction, pid);
            }
            EventPayload::FileOpen(open) => {
                let path = open.resolved_path.as_deref().unwrap_or(&open.path);
                let category = path_category(path);
                let activity = self
                    .artifacts
                    .entry((category.to_owned(), path.to_owned()))
                    .or_default();
                activity.open_attempts += 1;
                if open.result >= 0 {
                    activity.successful_opens += 1;
                } else {
                    activity.failed_opens += 1;
                }
                if activity.content_sha256.is_none() {
                    if let Some(digest) = open.content_sha256.clone() {
                        activity.content_sha256 = Some(digest);
                        activity.content_bytes = open.content_bytes;
                    }
                }
                if let Some(fd) = open.file_descriptor.filter(|_| open.result >= 0) {
                    self.fd_lifecycle.successful_opens += 1;
                    self.active_fds.insert((pid, fd));
                }
            }
            EventPayload::FileDescriptorChange(change) => {
                self.fd_lifecycle.lineage_observed = true;
                self.record_fd(pid, change);
            }
            EventPayload::MemoryRegionChange(change) => {
                self.record_memory(pid, change);
                if let Some(path) = change.backing_path.as_deref() {
                    let category = path_category(path);
                    self.artifacts
                        .entry((category.to_owned(), path.to_owned()))
                        .or_default()
                        .mappings += 1;
                }
            }
            EventPayload::SocketConnect(connect) => self.record_socket_connect(pid, connect),
            EventPayload::SocketAccept(accept) => self.record_socket_accept(pid, accept),
            EventPayload::SocketIo(io) => self.record_socket_io(pid, io),
            EventPayload::DnsDatagram(datagram) => self.record_dns(pid, datagram),
            EventPayload::NetworkHandshake(handshake) => self.record_handshake(pid, handshake),
            EventPayload::SessionFdBaseline(baseline) => {
                self.record_fd_baseline(baseline);
            }
            EventPayload::SessionVmaBaseline(baseline) => {
                self.record_vma_baseline(baseline);
            }
            EventPayload::SchedWakeup(wakeup) => {
                *self
                    .sched_wakeups
                    .entry((pid, wakeup.wakee_tid))
                    .or_default() += 1;
            }
            EventPayload::InspectPlaintext(fragment) => {
                let (preview, class) = decode_inspect_preview(fragment);
                let activity = self
                    .plaintext
                    .entry((pid, fragment.adapter.clone(), fragment.direction.clone()))
                    .or_default();
                activity.count += 1;
                activity.requested_bytes += fragment.requested_bytes;
                activity.captured_bytes += u64::from(fragment.captured_bytes);
                if activity.sha256_samples.len() < 8 {
                    activity.sha256_samples.push(fragment.sha256.clone());
                }
                absorb_plaintext_preview(activity, &preview, &class);
                if activity.content_class.is_empty() {
                    activity.content_class.clone_from(&class);
                } else if activity.content_class != class {
                    "mixed".clone_into(&mut activity.content_class);
                }
                let inspect = self
                    .inspect_hits
                    .entry((pid, fragment.adapter.clone(), fragment.library.clone()))
                    .or_default();
                inspect.attached = true;
                inspect.hits = inspect.hits.saturating_add(1);
                if inspect.last_detail.is_empty() && !preview.is_empty() {
                    inspect.last_detail = format!(
                        "{} {} class={} {}",
                        fragment.adapter,
                        fragment.direction,
                        class,
                        preview.replace('\n', " ")
                    );
                    inspect.last_detail.truncate(240);
                }
                let raw = inspect_preview_bytes(fragment);
                let inflated = crate::inflate_inspect_buffer(&raw).unwrap_or(raw);
                let h2_key = (pid, fragment.adapter.clone(), fragment.direction.clone());
                let continue_h2 = self.http2.contains_key(&h2_key);
                if class != "tls_record"
                    && !inflated.is_empty()
                    && (continue_h2 || crate::http2::looks_like_http2(&inflated))
                {
                    let parsed_h2 = self.http2.entry(h2_key).or_default().push(&inflated);
                    for parsed in parsed_h2 {
                        if parsed.kind == "http2_preface" {
                            continue;
                        }
                        if parsed.kind == "http2_request" {
                            if let Some(url) = crate::format_inspect_url(
                                parsed.scheme.or(Some("https")),
                                parsed.host.as_deref().unwrap_or(""),
                                &parsed.path,
                            ) {
                                if let Some(plain) = self.plaintext.get_mut(&(
                                    pid,
                                    fragment.adapter.clone(),
                                    fragment.direction.clone(),
                                )) {
                                    extend_unique(&mut plain.urls, std::slice::from_ref(&url), 32);
                                }
                            }
                        }
                        self.record_http_call(pid, &fragment.direction, "inspect", parsed);
                    }
                }
                for parsed in crate::parse_http_plain_all(&preview, &class) {
                    if parsed.kind.starts_with("http2") {
                        continue;
                    }
                    if parsed.kind == "url"
                        && crate::format_inspect_url(
                            parsed.scheme,
                            parsed.host.as_deref().unwrap_or(""),
                            &parsed.path,
                        )
                        .is_none()
                    {
                        continue;
                    }
                    self.record_http_call(pid, &fragment.direction, "inspect", parsed);
                }
            }
            EventPayload::InspectObservation(observation) => {
                {
                    let activity = self
                        .inspect_hits
                        .entry((
                            pid,
                            observation.adapter.clone(),
                            observation.library.clone(),
                        ))
                        .or_default();
                    activity.attached |= observation.attached;
                    if observation.hit {
                        activity.hits = activity.hits.saturating_add(1);
                    }
                    if !observation.detail.is_empty() {
                        activity.last_detail.clone_from(&observation.detail);
                    }
                    activity.process_instance_id = Some(format!(
                        "{}:{pid}:{}",
                        header.process.key.boot_id, header.process.key.start_time_ns
                    ));
                    if observation.binder_handle.is_some() {
                        activity.binder_handle = observation.binder_handle;
                    }
                    if observation.binder_code.is_some() {
                        activity.binder_code = observation.binder_code;
                    }
                    if observation.binder_interface.is_some() {
                        activity
                            .binder_interface
                            .clone_from(&observation.binder_interface);
                    }
                    if observation.binder_method.is_some() {
                        activity
                            .binder_method
                            .clone_from(&observation.binder_method);
                    }
                    if observation.binder_method_source.is_some() {
                        activity
                            .binder_method_source
                            .clone_from(&observation.binder_method_source);
                    }
                    if observation.binder_strings.is_some() {
                        activity
                            .binder_strings
                            .clone_from(&observation.binder_strings);
                    }
                    if observation.binder_ints.is_some() {
                        activity.binder_ints.clone_from(&observation.binder_ints);
                    }
                    if observation.binder_fds.is_some() {
                        activity.binder_fds.clone_from(&observation.binder_fds);
                    }
                    if observation.binder_blobs.is_some() {
                        activity.binder_blobs.clone_from(&observation.binder_blobs);
                    }
                    if observation.binder_binders.is_some() {
                        activity
                            .binder_binders
                            .clone_from(&observation.binder_binders);
                    }
                    if observation.binder_int64s.is_some() {
                        activity
                            .binder_int64s
                            .clone_from(&observation.binder_int64s);
                    }
                    if observation.binder_bools.is_some() {
                        activity.binder_bools.clone_from(&observation.binder_bools);
                    }
                }
                if observation.hit && observation.adapter == "binder_userspace" {
                    if let Some(code) = observation.binder_code {
                        self.join_inspect_binder(pid, header.process.tid, code);
                    }
                }
            }
            EventPayload::ProcessLifecycle(_)
            | EventPayload::ProcessIdentityChange(_)
            | EventPayload::SessionEnvironment(_)
            | EventPayload::SessionCompletion(_)
            | EventPayload::Opaque { .. } => {}
        }
    }

    fn record_fd_baseline(&mut self, baseline: &ksight_model::SessionFdBaseline) {
        for entry in &baseline.fds {
            self.active_fds.insert((baseline.process_id, entry.fd));
            if entry.kind == BaselineFdKind::Socket {
                self.socket_fds.insert((baseline.process_id, entry.fd));
            }
        }
    }

    fn record_vma_baseline(&mut self, baseline: &ksight_model::SessionVmaBaseline) {
        for region in &baseline.vmas {
            if region.end <= region.start {
                continue;
            }
            self.memory_regions
                .insert((baseline.process_id, region.start), region.end);
            self.note_observed_span(
                baseline.process_id,
                region.start,
                region.end,
                MappingSource::VmaBaseline,
                region.path.clone(),
            );
            if let Some(path) = region.path.as_deref() {
                self.artifacts
                    .entry((path_category(path).to_owned(), path.to_owned()))
                    .or_default()
                    .mappings += 1;
            }
        }
    }

    fn record_dns(&mut self, pid: u32, datagram: &ksight_model::DnsDatagram) {
        self.dns_datagrams = self.dns_datagrams.saturating_add(1);
        let Some(qname) = datagram.qname.as_deref() else {
            return;
        };
        if qname.is_empty() {
            return;
        }
        let names = self.dns_names.entry((pid, qname.to_owned())).or_default();
        for address in &datagram.addresses {
            if address.is_empty() {
                continue;
            }
            names.insert(address.clone());
            self.dns_by_ip
                .entry((pid, address.clone()))
                .or_insert_with(|| qname.to_owned());
            self.dns_by_ip_global
                .insert(address.clone(), qname.to_owned());
        }
    }

    fn stamp_dns_peers(&mut self) {
        for ((pid, peer, _), activity) in &mut self.network {
            if activity.resolved_name.is_some() {
                continue;
            }
            if let Some(name) = self.dns_by_ip.get(&(*pid, peer.clone())) {
                activity.resolved_name = Some(name.clone());
            } else if let Some(name) = self.dns_by_ip_global.get(peer) {
                activity.resolved_name = Some(name.clone());
            }
        }
    }

    fn record_handshake(&mut self, pid: u32, handshake: &ksight_model::NetworkHandshake) {
        self.handshake_events = self.handshake_events.saturating_add(1);
        let peer = handshake
            .peer_address
            .as_deref()
            .map(normalize_peer_address);
        let port = (handshake.peer_port != 0).then_some(handshake.peer_port);
        self.handshake_names.push(HandshakeNameActivity {
            process_id: pid,
            kind: handshake.kind.clone(),
            sni: handshake.sni.clone(),
            alpn: handshake.alpn.clone(),
            http_host: handshake.http_host.clone(),
            http_method: handshake.http_method.clone(),
            peer: peer.clone(),
            port,
        });
        let stamp = MutableHandshake {
            kind: handshake.kind.clone(),
            sni: handshake.sni.clone(),
            alpn: handshake.alpn.clone(),
            http_host: handshake.http_host.clone(),
            http_method: handshake.http_method.clone(),
        };
        merge_handshake(
            self.handshake_by_fd
                .entry((pid, handshake.file_descriptor))
                .or_default(),
            &stamp,
        );
        if let Some(peer) = peer {
            let activity = self.network.entry((pid, peer, port)).or_default();
            apply_handshake(activity, &stamp);
        }
    }

    fn stamp_handshake_peers(&mut self) {
        let stamps: Vec<((u32, i32), MutableHandshake)> = self
            .handshake_by_fd
            .iter()
            .map(|(key, value)| (*key, value.clone()))
            .collect();
        for ((pid, fd), stamp) in stamps {
            let Some((peer, port)) = self.socket_peers.get(&(pid, fd)).cloned() else {
                continue;
            };
            let activity = self.network.entry((pid, peer, port)).or_default();
            apply_handshake(activity, &stamp);
        }
    }

    fn record_socket_connect(&mut self, pid: u32, connect: &ksight_model::SocketConnect) {
        self.socket_lifecycle.connect_attempts += 1;
        let associated = connect.result == 0 || connect.result == -115;
        if associated {
            self.socket_lifecycle.connected_or_in_progress += 1;
            self.socket_fds.insert((pid, connect.file_descriptor));
        }
        let peer = normalize_peer_address(
            connect
                .peer_address
                .as_deref()
                .unwrap_or(&fallback_peer(connect.address_family)),
        );
        let activity = self
            .network
            .entry((pid, peer.clone(), connect.peer_port))
            .or_default();
        activity.attempts += 1;
        activity.successful += u64::from(connect.result == 0);
        activity.in_progress += u64::from(connect.result == -115);
        if activity.resolved_name.is_none() {
            activity.resolved_name.clone_from(&connect.resolved_name);
        }
        if associated {
            self.socket_peers
                .insert((pid, connect.file_descriptor), (peer, connect.peer_port));
        }
    }

    fn record_socket_accept(&mut self, pid: u32, accept: &ksight_model::SocketAccept) {
        self.socket_lifecycle.accept_attempts += 1;
        if let Some(fd) = accept.accepted_file_descriptor {
            self.socket_lifecycle.accepted_descriptors += 1;
            self.socket_fds.insert((pid, fd));
            self.active_fds.insert((pid, fd));
        }
        let peer = accept
            .peer_address
            .clone()
            .unwrap_or_else(|| fallback_peer(accept.address_family));
        if let Some(fd) = accept.accepted_file_descriptor {
            self.socket_peers
                .insert((pid, fd), (peer.clone(), accept.peer_port));
        }
        self.network
            .entry((pid, peer, accept.peer_port))
            .or_default()
            .accepted += u64::from(accept.accepted_file_descriptor.is_some());
    }

    fn record_socket_io(&mut self, pid: u32, io: &ksight_model::SocketIo) {
        match io.operation {
            SocketIoOperation::Send => self.socket_lifecycle.send_calls += 1,
            SocketIoOperation::Receive => self.socket_lifecycle.receive_calls += 1,
        }
        if io.result < 0 {
            self.socket_lifecycle.failed_io += 1;
            return;
        }
        let result = u64::try_from(io.result).unwrap_or(u64::MAX);
        let is_message_count = matches!(io.syscall, 243 | 269);
        if is_message_count {
            match io.operation {
                SocketIoOperation::Send => {
                    self.socket_lifecycle.sent_messages =
                        self.socket_lifecycle.sent_messages.saturating_add(result);
                }
                SocketIoOperation::Receive => {
                    self.socket_lifecycle.received_messages = self
                        .socket_lifecycle
                        .received_messages
                        .saturating_add(result);
                }
            }
        } else {
            match io.operation {
                SocketIoOperation::Send => {
                    self.socket_lifecycle.sent_bytes =
                        self.socket_lifecycle.sent_bytes.saturating_add(result);
                }
                SocketIoOperation::Receive => {
                    self.socket_lifecycle.received_bytes =
                        self.socket_lifecycle.received_bytes.saturating_add(result);
                }
            }
        }
        let Some((peer, port)) = self.socket_peers.get(&(pid, io.file_descriptor)).cloned() else {
            self.socket_lifecycle.io_without_observed_lifecycle += 1;
            return;
        };
        let activity = self.network.entry((pid, peer, port)).or_default();
        match io.operation {
            SocketIoOperation::Send => {
                if is_message_count {
                    activity.sent_messages = activity.sent_messages.saturating_add(result);
                } else {
                    activity.sent_bytes = activity.sent_bytes.saturating_add(result);
                }
            }
            SocketIoOperation::Receive => {
                if is_message_count {
                    activity.received_messages = activity.received_messages.saturating_add(result);
                } else {
                    activity.received_bytes = activity.received_bytes.saturating_add(result);
                }
            }
        }
    }

    /// Finish aggregation and order high-volume groups by descending activity.
    #[allow(clippy::too_many_lines)] // Final ordering keeps all report sections deterministic.
    pub fn finish(mut self) -> SessionReport {
        self.stamp_dns_peers();
        self.stamp_handshake_peers();
        let mut processes = self
            .processes
            .into_iter()
            .map(|(label, value)| ProcessActivity {
                label,
                package: value.package,
                process_ids: value.process_ids.into_iter().collect(),
                instances: value.instances.into_values().collect(),
                event_count: value.event_count,
                sensor_counts: value.sensor_counts,
            })
            .collect::<Vec<_>>();
        processes.sort_by(|left, right| {
            right
                .event_count
                .cmp(&left.event_count)
                .then_with(|| left.label.cmp(&right.label))
        });

        let mut binder_relations = self
            .binder
            .into_iter()
            .map(|((source_pid, target_pid), value)| BinderRelation {
                source: resolve_label(&self.identities, source_pid),
                source_process_id: source_pid,
                target: target_pid.map_or_else(
                    || "unresolved Binder target".to_owned(),
                    |pid| resolve_label(&self.identities, pid),
                ),
                target_process_id: target_pid,
                requests: value.requests,
                replies: value.replies,
                codes: value.codes,
                paired_replies: value.paired_replies,
                interfaces: value.interfaces,
            })
            .collect::<Vec<_>>();
        binder_relations.sort_by(|left, right| {
            let left_count = left.requests + left.replies;
            let right_count = right.requests + right.replies;
            right_count
                .cmp(&left_count)
                .then_with(|| left.source.cmp(&right.source))
        });

        let mut artifacts = self
            .artifacts
            .into_iter()
            .map(|((category, path), value)| ArtifactActivity {
                category,
                path,
                open_attempts: value.open_attempts,
                successful_opens: value.successful_opens,
                failed_opens: value.failed_opens,
                mappings: value.mappings,
                content_sha256: value.content_sha256,
                content_bytes: value.content_bytes,
            })
            .collect::<Vec<_>>();
        artifacts.sort_by(|left, right| {
            let left_count = left.open_attempts + left.mappings;
            let right_count = right.open_attempts + right.mappings;
            right_count
                .cmp(&left_count)
                .then_with(|| left.path.cmp(&right.path))
        });

        let mut dns_names = self
            .dns_names
            .into_iter()
            .map(|((process_id, qname), addresses)| DnsNameActivity {
                process_id,
                qname,
                addresses: addresses.into_iter().collect(),
            })
            .collect::<Vec<_>>();
        dns_names.sort_by(|left, right| {
            left.qname
                .cmp(&right.qname)
                .then_with(|| left.process_id.cmp(&right.process_id))
        });
        dns_names.truncate(128);
        let dns_datagrams = self.dns_datagrams;
        let handshake_events = self.handshake_events;
        let mut handshake_names = self.handshake_names;
        handshake_names.sort_by(|left, right| {
            left.kind
                .cmp(&right.kind)
                .then_with(|| left.sni.cmp(&right.sni))
                .then_with(|| left.http_host.cmp(&right.http_host))
                .then_with(|| left.process_id.cmp(&right.process_id))
        });
        handshake_names.truncate(128);

        let mut network_peers = self
            .network
            .into_iter()
            .map(|((source_pid, peer, port), value)| NetworkPeerActivity {
                source: resolve_label(&self.identities, source_pid),
                source_process_id: source_pid,
                peer,
                port,
                attempts: value.attempts,
                successful: value.successful,
                in_progress: value.in_progress,
                accepted: value.accepted,
                sent_bytes: value.sent_bytes,
                received_bytes: value.received_bytes,
                sent_messages: value.sent_messages,
                received_messages: value.received_messages,
                resolved_name: value.resolved_name,
                sni: value.sni,
                alpn: value.alpn,
                http_host: value.http_host,
                http_method: value.http_method,
                handshake_kind: value.handshake_kind,
            })
            .collect::<Vec<_>>();
        let loopback_scans = collapse_loopback_scans(&mut network_peers);
        network_peers.sort_by(|left, right| {
            (right.attempts + right.accepted + right.in_progress)
                .cmp(&(left.attempts + left.accepted + left.in_progress))
                .then_with(|| left.peer.cmp(&right.peer))
        });

        let active_at_end = u64::try_from(self.active_fds.len()).unwrap_or(u64::MAX);
        let active_sockets_at_end = u64::try_from(self.socket_fds.len()).unwrap_or(u64::MAX);
        let active_regions_at_end = u64::try_from(self.memory_regions.len()).unwrap_or(u64::MAX);
        let mut observed_mappings = self.observed_spans.into_values().collect::<Vec<_>>();
        rank_observed_mappings(&mut observed_mappings);
        observed_mappings.truncate(1024);
        let fd_lineage_complete = self.fd_lifecycle.lineage_observed
            && self.fd_lifecycle.closes_without_observed_origin == 0
            && self.fd_lifecycle.duplicates_without_observed_origin == 0
            && self.quality.lost_records == 0
            && self.quality.max_sample_one_in <= 1;
        let execution_complete = self.completion.as_ref().is_some_and(|completion| {
            completion.capture_complete
                && completion.invalid_records == 0
                && completion
                    .dropped_by_sensor
                    .values()
                    .all(|count| *count == 0)
        });
        let mut sched_wakeups = self
            .sched_wakeups
            .into_iter()
            .map(|((waker_pid, wakee_tid), count)| SchedWakeupActivity {
                waker: resolve_label(&self.identities, waker_pid),
                waker_process_id: waker_pid,
                wakee_tid,
                count,
            })
            .collect::<Vec<_>>();
        sched_wakeups.sort_by(|left, right| {
            right
                .count
                .cmp(&left.count)
                .then_with(|| left.waker_process_id.cmp(&right.waker_process_id))
        });
        let mut plaintext = self
            .plaintext
            .into_iter()
            .map(|((process_id, adapter, direction), activity)| {
                let content_class =
                    inferred_content_class(&activity.content_class, activity.preview.as_deref());
                PlaintextActivity {
                    source: resolve_label(&self.identities, process_id),
                    process_id,
                    adapter,
                    direction,
                    count: activity.count,
                    requested_bytes: activity.requested_bytes,
                    captured_bytes: activity.captured_bytes,
                    sha256_samples: activity.sha256_samples,
                    preview: activity.preview,
                    urls: activity.urls,
                    content_class,
                }
            })
            .collect::<Vec<_>>();
        plaintext.sort_by(|left, right| {
            right
                .urls
                .len()
                .cmp(&left.urls.len())
                .then_with(|| {
                    preview_evidence_score(
                        right.preview.as_deref().unwrap_or(""),
                        &right.content_class,
                    )
                    .cmp(&preview_evidence_score(
                        left.preview.as_deref().unwrap_or(""),
                        &left.content_class,
                    ))
                })
                .then_with(|| left.source.cmp(&right.source))
        });
        let mut http_calls = self
            .http_calls
            .into_iter()
            .map(|(key, activity)| HttpCallActivity {
                source: resolve_label(&self.identities, key.process_id),
                process_id: key.process_id,
                direction: key.direction,
                origin: key.origin,
                kind: key.kind,
                method: key.method,
                host: (!key.host.is_empty()).then_some(key.host),
                path: key.path,
                status: activity.status,
                query_keys: activity.query_keys,
                header_names: activity.header_names,
                redacted_headers: activity.redacted_headers,
                body_keys: activity.body_keys,
                redacted_body_keys: activity.redacted_body_keys,
                content_type: activity.content_type,
                third_party: activity.third_party,
                count: activity.count,
            })
            .collect::<Vec<_>>();
        stamp_empty_hosts_from_sni(&mut http_calls, &handshake_names);
        sort_http_catalog(&mut http_calls);
        let mut graph = crate::SessionGraph::from_l0(
            self.session_id,
            &processes,
            &binder_relations,
            &artifacts,
            &network_peers,
            &sched_wakeups,
        );
        let session_id = self.session_id.unwrap_or(Uuid::nil());
        for scan in loopback_scans.iter().take(16) {
            let from = graph.ensure_process(session_id, &scan.source, scan.process_id);
            let to = format!(
                "loopback-scan:{}:{}-{}",
                scan.address, scan.port_min, scan.port_max
            );
            graph.entities.push(crate::GraphEntity {
                kind: crate::GraphEntityKind::SocketFlow,
                session_id,
                key: to.clone(),
                label: format!(
                    "{}:{}-{} ({} ports)",
                    scan.address, scan.port_min, scan.port_max, scan.unique_ports
                ),
                sensors: vec![SensorKind::Network],
                artifact: None,
                process_instance_id: None,
            });
            graph.edges.push(crate::GraphEdge {
                from,
                to,
                relation: "scans".to_owned(),
                strength: crate::EdgeStrength::Confirmed,
                sensor: Some(SensorKind::Network),
            });
        }
        for row in plaintext.iter().take(64) {
            let from = graph.ensure_process(session_id, &row.source, row.process_id);
            let to = format!(
                "plaintext:{}",
                row.sha256_samples
                    .first()
                    .cloned()
                    .unwrap_or_else(|| row.adapter.clone())
            );
            graph.entities.push(crate::GraphEntity {
                kind: crate::GraphEntityKind::FileObject,
                session_id,
                key: to.clone(),
                label: row.preview.clone().unwrap_or_else(|| row.adapter.clone()),
                sensors: vec![SensorKind::Integrity],
                artifact: None,
                process_instance_id: None,
            });
            graph.edges.push(crate::GraphEdge {
                from,
                to,
                relation: plaintext_graph_relation(&row.adapter, &row.direction).to_owned(),
                strength: crate::EdgeStrength::Confirmed,
                sensor: Some(SensorKind::Integrity),
            });
        }
        attach_http_call_graph(&mut graph, session_id, &http_calls);
        pair_http_replies(&mut graph, session_id, &http_calls);
        graph.attach_observed_mappings(session_id, &observed_mappings, &processes);
        let mut inspect_hits = self
            .inspect_hits
            .into_iter()
            .map(|((process_id, adapter, library), activity)| InspectHitActivity {
                adapter,
                library,
                process_id,
                process_instance_id: activity.process_instance_id,
                attached: activity.attached,
                hits: activity.hits,
                last_detail: activity.last_detail,
                binder_handle: activity.binder_handle,
                binder_code: activity.binder_code,
                binder_interface: activity.binder_interface,
                binder_method: activity.binder_method,
                binder_method_source: activity.binder_method_source,
                binder_strings: activity.binder_strings,
                binder_ints: activity.binder_ints,
                binder_int64s: activity.binder_int64s,
                binder_bools: activity.binder_bools,
                binder_fds: activity.binder_fds,
                binder_blobs: activity.binder_blobs,
                binder_binders: activity.binder_binders,
                binder_transaction_id: activity.binder_transaction_id,
                reply_latency_ns: activity.reply_latency_ns,
            })
            .collect::<Vec<_>>();
        inspect_hits.sort_by(|left, right| {
            right
                .hits
                .cmp(&left.hits)
                .then_with(|| left.adapter.cmp(&right.adapter))
                .then_with(|| left.process_id.cmp(&right.process_id))
        });
        graph.attach_binder_fd_transfers(session_id, &self.binder_fd_transfers, &processes);
        graph.attach_binder_replies(session_id, &self.binder_reply_pairs, &processes);
        graph.attach_inspect_hits(session_id, &inspect_hits, &processes);
        for (txn, code, token, method) in self
            .binder_transactions
            .iter()
            .filter_map(|(txn, state)| {
                state
                    .interface_token
                    .as_deref()
                    .map(|token| (*txn, state.code, token, state.binder_method.as_deref()))
            })
            .take(64)
        {
            let req_key = format!("binder:req:{txn}");
            let label = match method {
                Some(method) => format!("binder request {txn} {token}::{method}"),
                None => format!("binder request {txn} {token} code={code}"),
            };
            if let Some(entity) = graph
                .entities
                .iter_mut()
                .find(|entity| entity.key == req_key)
            {
                entity.label = label;
            } else {
                graph.entities.push(crate::GraphEntity {
                    kind: crate::GraphEntityKind::BinderTransaction,
                    session_id,
                    key: req_key,
                    label,
                    sensors: vec![SensorKind::Binder],
                    artifact: None,
                    process_instance_id: None,
                });
            }
        }
        SessionReport {
            schema_version: "mobilee.kernsight-session-report/v1".to_owned(),
            session_id: self.session_id,
            mixed_sessions: self.mixed_sessions,
            total_events: self.total_events,
            first_monotonic_ns: self.first_monotonic_ns,
            last_monotonic_ns: self.last_monotonic_ns,
            sensor_counts: self.sensor_counts,
            mode_counts: self.mode_counts,
            quality: self.quality,
            environment: self.environment,
            environment_transitions: self.environment_transitions,
            completion: self.completion,
            execution_complete,
            processes,
            binder_relations,
            artifacts,
            network_peers,
            dns_datagrams,
            dns_names,
            handshake_events,
            handshake_names,
            fd_lifecycle: FdLifecycleSummary {
                active_at_end,
                lineage_complete: fd_lineage_complete,
                ..self.fd_lifecycle
            },
            memory_lifecycle: MemoryLifecycleSummary {
                active_regions_at_end,
                ..self.memory_lifecycle
            },
            observed_mappings,
            binder_lifecycle: BinderLifecycleSummary {
                average_delivery_ns: (self.binder_lifecycle.delivered > 0)
                    .then(|| self.binder_latency_total_ns / self.binder_lifecycle.delivered),
                average_reply_ns: (self.binder_lifecycle.paired_replies > 0).then(|| {
                    self.binder_reply_latency_total_ns / self.binder_lifecycle.paired_replies
                }),
                ..self.binder_lifecycle
            },
            binder_fd_transfers: self.binder_fd_transfers,
            binder_reply_pairs: self.binder_reply_pairs,
            socket_lifecycle: SocketLifecycleSummary {
                active_at_end: active_sockets_at_end,
                ..self.socket_lifecycle
            },
            sched_wakeups,
            plaintext,
            http_calls,
            http_code_refs: Vec::new(),
            inspect_hits,
            loopback_scans,
            merged_dumps: Vec::new(),
            graph,
            limitations: report_limitations(),
        }
    }

    fn record_http_call(
        &mut self,
        pid: u32,
        direction: &str,
        origin: &str,
        parsed: crate::ParsedHttpPlain,
    ) {
        let key = HttpCallKey {
            process_id: pid,
            direction: direction.to_owned(),
            origin: origin.to_owned(),
            kind: parsed.kind.to_owned(),
            method: parsed.method,
            host: parsed.host.unwrap_or_default(),
            path: parsed.path,
        };
        let activity = self.http_calls.entry(key).or_default();
        activity.count = activity.count.saturating_add(1);
        activity.third_party |= parsed.third_party;
        if activity.status.is_none() {
            activity.status = parsed.status;
        }
        if activity.content_type.is_none() {
            activity.content_type.clone_from(&parsed.content_type);
        }
        extend_unique(&mut activity.query_keys, &parsed.query_keys, 24);
        extend_unique(&mut activity.header_names, &parsed.header_names, 24);
        extend_unique(&mut activity.redacted_headers, &parsed.redacted_headers, 24);
        extend_unique(&mut activity.body_keys, &parsed.body_keys, 24);
        extend_unique(
            &mut activity.redacted_body_keys,
            &parsed.redacted_body_keys,
            24,
        );
    }

    fn record_fd(&mut self, pid: u32, change: &ksight_model::FileDescriptorChange) {
        if change.result < 0 {
            self.fd_lifecycle.failed_operations += 1;
            return;
        }
        match change.operation {
            FileDescriptorOperation::Close => {
                self.fd_lifecycle.successful_closes += 1;
                if !self.active_fds.remove(&(pid, change.file_descriptor)) {
                    self.fd_lifecycle.closes_without_observed_origin += 1;
                }
                if self.socket_fds.remove(&(pid, change.file_descriptor)) {
                    self.socket_lifecycle.closed_descriptors += 1;
                }
                self.socket_peers.remove(&(pid, change.file_descriptor));
            }
            FileDescriptorOperation::CloseRange => {
                const CLOSE_RANGE_CLOEXEC: u32 = 1 << 2;
                if change.flags & CLOSE_RANGE_CLOEXEC != 0 {
                    return;
                }
                self.fd_lifecycle.successful_close_ranges += 1;
                let first = u32::try_from(change.file_descriptor).unwrap_or(0);
                let last = change.last_file_descriptor.unwrap_or(first);
                let closing = self
                    .active_fds
                    .iter()
                    .copied()
                    .filter(|&(owner, fd)| {
                        owner == pid
                            && u32::try_from(fd)
                                .is_ok_and(|descriptor| descriptor >= first && descriptor <= last)
                    })
                    .collect::<Vec<_>>();
                if closing.is_empty() {
                    self.fd_lifecycle.closes_without_observed_origin += 1;
                }
                for key in closing {
                    self.active_fds.remove(&key);
                    if self.socket_fds.remove(&key) {
                        self.fd_lifecycle.successful_closes += 1;
                        self.socket_lifecycle.closed_descriptors += 1;
                    } else {
                        self.fd_lifecycle.successful_closes += 1;
                    }
                    self.socket_peers.remove(&key);
                }
            }
            FileDescriptorOperation::RightsSend | FileDescriptorOperation::RightsReceive => {
                self.fd_lifecycle.successful_duplicates = self
                    .fd_lifecycle
                    .successful_duplicates
                    .saturating_add(u64::from(change.flags.max(1)));
                if let Some(fd) = change.requested_file_descriptor {
                    self.active_fds.insert((pid, fd));
                }
            }
            FileDescriptorOperation::Duplicate => {
                self.fd_lifecycle.successful_duplicates += 1;
                if !self.active_fds.contains(&(pid, change.file_descriptor)) {
                    self.fd_lifecycle.duplicates_without_observed_origin += 1;
                }
                if let Some(new_fd) = change.resulting_file_descriptor {
                    self.active_fds.insert((pid, new_fd));
                    if self.socket_fds.contains(&(pid, change.file_descriptor)) {
                        self.socket_fds.insert((pid, new_fd));
                        self.socket_lifecycle.duplicated_descriptors += 1;
                    }
                    if let Some(peer) = self
                        .socket_peers
                        .get(&(pid, change.file_descriptor))
                        .cloned()
                    {
                        self.socket_peers.insert((pid, new_fd), peer);
                    }
                }
            }
        }
    }

    fn record_memory(&mut self, pid: u32, change: &ksight_model::MemoryRegionChange) {
        if change.result < 0 {
            self.memory_lifecycle.failed_operations += 1;
            return;
        }
        match change.operation {
            MemoryOperation::Map => {
                self.memory_lifecycle.successful_maps += 1;
                if let Ok(start) = u64::try_from(change.result) {
                    let end = start.saturating_add(change.length);
                    if plausible_mapping_span(start, end) {
                        self.memory_lifecycle.mapped_bytes = self
                            .memory_lifecycle
                            .mapped_bytes
                            .saturating_add(change.length);
                        self.replace_region(pid, start, change.length);
                        self.note_observed_span(
                            pid,
                            start,
                            end,
                            MappingSource::Mmap,
                            change.backing_path.clone(),
                        );
                    }
                }
            }
            MemoryOperation::Protect => self.memory_lifecycle.successful_protects += 1,
            MemoryOperation::Unmap => {
                self.memory_lifecycle.successful_unmaps += 1;
                if change.length > 0 && change.length <= 1024 * 1024 * 1024 {
                    if plausible_mapping_length(change.length) {
                        self.memory_lifecycle.unmapped_bytes = self
                            .memory_lifecycle
                            .unmapped_bytes
                            .saturating_add(change.length);
                    }
                    self.unmap_regions(pid, change.address, change.length);
                }
            }
            MemoryOperation::Remap => {
                self.memory_lifecycle.successful_remaps += 1;
                if change.length > 0 && change.length <= 1024 * 1024 * 1024 {
                    self.unmap_regions(pid, change.address, change.length);
                }
                if let Ok(start) = u64::try_from(change.result) {
                    let new_len = change.offset.unwrap_or(change.length);
                    let end = start.saturating_add(new_len);
                    if plausible_mapping_span(start, end) {
                        self.replace_region(pid, start, new_len);
                        self.note_observed_span(
                            pid,
                            start,
                            end,
                            MappingSource::Mmap,
                            change.backing_path.clone(),
                        );
                        self.memory_lifecycle.mapped_bytes =
                            self.memory_lifecycle.mapped_bytes.saturating_add(new_len);
                    }
                }
            }
            MemoryOperation::Brk => {
                self.memory_lifecycle.successful_brk += 1;
            }
        }
    }

    fn unmap_regions(&mut self, pid: u32, start: u64, length: u64) {
        let end = start.saturating_add(length);
        let overlaps = self
            .memory_regions
            .range((pid, 0)..=(pid, u64::MAX))
            .filter_map(|(&(region_pid, region_start), &region_end)| {
                (region_start < end && region_end > start)
                    .then_some(((region_pid, region_start), region_end))
            })
            .collect::<Vec<_>>();
        if overlaps.is_empty() {
            self.memory_lifecycle.unmaps_without_observed_mapping += 1;
            return;
        }
        self.memory_lifecycle.unmaps_with_observed_mapping += 1;
        for ((region_pid, region_start), region_end) in overlaps {
            self.memory_regions.remove(&(region_pid, region_start));
            if region_start < start {
                self.memory_regions
                    .insert((region_pid, region_start), start);
            }
            if region_end > end {
                self.memory_regions.insert((region_pid, end), region_end);
            }
        }
    }

    fn replace_region(&mut self, pid: u32, start: u64, length: u64) {
        let end = start.saturating_add(length);
        let overlaps = self
            .memory_regions
            .range((pid, 0)..=(pid, u64::MAX))
            .filter_map(|(&(region_pid, region_start), &region_end)| {
                (region_start < end && region_end > start)
                    .then_some(((region_pid, region_start), region_end))
            })
            .collect::<Vec<_>>();
        for ((region_pid, region_start), region_end) in overlaps {
            self.memory_regions.remove(&(region_pid, region_start));
            if region_start < start {
                self.memory_regions
                    .insert((region_pid, region_start), start);
            }
            if region_end > end {
                self.memory_regions.insert((region_pid, end), region_end);
            }
        }
        if end > start {
            self.memory_regions.insert((pid, start), end);
        }
    }

    fn note_observed_span(
        &mut self,
        pid: u32,
        start: u64,
        end: u64,
        source: MappingSource,
        path: Option<String>,
    ) {
        if !plausible_mapping_span(start, end) {
            return;
        }
        let slot = self
            .observed_spans
            .entry((pid, start, end))
            .or_insert_with(|| {
                let mapping_generation = if source == MappingSource::Mmap {
                    let generation = self.mapping_generations.entry(pid).or_insert(0);
                    *generation = generation.saturating_add(1);
                    *generation
                } else {
                    0
                };
                ObservedMapping {
                    process_id: pid,
                    start,
                    end,
                    backing_path: path.clone(),
                    source,
                    mapping_generation,
                }
            });
        if slot.backing_path.is_none() {
            slot.backing_path = path;
        }
        if source == MappingSource::Mmap {
            slot.source = MappingSource::Mmap;
        }
    }

    #[allow(clippy::too_many_lines)]
    fn record_binder(
        &mut self,
        event: &Event,
        transaction: &ksight_model::BinderTransaction,
        pid: u32,
    ) {
        match transaction.stage {
            BinderTransactionStage::Submitted => {
                self.binder_lifecycle.submitted += 1;
                let one_way = transaction
                    .decoded_flags
                    .contains(&BinderTransactionFlag::OneWay)
                    || transaction.flags & 0x1 != 0;
                let two_way = !transaction.reply && !one_way;
                if transaction.reply {
                    self.binder_lifecycle.reply_submitted =
                        self.binder_lifecycle.reply_submitted.saturating_add(1);
                    self.record_binder_reply(event, transaction, pid);
                } else if one_way {
                    self.binder_lifecycle.one_way_submitted =
                        self.binder_lifecycle.one_way_submitted.saturating_add(1);
                } else {
                    self.binder_lifecycle.two_way_submitted =
                        self.binder_lifecycle.two_way_submitted.saturating_add(1);
                }
                self.binder_transactions.insert(
                    transaction.transaction_id,
                    MutableBinderTransaction {
                        submitted_ns: event.header.monotonic_ns,
                        delivered: false,
                        buffer_observed: false,
                        source_pid: pid,
                        code: transaction.code,
                        two_way,
                        interface_token: transaction.interface_token.clone(),
                        binder_method: transaction.binder_method.clone(),
                    },
                );
                if !transaction.reply {
                    self.join_binder_submit(
                        event.header.process.tid,
                        transaction.code,
                        transaction.transaction_id,
                    );
                    self.stamp_kernel_parcel_on_inspect(pid, transaction);
                }
                let relation = self
                    .binder
                    .entry((pid, transaction.target_process_id))
                    .or_default();
                if transaction.reply {
                    relation.replies += 1;
                } else {
                    relation.requests += 1;
                }
                *relation.codes.entry(transaction.code).or_default() += 1;
                if let Some(token) = transaction.interface_token.as_deref() {
                    *relation.interfaces.entry(token.to_owned()).or_default() += 1;
                }
            }
            BinderTransactionStage::ParcelPrefix => {
                if let Some(state) = self
                    .binder_transactions
                    .get_mut(&transaction.transaction_id)
                {
                    if state.interface_token.is_none() {
                        state
                            .interface_token
                            .clone_from(&transaction.interface_token);
                    }
                    if state.binder_method.is_none() {
                        state.binder_method.clone_from(&transaction.binder_method);
                    }
                }
                if !transaction.reply {
                    self.stamp_kernel_parcel_on_inspect(pid, transaction);
                }
                if let Some(token) = transaction.interface_token.as_deref() {
                    *self
                        .binder
                        .entry((pid, transaction.target_process_id))
                        .or_default()
                        .interfaces
                        .entry(token.to_owned())
                        .or_default() += 1;
                }
            }
            BinderTransactionStage::Received => {
                let Some(state) = self
                    .binder_transactions
                    .get_mut(&transaction.transaction_id)
                else {
                    self.binder_lifecycle.delivery_without_submission += 1;
                    return;
                };
                if state.delivered {
                    return;
                }
                state.delivered = true;
                self.binder_lifecycle.delivered += 1;
                let latency = event.header.monotonic_ns.saturating_sub(state.submitted_ns);
                self.binder_latency_total_ns = self.binder_latency_total_ns.saturating_add(latency);
                self.binder_lifecycle.minimum_delivery_ns = Some(
                    self.binder_lifecycle
                        .minimum_delivery_ns
                        .map_or(latency, |value| value.min(latency)),
                );
                self.binder_lifecycle.maximum_delivery_ns = Some(
                    self.binder_lifecycle
                        .maximum_delivery_ns
                        .map_or(latency, |value| value.max(latency)),
                );
            }
            BinderTransactionStage::BufferAllocated => {
                let Some(state) = self
                    .binder_transactions
                    .get_mut(&transaction.transaction_id)
                else {
                    self.binder_lifecycle.buffer_without_submission += 1;
                    return;
                };
                if !state.buffer_observed {
                    state.buffer_observed = true;
                    self.binder_lifecycle.buffers_observed += 1;
                    self.binder_lifecycle.parcel_data_bytes = self
                        .binder_lifecycle
                        .parcel_data_bytes
                        .saturating_add(transaction.data_size.unwrap_or_default());
                }
            }
            BinderTransactionStage::FdSent => {
                if self
                    .binder_transactions
                    .contains_key(&transaction.transaction_id)
                {
                    self.binder_lifecycle.file_descriptors_sent += 1;
                } else {
                    self.binder_lifecycle.fd_transfer_without_submission += 1;
                }
            }
            BinderTransactionStage::FdReceived => {
                if self
                    .binder_transactions
                    .contains_key(&transaction.transaction_id)
                {
                    self.binder_lifecycle.file_descriptors_received += 1;
                } else {
                    self.binder_lifecycle.fd_transfer_without_submission += 1;
                }
                if let (Some(origin), Some(source_pid), Some(source_fd), Some(target_fd)) = (
                    transaction.transferred_fd_origin.clone(),
                    transaction.transferred_fd_source_pid,
                    transaction.transferred_fd_source_fd,
                    transaction.file_descriptor,
                ) {
                    self.binder_fd_transfers.push(BinderFdTransfer {
                        transaction_id: transaction.transaction_id,
                        source_process_id: source_pid,
                        source_fd,
                        target_process_id: pid,
                        target_fd,
                        origin,
                    });
                }
            }
        }
    }

    fn record_binder_reply(
        &mut self,
        event: &Event,
        transaction: &ksight_model::BinderTransaction,
        server_pid: u32,
    ) {
        let Some(request_id) = transaction.reply_to_request_id else {
            self.binder_lifecycle.reply_without_request = self
                .binder_lifecycle
                .reply_without_request
                .saturating_add(1);
            return;
        };
        let Some((client_pid, code, submitted_ns, two_way)) =
            self.binder_transactions.get(&request_id).map(|request| {
                (
                    request.source_pid,
                    request.code,
                    request.submitted_ns,
                    request.two_way,
                )
            })
        else {
            self.binder_lifecycle.reply_without_request = self
                .binder_lifecycle
                .reply_without_request
                .saturating_add(1);
            return;
        };
        if !two_way {
            self.binder_lifecycle.reply_without_request = self
                .binder_lifecycle
                .reply_without_request
                .saturating_add(1);
            return;
        }
        let latency = transaction
            .reply_latency_ns
            .unwrap_or_else(|| event.header.monotonic_ns.saturating_sub(submitted_ns));
        self.binder_lifecycle.paired_replies =
            self.binder_lifecycle.paired_replies.saturating_add(1);
        self.binder_reply_latency_total_ns =
            self.binder_reply_latency_total_ns.saturating_add(latency);
        self.binder_lifecycle.minimum_reply_ns = Some(
            self.binder_lifecycle
                .minimum_reply_ns
                .map_or(latency, |value| value.min(latency)),
        );
        self.binder_lifecycle.maximum_reply_ns = Some(
            self.binder_lifecycle
                .maximum_reply_ns
                .map_or(latency, |value| value.max(latency)),
        );
        {
            let slot = self
                .binder
                .entry((server_pid, transaction.target_process_id))
                .or_default();
            slot.paired_replies = slot.paired_replies.saturating_add(1);
        }
        if self.binder_reply_pairs.len() < 64 {
            self.binder_reply_pairs.push(BinderReplyPair {
                request_transaction_id: request_id,
                reply_transaction_id: transaction.transaction_id,
                client_process_id: client_pid,
                server_process_id: server_pid,
                code,
                latency_ns: latency,
            });
        }
        if let Some(pid) = self.inspect_joined_txns.get(&request_id).copied() {
            if let Some(activity) = self.inspect_hit_mut(pid, "binder_userspace") {
                activity.reply_latency_ns = Some(latency);
            }
        }
    }

    fn join_inspect_binder(&mut self, pid: u32, tid: u32, code: u32) {
        let key = (tid, code);
        if let Some(queue) = self.unmatched_binder_submits.get_mut(&key) {
            if let Some(txn_id) = queue.pop_front() {
                if queue.is_empty() {
                    self.unmatched_binder_submits.remove(&key);
                }
                self.stamp_inspect_join(pid, txn_id);
                return;
            }
        }
        if self.pending_inspect_transacts.len() >= 4096
            && !self.pending_inspect_transacts.contains_key(&key)
        {
            return;
        }
        let queue = self.pending_inspect_transacts.entry(key).or_default();
        if queue.len() >= 8 {
            queue.pop_front();
        }
        queue.push_back(pid);
    }

    fn join_binder_submit(&mut self, tid: u32, code: u32, txn_id: i32) {
        let key = (tid, code);
        if let Some(queue) = self.pending_inspect_transacts.get_mut(&key) {
            if let Some(pid) = queue.pop_front() {
                if queue.is_empty() {
                    self.pending_inspect_transacts.remove(&key);
                }
                self.stamp_inspect_join(pid, txn_id);
                return;
            }
        }
        if self.unmatched_binder_submits.len() >= 4096
            && !self.unmatched_binder_submits.contains_key(&key)
        {
            return;
        }
        let queue = self.unmatched_binder_submits.entry(key).or_default();
        if queue.len() >= 8 {
            queue.pop_front();
        }
        queue.push_back(txn_id);
    }

    fn inspect_hit_mut(&mut self, pid: u32, adapter: &str) -> Option<&mut MutableInspectHit> {
        let key = self
            .inspect_hits
            .keys()
            .find(|(process_id, name, _)| *process_id == pid && name == adapter)
            .cloned()?;
        self.inspect_hits.get_mut(&key)
    }

    fn stamp_inspect_join(&mut self, pid: u32, txn_id: i32) {
        let token = self
            .binder_transactions
            .get(&txn_id)
            .and_then(|state| state.interface_token.clone());
        let method = self
            .binder_transactions
            .get(&txn_id)
            .and_then(|state| state.binder_method.clone());
        if let Some(activity) = self.inspect_hit_mut(pid, "binder_userspace") {
            activity.binder_transaction_id = Some(txn_id);
            if activity.binder_interface.is_none() {
                activity.binder_interface = token;
                if activity.binder_method.is_none() {
                    activity.binder_method = method;
                    if activity.binder_method.is_some() {
                        activity.binder_method_source = Some("aosp_stub".to_owned());
                    }
                }
            }
        }
        self.inspect_joined_txns.insert(txn_id, pid);
    }

    fn stamp_kernel_parcel_on_inspect(
        &mut self,
        pid: u32,
        transaction: &ksight_model::BinderTransaction,
    ) {
        let Some(token) = transaction.interface_token.as_ref() else {
            return;
        };
        let Some(activity) = self.inspect_hit_mut(pid, "binder_userspace") else {
            return;
        };
        if activity.binder_interface.is_none() {
            activity.binder_interface = Some(token.clone());
        }
        if activity.binder_method.is_none() {
            activity
                .binder_method
                .clone_from(&transaction.binder_method);
            activity
                .binder_method_source
                .clone_from(&transaction.binder_method_source);
        }
    }

    fn record_quality(&mut self, event: &Event) {
        let quality = &event.header.quality;
        self.quality.lost_records += quality.lost_before;
        self.quality.truncated_events += u64::from(quality.truncated);
        if quality.truncated {
            *self
                .quality
                .truncated_by_source
                .entry(quality.source.clone())
                .or_default() += 1;
        }
        if quality.lost_before != 0 {
            *self
                .quality
                .lost_by_sensor
                .entry(event.header.sensor)
                .or_default() += quality.lost_before;
        }
        if quality.sample_one_in > 1 {
            self.quality.sampled_events += 1;
        }
        self.quality.max_sample_one_in = self
            .quality
            .max_sample_one_in
            .max(quality.sample_one_in.max(1));
        self.quality.opaque_events +=
            u64::from(matches!(event.payload, EventPayload::Opaque { .. }));
    }
}

fn plausible_mapping_length(length: u64) -> bool {
    (4096..=1024 * 1024 * 1024).contains(&length)
}

fn plausible_mapping_span(start: u64, end: u64) -> bool {
    start >= 0x1000 && end > start && plausible_mapping_length(end.saturating_sub(start))
}

fn best_package(event: &Event) -> Option<String> {
    event
        .header
        .process
        .packages
        .iter()
        .filter(|candidate| candidate.confidence_percent >= 90)
        .max_by_key(|candidate| candidate.confidence_percent)
        .map(|candidate| candidate.package_name.clone())
}

fn same_environment_state(
    left: &ksight_model::SessionEnvironment,
    right: &ksight_model::SessionEnvironment,
) -> bool {
    left.collector_mode == right.collector_mode
        && left.developer_options == right.developer_options
        && left.usb_debugging == right.usb_debugging
        && left.wireless_debugging == right.wireless_debugging
        && left.root_authorized == right.root_authorized
        && left.selinux_enforcing == right.selinux_enforcing
        && left.verified_boot_state == right.verified_boot_state
        && left.bootloader_locked == right.bootloader_locked
        && left.target_behavior_may_be_altered == right.target_behavior_may_be_altered
        && left.warnings == right.warnings
}

fn fallback_label(event: &Event) -> String {
    event
        .header
        .process
        .command_line
        .clone()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| event.header.process.comm.clone())
}

fn resolve_label(identities: &BTreeMap<u32, ObservedIdentity>, pid: u32) -> String {
    let Some(identity) = identities.get(&pid) else {
        return format!("pid:{pid}");
    };
    identity
        .package
        .clone()
        .or_else(|| identity.command_line.clone())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| identity.comm.clone())
}

fn normalize_peer_address(peer: &str) -> String {
    peer.strip_prefix("::ffff:").unwrap_or(peer).to_owned()
}

fn fallback_peer(family: u16) -> String {
    match family {
        0 => "empty-sockaddr".to_owned(),
        16 => "netlink".to_owned(),
        17 => "af-packet".to_owned(),
        38 => "af-alg".to_owned(),
        40 => "vsock".to_owned(),
        42 => "af-qipcrtr".to_owned(),
        other => format!("address-family-{other}"),
    }
}

fn extend_unique(dst: &mut Vec<String>, src: &[String], cap: usize) {
    for item in src {
        if dst.len() >= cap {
            return;
        }
        if !dst.iter().any(|seen| seen == item) {
            dst.push(item.clone());
        }
    }
}

fn http_call_key(row: &HttpCallActivity) -> String {
    let host = row.host.as_deref().unwrap_or("-");
    let origin = if row.origin.is_empty() {
        "inspect"
    } else {
        row.origin.as_str()
    };
    format!(
        "http_call:{origin}:{}:{}:{}{}",
        row.process_id, row.method, host, row.path
    )
}

fn http_call_label(row: &HttpCallActivity) -> String {
    let tracker = if row.third_party { " tracker" } else { "" };
    if row.kind == "http1_response" || row.kind == "http2_response" {
        let status = row
            .status
            .map_or_else(|| "?".to_owned(), |value| value.to_string());
        let content = row.content_type.as_deref().unwrap_or("");
        return format!("HTTP {status} {content}{tracker} ×{}", row.count);
    }
    let host = row.host.as_deref().unwrap_or("-");
    format!("{} {host}{}{tracker} ×{}", row.method, row.path, row.count)
}

fn attach_http_call_graph(
    graph: &mut crate::SessionGraph,
    session_id: Uuid,
    calls: &[HttpCallActivity],
) {
    for row in calls.iter().take(64) {
        let from = graph.ensure_process(session_id, &row.source, row.process_id);
        let to = http_call_key(row);
        if !graph.entities.iter().any(|entity| entity.key == to) {
            graph.entities.push(crate::GraphEntity {
                kind: crate::GraphEntityKind::SocketFlow,
                session_id,
                key: to.clone(),
                label: http_call_label(row),
                sensors: vec![SensorKind::Integrity],
                artifact: None,
                process_instance_id: None,
            });
        }
        let strength = if row.origin == "heap" {
            crate::EdgeStrength::Correlated
        } else {
            crate::EdgeStrength::Confirmed
        };
        graph.edges.push(crate::GraphEdge {
            from,
            to: to.clone(),
            relation: "http_call".to_owned(),
            strength,
            sensor: Some(SensorKind::Integrity),
        });
        if let Some(name) = row.host.as_deref() {
            let host_key = format!("host:{name}");
            if !graph.entities.iter().any(|entity| entity.key == host_key) {
                graph.entities.push(crate::GraphEntity {
                    kind: crate::GraphEntityKind::HostName,
                    session_id,
                    key: host_key.clone(),
                    label: name.to_owned(),
                    sensors: vec![SensorKind::Integrity],
                    artifact: None,
                    process_instance_id: None,
                });
            }
            graph.edges.push(crate::GraphEdge {
                from: host_key,
                to,
                relation: "http_host".to_owned(),
                strength: crate::EdgeStrength::Correlated,
                sensor: Some(SensorKind::Integrity),
            });
        }
    }
}

fn pair_http_replies(
    graph: &mut crate::SessionGraph,
    _session_id: Uuid,
    calls: &[HttpCallActivity],
) {
    let requests: Vec<&HttpCallActivity> = calls
        .iter()
        .filter(|row| {
            matches!(row.kind.as_str(), "http1_request" | "http2_request") && row.host.is_some()
        })
        .take(64)
        .collect();
    let responses: Vec<&HttpCallActivity> = calls
        .iter()
        .filter(|row| {
            matches!(row.kind.as_str(), "http1_response" | "http2_response") && row.host.is_some()
        })
        .take(64)
        .collect();
    let mut paired = 0_usize;
    for request in requests {
        for response in &responses {
            if paired >= 32 {
                return;
            }
            if request.process_id != response.process_id {
                continue;
            }
            if request.host != response.host {
                continue;
            }
            graph.edges.push(crate::GraphEdge {
                from: http_call_key(request),
                to: http_call_key(response),
                relation: "http_reply".to_owned(),
                strength: crate::EdgeStrength::Correlated,
                sensor: Some(SensorKind::Integrity),
            });
            paired = paired.saturating_add(1);
        }
    }
}

/// Parse dump/forensics `plaintext/` windows into heap `http_calls`.
#[must_use]
pub fn http_calls_from_plaintext_dir(dir: &std::path::Path, source: &str) -> Vec<HttpCallActivity> {
    http_calls_from_store(dir, source, "heap", 8 * 1024, false)
}

/// Parse already-copied CE/DE prefs/databases/files for `http(s)://` interface rows.
#[must_use]
pub fn http_calls_from_private_dir(dir: &std::path::Path, source: &str) -> Vec<HttpCallActivity> {
    http_calls_from_store(dir, source, "private", 512 * 1024, true)
}

fn http_calls_from_store(
    dir: &std::path::Path,
    source: &str,
    origin: &str,
    max_bytes: usize,
    recursive: bool,
) -> Vec<HttpCallActivity> {
    let mut files = Vec::new();
    let mut remaining = 256_usize;
    collect_store_files(dir, recursive, &mut files, &mut remaining);
    let mut calls = BTreeMap::<(u32, String, String, String, String), HttpCallActivity>::new();
    for path in files {
        let Ok(mut bytes) = std::fs::read(&path) else {
            continue;
        };
        if bytes.len() > max_bytes {
            bytes.truncate(max_bytes);
        }
        if bytes.is_empty() {
            continue;
        }
        let process_id = pid_from_plaintext_name(&path);
        for parsed in crate::parse_http_plain_all_bytes(&bytes, "text") {
            if parsed.kind == "http2_preface" {
                continue;
            }
            let host = parsed.host.clone().unwrap_or_default();
            let is_response = parsed.status.is_some() && parsed.kind.contains("response");
            if host.is_empty() && !is_response {
                continue;
            }
            if !host.is_empty()
                && crate::format_inspect_url(parsed.scheme, &host, &parsed.path).is_none()
            {
                continue;
            }
            let key = (
                process_id,
                parsed.kind.to_owned(),
                parsed.method.clone(),
                host.clone(),
                parsed.path.clone(),
            );
            let activity = calls.entry(key).or_insert_with(|| HttpCallActivity {
                source: source.to_owned(),
                process_id,
                direction: origin.to_owned(),
                kind: parsed.kind.to_owned(),
                method: parsed.method.clone(),
                host: (!host.is_empty()).then_some(host.clone()),
                path: parsed.path.clone(),
                status: parsed.status,
                query_keys: parsed.query_keys.clone(),
                header_names: parsed.header_names.clone(),
                redacted_headers: parsed.redacted_headers.clone(),
                body_keys: parsed.body_keys.clone(),
                redacted_body_keys: parsed.redacted_body_keys.clone(),
                content_type: parsed.content_type.clone(),
                third_party: parsed.third_party,
                count: 0,
                origin: origin.to_owned(),
            });
            activity.count = activity.count.saturating_add(1);
            activity.third_party |= parsed.third_party;
        }
    }
    let mut out = calls.into_values().collect::<Vec<_>>();
    sort_http_catalog(&mut out);
    out
}

/// First-party inspect/private/heap paths outrank tracker/CDN so the 256-row cap keeps APIs.
pub fn sort_http_catalog(calls: &mut Vec<HttpCallActivity>) {
    calls.retain(keep_catalog_row);
    drop_truncated_catalog_hosts(calls);
    drop_truncated_catalog_paths(calls);
    for row in calls.iter_mut() {
        if let Some(host) = row.host.as_deref() {
            row.third_party |= crate::is_third_party_host(host);
        }
    }
    calls.sort_by(|left, right| {
        catalog_weight(right)
            .cmp(&catalog_weight(left))
            .then_with(|| right.count.cmp(&left.count))
            .then_with(|| left.origin.cmp(&right.origin))
            .then_with(|| left.path.cmp(&right.path))
            .then_with(|| left.method.cmp(&right.method))
    });
    calls.truncate(256);
}

fn stamp_empty_hosts_from_sni(
    calls: &mut [HttpCallActivity],
    handshakes: &[HandshakeNameActivity],
) {
    let mut by_pid: BTreeMap<u32, BTreeSet<String>> = BTreeMap::new();
    for handshake in handshakes {
        if let Some(sni) = handshake.sni.as_deref().filter(|value| !value.is_empty()) {
            by_pid
                .entry(handshake.process_id)
                .or_default()
                .insert(sni.to_ascii_lowercase());
        }
        if let Some(host) = handshake
            .http_host
            .as_deref()
            .filter(|value| !value.is_empty())
        {
            by_pid
                .entry(handshake.process_id)
                .or_default()
                .insert(host.to_ascii_lowercase());
        }
    }
    for call in calls {
        if call.host.as_deref().is_some_and(|host| !host.is_empty()) {
            continue;
        }
        let Some(names) = by_pid.get(&call.process_id) else {
            continue;
        };
        if names.len() != 1 {
            continue;
        }
        let Some(host) = names.iter().next().cloned() else {
            continue;
        };
        if crate::format_inspect_url(Some("https"), &host, &call.path).is_some() {
            call.host = Some(host);
        }
    }
}

fn keep_catalog_row(row: &HttpCallActivity) -> bool {
    if row.host.as_deref().is_some_and(|host| {
        crate::format_inspect_url(Some("https"), host, &row.path).is_some()
    }) {
        return true;
    }
    row.status.is_some() && row.kind.contains("response")
}

fn drop_truncated_catalog_hosts(calls: &mut Vec<HttpCallActivity>) {
    let hosts: Vec<String> = calls.iter().filter_map(|row| row.host.clone()).collect();
    calls.retain(|row| {
        let Some(host) = row.host.as_deref() else {
            return row.status.is_some() && row.kind.contains("response");
        };
        !hosts
            .iter()
            .any(|other| crate::http_plain::is_truncated_host(host, other))
    });
}

fn drop_truncated_catalog_paths(calls: &mut Vec<HttpCallActivity>) {
    let keys: Vec<(String, String)> = calls
        .iter()
        .map(|row| (row.host.clone().unwrap_or_default(), row.path.clone()))
        .collect();
    calls.retain(|row| {
        let host = row.host.clone().unwrap_or_default();
        let path = &row.path;
        if path.is_empty() {
            return true;
        }
        !keys.iter().any(|(other_host, other_path)| {
            other_host == &host
                && other_path.len() > path.len()
                && other_path.starts_with(path)
                && other_path.as_bytes().get(path.len()).is_some_and(|byte| {
                    *byte == b'/' || byte.is_ascii_alphanumeric()
                })
        })
    });
}

fn catalog_weight(row: &HttpCallActivity) -> u8 {
    let Some(host) = row.host.as_deref().filter(|value| !value.is_empty()) else {
        return 0;
    };
    if row.third_party {
        return 1;
    }
    let host_l = host.to_ascii_lowercase();
    let path = row.path.to_ascii_lowercase();
    let static_like = host_l.contains("cdn")
        || host_l.contains("static")
        || host_l.starts_with("image")
        || path.contains("/static/")
        || path.contains("/assets/")
        || path.contains("/img/")
        || path.contains("/huamei_")
        || path.contains("/www/js/")
        || path.contains("/file/download/");
    let ext = std::path::Path::new(&path)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("");
    let static_like = static_like
        || ext.eq_ignore_ascii_case("js")
        || ext.eq_ignore_ascii_case("css");
    let api_like = path.contains("/api")
        || path.contains("/mbfront")
        || path.contains("/login")
        || path.contains("/ebs")
        || path.contains("/phone")
        || path.contains("/wap")
        || path.contains("/interface/")
        || row.kind.contains("request");
    let has_path = !path.is_empty();
    let mut weight: u8 = match row.origin.as_str() {
        "inspect" if api_like || (has_path && !static_like) => 6,
        "private" | "heap" if api_like => 5,
        "inspect" => 4,
        "private" | "heap" if has_path && !static_like => 4,
        "private" | "heap" if has_path => 3,
        _ => 2,
    };
    if source_matches_host(&row.source, host) && !static_like {
        weight = weight.saturating_add(2);
    }
    weight
}

fn source_matches_host(source: &str, host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    source
        .to_ascii_lowercase()
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .flat_map(|token| {
            let mut tokens = Vec::new();
            if token.len() >= 4 {
                tokens.push(token.to_owned());
            }
            for suffix in ["gphone", "phone", "mobile", "android"] {
                if let Some(stem) = token.strip_suffix(suffix) {
                    if stem.len() >= 4 {
                        tokens.push(stem.to_owned());
                    }
                }
            }
            tokens
        })
        .filter(|token| {
            !matches!(
                token.as_str(),
                "android"
                    | "phone"
                    | "mobile"
                    | "plat"
                    | "apps"
                    | "gphone"
                    | "main"
                    | "studio"
                    | "winner"
            )
        })
        .any(|token| host.contains(&token))
}

fn collect_store_files(
    dir: &std::path::Path,
    recursive: bool,
    out: &mut Vec<std::path::PathBuf>,
    remaining: &mut usize,
) {
    if *remaining == 0 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if *remaining == 0 {
            return;
        }
        let path = entry.path();
        if path.is_dir() {
            if recursive {
                collect_store_files(&path, true, out, remaining);
            }
            continue;
        }
        if path.components().any(|part| {
            skip_store_dir_name(&part.as_os_str().to_string_lossy())
        }) {
            continue;
        }
        if !keep_store_file(&path) {
            continue;
        }
        out.push(path);
        *remaining = remaining.saturating_sub(1);
    }
}

fn skip_store_dir_name(name: &str) -> bool {
    matches!(
        name,
        "fresco_disk_cache"
            | "image_manager_disk_cache"
            | "Crash Reports"
            | "HTTP Cache"
            | "Code Cache"
            | "Cache_Data"
            | "oat_primary"
            | "shaders_cache"
            | "com.android.opengl.shaders_cache.multifile"
    )
}

fn keep_store_file(path: &std::path::Path) -> bool {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if name.ends_with("-wal") || name.ends_with("-shm") || name.ends_with("-journal") {
        return false;
    }
    let ext = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    matches!(
        ext.as_str(),
        "xml" | "json" | "txt" | "html" | "db" | "sqlite" | "sqlite3" | ""
    ) || name.starts_with("mem-")
        || name == "cookies"
        || name.contains("webview")
}

fn pid_from_plaintext_name(path: &std::path::Path) -> u32 {
    path.file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_prefix("mem-"))
        .and_then(|name| name.split('-').next())
        .and_then(|pid| pid.parse().ok())
        .unwrap_or(0)
}

impl SessionReport {
    /// Join dump-package heap HTTP catalog. Heap edges stay correlated.
    pub fn ingest_dump_http_calls(&mut self, calls: Vec<HttpCallActivity>) {
        if calls.is_empty() {
            return;
        }
        let session_id = self.session_id.unwrap_or(Uuid::nil());
        attach_http_call_graph(&mut self.graph, session_id, &calls);
        pair_http_replies(&mut self.graph, session_id, &calls);
        self.http_calls.extend(calls);
        sort_http_catalog(&mut self.http_calls);
    }

    /// Join dump-side DEX string/method names onto HTTP calls. Always correlated.
    pub fn ingest_http_code_refs(&mut self, refs: Vec<HttpCodeRef>) {
        if refs.is_empty() {
            return;
        }
        self.http_code_refs.extend(refs);
        self.http_code_refs.truncate(128);
    }
}

/// Match HTTP catalog paths/hosts to DEX string-pool and method names.
///
/// Hits are correlated identifiers in the same dump, not JNI/ART call traces.
#[must_use]
pub fn correlate_http_calls_to_dex(
    calls: &[HttpCallActivity],
    sets: &[crate::DexArtifactSet],
) -> Vec<HttpCodeRef> {
    let mut refs = Vec::new();
    for call in calls.iter().take(64) {
        let path = call.path.trim();
        let host = call.host.as_deref().unwrap_or("");
        if path.len() < 4 && host.len() < 4 {
            continue;
        }
        let path_tail = path.rsplit('/').next().unwrap_or(path);
        for set in sets {
            let Some(semantic) = set.semantic.as_ref() else {
                continue;
            };
            let mut matches = Vec::new();
            for sample in semantic
                .api_strings
                .iter()
                .chain(semantic.method_names.iter())
                .chain(semantic.method_prototypes.iter())
            {
                if matches.len() >= 8 {
                    break;
                }
                let hit = (!path.is_empty() && path.len() >= 4 && sample.contains(path))
                    || (!host.is_empty() && sample.to_ascii_lowercase().contains(host))
                    || (path_tail.len() >= 6 && sample.contains(path_tail));
                if hit && !matches.iter().any(|seen: &String| seen == sample) {
                    matches.push(sample.clone());
                }
            }
            if matches.is_empty() {
                continue;
            }
            refs.push(HttpCodeRef {
                http_method: call.method.clone(),
                host: call.host.clone(),
                path: call.path.clone(),
                dex_sha256: Some(set.sha256.clone()),
                relative_path: Some(set.canonical_relative_path.clone()),
                matches,
            });
            if refs.len() >= 64 {
                return refs;
            }
        }
    }
    refs
}

const PREVIEW_STITCH_CAP: usize = 16 * 1024;

fn decode_inspect_preview(fragment: &ksight_model::InspectPlaintext) -> (String, String) {
    let raw = if fragment.preview_encoding == "hex" || preview_is_hex(&fragment.preview) {
        crate::decode_hex_bytes(&fragment.preview)
            .unwrap_or_else(|| fragment.preview.as_bytes().to_vec())
    } else {
        fragment.preview.as_bytes().to_vec()
    };
    if let Some(plain) = crate::inflate_inspect_buffer(&raw) {
        let text = String::from_utf8_lossy(&plain).into_owned();
        let class = if looks_mostly_printable(plain.as_slice()) {
            "text".to_owned()
        } else {
            "binary".to_owned()
        };
        return (text, class);
    }
    let class = if fragment.content_class.is_empty() {
        inferred_content_class("", Some(&fragment.preview))
    } else {
        fragment.content_class.clone()
    };
    if class == "tls_record" {
        return (fragment.preview.clone(), class);
    }
    (fragment.preview.clone(), class)
}

fn inspect_preview_bytes(fragment: &ksight_model::InspectPlaintext) -> Vec<u8> {
    if fragment.preview_encoding == "hex" || preview_is_hex(&fragment.preview) {
        crate::decode_hex_bytes(&fragment.preview)
            .unwrap_or_else(|| fragment.preview.as_bytes().to_vec())
    } else {
        fragment.preview.as_bytes().to_vec()
    }
}

fn absorb_plaintext_preview(activity: &mut MutablePlaintext, preview: &str, class: &str) {
    if preview.is_empty() {
        return;
    }
    extend_unique(&mut activity.urls, &preview_url_list(preview), 32);
    let new_score = preview_evidence_score(preview, class);
    activity.preview = Some(match activity.preview.take() {
        None => preview.to_owned(),
        Some(existing) => {
            let old_score = preview_evidence_score(&existing, "");
            let new_urls = new_score.0;
            let old_urls = old_score.0;
            if new_urls > 0
                && old_urls > 0
                && !preview_is_hex(preview)
                && !preview_is_hex(&existing)
                && !preview_is_tls_record_text(preview)
                && !preview_is_tls_record_text(&existing)
            {
                stitch_preview(&existing, preview)
            } else if new_score > old_score {
                preview.to_owned()
            } else {
                existing
            }
        }
    });
}

fn preview_url_list(preview: &str) -> Vec<String> {
    crate::parse_http_plain_all(preview, "text")
        .into_iter()
        .filter_map(|parsed| {
            if !matches!(parsed.kind, "url" | "http1_request" | "http2_request") {
                return None;
            }
            let scheme = parsed.scheme.or(Some("https"));
            crate::format_inspect_url(scheme, parsed.host.as_deref()?, &parsed.path)
        })
        .collect()
}

fn preview_evidence_score(preview: &str, class: &str) -> (u32, u8, u8, usize) {
    if preview.is_empty() || class == "tls_record" || preview_is_tls_record_text(preview) {
        return (0, 0, 0, 0);
    }
    if preview_is_hex(preview) {
        return (0, 0, 0, 0);
    }
    let urls = u32::try_from(preview_url_list(preview).len()).unwrap_or(u32::MAX);
    let kind = if preview.contains("HTTP/1.")
        || preview.starts_with("GET ")
        || preview.starts_with("POST ")
    {
        3_u8
    } else if preview.contains("\"url\"")
        || preview.contains("https://")
        || preview.contains("http://")
        || preview.contains('{')
    {
        2
    } else {
        u8::from(class == "text" || looks_mostly_printable(preview.as_bytes()))
    };
    (
        urls,
        1,
        kind,
        if urls > 0 {
            preview.len().min(PREVIEW_STITCH_CAP)
        } else {
            0
        },
    )
}

fn stitch_preview(existing: &str, next: &str) -> String {
    let mut out = String::with_capacity(
        existing
            .len()
            .saturating_add(next.len())
            .saturating_add(1)
            .min(PREVIEW_STITCH_CAP),
    );
    out.push_str(existing);
    let next_trim = next.trim_start();
    if !existing.ends_with('\n')
        && (next_trim.starts_with("http://")
            || next_trim.starts_with("https://")
            || next_trim.starts_with("HTTP/"))
    {
        out.push('\n');
    }
    out.push_str(next);
    if out.len() > PREVIEW_STITCH_CAP {
        out.truncate(PREVIEW_STITCH_CAP);
    }
    out
}

fn preview_is_hex(preview: &str) -> bool {
    let trimmed = preview.trim();
    trimmed.len() >= 8
        && trimmed.len() % 2 == 0
        && trimmed.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn preview_is_tls_record_text(preview: &str) -> bool {
    preview.starts_with("TLS ") || inferred_content_class("", Some(preview)) == "tls_record"
}

fn looks_mostly_printable(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let printable = bytes
        .iter()
        .filter(|byte| byte.is_ascii_graphic() || byte.is_ascii_whitespace())
        .count();
    printable.saturating_mul(4) >= bytes.len().saturating_mul(3)
}

fn inferred_content_class(class: &str, preview: Option<&str>) -> String {
    if !class.is_empty() {
        return class.to_owned();
    }
    let Some(preview) = preview.map(str::trim) else {
        return String::new();
    };
    if preview.len() < 6 || !preview.is_ascii() {
        return String::new();
    }
    let Ok(record) = u8::from_str_radix(&preview[..2], 16) else {
        return String::new();
    };
    let Ok(version) = u16::from_str_radix(&preview[2..6], 16) else {
        return String::new();
    };
    if matches!(record, 0x14..=0x17) && matches!(version, 0x0301..=0x0304) {
        "tls_record".to_owned()
    } else {
        String::new()
    }
}

#[allow(clippy::type_complexity)]
fn merge_handshake(dst: &mut MutableHandshake, src: &MutableHandshake) {
    if dst.kind.is_empty() {
        dst.kind.clone_from(&src.kind);
    } else if !src.kind.is_empty() && !dst.kind.split(',').any(|part| part == src.kind) {
        dst.kind = format!("{},{}", dst.kind, src.kind);
    }
    if dst.sni.is_none() {
        dst.sni.clone_from(&src.sni);
    }
    if dst.alpn.is_none() {
        dst.alpn.clone_from(&src.alpn);
    }
    if dst.http_host.is_none() {
        dst.http_host.clone_from(&src.http_host);
    }
    if dst.http_method.is_none() {
        dst.http_method.clone_from(&src.http_method);
    }
}

fn apply_handshake(activity: &mut MutableNetworkPeerActivity, stamp: &MutableHandshake) {
    if activity.sni.is_none() {
        activity.sni.clone_from(&stamp.sni);
    }
    if activity.alpn.is_none() {
        activity.alpn.clone_from(&stamp.alpn);
    }
    if activity.http_host.is_none() {
        activity.http_host.clone_from(&stamp.http_host);
    }
    if activity.http_method.is_none() {
        activity.http_method.clone_from(&stamp.http_method);
    }
    if activity.handshake_kind.is_none() {
        if !stamp.kind.is_empty() {
            activity.handshake_kind = Some(stamp.kind.clone());
        }
    } else if let Some(existing) = activity.handshake_kind.as_mut() {
        if !stamp.kind.is_empty() && !existing.split(',').any(|part| part == stamp.kind) {
            existing.push(',');
            existing.push_str(&stamp.kind);
        }
    }
}

#[allow(clippy::type_complexity)]
fn collapse_loopback_scans(peers: &mut Vec<NetworkPeerActivity>) -> Vec<LoopbackScanActivity> {
    let mut unique: BTreeMap<(u32, String), BTreeSet<u16>> = BTreeMap::new();
    for peer in peers.iter() {
        if let Some(port) = peer.port {
            if peer.peer == "127.0.0.1" || peer.peer == "::1" {
                unique
                    .entry((peer.source_process_id, peer.peer.clone()))
                    .or_default()
                    .insert(port);
            }
        }
    }
    let collapse: BTreeSet<(u32, String)> = unique
        .into_iter()
        .filter(|(_, ports)| ports.len() >= 16)
        .map(|(key, _)| key)
        .collect();
    let mut grouped: BTreeMap<(u32, String, String), (u16, u16, u64, u64)> = BTreeMap::new();
    peers.retain(|peer| {
        let key = (peer.source_process_id, peer.peer.clone());
        if !collapse.contains(&key) {
            return true;
        }
        let Some(port) = peer.port else {
            return true;
        };
        let slot = grouped
            .entry((
                peer.source_process_id,
                peer.source.clone(),
                peer.peer.clone(),
            ))
            .or_insert((port, port, 0, 0));
        slot.0 = slot.0.min(port);
        slot.1 = slot.1.max(port);
        slot.2 = slot.2.saturating_add(1);
        slot.3 = slot.3.saturating_add(peer.attempts);
        false
    });
    let mut scans = grouped
        .into_iter()
        .map(
            |((process_id, source, address), (port_min, port_max, unique_ports, attempts))| {
                LoopbackScanActivity {
                    source,
                    process_id,
                    address,
                    port_min,
                    port_max,
                    unique_ports,
                    attempts,
                }
            },
        )
        .collect::<Vec<_>>();
    scans.sort_by_key(|scan| std::cmp::Reverse(scan.attempts));
    scans
}

fn mode_name(mode: ksight_model::CaptureMode) -> &'static str {
    match mode {
        ksight_model::CaptureMode::Observe => "observe",
        ksight_model::CaptureMode::Inspect => "inspect",
        ksight_model::CaptureMode::Debug => "debug",
    }
}

fn path_category(path: &str) -> &'static str {
    let lower = path.to_ascii_lowercase();
    let extension = std::path::Path::new(path)
        .extension()
        .and_then(std::ffi::OsStr::to_str);
    if extension.is_some_and(|value| {
        value.eq_ignore_ascii_case("dex")
            || value.eq_ignore_ascii_case("odex")
            || value.eq_ignore_ascii_case("vdex")
    }) {
        "dex"
    } else if extension
        .is_some_and(|value| value.eq_ignore_ascii_case("apk") || value.eq_ignore_ascii_case("jar"))
    {
        "android_package"
    } else if extension.is_some_and(|value| value.eq_ignore_ascii_case("so"))
        || lower.contains("/lib/")
    {
        "native_elf_candidate"
    } else if lower.starts_with("/proc/") {
        "proc"
    } else if lower.starts_with("/sys/") {
        "sys"
    } else if lower.starts_with("/data/") {
        "app_or_system_data"
    } else {
        "other"
    }
}

fn plaintext_graph_relation(adapter: &str, direction: &str) -> &'static str {
    if adapter.starts_with("jni_") {
        match direction {
            "java_to_native" => "jni_from_java",
            "native_to_java" => "jni_to_java",
            _ => "jni_plain",
        }
    } else if direction == "recv" {
        "tls_recv"
    } else {
        "tls_send"
    }
}

fn report_limitations() -> Vec<String> {
    vec![
        "Binder driver submission-to-delivery latency is correlated by transaction ID. Two-way RPCs pair reply submit to the request debug_id (binder_reply / replies_to, confirmed). A 128-byte parcel prefix is copied at kprobe binder_transaction (every online CPU) for 32-bit and 64-bit clients (native UAPI after compat conversion) and parsed as writeInterfaceToken String16. Inspect transact joins that request by tid+code as correlated joined_transact and copies reply latency when the kernel pair exists. Inspect pairs writeInterfaceToken and bounded exported Parcel writers on the same TID on ELF64; this GKI rejects AArch32 uprobes. AIDL method names come from on-device AOSP Stub tables (aosp_stub) or that process's loaded DEX TRANSACTION_* (process_dex). Parcel C++ object fields and writeFloat/writeDouble (no FPSIMD in uprobe pt_regs) are not read.".to_owned(),
        "DEX, ELF, connlog, and packed-cache path candidates may include a SHA-256 when a regular file <= 1 MiB is opened; capture also copies those forensic files under the spool forensics directory because apps often delete packed DEX after load.".to_owned(),
        "Connect/accept and FD baseline/dup/close evidence reconstruct descriptor lifetimes. Optional network-io counts byte-returning socket calls and reports sendmmsg/recvmmsg results as message counts. UDP/53 datagrams parse QNAME/A/AAAA and stamp later connect() as correlated resolved_name (same-process first, then any resolver that answered the IP). getaddrinfo uprobes and non-53 resolvers remain uncovered. TLS/QUIC plaintext is Inspect-only. Consecutive SSL_read/SSL_write text previews for one process are stitched up to 16 KiB. gzip/zlib magic in those buffers is inflated before HTTP/JSON/`http(s)://` URL parse. HTTP/1 request-line, Host, query keys, JSON/form keys, embedded URLs, and HTTP/2 HEADERS HPACK (`:method`/`:path`/`:authority`) go into http_calls; Cookie/Authorization/token values are redacted. HTTP responses have no URL path. Heap windows that start at HTTP/1.1, GET/POST, `https://`, `\"url\"`, `/api/`, `/login`, `/mbfront`, or `:path`/`:authority` are 8192-byte cuts (NUL or CRLF), not a full memory image. CE/DE shared_prefs/SQLite copies contribute origin=private URL rows. Same-process same-host request/response pairs are correlated http_reply. HPACK is report-side analysis of already-copied Inspect/dump buffers, not MITM. QUIC/HTTP/3 bodies, Cronet without SSL_write, Flutter Dart TLS, WebView/Chromium, and custom TLS without that export are not decoded.".to_owned(),
        "The L0 graph is queryable (`ksightctl device graph`). Process instances use `procinst:{boot_id:pid:start_time_ns}` when start time is known; otherwise `process:pkg:pid`. Confirmed edges are Binder, Binder `replies_to`/`binder_reply` (request debug_id), socket, Binder FD `transfers_fd`, loopback scans, sched wakeup identity, and mmap/remap `maps` edges. Dump VMA `overlaps_mmap` is correlated even on an exact address match. Inspect `inspect_hit` and TLS `tls_send`/`tls_recv` are selected-process facts, not Observe. JNIEnv UTF-8/`byte[]` Inspect previews graph as `jni_from_java`/`jni_to_java` (confirmed selected-process, not Observe). Inspect HTTP `http_call` edges are parsed from those TLS or JNI previews (HTTP/1, HTTP/2 HPACK, JSON, or embedded URLs); dump heap `http_call` edges are correlated. Same-host `http_reply` is correlated, not a stream id. Binder userspace hits record handle/code and join L0 `binder:req` by tid+code as correlated `joined_transact`. The interface token and bounded scalars come from exported Parcel writers on the same TID. AIDL names come from on-device AOSP Stub tables or session process DEX; they are not hardcoded GMS/app names. Parcel C++ fields are not read. RegisterNatives copies JNINativeMethod name/signature/fnPtr from the JNINativeInterface slot; jclass fields and Java/native stacks remain unresolved. Cronet/QUIC and custom TLS remain unresolved. Time proximity is never a confirmed edge.".to_owned(),
        "dup/close file-descriptor events are off unless --files-fd is set. WebView/Chromium dup storms previously overflowed the file ring and dropped millions of records.".to_owned(),
        "Sampling, truncation, source loss, compatibility failures, or target early exit can make application behavior incomplete.".to_owned(),
    ]
}

#[cfg(test)]
mod tests {
    use ksight_model::{
        BinderTransaction, BinderTransactionDirection, BinderTransactionStage, CaptureMode,
        Confidence, DataQuality, EventHeader, InspectObservation, PackageCandidate,
        ProcessIdentity, ProcessKey, SchemaVersion,
    };

    use super::*;

    #[test]
    fn groups_binder_and_artifact_activity_without_claiming_semantics() {
        let session = Uuid::new_v4();
        let mut builder = SessionReportBuilder::default();
        builder.record(&binder_event(session, 10, Some(20), false, 7));
        builder.record(&binder_event(session, 20, Some(10), true, 0));
        builder.record(&file_event(session, "/data/app/com.example/base.apk"));

        let report = builder.finish();
        assert_eq!(report.total_events, 3);
        assert_eq!(report.binder_relations.len(), 2);
        assert_eq!(report.artifacts[0].category, "android_package");
        assert!(report
            .limitations
            .iter()
            .any(|value| value.contains("AIDL")));
        assert!(report
            .graph
            .edges
            .iter()
            .any(|edge| edge.relation == "binder"));
        let binder_graph = report.graph.query(&crate::GraphQuery {
            relation: Some("binder".to_owned()),
            limit: 8,
            ..crate::GraphQuery::default()
        });
        assert!(!binder_graph.edges.is_empty());
        assert!(report.graph.edges.iter().any(|edge| {
            edge.relation == "binder" && edge.from.contains(":10") && edge.to.contains(":20")
        }));
        assert!(report
            .graph
            .edges
            .iter()
            .any(|edge| edge.relation == "contains"));
        assert!(report
            .processes
            .iter()
            .any(|process| process.instances.iter().any(
                |instance| instance.pid == 10 && instance.process_instance_id.contains(":10:")
            )));
        assert!(report
            .graph
            .entities
            .iter()
            .any(|entity| entity.key.starts_with("procinst:")
                && entity.process_instance_id.is_some()));
    }

    #[test]
    fn infers_tls_record_from_legacy_preview_and_keeps_file_digest() {
        let session = Uuid::new_v4();
        let mut builder = SessionReportBuilder::default();
        let mut hashed = file_event(session, "/data/user/0/com.example/code_cache/1.dex");
        if let EventPayload::FileOpen(open) = &mut hashed.payload {
            open.content_sha256 = Some("abc123".to_owned());
            open.content_bytes = Some(32);
        }
        builder.record(&hashed);
        builder.record(&Event {
            header: header(session, 10, SensorKind::Integrity),
            payload: EventPayload::InspectPlaintext(ksight_model::InspectPlaintext {
                adapter: "tls_ssl_write".to_owned(),
                direction: "send".to_owned(),
                library: "libssl.so".to_owned(),
                build_id: None,
                offset: None,
                requested_bytes: 64,
                captured_bytes: 16,
                truncated: false,
                sha256: "deadbeef".to_owned(),
                preview: "17030307a4000000".to_owned(),
                preview_encoding: "hex".to_owned(),
                content_class: String::new(),
            }),
        });

        let report = builder.finish();
        assert_eq!(
            report.artifacts[0].content_sha256.as_deref(),
            Some("abc123")
        );
        assert_eq!(report.plaintext[0].content_class, "tls_record");
        assert!(report
            .graph
            .edges
            .iter()
            .any(|edge| { edge.relation == "tls_send" && edge.from == "process:com.example:10" }));
    }

    #[test]
    fn separates_failed_opens_and_attributes_truncation() {
        let session = Uuid::new_v4();
        let mut builder = SessionReportBuilder::default();
        builder.record(&file_event(session, "/data/app/com.example/base.apk"));
        let mut failed = file_event(session, "/data/app/com.example/base.apk");
        let EventPayload::FileOpen(open) = &mut failed.payload else {
            unreachable!("file_event must produce FileOpen");
        };
        open.result = -2;
        open.file_descriptor = None;
        failed.header.quality.truncated = true;
        failed.header.quality.source = "syscalls/sys_exit_openat".to_owned();
        builder.record(&failed);

        let report = builder.finish();
        assert_eq!(report.artifacts[0].open_attempts, 2);
        assert_eq!(report.artifacts[0].successful_opens, 1);
        assert_eq!(report.artifacts[0].failed_opens, 1);
        assert_eq!(
            report.quality.truncated_by_source["syscalls/sys_exit_openat"],
            1
        );
    }

    #[test]
    fn correlates_fd_and_binder_lifecycles() {
        let session = Uuid::new_v4();
        let mut builder = SessionReportBuilder::default();
        builder.record(&file_event(session, "/data/local/tmp/demo.so"));
        builder.record(&fd_event(session, FileDescriptorOperation::Duplicate, 3, 4));
        builder.record(&fd_event(session, FileDescriptorOperation::Close, 3, 0));
        builder.record(&socket_event(session, 4, -115));
        builder.record(&socket_io_event(session, 4, SocketIoOperation::Send, 120));
        builder.record(&fd_event(session, FileDescriptorOperation::Close, 4, 0));
        builder.record(&socket_accept_event(session, 7, 5));
        builder.record(&socket_io_event(session, 5, SocketIoOperation::Receive, 80));
        builder.record(&fd_event(session, FileDescriptorOperation::Close, 5, 0));
        builder.record(&memory_event(session, MemoryOperation::Map, 0x1000, 0x2000));
        builder.record(&memory_event(
            session,
            MemoryOperation::Unmap,
            0x1800,
            0x800,
        ));

        let mut submitted = binder_event(session, 10, Some(20), false, 7);
        submitted.header.monotonic_ns = 100;
        builder.record(&submitted);
        let mut received = binder_event(session, 20, None, false, 0);
        received.header.monotonic_ns = 160;
        if let EventPayload::BinderTransaction(transaction) = &mut received.payload {
            transaction.stage = BinderTransactionStage::Received;
            transaction.transaction_id = 10;
        }
        builder.record(&received);

        let report = builder.finish();
        assert_eq!(report.fd_lifecycle.successful_opens, 1);
        assert_eq!(report.fd_lifecycle.successful_duplicates, 1);
        assert_eq!(report.fd_lifecycle.successful_closes, 3);
        assert_eq!(report.fd_lifecycle.active_at_end, 0);
        assert!(report.fd_lifecycle.lineage_complete);
        assert_eq!(report.socket_lifecycle.connected_or_in_progress, 1);
        assert_eq!(report.socket_lifecycle.accept_attempts, 1);
        assert_eq!(report.socket_lifecycle.accepted_descriptors, 1);
        assert_eq!(report.socket_lifecycle.sent_bytes, 120);
        assert_eq!(report.socket_lifecycle.received_bytes, 80);
        assert_eq!(report.socket_lifecycle.io_without_observed_lifecycle, 0);
        assert_eq!(report.socket_lifecycle.closed_descriptors, 2);
        assert_eq!(report.socket_lifecycle.active_at_end, 0);
        assert_eq!(report.memory_lifecycle.unmaps_with_observed_mapping, 1);
        assert_eq!(report.memory_lifecycle.unmaps_without_observed_mapping, 0);
        assert_eq!(report.memory_lifecycle.active_regions_at_end, 2);
        assert!(report.observed_mappings.iter().any(|mapping| {
            mapping.process_id == 10
                && mapping.start == 0x1000
                && mapping.end == 0x3000
                && mapping.source == MappingSource::Mmap
        }));
        assert!(report.graph.edges.iter().any(|edge| {
            edge.relation == "maps"
                && edge.strength == crate::EdgeStrength::Confirmed
                && edge.to.starts_with("mmap:10:1000-3000")
        }));
        assert_eq!(report.binder_lifecycle.submitted, 1);
        assert_eq!(report.binder_lifecycle.delivered, 1);
        assert_eq!(report.binder_lifecycle.average_delivery_ns, Some(60));
        assert_eq!(report.binder_lifecycle.two_way_submitted, 1);
        assert_eq!(report.binder_lifecycle.paired_replies, 0);
    }

    #[test]
    fn pairs_two_way_binder_request_and_reply() {
        let session = Uuid::new_v4();
        let mut builder = SessionReportBuilder::default();
        let mut request = binder_event(session, 10, Some(20), false, 7);
        request.header.monotonic_ns = 100;
        if let EventPayload::BinderTransaction(transaction) = &mut request.payload {
            transaction.transaction_id = 42;
        }
        builder.record(&request);
        let mut reply = binder_event(session, 20, Some(10), true, 7);
        reply.header.monotonic_ns = 5_100;
        if let EventPayload::BinderTransaction(transaction) = &mut reply.payload {
            transaction.transaction_id = 99;
            transaction.reply = true;
            transaction.direction = BinderTransactionDirection::Reply;
            transaction.reply_to_request_id = Some(42);
            transaction.reply_latency_ns = Some(5_000);
        }
        builder.record(&reply);
        let report = builder.finish();
        assert_eq!(report.binder_lifecycle.two_way_submitted, 1);
        assert_eq!(report.binder_lifecycle.reply_submitted, 1);
        assert_eq!(report.binder_lifecycle.paired_replies, 1);
        assert_eq!(report.binder_lifecycle.average_reply_ns, Some(5_000));
        assert_eq!(report.binder_reply_pairs.len(), 1);
        assert_eq!(report.binder_reply_pairs[0].request_transaction_id, 42);
        assert_eq!(report.binder_reply_pairs[0].client_process_id, 10);
        assert_eq!(report.binder_reply_pairs[0].server_process_id, 20);
        assert!(report
            .graph
            .edges
            .iter()
            .any(|edge| edge.relation == "replies_to"
                && edge.strength == crate::EdgeStrength::Confirmed));
        assert!(report
            .graph
            .edges
            .iter()
            .any(|edge| edge.relation == "binder_reply"
                && edge.strength == crate::EdgeStrength::Confirmed));
    }

    #[test]
    fn one_way_binder_is_not_a_reply_pair() {
        let session = Uuid::new_v4();
        let mut builder = SessionReportBuilder::default();
        let mut request = binder_event(session, 10, Some(20), false, 7);
        if let EventPayload::BinderTransaction(transaction) = &mut request.payload {
            transaction.transaction_id = 42;
            transaction.flags = 0x1;
            transaction.decoded_flags = vec![ksight_model::BinderTransactionFlag::OneWay];
        }
        builder.record(&request);
        let report = builder.finish();
        assert_eq!(report.binder_lifecycle.one_way_submitted, 1);
        assert_eq!(report.binder_lifecycle.two_way_submitted, 0);
        assert_eq!(report.binder_lifecycle.paired_replies, 0);
        assert!(report.binder_reply_pairs.is_empty());
    }

    #[test]
    fn kernel_parcel_token_is_counted_on_binder_relation() {
        let session = Uuid::new_v4();
        let mut builder = SessionReportBuilder::default();
        let mut request = binder_event(session, 10, Some(20), false, 1);
        if let EventPayload::BinderTransaction(transaction) = &mut request.payload {
            transaction.transaction_id = 42;
            transaction.interface_token = Some("android.os.IServiceManager".to_owned());
            transaction.binder_method = Some("getService".to_owned());
            transaction.binder_method_source = Some("aosp_stub".to_owned());
        }
        builder.record(&request);
        let report = builder.finish();
        assert_eq!(
            report.binder_relations[0]
                .interfaces
                .get("android.os.IServiceManager"),
            Some(&1)
        );
        assert!(report.graph.entities.iter().any(|entity| {
            entity.key == "binder:req:42"
                && entity
                    .label
                    .contains("android.os.IServiceManager::getService")
        }));
    }

    #[test]
    fn inspect_transact_joins_two_way_binder_by_tid_and_code() {
        let session = Uuid::new_v4();
        let mut builder = SessionReportBuilder::default();
        builder.record(&inspect_transact_event(session, 10, 11, 7));
        let mut request = binder_event(session, 10, Some(20), false, 7);
        request.header.process.tid = 11;
        request.header.monotonic_ns = 100;
        if let EventPayload::BinderTransaction(transaction) = &mut request.payload {
            transaction.transaction_id = 42;
        }
        builder.record(&request);
        let mut reply = binder_event(session, 20, Some(10), true, 7);
        reply.header.monotonic_ns = 5_100;
        if let EventPayload::BinderTransaction(transaction) = &mut reply.payload {
            transaction.transaction_id = 99;
            transaction.reply = true;
            transaction.direction = BinderTransactionDirection::Reply;
            transaction.reply_to_request_id = Some(42);
            transaction.reply_latency_ns = Some(5_000);
        }
        builder.record(&reply);
        let report = builder.finish();
        let hit = report
            .inspect_hits
            .iter()
            .find(|row| row.adapter == "binder_userspace")
            .expect("inspect hit");
        assert_eq!(hit.binder_transaction_id, Some(42));
        assert_eq!(hit.reply_latency_ns, Some(5_000));
        assert!(report.graph.edges.iter().any(|edge| {
            edge.relation == "joined_transact"
                && edge.strength == crate::EdgeStrength::Correlated
                && edge.to == "binder:req:42"
        }));
        assert!(report
            .graph
            .edges
            .iter()
            .any(|edge| edge.relation == "replies_to"));
    }

    #[test]
    fn inspect_transact_does_not_join_mismatched_tid() {
        let session = Uuid::new_v4();
        let mut builder = SessionReportBuilder::default();
        builder.record(&inspect_transact_event(session, 10, 11, 7));
        let mut request = binder_event(session, 10, Some(20), false, 7);
        request.header.process.tid = 99;
        if let EventPayload::BinderTransaction(transaction) = &mut request.payload {
            transaction.transaction_id = 42;
        }
        builder.record(&request);
        let report = builder.finish();
        let hit = report
            .inspect_hits
            .iter()
            .find(|row| row.adapter == "binder_userspace")
            .expect("inspect hit");
        assert_eq!(hit.binder_transaction_id, None);
        assert!(report
            .graph
            .edges
            .iter()
            .all(|edge| edge.relation != "joined_transact"));
    }

    #[test]
    fn inspect_transact_joins_one_way_request_without_reply_latency() {
        let session = Uuid::new_v4();
        let mut builder = SessionReportBuilder::default();
        builder.record(&inspect_transact_event(session, 10, 11, 7));
        let mut request = binder_event(session, 10, Some(20), false, 7);
        request.header.process.tid = 11;
        if let EventPayload::BinderTransaction(transaction) = &mut request.payload {
            transaction.transaction_id = 42;
            transaction.flags = 0x1;
            transaction.decoded_flags = vec![ksight_model::BinderTransactionFlag::OneWay];
        }
        builder.record(&request);
        let report = builder.finish();
        let hit = report
            .inspect_hits
            .iter()
            .find(|row| row.adapter == "binder_userspace")
            .expect("inspect hit");
        assert_eq!(hit.binder_transaction_id, Some(42));
        assert_eq!(hit.reply_latency_ns, None);
        assert!(report
            .graph
            .edges
            .iter()
            .any(|edge| { edge.relation == "joined_transact" && edge.to == "binder:req:42" }));
    }

    #[test]
    fn baselines_seed_fd_socket_and_memory_state() {
        let session = Uuid::new_v4();
        let mut builder = SessionReportBuilder::default();
        builder.record(&Event {
            header: header(session, 10, SensorKind::File),
            payload: EventPayload::SessionFdBaseline(ksight_model::SessionFdBaseline {
                process_id: 10,
                fds: vec![ksight_model::BaselineFd {
                    fd: 7,
                    kind: BaselineFdKind::Socket,
                    target: "socket:[123]".to_owned(),
                }],
                chunk_index: 0,
                chunk_count: 1,
            }),
        });
        builder.record(&Event {
            header: header(session, 10, SensorKind::Memory),
            payload: EventPayload::SessionVmaBaseline(ksight_model::SessionVmaBaseline {
                process_id: 10,
                vmas: vec![ksight_model::BaselineVma {
                    start: 0x1000,
                    end: 0x3000,
                    protection: 5,
                    path: Some("/system/lib64/libc.so".to_owned()),
                }],
                chunk_index: 0,
                chunk_count: 1,
            }),
        });

        let report = builder.finish();
        assert_eq!(report.fd_lifecycle.active_at_end, 1);
        assert_eq!(report.socket_lifecycle.active_at_end, 1);
        assert_eq!(report.memory_lifecycle.active_regions_at_end, 1);
        assert_eq!(report.artifacts[0].mappings, 1);
        assert_eq!(report.observed_mappings.len(), 1);
        assert_eq!(
            report.observed_mappings[0].source,
            MappingSource::VmaBaseline
        );
        assert!(report.graph.edges.iter().any(|edge| {
            edge.relation == "maps" && edge.strength == crate::EdgeStrength::Correlated
        }));
    }

    #[test]
    fn observed_mappings_keep_large_mmap_ahead_of_tiny_baselines() {
        let session = Uuid::new_v4();
        let mut builder = SessionReportBuilder::default();
        builder.record(&Event {
            header: header(session, 10, SensorKind::Memory),
            payload: EventPayload::SessionVmaBaseline(ksight_model::SessionVmaBaseline {
                process_id: 10,
                vmas: (0_u32..80)
                    .map(|index| ksight_model::BaselineVma {
                        start: u64::from(index) * 0x1000,
                        end: u64::from(index) * 0x1000 + 0x1000,
                        protection: 3,
                        path: None,
                    })
                    .collect(),
                chunk_index: 0,
                chunk_count: 1,
            }),
        });
        builder.record(&memory_event(
            session,
            MemoryOperation::Map,
            0x006e_5f3f_1000,
            53_604_352,
        ));
        builder.record(&memory_event(session, MemoryOperation::Map, 0, 1 << 50));

        let report = builder.finish();
        assert_eq!(report.observed_mappings[0].source, MappingSource::Mmap);
        assert_eq!(report.observed_mappings[0].start, 0x006e_5f3f_1000);
        assert!(report.observed_mappings.iter().all(|mapping| {
            mapping.start >= 0x1000
                && mapping.end.saturating_sub(mapping.start) <= 1024 * 1024 * 1024
        }));
        assert_eq!(report.memory_lifecycle.mapped_bytes, 53_604_352);
        assert!(report.graph.edges.iter().any(|edge| {
            edge.relation == "maps"
                && edge.strength == crate::EdgeStrength::Confirmed
                && edge.to.contains("mmap:10:6e5f3f1000-")
        }));
    }

    #[test]
    fn mmsg_results_are_messages_not_bytes() {
        let session = Uuid::new_v4();
        let mut builder = SessionReportBuilder::default();
        builder.record(&socket_event(session, 4, 0));
        let mut send = socket_io_event(session, 4, SocketIoOperation::Send, 3);
        let EventPayload::SocketIo(io) = &mut send.payload else {
            panic!("expected socket I/O");
        };
        io.syscall = 269;
        io.requested_bytes = None;
        builder.record(&send);

        let report = builder.finish();
        assert_eq!(report.socket_lifecycle.sent_messages, 3);
        assert_eq!(report.socket_lifecycle.sent_bytes, 0);
        assert_eq!(report.network_peers[0].sent_messages, 3);
        assert_eq!(report.network_peers[0].sent_bytes, 0);
    }

    #[test]
    fn dns_answer_stamps_connect_at_finish() {
        let session = Uuid::new_v4();
        let mut builder = SessionReportBuilder::default();
        builder.record(&socket_event(session, 5, 0));
        builder.record(&Event {
            header: header(session, 10, SensorKind::Network),
            payload: EventPayload::DnsDatagram(ksight_model::DnsDatagram {
                file_descriptor: 4,
                result: 32,
                address_family: 2,
                peer_port: 53,
                peer_address: Some("8.8.8.8".to_owned()),
                direction: "response".to_owned(),
                truncated: false,
                qname: Some("example.com".to_owned()),
                addresses: vec!["127.0.0.1".to_owned()],
            }),
        });
        let report = builder.finish();
        assert_eq!(report.dns_datagrams, 1);
        assert_eq!(report.dns_names[0].qname, "example.com");
        assert_eq!(
            report.network_peers[0].resolved_name.as_deref(),
            Some("example.com")
        );
        assert!(report
            .graph
            .edges
            .iter()
            .any(|edge| edge.relation == "answers"
                && edge.strength == crate::EdgeStrength::Correlated));
    }

    #[test]
    fn unique_sni_stamps_empty_inspect_http_host() {
        let mut calls = vec![HttpCallActivity {
            source: "us.hsbc.hsbcus".to_owned(),
            process_id: 7554,
            direction: "recv".to_owned(),
            kind: "http1_response".to_owned(),
            method: "HTTP".to_owned(),
            host: None,
            path: String::new(),
            status: Some(200),
            query_keys: Vec::new(),
            header_names: vec!["Content-Type".to_owned()],
            redacted_headers: Vec::new(),
            body_keys: Vec::new(),
            redacted_body_keys: Vec::new(),
            content_type: Some("application/json".to_owned()),
            third_party: false,
            count: 1,
            origin: "inspect".to_owned(),
        }];
        let handshakes = vec![HandshakeNameActivity {
            process_id: 7554,
            kind: "tls".to_owned(),
            sni: Some("www.us.hsbc.com".to_owned()),
            alpn: Some("h2".to_owned()),
            http_host: None,
            http_method: None,
            peer: None,
            port: None,
        }];
        stamp_empty_hosts_from_sni(&mut calls, &handshakes);
        assert_eq!(calls[0].host.as_deref(), Some("www.us.hsbc.com"));
    }

    #[test]
    fn handshake_sni_stamps_connect_at_finish() {
        let session = Uuid::new_v4();
        let mut builder = SessionReportBuilder::default();
        builder.record(&socket_event(session, 5, 0));
        builder.record(&Event {
            header: header(session, 10, SensorKind::Network),
            payload: EventPayload::NetworkHandshake(ksight_model::NetworkHandshake {
                file_descriptor: 5,
                result: 120,
                address_family: 2,
                peer_port: 0,
                peer_address: None,
                truncated: false,
                kind: "tls".to_owned(),
                sni: Some("bank.example".to_owned()),
                alpn: Some("h2".to_owned()),
                ech: false,
                http_method: None,
                http_path: None,
                http_host: None,
                quic_version: None,
                quic_packet: None,
            }),
        });
        let report = builder.finish();
        assert_eq!(report.handshake_events, 1);
        assert_eq!(
            report.handshake_names[0].sni.as_deref(),
            Some("bank.example")
        );
        assert_eq!(report.network_peers[0].sni.as_deref(), Some("bank.example"));
        assert_eq!(report.network_peers[0].alpn.as_deref(), Some("h2"));
        assert!(report.graph.edges.iter().any(|edge| {
            edge.relation == "sni" && edge.strength == crate::EdgeStrength::Correlated
        }));
    }

    #[test]
    fn binder_fd_receive_emits_transfers_fd() {
        let session = Uuid::new_v4();
        let mut builder = SessionReportBuilder::default();
        let mut received = binder_event(session, 20, Some(10), false, 1);
        received.payload = EventPayload::BinderTransaction(BinderTransaction {
            stage: BinderTransactionStage::FdReceived,
            transaction_id: 7,
            target_node: None,
            target_process_id: Some(20),
            target_thread_id: None,
            target_kind: None,
            reply: false,
            direction: BinderTransactionDirection::Request,
            reply_to_request_id: None,
            reply_latency_ns: None,
            code: 1,
            code_kind: None,
            flags: 0,
            decoded_flags: Vec::new(),
            data_size: None,
            offsets_size: None,
            extra_buffers_size: None,
            file_descriptor: Some(9),
            object_offset: Some(0x10),
            transferred_fd_origin: Some("/data/app/base.apk".to_owned()),
            transferred_fd_source_pid: Some(10),
            transferred_fd_source_fd: Some(7),
            interface_token: None,
            binder_method: None,
            binder_method_source: None,
            parcel_prefix_hex: None,
        });
        builder.record(&received);
        let report = builder.finish();
        assert_eq!(report.binder_fd_transfers.len(), 1);
        assert_eq!(report.binder_fd_transfers[0].origin, "/data/app/base.apk");
        assert!(report.graph.edges.iter().any(|edge| {
            edge.relation == "transfers_fd"
                && edge.strength == crate::EdgeStrength::Confirmed
                && edge.from == "fd:10:7"
                && edge.to == "fd:20:9"
        }));
    }

    #[test]
    fn ssl_read_plaintext_graphs_tls_recv() {
        let session = Uuid::new_v4();
        let mut builder = SessionReportBuilder::default();
        builder.record(&file_event(
            session,
            "/data/user/0/com.example/code_cache/1.dex",
        ));
        builder.record(&Event {
            header: header(session, 10, SensorKind::Integrity),
            payload: EventPayload::InspectPlaintext(ksight_model::InspectPlaintext {
                adapter: "tls_ssl_read".to_owned(),
                direction: "recv".to_owned(),
                library: "libssl.so".to_owned(),
                build_id: None,
                offset: None,
                requested_bytes: 64,
                captured_bytes: 16,
                truncated: false,
                sha256: "cafebabe".to_owned(),
                preview: "17030307a4000000".to_owned(),
                preview_encoding: "hex".to_owned(),
                content_class: String::new(),
            }),
        });
        let report = builder.finish();
        assert_eq!(report.plaintext[0].direction, "recv");
        assert!(report
            .graph
            .edges
            .iter()
            .any(|edge| edge.relation == "tls_recv"));
    }

    #[test]
    fn stitches_ssl_read_text_and_extracts_split_urls() {
        let session = Uuid::new_v4();
        let mut builder = SessionReportBuilder::default();
        builder.record(&Event {
            header: header(session, 22, SensorKind::Integrity),
            payload: EventPayload::InspectPlaintext(ksight_model::InspectPlaintext {
                adapter: "tls_ssl_read".to_owned(),
                direction: "recv".to_owned(),
                library: "libssl.so".to_owned(),
                build_id: None,
                offset: None,
                requested_bytes: 64,
                captured_bytes: 64,
                truncated: true,
                sha256: "aa".to_owned(),
                preview: r#"{"type":"hummer","url":"https://s.thsi.cn/cd/acrossBar.zip""#
                    .to_owned(),
                preview_encoding: "utf8_lossy".to_owned(),
                content_class: "text".to_owned(),
            }),
        });
        builder.record(&Event {
            header: header(session, 22, SensorKind::Integrity),
            payload: EventPayload::InspectPlaintext(ksight_model::InspectPlaintext {
                adapter: "tls_ssl_read".to_owned(),
                direction: "recv".to_owned(),
                library: "libssl.so".to_owned(),
                build_id: None,
                offset: None,
                requested_bytes: 40,
                captured_bytes: 40,
                truncated: true,
                sha256: "bb".to_owned(),
                preview: r#","md5":"abc","url":"https://sp.thsi.cn/pkg/e5.zip"}"#.to_owned(),
                preview_encoding: "utf8_lossy".to_owned(),
                content_class: "text".to_owned(),
            }),
        });
        let report = builder.finish();
        let preview = report.plaintext[0].preview.as_deref().unwrap_or("");
        assert!(preview.contains("s.thsi.cn"));
        assert!(preview.contains("sp.thsi.cn"));
        assert!(report.http_calls.iter().any(|call| {
            call.host.as_deref() == Some("s.thsi.cn") && call.path.contains("acrossBar.zip")
        }));
        assert!(report
            .http_calls
            .iter()
            .any(|call| call.host.as_deref() == Some("sp.thsi.cn")));
    }

    #[test]
    fn utf8_inspect_preview_does_not_panic_on_content_class() {
        let session = Uuid::new_v4();
        let mut builder = SessionReportBuilder::default();
        builder.record(&Event {
            header: header(session, 11, SensorKind::Integrity),
            payload: EventPayload::InspectPlaintext(ksight_model::InspectPlaintext {
                adapter: "tls_ssl_read".to_owned(),
                direction: "recv".to_owned(),
                library: "libssl.so".to_owned(),
                build_id: None,
                offset: None,
                requested_bytes: 32,
                captured_bytes: 32,
                truncated: false,
                sha256: "cc".to_owned(),
                preview: "证指数".to_owned(),
                preview_encoding: "utf8_lossy".to_owned(),
                content_class: String::new(),
            }),
        });
        let report = builder.finish();
        assert_eq!(report.plaintext[0].preview.as_deref(), Some("证指数"));
    }

    #[test]
    fn keeps_url_json_over_longer_jni_javascript() {
        let session = Uuid::new_v4();
        let mut builder = SessionReportBuilder::default();
        let urls = r#"{"type":"hummer","url":"https://s.thsi.cn/cd/acrossBar_v1.8.zip"}"#;
        builder.record(&Event {
            header: header(session, 30, SensorKind::Integrity),
            payload: EventPayload::InspectPlaintext(ksight_model::InspectPlaintext {
                adapter: "jni_get_string_utf_chars".to_owned(),
                direction: "java_to_native".to_owned(),
                library: "libart.so".to_owned(),
                build_id: None,
                offset: None,
                requested_bytes: urls.len() as u64,
                captured_bytes: u32::try_from(urls.len()).unwrap_or(u32::MAX),
                truncated: false,
                sha256: "urljson".to_owned(),
                preview: urls.to_owned(),
                preview_encoding: "utf8_lossy".to_owned(),
                content_class: "text".to_owned(),
            }),
        });
        let long_js = "dth\",\"height\",\"render\"];".repeat(80);
        builder.record(&Event {
            header: header(session, 30, SensorKind::Integrity),
            payload: EventPayload::InspectPlaintext(ksight_model::InspectPlaintext {
                adapter: "jni_get_string_utf_chars".to_owned(),
                direction: "java_to_native".to_owned(),
                library: "libart.so".to_owned(),
                build_id: None,
                offset: None,
                requested_bytes: long_js.len() as u64,
                captured_bytes: u32::try_from(long_js.len()).unwrap_or(u32::MAX),
                truncated: false,
                sha256: "webpack".to_owned(),
                preview: long_js,
                preview_encoding: "utf8_lossy".to_owned(),
                content_class: "text".to_owned(),
            }),
        });
        let report = builder.finish();
        let preview = report.plaintext[0].preview.as_deref().unwrap_or("");
        assert!(
            preview.contains("s.thsi.cn/cd/acrossBar_v1.8.zip"),
            "longer JS must not replace URL JSON: {preview}"
        );
        assert!(report.plaintext[0]
            .urls
            .iter()
            .any(|url| url.contains("s.thsi.cn")));
    }

    #[test]
    fn tls_hex_does_not_hide_later_zip_urls() {
        let session = Uuid::new_v4();
        let mut builder = SessionReportBuilder::default();
        builder.record(&Event {
            header: header(session, 31, SensorKind::Integrity),
            payload: EventPayload::InspectPlaintext(ksight_model::InspectPlaintext {
                adapter: "tls_ssl_read".to_owned(),
                direction: "recv".to_owned(),
                library: "libssl.so".to_owned(),
                build_id: None,
                offset: None,
                requested_bytes: 32,
                captured_bytes: 32,
                truncated: false,
                sha256: "h2".to_owned(),
                preview: "000000000100000005886196dc34fd28".to_owned(),
                preview_encoding: "hex".to_owned(),
                content_class: "binary".to_owned(),
            }),
        });
        let json = r#"{"url":"https://s.thsi.cn/cd/mobileweb-eq-homepage-v2-front-container/acrossBar_v1.8.zip"}"#;
        builder.record(&Event {
            header: header(session, 31, SensorKind::Integrity),
            payload: EventPayload::InspectPlaintext(ksight_model::InspectPlaintext {
                adapter: "tls_ssl_read".to_owned(),
                direction: "recv".to_owned(),
                library: "libssl.so".to_owned(),
                build_id: None,
                offset: None,
                requested_bytes: json.len() as u64,
                captured_bytes: u32::try_from(json.len()).unwrap_or(u32::MAX),
                truncated: false,
                sha256: "zip".to_owned(),
                preview: json.to_owned(),
                preview_encoding: "utf8_lossy".to_owned(),
                content_class: "text".to_owned(),
            }),
        });
        let report = builder.finish();
        let preview = report.plaintext[0].preview.as_deref().unwrap_or("");
        assert!(
            preview.contains("acrossBar_v1.8.zip"),
            "HTTP/2 hex must not hide zip URL JSON: {preview}"
        );
        assert!(!preview.starts_with("00000000"), "{preview}");
    }

    #[test]
    fn http2_hpack_hex_preview_becomes_http_calls_and_urls() {
        let session = Uuid::new_v4();
        let block = [
            0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab,
            0x90, 0xf4, 0xff,
        ];
        let mut frame = vec![
            0,
            0,
            u8::try_from(block.len()).unwrap(),
            0x1,
            0x04,
            0,
            0,
            0,
            1,
        ];
        frame.extend_from_slice(&block);
        let mut hex = String::new();
        for byte in &frame {
            let _ = std::fmt::Write::write_fmt(&mut hex, format_args!("{byte:02x}"));
        }
        let mut builder = SessionReportBuilder::default();
        builder.record(&Event {
            header: header(session, 31, SensorKind::Integrity),
            payload: EventPayload::InspectPlaintext(ksight_model::InspectPlaintext {
                adapter: "tls_ssl_read".to_owned(),
                direction: "recv".to_owned(),
                library: "libssl.so".to_owned(),
                build_id: None,
                offset: None,
                requested_bytes: u64::try_from(frame.len()).unwrap_or(0),
                captured_bytes: u32::try_from(frame.len()).unwrap_or(u32::MAX),
                truncated: false,
                sha256: "hpack".to_owned(),
                preview: hex,
                preview_encoding: "hex".to_owned(),
                content_class: "binary".to_owned(),
            }),
        });
        let report = builder.finish();
        assert!(
            report.http_calls.iter().any(|call| {
                call.kind == "http2_request"
                    && call.method == "GET"
                    && call.host.as_deref() == Some("www.example.com")
                    && call.path == "/"
            }),
            "{:?}",
            report.http_calls
        );
        assert!(
            report.plaintext[0]
                .urls
                .iter()
                .any(|url| url == "http://www.example.com/" || url == "https://www.example.com/"),
            "{:?}",
            report.plaintext[0].urls
        );
    }

    #[test]
    fn http2_hpack_dynamic_table_survives_split_ssl_reads() {
        let session = Uuid::new_v4();
        let first = [
            0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab,
            0x90, 0xf4, 0xff,
        ];
        let mut frame1 = vec![
            0,
            0,
            u8::try_from(first.len()).unwrap(),
            0x1,
            0x04,
            0,
            0,
            0,
            1,
        ];
        frame1.extend_from_slice(&first);
        let second = [
            0x82, 0x86, 0x84, 0xbe, 0x58, 0x08, 0x6e, 0x6f, 0x2d, 0x63, 0x61, 0x63, 0x68, 0x65,
        ];
        let mut frame2 = vec![
            0,
            0,
            u8::try_from(second.len()).unwrap(),
            0x1,
            0x04,
            0,
            0,
            0,
            3,
        ];
        frame2.extend_from_slice(&second);
        let mut hex1 = String::new();
        for byte in &frame1 {
            let _ = std::fmt::Write::write_fmt(&mut hex1, format_args!("{byte:02x}"));
        }
        let mut hex2 = String::new();
        for byte in &frame2 {
            let _ = std::fmt::Write::write_fmt(&mut hex2, format_args!("{byte:02x}"));
        }
        let mut builder = SessionReportBuilder::default();
        builder.record(&Event {
            header: header(session, 31, SensorKind::Integrity),
            payload: EventPayload::InspectPlaintext(ksight_model::InspectPlaintext {
                adapter: "tls_ssl_read".to_owned(),
                direction: "recv".to_owned(),
                library: "libssl.so".to_owned(),
                build_id: None,
                offset: None,
                requested_bytes: u64::try_from(frame1.len()).unwrap_or(0),
                captured_bytes: u32::try_from(frame1.len()).unwrap_or(u32::MAX),
                truncated: false,
                sha256: "h1".to_owned(),
                preview: hex1,
                preview_encoding: "hex".to_owned(),
                content_class: "binary".to_owned(),
            }),
        });
        builder.record(&Event {
            header: header(session, 31, SensorKind::Integrity),
            payload: EventPayload::InspectPlaintext(ksight_model::InspectPlaintext {
                adapter: "tls_ssl_read".to_owned(),
                direction: "recv".to_owned(),
                library: "libssl.so".to_owned(),
                build_id: None,
                offset: None,
                requested_bytes: u64::try_from(frame2.len()).unwrap_or(0),
                captured_bytes: u32::try_from(frame2.len()).unwrap_or(u32::MAX),
                truncated: false,
                sha256: "h2".to_owned(),
                preview: hex2,
                preview_encoding: "hex".to_owned(),
                content_class: "binary".to_owned(),
            }),
        });
        let report = builder.finish();
        let call = report
            .http_calls
            .iter()
            .find(|call| {
                call.kind == "http2_request" && call.host.as_deref() == Some("www.example.com")
            })
            .expect("h2 request");
        assert!(
            call.count >= 2 && call.header_names.iter().any(|name| name == "cache-control"),
            "dynamic :authority must survive the second SSL_read: {:?}",
            report.http_calls
        );
    }

    #[test]
    fn private_store_sqlite_bytes_become_http_calls() {
        let dir = std::env::temp_dir().join(format!("ksight-ce-{}", Uuid::new_v4()));
        std::fs::create_dir_all(dir.join("ce/databases")).expect("db dir");
        let mut bytes = b"COL".to_vec();
        bytes.extend_from_slice(b"https://ebsnew.boc.cn/api/login");
        bytes.push(0);
        bytes.extend_from_slice(b"https://mbs.boc.cn/phone/");
        std::fs::write(dir.join("ce/databases/boc_mobile_database.db"), &bytes).expect("db");
        std::fs::write(
            dir.join("ce/shared_prefs.xml"),
            br#"<?xml version='1.0'?><map><string name="host">https://wap.boc.cn/cs/fd5/index.html</string></map>"#,
        )
        .expect("xml");
        let calls = http_calls_from_private_dir(&dir, "com.chinamworld.bocmbci");
        assert!(
            calls.iter().any(|call| {
                call.origin == "private" && call.host.as_deref() == Some("ebsnew.boc.cn")
            }),
            "{calls:?}"
        );
        assert!(
            calls
                .iter()
                .any(|call| call.host.as_deref() == Some("wap.boc.cn")),
            "{calls:?}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn catalog_keeps_first_party_paths_ahead_of_cdn() {
        let mut calls = vec![
            HttpCallActivity {
                source: "app".to_owned(),
                process_id: 1,
                direction: "private".to_owned(),
                kind: "url".to_owned(),
                method: "URL".to_owned(),
                host: Some("mdn.alipayobjects.com".to_owned()),
                path: "/img/x".to_owned(),
                status: None,
                query_keys: Vec::new(),
                header_names: Vec::new(),
                redacted_headers: Vec::new(),
                body_keys: Vec::new(),
                redacted_body_keys: Vec::new(),
                content_type: None,
                third_party: true,
                count: 99,
                origin: "private".to_owned(),
            },
            HttpCallActivity {
                source: "app".to_owned(),
                process_id: 1,
                direction: "private".to_owned(),
                kind: "url".to_owned(),
                method: "URL".to_owned(),
                host: Some("render.alipay.com".to_owned()),
                path: "/api/pay".to_owned(),
                status: None,
                query_keys: Vec::new(),
                header_names: Vec::new(),
                redacted_headers: Vec::new(),
                body_keys: Vec::new(),
                redacted_body_keys: Vec::new(),
                content_type: None,
                third_party: false,
                count: 1,
                origin: "private".to_owned(),
            },
        ];
        sort_http_catalog(&mut calls);
        assert_eq!(calls[0].host.as_deref(), Some("render.alipay.com"));
        calls[1].source = "com.eg.android.AlipayGphone".to_owned();
        calls[1].host = Some("clientsc.alipay.com".to_owned());
        calls[1].path = "/account/gateway.htm".to_owned();
        calls[1].third_party = false;
        calls.push(HttpCallActivity {
            source: "com.eg.android.AlipayGphone".to_owned(),
            process_id: 1,
            direction: "private".to_owned(),
            kind: "url".to_owned(),
            method: "URL".to_owned(),
            host: Some("account.chsi.com.cn".to_owned()),
            path: "/passport/login".to_owned(),
            status: None,
            query_keys: Vec::new(),
            header_names: Vec::new(),
            redacted_headers: Vec::new(),
            body_keys: Vec::new(),
            redacted_body_keys: Vec::new(),
            content_type: None,
            third_party: false,
            count: 9,
            origin: "private".to_owned(),
        });
        sort_http_catalog(&mut calls);
        assert_eq!(calls[0].host.as_deref(), Some("clientsc.alipay.com"));
    }

    #[test]
    fn catalog_drops_empty_host_and_truncated_prefix() {
        let mut calls = vec![
            HttpCallActivity {
                source: "app".to_owned(),
                process_id: 1,
                direction: "heap".to_owned(),
                kind: "url".to_owned(),
                method: "URL".to_owned(),
                host: None,
                path: String::new(),
                status: None,
                query_keys: Vec::new(),
                header_names: Vec::new(),
                redacted_headers: Vec::new(),
                body_keys: Vec::new(),
                redacted_body_keys: Vec::new(),
                content_type: None,
                third_party: false,
                count: 9,
                origin: "heap".to_owned(),
            },
            HttpCallActivity {
                source: "app".to_owned(),
                process_id: 1,
                direction: "heap".to_owned(),
                kind: "url".to_owned(),
                method: "URL".to_owned(),
                host: Some("data.10jqka.co".to_owned()),
                path: String::new(),
                status: None,
                query_keys: Vec::new(),
                header_names: Vec::new(),
                redacted_headers: Vec::new(),
                body_keys: Vec::new(),
                redacted_body_keys: Vec::new(),
                content_type: None,
                third_party: false,
                count: 3,
                origin: "heap".to_owned(),
            },
            HttpCallActivity {
                source: "app".to_owned(),
                process_id: 1,
                direction: "heap".to_owned(),
                kind: "url".to_owned(),
                method: "URL".to_owned(),
                host: Some("data.10jqka.com.cn".to_owned()),
                path: "/api/quote".to_owned(),
                status: None,
                query_keys: Vec::new(),
                header_names: Vec::new(),
                redacted_headers: Vec::new(),
                body_keys: Vec::new(),
                redacted_body_keys: Vec::new(),
                content_type: None,
                third_party: false,
                count: 1,
                origin: "heap".to_owned(),
            },
        ];
        sort_http_catalog(&mut calls);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].host.as_deref(), Some("data.10jqka.com.cn"));
        calls.push(HttpCallActivity {
            source: "app".to_owned(),
            process_id: 1,
            direction: "heap".to_owned(),
            kind: "url".to_owned(),
            method: "URL".to_owned(),
            host: Some("data.10jqka.com.cn".to_owned()),
            path: "/api".to_owned(),
            status: None,
            query_keys: Vec::new(),
            header_names: Vec::new(),
            redacted_headers: Vec::new(),
            body_keys: Vec::new(),
            redacted_body_keys: Vec::new(),
            content_type: None,
            third_party: false,
            count: 4,
            origin: "heap".to_owned(),
        });
        sort_http_catalog(&mut calls);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].path, "/api/quote");
    }

    #[test]
    fn recatalog_on_disk_reports_if_requested() {
        if std::env::var_os("KSIGHT_RECATALOG").is_none() {
            return;
        }
        let root = std::path::Path::new("/Users/swyiic/Desktop/KernSight-reports");
        if !root.is_dir() {
            return;
        }
        for entry in std::fs::read_dir(root).expect("reports") {
            let dest = entry.expect("entry").path();
            let report_path = dest.join("dump-report.json");
            if !report_path.is_file() {
                continue;
            }
            let package = dest
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("");
            let mut calls =
                http_calls_from_plaintext_dir(&dest.join("runtime/plaintext"), package);
            calls.extend(http_calls_from_private_dir(
                &dest.join("data-private"),
                package,
            ));
            sort_http_catalog(&mut calls);
            let text = std::fs::read_to_string(&report_path).expect("read dump");
            let mut value: serde_json::Value = serde_json::from_str(&text).expect("json");
            value["http_calls"] = serde_json::to_value(&calls).expect("ser");
            std::fs::write(
                &report_path,
                serde_json::to_vec_pretty(&value).expect("bytes"),
            )
            .expect("write dump");
            eprintln!("dump {package} http_calls={}", calls.len());
        }
        for entry in std::fs::read_dir(root).expect("reports") {
            let path = entry.expect("entry").path();
            let name = path
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("");
            if !name.ends_with("-report.json") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("read session");
            let Ok(mut value) = serde_json::from_str::<serde_json::Value>(&text) else {
                continue;
            };
            let Some(arr) = value.get("http_calls").cloned() else {
                continue;
            };
            let Ok(mut calls) = serde_json::from_value::<Vec<HttpCallActivity>>(arr) else {
                continue;
            };
            sort_http_catalog(&mut calls);
            value["http_calls"] = serde_json::to_value(&calls).expect("ser");
            std::fs::write(&path, serde_json::to_vec_pretty(&value).expect("bytes"))
                .expect("write session");
            eprintln!("session {name} http_calls={}", calls.len());
        }
    }

    #[test]
    fn icbc_private_store_on_disk_if_present() {
        let dir = std::path::Path::new(
            "/Users/swyiic/Desktop/KernSight-reports/com.icbc/data-private",
        );
        if !dir.is_dir() {
            return;
        }
        let calls = http_calls_from_private_dir(dir, "com.icbc");
        assert!(
            calls.iter().any(|call| call
                .host
                .as_deref()
                .is_some_and(|host| host.contains("icbc.com.cn"))),
            "{calls:?}"
        );
    }

    #[test]
    fn jni_plaintext_graphs_jni_from_java() {
        let session = Uuid::new_v4();
        let mut builder = SessionReportBuilder::default();
        builder.record(&Event {
            header: header(session, 10, SensorKind::Integrity),
            payload: EventPayload::InspectPlaintext(ksight_model::InspectPlaintext {
                adapter: "jni_get_string_utf_chars".to_owned(),
                direction: "java_to_native".to_owned(),
                library: "/apex/com.android.art/lib64/libart.so".to_owned(),
                build_id: None,
                offset: Some(0x0080_d02c),
                requested_bytes: 12,
                captured_bytes: 11,
                truncated: false,
                sha256: "aabbccdd".to_owned(),
                preview: "hello world".to_owned(),
                preview_encoding: "utf8_lossy".to_owned(),
                content_class: "text".to_owned(),
            }),
        });
        let report = builder.finish();
        assert_eq!(report.plaintext[0].adapter, "jni_get_string_utf_chars");
        assert!(report
            .graph
            .edges
            .iter()
            .any(|edge| edge.relation == "jni_from_java"));
        assert!(report
            .inspect_hits
            .iter()
            .any(|hit| hit.adapter == "jni_get_string_utf_chars" && hit.hits >= 1));
    }

    #[test]
    fn parses_http_calls_from_inspect_plaintext_and_redacts_tokens() {
        let session = Uuid::new_v4();
        let mut builder = SessionReportBuilder::default();
        let preview = concat!(
            "POST /v6/feed/createFeed HTTP/1.1\r\n",
            "Host: api.coolapk.com\r\n",
            "Cookie: session=secret\r\n",
            "X-App-Token: abc\r\n",
            "Content-Type: application/x-www-form-urlencoded\r\n",
            "\r\n",
            "message=hello&status=1&_v2_post_token=xyz"
        );
        builder.record(&Event {
            header: header(session, 10, SensorKind::Integrity),
            payload: EventPayload::InspectPlaintext(ksight_model::InspectPlaintext {
                adapter: "tls_ssl_write".to_owned(),
                direction: "send".to_owned(),
                library: "libssl.so".to_owned(),
                build_id: None,
                offset: None,
                requested_bytes: preview.len() as u64,
                captured_bytes: u32::try_from(preview.len()).unwrap_or(u32::MAX),
                truncated: false,
                sha256: "feed1".to_owned(),
                preview: preview.to_owned(),
                preview_encoding: "utf8_lossy".to_owned(),
                content_class: "text".to_owned(),
            }),
        });
        builder.record(&Event {
            header: header(session, 10, SensorKind::Integrity),
            payload: EventPayload::InspectPlaintext(ksight_model::InspectPlaintext {
                adapter: "tls_ssl_write".to_owned(),
                direction: "send".to_owned(),
                library: "libssl.so".to_owned(),
                build_id: None,
                offset: None,
                requested_bytes: 80,
                captured_bytes: 80,
                truncated: false,
                sha256: "tracker1".to_owned(),
                preview: "GET /v6/main/indexV8?page=1 HTTP/1.1\r\nHost: log-api.pangle.io\r\n\r\n"
                    .to_owned(),
                preview_encoding: "utf8_lossy".to_owned(),
                content_class: "text".to_owned(),
            }),
        });
        let report = builder.finish();
        assert_eq!(report.http_calls.len(), 2);
        let create = report
            .http_calls
            .iter()
            .find(|row| row.path == "/v6/feed/createFeed")
            .expect("createFeed");
        assert_eq!(create.method, "POST");
        assert_eq!(create.host.as_deref(), Some("api.coolapk.com"));
        assert_eq!(create.count, 1);
        assert!(!create.third_party);
        assert!(create
            .redacted_headers
            .iter()
            .any(|row| row.starts_with("Cookie=")));
        assert!(create
            .redacted_body_keys
            .contains(&"_v2_post_token".to_owned()));
        assert!(!create.body_keys.iter().any(|key| key.contains("xyz")));
        let tracker = report
            .http_calls
            .iter()
            .find(|row| row.third_party)
            .expect("tracker");
        assert_eq!(tracker.host.as_deref(), Some("log-api.pangle.io"));
        assert!(report
            .graph
            .edges
            .iter()
            .any(|edge| edge.relation == "http_call"));
        assert!(report
            .limitations
            .iter()
            .any(|line| line.contains("http_calls")));
        assert_eq!(
            report
                .http_calls
                .iter()
                .find(|row| row.path == "/v6/feed/createFeed")
                .map(|row| row.origin.as_str()),
            Some("inspect")
        );
    }

    #[test]
    fn ingest_heap_http_calls_are_correlated_and_pair_by_host() {
        let session = Uuid::new_v4();
        let mut builder = SessionReportBuilder::default();
        builder.record(&Event {
            header: header(session, 10, SensorKind::Integrity),
            payload: EventPayload::InspectPlaintext(ksight_model::InspectPlaintext {
                adapter: "tls_ssl_write".to_owned(),
                direction: "send".to_owned(),
                library: "libssl.so".to_owned(),
                build_id: None,
                offset: None,
                requested_bytes: 40,
                captured_bytes: 40,
                truncated: false,
                sha256: "req".to_owned(),
                preview: "POST /v1/login HTTP/1.1\r\nHost: pay.example\r\n\r\n".to_owned(),
                preview_encoding: "utf8_lossy".to_owned(),
                content_class: "text".to_owned(),
            }),
        });
        builder.record(&Event {
            header: header(session, 10, SensorKind::Integrity),
            payload: EventPayload::InspectPlaintext(ksight_model::InspectPlaintext {
                adapter: "tls_ssl_read".to_owned(),
                direction: "recv".to_owned(),
                library: "libssl.so".to_owned(),
                build_id: None,
                offset: None,
                requested_bytes: 40,
                captured_bytes: 40,
                truncated: false,
                sha256: "resp".to_owned(),
                preview: "HTTP/1.1 200 OK\r\nHost: pay.example\r\nContent-Type: application/json\r\n\r\n{}".to_owned(),
                preview_encoding: "utf8_lossy".to_owned(),
                content_class: "text".to_owned(),
            }),
        });
        let mut report = builder.finish();
        report.ingest_dump_http_calls(vec![HttpCallActivity {
            source: "com.example".to_owned(),
            process_id: 10,
            direction: "heap".to_owned(),
            kind: "http1_response".to_owned(),
            method: "HTTP".to_owned(),
            host: None,
            path: String::new(),
            status: Some(200),
            query_keys: Vec::new(),
            header_names: vec!["Content-Type".to_owned()],
            redacted_headers: Vec::new(),
            body_keys: Vec::new(),
            redacted_body_keys: Vec::new(),
            content_type: Some("image/jpeg".to_owned()),
            third_party: false,
            count: 1,
            origin: "heap".to_owned(),
        }]);
        assert!(report
            .http_calls
            .iter()
            .any(|row| row.origin == "heap" && row.status == Some(200) && row.path.is_empty()));
        assert!(report
            .graph
            .edges
            .iter()
            .any(|edge| edge.relation == "http_reply"
                && edge.strength == crate::EdgeStrength::Correlated));
        assert!(report.graph.edges.iter().any(|edge| {
            edge.relation == "http_call" && edge.strength == crate::EdgeStrength::Correlated
        }));
    }

    #[test]
    fn correlates_http_path_to_dex_string_and_method() {
        let calls = vec![HttpCallActivity {
            source: "com.example".to_owned(),
            process_id: 1,
            direction: "send".to_owned(),
            kind: "http1_request".to_owned(),
            method: "POST".to_owned(),
            host: Some("api.coolapk.com".to_owned()),
            path: "/v6/feed/createFeed".to_owned(),
            status: None,
            query_keys: Vec::new(),
            header_names: Vec::new(),
            redacted_headers: Vec::new(),
            body_keys: Vec::new(),
            redacted_body_keys: Vec::new(),
            content_type: None,
            third_party: false,
            count: 1,
            origin: "inspect".to_owned(),
        }];
        let semantic = crate::DexSemanticSummary {
            api_strings: vec!["https://api.coolapk.com/v6/feed/createFeed".to_owned()],
            method_names: vec!["Lcom/coolapk/Market;->createFeed".to_owned()],
            ..crate::DexSemanticSummary::default()
        };
        let set = crate::DexArtifactSet {
            sha256: "abc".to_owned(),
            bytes: 10,
            canonical_relative_path: "readable-dex/x.dex".to_owned(),
            sources: vec!["heap-blob".to_owned()],
            observations: Vec::new(),
            semantic: Some(semantic),
        };
        let refs = correlate_http_calls_to_dex(&calls, &[set]);
        assert_eq!(refs.len(), 1);
        assert!(refs[0].matches.iter().any(|row| row.contains("createFeed")));
        assert_eq!(refs[0].relative_path.as_deref(), Some("readable-dex/x.dex"));
    }

    fn inspect_transact_event(session_id: Uuid, pid: u32, tid: u32, code: u32) -> Event {
        let mut event = Event {
            header: header(session_id, pid, SensorKind::Integrity),
            payload: EventPayload::InspectObservation(InspectObservation {
                adapter: "binder_userspace".to_owned(),
                attached: true,
                hit: true,
                library: "/system/lib64/libbinder.so".to_owned(),
                binder_handle: Some(3),
                binder_code: Some(code),
                binder_interface: Some("android.os.IServiceManager".to_owned()),
                binder_method: Some("getService".to_owned()),
                binder_method_source: Some("aosp_stub".to_owned()),
                detail: format!("binder transact hit pid={pid} code={code:#x}"),
                ..InspectObservation::default()
            }),
        };
        event.header.process.tid = tid;
        event.header.mode = CaptureMode::Inspect;
        event
    }

    fn binder_event(
        session_id: Uuid,
        pid: u32,
        target: Option<u32>,
        reply: bool,
        code: u32,
    ) -> Event {
        Event {
            header: header(session_id, pid, SensorKind::Binder),
            payload: EventPayload::BinderTransaction(BinderTransaction {
                stage: BinderTransactionStage::Submitted,
                transaction_id: i32::try_from(pid).unwrap_or_default(),
                target_node: None,
                target_process_id: target,
                target_thread_id: None,
                target_kind: None,
                reply,
                direction: BinderTransactionDirection::Request,
                reply_to_request_id: None,
                reply_latency_ns: None,
                code,
                code_kind: None,
                flags: 0,
                decoded_flags: Vec::new(),
                data_size: None,
                offsets_size: None,
                extra_buffers_size: None,
                file_descriptor: None,
                object_offset: None,
                transferred_fd_origin: None,
                transferred_fd_source_pid: None,
                transferred_fd_source_fd: None,
                interface_token: None,
                binder_method: None,
                binder_method_source: None,
                parcel_prefix_hex: None,
            }),
        }
    }

    fn file_event(session_id: Uuid, path: &str) -> Event {
        Event {
            header: header(session_id, 10, SensorKind::File),
            payload: EventPayload::FileOpen(ksight_model::FileOpen {
                directory_fd: -100,
                file_descriptor: Some(3),
                result: 3,
                flags: 0,
                mode: 0,
                path: path.to_owned(),
                resolved_path: None,
                content_sha256: None,
                content_bytes: None,
            }),
        }
    }

    fn fd_event(
        session_id: Uuid,
        operation: FileDescriptorOperation,
        fd: i32,
        result: i32,
    ) -> Event {
        Event {
            header: header(session_id, 10, SensorKind::File),
            payload: EventPayload::FileDescriptorChange(ksight_model::FileDescriptorChange {
                operation,
                file_descriptor: fd,
                requested_file_descriptor: None,
                resulting_file_descriptor: (operation == FileDescriptorOperation::Duplicate)
                    .then_some(result),
                result,
                command: 0,
                flags: 0,
                last_file_descriptor: None,
            }),
        }
    }

    fn socket_event(session_id: Uuid, fd: i32, result: i32) -> Event {
        Event {
            header: header(session_id, 10, SensorKind::Network),
            payload: EventPayload::SocketConnect(ksight_model::SocketConnect {
                file_descriptor: fd,
                result,
                address_family: 2,
                submitted_address_length: 16,
                captured_address_length: 16,
                peer_address: Some("127.0.0.1".to_owned()),
                peer_port: Some(443),
                scope_id: None,
                resolved_name: None,
            }),
        }
    }

    fn socket_accept_event(session_id: Uuid, listening_fd: i32, accepted_fd: i32) -> Event {
        Event {
            header: header(session_id, 10, SensorKind::Network),
            payload: EventPayload::SocketAccept(ksight_model::SocketAccept {
                listening_file_descriptor: listening_fd,
                accepted_file_descriptor: Some(accepted_fd),
                result: accepted_fd,
                address_family: 2,
                returned_address_length: 16,
                captured_address_length: 16,
                peer_address: Some("127.0.0.2".to_owned()),
                peer_port: Some(8443),
                scope_id: None,
            }),
        }
    }

    fn socket_io_event(
        session_id: Uuid,
        fd: i32,
        operation: SocketIoOperation,
        result: i64,
    ) -> Event {
        Event {
            header: header(session_id, 10, SensorKind::Network),
            payload: EventPayload::SocketIo(ksight_model::SocketIo {
                file_descriptor: fd,
                operation,
                result,
                requested_bytes: Some(u64::try_from(result).expect("positive test result")),
                syscall: if operation == SocketIoOperation::Send {
                    206
                } else {
                    207
                },
            }),
        }
    }

    fn memory_event(
        session_id: Uuid,
        operation: MemoryOperation,
        address: u64,
        length: u64,
    ) -> Event {
        Event {
            header: header(session_id, 10, SensorKind::Memory),
            payload: EventPayload::MemoryRegionChange(ksight_model::MemoryRegionChange {
                operation,
                address,
                length,
                result: if operation == MemoryOperation::Map {
                    i64::try_from(address).expect("test address")
                } else {
                    0
                },
                protection: 5,
                mapping_flags: (operation == MemoryOperation::Map).then_some(2),
                file_descriptor: None,
                backing_path: None,
                offset: None,
            }),
        }
    }

    fn header(session_id: Uuid, pid: u32, sensor: SensorKind) -> EventHeader {
        EventHeader {
            schema: SchemaVersion {
                major: 1,
                minor: 10,
            },
            session_id,
            source_sequence: u64::from(pid),
            monotonic_ns: u64::from(pid),
            cpu: Some(0),
            process: ProcessIdentity {
                key: ProcessKey {
                    boot_id: Uuid::nil(),
                    pid,
                    start_time_ns: 1,
                },
                tid: pid,
                tgid: pid,
                uid: 10_000,
                gid: 10_000,
                comm: format!("proc-{pid}"),
                command_line: None,
                selinux_context: None,
                packages: vec![PackageCandidate {
                    package_name: "com.example".to_owned(),
                    source: "test".to_owned(),
                    confidence_percent: 100,
                }],
            },
            sensor,
            mode: CaptureMode::Observe,
            quality: DataQuality {
                confidence: Confidence::Confirmed,
                truncated: false,
                lost_before: 0,
                sample_one_in: 1,
                source: "test".to_owned(),
            },
        }
    }
}
