use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use ksight_model::{
    BaselineFdKind, BinderTransactionFlag, BinderTransactionStage, Event, EventPayload,
    FileDescriptorOperation, MemoryOperation, SensorKind, SocketIoOperation,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

mod http_catalog;
mod preview;
use preview::*;
mod helpers;
use helpers::*;
pub(crate) use http_catalog::{
    attach_http_call_graph, pair_http_replies, stamp_empty_hosts_from_sni,
};
pub use http_catalog::{
    http_calls_from_plaintext_dir, http_calls_from_private_dir, sort_http_catalog,
};

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
    /// Latest payload-free diagnostic counters emitted by this adapter.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metrics: BTreeMap<String, u64>,
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
    metrics: BTreeMap<String, u64>,
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
                    if !observation.metrics.is_empty() {
                        activity.metrics.clone_from(&observation.metrics);
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
            .map(
                |((process_id, adapter, library), activity)| InspectHitActivity {
                    adapter,
                    library,
                    process_id,
                    process_instance_id: activity.process_instance_id,
                    attached: activity.attached,
                    hits: activity.hits,
                    last_detail: activity.last_detail,
                    metrics: activity.metrics,
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
                },
            )
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

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
