use serde::{Deserialize, Serialize};

/// Collection depth used by one observability capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationTier {
    /// Whole-device kernel facts with bounded payloads.
    ObserveL0,
    /// Explicit semantic inspection of selected processes.
    InspectL1,
    /// Intrusive forensic or debugger activity on a laboratory target.
    ForensicL2,
}

/// Implementation maturity of a capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityStage {
    /// Implemented and exercised on the current device baseline.
    Implemented,
    /// Some facts are implemented, but important lifecycle or semantic links are absent.
    Partial,
    /// Designed and scheduled, but not implemented.
    Planned,
    /// Requires research and cannot yet be promised.
    Research,
}

/// Expected target-visible impact of a collection mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VisibilityRisk {
    /// Kernel-only metadata with low expected target-process disturbance.
    Low,
    /// Selected-process probes or stack collection with measurable side effects.
    Medium,
    /// Breakpoints, snapshots, or broad payload capture with explicit disturbance.
    High,
}

/// One honest statement of current and future collection ability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityArea {
    /// Stable machine-readable name.
    pub id: &'static str,
    /// Short operator-facing title.
    pub title: &'static str,
    /// Minimum collection tier required.
    pub tier: ObservationTier,
    /// Current implementation state.
    pub stage: CapabilityStage,
    /// Expected visibility or disturbance.
    pub visibility: VisibilityRisk,
    /// Exact boundary of what is or is not available.
    pub detail: &'static str,
}

/// Candidate selected-process boundary for future L1 semantic inspection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SemanticKeypoint {
    /// Stable keypoint identifier.
    pub id: &'static str,
    /// Runtime layer owning the boundary.
    pub layer: &'static str,
    /// Semantic fact the adapter is intended to establish.
    pub objective: &'static str,
    /// Candidate modules or components; exact build identity is required before use.
    pub components: &'static [&'static str],
    /// How a device-specific adapter may resolve the location.
    pub selector: &'static str,
    /// Minimum evidence required before the keypoint may be enabled.
    pub validation: &'static str,
    /// Known target-visible or behavior-changing surfaces.
    pub detection_surface: &'static str,
    /// Current implementation maturity.
    pub stage: CapabilityStage,
    /// Keypoints are never active in a default whole-device session.
    pub enabled_by_default: bool,
}

/// Return the capability matrix for the current build.
pub fn current_capabilities() -> Vec<CapabilityArea> {
    vec![
        area("process_thread", "Process / thread identity", ObservationTier::ObserveL0, CapabilityStage::Implemented, VisibilityRisk::Low, "PID, TID, UID, package candidates, lifecycle and task names are normalized. Raw-syscall supplements currently support aarch64 only; 32-bit compat syscall decoding is not yet claimed."),
        area("sched_wakeup", "Scheduler wakeup relationships", ObservationTier::ObserveL0, CapabilityStage::Partial, VisibilityRisk::Low, "Scoped wakeup relationships are captured via sched_wakeup after a runtime tracefs-format contract check. Attachment and event emission are validated at capture time; whole-device sched_switch streaming remains disabled."),
        area("file_fd", "File / FD activity", ObservationTier::ObserveL0, CapabilityStage::Partial, VisibilityRisk::Low, "Open, close, close_range, dup/dup3, duplication fcntl and Unix SCM_RIGHTS send/receive are captured. Observed descriptors are copied across fork, re-seeded from procfs after exec, and dropped on process exit. io_uring file operations remain incomplete."),
        area("binder_metadata", "Binder metadata", ObservationTier::ObserveL0, CapabilityStage::Partial, VisibilityRisk::Low, "Submission, driver-buffer sizes, destination delivery and Binder FD transfer stages are paired by transaction ID with driver latency; request and reply transactions are now correlated with kernel-side latency, while AIDL names and Parcel contents remain planned."),
        area("memory_mapping", "Memory mappings", ObservationTier::ObserveL0, CapabilityStage::Partial, VisibilityRisk::Low, "Executable mmap/mprotect are captured by default. memory-all keeps mapping-sized mmap/munmap (>= 256 KiB), large mprotect (>= 1 MiB), mremap and brk, and always keeps executable transitions so packed-app heaps survive the ring. Page-permission storms are dropped in the kernel. The memory ring is 8 MiB. Protection-interval reconstruction, memfd provenance and page contents remain planned."),
        area("network_flow", "Network flow metadata", ObservationTier::ObserveL0, CapabilityStage::Partial, VisibilityRisk::Low, "Connect and accept endpoints are captured and joined to observed FD dup/close lifetimes; pre-session sockets are enumerated by the FD baseline, while DNS ownership and protocol semantics remain planned."),
        area("network_io", "Socket byte-count metadata", ObservationTier::ObserveL0, CapabilityStage::Partial, VisibilityRisk::Medium, "Explicit network-io policy counts sendto/recvfrom/sendmsg/recvmsg, socket read/write and sendmmsg/recvmmsg batch counts without reading payload buffers; pre-session socket descriptors are enumerated by the FD baseline. It is disabled by default."),
        area("dex_elf", "DEX / ELF provenance", ObservationTier::ObserveL0, CapabilityStage::Partial, VisibilityRisk::Low, "Successful opens of .so/.dex/.apk/.oat/.vdex/.art files at most 1 MiB are SHA-256 hashed on the device. dump-package catalogs APK DEX, anonymous heap blobs, live memory DEX, and loaded SO with correlated VMA/maps edges; its v2 report groups content-identical DEX observations by SHA-256 without deleting physical evidence, publishes a bounded class/method-name index, and classifies SO framework candidates with a versioned rule library. File-backed vdex/so are not treated as heap unpacks. Discontinuous-page reconstruction, ClassLoader/load-order identity, and full method prototypes remain planned. A default-off linker SO-load Inspect adapter can confirm a selected-process load boundary when GNU build-id and offset match."),
        area("art_jni_native", "ART / JNI / Native semantics", ObservationTier::InspectL1, CapabilityStage::Partial, VisibilityRisk::Medium, "ART file DEX Open attaches to exported ArtDexFileLoader::Open(char const*). Memory DEX Open attaches only to the exported Open(uint8_t const*, size_t, ...) in libdexfile.so after GNU build-id match; there is no OpenMemory symbol on this Android 14 build and offsets are not guessed. Packed-app heap DEX is recorded by dump-package as correlated VMA evidence, not as an ART inspect hit. JNI RegisterNatives has no exported boundary and is refused. No Java method relationship is claimed."),
        area("tls_quic", "TLS / QUIC boundaries", ObservationTier::InspectL1, CapabilityStage::Partial, VisibilityRisk::High, "Default-off SSL_write uprobe on system and Conscrypt libssl.so copies a bounded outbound plaintext preview after GNU build-id and exported-symbol checks. SSL_read, Cronet/QUIC, and statically linked TLS stacks are not covered."),
        area("native_stack", "Native call chains", ObservationTier::InspectL1, CapabilityStage::Planned, VisibilityRisk::Medium, "Requires stack collection plus symbol and unwind metadata; stripped or generated code may remain unresolved."),
        area("java_stack", "Java call chains", ObservationTier::InspectL1, CapabilityStage::Research, VisibilityRisk::Medium, "Requires Android-version-specific ART metadata and stack reconstruction; universal coverage cannot be promised."),
        area("memory_snapshot", "Memory snapshots", ObservationTier::ForensicL2, CapabilityStage::Planned, VisibilityRisk::High, "Snapshots must be explicit, selected-process, bounded and provenance-labelled; eBPF will not bulk-copy process memory."),
        area("plaintext", "Plaintext evidence", ObservationTier::InspectL1, CapabilityStage::Partial, VisibilityRisk::High, "Outbound TLS writes can be copied at SSL_write for one app during a short test (`--inspect-tls --package`). Previews are bounded, hashed, and never Observe events. Chrome/Cronet and other custom TLS stacks are not covered."),
        area("data_flow", "Cross-layer data-flow graph", ObservationTier::ObserveL0, CapabilityStage::Partial, VisibilityRisk::Low, "Session reports expose a queryable L0 graph (`ksightctl device graph`) with confirmed Binder, socket, sched-wakeup, and mmap `maps` edges. dump-package VMA overlap is `overlaps_mmap` and always correlated, including exact address matches. Time proximity is never a confirmed edge. ART/JNI/plaintext data-flow remains planned."),
    ]
}

/// Return the reviewed but disabled L1 semantic keypoint registry.
pub fn semantic_keypoints() -> Vec<SemanticKeypoint> {
    vec![
        keypoint("linker_load", "linker", "Establish a confirmed shared-object load boundary and loader namespace.", &["linker64", "libdl.so"], "Exported symbol when present; otherwise build-ID-scoped symbol/offset adapter.", "Module build ID, ABI signature, short dry-run, and mmap/linker event agreement.", "Probe state, instruction patch/breakpoint mechanism, execution latency, and custom linker checks.", CapabilityStage::Partial),
        keypoint("art_dex_load", "ART", "Associate a validated DEX container with the process and load time.", &["libdexfile.so"], "Exported ArtDexFileLoader::Open(char const*) and, separately, Open(uint8_t const*, size_t, ...) file offsets after GNU build-id match. No invented OpenMemory offset.", "Build ID, exact exported symbol, bounded argument validation, and agreement with dump VMA/path evidence.", "ART internals vary by release; timing, tracing state, code-page checks, or runtime self-tests may react.", CapabilityStage::Partial),
        keypoint("jni_registration", "JNI", "Relate Java native method registrations to Native function addresses.", &["libart.so", "application native libraries"], "Stable JNI table boundary where available plus build-ID-scoped ART adapter.", "Method/class bounds, executable address ownership, module build ID, and repeatable registration evidence.", "Registration timing changes and ART/native integrity checks may reveal observation.", CapabilityStage::Research),
        keypoint("binder_userspace", "Binder", "Resolve interface descriptors and userspace transaction boundaries.", &["libbinder.so"], "Exported IPCThreadState::transact; handle and code from AAPCS registers. Parcel descriptors are not decoded.", "Descriptor bounds, transaction-code registry version, and agreement with kernel Binder stages.", "C++ symbols and wrappers vary; high-frequency probes can change IPC latency.", CapabilityStage::Partial),
        keypoint("tls_boundary", "TLS", "Identify library-level plaintext length and direction at an authorized boundary.", &["BoringSSL", "Conscrypt", "libssl.so"], "Exported SSL_write on system/Conscrypt libssl.so; bounded copy of the userspace buffer.", "Module build ID, connection-object correlation, strict byte policy, and encrypted socket-flow agreement.", "Function timing, symbol/code checks, custom TLS stacks, and sensitive-buffer access are detectable.", CapabilityStage::Partial),
        keypoint("quic_boundary", "QUIC", "Associate QUIC stream activity with UDP flows and library ownership.", &["Cronet", "application QUIC libraries"], "Versioned library adapter; no universal symbol assumption.", "Module/build version, connection and stream identifiers, UDP flow agreement, and bounded metadata.", "Aggressive inlining, custom builds, timing changes, and library self-checks reduce reliability.", CapabilityStage::Research),
        keypoint("native_stack", "Native", "Collect bounded call stacks at selected confirmed events.", &["application ELF", "system native libraries", "JIT code maps"], "Perf/BPF stack source selected per device capability, followed by offline symbolization.", "Stack depth/rate limits, unwind coverage, module build IDs, and measured overhead budget.", "Sampling overhead, perf/tracing state, stripped code, JIT movement, and timing checks are observable.", CapabilityStage::Planned),
    ]
}

const fn area(
    id: &'static str,
    title: &'static str,
    tier: ObservationTier,
    stage: CapabilityStage,
    visibility: VisibilityRisk,
    detail: &'static str,
) -> CapabilityArea {
    CapabilityArea {
        id,
        title,
        tier,
        stage,
        visibility,
        detail,
    }
}

#[allow(clippy::too_many_arguments)] // Declarative registry rows keep every review field visible.
const fn keypoint(
    id: &'static str,
    layer: &'static str,
    objective: &'static str,
    components: &'static [&'static str],
    selector: &'static str,
    validation: &'static str,
    detection_surface: &'static str,
    stage: CapabilityStage,
) -> SemanticKeypoint {
    SemanticKeypoint {
        id,
        layer,
        objective,
        components,
        selector,
        validation,
        detection_surface,
        stage,
        enabled_by_default: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deep_semantics_are_not_reported_as_observe_implemented() {
        for capability in current_capabilities() {
            if matches!(capability.id, "art_jni_native" | "tls_quic" | "plaintext") {
                assert_ne!(capability.stage, CapabilityStage::Implemented);
            }
        }
    }

    #[test]
    fn semantic_keypoints_are_never_enabled_by_default() {
        assert!(semantic_keypoints()
            .iter()
            .all(|keypoint| !keypoint.enabled_by_default));
    }
}
