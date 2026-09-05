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
        area("file_fd", "File / FD activity", ObservationTier::ObserveL0, CapabilityStage::Partial, VisibilityRisk::Low, "Open, close, close_range, dup/dup3, duplication fcntl and Unix SCM_RIGHTS send/receive are captured. Observed descriptors are copied across fork, re-seeded from procfs after exec, and dropped on process exit. Binder FD send/receive is paired by transaction id into source→destination transfers with origin path (Pixel 6a: ksight-fd-probe clone+close_range; system_server→Settings transfers_fd with origin). io_uring file operations remain incomplete."),
        area("binder_metadata", "Binder metadata", ObservationTier::ObserveL0, CapabilityStage::Partial, VisibilityRisk::Low, "Submission, driver-buffer sizes, destination delivery and Binder FD transfer stages are paired by transaction ID with driver latency; two-way request and reply transactions pair on the kernel debug_id. A bounded parcel prefix is copied at kprobe binder_transaction on every online CPU (native 64-bit UAPI after the driver converts 32-bit clients) and parsed as writeInterfaceToken String16 for both ELF32 and ELF64 processes. Inspect transact joins that request by tid+code as correlated joined_transact. AIDL names from the parcel token use aosp_stub; Parcel scalars remain Inspect (exported writeString16/writeString8/writeCString/writeInt32/writeInt64/writeUint32/writeUint64/writeBool/writeByteArray/writeFileDescriptor/writeDupFileDescriptor/writeStrongBinder). Userspace ELF32 uprobes are ENOTSUP on this GKI."),
        area("memory_mapping", "Memory mappings", ObservationTier::ObserveL0, CapabilityStage::Partial, VisibilityRisk::Low, "Executable mmap/mprotect are captured by default. memory-all keeps mapping-sized mmap/munmap (>= 256 KiB), large mprotect (>= 1 MiB), mremap and brk, and always keeps executable transitions so packed-app heaps survive the ring. Page-permission storms are dropped in the kernel. The memory ring is 8 MiB. Protection-interval reconstruction, memfd provenance and page contents remain planned."),
        area("network_flow", "Network flow metadata", ObservationTier::ObserveL0, CapabilityStage::Partial, VisibilityRisk::Low, "Connect and accept endpoints are captured and joined to observed FD dup/close lifetimes; pre-session sockets are enumerated by the FD baseline. Bounded UDP/53 sendto/recvfrom copies (512 B) parse QNAME/A/AAAA; later connect() to those IPs is stamped resolved_name (same-process first, then any resolver such as netd). First write/sendto/sendmsg per socket (512 B, once per TLS/HTTP/QUIC kind, not port 53) parses TLS ClientHello SNI/ALPN, HTTP/1 request-line/Host, and QUIC long-header version/type without decrypting. QUIC Initial CRYPTO SNI, ECH inner name, getaddrinfo uprobe, and non-53 resolvers remain uncovered."),
        area("network_io", "Socket byte-count metadata", ObservationTier::ObserveL0, CapabilityStage::Partial, VisibilityRisk::Medium, "Explicit network-io policy counts sendto/recvfrom/sendmsg/recvmsg, socket read/write and sendmmsg/recvmmsg batch counts without reading payload buffers; pre-session socket descriptors are enumerated by the FD baseline. It is disabled by default."),
        area("dex_elf", "DEX / ELF provenance", ObservationTier::ObserveL0, CapabilityStage::Partial, VisibilityRisk::Low, "Successful opens of .so/.dex/.apk/.oat/.vdex/.art files at most 1 MiB are SHA-256 hashed on the device. dump-package catalogs APK DEX, anonymous heap blobs, writable app-private overlays, live memory DEX, and loaded SO with correlated VMA/maps edges; split-APK lib/<abi> is mapped to the installer ISA directory. File-backed vdex/oat/art/apk are not heap unpacks. Adjacent same-path VMAs are stitched before DEX copy. code_loaders records boot/install/secondary/in_memory roles from maps, open fds, and exported ART DexFile Open during --launch. ART Open hits join dump DEX by path or buffer size as correlated joined_dex edges, not a Java ClassLoader instance. Packer-key/plaintext harvest runs only when a packer/VMP SO is mapped. DEX proto_ids are published as bounded class->name(params)return prototypes; they are dump-side signatures, not ART call relationships."),
        area("art_jni_native", "ART / JNI / Native semantics", ObservationTier::InspectL1, CapabilityStage::Partial, VisibilityRisk::Medium, "ART DEX Open attaches to every exported DexFileLoader/ArtDexFileLoader Open, OpenCommon, OpenFromZipEntry, and OpenOne in libdexfile.so after GNU build-id match (dynsym prefix; no invented offsets). Path/size is decoded from AAPCS x0-x3 using that export's Itanium encoding; std::string and ClassLoader fields are not read. There is no OpenMemory symbol on this Android 14 build. Binder userspace inspect records handle and code from IPCThreadState::transact AAPCS registers; the interface token is UTF-16 from exported Parcel::writeInterfaceToken (x1/x2), copied at uprobe hit and paired to transact by TID (Pixel 6a: ~97% named in an 8s whole-device window). AIDL method names come from Pixel 6a on-device Stub TRANSACTION_* tables (aosp_stub) and, for unknown tokens, DESCRIPTOR/TRANSACTION_* in that process's stitched [anon:dalvik-DEX data] walked by DEX header file_size (process_dex, session-only; no VMA size cliff). NDK LAST_CALL_TRANSACTION is getInterfaceVersion/Hash on every HAL. Pixel 6a extra_hal covers IComponent, IAllocator, IGpuService, and IDrmFactory from on-device NDK/Bn switch tables. GMS/app names are not hardcoded. Exported Parcel writers attached on the same TID: writeString16(char16_t const*, size_t), writeString8(char const*, size_t), writeCString(char const*), writeInt32, writeInt64, writeUint32, writeUint64, writeBool, writeByteArray, writeFileDescriptor, writeDupFileDescriptor. writeFloat/writeDouble are not attached (uprobe has no FP regs). writeStrongBinder is not attached (sp<IBinder> is a C++ object). Inspect transact joins L0 binder:req by tid+code as correlated joined_transact and copies reply latency from the kernel pair. Packed-app heap DEX is dump-package correlated VMA evidence, not an ART inspect hit. JNIEnv GetStringUTFChars/NewStringUTF/GetByteArray*/RegisterNatives are not dynsym names on this Android 16 libart; `--inspect-adapter jni_plaintext` resolves JNINativeInterface from exported art::JNIEnvExt::GetFunctionTable ADRP+ADD tables using public jni.h slots (no ART String/array object offsets). RegisterNatives copies JNINativeMethod name/signature/fnPtr; jclass fields are not read. Dump jni_exports lists dynsym Java_*/JNI_OnLoad; stripped packer SOs are empty. HTTP catalog paths join DEX string-pool/class->method as correlated http_code_refs, not a JNI call stack. No Java method execution is claimed."),
        area("tls_quic", "TLS / QUIC boundaries", ObservationTier::InspectL1, CapabilityStage::Partial, VisibilityRisk::High, "L0 first-write copies parse TLS ClientHello SNI/ALPN and detect QUIC Initial without MITM. --inspect-tls may be combined with --inspect-adapter binder_userspace. SSL_write/SSL_read attach on Conscrypt libssl.so and tethering stable_cronet_libssl.so when exported; ELF64 is preferred and ELF32 is skipped when a 64-bit libssl with SSL_write is mapped (this arm64 GKI returns ENOTSUP for AArch32 uprobes). QUIC STREAM/HTTP/3 bodies are not SSL_write and are not decrypted. dump tls_stacks classifies Conscrypt/Cronet/Flutter/mbedTLS/wolfSSL/GmSSL/TASSL/app libssl. Flutter Dart TLS, Cronet without exported SSL_write, WebView/Chromium, and custom stacks (including app `libhssl` without that export) are not copied."),
        area("native_stack", "Native call chains", ObservationTier::InspectL1, CapabilityStage::Planned, VisibilityRisk::Medium, "Requires stack collection plus symbol and unwind metadata; stripped or generated code may remain unresolved."),
        area("java_stack", "Java call chains", ObservationTier::InspectL1, CapabilityStage::Research, VisibilityRisk::Medium, "Requires Android-version-specific ART metadata and stack reconstruction; universal coverage cannot be promised."),
        area("memory_snapshot", "Memory snapshots", ObservationTier::ForensicL2, CapabilityStage::Partial, VisibilityRisk::High, "ksightd snapshot / ksightctl device snapshot copies selected live mappings of one PID/package: SIGSTOP, bounded /proc/pid/mem, per-range SHA-256, pause/torn/elapsed. Auto-select ranks stitched rw heaps; --start/--end copies one VA window. dump-package live harvest also pauses, then copies bounded CE/DE shared_prefs/databases/files/no_backup into data-private (≤512 files, ≤8 MiB each; not a full /data/data image). Those copies are scanned for `http(s)://` into dump `http_calls` (origin=private). Heap plaintext windows (4096-byte cuts around HTTP/JSON/`https://` needles, cap 64) are scanned even when the packer SO has already unmapped. pull-package --hide-debug clears USB debugging after ART attach and before --launch (apps that read adb_enabled). pull-package --denylist adds the package to Magisk DenyList for the dump window when Magisk is present. Neither hides root or an unlocked bootloader. eBPF does not bulk-copy process memory."),
        area("plaintext", "Plaintext evidence", ObservationTier::InspectL1, CapabilityStage::Partial, VisibilityRisk::High, "Outbound TLS writes are copied at SSL_write entry. Inbound TLS reads pair SSL_read entry (buffer pointer) with uretprobe return (byte count in x0), then copy the filled buffer (default 4096, hard cap 4096). Consecutive SSL_read/SSL_write text previews for one process are stitched up to 16 KiB. gzip/zlib magic in those buffers is inflated before HTTP/JSON/`http(s)://` URL parse. `--inspect-tls --package` attaches both on mapped ELF64 libssl.so/libcronet.so that export SSL_write; ELF32 is skipped when ELF64 is available. Combine with `--inspect-adapter binder_userspace`. recv graphs as `tls_recv`. HTTP/1 request-line, Host, query keys, JSON/form body keys, and embedded URLs are parsed from Inspect previews and dump heap windows into `http_calls` with Cookie/Authorization/token values redacted. Heap windows are 4096-byte cuts around HTTP/1.1, GET/POST, `https://`, `\"url\"`/`\"host\"`/`\"path\"`, `/api/`, or `:path`/`:authority`; NUL header tables are parsed; responses have no URL path. Same-host request/response is correlated `http_reply`. HTTP/2 HEADERS are HPACK-decoded from already-copied TLS/JNI buffers with per-direction reassembly (`:method`/`:path`/`:authority`); DATA payloads may yield JSON/URLs. HPACK is report-side analysis of copied bytes, not MITM. CE/DE prefs/SQLite copies contribute origin=private URL rows. QUIC/HTTP/3 bodies are not decoded. Never Observe events. Cronet without SSL_write, Flutter Dart TLS, WebView/Chromium, and custom TLS without that export are classified in dump tls_stacks but not copied. `--inspect-adapter jni_plaintext` copies JNIEnv UTF-8/`byte[]` at the same selected-process Inspect layer (NewStringUTF x1, GetStringUTFChars return, Get/SetByteArrayRegion x3/x4); GetByteArrayElements is length-paired with GetArrayLength on the same jobject and zero-heavy/non-text arrays are dropped. Java-only and Flutter/WebView heaps are not JNI."),
        area("data_flow", "Cross-layer data-flow graph", ObservationTier::ObserveL0, CapabilityStage::Partial, VisibilityRisk::Low, "Session reports expose a queryable graph with confirmed Binder, Binder `replies_to`/`binder_reply` (request debug_id), Binder FD `transfers_fd`, socket, sched-wakeup, and mmap `maps` edges. DNS `answers` and first-write `sni`/`http_host` are correlated. Process nodes carry process_instance_id (`boot_id:pid:start_time_ns`) as `procinst:` keys when start time is known. mmap intervals record mapping_generation. dump-package VMA overlap is `overlaps_mmap` and always correlated. Inspect hits are correlated `inspect_hit` edges; binder_userspace transact may add correlated `joined_transact` to `binder:req` by tid+code. TLS `tls_send`/`tls_recv`, JNIEnv `jni_from_java`/`jni_to_java`, and Inspect HTTP `http_call` are selected-process facts; dump heap `http_call` and same-host `http_reply` are correlated. Time proximity is never a confirmed edge. fd_generation as a first-class join key remains planned."),
    ]
}

/// Return the reviewed but disabled L1 semantic keypoint registry.
pub fn semantic_keypoints() -> Vec<SemanticKeypoint> {
    vec![
        keypoint("linker_load", "linker", "Establish a confirmed shared-object load boundary and loader namespace.", &["linker64", "libdl.so"], "Exported symbol when present; otherwise build-ID-scoped symbol/offset adapter.", "Module build ID, ABI signature, short dry-run, and mmap/linker event agreement.", "Probe state, instruction patch/breakpoint mechanism, execution latency, and custom linker checks.", CapabilityStage::Partial),
        keypoint("art_dex_load", "ART", "Associate a validated DEX container with the process and load time.", &["libdexfile.so"], "Exported DexFileLoader/ArtDexFileLoader Open, OpenCommon, OpenFromZipEntry, and OpenOne file offsets after GNU build-id match. Argument layout from the export's Itanium encoding (x0-x3). No invented OpenMemory or ClassLoader offsets.", "Build ID, exported symbol, bounded argument validation, and agreement with dump VMA/path evidence.", "ART internals vary by release; timing, tracing state, code-page checks, or runtime self-tests may react.", CapabilityStage::Partial),
        keypoint("jni_registration", "JNI", "Relate Java native method registrations to Native function addresses.", &["libart.so", "application native libraries"], "JNINativeInterface::RegisterNatives file offset from exported GetFunctionTable tables and the public jni.h slot; JNINativeMethod name/signature/fnPtr copied from x2/x3. jclass object fields are not read.", "Method name+signature, native fnPtr, module build ID, and repeatable registration evidence.", "Registration timing changes and ART/native integrity checks may reveal observation.", CapabilityStage::Partial),
        keypoint("binder_userspace", "Binder", "Resolve interface descriptors and userspace transaction boundaries.", &["libbinder.so"], "ELF32 and ELF64 libbinder.so are both discovered (maps + /system/lib and /system/lib64). Exported IPCThreadState::transact plus Parcel writers attach on ELF64; this GKI returns ENOTSUP for AArch32 uprobes. Kernel binder_transaction copies a bounded parcel prefix for both ABIs after compat conversion and parses the String16 interface token. AIDL names from Pixel 6a on-device Stub TRANSACTION tables, session process DEX for unknown tokens, and extra_hal NDK/Bn tables. writeFloat/writeDouble are not attached (no FPSIMD in uprobe pt_regs). IBinder C++ fields and Parcel mData are not read.", "Build ID, exported symbols, bounded UTF-16 validation, and agreement with kernel Binder stages.", "C++ symbols and wrappers vary; high-frequency probes can change IPC latency.", CapabilityStage::Partial),
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
