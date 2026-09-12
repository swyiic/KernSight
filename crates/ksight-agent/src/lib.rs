//! Device-side `KernSight` orchestration boundaries.

/// Low-cost userspace aggregation.
pub mod aggregate;
/// Session-start procfs FD/VMA baseline capture.
pub mod baseline;
/// Pixel 6a AOSP Binder `TRANSACTION_*` method names.
pub mod binder_aidl;
/// Session-scoped Binder method names from a process's loaded DEX.
pub mod binder_dex;
/// Reconstruct Inspect HTTP/WS copies and feed a Burp HTTP proxy.
pub mod burp_mirror;
/// Read-only platform capability discovery.
pub mod capabilities;
/// Foreground multi-sensor capture orchestration.
pub mod capture;
/// Bounded raw-record collection.
pub mod collector;
/// Negotiated durable-session control protocol.
pub mod control;
/// Live heap scan for AES/SM4 material while capturing.
/// Included under `test` so host unit tests can validate needle families on macOS.
#[cfg(any(test, target_os = "android", target_os = "linux"))]
pub mod crypto_watch;
/// Dump decrypted DEX from live process mappings.
pub mod dexdump;
/// Join DNS answers to later socket connects.
pub mod dns_lineage;
/// Copy an installed package's APK, native libraries, and live DEX images.
pub mod dump;
/// Operator opt-in dump-window helpers (USB hide marker, Magisk DenyList).
pub mod dump_guard;
/// Minimal ELF64 identity used by Inspect adapters.
pub mod elf;
/// Session-start Android environment evidence.
pub mod environment;
/// Cross-process file-descriptor lineage tracking.
pub mod fd_lineage;
/// Best-effort file path semantic enrichment.
pub mod file;
pub mod identity;
pub mod infosec_probe;
/// Inspect adapter evaluation and selected-process attachment.
pub mod inspect_runtime;
/// Capture and deployment integrity reporting.
pub mod integrity;
/// `JNIEnv` plaintext functions from exported `GetFunctionTable` + `jni.h` slots.
pub mod jni_env;
pub mod keylog_probe;
/// Sensor loading and attachment lifecycle.
pub mod loader;
/// Best-effort virtual-memory semantic enrichment.
pub mod memory;
/// Per-UID iptables DNAT to Burp.
#[cfg(any(target_os = "android", target_os = "linux"))]
pub mod mitm_redirect;
/// Raw ABI normalization.
pub mod normalize;
/// Validated capture policy state.
pub mod policy;
/// Global spool retention, last-exit records, and interrupted-session repair.
pub mod retention;
/// Agent lifecycle orchestration.
pub mod runtime;
/// Enriched capture-scope filtering.
pub mod scope;
/// Versioned long-running collector configuration.
pub mod service;
/// Bounded L2 forensic memory snapshots.
pub mod snapshot;
/// Durable disconnected-session buffering.
pub mod spool;
/// Late `dlopen` of `libksight_tls.so` after packer init.
#[cfg(any(target_os = "android", target_os = "linux"))]
pub mod tls_inject;
/// Runtime tracepoint-format compatibility checks.
pub mod tracepoint;
/// Authenticated local transport boundary.
pub mod transport;

/// Linux/Android eBPF sensor adapter.
#[cfg(any(target_os = "android", target_os = "linux"))]
pub mod ebpf;
pub mod embedded;

pub use capabilities::{
    CapabilityProbe, CapabilityStatus, HostCapabilityProbe, ProbeReport, TracepointCapability,
};
pub use runtime::{AgentRuntime, RuntimeState};
