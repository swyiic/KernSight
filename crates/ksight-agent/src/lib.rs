//! Device-side `KernSight` orchestration boundaries.

/// Low-cost userspace aggregation.
pub mod aggregate;
/// Session-start procfs FD/VMA baseline capture.
pub mod baseline;
/// Read-only platform capability discovery.
pub mod capabilities;
/// Foreground multi-sensor capture orchestration.
pub mod capture;
/// Bounded raw-record collection.
pub mod collector;
/// Negotiated durable-session control protocol.
pub mod control;
/// Dump decrypted DEX from live process mappings.
pub mod dexdump;
/// Copy an installed package's APK, native libraries, and live DEX images.
pub mod dump;
/// Minimal ELF64 identity used by Inspect adapters.
pub mod elf;
/// Session-start Android environment evidence.
pub mod environment;
/// Cross-process file-descriptor lineage tracking.
pub mod fd_lineage;
/// Best-effort file path semantic enrichment.
pub mod file;
pub mod identity;
/// Inspect adapter evaluation and selected-process attachment.
pub mod inspect_runtime;
/// Capture and deployment integrity reporting.
pub mod integrity;
/// Sensor loading and attachment lifecycle.
pub mod loader;
/// Best-effort virtual-memory semantic enrichment.
pub mod memory;
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
/// Durable disconnected-session buffering.
pub mod spool;
/// Runtime tracepoint-format compatibility checks.
pub mod tracepoint;
/// Authenticated local transport boundary.
pub mod transport;

/// Linux/Android eBPF sensor adapter.
#[cfg(any(target_os = "android", target_os = "linux"))]
pub mod ebpf;

pub use capabilities::{
    CapabilityProbe, CapabilityStatus, HostCapabilityProbe, ProbeReport, TracepointCapability,
};
pub use runtime::{AgentRuntime, RuntimeState};
