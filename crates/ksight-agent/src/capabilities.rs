use serde::{Deserialize, Serialize};

/// Read-only platform capability probe.
pub trait CapabilityProbe {
    /// Collect a report without changing system state.
    fn probe(&self) -> ProbeReport;
}

/// Minimal host-safe probe used before Android adapters exist.
#[derive(Debug, Default)]
pub struct HostCapabilityProbe;

impl CapabilityProbe for HostCapabilityProbe {
    fn probe(&self) -> ProbeReport {
        ProbeReport {
            target_os: std::env::consts::OS.to_owned(),
            architecture: std::env::consts::ARCH.to_owned(),
            android: cfg!(target_os = "android"),
            bpf_loader_implemented: false,
            notes: vec!["architecture baseline only; no kernel probe executed".to_owned()],
        }
    }
}

/// Read-only capability result suitable for CLI diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeReport {
    /// Rust target operating system.
    pub target_os: String,
    /// Rust target architecture.
    pub architecture: String,
    /// Whether this binary is running on Android.
    pub android: bool,
    /// Whether a real BPF loader is present in this build.
    pub bpf_loader_implemented: bool,
    /// Operator-facing limitations.
    pub notes: Vec<String>,
}
