//! Explicit Inspect policy. Adapters are off by default and must name a process.

use serde::{Deserialize, Serialize};

/// Versioned Inspect/Debug authorization for selected-process adapters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InspectPolicy {
    /// Master switch; default is disabled.
    pub enabled: bool,
    /// Target thread-group ID.
    pub pid: Option<u32>,
    /// Target Linux UID, including the app's colon processes.
    pub uid: Option<u32>,
    /// Target Android package. Preferred selector for plaintext Inspect.
    pub package: Option<String>,
    /// Optional ELF path for uprobe attachment.
    pub elf_path: Option<String>,
    /// Optional file offset for the probe.
    pub offset: Option<u64>,
    /// Optional GNU build-id that must match before attach.
    pub build_id: Option<String>,
    /// Maximum hits before the probe is revoked.
    pub max_hits: u32,
    /// Maximum wall time for the adapter.
    pub max_duration_secs: u32,
    /// Attach with no app filter. Noisy; prefer `--package` during a short test.
    pub whole_device: bool,
    /// Maximum plaintext bytes copied from a single TLS write.
    pub max_payload_bytes: u32,
    /// Operator-visible statement that the mechanism is detectable.
    pub detectability_notice: String,
}

impl Default for InspectPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            pid: None,
            uid: None,
            package: None,
            elf_path: None,
            offset: None,
            build_id: None,
            max_hits: 1,
            max_duration_secs: 5,
            whole_device: false,
            max_payload_bytes: 256,
            detectability_notice: "Inspect uses observable uprobes and is never an Observe event"
                .to_owned(),
        }
    }
}

impl InspectPolicy {
    /// Whether this policy may attach an adapter.
    pub fn may_attach(&self) -> bool {
        self.enabled
            && (self.whole_device
                || self.pid.is_some_and(|pid| pid > 0)
                || self.uid.is_some_and(|uid| uid > 0)
                || self.package.as_deref().is_some_and(|name| !name.is_empty()))
    }
}

/// One auditable Inspect decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InspectAuditEvent {
    /// Policy generation.
    pub generation: u64,
    /// Adapter name, for example `linker_so_load`.
    pub adapter: String,
    /// Whether the adapter attached.
    pub attached: bool,
    /// Why attach was refused or revoked.
    pub detail: String,
}
