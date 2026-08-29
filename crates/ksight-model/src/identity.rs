use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Stable process key that survives PID reuse.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProcessKey {
    /// Device boot identifier.
    pub boot_id: Uuid,
    /// Linux process ID.
    pub pid: u32,
    /// Kernel monotonic process start time in nanoseconds, or zero when not observed.
    pub start_time_ns: u64,
}

/// Candidate Android package associated with a Linux identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageCandidate {
    /// Android package name.
    pub package_name: String,
    /// Why this package is a candidate.
    pub source: String,
    /// Confidence from 0 through 100.
    pub confidence_percent: u8,
}

/// Normalized Linux and Android identity attached to an event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessIdentity {
    /// Stable process instance key.
    pub key: ProcessKey,
    /// Thread ID.
    pub tid: u32,
    /// Thread-group ID.
    pub tgid: u32,
    /// Linux UID.
    pub uid: u32,
    /// Linux GID.
    pub gid: u32,
    /// Kernel task name.
    pub comm: String,
    /// First null-terminated command-line component when procfs is readable.
    pub command_line: Option<String>,
    /// `SELinux` context when available.
    pub selinux_context: Option<String>,
    /// Zero or more candidates; shared and isolated UIDs may be ambiguous.
    pub packages: Vec<PackageCandidate>,
}
