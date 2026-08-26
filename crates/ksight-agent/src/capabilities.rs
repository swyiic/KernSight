use serde::{Deserialize, Serialize};
use std::io::Read;

/// Read-only platform capability probe.
pub trait CapabilityProbe {
    /// Collect a report without changing system state.
    fn probe(&self) -> ProbeReport;
}

/// Host-safe probe that discovers Linux/Android kernel interfaces without changing them.
#[derive(Debug, Default)]
pub struct HostCapabilityProbe;

impl CapabilityProbe for HostCapabilityProbe {
    fn probe(&self) -> ProbeReport {
        let mounts = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
        let android = std::path::Path::new("/system/build.prop").exists()
            || std::path::Path::new("/system/bin/app_process64").exists();
        let tracepoints = [
            "sched/sched_process_fork",
            "sched/sched_process_exec",
            "sched/sched_process_exit",
        ]
        .into_iter()
        .map(|name| TracepointCapability {
            available: std::path::Path::new("/sys/kernel/tracing/events")
                .join(name)
                .join("id")
                .exists(),
            name: name.to_owned(),
        })
        .collect::<Vec<_>>();
        let btf_readable = can_read_byte("/sys/kernel/btf/vmlinux");
        let bpffs_mounted = mount_type_present(&mounts, "bpf", "/sys/fs/bpf");
        let tracefs_mounted = mount_type_present(&mounts, "tracefs", "/sys/kernel/tracing");
        let running_as_root = effective_uid().is_some_and(|uid| uid == 0);
        let loader_available = cfg!(any(target_os = "android", target_os = "linux"));
        let mut notes = Vec::new();

        if !loader_available {
            notes.push("live eBPF loader is not included for this host target".to_owned());
        }
        if !running_as_root {
            notes.push("capture normally requires a root-authorized service domain".to_owned());
        }
        if !btf_readable {
            notes.push("kernel BTF is not readable in the current security domain".to_owned());
        }
        if tracepoints.iter().any(|tracepoint| !tracepoint.available) {
            notes.push("one or more M1 scheduler tracepoints are unavailable".to_owned());
        }

        ProbeReport {
            target_os: std::env::consts::OS.to_owned(),
            architecture: std::env::consts::ARCH.to_owned(),
            android,
            kernel_release: read_trimmed("/proc/sys/kernel/osrelease"),
            running_as_root,
            btf_readable: CapabilityStatus::from(btf_readable),
            bpffs_mounted: CapabilityStatus::from(bpffs_mounted),
            tracefs_mounted: CapabilityStatus::from(tracefs_mounted),
            tracepoints,
            bpf_loader_implemented: CapabilityStatus::from(loader_available),
            notes,
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
    /// Running kernel release when exposed by procfs.
    pub kernel_release: Option<String>,
    /// Whether the process has effective UID zero.
    pub running_as_root: bool,
    /// Whether runtime kernel BTF can be opened by this security domain.
    pub btf_readable: CapabilityStatus,
    /// Whether bpffs is mounted at the conventional Android path.
    pub bpffs_mounted: CapabilityStatus,
    /// Whether tracefs is mounted at the conventional Android path.
    pub tracefs_mounted: CapabilityStatus,
    /// Required M1 scheduler tracepoints.
    pub tracepoints: Vec<TracepointCapability>,
    /// Whether a real BPF loader is present in this build.
    pub bpf_loader_implemented: CapabilityStatus,
    /// Operator-facing limitations.
    pub notes: Vec<String>,
}

/// Uniform status for a probed capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityStatus {
    /// The capability was established in the current security domain.
    Available,
    /// The capability could not be established in the current security domain.
    Unavailable,
}

impl From<bool> for CapabilityStatus {
    fn from(available: bool) -> Self {
        if available {
            Self::Available
        } else {
            Self::Unavailable
        }
    }
}

impl std::fmt::Display for CapabilityStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Available => formatter.write_str("available"),
            Self::Unavailable => formatter.write_str("unavailable"),
        }
    }
}

/// Availability of one tracepoint required by a sensor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TracepointCapability {
    /// Tracefs-relative category and event name.
    pub name: String,
    /// Whether its numeric tracepoint ID is visible.
    pub available: bool,
}

fn read_trimmed(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn can_read_byte(path: &str) -> bool {
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    let mut byte = [0_u8; 1];
    file.read_exact(&mut byte).is_ok()
}

fn mount_type_present(mounts: &str, filesystem: &str, mountpoint: &str) -> bool {
    mounts.lines().any(|line| {
        let mut fields = line.split_whitespace();
        let _source = fields.next();
        let mounted_at = fields.next();
        let mounted_type = fields.next();
        mounted_at == Some(mountpoint) && mounted_type == Some(filesystem)
    })
}

fn effective_uid() -> Option<u32> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with("Uid:"))?;
    line.split_whitespace().nth(2)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_exact_mount_type_and_path() {
        let mounts = "bpffs /sys/fs/bpf bpf rw 0 0\ntracefs /sys/kernel/tracing tracefs rw 0 0\n";
        assert!(mount_type_present(mounts, "bpf", "/sys/fs/bpf"));
        assert!(mount_type_present(mounts, "tracefs", "/sys/kernel/tracing"));
        assert!(!mount_type_present(
            mounts,
            "debugfs",
            "/sys/kernel/tracing"
        ));
    }
}
