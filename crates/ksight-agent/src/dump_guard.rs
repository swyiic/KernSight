//! Operator opt-in dump-window helpers. Generic; not tied to any package name.

use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

use ksight_model::{CollectorMode, EnvironmentState};

use crate::environment;

/// Marker the hide-debug wrapper waits for before turning USB debugging off.
pub const DUMP_READY_PATH: &str = "/data/local/tmp/ksight/dump-ready";

/// Optional Magisk `DenyList` and dump-ready marker for one dump.
pub struct DumpWindow {
    package: String,
    denylist_requested: bool,
    denylist_added: bool,
    denylist_detail: String,
    hide_debug: bool,
}

/// Environment recorded into the dump report. Not a claim that the app was fooled.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[allow(clippy::struct_excessive_bools)]
#[serde(default)]
pub struct DumpObservationEnv {
    /// `settings get global adb_enabled` at dump start.
    pub usb_debugging: String,
    /// `settings get global development_settings_enabled` at dump start.
    pub developer_options: String,
    /// Collector effective UID is 0.
    pub root_authorized: bool,
    /// USB debugging hide was requested (wrapper turns it off after attach).
    pub hide_debug_requested: bool,
    /// Magisk `DenyList` add was requested.
    pub denylist_requested: bool,
    /// Whether `DenyList` add succeeded.
    pub denylist_applied: bool,
    /// Magisk/`DenyList` outcome; empty when not requested.
    pub denylist_detail: String,
}

impl DumpWindow {
    /// Apply optional `DenyList`; USB hide is performed by the host wrapper after [`Self::mark_ready_and_yield`].
    pub fn enter(package: &str, hide_debug: bool, denylist: bool) -> Self {
        let mut window = Self {
            package: package.to_owned(),
            denylist_requested: denylist,
            denylist_added: false,
            denylist_detail: String::new(),
            hide_debug,
        };
        let _ = std::fs::remove_file(DUMP_READY_PATH);
        if denylist {
            match magisk_denylist_add(package) {
                Ok(detail) => {
                    window.denylist_added = true;
                    window.denylist_detail = detail;
                }
                Err(detail) => window.denylist_detail = detail,
            }
        }
        window
    }

    /// Snapshot environment after optional `DenyList`, before launch.
    pub fn observation_env(&self) -> DumpObservationEnv {
        let env = environment::collect(CollectorMode::ForegroundAdb);
        DumpObservationEnv {
            usb_debugging: state_name(env.usb_debugging),
            developer_options: state_name(env.developer_options),
            root_authorized: env.root_authorized,
            hide_debug_requested: self.hide_debug,
            denylist_requested: self.denylist_requested,
            denylist_applied: self.denylist_added,
            denylist_detail: self.denylist_detail.clone(),
        }
    }

    /// Signal the hide-debug wrapper that uprobes are attached and launch may proceed.
    pub fn mark_ready_and_yield(&self) {
        if !self.hide_debug {
            return;
        }
        let _ = std::fs::write(DUMP_READY_PATH, self.package.as_bytes());
        // Wrapper turns USB debugging off after this file appears.
        std::thread::sleep(Duration::from_millis(1500));
    }
}

impl Drop for DumpWindow {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(DUMP_READY_PATH);
        if self.denylist_added {
            magisk_denylist_rm(&self.package);
        }
    }
}

fn state_name(state: EnvironmentState) -> String {
    match state {
        EnvironmentState::Enabled => "enabled".to_owned(),
        EnvironmentState::Disabled => "disabled".to_owned(),
        EnvironmentState::Unknown => "unknown".to_owned(),
    }
}

fn magisk_bin() -> Option<PathBuf> {
    const CANDIDATES: [&str; 4] = [
        "/sbin/magisk",
        "/system/bin/magisk",
        "/data/adb/magisk/magisk",
        "/debug_ramdisk/magisk",
    ];
    CANDIDATES
        .iter()
        .map(Path::new)
        .find(|path| path.is_file())
        .map(Path::to_path_buf)
}

fn magisk_denylist_add(package: &str) -> Result<String, String> {
    let Some(bin) = magisk_bin() else {
        return Err(
            "magisk binary not found; DenyList not applied (does not hide root)".to_owned(),
        );
    };
    let _ = Command::new(&bin)
        .args(["--denylist", "enable"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let status = Command::new(&bin)
        .args(["--denylist", "add", package])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("magisk denylist add failed: {error}"))?;
    if status.success() {
        Ok(format!(
            "added {package} to Magisk DenyList for this dump window"
        ))
    } else {
        Err(format!(
            "magisk denylist add exited {}; put the package on DenyList yourself",
            status.code().unwrap_or(-1)
        ))
    }
}

fn magisk_denylist_rm(package: &str) {
    let Some(bin) = magisk_bin() else {
        return;
    };
    let _ = Command::new(bin)
        .args(["--denylist", "rm", package])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// Rank dump targets: main package cmdline first, then `:service` processes.
pub fn cmdline_dump_rank(package: &str, cmdline: &str) -> u8 {
    if cmdline == package {
        0
    } else if cmdline.starts_with(&format!("{package}:")) {
        1
    } else {
        2
    }
}

#[cfg(test)]
mod tests {
    use super::cmdline_dump_rank;

    #[test]
    fn ranks_main_package_ahead_of_services() {
        assert_eq!(cmdline_dump_rank("com.icbc", "com.icbc"), 0);
        assert_eq!(cmdline_dump_rank("com.icbc", "com.icbc:push"), 1);
        assert_eq!(cmdline_dump_rank("com.icbc", "zygote"), 2);
    }
}
