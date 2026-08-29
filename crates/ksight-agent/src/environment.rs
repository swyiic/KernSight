//! Bounded session-start Android environment evidence.

use std::process::Command;

use ksight_model::{CollectorMode, EnvironmentState, SessionEnvironment};

const MAX_VALUE_BYTES: usize = 256;

/// Collect environment switches that may make an application alter its execution path.
pub fn collect(mode: CollectorMode) -> SessionEnvironment {
    let developer_options = setting_state("development_settings_enabled");
    let usb_debugging = setting_state("adb_enabled");
    let wireless_debugging = setting_state("adb_wifi_enabled");
    let root_authorized = effective_uid() == Some(0);
    let selinux_enforcing = std::fs::read_to_string("/sys/fs/selinux/enforce")
        .ok()
        .and_then(|value| parse_bool(value.trim()));
    let verified_boot_state = property("ro.boot.verifiedbootstate");
    let bootloader_locked = property("ro.boot.flash.locked")
        .as_deref()
        .and_then(parse_bool);
    let mut warnings = Vec::new();
    if developer_options == EnvironmentState::Enabled {
        warnings.push("developer options enabled".to_owned());
    }
    if usb_debugging == EnvironmentState::Enabled {
        warnings.push("USB debugging enabled".to_owned());
    }
    if wireless_debugging == EnvironmentState::Enabled {
        warnings.push("wireless debugging enabled".to_owned());
    }
    if root_authorized {
        warnings.push("collector has root authorization".to_owned());
    }
    if verified_boot_state
        .as_deref()
        .is_some_and(|state| state != "green")
    {
        warnings.push("verified boot state is not green".to_owned());
    }
    if bootloader_locked == Some(false) {
        warnings.push("bootloader reported unlocked".to_owned());
    }

    SessionEnvironment {
        collector_mode: mode,
        developer_options,
        usb_debugging,
        wireless_debugging,
        root_authorized,
        selinux_enforcing,
        verified_boot_state,
        bootloader_locked,
        target_behavior_may_be_altered: !warnings.is_empty(),
        warnings,
        monotonic_ns: clock_ns(nix::time::ClockId::CLOCK_MONOTONIC),
        wall_clock_ns: clock_ns(nix::time::ClockId::CLOCK_REALTIME),
    }
}

fn clock_ns(clock: nix::time::ClockId) -> Option<u64> {
    let timespec = nix::time::clock_gettime(clock).ok()?;
    let seconds = u64::try_from(timespec.tv_sec()).ok()?;
    let nanos = u64::try_from(timespec.tv_nsec()).ok()?;
    seconds.checked_mul(1_000_000_000)?.checked_add(nanos)
}

fn setting_state(name: &str) -> EnvironmentState {
    command_value("/system/bin/settings", &["get", "global", name])
        .as_deref()
        .and_then(parse_bool)
        .map_or(EnvironmentState::Unknown, |enabled| {
            if enabled {
                EnvironmentState::Enabled
            } else {
                EnvironmentState::Disabled
            }
        })
}

fn property(name: &str) -> Option<String> {
    command_value("/system/bin/getprop", &[name]).filter(|value| !value.is_empty())
}

fn command_value(program: &str, arguments: &[&str]) -> Option<String> {
    let output = Command::new(program).args(arguments).output().ok()?;
    if !output.status.success() || output.stdout.len() > MAX_VALUE_BYTES {
        return None;
    }
    String::from_utf8(output.stdout)
        .ok()
        .map(|value| value.trim().to_owned())
}

fn parse_bool(value: &str) -> Option<bool> {
    match value {
        "1" | "true" | "enabled" => Some(true),
        "0" | "false" | "disabled" => Some(false),
        _ => None,
    }
}

fn effective_uid() -> Option<u32> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status
        .lines()
        .find(|line| line.starts_with("Uid:"))?
        .split_whitespace()
        .nth(2)?
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boolean_parser_is_strict() {
        assert_eq!(parse_bool("1"), Some(true));
        assert_eq!(parse_bool("disabled"), Some(false));
        assert_eq!(parse_bool("null"), None);
    }
}
