//! Bounded session-start Android environment evidence.

use std::process::Command;
use std::time::{Duration, Instant};

use ksight_model::{CollectorMode, EnvironmentState, SessionEnvironment};

const MAX_VALUE_BYTES: usize = 256;
const ENVIRONMENT_READ_BUDGET: Duration = Duration::from_millis(250);
const COMMAND_READ_BUDGET: Duration = Duration::from_millis(100);

/// Collect environment switches that may make an application alter its execution path.
pub fn collect(mode: CollectorMode) -> SessionEnvironment {
    let deadline = Instant::now() + ENVIRONMENT_READ_BUDGET;
    let developer_options = setting_state("development_settings_enabled", deadline);
    let usb_debugging = setting_state("adb_enabled", deadline);
    let wireless_debugging = setting_state("adb_wifi_enabled", deadline);
    let root_authorized = effective_uid() == Some(0);
    let selinux_enforcing = std::fs::read_to_string("/sys/fs/selinux/enforce")
        .ok()
        .and_then(|value| parse_bool(value.trim()));
    let verified_boot_state = property("ro.boot.verifiedbootstate", deadline);
    let bootloader_locked = property("ro.boot.flash.locked", deadline)
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

fn setting_state(name: &str, deadline: Instant) -> EnvironmentState {
    command_value("/system/bin/settings", &["get", "global", name], deadline)
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

fn property(name: &str, deadline: Instant) -> Option<String> {
    command_value("/system/bin/getprop", &[name], deadline).filter(|value| !value.is_empty())
}

// Advisory environment commands must not block the capture loop or outlive
// its original lease. Failure remains Unknown; no success/false is invented.
fn command_value(program: &str, arguments: &[&str], deadline: Instant) -> Option<String> {
    let started = Instant::now();
    let command_deadline = deadline.min(started + COMMAND_READ_BUDGET);
    let mut command = Command::new(program);
    command.args(arguments);
    let value = bounded_command_value(command, command_deadline, || {
        ksight_core::output_budget::should_stop(&crate::runtime_paths::root().join("spool"))
    });
    if value.is_none() {
        let stopped =
            ksight_core::output_budget::should_stop(&crate::runtime_paths::root().join("spool"));
        eprintln!(
            "{}",
            serde_json::json!({
                "schema":"kernsight.environment-command/v1", "program":program,
                "arguments":arguments, "elapsed_ms":started.elapsed().as_millis(),
                "status":"unknown", "reason":if stopped { "original_lease_stopped" } else if Instant::now() >= command_deadline { "command_deadline_exhausted" } else { "command_output_unavailable" },
                "output_limit_bytes":MAX_VALUE_BYTES,
            })
        );
    }
    value
}

#[cfg(unix)]
fn bounded_command_value(
    mut command: Command,
    deadline: Instant,
    should_stop: impl Fn() -> bool,
) -> Option<String> {
    use rustix::process::{waitid, Pid, WaitId, WaitIdOptions};
    use std::io::Read;
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;
    if Instant::now() >= deadline || should_stop() {
        return None;
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0);
    let mut child = command.spawn().ok()?;
    // Keep the owned leader unreaped until both exit and bounded pipe EOF.
    // This also keeps its PID reserved while cancelling its process group.
    let result = (|| {
        let mut stdout = child.stdout.take()?;
        let flags = rustix::fs::fcntl_getfl(&stdout).ok()?;
        rustix::fs::fcntl_setfl(&stdout, flags | rustix::fs::OFlags::NONBLOCK).ok()?;
        let pid = Pid::from_raw(i32::try_from(child.id()).ok()?)?;
        let mut bytes = Vec::with_capacity(MAX_VALUE_BYTES + 1);
        let mut eof = false;
        loop {
            if Instant::now() >= deadline || should_stop() {
                return None;
            }
            let mut block = [0u8; MAX_VALUE_BYTES + 1];
            match stdout.read(&mut block) {
                Ok(0) => eof = true,
                Ok(n) => {
                    bytes.extend_from_slice(&block[..n]);
                    if bytes.len() > MAX_VALUE_BYTES {
                        return None;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return None,
            }
            let exited = waitid(
                WaitId::Pid(pid),
                WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
            )
            .ok()?
            .is_some();
            if exited && eof {
                return Some(bytes);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    })();
    if result.is_none() {
        // The leader has never been reaped, so this numeric group cannot have
        // been reused. Only the child group created above is signalled.
        if let Ok(pid) = i32::try_from(child.id()) {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(-pid),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
        let _ = child.kill();
    }
    let status = child.wait().ok()?;
    if !status.success() {
        return None;
    }
    String::from_utf8(result?)
        .ok()
        .map(|value| value.trim().to_owned())
}

#[cfg(not(unix))]
fn bounded_command_value(
    _command: Command,
    _deadline: Instant,
    _should_stop: impl Fn() -> bool,
) -> Option<String> {
    None
}

#[cfg(all(test, unix))]
mod bounded_command_tests {
    use super::*;
    fn shell(script: &str) -> Command {
        let mut c = Command::new("/bin/sh");
        c.args(["-c", script]);
        c
    }
    #[test]
    fn ordinary_and_nonzero_outputs_remain_truthful() {
        assert_eq!(
            bounded_command_value(
                shell("printf ' 1\n'"),
                Instant::now() + Duration::from_secs(1),
                || false
            )
            .as_deref(),
            Some("1")
        );
        assert_eq!(
            bounded_command_value(
                shell("printf 1; exit 7"),
                Instant::now() + Duration::from_secs(1),
                || false
            ),
            None
        );
    }
    #[test]
    fn sleeping_command_cannot_block_capture_or_outlive_deadline() {
        let start = Instant::now();
        assert_eq!(
            bounded_command_value(shell("sleep 10"), start + Duration::from_millis(40), || {
                false
            }),
            None
        );
        assert!(start.elapsed() < Duration::from_secs(1));
    }
    #[test]
    fn exited_leader_with_descendant_held_pipe_is_bounded() {
        let start = Instant::now();
        assert_eq!(
            bounded_command_value(
                shell("sleep 10 & exit 0"),
                start + Duration::from_millis(40),
                || false
            ),
            None
        );
        assert!(start.elapsed() < Duration::from_secs(1));
    }
    #[test]
    fn oversized_output_does_not_wait_for_eof() {
        let start = Instant::now();
        assert_eq!(
            bounded_command_value(
                shell("printf '%0300d' 0; sleep 10"),
                start + Duration::from_secs(2),
                || false
            ),
            None
        );
        assert!(start.elapsed() < Duration::from_secs(1));
    }
    #[test]
    fn original_lease_stop_cancels_inflight_environment_read() {
        let start = Instant::now();
        assert_eq!(
            bounded_command_value(shell("sleep 10"), start + Duration::from_secs(2), || start
                .elapsed()
                > Duration::from_millis(30)),
            None
        );
        assert!(start.elapsed() < Duration::from_secs(1));
    }
    #[test]
    fn exhausted_collection_budget_spawns_nothing() {
        assert_eq!(
            bounded_command_value(Command::new("/not/a/real/program"), Instant::now(), || {
                false
            }),
            None
        );
    }
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
