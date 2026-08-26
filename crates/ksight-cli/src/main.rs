//! `ksightctl` command-line client entry point.

use std::process::{Command as ProcessCommand, ExitStatus};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use ksight_model::CURRENT_SCHEMA;
use ksight_protocol::CURRENT_PROTOCOL;

const DEVICE_AGENT: &str = "/data/local/tmp/ksight/ksightd";
const DEVICE_PROCESS_OBJECT: &str = "/data/local/tmp/ksight/process_lifecycle.bpf.o";

#[derive(Debug, Parser)]
#[command(name = "ksightctl", version, about = "KernSight command-line client")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print component boundaries before a device transport exists.
    Architecture,
    /// Print compatibility versions.
    Versions,
    /// Operate the authorized `KernSight` agent over ADB.
    Device {
        /// Select a device by ADB serial when more than one is connected.
        #[arg(long)]
        serial: Option<String>,
        #[command(subcommand)]
        command: DeviceCommand,
    },
}

#[derive(Debug, Subcommand)]
enum DeviceCommand {
    /// Print the device's read-only kernel capability report.
    Probe,
    /// Stream whole-device process lifecycle events.
    Capture {
        /// Stop after this many events; zero means no event limit.
        #[arg(long, default_value_t = 0)]
        count: u64,
        /// Stop after this many seconds; zero means no time limit.
        #[arg(long, default_value_t = 0)]
        duration_seconds: u64,
        /// Emit one normalized JSON event per line.
        #[arg(long)]
        json: bool,
    },
}

fn main() -> Result<()> {
    let args = Args::parse();
    match args.command {
        Command::Architecture => {
            println!("ksightctl -> versioned protocol -> ksightd -> sensor adapters -> eBPF");
            println!("MobileE is a peer client and is not a dependency of KernSight.");
        }
        Command::Versions => {
            println!(
                "wire={}.{} schema={}.{} raw_abi=1",
                CURRENT_PROTOCOL.major,
                CURRENT_PROTOCOL.minor,
                CURRENT_SCHEMA.major,
                CURRENT_SCHEMA.minor
            );
        }
        Command::Device { serial, command } => match command {
            DeviceCommand::Probe => {
                run_device(serial.as_deref(), &format!("{DEVICE_AGENT} probe --json"))?;
            }
            DeviceCommand::Capture {
                count,
                duration_seconds,
                json,
            } => {
                let json_flag = if json { " --json" } else { "" };
                let command = format!(
                    "{DEVICE_AGENT} capture --object {DEVICE_PROCESS_OBJECT} --count {count} --duration-seconds {duration_seconds}{json_flag}"
                );
                run_device(serial.as_deref(), &command)?;
            }
        },
    }
    Ok(())
}

fn run_device(serial: Option<&str>, device_command: &str) -> Result<()> {
    let mut adb = ProcessCommand::new("adb");
    if let Some(serial) = serial {
        validate_serial(serial)?;
        adb.args(["-s", serial]);
    }
    let remote = format!("su -c \"{device_command}\"");
    let status = adb
        .args(["shell", &remote])
        .status()
        .context("start adb; ensure Android platform-tools is installed and on PATH")?;
    ensure_success(status)
}

fn validate_serial(serial: &str) -> Result<()> {
    if serial.is_empty()
        || !serial
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:".contains(&byte))
    {
        bail!("ADB serial contains unsupported characters")
    }
    Ok(())
}

fn ensure_success(status: ExitStatus) -> Result<()> {
    if !status.success() {
        bail!("ADB device command failed with {status}")
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adb_serial_validation_rejects_shell_syntax() {
        assert!(validate_serial("42091FDH20089A").is_ok());
        assert!(validate_serial("emulator-5554").is_ok());
        assert!(validate_serial("device;reboot").is_err());
        assert!(validate_serial("").is_err());
    }
}
