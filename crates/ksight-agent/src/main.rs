//! `ksightd` device-service entry point.

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use ksight_agent::{CapabilityProbe, HostCapabilityProbe};

#[derive(Debug, Parser)]
#[command(name = "ksightd", version, about = "KernSight device agent")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Perform a read-only capability probe.
    Probe {
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Start the device service when a capture adapter is available.
    Run {
        /// Validate configuration without starting capture.
        #[arg(long)]
        dry_run: bool,
    },
}

fn main() -> Result<()> {
    let args = Args::parse();
    match args.command {
        Command::Probe { json } => {
            let report = HostCapabilityProbe.probe();
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("target: {}/{}", report.target_os, report.architecture);
                for note in report.notes {
                    println!("note: {note}");
                }
            }
            Ok(())
        }
        Command::Run { dry_run: true } => {
            println!("configuration boundary is valid; capture adapter is not implemented");
            Ok(())
        }
        Command::Run { dry_run: false } => {
            bail!("capture adapter is not implemented; refusing to claim a running session")
        }
    }
}
