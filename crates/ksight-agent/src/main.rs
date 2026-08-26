//! `ksightd` device-service entry point.

use std::path::PathBuf;

#[cfg(any(target_os = "android", target_os = "linux"))]
use std::time::Duration;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
#[cfg(any(target_os = "android", target_os = "linux"))]
use ksight_agent::{
    collector::Collector,
    normalize::{Normalizer, ProcessNormalizer},
};
use ksight_agent::{CapabilityProbe, HostCapabilityProbe};
#[cfg(any(target_os = "android", target_os = "linux"))]
use ksight_model::{Event, EventPayload};

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
    /// Attach the M1 process sensor and stream normalized lifecycle events.
    Capture {
        /// Compiled process lifecycle BPF object.
        #[arg(long, default_value = "build/bpf/process_lifecycle.bpf.o")]
        object: PathBuf,
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
        Command::Probe { json } => {
            let report = HostCapabilityProbe.probe();
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("target: {}/{}", report.target_os, report.architecture);
                println!("android: {}", report.android);
                println!(
                    "kernel: {}",
                    report.kernel_release.as_deref().unwrap_or("unknown")
                );
                println!("root: {}", report.running_as_root);
                println!("btf: {}", report.btf_readable);
                println!("bpffs: {}", report.bpffs_mounted);
                println!("tracefs: {}", report.tracefs_mounted);
                for tracepoint in report.tracepoints {
                    println!("tracepoint {}: {}", tracepoint.name, tracepoint.available);
                }
                for note in report.notes {
                    println!("note: {note}");
                }
            }
            Ok(())
        }
        Command::Run { dry_run: true } => {
            println!("configuration boundary is valid; use capture for the foreground M1 sensor");
            Ok(())
        }
        Command::Run { dry_run: false } => {
            bail!("background service mode is not implemented; use the capture command")
        }
        Command::Capture {
            object,
            count,
            duration_seconds,
            json,
        } => capture(&object, count, duration_seconds, json),
    }
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn capture(object: &std::path::Path, count: u64, duration_seconds: u64, json: bool) -> Result<()> {
    use std::time::Instant;

    use ksight_agent::ebpf::ProcessSensor;

    let mut sensor = ProcessSensor::load_and_attach(object)?;
    let mut normalizer = ProcessNormalizer::from_system()?;
    let started = Instant::now();
    let deadline = (duration_seconds != 0).then(|| Duration::from_secs(duration_seconds));
    let mut emitted = 0_u64;

    loop {
        if count != 0 && emitted >= count {
            break;
        }
        if deadline.is_some_and(|duration| started.elapsed() >= duration) {
            break;
        }

        if let Some(record) = sensor.next_record()? {
            let event = normalizer.normalize(record)?;
            if json {
                println!("{}", serde_json::to_string(&event)?);
            } else {
                print_event(&event);
            }
            emitted += 1;
        } else {
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    eprintln!(
        "capture complete: emitted={emitted} dropped={}",
        sensor.dropped_records()
    );
    Ok(())
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
fn capture(
    _object: &std::path::Path,
    _count: u64,
    _duration_seconds: u64,
    _json: bool,
) -> Result<()> {
    bail!("live eBPF capture is available only in Linux or Android builds")
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn print_event(event: &Event) {
    let process = &event.header.process;
    if let EventPayload::ProcessLifecycle(lifecycle) = &event.payload {
        let detail = lifecycle
            .filename
            .as_deref()
            .map_or_else(String::new, |filename| format!(" file={filename}"));
        println!(
            "seq={} cpu={} uid={} pid={} tid={} comm={} kind={:?}{}",
            event.header.source_sequence,
            event.header.cpu.unwrap_or_default(),
            process.uid,
            process.key.pid,
            process.tid,
            process.comm,
            lifecycle.kind,
            detail
        );
    }
}
