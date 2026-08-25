//! Repository architecture validation tasks.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

const MAX_BPF_C_LINES: usize = 500;

#[derive(Debug, Parser)]
#[command(name = "xtask", about = "KernSight repository tasks")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validate architectural directory and BPF source-size invariants.
    Architecture,
}

fn main() -> Result<()> {
    let args = Args::parse();
    match args.command {
        Command::Architecture => validate_architecture(),
    }
}

fn validate_architecture() -> Result<()> {
    let root = workspace_root()?;
    for required in [
        "crates/ksight-model",
        "crates/ksight-abi",
        "crates/ksight-protocol",
        "crates/ksight-core",
        "crates/ksight-agent",
        "crates/ksight-cli",
        "bpf/include",
        "bpf/programs/process",
        "bpf/programs/file",
        "bpf/programs/memory",
        "bpf/programs/network",
        "bpf/programs/binder",
        "bpf/programs/integrity",
        "android/init",
        "android/sepolicy",
        "schemas/binder",
    ] {
        let path = root.join(required);
        if !path.exists() {
            bail!("required architecture path is missing: {}", path.display());
        }
    }

    let mut files = Vec::new();
    collect_files(&root.join("bpf/programs"), &mut files)?;
    for file in files {
        if file.extension().is_some_and(|extension| extension == "c") {
            let source = fs::read_to_string(&file)
                .with_context(|| format!("read BPF source {}", file.display()))?;
            let lines = source.lines().count();
            if lines > MAX_BPF_C_LINES {
                bail!(
                    "BPF source {} has {lines} lines; split it before exceeding {MAX_BPF_C_LINES}",
                    file.display()
                );
            }
        }
    }

    println!("architecture checks passed");
    Ok(())
}

fn workspace_root() -> Result<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .context("xtask must live directly under the workspace root")
}

fn collect_files(directory: &Path, output: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(directory)
        .with_context(|| format!("read architecture directory {}", directory.display()))?
    {
        let path = entry?.path();
        if path.is_dir() {
            collect_files(&path, output)?;
        } else {
            output.push(path);
        }
    }
    Ok(())
}
