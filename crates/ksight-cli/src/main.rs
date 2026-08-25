//! `ksightctl` command-line client entry point.

use clap::{Parser, Subcommand};
use ksight_model::CURRENT_SCHEMA;
use ksight_protocol::CURRENT_PROTOCOL;

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
}

fn main() {
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
    }
}
