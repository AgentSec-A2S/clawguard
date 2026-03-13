use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "clawguard",
    version,
    about = "Security scanner for agent runtimes",
    long_about = None
)]
pub struct Cli {
    /// Output results as JSON.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Run a security scan.
    Scan,
}

pub fn run() -> ExitCode {
    let cli = Cli::parse();
    let _json = cli.json;

    match cli.command {
        Some(Commands::Scan) => {
            println!("scan not implemented yet");
            ExitCode::SUCCESS
        }
        None => {
            println!("ClawGuard is not configured yet. Run `clawguard scan` to start.");
            ExitCode::SUCCESS
        }
    }
}
