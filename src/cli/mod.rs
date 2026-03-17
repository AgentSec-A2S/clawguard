use std::process::ExitCode;

use clap::{Parser, Subcommand};

use crate::config::store::load_config;
use crate::discovery::{discover_from_builtin_presets, DiscoveryOptions};
use crate::wizard::run_interactive;

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
        None => run_root_command(),
    }
}

fn run_root_command() -> ExitCode {
    match load_config() {
        Ok(Some(_)) => {
            println!("ClawGuard is configured. Run `clawguard scan` to start.");
            ExitCode::SUCCESS
        }
        Ok(None) => {
            let discovery = discover_from_builtin_presets(&DiscoveryOptions::default());
            if discovery.runtimes.is_empty() {
                println!("ClawGuard is not configured yet. Install OpenClaw or run `clawguard scan` once a supported runtime exists.");
                return ExitCode::SUCCESS;
            }

            match run_interactive(&discovery) {
                Ok(_) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("failed to run first-run setup: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        Err(error) => {
            eprintln!("failed to load config: {error}");
            ExitCode::FAILURE
        }
    }
}
