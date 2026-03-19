use std::process::ExitCode;

use clap::{Parser, Subcommand};

use crate::config::schema::{AlertStrategy, AppConfig, Strictness};
use crate::config::store::load_config;
use crate::config::store::resolve_home_dir;
use crate::discovery::{discover_from_builtin_presets, DiscoveryOptions};
use crate::scan::{run_scan, runtime_not_detected_result, ScanResult};
use crate::ui::findings::FindingsUiState;
use crate::wizard::{run_interactive, run_non_interactive, WizardAnswers};

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

    /// Skip prompts and accept the default first-run configuration.
    #[arg(long, global = true)]
    no_interactive: bool,

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

    match cli.command {
        Some(Commands::Scan) => run_scan_command(&cli),
        None => run_root_command(&cli),
    }
}

fn run_root_command(cli: &Cli) -> ExitCode {
    run_scan_flow(cli)
}

fn run_scan_command(cli: &Cli) -> ExitCode {
    run_scan_flow(cli)
}

fn run_scan_flow(cli: &Cli) -> ExitCode {
    let discovery = discover_from_builtin_presets(&DiscoveryOptions::default());

    match load_config() {
        Ok(Some(config)) => {
            if discovery.runtimes.is_empty() {
                return render_runtime_not_detected(cli.json);
            }

            render_scan_output(&config, &discovery, cli.json)
        }
        Ok(None) => {
            if discovery.runtimes.is_empty() {
                return render_runtime_not_detected(cli.json);
            }

            let config = if cli.no_interactive || cli.json {
                match run_non_interactive(&discovery, default_wizard_answers(), &resolve_home_dir())
                {
                    Ok(config) => config,
                    Err(error) => {
                        eprintln!("failed to run first-run setup: {error}");
                        return ExitCode::FAILURE;
                    }
                }
            } else {
                match run_interactive(&discovery) {
                    Ok(config) => config,
                    Err(error) => {
                        eprintln!("failed to run first-run setup: {error}");
                        return ExitCode::FAILURE;
                    }
                }
            };

            render_scan_output(&config, &discovery, cli.json)
        }
        Err(error) => {
            eprintln!("failed to load config: {error}");
            ExitCode::FAILURE
        }
    }
}

fn render_scan_output(
    config: &AppConfig,
    discovery: &crate::discovery::DiscoveryReport,
    json: bool,
) -> ExitCode {
    let result = run_scan(config, discovery);
    render_result_output(result, json)
}

fn render_result_output(result: ScanResult, json: bool) -> ExitCode {
    if json {
        match result.to_json_pretty() {
            Ok(report) => println!("{report}"),
            Err(error) => {
                eprintln!("failed to serialize scan results: {error}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        println!("{}", FindingsUiState::new(result).render());
    }

    ExitCode::SUCCESS
}

fn render_runtime_not_detected(json: bool) -> ExitCode {
    let expected_config_path = resolve_home_dir().join(".openclaw").join("openclaw.json");
    render_result_output(runtime_not_detected_result(&expected_config_path), json)
}

fn default_wizard_answers() -> WizardAnswers {
    WizardAnswers {
        selected_preset: None,
        alert_strategy: AlertStrategy::Desktop,
        strictness: Strictness::Recommended,
    }
}
