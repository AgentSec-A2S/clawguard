use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{Args, Parser, Subcommand};
use serde::Serialize;

use crate::config::schema::{AlertStrategy, AppConfig, Strictness};
use crate::config::store::{clawguard_dir_for_home, load_config, resolve_home_dir};
use crate::daemon::watch::{
    build_watch_plan, NotifyWatchBackend, PollingWatchBackend, WatchBackend, WatchCycleOutcome,
    WatchEventOutcome, WatchIterationOutcome, WatchService, WatchWarning,
};
use crate::discovery::{discover_from_builtin_presets, DiscoveryOptions, DiscoveryReport};
use crate::scan::baseline::collect_restore_payload_candidates;
use crate::scan::{
    collect_scan_evidence, run_scan, runtime_not_detected_result, BaselineArtifact, ScanResult,
};
use crate::state::db::{StateStore, StateStoreConfig};
use crate::state::model::{BaselineRecord, StateWarning};
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
    /// Approve the current runtime state as the baseline used for drift detection.
    Baseline {
        #[command(subcommand)]
        command: BaselineCommands,
    },
    /// Start the foreground watcher loop for the configured runtime.
    Watch(WatchArgs),
}

#[derive(Debug, Subcommand)]
enum BaselineCommands {
    /// Approve the current runtime state as the baseline.
    Approve,
}

#[derive(Debug, Args)]
struct WatchArgs {
    /// Stop after this many loop iterations. `0` means run until interrupted.
    #[arg(long, default_value_t = 0)]
    iterations: u32,

    /// Sleep this long between loop iterations.
    #[arg(long, default_value_t = 1_000)]
    poll_interval_ms: u64,
}

#[derive(Debug, Serialize)]
struct BaselineApproveOutput {
    baseline_count: usize,
    restore_payload_count: usize,
    state_db_path: String,
    warnings: Vec<WarningOutput>,
}

#[derive(Debug, Serialize)]
struct WatchIterationOutput {
    iteration: u32,
    backend: String,
    state_db_path: String,
    cold_boot: Option<WatchCycleOutput>,
    rescanned_event_count: usize,
    debounced_event_count: usize,
    warnings: Vec<WarningOutput>,
}

#[derive(Debug, Serialize)]
struct WatchCycleOutput {
    finding_count: usize,
    alerts_created: usize,
    watch_target_count: usize,
}

#[derive(Debug, Serialize)]
struct WarningOutput {
    path: Option<String>,
    message: String,
}

#[derive(Debug)]
struct BaselineApprovalSummary {
    baseline_count: usize,
    restore_payload_count: usize,
}

pub fn run() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Scan) => run_scan_command(&cli),
        Some(Commands::Baseline {
            command: BaselineCommands::Approve,
        }) => run_baseline_approve_command(&cli),
        Some(Commands::Watch(ref args)) => run_watch_command(&cli, args),
        None => run_root_command(&cli),
    }
}

fn run_root_command(cli: &Cli) -> ExitCode {
    run_scan_flow(cli)
}

fn run_scan_command(cli: &Cli) -> ExitCode {
    run_scan_flow(cli)
}

fn run_baseline_approve_command(cli: &Cli) -> ExitCode {
    let home_dir = resolve_home_dir();
    let config = match load_saved_config_for_operational_command("baseline approve") {
        Ok(config) => config,
        Err(code) => return code,
    };
    let discovery = discover_from_builtin_presets(&DiscoveryOptions::default());
    if !runtime_available_for_operational_command(&discovery, "baseline approve") {
        return ExitCode::FAILURE;
    }

    let mut state = match open_state_store_for_home(&home_dir) {
        Ok(state) => state,
        Err(code) => return code,
    };
    let warning_outputs: Vec<_> = state
        .warnings
        .iter()
        .map(warning_output_from_state)
        .collect();
    let evidence = collect_scan_evidence(&config, &discovery);
    let approved_at_unix_ms = now_unix_ms();
    let summary = match approve_baselines_from_artifacts(
        &mut state.store,
        approved_at_unix_ms,
        &evidence.artifacts,
    ) {
        Ok(summary) => summary,
        Err(error) => {
            eprintln!("failed to approve baseline state: {error}");
            return ExitCode::FAILURE;
        }
    };

    let output = BaselineApproveOutput {
        baseline_count: summary.baseline_count,
        restore_payload_count: summary.restore_payload_count,
        state_db_path: state.store.path().display().to_string(),
        warnings: warning_outputs,
    };

    render_baseline_approve_output(cli.json, &output)
}

fn run_watch_command(cli: &Cli, args: &WatchArgs) -> ExitCode {
    let home_dir = resolve_home_dir();
    let config = match load_saved_config_for_operational_command("watch") {
        Ok(config) => config,
        Err(code) => return code,
    };
    let discovery = discover_from_builtin_presets(&DiscoveryOptions::default());
    if !runtime_available_for_operational_command(&discovery, "watch") {
        return ExitCode::FAILURE;
    }

    let plan = match build_watch_plan(&discovery) {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("failed to build watch plan: {error}");
            return ExitCode::FAILURE;
        }
    };
    let state = match open_state_store_for_home(&home_dir) {
        Ok(state) => state,
        Err(code) => return code,
    };
    let (mut backend, backend_label, backend_warnings) = match create_cli_watch_backend(&plan) {
        Ok(backend) => backend,
        Err(error) => {
            eprintln!("failed to start watch backend: {error}");
            return ExitCode::FAILURE;
        }
    };
    let mut pending_warning_outputs: Vec<_> = state
        .warnings
        .iter()
        .map(warning_output_from_state)
        .collect();
    match state.store.list_baselines() {
        Ok(baselines) if baselines.is_empty() => pending_warning_outputs.push(WarningOutput {
            path: None,
            message: "no approved baselines exist yet; run `clawguard baseline approve` before treating drift findings as a trusted delta".to_string(),
        }),
        Ok(_) => {}
        Err(error) => {
            eprintln!("failed to inspect approved baselines: {error}");
            return ExitCode::FAILURE;
        }
    }
    pending_warning_outputs.extend(backend_warnings.iter().map(warning_output_from_watch));

    let mut service = WatchService::new(config, DiscoveryOptions::default(), state.store);
    let state_db_path = service.state().path().display().to_string();
    let max_iterations = if args.iterations == 0 {
        None
    } else {
        Some(args.iterations)
    };
    let mut completed_iterations = 0;

    loop {
        if let Some(limit) = max_iterations {
            if completed_iterations >= limit {
                break;
            }
        }

        completed_iterations += 1;
        let outcome = match service.run_iteration(backend.as_mut(), now_unix_ms()) {
            Ok(outcome) => outcome,
            Err(error) => {
                eprintln!("watch iteration failed: {error}");
                return ExitCode::FAILURE;
            }
        };
        let mut warnings = std::mem::take(&mut pending_warning_outputs);
        warnings.extend(outcome.warnings.iter().map(warning_output_from_watch));
        let output = watch_iteration_output(
            completed_iterations,
            &backend_label,
            &state_db_path,
            &outcome,
            warnings,
        );

        if let Err(error) = render_watch_iteration_output(cli.json, &output) {
            eprintln!("failed to render watch output: {error}");
            return ExitCode::FAILURE;
        }

        if max_iterations.is_some_and(|limit| completed_iterations >= limit) {
            break;
        }

        thread::sleep(Duration::from_millis(args.poll_interval_ms));
    }

    ExitCode::SUCCESS
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

fn render_baseline_approve_output(json: bool, output: &BaselineApproveOutput) -> ExitCode {
    if json {
        match serde_json::to_string_pretty(output) {
            Ok(serialized) => println!("{serialized}"),
            Err(error) => {
                eprintln!("failed to serialize baseline approval output: {error}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        for warning in &output.warnings {
            eprintln!("warning: {}", warning.message);
        }
        println!(
            "approved {} baseline artifacts into {}",
            output.baseline_count, output.state_db_path
        );
        println!(
            "captured {} restorable policy payloads",
            output.restore_payload_count
        );
    }

    ExitCode::SUCCESS
}

fn render_watch_iteration_output(json: bool, output: &WatchIterationOutput) -> Result<(), String> {
    if json {
        let serialized = serde_json::to_string(output)
            .map_err(|error| format!("failed to serialize watch output: {error}"))?;
        println!("{serialized}");
        return Ok(());
    }

    for warning in &output.warnings {
        eprintln!("warning: {}", warning.message);
    }

    println!(
        "watch iteration {} via {} backend",
        output.iteration, output.backend
    );
    if let Some(cold_boot) = &output.cold_boot {
        println!(
            "cold boot recorded {} findings, created {} alerts, and planned {} watch targets",
            cold_boot.finding_count, cold_boot.alerts_created, cold_boot.watch_target_count
        );
    }
    println!(
        "event rescans: {}, debounced events: {}",
        output.rescanned_event_count, output.debounced_event_count
    );

    Ok(())
}

fn default_wizard_answers() -> WizardAnswers {
    WizardAnswers {
        selected_preset: None,
        alert_strategy: AlertStrategy::Desktop,
        strictness: Strictness::Recommended,
    }
}

fn load_saved_config_for_operational_command(command_name: &str) -> Result<AppConfig, ExitCode> {
    match load_config() {
        Ok(Some(config)) => Ok(config),
        Ok(None) => {
            eprintln!(
                "`clawguard {command_name}` requires saved configuration; run `clawguard scan` first"
            );
            Err(ExitCode::FAILURE)
        }
        Err(error) => {
            eprintln!("failed to load config: {error}");
            Err(ExitCode::FAILURE)
        }
    }
}

fn runtime_available_for_operational_command(
    discovery: &DiscoveryReport,
    command_name: &str,
) -> bool {
    if !discovery.runtimes.is_empty() {
        return true;
    }

    eprintln!(
        "`clawguard {command_name}` requires a detected supported runtime; rerun it after OpenClaw is available"
    );
    false
}

fn open_state_store_for_home(
    home_dir: &Path,
) -> Result<crate::state::db::StateOpenResult, ExitCode> {
    StateStore::open(StateStoreConfig::for_path(state_db_path_for_home(home_dir))).map_err(
        |error| {
            eprintln!("failed to open state database: {error}");
            ExitCode::FAILURE
        },
    )
}

fn state_db_path_for_home(home_dir: &Path) -> PathBuf {
    clawguard_dir_for_home(home_dir).join("state.db")
}

fn approve_baselines_from_artifacts(
    store: &mut StateStore,
    approved_at_unix_ms: u64,
    artifacts: &[BaselineArtifact],
) -> Result<BaselineApprovalSummary, crate::state::db::StateStoreError> {
    let baselines: Vec<_> = artifacts
        .iter()
        .map(|artifact| BaselineRecord {
            path: artifact.path.clone(),
            sha256: artifact.sha256.clone(),
            approved_at_unix_ms,
            source_label: artifact.source_label.clone(),
        })
        .collect();
    let source_labels = approval_source_labels(store, &baselines)?;
    let baselines_by_source = baselines_by_source(&baselines);

    for source_label in source_labels {
        let source_baselines = baselines_by_source
            .get(source_label.as_str())
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        store.replace_baselines_for_source(&source_label, source_baselines)?;
    }

    let restore_payloads = collect_restore_payload_candidates(approved_at_unix_ms, artifacts);
    store.replace_restore_payloads_for_source("config", &restore_payloads)?;

    Ok(BaselineApprovalSummary {
        baseline_count: baselines.len(),
        restore_payload_count: restore_payloads.len(),
    })
}

fn approval_source_labels(
    store: &StateStore,
    baselines: &[BaselineRecord],
) -> Result<BTreeSet<String>, crate::state::db::StateStoreError> {
    let mut source_labels = BTreeSet::from([
        "config".to_string(),
        "skills".to_string(),
        "mcp".to_string(),
        "env".to_string(),
    ]);
    source_labels.extend(
        baselines
            .iter()
            .map(|baseline| baseline.source_label.clone()),
    );
    source_labels.extend(
        store
            .list_baselines()?
            .into_iter()
            .map(|baseline| baseline.source_label),
    );

    Ok(source_labels)
}

fn baselines_by_source(baselines: &[BaselineRecord]) -> BTreeMap<&str, Vec<BaselineRecord>> {
    let mut grouped = BTreeMap::new();

    for baseline in baselines {
        grouped
            .entry(baseline.source_label.as_str())
            .or_insert_with(Vec::new)
            .push(baseline.clone());
    }

    grouped
}

fn create_cli_watch_backend(
    plan: &crate::daemon::watch::WatchPlan,
) -> Result<(Box<dyn WatchBackend>, String, Vec<WatchWarning>), String> {
    create_cli_watch_backend_from_notify_result(plan, NotifyWatchBackend::new(plan))
}

fn create_cli_watch_backend_from_notify_result(
    plan: &crate::daemon::watch::WatchPlan,
    notify_result: Result<NotifyWatchBackend, crate::daemon::watch::WatchBackendError>,
) -> Result<(Box<dyn WatchBackend>, String, Vec<WatchWarning>), String> {
    match notify_result {
        Ok(backend) => Ok((Box::new(backend), "notify".to_string(), Vec::new())),
        Err(error) => Ok((
            Box::new(PollingWatchBackend::new(plan)),
            "polling".to_string(),
            vec![WatchWarning {
                path: None,
                message: format!("notify backend unavailable ({error}); falling back to polling"),
            }],
        )),
    }
}

fn watch_iteration_output(
    iteration: u32,
    backend: &str,
    state_db_path: &str,
    outcome: &WatchIterationOutcome,
    warnings: Vec<WarningOutput>,
) -> WatchIterationOutput {
    let rescanned_event_count = outcome
        .event_outcomes
        .iter()
        .filter(|event| matches!(event, WatchEventOutcome::Rescanned(_)))
        .count();
    let debounced_event_count = outcome
        .event_outcomes
        .iter()
        .filter(|event| matches!(event, WatchEventOutcome::Debounced))
        .count();

    WatchIterationOutput {
        iteration,
        backend: backend.to_string(),
        state_db_path: state_db_path.to_string(),
        cold_boot: outcome.cold_boot.as_ref().map(watch_cycle_output),
        rescanned_event_count,
        debounced_event_count,
        warnings,
    }
}

fn watch_cycle_output(outcome: &WatchCycleOutcome) -> WatchCycleOutput {
    WatchCycleOutput {
        finding_count: outcome.snapshot.findings.len(),
        alerts_created: outcome.alerts_created.len(),
        watch_target_count: outcome.watch_plan.targets.len(),
    }
}

fn warning_output_from_state(warning: &StateWarning) -> WarningOutput {
    WarningOutput {
        path: warning.path.as_ref().map(|path| path.display().to_string()),
        message: warning.message.clone(),
    }
}

fn warning_output_from_watch(warning: &WatchWarning) -> WarningOutput {
    WarningOutput {
        path: warning.path.as_ref().map(|path| path.display().to_string()),
        message: warning.message.clone(),
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::daemon::watch::{WatchBackendError, WatchKind, WatchPlan, WatchTarget};

    use super::create_cli_watch_backend_from_notify_result;

    #[test]
    fn cli_watch_backend_falls_back_to_polling_when_notify_creation_fails() {
        let plan = WatchPlan {
            targets: vec![WatchTarget {
                logical_path: PathBuf::from("/tmp/.openclaw/openclaw.json"),
                watch_root: PathBuf::from("/tmp/.openclaw"),
                watch_kind: WatchKind::Directory,
                source_label: "config".to_string(),
                excluded_subpaths: Vec::new(),
            }],
        };

        let (_, backend_label, warnings) = create_cli_watch_backend_from_notify_result(
            &plan,
            Err(WatchBackendError::Create(
                "notify intentionally unavailable for test".to_string(),
            )),
        )
        .expect("fallback backend should be created");

        assert_eq!(backend_label, "polling");
        assert_eq!(warnings.len(), 1);
        assert!(
            warnings[0].message.contains("falling back to polling"),
            "fallback warning should explain why polling was selected"
        );
    }
}
