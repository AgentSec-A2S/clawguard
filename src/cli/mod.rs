use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{Args, Parser, Subcommand};
use serde::Serialize;

use crate::config::schema::{AlertStrategy, AppConfig, Strictness};
use crate::config::store::{clawguard_dir_for_home, load_config, resolve_home_dir};
use crate::daemon::recovery::restore_policy_file;
use crate::daemon::watch::{
    build_watch_plan, NotifyWatchBackend, PollingWatchBackend, WatchBackend, WatchCycleOutcome,
    WatchEventOutcome, WatchIterationOutcome, WatchService, WatchWarning,
};
use crate::discovery::{discover_from_builtin_presets, DiscoveryOptions, DiscoveryReport};
use crate::notify::{
    deliver_daily_digest_if_due_with_services, deliver_pending_alerts_for_route_with_services,
    platform::{CommandDesktopNotifier, PlatformSnapshot},
    webhook::UreqWebhookTransport,
    DailyDigestDeliveryReport, NotificationServices, PendingAlertDeliveryReport,
};
use crate::scan::baseline::{
    collect_restore_payload_candidates, restore_target_kind_for_path, RestoreTargetKind,
};
use crate::scan::{
    collect_scan_evidence, run_scan, runtime_not_detected_result, BaselineArtifact, ScanResult,
    ScanSummary, Severity,
};
use crate::state::db::{StateStore, StateStoreConfig};
use crate::state::model::{AlertStatus, BaselineRecord, RestorePayloadRecord, StateWarning};
use crate::ui::{
    alerts::{AlertListItem, AlertsView},
    findings::FindingsUiState,
    status::{StatusAlertItem, StatusSnapshotSummary, StatusView},
};
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
    /// Show the persisted runtime status view.
    Status,
    /// Approve the current runtime state as the baseline used for drift detection.
    Baseline {
        #[command(subcommand)]
        command: BaselineCommands,
    },
    /// Show persisted alerts or acknowledge one alert.
    Alerts {
        #[command(subcommand)]
        command: Option<AlertsCommands>,
    },
    /// Restore one approved trust target from the saved baseline payload.
    Trust(TrustArgs),
    /// Start the foreground watcher loop for the configured runtime.
    Watch(WatchArgs),
}

#[derive(Debug, Subcommand)]
enum BaselineCommands {
    /// Approve the current runtime state as the baseline.
    Approve,
}

#[derive(Debug, Subcommand)]
enum AlertsCommands {
    /// Acknowledge one persisted alert without deleting its history.
    Ignore { alert_id: String },
}

#[derive(Debug, Args)]
struct TrustArgs {
    /// The allowlisted trust target name, such as `openclaw-config`.
    target: String,
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
    alerts_notified: usize,
    digest_delivered: bool,
    notification_logs: Vec<String>,
    warnings: Vec<WarningOutput>,
}

#[derive(Debug, Serialize)]
struct WatchCycleOutput {
    finding_count: usize,
    alerts_created: usize,
    watch_target_count: usize,
}

#[derive(Debug, Serialize)]
struct StatusOutput {
    mode: &'static str,
    open_alert_count: usize,
    acknowledged_alert_count: usize,
    latest_snapshot_summary: Option<ScanSummary>,
    baseline_count: usize,
    trust_targets: Vec<String>,
    warnings: Vec<WarningOutput>,
}

#[derive(Debug, Serialize)]
struct AlertsOutput {
    mode: &'static str,
    alerts: Vec<AlertSummaryOutput>,
    warnings: Vec<WarningOutput>,
}

#[derive(Debug, Serialize)]
struct AlertSummaryOutput {
    alert_id: String,
    status: AlertStatus,
    severity: Severity,
    path: String,
    created_at_unix_ms: u64,
}

#[derive(Debug, Serialize)]
struct AlertIgnoreOutput {
    alert_id: String,
    previous_status: AlertStatus,
    new_status: AlertStatus,
    warnings: Vec<WarningOutput>,
}

#[derive(Debug, Serialize)]
struct TrustOutput {
    trust_target: String,
    restored_path: String,
    resolved_alert_count: usize,
    warnings: Vec<WarningOutput>,
}

#[derive(Debug, Clone, Serialize)]
struct WarningOutput {
    path: Option<String>,
    message: String,
}

#[derive(Debug)]
struct BaselineApprovalSummary {
    baseline_count: usize,
    restore_payload_count: usize,
}

const RECENT_ALERT_LIMIT: usize = 50;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrustTarget {
    OpenClawConfig,
    ExecApprovals,
}

impl TrustTarget {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "openclaw-config" => Some(Self::OpenClawConfig),
            "exec-approvals" => Some(Self::ExecApprovals),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::OpenClawConfig => "openclaw-config",
            Self::ExecApprovals => "exec-approvals",
        }
    }
}

pub fn run() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Scan) => run_scan_command(&cli),
        Some(Commands::Status) => run_status_command(&cli),
        Some(Commands::Baseline {
            command: BaselineCommands::Approve,
        }) => run_baseline_approve_command(&cli),
        Some(Commands::Alerts { command: None }) => run_alerts_command(&cli),
        Some(Commands::Alerts {
            command: Some(AlertsCommands::Ignore { ref alert_id }),
        }) => run_alert_ignore_command(&cli, alert_id),
        Some(Commands::Trust(ref args)) => run_trust_command(&cli, args),
        Some(Commands::Watch(ref args)) => run_watch_command(&cli, args),
        None => run_root_command(&cli),
    }
}

fn run_root_command(cli: &Cli) -> ExitCode {
    let discovery = discover_from_builtin_presets(&DiscoveryOptions::default());

    match load_config() {
        Ok(Some(config)) => {
            if discovery.runtimes.is_empty() {
                return render_runtime_not_detected(cli.json);
            }

            if cli.json {
                return render_scan_output(&config, &discovery, true);
            }

            run_status_command_with_home(cli, &resolve_home_dir())
        }
        Ok(None) => {
            if discovery.runtimes.is_empty() {
                return render_runtime_not_detected(cli.json);
            }

            run_scan_flow(cli)
        }
        Err(error) => {
            eprintln!("failed to load config: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_scan_command(cli: &Cli) -> ExitCode {
    run_scan_flow(cli)
}

fn run_status_command(cli: &Cli) -> ExitCode {
    if load_saved_config_for_operational_command("status").is_err() {
        return ExitCode::FAILURE;
    }
    let discovery = discover_from_builtin_presets(&DiscoveryOptions::default());
    if !runtime_available_for_operational_command(&discovery, "status") {
        return ExitCode::FAILURE;
    }

    run_status_command_with_home(cli, &resolve_home_dir())
}

fn run_status_command_with_home(cli: &Cli, home_dir: &Path) -> ExitCode {
    let state = match open_state_store_for_home(home_dir) {
        Ok(state) => state,
        Err(code) => return code,
    };
    let warnings: Vec<_> = state
        .warnings
        .iter()
        .map(warning_output_from_state)
        .collect();
    let open_alerts = match state.store.list_open_alerts() {
        Ok(alerts) => alerts,
        Err(error) => {
            eprintln!("failed to load open alerts: {error}");
            return ExitCode::FAILURE;
        }
    };
    let acknowledged_alert_count = match state.store.count_acknowledged_alerts() {
        Ok(count) => count,
        Err(error) => {
            eprintln!("failed to count acknowledged alerts: {error}");
            return ExitCode::FAILURE;
        }
    };
    let latest_snapshot_summary = match state.store.latest_scan_snapshot() {
        Ok(snapshot) => snapshot.map(|snapshot| snapshot.summary),
        Err(error) => {
            eprintln!("failed to load latest scan snapshot: {error}");
            return ExitCode::FAILURE;
        }
    };
    let baseline_count = match state.store.list_baselines() {
        Ok(baselines) => baselines.len(),
        Err(error) => {
            eprintln!("failed to load approved baselines: {error}");
            return ExitCode::FAILURE;
        }
    };
    let trust_targets = match state.store.list_restore_payloads() {
        Ok(payloads) => available_trust_targets(&payloads),
        Err(error) => {
            eprintln!("failed to enumerate approved restore payloads: {error}");
            return ExitCode::FAILURE;
        }
    };
    let view = StatusView {
        open_alerts: open_alerts
            .iter()
            .map(|alert| StatusAlertItem {
                alert_id: alert.alert_id.clone(),
                severity: alert.finding.severity,
                path: alert.finding.path.clone(),
            })
            .collect(),
        acknowledged_alert_count,
        latest_snapshot_summary: latest_snapshot_summary.clone().map(|summary| {
            StatusSnapshotSummary {
                total_findings: summary.total_findings,
                highest_severity: summary.highest_severity,
            }
        }),
        baseline_count,
        trust_targets: trust_targets.clone(),
        command_hints: status_command_hints(
            baseline_count,
            latest_snapshot_summary.is_some(),
            !open_alerts.is_empty(),
            &trust_targets,
        ),
    };
    let output = StatusOutput {
        mode: "status",
        open_alert_count: open_alerts.len(),
        acknowledged_alert_count,
        latest_snapshot_summary,
        baseline_count,
        trust_targets,
        warnings,
    };

    render_status_output(cli.json, &output, &view)
}

fn run_alerts_command(cli: &Cli) -> ExitCode {
    if load_saved_config_for_operational_command("alerts").is_err() {
        return ExitCode::FAILURE;
    }

    let state = match open_state_store_for_home(&resolve_home_dir()) {
        Ok(state) => state,
        Err(code) => return code,
    };
    let warnings: Vec<_> = state
        .warnings
        .iter()
        .map(warning_output_from_state)
        .collect();
    let alerts = match state.store.list_recent_alerts(RECENT_ALERT_LIMIT) {
        Ok(alerts) => alerts,
        Err(error) => {
            eprintln!("failed to load recent alerts: {error}");
            return ExitCode::FAILURE;
        }
    };
    let view = AlertsView {
        alerts: alerts
            .iter()
            .map(|alert| AlertListItem {
                alert_id: alert.alert_id.clone(),
                status: alert.status,
                severity: alert.finding.severity,
                path: alert.finding.path.clone(),
            })
            .collect(),
        command_hints: vec![
            "clawguard alerts ignore <alert-id>".to_string(),
            "clawguard status".to_string(),
        ],
    };
    let output = AlertsOutput {
        mode: "alerts",
        alerts: alerts
            .iter()
            .map(|alert| AlertSummaryOutput {
                alert_id: alert.alert_id.clone(),
                status: alert.status,
                severity: alert.finding.severity,
                path: alert.finding.path.clone(),
                created_at_unix_ms: alert.created_at_unix_ms,
            })
            .collect(),
        warnings: warnings.clone(),
    };

    render_alerts_output(cli.json, &output, &view, &warnings)
}

fn run_alert_ignore_command(cli: &Cli, alert_id: &str) -> ExitCode {
    if load_saved_config_for_operational_command("alerts ignore").is_err() {
        return ExitCode::FAILURE;
    }

    let mut state = match open_state_store_for_home(&resolve_home_dir()) {
        Ok(state) => state,
        Err(code) => return code,
    };
    let warnings: Vec<_> = state
        .warnings
        .iter()
        .map(warning_output_from_state)
        .collect();
    let existing_alert = match state.store.alert_by_id(alert_id) {
        Ok(alert) => alert,
        Err(error) => {
            eprintln!("failed to load alert: {error}");
            return ExitCode::FAILURE;
        }
    };
    let Some(existing_alert) = existing_alert else {
        eprintln!("no stored alert exists with id {alert_id}");
        return ExitCode::FAILURE;
    };
    if existing_alert.status == AlertStatus::Resolved {
        eprintln!("alert {alert_id} is already resolved");
        return ExitCode::FAILURE;
    }
    if let Err(error) = state
        .store
        .update_alert_status(alert_id, AlertStatus::Acknowledged)
    {
        eprintln!("failed to update alert status: {error}");
        return ExitCode::FAILURE;
    }

    let output = AlertIgnoreOutput {
        alert_id: alert_id.to_string(),
        previous_status: existing_alert.status,
        new_status: AlertStatus::Acknowledged,
        warnings: warnings.clone(),
    };

    render_alert_ignore_output(cli.json, &output, &warnings)
}

fn run_trust_command(cli: &Cli, args: &TrustArgs) -> ExitCode {
    if load_saved_config_for_operational_command("trust").is_err() {
        return ExitCode::FAILURE;
    }
    let discovery = discover_from_builtin_presets(&DiscoveryOptions::default());
    if !runtime_available_for_operational_command(&discovery, "trust") {
        return ExitCode::FAILURE;
    }

    let Some(target) = TrustTarget::parse(&args.target) else {
        eprintln!(
            "unknown trust target `{}`; supported trust targets: openclaw-config, exec-approvals",
            args.target
        );
        return ExitCode::FAILURE;
    };

    let mut state = match open_state_store_for_home(&resolve_home_dir()) {
        Ok(state) => state,
        Err(code) => return code,
    };
    let warnings: Vec<_> = state
        .warnings
        .iter()
        .map(warning_output_from_state)
        .collect();
    let payloads = match state.store.list_restore_payloads() {
        Ok(payloads) => payloads,
        Err(error) => {
            eprintln!("failed to enumerate approved restore payloads: {error}");
            return ExitCode::FAILURE;
        }
    };
    let Some(restored_path) = restore_path_for_target(&payloads, target) else {
        eprintln!("no approved restore payload exists for {}", target.as_str());
        return ExitCode::FAILURE;
    };

    if let Err(error) = restore_policy_file(&state.store, Path::new(&restored_path)) {
        eprintln!("failed to trust {}: {error}", target.as_str());
        return ExitCode::FAILURE;
    }

    let matching_alert_ids: Vec<_> = match state.store.list_unresolved_alerts() {
        Ok(alerts) => alerts
            .into_iter()
            .filter(|alert| {
                alert.finding.category == crate::scan::FindingCategory::Drift
                    && alert.finding.path == restored_path
            })
            .map(|alert| alert.alert_id)
            .collect(),
        Err(error) => {
            eprintln!("failed to load unresolved alerts: {error}");
            return ExitCode::FAILURE;
        }
    };
    for alert_id in &matching_alert_ids {
        if let Err(error) = state
            .store
            .update_alert_status(alert_id, AlertStatus::Resolved)
        {
            eprintln!("failed to resolve restored drift alert {alert_id}: {error}");
            return ExitCode::FAILURE;
        }
    }

    let output = TrustOutput {
        trust_target: target.as_str().to_string(),
        restored_path,
        resolved_alert_count: matching_alert_ids.len(),
        warnings,
    };

    render_trust_output(cli.json, &output)
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

    let mut service = WatchService::new(config.clone(), DiscoveryOptions::default(), state.store);
    let platform = PlatformSnapshot::detect();
    let desktop_notifier = CommandDesktopNotifier;
    let webhook_transport = UreqWebhookTransport::default();
    let notification_services = NotificationServices {
        platform,
        desktop_notifier: &desktop_notifier,
        webhook_transport: &webhook_transport,
    };
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
        let alert_delivery = match deliver_pending_alerts_for_route_with_services(
            service.state_mut(),
            &config,
            now_unix_ms(),
            &notification_services,
        ) {
            Ok(report) => report,
            Err(error) => {
                warnings.push(warning_output_from_message(&format!(
                    "pending alert delivery state error: {error}"
                )));
                error.pending_report().cloned().unwrap_or_default()
            }
        };
        let digest_delivery = match deliver_daily_digest_if_due_with_services(
            service.state_mut(),
            &config,
            now_unix_ms(),
            &notification_services,
        ) {
            Ok(report) => report,
            Err(error) => {
                warnings.push(warning_output_from_message(&format!(
                    "daily digest delivery state error: {error}"
                )));
                error
                    .daily_digest_report()
                    .cloned()
                    .unwrap_or(DailyDigestDeliveryReport {
                        handled: false,
                        suppressed: true,
                        alert_count: 0,
                        warnings: Vec::new(),
                        log_line: None,
                    })
            }
        };
        warnings.extend(
            alert_delivery
                .warnings
                .iter()
                .map(|warning| warning_output_from_message(warning)),
        );
        warnings.extend(
            digest_delivery
                .warnings
                .iter()
                .map(|warning| warning_output_from_message(warning)),
        );
        let output = watch_iteration_output(
            completed_iterations,
            &backend_label,
            &state_db_path,
            &outcome,
            &alert_delivery,
            &digest_delivery,
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

fn render_status_output(json: bool, output: &StatusOutput, view: &StatusView) -> ExitCode {
    if json {
        match serde_json::to_string_pretty(output) {
            Ok(serialized) => println!("{serialized}"),
            Err(error) => {
                eprintln!("failed to serialize status output: {error}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        for warning in &output.warnings {
            eprintln!("warning: {}", warning.message);
        }
        println!("{}", view.render());
    }

    ExitCode::SUCCESS
}

fn render_alerts_output(
    json: bool,
    output: &AlertsOutput,
    view: &AlertsView,
    warnings: &[WarningOutput],
) -> ExitCode {
    if json {
        match serde_json::to_string_pretty(output) {
            Ok(serialized) => println!("{serialized}"),
            Err(error) => {
                eprintln!("failed to serialize alerts output: {error}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        for warning in warnings {
            eprintln!("warning: {}", warning.message);
        }
        println!("{}", view.render());
    }

    ExitCode::SUCCESS
}

fn render_alert_ignore_output(
    json: bool,
    output: &AlertIgnoreOutput,
    warnings: &[WarningOutput],
) -> ExitCode {
    if json {
        match serde_json::to_string_pretty(output) {
            Ok(serialized) => println!("{serialized}"),
            Err(error) => {
                eprintln!("failed to serialize alert update output: {error}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        for warning in warnings {
            eprintln!("warning: {}", warning.message);
        }
        println!(
            "acknowledged alert {} (previously {})",
            output.alert_id,
            output.previous_status.as_str()
        );
    }

    ExitCode::SUCCESS
}

fn render_trust_output(json: bool, output: &TrustOutput) -> ExitCode {
    if json {
        match serde_json::to_string_pretty(output) {
            Ok(serialized) => println!("{serialized}"),
            Err(error) => {
                eprintln!("failed to serialize trust output: {error}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        for warning in &output.warnings {
            eprintln!("warning: {}", warning.message);
        }
        println!(
            "restored approved payload for {} to {}",
            output.trust_target, output.restored_path
        );
        println!(
            "resolved {} matching drift alerts",
            output.resolved_alert_count
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
    for log_line in &output.notification_logs {
        println!("{log_line}");
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
    println!(
        "notifications handled: {}, daily digest delivered: {}",
        output.alerts_notified, output.digest_delivered
    );

    Ok(())
}

fn default_wizard_answers() -> WizardAnswers {
    WizardAnswers {
        selected_preset: None,
        alert_strategy: AlertStrategy::Desktop,
        webhook_url: None,
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

fn status_command_hints(
    baseline_count: usize,
    has_snapshot: bool,
    has_open_alerts: bool,
    trust_targets: &[String],
) -> Vec<String> {
    let mut hints = Vec::new();

    push_hint(&mut hints, "clawguard scan");
    if baseline_count == 0 {
        push_hint(&mut hints, "clawguard baseline approve");
    }
    if !has_snapshot || baseline_count == 0 {
        push_hint(&mut hints, "clawguard watch");
    }
    push_hint(&mut hints, "clawguard alerts");
    if has_open_alerts {
        push_hint(&mut hints, "clawguard alerts ignore <alert-id>");
    }
    for target in trust_targets {
        push_hint(&mut hints, &format!("clawguard trust {target}"));
    }

    hints
}

fn push_hint(hints: &mut Vec<String>, hint: &str) {
    if hints.iter().any(|existing| existing == hint) {
        return;
    }

    hints.push(hint.to_string());
}

fn available_trust_targets(payloads: &[RestorePayloadRecord]) -> Vec<String> {
    payloads
        .iter()
        .filter_map(|payload| {
            restore_target_kind_for_path(&payload.path, &payload.source_label).map(
                |kind| match kind {
                    RestoreTargetKind::OpenClawConfig => TrustTarget::OpenClawConfig.as_str(),
                    RestoreTargetKind::ExecApprovals => TrustTarget::ExecApprovals.as_str(),
                },
            )
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(str::to_string)
        .collect()
}

fn restore_path_for_target(
    payloads: &[RestorePayloadRecord],
    target: TrustTarget,
) -> Option<String> {
    payloads
        .iter()
        .find(|payload| {
            matches!(
                (
                    target,
                    restore_target_kind_for_path(&payload.path, &payload.source_label)
                ),
                (
                    TrustTarget::OpenClawConfig,
                    Some(RestoreTargetKind::OpenClawConfig)
                ) | (
                    TrustTarget::ExecApprovals,
                    Some(RestoreTargetKind::ExecApprovals)
                )
            )
        })
        .map(|payload| payload.path.clone())
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
    alert_delivery: &PendingAlertDeliveryReport,
    digest_delivery: &DailyDigestDeliveryReport,
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
    let mut notification_logs = alert_delivery.log_lines.clone();
    if let Some(log_line) = &digest_delivery.log_line {
        notification_logs.push(log_line.clone());
    }

    WatchIterationOutput {
        iteration,
        backend: backend.to_string(),
        state_db_path: state_db_path.to_string(),
        cold_boot: outcome.cold_boot.as_ref().map(watch_cycle_output),
        rescanned_event_count,
        debounced_event_count,
        alerts_notified: alert_delivery.delivered_count,
        digest_delivered: digest_delivery.handled,
        notification_logs,
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

fn warning_output_from_message(message: &str) -> WarningOutput {
    WarningOutput {
        path: None,
        message: message.to_string(),
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
