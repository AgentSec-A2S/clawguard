use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{Args, Parser, Subcommand};
use serde::Serialize;

use crate::config::schema::{AlertStrategy, AppConfig, Strictness};
use crate::config::store::{
    clawguard_dir_for_home, load_config, resolve_home_dir, save_config_for_home,
    validate_webhook_url,
};
use crate::daemon::recovery::restore_policy_file;
use crate::daemon::watch::{
    build_watch_plan, NotifyWatchBackend, PollingWatchBackend, WatchBackend, WatchCycleOutcome,
    WatchEventOutcome, WatchIterationOutcome, WatchService, WatchWarning,
};
use crate::discovery::{discover_from_builtin_presets, DiscoveryOptions, DiscoveryReport};
use crate::notify::{
    deliver_daily_digest_if_due_with_services, deliver_pending_alerts_for_route_with_services,
    platform::{CommandDesktopNotifier, PlatformSnapshot},
    sse::{SseAlertEvent, SseDigestEvent, SseEvent, SseServer},
    webhook::UreqWebhookTransport,
    DailyDigestDeliveryReport, NotificationServices, PendingAlertDeliveryReport,
};
use crate::scan::baseline::{
    collect_restore_payload_candidates, restore_target_kind_for_path, RestoreTargetKind,
};
use crate::scan::{
    collect_scan_evidence, runtime_not_detected_result, BaselineArtifact, ScanResult, ScanSummary,
    Severity,
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
    /// View or change notification settings.
    Notify {
        #[command(subcommand)]
        command: Option<NotifyCommands>,
    },
    /// Start the foreground watcher loop for the configured runtime.
    Watch(WatchArgs),
    /// Show the local audit event log.
    Audit(AuditArgs),
    /// Show scan and security statistics.
    Stats(StatsArgs),
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

    /// Start an SSE server on this port for real-time alert streaming. 0 = disabled.
    #[arg(long, default_value_t = 0)]
    sse_port: u16,
}

#[derive(Debug, Args)]
struct AuditArgs {
    /// Filter by event category: config, hook, plugin, tool, skill.
    #[arg(long)]
    category: Option<String>,

    /// Show events since: 1h, 24h, 7d, or a Unix timestamp in milliseconds.
    #[arg(long)]
    since: Option<String>,

    /// Maximum number of events to show.
    #[arg(long, default_value_t = 50)]
    limit: u32,
}

#[derive(Debug, Args)]
struct StatsArgs {
    /// Show statistics since: 1h, 24h, 7d, 30d, or a Unix timestamp in milliseconds.
    #[arg(long)]
    since: Option<String>,
}

#[derive(Debug, Subcommand)]
enum NotifyCommands {
    /// Switch to desktop notifications.
    Desktop,
    /// Switch to webhook notifications.
    Webhook {
        /// The webhook URL (must start with http:// or https://).
        url: String,
    },
    /// Enable SSE server and configure Telegram alerts via OpenClaw plugin.
    Telegram {
        /// Telegram chat ID. If omitted, auto-detects from OpenClaw config or uses saved value.
        chat_id: Option<String>,
        /// Automatically write the plugin config into openclaw.json (creates backup first).
        #[arg(long)]
        apply: bool,
    },
    /// Disable all notifications (log-only) and stop SSE server.
    Off,
}

#[derive(Debug, Serialize)]
struct NotifyShowOutput {
    mode: &'static str,
    alert_strategy: String,
    webhook_url: Option<String>,
    telegram_chat_id: Option<String>,
    sse_port: u16,
    sse_bind: String,
}

#[derive(Debug, Serialize)]
struct NotifyUpdateOutput {
    mode: &'static str,
    alert_strategy: String,
    webhook_url: Option<String>,
    telegram_chat_id: Option<String>,
    sse_port: u16,
    sse_bind: String,
    changed: Vec<String>,
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
        Some(Commands::Notify { command: None }) => run_notify_show_command(&cli),
        Some(Commands::Notify {
            command: Some(ref cmd),
        }) => run_notify_update_command(&cli, cmd),
        Some(Commands::Watch(ref args)) => run_watch_command(&cli, args),
        Some(Commands::Audit(ref args)) => run_audit_command(&cli, args),
        Some(Commands::Stats(ref args)) => run_stats_command(&cli, args),
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

fn run_notify_show_command(cli: &Cli) -> ExitCode {
    let config = match load_saved_config_for_operational_command("notify") {
        Ok(config) => config,
        Err(code) => return code,
    };

    let telegram_active = config.sse.port > 0 && config.telegram_chat_id.is_some();

    let output = NotifyShowOutput {
        mode: "notify",
        alert_strategy: format!("{:?}", config.alert_strategy),
        webhook_url: config.webhook_url.clone(),
        telegram_chat_id: config.telegram_chat_id.clone(),
        sse_port: config.sse.port,
        sse_bind: config.sse.bind.clone(),
    };

    if cli.json {
        match serde_json::to_string_pretty(&output) {
            Ok(serialized) => println!("{serialized}"),
            Err(error) => {
                eprintln!("failed to serialize notify output: {error}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        println!("Notification Configuration");
        println!("  Strategy:    {}", format!("{:?}", config.alert_strategy));
        if let Some(ref url) = config.webhook_url {
            println!("  Webhook:     {url}");
        } else {
            println!("  Webhook:     (not configured)");
        }
        if telegram_active {
            println!(
                "  Telegram:    active (chat {})",
                config.telegram_chat_id.as_deref().unwrap_or("?")
            );
        } else {
            println!("  Telegram:    inactive");
        }
        if config.sse.port > 0 {
            println!(
                "  SSE:         port {} on {}",
                config.sse.port, config.sse.bind
            );
        } else {
            println!("  SSE:         disabled");
        }
        println!();
        println!("Commands:");
        println!("  clawguard notify desktop              switch to desktop notifications");
        println!("  clawguard notify webhook <url>        switch to webhook");
        println!("  clawguard notify telegram [chat-id]   enable Telegram via SSE");
        println!("  clawguard notify off                  disable all notifications");
    }

    ExitCode::SUCCESS
}

fn run_notify_update_command(cli: &Cli, cmd: &NotifyCommands) -> ExitCode {
    let home_dir = resolve_home_dir();
    let mut config = match load_saved_config_for_operational_command("notify") {
        Ok(config) => config,
        Err(code) => return code,
    };

    let mut changed = Vec::new();

    match cmd {
        NotifyCommands::Desktop => {
            config.alert_strategy = AlertStrategy::Desktop;
            config.webhook_url = None;
            changed.push("alert_strategy -> Desktop".to_string());
        }
        NotifyCommands::Webhook { url } => {
            let validated = match validate_webhook_url(url) {
                Ok(url) => url,
                Err(error) => {
                    eprintln!("invalid webhook URL: {error}");
                    return ExitCode::FAILURE;
                }
            };
            config.alert_strategy = AlertStrategy::Webhook;
            config.webhook_url = Some(validated);
            changed.push("alert_strategy -> Webhook".to_string());
            changed.push(format!("webhook_url -> {url}"));
        }
        NotifyCommands::Telegram { chat_id, .. } => {
            if let Some(ref id) = chat_id {
                let trimmed = id.trim();
                if trimmed.is_empty() {
                    eprintln!("telegram chat ID cannot be empty");
                    return ExitCode::FAILURE;
                }
                if trimmed.len() > 64 {
                    eprintln!("telegram chat ID is too long (max 64 characters)");
                    return ExitCode::FAILURE;
                }
                if !trimmed
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                {
                    eprintln!(
                        "telegram chat ID must contain only alphanumeric characters, hyphens, or underscores"
                    );
                    return ExitCode::FAILURE;
                }
                config.telegram_chat_id = Some(trimmed.to_string());
                changed.push(format!("telegram_chat_id -> {trimmed}"));
            } else if config.telegram_chat_id.is_none() {
                // Auto-detect from OpenClaw config
                let detected = resolve_openclaw_config_path(&home_dir)
                    .map(|p| extract_telegram_chat_ids(&p))
                    .unwrap_or_default();

                if detected.is_empty() {
                    eprintln!("no telegram chat ID found; provide one: clawguard notify telegram <chat-id>");
                    return ExitCode::FAILURE;
                } else if detected.len() == 1 {
                    let picked = &detected[0];
                    config.telegram_chat_id = Some(picked.id.clone());
                    changed.push(format!(
                        "telegram_chat_id -> {} (auto-detected from {})",
                        picked.id, picked.source
                    ));
                } else if cli.json || cli.no_interactive {
                    // Non-interactive: only auto-select if exactly 1 high-confidence defaultTo
                    let high_confidence: Vec<_> =
                        detected.iter().filter(|c| c.confidence == 1).collect();
                    if high_confidence.len() == 1 {
                        config.telegram_chat_id = Some(high_confidence[0].id.clone());
                        changed.push(format!(
                            "telegram_chat_id -> {} (auto-detected from {})",
                            high_confidence[0].id, high_confidence[0].source
                        ));
                    } else {
                        if cli.json {
                            let output = serde_json::json!({
                                "mode": "notify_update",
                                "error": "multiple telegram chat IDs detected",
                                "detected_chat_ids": detected,
                            });
                            if let Ok(s) = serde_json::to_string_pretty(&output) {
                                println!("{s}");
                            }
                        } else {
                            eprintln!(
                                "multiple telegram chat IDs detected; specify one explicitly:"
                            );
                            for (i, c) in detected.iter().enumerate() {
                                eprintln!("  [{}] {}  ({})", i + 1, c.id, c.source);
                            }
                            eprintln!();
                            eprintln!("Re-run: clawguard notify telegram <chat-id>");
                        }
                        return ExitCode::FAILURE;
                    }
                } else {
                    // Interactive: show list and ask user to re-run
                    eprintln!(
                        "Found {} Telegram chat IDs in OpenClaw config:",
                        detected.len()
                    );
                    eprintln!();
                    for (i, c) in detected.iter().enumerate() {
                        let label = if c.confidence == 1 {
                            "  \u{2190} recommended"
                        } else {
                            ""
                        };
                        eprintln!("  [{}] {}  ({}){}", i + 1, c.id, c.source, label);
                    }
                    eprintln!();
                    eprintln!("Re-run with your choice: clawguard notify telegram <chat-id>");
                    return ExitCode::FAILURE;
                }
            }
            config.alert_strategy = AlertStrategy::LogOnly;
            config.webhook_url = None;
            if config.sse.port == 0 {
                config.sse.port = 37776;
                changed.push("sse.port -> 37776".to_string());
            }
            changed.push("alert_strategy -> LogOnly (Telegram via SSE)".to_string());
        }
        NotifyCommands::Off => {
            config.alert_strategy = AlertStrategy::LogOnly;
            config.webhook_url = None;
            config.sse.port = 0;
            changed.push("alert_strategy -> LogOnly".to_string());
            changed.push("sse.port -> 0".to_string());
        }
    }

    if let Err(error) = save_config_for_home(&config, &home_dir) {
        eprintln!("failed to save config: {error}");
        return ExitCode::FAILURE;
    }

    let output = NotifyUpdateOutput {
        mode: "notify_update",
        alert_strategy: format!("{:?}", config.alert_strategy),
        webhook_url: config.webhook_url.clone(),
        telegram_chat_id: config.telegram_chat_id.clone(),
        sse_port: config.sse.port,
        sse_bind: config.sse.bind.clone(),
        changed: changed.clone(),
    };

    if cli.json {
        match serde_json::to_string_pretty(&output) {
            Ok(serialized) => println!("{serialized}"),
            Err(error) => {
                eprintln!("failed to serialize notify update output: {error}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        for change in &changed {
            println!("  {change}");
        }
        println!();

        if let NotifyCommands::Telegram { apply, .. } = cmd {
            let chat_id_display = config
                .telegram_chat_id
                .as_deref()
                .unwrap_or("<your-chat-id>");

            if *apply {
                // Auto-write plugin config into openclaw.json
                if let Some(openclaw_path) = resolve_openclaw_config_path(&home_dir) {
                    match apply_plugin_config_to_openclaw(
                        &openclaw_path,
                        config.sse.port,
                        chat_id_display,
                    ) {
                        Ok(backup_path) => {
                            println!(
                                "Wrote ClawGuard plugin config to {}",
                                openclaw_path.display()
                            );
                            println!("Backup saved to {}", backup_path.display());
                            println!();
                            println!("Note: JSON5 comments in openclaw.json were not preserved.");
                        }
                        Err(error) => {
                            eprintln!("failed to apply plugin config: {error}");
                            return ExitCode::FAILURE;
                        }
                    }
                } else {
                    eprintln!("could not find openclaw.json; paste the config manually instead");
                    return ExitCode::FAILURE;
                }
            } else {
                // Print snippet for manual paste
                let snippet = serde_json::json!({
                    "plugins": {
                        "entries": {
                            "clawguard": {
                                "enabled": true,
                                "config": {
                                    "port": config.sse.port,
                                    "channel": "telegram",
                                    "to": chat_id_display
                                }
                            }
                        }
                    }
                });
                println!("Add this to your openclaw.json to receive alerts in Telegram:");
                println!();
                if let Ok(pretty) = serde_json::to_string_pretty(&snippet) {
                    for line in pretty.lines() {
                        println!("  {line}");
                    }
                }
                println!();
                println!("Or re-run with --apply to write it automatically.");
            }
        }

        println!("Run `clawguard watch` to start monitoring.");

        if config.sse.bind == "127.0.0.1" {
            println!();
            println!("Note: SSE server will bind to 127.0.0.1 (loopback only).");
            println!("If OpenClaw runs in Docker, set sse.bind in ~/.clawguard/config.toml:");
            println!("  [sse]");
            println!("  bind = \"0.0.0.0\"");
        }
    }

    ExitCode::SUCCESS
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

fn run_audit_command(cli: &Cli, args: &AuditArgs) -> ExitCode {
    let home_dir = resolve_home_dir();
    let db_path = state_db_path_for_home(&home_dir);

    if !db_path.exists() {
        if cli.json {
            println!("[]");
        } else {
            println!("No audit events yet — run a scan or watch first.");
        }
        return ExitCode::SUCCESS;
    }

    let open_result = match open_state_store_for_home(&home_dir) {
        Ok(result) => result,
        Err(exit_code) => return exit_code,
    };

    let since_unix_ms = args.since.as_deref().and_then(parse_since_duration);

    let events = match open_result.store.list_audit_events(
        args.category.as_deref(),
        since_unix_ms,
        args.limit,
    ) {
        Ok(events) => events,
        Err(error) => {
            eprintln!("Error: failed to query audit events: {error}");
            return ExitCode::FAILURE;
        }
    };

    if cli.json {
        for event in &events {
            if let Ok(json) = serde_json::to_string(event) {
                println!("{json}");
            }
        }
    } else if events.is_empty() {
        println!("No audit events found.");
    } else {
        render_audit_table(&events);
    }

    ExitCode::SUCCESS
}

fn run_stats_command(cli: &Cli, args: &StatsArgs) -> ExitCode {
    let home_dir = resolve_home_dir();
    let db_path = state_db_path_for_home(&home_dir);

    if !db_path.exists() {
        if cli.json {
            println!("{{}}");
        } else {
            println!("No scan data yet. Run `clawguard scan` to start.");
        }
        return ExitCode::SUCCESS;
    }

    let open_result = match open_state_store_for_home(&home_dir) {
        Ok(result) => result,
        Err(exit_code) => return exit_code,
    };
    let store = &open_result.store;

    let since_unix_ms = args.since.as_deref().and_then(parse_since_duration);

    let scan_stats = match store.count_scan_snapshots(since_unix_ms) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: failed to query scan stats: {e}");
            return ExitCode::FAILURE;
        }
    };

    if scan_stats.total == 0 {
        if cli.json {
            println!("{{}}");
        } else {
            println!("No scan data yet. Run `clawguard scan` to start.");
        }
        return ExitCode::SUCCESS;
    }

    let alert_stats =
        store
            .count_alerts_by_status(since_unix_ms)
            .unwrap_or(crate::state::model::AlertStats {
                open: 0,
                acknowledged: 0,
                resolved: 0,
            });
    let baseline_count = store.count_baselines(since_unix_ms).unwrap_or(0);
    let audit_by_cat = store
        .count_audit_events_by_category(since_unix_ms)
        .unwrap_or_default();
    let current_findings = store.list_current_findings().unwrap_or_default();

    // Trend: earliest snapshot in window vs latest snapshot overall.
    // Both use snapshot summary totals for consistency (not current_findings which
    // reflects post-scan mutations and isn't time-filtered).
    // Note: latest_scan_snapshot() is globally unfiltered intentionally — if scan_stats.total > 0
    // (checked above), the global latest is always >= any snapshot in the window.
    let earliest = store.earliest_scan_snapshot(since_unix_ms).ok().flatten();
    let latest = store.latest_scan_snapshot().ok().flatten();
    let findings_start = earliest
        .as_ref()
        .map(|s| s.summary.total_findings)
        .unwrap_or(0);
    let findings_current = latest
        .as_ref()
        .map(|s| s.summary.total_findings)
        .unwrap_or(current_findings.len());

    // Per-severity breakdown from current findings
    let mut by_severity: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    for f in &current_findings {
        *by_severity.entry(format!("{:?}", f.severity)).or_insert(0) += 1;
    }

    let alert_total = alert_stats.open + alert_stats.acknowledged + alert_stats.resolved;
    let audit_total: u64 = audit_by_cat.values().sum();

    if cli.json {
        let trend_direction = if findings_current < findings_start {
            "improved"
        } else if findings_current > findings_start {
            "degraded"
        } else {
            "stable"
        };

        let json = serde_json::json!({
            "since_unix_ms": since_unix_ms,
            "scans": {
                "total": scan_stats.total,
                "first_at_unix_ms": scan_stats.first_at_unix_ms,
                "last_at_unix_ms": scan_stats.last_at_unix_ms,
            },
            "findings": {
                "current": {
                    "total": findings_current,
                    "critical": by_severity.get("Critical").unwrap_or(&0),
                    "high": by_severity.get("High").unwrap_or(&0),
                    "medium": by_severity.get("Medium").unwrap_or(&0),
                    "low": by_severity.get("Low").unwrap_or(&0),
                    "info": by_severity.get("Info").unwrap_or(&0),
                },
            },
            "alerts": {
                "total": alert_total,
                "open": alert_stats.open,
                "acknowledged": alert_stats.acknowledged,
                "resolved": alert_stats.resolved,
            },
            "baselines": {
                "approved_paths": baseline_count,
            },
            "audit_events": {
                "total": audit_total,
                "by_category": audit_by_cat,
            },
            "trend": {
                "findings_start": findings_start,
                "findings_current": findings_current,
                "findings_direction": trend_direction,
            },
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&json).unwrap_or_default()
        );
        return ExitCode::SUCCESS;
    }

    // Terminal output
    let since_label = if let Some(s) = &args.since {
        format!(" (since {s})")
    } else {
        String::new()
    };
    println!("ClawGuard Security Statistics{since_label}");
    println!("{}", "─".repeat(45));

    // Scans
    let last_ago = scan_stats
        .last_at_unix_ms
        .map_or("unknown".to_string(), |ts| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            let diff_secs = now.saturating_sub(ts) / 1000;
            if diff_secs < 60 {
                format!("{diff_secs} seconds ago")
            } else if diff_secs < 3600 {
                format!("{} minutes ago", diff_secs / 60)
            } else if diff_secs < 86400 {
                format!("{} hours ago", diff_secs / 3600)
            } else {
                format!("{} days ago", diff_secs / 86400)
            }
        });
    println!(
        "Scans:          {} total (last: {})",
        scan_stats.total, last_ago
    );

    // Findings
    let severity_parts: Vec<String> = ["Critical", "High", "Medium", "Low", "Info"]
        .iter()
        .filter_map(|sev| {
            let count = by_severity.get(*sev).unwrap_or(&0);
            if *count > 0 {
                Some(format!("{count} {sev}"))
            } else {
                None
            }
        })
        .collect();
    let severity_detail = if severity_parts.is_empty() {
        String::new()
    } else {
        format!(" ({})", severity_parts.join(", "))
    };
    println!(
        "Findings:       {} current{}",
        findings_current, severity_detail
    );

    // Alerts
    println!(
        "Alerts:         {} total ({} open, {} acknowledged, {} resolved)",
        alert_total, alert_stats.open, alert_stats.acknowledged, alert_stats.resolved
    );

    // Baselines
    println!("Baselines:      {} approved paths", baseline_count);

    // Audit events
    let cat_parts: Vec<String> = audit_by_cat
        .iter()
        .map(|(cat, count)| format!("{count} {cat}"))
        .collect();
    let cat_detail = if cat_parts.is_empty() {
        String::new()
    } else {
        format!(" ({})", cat_parts.join(", "))
    };
    println!("Audit events:   {} total{}", audit_total, cat_detail);

    // Trend
    if findings_start > 0 || findings_current > 0 {
        println!();
        println!("Trend:");
        let direction = if findings_current < findings_start {
            "↓ improved"
        } else if findings_current > findings_start {
            "↑ degraded"
        } else {
            "→ stable"
        };
        println!(
            "  Findings:  {} → {} ({})",
            findings_start, findings_current, direction
        );
    }

    ExitCode::SUCCESS
}

fn parse_since_duration(s: &str) -> Option<u64> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    if let Ok(ts) = s.parse::<u64>() {
        return Some(ts);
    }

    let trimmed = s.trim().to_lowercase();
    let ms = if trimmed.ends_with('h') {
        trimmed.trim_end_matches('h').parse::<u64>().ok()? * 3_600_000
    } else if trimmed.ends_with('d') {
        trimmed.trim_end_matches('d').parse::<u64>().ok()? * 86_400_000
    } else if trimmed.ends_with('m') {
        trimmed.trim_end_matches('m').parse::<u64>().ok()? * 60_000
    } else {
        return None;
    };

    Some(now.saturating_sub(ms))
}

fn render_audit_table(events: &[crate::audit::AuditEvent]) {
    println!(
        "{:<23} {:<8} {:<22} {}",
        "Timestamp", "Category", "Type", "Summary"
    );
    println!("{}", "-".repeat(80));

    for event in events {
        let ts = format_unix_ms(event.event_at_unix_ms);
        let cat = event.category.as_str();
        let etype = if event.event_type.len() > 22 {
            &event.event_type[..22]
        } else {
            &event.event_type
        };
        let summary = if event.summary.len() > 50 {
            format!("{}...", &event.summary[..47])
        } else {
            event.summary.clone()
        };
        println!("{:<23} {:<8} {:<22} {}", ts, cat, etype, summary);
    }
}

fn format_unix_ms(ms: u64) -> String {
    let secs = ms / 1000;
    let days_since_epoch = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Simple date calculation (good enough for display)
    let mut y = 1970i64;
    let mut remaining_days = days_since_epoch as i64;
    loop {
        let days_in_year = if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) {
            366
        } else {
            365
        };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        y += 1;
    }
    let is_leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let month_days = [
        31,
        if is_leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut m = 0usize;
    for (i, &days) in month_days.iter().enumerate() {
        if remaining_days < days {
            m = i;
            break;
        }
        remaining_days -= days;
    }
    format!(
        "{y:04}-{:02}-{:02} {hours:02}:{minutes:02}:{seconds:02}",
        m + 1,
        remaining_days + 1
    )
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
    // SSE server: CLI flag overrides config; config is hot-reloaded each iteration.
    let sse_port_from_flag = args.sse_port;
    let sse_port_override = sse_port_from_flag > 0;
    let mut current_sse_port: u16 = if sse_port_override {
        sse_port_from_flag
    } else {
        config.sse.port
    };
    let mut current_sse_bind = config.sse.bind.clone();
    let mut sse_server = start_sse_if_enabled(&current_sse_bind, current_sse_port);

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

        if let Some(ref sse) = sse_server {
            for alert in &alert_delivery.delivered_alerts {
                sse.broadcast(SseEvent::Alert(SseAlertEvent::from_alert(alert)));
            }
            if digest_delivery.handled && digest_delivery.alert_count > 0 {
                sse.broadcast(SseEvent::Digest(SseDigestEvent {
                    alert_count: digest_delivery.alert_count,
                    summary: digest_delivery.log_line.clone().unwrap_or_default(),
                }));
            }
        }

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

        // Hot-reload SSE config from TOML (unless CLI flag overrides).
        if !sse_port_override {
            if let Ok(Some(refreshed)) = load_config() {
                let new_port = refreshed.sse.port;
                let new_bind = refreshed.sse.bind.clone();
                if new_port != current_sse_port || new_bind != current_sse_bind {
                    if let Some(old) = sse_server.take() {
                        eprintln!(
                            "SSE config changed ({}:{} -> {}:{}), restarting server",
                            current_sse_bind, current_sse_port, new_bind, new_port
                        );
                        old.shutdown();
                    }
                    current_sse_port = new_port;
                    current_sse_bind = new_bind;
                    sse_server = start_sse_if_enabled(&current_sse_bind, current_sse_port);
                }
            }
        }

        thread::sleep(Duration::from_millis(args.poll_interval_ms));
    }

    if let Some(sse) = sse_server {
        sse.shutdown();
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
    let evidence = collect_scan_evidence(config, discovery);

    // Best-effort provenance check: if state DB exists, load baselines and generate
    // provenance findings. If no DB, skip — provenance is advisory, not blocking.
    let home_dir = resolve_home_dir();
    let db_path = state_db_path_for_home(&home_dir);
    let provenance_findings = if db_path.exists() {
        open_state_store_for_home(&home_dir)
            .ok()
            .map(|state| {
                let baselines = state.store.list_baselines().unwrap_or_default();
                crate::scan::baseline::provenance_findings_for_artifacts(
                    &baselines,
                    &evidence.artifacts,
                )
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    let result = if provenance_findings.is_empty() {
        evidence.result
    } else {
        ScanResult::from_batches(vec![
            evidence.result.findings().to_vec(),
            provenance_findings,
        ])
    };

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

#[derive(Debug, Clone, Serialize)]
struct DetectedChatId {
    id: String,
    source: String,
    confidence: u8,
}

/// Extract Telegram chat IDs from an OpenClaw config file, ranked by confidence.
/// confidence: 1=defaultTo (outbound destination), 2=groups/direct keys, 3=allowFrom (inbound auth)
fn extract_telegram_chat_ids(openclaw_config_path: &Path) -> Vec<DetectedChatId> {
    let contents = match std::fs::read_to_string(openclaw_config_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let raw: serde_json::Value = match json5::from_str(&contents) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut candidates: Vec<DetectedChatId> = Vec::new();
    let mut seen = BTreeSet::new();

    let channels_telegram = raw.get("channels").and_then(|c| c.get("telegram"));

    let Some(tg) = channels_telegram else {
        return Vec::new();
    };

    // Helper to add a candidate if not already seen
    let mut add = |id: &str, source: String, confidence: u8| {
        let normalized = id.trim().to_string();
        if !normalized.is_empty() && seen.insert(normalized.clone()) {
            candidates.push(DetectedChatId {
                id: normalized,
                source,
                confidence,
            });
        }
    };

    // Extract from a single TelegramAccountConfig-shaped value
    let extract_account =
        |obj: &serde_json::Value, prefix: &str, add: &mut dyn FnMut(&str, String, u8)| {
            // defaultTo (confidence 1)
            if let Some(dt) = obj.get("defaultTo") {
                let val = match dt {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Number(n) => n.to_string(),
                    _ => String::new(),
                };
                if !val.is_empty() {
                    add(&val, format!("{prefix}.defaultTo"), 1);
                }
            }
            // groups keys (confidence 2)
            if let Some(groups) = obj.get("groups").and_then(|g| g.as_object()) {
                for key in groups.keys() {
                    if key != "*" {
                        add(key, format!("{prefix}.groups.{key}"), 2);
                    }
                }
            }
            // direct keys (confidence 2)
            if let Some(direct) = obj.get("direct").and_then(|d| d.as_object()) {
                for key in direct.keys() {
                    add(key, format!("{prefix}.direct.{key}"), 2);
                }
            }
            // allowFrom (confidence 3)
            if let Some(af) = obj.get("allowFrom").and_then(|a| a.as_array()) {
                for item in af {
                    let val = match item {
                        serde_json::Value::String(s) => s.clone(),
                        serde_json::Value::Number(n) => n.to_string(),
                        _ => continue,
                    };
                    add(&val, format!("{prefix}.allowFrom"), 3);
                }
            }
        };

    // Top-level telegram config (inherits TelegramAccountConfig)
    extract_account(tg, "channels.telegram", &mut add);

    // Per-account configs
    if let Some(accounts) = tg.get("accounts").and_then(|a| a.as_object()) {
        let mut account_names: Vec<_> = accounts.keys().cloned().collect();
        account_names.sort();
        for name in account_names {
            if let Some(acct) = accounts.get(&name) {
                extract_account(
                    acct,
                    &format!("channels.telegram.accounts.{name}"),
                    &mut add,
                );
            }
        }
    }

    // Sort by confidence (lowest number = highest confidence)
    candidates.sort_by_key(|c| c.confidence);
    candidates
}

/// Find the OpenClaw config path from discovery or fall back to the preset path.
fn resolve_openclaw_config_path(home_dir: &Path) -> Option<PathBuf> {
    let discovery = discover_from_builtin_presets(&DiscoveryOptions {
        home_dir: Some(home_dir.to_path_buf()),
        ..DiscoveryOptions::default()
    });
    // Use the first config-domain path from the first detected runtime
    for runtime in &discovery.runtimes {
        for target in &runtime.targets {
            if target.domain == crate::config::schema::ScanDomain::Config {
                for path in &target.paths {
                    if path.ends_with("openclaw.json") {
                        let p = PathBuf::from(path);
                        if p.exists() {
                            return Some(p);
                        }
                    }
                }
            }
        }
    }
    // Fallback to preset path
    let fallback = home_dir.join(".openclaw").join("openclaw.json");
    if fallback.exists() {
        Some(fallback)
    } else {
        None
    }
}

/// Write the ClawGuard plugin config into an existing openclaw.json file.
/// Creates a backup before writing. Returns the backup path on success.
fn apply_plugin_config_to_openclaw(
    openclaw_config_path: &Path,
    sse_port: u16,
    chat_id: &str,
) -> Result<PathBuf, String> {
    let contents = std::fs::read_to_string(openclaw_config_path)
        .map_err(|e| format!("failed to read {}: {e}", openclaw_config_path.display()))?;
    let mut config: serde_json::Value =
        json5::from_str(&contents).map_err(|e| format!("failed to parse config: {e}"))?;

    // Create backup
    let backup_path = openclaw_config_path.with_extension("json.clawguard-backup");
    std::fs::write(&backup_path, &contents)
        .map_err(|e| format!("failed to create backup at {}: {e}", backup_path.display()))?;

    // Deep-merge only plugins.entries.clawguard
    let root = config
        .as_object_mut()
        .ok_or("openclaw.json root is not an object")?;
    let plugins = root
        .entry("plugins")
        .or_insert_with(|| serde_json::json!({}));
    let plugins_obj = plugins.as_object_mut().ok_or("plugins is not an object")?;
    let entries = plugins_obj
        .entry("entries")
        .or_insert_with(|| serde_json::json!({}));
    let entries_obj = entries
        .as_object_mut()
        .ok_or("plugins.entries is not an object")?;

    entries_obj.insert(
        "clawguard".to_string(),
        serde_json::json!({
            "enabled": true,
            "config": {
                "port": sse_port,
                "channel": "telegram",
                "to": chat_id
            }
        }),
    );

    // Write back via atomic temp+rename
    let pretty =
        serde_json::to_string_pretty(&config).map_err(|e| format!("serialization failed: {e}"))?;
    let tmp_path = openclaw_config_path.with_extension("json.clawguard-tmp");
    std::fs::write(&tmp_path, &pretty).map_err(|e| format!("failed to write temp file: {e}"))?;
    std::fs::rename(&tmp_path, openclaw_config_path)
        .map_err(|e| format!("failed to rename temp file: {e}"))?;

    Ok(backup_path)
}

fn start_sse_if_enabled(bind: &str, port: u16) -> Option<SseServer> {
    if port == 0 {
        return None;
    }

    match SseServer::start(bind, port) {
        Ok(server) => {
            eprintln!("SSE server listening on {}:{}", bind, server.port());
            Some(server)
        }
        Err(error) => {
            eprintln!("warning: failed to start SSE server: {error}");
            None
        }
    }
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
            git_remote_url: artifact.git_remote_url.clone(),
            git_head_sha: artifact.git_head_sha.clone(),
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
