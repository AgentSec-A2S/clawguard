pub mod platform;
pub mod webhook;

use std::fmt::{Display, Formatter};

use crate::config::schema::{AlertStrategy, AppConfig};
use crate::scan::Severity;
use crate::state::db::{StateStore, StateStoreError};
use crate::state::model::{AlertRecord, NotificationCursorRecord, NotificationReceiptRecord};

use self::platform::{
    CommandDesktopNotifier, DesktopNotification, DesktopNotifier, PlatformSnapshot,
};
use self::webhook::{
    build_webhook_payload, UreqWebhookTransport, WebhookDigestPayload, WebhookTransport,
};

const DAILY_DIGEST_INTERVAL_MS: u64 = 24 * 60 * 60 * 1_000;
const DIGEST_PATH_LIMIT: usize = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationMessage {
    pub title: String,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationOutcome {
    pub route_key: String,
    pub handled: bool,
    pub warnings: Vec<String>,
    pub log_line: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PendingAlertDeliveryReport {
    pub delivered_count: usize,
    pub warnings: Vec<String>,
    pub log_lines: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DailyDigestDeliveryReport {
    pub handled: bool,
    pub suppressed: bool,
    pub alert_count: usize,
    pub warnings: Vec<String>,
    pub log_line: Option<String>,
}

pub struct NotificationServices<'a> {
    pub platform: PlatformSnapshot,
    pub desktop_notifier: &'a dyn DesktopNotifier,
    pub webhook_transport: &'a dyn WebhookTransport,
}

#[derive(Debug)]
pub enum NotifyError {
    State(String),
}

impl Display for NotifyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::State(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for NotifyError {}

impl From<StateStoreError> for NotifyError {
    fn from(value: StateStoreError) -> Self {
        Self::State(value.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DailyDigestSummary {
    alert_count: usize,
    highest_severity: Severity,
    affected_paths: Vec<String>,
}

pub fn deliver_alert(config: &AppConfig, alert: &AlertRecord) -> NotificationOutcome {
    let platform = PlatformSnapshot::detect();
    let desktop_notifier = CommandDesktopNotifier;
    let webhook_transport = UreqWebhookTransport::default();
    let services = NotificationServices {
        platform,
        desktop_notifier: &desktop_notifier,
        webhook_transport: &webhook_transport,
    };

    deliver_alert_with_services(config, alert, &services)
}

pub fn deliver_alert_with_services(
    config: &AppConfig,
    alert: &AlertRecord,
    services: &NotificationServices<'_>,
) -> NotificationOutcome {
    match config.alert_strategy {
        AlertStrategy::Desktop => deliver_desktop_message(
            "desktop",
            notification_message_for_alert(alert),
            notification_log_line_for_alert(alert),
            services,
        ),
        AlertStrategy::Webhook => deliver_webhook_alert(config, alert, services),
        AlertStrategy::LogOnly => {
            deliver_log_only_message("log_only", notification_log_line_for_alert(alert))
        }
    }
}

pub fn deliver_pending_alerts_for_route(
    store: &mut StateStore,
    config: &AppConfig,
    delivered_at_unix_ms: u64,
) -> Result<PendingAlertDeliveryReport, NotifyError> {
    let platform = PlatformSnapshot::detect();
    let desktop_notifier = CommandDesktopNotifier;
    let webhook_transport = UreqWebhookTransport::default();
    let services = NotificationServices {
        platform,
        desktop_notifier: &desktop_notifier,
        webhook_transport: &webhook_transport,
    };

    deliver_pending_alerts_for_route_with_services(store, config, delivered_at_unix_ms, &services)
}

pub fn deliver_pending_alerts_for_route_with_services(
    store: &mut StateStore,
    config: &AppConfig,
    delivered_at_unix_ms: u64,
    services: &NotificationServices<'_>,
) -> Result<PendingAlertDeliveryReport, NotifyError> {
    let route_key = configured_route_key(config.alert_strategy);
    let alerts = store.list_undelivered_alerts_for_route(route_key)?;
    let mut report = PendingAlertDeliveryReport::default();

    for alert in alerts {
        let outcome = deliver_alert_with_services(config, &alert, services);
        report.warnings.extend(outcome.warnings);
        if let Some(log_line) = outcome.log_line {
            report.log_lines.push(log_line);
        }

        if outcome.handled {
            store.record_notification_receipt(&NotificationReceiptRecord {
                alert_id: alert.alert_id,
                delivery_route: route_key.to_string(),
                delivered_at_unix_ms,
            })?;
            report.delivered_count += 1;
        }
    }

    Ok(report)
}

pub fn deliver_daily_digest_if_due(
    store: &mut StateStore,
    config: &AppConfig,
    delivered_at_unix_ms: u64,
) -> Result<DailyDigestDeliveryReport, NotifyError> {
    let platform = PlatformSnapshot::detect();
    let desktop_notifier = CommandDesktopNotifier;
    let webhook_transport = UreqWebhookTransport::default();
    let services = NotificationServices {
        platform,
        desktop_notifier: &desktop_notifier,
        webhook_transport: &webhook_transport,
    };

    deliver_daily_digest_if_due_with_services(store, config, delivered_at_unix_ms, &services)
}

pub fn deliver_daily_digest_if_due_with_services(
    store: &mut StateStore,
    config: &AppConfig,
    delivered_at_unix_ms: u64,
    services: &NotificationServices<'_>,
) -> Result<DailyDigestDeliveryReport, NotifyError> {
    let route_key = configured_route_key(config.alert_strategy);
    let cursor_key = digest_cursor_key(route_key);
    let cursor = store.notification_cursor(&cursor_key)?;
    let alerts =
        store.list_alerts_created_after(cursor.as_ref().map_or(0, |cursor| cursor.unix_ms))?;

    if alerts.is_empty() {
        return Ok(DailyDigestDeliveryReport {
            handled: false,
            suppressed: true,
            alert_count: 0,
            warnings: Vec::new(),
            log_line: None,
        });
    }

    if cursor.is_none() {
        // Start digest cadence from the first watch-driven evaluation instead of immediately
        // backfilling historical alerts based on their original creation timestamps.
        store.set_notification_cursor(&NotificationCursorRecord {
            cursor_key,
            unix_ms: delivered_at_unix_ms,
        })?;
        return Ok(DailyDigestDeliveryReport {
            handled: false,
            suppressed: true,
            alert_count: alerts.len(),
            warnings: Vec::new(),
            log_line: None,
        });
    }

    let digest_window_start_unix_ms = cursor.as_ref().map_or(0, |cursor| cursor.unix_ms);
    if delivered_at_unix_ms < digest_window_start_unix_ms.saturating_add(DAILY_DIGEST_INTERVAL_MS) {
        return Ok(DailyDigestDeliveryReport {
            handled: false,
            suppressed: true,
            alert_count: alerts.len(),
            warnings: Vec::new(),
            log_line: None,
        });
    }

    let summary = build_daily_digest_summary(&alerts);
    let outcome = deliver_daily_digest_with_services(
        config,
        &cursor_key,
        delivered_at_unix_ms,
        &summary,
        services,
    );

    if outcome.handled {
        store.set_notification_cursor(&NotificationCursorRecord {
            cursor_key,
            unix_ms: delivered_at_unix_ms,
        })?;
    }

    Ok(DailyDigestDeliveryReport {
        handled: outcome.handled,
        suppressed: false,
        alert_count: summary.alert_count,
        warnings: outcome.warnings,
        log_line: outcome.log_line,
    })
}

pub fn notification_message_for_alert(alert: &AlertRecord) -> NotificationMessage {
    NotificationMessage {
        title: format!(
            "ClawGuard {} alert",
            severity_label(&alert.finding.severity)
        ),
        body: format!(
            "{}\n{}",
            alert.finding.path, alert.finding.plain_english_explanation
        ),
    }
}

fn deliver_daily_digest_with_services(
    config: &AppConfig,
    cursor_key: &str,
    delivered_at_unix_ms: u64,
    summary: &DailyDigestSummary,
    services: &NotificationServices<'_>,
) -> NotificationOutcome {
    match config.alert_strategy {
        AlertStrategy::Desktop => deliver_desktop_message(
            "desktop",
            notification_message_for_daily_digest(summary),
            notification_log_line_for_daily_digest(summary),
            services,
        ),
        AlertStrategy::Webhook => deliver_webhook_digest(
            config,
            build_webhook_digest_payload(cursor_key, delivered_at_unix_ms, summary),
            services,
        ),
        AlertStrategy::LogOnly => {
            deliver_log_only_message("log_only", notification_log_line_for_daily_digest(summary))
        }
    }
}

fn deliver_desktop_message(
    route_key: &str,
    message: NotificationMessage,
    fallback_log_line: String,
    services: &NotificationServices<'_>,
) -> NotificationOutcome {
    match services.platform.desktop_notifier_kind() {
        Some(kind) => match services.desktop_notifier.notify(DesktopNotification {
            kind,
            title: message.title,
            body: message.body,
        }) {
            Ok(()) => NotificationOutcome {
                route_key: route_key.to_string(),
                handled: true,
                warnings: Vec::new(),
                log_line: None,
            },
            Err(error) => {
                let mut outcome = deliver_log_only_message(route_key, fallback_log_line);
                outcome.warnings.push(format!(
                    "desktop notification failed: {error}; falling back to log-only"
                ));
                outcome
            }
        },
        None => {
            let mut outcome = deliver_log_only_message(route_key, fallback_log_line);
            outcome.warnings.push(
                "desktop notifications are unavailable in this environment; falling back to log-only"
                    .to_string(),
            );
            outcome
        }
    }
}

fn deliver_webhook_alert(
    config: &AppConfig,
    alert: &AlertRecord,
    services: &NotificationServices<'_>,
) -> NotificationOutcome {
    let Some(url) = config.webhook_url.as_deref() else {
        return NotificationOutcome {
            route_key: "webhook".to_string(),
            handled: false,
            warnings: vec!["webhook alert strategy requires a configured webhook_url".to_string()],
            log_line: None,
        };
    };

    let payload = build_webhook_payload(alert);
    match services.webhook_transport.post_json(url, &payload) {
        Ok(()) => NotificationOutcome {
            route_key: "webhook".to_string(),
            handled: true,
            warnings: Vec::new(),
            log_line: None,
        },
        Err(error) => NotificationOutcome {
            route_key: "webhook".to_string(),
            handled: false,
            warnings: vec![error],
            log_line: None,
        },
    }
}

fn deliver_webhook_digest(
    config: &AppConfig,
    payload: WebhookDigestPayload,
    services: &NotificationServices<'_>,
) -> NotificationOutcome {
    let Some(url) = config.webhook_url.as_deref() else {
        return NotificationOutcome {
            route_key: "webhook".to_string(),
            handled: false,
            warnings: vec!["webhook alert strategy requires a configured webhook_url".to_string()],
            log_line: None,
        };
    };

    match services.webhook_transport.post_digest_json(url, &payload) {
        Ok(()) => NotificationOutcome {
            route_key: "webhook".to_string(),
            handled: true,
            warnings: Vec::new(),
            log_line: None,
        },
        Err(error) => NotificationOutcome {
            route_key: "webhook".to_string(),
            handled: false,
            warnings: vec![error],
            log_line: None,
        },
    }
}

fn deliver_log_only_message(route_key: &str, log_line: String) -> NotificationOutcome {
    NotificationOutcome {
        route_key: route_key.to_string(),
        handled: true,
        warnings: Vec::new(),
        log_line: Some(log_line),
    }
}

fn notification_log_line_for_alert(alert: &AlertRecord) -> String {
    format!(
        "[clawguard:{}] {} :: {}",
        severity_slug(&alert.finding.severity),
        alert.finding.path,
        alert.finding.plain_english_explanation
    )
}

fn notification_message_for_daily_digest(summary: &DailyDigestSummary) -> NotificationMessage {
    NotificationMessage {
        title: format!("ClawGuard daily digest: {} new alerts", summary.alert_count),
        body: format!(
            "Highest severity: {}\nAffected paths: {}",
            severity_label(&summary.highest_severity),
            summary.affected_paths.join(", ")
        ),
    }
}

fn notification_log_line_for_daily_digest(summary: &DailyDigestSummary) -> String {
    format!(
        "[clawguard:digest:{}] {} new alerts :: {}",
        severity_slug(&summary.highest_severity),
        summary.alert_count,
        summary.affected_paths.join(", ")
    )
}

fn build_daily_digest_summary(alerts: &[AlertRecord]) -> DailyDigestSummary {
    let mut affected_paths = Vec::new();
    let highest_severity = alerts
        .iter()
        .map(|alert| alert.finding.severity)
        .max()
        .unwrap_or(Severity::Info);

    for alert in alerts {
        if affected_paths
            .iter()
            .any(|path| path == &alert.finding.path)
        {
            continue;
        }

        affected_paths.push(alert.finding.path.clone());
        if affected_paths.len() >= DIGEST_PATH_LIMIT {
            break;
        }
    }

    DailyDigestSummary {
        alert_count: alerts.len(),
        highest_severity,
        affected_paths,
    }
}

fn build_webhook_digest_payload(
    cursor_key: &str,
    delivered_at_unix_ms: u64,
    summary: &DailyDigestSummary,
) -> WebhookDigestPayload {
    WebhookDigestPayload {
        product: "clawguard".to_string(),
        cursor_key: cursor_key.to_string(),
        delivered_at_unix_ms,
        alert_count: summary.alert_count,
        highest_severity: severity_slug(&summary.highest_severity).to_string(),
        affected_paths: summary.affected_paths.clone(),
    }
}

fn configured_route_key(strategy: AlertStrategy) -> &'static str {
    match strategy {
        AlertStrategy::Desktop => "desktop",
        AlertStrategy::Webhook => "webhook",
        AlertStrategy::LogOnly => "log_only",
    }
}

fn digest_cursor_key(route_key: &str) -> String {
    format!("daily_digest:{route_key}")
}

fn severity_label(severity: &Severity) -> &'static str {
    match severity {
        Severity::Info => "Info",
        Severity::Low => "Low",
        Severity::Medium => "Medium",
        Severity::High => "High",
        Severity::Critical => "Critical",
    }
}

fn severity_slug(severity: &Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}
