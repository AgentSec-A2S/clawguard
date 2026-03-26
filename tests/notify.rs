use std::cell::RefCell;

use clawguard::config::schema::{AlertStrategy, AppConfig, Strictness};
use clawguard::notify::platform::{
    DesktopNotification, DesktopNotifier, DesktopNotifierKind, PlatformSnapshot,
};
use clawguard::notify::webhook::{
    build_webhook_payload, WebhookDigestPayload, WebhookPayload, WebhookTransport,
};
use clawguard::notify::NotifyError;
use clawguard::notify::{
    deliver_alert_with_services, deliver_daily_digest_if_due_with_services,
    deliver_pending_alerts_for_route_with_services, NotificationServices,
};
use clawguard::scan::{
    Finding, FindingCategory, Fixability, RecommendedAction, RuntimeConfidence, Severity,
};
use clawguard::state::db::{StateStore, StateStoreConfig};
use clawguard::state::model::{AlertRecord, AlertStatus, NotificationCursorRecord};
use rusqlite::Connection;
use tempfile::tempdir;

#[test]
fn desktop_strategy_uses_platform_notifier_when_supported() {
    let alert = sample_alert();
    let config = desktop_config();
    let desktop = FakeDesktopNotifier::default();
    let webhook = FakeWebhookTransport::success();
    let services = NotificationServices {
        platform: PlatformSnapshot {
            target_os: "macos".to_string(),
            ssh_session: false,
            container_like: false,
            display_available: true,
            wayland_available: false,
            osascript_on_path: true,
            notify_send_on_path: false,
        },
        desktop_notifier: &desktop,
        webhook_transport: &webhook,
    };

    let outcome = deliver_alert_with_services(&config, &alert, &services);

    assert!(outcome.handled);
    assert!(outcome.warnings.is_empty());
    let calls = desktop.calls.borrow();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].kind, DesktopNotifierKind::Osascript);
    assert!(calls[0].title.contains("ClawGuard"));
    assert!(calls[0].body.contains(&alert.finding.path));
}

#[test]
fn desktop_strategy_degrades_to_log_only_in_headless_env() {
    let alert = sample_alert();
    let config = desktop_config();
    let desktop = FakeDesktopNotifier::default();
    let webhook = FakeWebhookTransport::success();
    let services = NotificationServices {
        platform: PlatformSnapshot {
            target_os: "linux".to_string(),
            ssh_session: true,
            container_like: false,
            display_available: false,
            wayland_available: false,
            osascript_on_path: false,
            notify_send_on_path: true,
        },
        desktop_notifier: &desktop,
        webhook_transport: &webhook,
    };

    let outcome = deliver_alert_with_services(&config, &alert, &services);

    assert!(outcome.handled);
    assert!(
        outcome
            .warnings
            .iter()
            .any(|warning| warning.contains("log-only")),
        "desktop fallback should explain the log-only downgrade"
    );
    assert!(
        outcome.log_line.is_some(),
        "headless desktop delivery should still produce a log-only message"
    );
    assert!(
        desktop.calls.borrow().is_empty(),
        "desktop notifier should not run when the environment is unsupported"
    );
}

#[test]
fn webhook_payload_contains_alert_context_and_paths() {
    let alert = sample_alert();
    let payload = build_webhook_payload(&alert);
    let serialized = serde_json::to_value(&payload).expect("payload should serialize");

    assert_eq!(payload.alert_id, alert.alert_id);
    assert_eq!(payload.finding_id, alert.finding_id);
    assert_eq!(payload.severity, "high");
    assert_eq!(payload.path, alert.finding.path);
    assert!(
        serialized["recommended_action"]["label"]
            .as_str()
            .is_some_and(|label| label.contains("Review")),
        "payload should include the recommended action context"
    );
}

#[test]
fn webhook_failure_returns_warning_without_claiming_success() {
    let alert = sample_alert();
    let config = AppConfig {
        preset: "openclaw".to_string(),
        strictness: Strictness::Recommended,
        alert_strategy: AlertStrategy::Webhook,
        webhook_url: Some("https://example.invalid/hook".to_string()),
        max_file_size_bytes: 1024 * 1024,
        sse: Default::default(),
    };
    let desktop = FakeDesktopNotifier::default();
    let webhook = FakeWebhookTransport::failure("timeout talking to upstream");
    let services = NotificationServices {
        platform: PlatformSnapshot::default(),
        desktop_notifier: &desktop,
        webhook_transport: &webhook,
    };

    let outcome = deliver_alert_with_services(&config, &alert, &services);

    assert!(!outcome.handled);
    assert!(
        outcome
            .warnings
            .iter()
            .any(|warning| warning.contains("timeout")),
        "webhook delivery errors should be returned as warnings"
    );
}

#[test]
fn webhook_strategy_requires_webhook_url() {
    let alert = sample_alert();
    let config = webhook_config(None);
    let desktop = FakeDesktopNotifier::success();
    let webhook = FakeWebhookTransport::success();
    let services = NotificationServices {
        platform: PlatformSnapshot::default(),
        desktop_notifier: &desktop,
        webhook_transport: &webhook,
    };

    let outcome = deliver_alert_with_services(&config, &alert, &services);

    assert!(!outcome.handled);
    assert!(
        outcome
            .warnings
            .iter()
            .any(|warning| warning.contains("webhook_url")),
        "missing webhook configuration should return a clear warning"
    );
}

#[test]
fn desktop_strategy_falls_back_to_log_only_when_notifier_errors() {
    let alert = sample_alert();
    let config = desktop_config();
    let desktop = FakeDesktopNotifier::failure("osascript permissions denied");
    let webhook = FakeWebhookTransport::success();
    let services = NotificationServices {
        platform: PlatformSnapshot {
            target_os: "macos".to_string(),
            ssh_session: false,
            container_like: false,
            display_available: true,
            wayland_available: false,
            osascript_on_path: true,
            notify_send_on_path: false,
        },
        desktop_notifier: &desktop,
        webhook_transport: &webhook,
    };

    let outcome = deliver_alert_with_services(&config, &alert, &services);

    assert!(outcome.handled);
    assert!(
        outcome.log_line.is_some(),
        "desktop command failures should degrade to log-only output"
    );
    assert!(
        outcome
            .warnings
            .iter()
            .any(|warning| warning.contains("permissions denied")),
        "desktop fallback should preserve the original failure reason"
    );
}

#[test]
fn pending_alert_delivery_records_receipts_once_per_route() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let mut store = StateStore::open(StateStoreConfig::for_path(temp_dir.path().join("state.db")))
        .expect("db should open")
        .store;
    let alert = sample_alert();
    let config = log_only_config();
    let desktop = FakeDesktopNotifier::default();
    let webhook = FakeWebhookTransport::success();
    let services = NotificationServices {
        platform: PlatformSnapshot::default(),
        desktop_notifier: &desktop,
        webhook_transport: &webhook,
    };

    store.append_alert(&alert).expect("alert should persist");

    let first = deliver_pending_alerts_for_route_with_services(&mut store, &config, 100, &services)
        .expect("pending alerts should deliver");
    assert_eq!(first.delivered_count, 1);
    assert_eq!(first.log_lines.len(), 1);
    let receipt = store
        .notification_receipt_for_alert(&alert.alert_id, "log_only")
        .expect("receipt lookup should succeed")
        .expect("receipt should be recorded");
    assert_eq!(receipt.delivered_at_unix_ms, 100);

    let second =
        deliver_pending_alerts_for_route_with_services(&mut store, &config, 200, &services)
            .expect("repeat delivery should still succeed");
    assert_eq!(second.delivered_count, 0);
    assert!(second.log_lines.is_empty());
    let receipt_after = store
        .notification_receipt_for_alert(&alert.alert_id, "log_only")
        .expect("receipt lookup should succeed")
        .expect("receipt should still exist");
    assert_eq!(receipt_after.delivered_at_unix_ms, 100);
}

#[test]
fn pending_alert_delivery_failure_returns_warning_without_receipt() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let mut store = StateStore::open(StateStoreConfig::for_path(temp_dir.path().join("state.db")))
        .expect("db should open")
        .store;
    let alert = sample_alert();
    let config = webhook_config(Some("https://example.invalid/hook"));
    let desktop = FakeDesktopNotifier::default();
    let webhook = FakeWebhookTransport::failure("timeout talking to upstream");
    let services = NotificationServices {
        platform: PlatformSnapshot::default(),
        desktop_notifier: &desktop,
        webhook_transport: &webhook,
    };

    store.append_alert(&alert).expect("alert should persist");

    let report =
        deliver_pending_alerts_for_route_with_services(&mut store, &config, 100, &services)
            .expect("warning delivery path should not be fatal");
    assert_eq!(report.delivered_count, 0);
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.contains("timeout")),
        "delivery warnings should bubble back to the caller"
    );
    assert!(
        store
            .notification_receipt_for_alert(&alert.alert_id, "webhook")
            .expect("receipt lookup should succeed")
            .is_none(),
        "failed deliveries must not record receipts"
    );
}

#[test]
fn pending_alert_delivery_preserves_partial_report_when_receipt_write_fails() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let db_path = temp_dir.path().join("state.db");
    let mut store = StateStore::open(
        StateStoreConfig::for_path(db_path.clone())
            .with_busy_timeout_ms(1)
            .with_lock_retry_count(0)
            .with_lock_retry_backoff_ms(0),
    )
    .expect("db should open")
    .store;
    let alert = sample_alert();
    let config = log_only_config();
    let desktop = FakeDesktopNotifier::default();
    let webhook = FakeWebhookTransport::success();
    let services = NotificationServices {
        platform: PlatformSnapshot::default(),
        desktop_notifier: &desktop,
        webhook_transport: &webhook,
    };

    store.append_alert(&alert).expect("alert should persist");

    let lock_conn = Connection::open(&db_path).expect("lock connection should open");
    lock_conn
        .execute_batch("BEGIN IMMEDIATE")
        .expect("lock transaction should start");

    let error = deliver_pending_alerts_for_route_with_services(&mut store, &config, 100, &services)
        .expect_err("receipt persistence should fail while the database is locked");
    let partial_report = error
        .pending_report()
        .cloned()
        .expect("receipt write failures should preserve the partial delivery report");

    drop(lock_conn);

    assert!(matches!(
        error,
        NotifyError::PendingAlertDeliveryState { .. }
    ));
    assert_eq!(partial_report.delivered_count, 1);
    assert_eq!(partial_report.log_lines.len(), 1);
    assert!(
        partial_report
            .warnings
            .iter()
            .any(|warning| warning.contains("receipt was not recorded")),
        "partial report should explain that delivery succeeded before receipt persistence failed"
    );
    assert!(
        store
            .notification_receipt_for_alert(&alert.alert_id, "log_only")
            .expect("receipt lookup should succeed")
            .is_none(),
        "failed receipt persistence must not invent a stored receipt"
    );
}

#[test]
fn daily_digest_is_suppressed_when_no_new_alerts_exist() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let mut store = StateStore::open(StateStoreConfig::for_path(temp_dir.path().join("state.db")))
        .expect("db should open")
        .store;
    let config = log_only_config();
    let desktop = FakeDesktopNotifier::default();
    let webhook = FakeWebhookTransport::success();
    let services = NotificationServices {
        platform: PlatformSnapshot::default(),
        desktop_notifier: &desktop,
        webhook_transport: &webhook,
    };

    let report =
        deliver_daily_digest_if_due_with_services(&mut store, &config, 86_400_000, &services)
            .expect("digest helper should succeed");
    assert!(report.suppressed);
    assert!(!report.handled);
    assert_eq!(report.alert_count, 0);
    assert!(
        store
            .notification_cursor("daily_digest:log_only")
            .expect("cursor lookup should succeed")
            .is_none(),
        "suppressed digests must not advance the cursor"
    );
}

#[test]
fn first_daily_digest_bootstraps_cursor_without_backfilling_old_alerts() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let mut store = StateStore::open(StateStoreConfig::for_path(temp_dir.path().join("state.db")))
        .expect("db should open")
        .store;
    let config = log_only_config();
    let desktop = FakeDesktopNotifier::success();
    let webhook = FakeWebhookTransport::success();
    let services = NotificationServices {
        platform: PlatformSnapshot::default(),
        desktop_notifier: &desktop,
        webhook_transport: &webhook,
    };

    store
        .append_alert(&sample_alert())
        .expect("alert should persist");

    let report = deliver_daily_digest_if_due_with_services(
        &mut store,
        &config,
        1_763_960_000_000,
        &services,
    )
    .expect("first digest bootstrap should succeed");
    assert!(report.suppressed);
    assert!(!report.handled);
    assert_eq!(report.alert_count, 1);
    assert!(
        store
            .notification_cursor("daily_digest:log_only")
            .expect("cursor lookup should succeed")
            .is_some_and(|cursor| cursor.unix_ms == 1_763_960_000_000),
        "first digest run should seed the cursor without sending a backfill digest"
    );
}

#[test]
fn daily_digest_is_suppressed_until_interval_elapses_after_cursor() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let mut store = StateStore::open(StateStoreConfig::for_path(temp_dir.path().join("state.db")))
        .expect("db should open")
        .store;
    let config = log_only_config();
    let desktop = FakeDesktopNotifier::success();
    let webhook = FakeWebhookTransport::success();
    let services = NotificationServices {
        platform: PlatformSnapshot::default(),
        desktop_notifier: &desktop,
        webhook_transport: &webhook,
    };

    store
        .set_notification_cursor(&NotificationCursorRecord {
            cursor_key: "daily_digest:log_only".to_string(),
            unix_ms: 1_763_949_000_000,
        })
        .expect("digest cursor should persist");
    store
        .append_alert(&sample_alert_with(
            "alert:test:recent",
            "baseline:modified:/tmp/.openclaw/openclaw.json",
            "/tmp/.openclaw/openclaw.json",
            Severity::High,
            1_763_950_100_000,
        ))
        .expect("recent alert should persist");

    let report = deliver_daily_digest_if_due_with_services(
        &mut store,
        &config,
        1_763_980_000_000,
        &services,
    )
    .expect("interval suppression should succeed");
    assert!(report.suppressed);
    assert!(!report.handled);
    assert_eq!(report.alert_count, 1);
    assert!(
        report.log_line.is_none(),
        "suppressed digest should not emit a notification log line"
    );
    assert!(
        store
            .notification_cursor("daily_digest:log_only")
            .expect("cursor lookup should succeed")
            .is_some_and(|cursor| cursor.unix_ms == 1_763_949_000_000),
        "suppressed digest should leave the existing cursor unchanged"
    );
}

#[test]
fn daily_digest_summarizes_new_alerts_since_cursor() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let mut store = StateStore::open(StateStoreConfig::for_path(temp_dir.path().join("state.db")))
        .expect("db should open")
        .store;
    let config = log_only_config();
    let desktop = FakeDesktopNotifier::default();
    let webhook = FakeWebhookTransport::success();
    let services = NotificationServices {
        platform: PlatformSnapshot::default(),
        desktop_notifier: &desktop,
        webhook_transport: &webhook,
    };
    let first = sample_alert();
    let second = sample_alert_with(
        "alert:test:2",
        "baseline:modified:/tmp/.openclaw/exec-approvals.json",
        "/tmp/.openclaw/exec-approvals.json",
        Severity::Critical,
        1_763_950_500_000,
    );

    store
        .append_alert(&first)
        .expect("first alert should persist");
    store
        .append_alert(&second)
        .expect("second alert should persist");
    store
        .set_notification_cursor(&NotificationCursorRecord {
            cursor_key: "daily_digest:log_only".to_string(),
            unix_ms: 1_763_949_000_000,
        })
        .expect("digest cursor should persist");

    let report = deliver_daily_digest_if_due_with_services(
        &mut store,
        &config,
        1_764_050_000_000,
        &services,
    )
    .expect("digest delivery should succeed");
    assert!(report.handled);
    assert!(!report.suppressed);
    assert_eq!(report.alert_count, 2);
    assert!(
        report
            .log_line
            .as_deref()
            .is_some_and(|line| line.contains("2 new alerts") && line.contains("critical")),
        "digest log line should summarize the alert volume and highest severity"
    );
    assert!(
        store
            .notification_cursor("daily_digest:log_only")
            .expect("cursor lookup should succeed")
            .is_some_and(|cursor| cursor.unix_ms == 1_764_050_000_000),
        "successful digest delivery should advance the cursor"
    );
}

#[test]
fn daily_digest_excludes_acknowledged_alerts_from_the_summary() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let mut store = StateStore::open(StateStoreConfig::for_path(temp_dir.path().join("state.db")))
        .expect("db should open")
        .store;
    let config = log_only_config();
    let desktop = FakeDesktopNotifier::default();
    let webhook = FakeWebhookTransport::success();
    let services = NotificationServices {
        platform: PlatformSnapshot::default(),
        desktop_notifier: &desktop,
        webhook_transport: &webhook,
    };
    let open_alert = sample_alert_with(
        "alert:test:open",
        "baseline:modified:/tmp/.openclaw/openclaw.json",
        "/tmp/.openclaw/openclaw.json",
        Severity::High,
        1_763_950_100_000,
    );
    let mut acknowledged_alert = sample_alert_with(
        "alert:test:ack",
        "baseline:modified:/tmp/.openclaw/exec-approvals.json",
        "/tmp/.openclaw/exec-approvals.json",
        Severity::Critical,
        1_763_950_200_000,
    );
    acknowledged_alert.status = AlertStatus::Acknowledged;

    store
        .append_alert(&open_alert)
        .expect("open alert should persist");
    store
        .append_alert(&acknowledged_alert)
        .expect("acknowledged alert should persist");
    store
        .set_notification_cursor(&NotificationCursorRecord {
            cursor_key: "daily_digest:log_only".to_string(),
            unix_ms: 1_763_949_000_000,
        })
        .expect("digest cursor should persist");

    let report = deliver_daily_digest_if_due_with_services(
        &mut store,
        &config,
        1_764_050_000_000,
        &services,
    )
    .expect("digest delivery should succeed");

    assert!(report.handled);
    assert_eq!(report.alert_count, 1);
    assert!(
        report
            .log_line
            .as_deref()
            .is_some_and(|line| line.contains("1 new alert") && !line.contains("2 new alerts")),
        "daily digest should ignore acknowledged alerts instead of re-surfacing them as active noise"
    );
}

#[test]
fn daily_digest_failure_does_not_advance_cursor() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let mut store = StateStore::open(StateStoreConfig::for_path(temp_dir.path().join("state.db")))
        .expect("db should open")
        .store;
    let alert = sample_alert();
    let config = webhook_config(Some("https://example.invalid/hook"));
    let desktop = FakeDesktopNotifier::default();
    let webhook = FakeWebhookTransport::failure("upstream rejected payload");
    let services = NotificationServices {
        platform: PlatformSnapshot::default(),
        desktop_notifier: &desktop,
        webhook_transport: &webhook,
    };

    store.append_alert(&alert).expect("alert should persist");
    store
        .set_notification_cursor(&NotificationCursorRecord {
            cursor_key: "daily_digest:webhook".to_string(),
            unix_ms: 1_763_949_000_000,
        })
        .expect("digest cursor should persist");

    let report = deliver_daily_digest_if_due_with_services(
        &mut store,
        &config,
        1_764_050_000_000,
        &services,
    )
    .expect("digest warning path should not be fatal");
    assert!(!report.handled);
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.contains("rejected")),
        "digest delivery failures should be surfaced as warnings"
    );
    assert!(
        store
            .notification_cursor("daily_digest:webhook")
            .expect("cursor lookup should succeed")
            .is_some_and(|cursor| cursor.unix_ms == 1_763_949_000_000),
        "failed digest delivery must not advance the cursor"
    );
}

#[test]
fn daily_digest_preserves_partial_report_when_cursor_update_fails() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let db_path = temp_dir.path().join("state.db");
    let mut store = StateStore::open(
        StateStoreConfig::for_path(db_path.clone())
            .with_busy_timeout_ms(1)
            .with_lock_retry_count(0)
            .with_lock_retry_backoff_ms(0),
    )
    .expect("db should open")
    .store;
    let config = log_only_config();
    let desktop = FakeDesktopNotifier::default();
    let webhook = FakeWebhookTransport::success();
    let services = NotificationServices {
        platform: PlatformSnapshot::default(),
        desktop_notifier: &desktop,
        webhook_transport: &webhook,
    };

    store
        .append_alert(&sample_alert())
        .expect("alert should persist");
    store
        .set_notification_cursor(&NotificationCursorRecord {
            cursor_key: "daily_digest:log_only".to_string(),
            unix_ms: 1_763_949_000_000,
        })
        .expect("digest cursor should persist");

    let lock_conn = Connection::open(&db_path).expect("lock connection should open");
    lock_conn
        .execute_batch("BEGIN IMMEDIATE")
        .expect("lock transaction should start");

    let error = deliver_daily_digest_if_due_with_services(
        &mut store,
        &config,
        1_764_050_000_000,
        &services,
    )
    .expect_err("cursor persistence should fail while the database is locked");
    let partial_report = error
        .daily_digest_report()
        .cloned()
        .expect("cursor write failures should preserve the delivered digest report");

    drop(lock_conn);

    assert!(matches!(error, NotifyError::DailyDigestState { .. }));
    assert!(partial_report.handled);
    assert!(!partial_report.suppressed);
    assert_eq!(partial_report.alert_count, 1);
    assert!(
        partial_report
            .log_line
            .as_deref()
            .is_some_and(|line| line.contains("[clawguard:digest:")),
        "partial digest report should preserve the emitted digest log line"
    );
    assert!(
        partial_report
            .warnings
            .iter()
            .any(|warning| warning.contains("cursor was not updated")),
        "partial digest report should explain that the cursor write failed after delivery"
    );
    assert!(
        store
            .notification_cursor("daily_digest:log_only")
            .expect("cursor lookup should succeed")
            .is_some_and(|cursor| cursor.unix_ms == 1_763_949_000_000),
        "failed cursor persistence must leave the existing cursor unchanged"
    );
}

struct FakeDesktopNotifier {
    calls: RefCell<Vec<DesktopNotification>>,
    response: Result<(), String>,
}

impl std::fmt::Debug for FakeDesktopNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeDesktopNotifier")
            .finish_non_exhaustive()
    }
}

impl FakeDesktopNotifier {
    fn success() -> Self {
        Self {
            calls: RefCell::new(Vec::new()),
            response: Ok(()),
        }
    }

    fn failure(message: &str) -> Self {
        Self {
            calls: RefCell::new(Vec::new()),
            response: Err(message.to_string()),
        }
    }
}

impl Default for FakeDesktopNotifier {
    fn default() -> Self {
        Self::success()
    }
}

impl DesktopNotifier for FakeDesktopNotifier {
    fn notify(&self, notification: DesktopNotification) -> Result<(), String> {
        self.calls.borrow_mut().push(notification);
        self.response.clone()
    }
}

#[derive(Debug)]
struct FakeWebhookTransport {
    response: Result<(), String>,
    sent: RefCell<Vec<WebhookPayload>>,
    sent_digests: RefCell<Vec<WebhookDigestPayload>>,
}

impl FakeWebhookTransport {
    fn success() -> Self {
        Self {
            response: Ok(()),
            sent: RefCell::new(Vec::new()),
            sent_digests: RefCell::new(Vec::new()),
        }
    }

    fn failure(message: &str) -> Self {
        Self {
            response: Err(message.to_string()),
            sent: RefCell::new(Vec::new()),
            sent_digests: RefCell::new(Vec::new()),
        }
    }
}

impl WebhookTransport for FakeWebhookTransport {
    fn post_json(&self, _url: &str, payload: &WebhookPayload) -> Result<(), String> {
        self.sent.borrow_mut().push(payload.clone());
        self.response.clone()
    }

    fn post_digest_json(&self, _url: &str, payload: &WebhookDigestPayload) -> Result<(), String> {
        self.sent_digests.borrow_mut().push(payload.clone());
        self.response.clone()
    }
}

fn desktop_config() -> AppConfig {
    AppConfig {
        preset: "openclaw".to_string(),
        strictness: Strictness::Recommended,
        alert_strategy: AlertStrategy::Desktop,
        webhook_url: None,
        max_file_size_bytes: 1024 * 1024,
        sse: Default::default(),
    }
}

fn log_only_config() -> AppConfig {
    AppConfig {
        preset: "openclaw".to_string(),
        strictness: Strictness::Recommended,
        alert_strategy: AlertStrategy::LogOnly,
        webhook_url: None,
        max_file_size_bytes: 1024 * 1024,
        sse: Default::default(),
    }
}

fn webhook_config(webhook_url: Option<&str>) -> AppConfig {
    AppConfig {
        preset: "openclaw".to_string(),
        strictness: Strictness::Recommended,
        alert_strategy: AlertStrategy::Webhook,
        webhook_url: webhook_url.map(str::to_string),
        max_file_size_bytes: 1024 * 1024,
        sse: Default::default(),
    }
}

fn sample_alert() -> AlertRecord {
    sample_alert_with(
        "alert:test",
        "baseline:modified:/tmp/.openclaw/openclaw.json",
        "/tmp/.openclaw/openclaw.json",
        Severity::High,
        1_763_950_000_000,
    )
}

fn sample_alert_with(
    alert_id: &str,
    finding_id: &str,
    path: &str,
    severity: Severity,
    created_at_unix_ms: u64,
) -> AlertRecord {
    AlertRecord {
        alert_id: alert_id.to_string(),
        finding_id: finding_id.to_string(),
        status: AlertStatus::Open,
        created_at_unix_ms,
        finding: Finding {
            id: finding_id.to_string(),
            detector_id: "baseline".to_string(),
            severity,
            category: FindingCategory::Drift,
            runtime_confidence: RuntimeConfidence::ActiveRuntime,
            path: path.to_string(),
            line: None,
            evidence: Some("approved=abc,current=def".to_string()),
            plain_english_explanation: "This file differs from the approved baseline.".to_string(),
            recommended_action: RecommendedAction {
                label: "Review the changed file before trusting it again".to_string(),
                command_hint: None,
            },
            fixability: Fixability::Manual,
            fix: None,
        },
    }
}
