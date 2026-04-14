use std::fs;
use std::time::Duration;

use clawguard::scan::{
    Finding, FindingCategory, Fixability, RecommendedAction, RuntimeConfidence, ScanSummary,
    Severity,
};
use clawguard::state::db::{StateStore, StateStoreConfig, StateStoreError};
use clawguard::state::model::{
    AlertRecord, AlertStatus, BaselineRecord, NotificationCursorRecord, NotificationReceiptRecord,
    RestorePayloadRecord, ScanSnapshot, StateWarningKind,
};
use rusqlite::Connection;
use tempfile::tempdir;

#[test]
fn missing_database_is_created_with_empty_state() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let db_path = temp_dir.path().join("state.db");

    let opened =
        StateStore::open(StateStoreConfig::for_path(db_path.clone())).expect("db should open");

    assert!(db_path.exists(), "database file should be created");
    assert!(
        opened.warnings.is_empty(),
        "missing db should be treated as the normal first-run path"
    );
    assert_eq!(opened.store.latest_scan_snapshot().unwrap(), None);
    assert!(opened.store.list_current_findings().unwrap().is_empty());
}

#[test]
fn corrupt_database_is_recreated_with_warning() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let db_path = temp_dir.path().join("state.db");
    fs::write(&db_path, "not sqlite").expect("corrupt db placeholder should be written");

    let opened =
        StateStore::open(StateStoreConfig::for_path(db_path.clone())).expect("db should reopen");

    assert!(
        opened
            .warnings
            .iter()
            .any(|warning| matches!(warning.kind, StateWarningKind::DatabaseCorruptRecreated)),
        "corrupt db should be recreated with an explicit warning"
    );
    assert!(
        fs::read_dir(temp_dir.path())
            .expect("temp dir should be readable")
            .filter_map(Result::ok)
            .any(|entry| entry.file_name().to_string_lossy().contains(".corrupt.")),
        "original corrupt db should be renamed aside"
    );
    assert_eq!(opened.store.latest_scan_snapshot().unwrap(), None);
}

#[test]
fn scan_snapshot_round_trips_with_summary_and_findings() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let mut store = StateStore::open(StateStoreConfig::for_path(temp_dir.path().join("state.db")))
        .expect("db should open")
        .store;
    let snapshot = sample_snapshot();

    store
        .record_scan_snapshot(&snapshot)
        .expect("snapshot should persist");

    assert_eq!(store.latest_scan_snapshot().unwrap(), Some(snapshot));
}

#[test]
fn latest_scan_snapshot_returns_most_recent_when_multiple_exist() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let mut store = StateStore::open(StateStoreConfig::for_path(temp_dir.path().join("state.db")))
        .expect("db should open")
        .store;

    let older = sample_snapshot();
    let mut newer = sample_snapshot();
    newer.recorded_at_unix_ms += 5_000;
    newer.findings = vec![sample_finding("finding-newer", Severity::Critical)];
    newer.summary.highest_severity = Some(Severity::Critical);
    newer.summary.total_findings = 1;

    store
        .record_scan_snapshot(&older)
        .expect("older snapshot should persist");
    store
        .record_scan_snapshot(&newer)
        .expect("newer snapshot should persist");

    assert_eq!(store.latest_scan_snapshot().unwrap(), Some(newer));
}

#[test]
fn record_scan_snapshot_and_replace_current_findings_updates_both_views() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let mut store = StateStore::open(StateStoreConfig::for_path(temp_dir.path().join("state.db")))
        .expect("db should open")
        .store;

    let snapshot = sample_snapshot();

    store
        .record_scan_snapshot_and_replace_current_findings(&snapshot)
        .expect("combined snapshot/current-finding write should succeed");

    assert_eq!(
        store.latest_scan_snapshot().unwrap(),
        Some(snapshot.clone())
    );
    assert_eq!(store.list_current_findings().unwrap(), snapshot.findings);
}

#[test]
fn replace_current_findings_overwrites_previous_unresolved_view() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let mut store = StateStore::open(StateStoreConfig::for_path(temp_dir.path().join("state.db")))
        .expect("db should open")
        .store;

    let original = vec![sample_finding("finding-original", Severity::Medium)];
    let replacement = vec![sample_finding("finding-replacement", Severity::High)];

    store
        .replace_current_findings(&original)
        .expect("original findings should persist");
    store
        .replace_current_findings(&replacement)
        .expect("replacement findings should persist");

    assert_eq!(store.list_current_findings().unwrap(), replacement);
}

#[test]
fn replace_current_findings_with_empty_slice_clears_the_view() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let mut store = StateStore::open(StateStoreConfig::for_path(temp_dir.path().join("state.db")))
        .expect("db should open")
        .store;

    store
        .replace_current_findings(&vec![sample_finding("finding-existing", Severity::Medium)])
        .expect("existing findings should persist");
    store
        .replace_current_findings(&[])
        .expect("empty replacement should succeed");

    assert!(store.list_current_findings().unwrap().is_empty());
}

#[test]
fn baseline_upsert_replaces_previous_hash_for_same_path() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let mut store = StateStore::open(StateStoreConfig::for_path(temp_dir.path().join("state.db")))
        .expect("db should open")
        .store;

    store
        .upsert_baseline(&baseline_record("/tmp/openclaw.json", "aaa"))
        .expect("first baseline should persist");
    store
        .upsert_baseline(&baseline_record("/tmp/openclaw.json", "bbb"))
        .expect("replacement baseline should persist");

    let baselines = store.list_baselines().unwrap();
    assert_eq!(baselines.len(), 1);
    assert_eq!(baselines[0].sha256, "bbb");
}

#[test]
fn baseline_for_path_returns_only_the_requested_record() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let mut store = StateStore::open(StateStoreConfig::for_path(temp_dir.path().join("state.db")))
        .expect("db should open")
        .store;

    let expected = baseline_record("/tmp/openclaw.json", "aaa");
    store
        .upsert_baseline(&expected)
        .expect("expected baseline should persist");
    store
        .upsert_baseline(&baseline_record("/tmp/other.json", "bbb"))
        .expect("other baseline should persist");

    assert_eq!(
        store.baseline_for_path("/tmp/openclaw.json").unwrap(),
        Some(expected)
    );
}

#[test]
fn replace_baselines_for_source_removes_stale_paths_transactionally() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let mut store = StateStore::open(StateStoreConfig::for_path(temp_dir.path().join("state.db")))
        .expect("db should open")
        .store;

    store
        .upsert_baseline(&baseline_record_with_source(
            "/tmp/openclaw.json",
            "aaa",
            "config",
        ))
        .expect("config baseline should persist");
    store
        .upsert_baseline(&baseline_record_with_source(
            "/tmp/exec-approvals.json",
            "bbb",
            "config",
        ))
        .expect("second config baseline should persist");
    store
        .upsert_baseline(&baseline_record_with_source(
            "/tmp/skills/risky/SKILL.md",
            "ccc",
            "skills",
        ))
        .expect("skills baseline should persist");

    let replacement = vec![baseline_record_with_source(
        "/tmp/openclaw.json",
        "updated",
        "config",
    )];

    store
        .replace_baselines_for_source("config", &replacement)
        .expect("source replacement should succeed");

    let baselines = store.list_baselines().unwrap();
    assert_eq!(
        baselines,
        vec![
            baseline_record_with_source("/tmp/openclaw.json", "updated", "config"),
            baseline_record_with_source("/tmp/skills/risky/SKILL.md", "ccc", "skills"),
        ]
    );
}

#[test]
fn replace_baselines_for_source_rejects_mismatched_source_label() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let mut store = StateStore::open(StateStoreConfig::for_path(temp_dir.path().join("state.db")))
        .expect("db should open")
        .store;

    let error = store
        .replace_baselines_for_source(
            "config",
            &[baseline_record_with_source(
                "/tmp/openclaw.json",
                "aaa",
                "skills",
            )],
        )
        .expect_err("mismatched source labels should be rejected");

    assert!(matches!(error, StateStoreError::Query { .. }));
}

#[test]
fn replace_baselines_for_source_rejects_path_owned_by_other_source() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let mut store = StateStore::open(StateStoreConfig::for_path(temp_dir.path().join("state.db")))
        .expect("db should open")
        .store;

    store
        .upsert_baseline(&baseline_record_with_source(
            "/tmp/openclaw.json",
            "aaa",
            "skills",
        ))
        .expect("existing skills baseline should persist");

    let error = store
        .replace_baselines_for_source(
            "config",
            &[baseline_record_with_source(
                "/tmp/openclaw.json",
                "bbb",
                "config",
            )],
        )
        .expect_err("cross-source path takeover should be rejected");

    assert!(matches!(error, StateStoreError::Query { .. }));
    assert_eq!(
        store.baseline_for_path("/tmp/openclaw.json").unwrap(),
        Some(baseline_record_with_source(
            "/tmp/openclaw.json",
            "aaa",
            "skills"
        ))
    );
}

#[test]
fn restore_payload_round_trips_by_path() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let mut store = StateStore::open(StateStoreConfig::for_path(temp_dir.path().join("state.db")))
        .expect("db should open")
        .store;

    let payload = restore_payload_record("/tmp/openclaw.json", "aaa", "config", "{ agents: {} }");

    store
        .replace_restore_payloads_for_source("config", std::slice::from_ref(&payload))
        .expect("restore payload should persist");

    assert_eq!(
        store
            .restore_payload_for_path("/tmp/openclaw.json")
            .unwrap(),
        Some(payload)
    );
}

#[test]
fn replace_restore_payloads_for_source_removes_stale_entries() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let mut store = StateStore::open(StateStoreConfig::for_path(temp_dir.path().join("state.db")))
        .expect("db should open")
        .store;

    store
        .replace_restore_payloads_for_source(
            "config",
            &[
                restore_payload_record("/tmp/openclaw.json", "aaa", "config", "{ one: true }"),
                restore_payload_record(
                    "/tmp/exec-approvals.json",
                    "bbb",
                    "config",
                    "{ mode: \"review\" }",
                ),
            ],
        )
        .expect("initial restore payloads should persist");

    let replacement =
        restore_payload_record("/tmp/openclaw.json", "updated", "config", "{ two: true }");
    store
        .replace_restore_payloads_for_source("config", std::slice::from_ref(&replacement))
        .expect("replacement payload should succeed");

    assert_eq!(
        store
            .restore_payload_for_path("/tmp/openclaw.json")
            .unwrap(),
        Some(replacement)
    );
    assert_eq!(
        store
            .restore_payload_for_path("/tmp/exec-approvals.json")
            .unwrap(),
        None
    );
}

#[test]
fn replace_restore_payloads_for_source_rejects_path_owned_by_other_source() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let mut store = StateStore::open(StateStoreConfig::for_path(temp_dir.path().join("state.db")))
        .expect("db should open")
        .store;

    let existing =
        restore_payload_record("/tmp/openclaw.json", "aaa", "skills", "{ injected: false }");
    store
        .replace_restore_payloads_for_source("skills", std::slice::from_ref(&existing))
        .expect("existing payload should persist");

    let error = store
        .replace_restore_payloads_for_source(
            "config",
            &[restore_payload_record(
                "/tmp/openclaw.json",
                "bbb",
                "config",
                "{ agents: {} }",
            )],
        )
        .expect_err("cross-source restore payload takeover should be rejected");

    assert!(matches!(error, StateStoreError::Query { .. }));
    assert_eq!(
        store
            .restore_payload_for_path("/tmp/openclaw.json")
            .unwrap(),
        Some(existing)
    );
}

#[test]
fn unresolved_alert_query_returns_only_open_and_acknowledged_alerts() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let mut store = StateStore::open(StateStoreConfig::for_path(temp_dir.path().join("state.db")))
        .expect("db should open")
        .store;

    store
        .append_alert(&alert_record(
            "alert-open",
            "finding-open",
            AlertStatus::Open,
        ))
        .expect("open alert should persist");
    store
        .append_alert(&alert_record(
            "alert-ack",
            "finding-ack",
            AlertStatus::Acknowledged,
        ))
        .expect("acknowledged alert should persist");
    store
        .append_alert(&alert_record(
            "alert-resolved",
            "finding-resolved",
            AlertStatus::Resolved,
        ))
        .expect("resolved alert should persist");

    let unresolved = store.list_unresolved_alerts().unwrap();
    assert_eq!(unresolved.len(), 2);
    assert!(unresolved
        .iter()
        .any(|alert| alert.status == AlertStatus::Open));
    assert!(unresolved
        .iter()
        .any(|alert| alert.status == AlertStatus::Acknowledged));
    assert!(unresolved
        .iter()
        .all(|alert| alert.status != AlertStatus::Resolved));
}

#[test]
fn update_alert_status_removes_resolved_alert_from_unresolved_view() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let mut store = StateStore::open(StateStoreConfig::for_path(temp_dir.path().join("state.db")))
        .expect("db should open")
        .store;

    store
        .append_alert(&alert_record(
            "alert-open",
            "finding-open",
            AlertStatus::Open,
        ))
        .expect("open alert should persist");

    store
        .update_alert_status("alert-open", AlertStatus::Resolved)
        .expect("alert status should update");

    assert!(store.list_unresolved_alerts().unwrap().is_empty());
}

#[test]
fn recent_alerts_return_newest_first_with_a_bounded_limit() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let mut store = StateStore::open(StateStoreConfig::for_path(temp_dir.path().join("state.db")))
        .expect("db should open")
        .store;

    let mut oldest = alert_record("alert-oldest", "finding-oldest", AlertStatus::Open);
    oldest.created_at_unix_ms = 1_763_573_000_000;
    let mut middle = alert_record("alert-middle", "finding-middle", AlertStatus::Acknowledged);
    middle.created_at_unix_ms = 1_763_573_100_000;
    let mut newest = alert_record("alert-newest", "finding-newest", AlertStatus::Resolved);
    newest.created_at_unix_ms = 1_763_573_200_000;

    store
        .append_alert(&oldest)
        .expect("oldest alert should persist");
    store
        .append_alert(&middle)
        .expect("middle alert should persist");
    store
        .append_alert(&newest)
        .expect("newest alert should persist");

    let recent = store
        .list_recent_alerts(2)
        .expect("recent alert query should succeed");

    assert_eq!(
        recent.iter().map(|alert| alert.alert_id.as_str()).collect::<Vec<_>>(),
        vec!["alert-newest", "alert-middle"],
        "recent alerts should include history statuses and return newest-first within the requested limit"
    );
}

#[test]
fn open_alerts_exclude_acknowledged_and_resolved_entries() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let mut store = StateStore::open(StateStoreConfig::for_path(temp_dir.path().join("state.db")))
        .expect("db should open")
        .store;

    store
        .append_alert(&alert_record(
            "alert-open",
            "finding-open",
            AlertStatus::Open,
        ))
        .expect("open alert should persist");
    store
        .append_alert(&alert_record(
            "alert-ack",
            "finding-ack",
            AlertStatus::Acknowledged,
        ))
        .expect("acknowledged alert should persist");
    store
        .append_alert(&alert_record(
            "alert-resolved",
            "finding-resolved",
            AlertStatus::Resolved,
        ))
        .expect("resolved alert should persist");

    let open_alerts = store
        .list_open_alerts()
        .expect("open alert query should succeed");

    assert_eq!(open_alerts.len(), 1);
    assert_eq!(open_alerts[0].alert_id, "alert-open");
    assert_eq!(open_alerts[0].status, AlertStatus::Open);
}

#[test]
fn open_alerts_created_after_exclude_acknowledged_entries() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let mut store = StateStore::open(StateStoreConfig::for_path(temp_dir.path().join("state.db")))
        .expect("db should open")
        .store;

    let mut open_recent = alert_record("alert-open", "finding-open", AlertStatus::Open);
    open_recent.created_at_unix_ms = 1_763_573_200_000;
    let mut ack_recent = alert_record("alert-ack", "finding-ack", AlertStatus::Acknowledged);
    ack_recent.created_at_unix_ms = 1_763_573_300_000;
    let mut resolved_recent =
        alert_record("alert-resolved", "finding-resolved", AlertStatus::Resolved);
    resolved_recent.created_at_unix_ms = 1_763_573_400_000;

    store
        .append_alert(&open_recent)
        .expect("open recent alert should persist");
    store
        .append_alert(&ack_recent)
        .expect("acknowledged recent alert should persist");
    store
        .append_alert(&resolved_recent)
        .expect("resolved recent alert should persist");

    let digest_candidates = store
        .list_open_alerts_created_after(1_763_573_100_000)
        .expect("digest candidate query should succeed");

    assert_eq!(digest_candidates.len(), 1);
    assert_eq!(digest_candidates[0].alert_id, "alert-open");
}

#[test]
fn alert_lookup_by_id_uses_the_primary_key_contract() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let mut store = StateStore::open(StateStoreConfig::for_path(temp_dir.path().join("state.db")))
        .expect("db should open")
        .store;
    let alert = alert_record("alert-open", "finding-open", AlertStatus::Open);

    store
        .append_alert(&alert)
        .expect("alert should persist for lookup");

    assert_eq!(
        store
            .alert_by_id("alert-open")
            .expect("alert lookup should succeed"),
        Some(alert)
    );
    assert_eq!(
        store
            .alert_by_id("missing-alert")
            .expect("missing alert lookup should succeed"),
        None
    );
}

#[test]
fn acknowledged_alert_count_tracks_only_acknowledged_entries() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let mut store = StateStore::open(StateStoreConfig::for_path(temp_dir.path().join("state.db")))
        .expect("db should open")
        .store;

    store
        .append_alert(&alert_record(
            "alert-open",
            "finding-open",
            AlertStatus::Open,
        ))
        .expect("open alert should persist");
    store
        .append_alert(&alert_record(
            "alert-ack-1",
            "finding-ack-1",
            AlertStatus::Acknowledged,
        ))
        .expect("first acknowledged alert should persist");
    store
        .append_alert(&alert_record(
            "alert-ack-2",
            "finding-ack-2",
            AlertStatus::Acknowledged,
        ))
        .expect("second acknowledged alert should persist");
    store
        .append_alert(&alert_record(
            "alert-resolved",
            "finding-resolved",
            AlertStatus::Resolved,
        ))
        .expect("resolved alert should persist");

    assert_eq!(
        store
            .count_acknowledged_alerts()
            .expect("acknowledged alert count should succeed"),
        2
    );
}

#[test]
fn restore_payload_enumeration_returns_exact_stored_paths() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let mut store = StateStore::open(StateStoreConfig::for_path(temp_dir.path().join("state.db")))
        .expect("db should open")
        .store;

    let config_payload =
        restore_payload_record("/tmp/openclaw.json", "aaa", "config", "{ agents: {} }");
    let approvals_payload = restore_payload_record(
        "/tmp/exec-approvals.json",
        "bbb",
        "config",
        "{ mode: \"review\" }",
    );
    store
        .replace_restore_payloads_for_source(
            "config",
            &[config_payload.clone(), approvals_payload.clone()],
        )
        .expect("restore payloads should persist");

    let payloads = store
        .list_restore_payloads()
        .expect("restore payload enumeration should succeed");

    assert_eq!(payloads, vec![approvals_payload, config_payload]);
}

#[test]
fn notification_receipt_round_trips_by_alert_and_route() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let mut store = StateStore::open(StateStoreConfig::for_path(temp_dir.path().join("state.db")))
        .expect("db should open")
        .store;

    let receipt = NotificationReceiptRecord {
        alert_id: "alert-open".to_string(),
        delivery_route: "desktop".to_string(),
        delivered_at_unix_ms: 1_763_900_100_000,
    };
    store
        .record_notification_receipt(&receipt)
        .expect("notification receipt should persist");

    assert_eq!(
        store
            .notification_receipt_for_alert("alert-open", "desktop")
            .unwrap(),
        Some(receipt)
    );
    assert_eq!(
        store
            .notification_receipt_for_alert("alert-open", "webhook")
            .unwrap(),
        None
    );
}

#[test]
fn undelivered_alerts_for_route_exclude_alerts_with_existing_receipts() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let mut store = StateStore::open(StateStoreConfig::for_path(temp_dir.path().join("state.db")))
        .expect("db should open")
        .store;

    store
        .append_alert(&alert_record(
            "alert-desktop",
            "finding-desktop",
            AlertStatus::Open,
        ))
        .expect("desktop alert should persist");
    store
        .append_alert(&alert_record(
            "alert-webhook",
            "finding-webhook",
            AlertStatus::Open,
        ))
        .expect("webhook alert should persist");
    store
        .record_notification_receipt(&NotificationReceiptRecord {
            alert_id: "alert-desktop".to_string(),
            delivery_route: "desktop".to_string(),
            delivered_at_unix_ms: 1_763_900_100_000,
        })
        .expect("desktop receipt should persist");

    let desktop_alerts = store
        .list_undelivered_alerts_for_route("desktop")
        .expect("desktop undelivered query should succeed");
    let webhook_alerts = store
        .list_undelivered_alerts_for_route("webhook")
        .expect("webhook undelivered query should succeed");

    assert_eq!(desktop_alerts.len(), 1);
    assert_eq!(desktop_alerts[0].alert_id, "alert-webhook");
    assert_eq!(webhook_alerts.len(), 2);
}

#[test]
fn daily_digest_cursor_round_trips_by_key() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let mut store = StateStore::open(StateStoreConfig::for_path(temp_dir.path().join("state.db")))
        .expect("db should open")
        .store;

    let initial = NotificationCursorRecord {
        cursor_key: "daily_digest:desktop".to_string(),
        unix_ms: 1_763_900_200_000,
    };
    let updated = NotificationCursorRecord {
        cursor_key: "daily_digest:desktop".to_string(),
        unix_ms: 1_763_900_300_000,
    };

    store
        .set_notification_cursor(&initial)
        .expect("initial cursor should persist");
    assert_eq!(
        store.notification_cursor("daily_digest:desktop").unwrap(),
        Some(initial)
    );

    store
        .set_notification_cursor(&updated)
        .expect("updated cursor should replace the prior value");
    assert_eq!(
        store.notification_cursor("daily_digest:desktop").unwrap(),
        Some(updated)
    );
    assert_eq!(
        store.notification_cursor("daily_digest:webhook").unwrap(),
        None
    );
}

#[test]
fn locked_database_retries_then_returns_clean_locked_error() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let db_path = temp_dir.path().join("state.db");
    let config = StateStoreConfig::for_path(db_path.clone())
        .with_busy_timeout_ms(10)
        .with_lock_retry_count(2)
        .with_lock_retry_backoff_ms(5);
    let mut store = StateStore::open(config).expect("db should open").store;
    let lock_connection = hold_exclusive_lock(&db_path);

    let error = store
        .replace_current_findings(&vec![sample_finding("finding-locked", Severity::High)])
        .expect_err("locked write should fail cleanly");

    drop(lock_connection);

    assert!(matches!(error, StateStoreError::Locked { .. }));
}

#[test]
fn sqlite_full_write_returns_clean_disk_full_error() {
    let error = StateStoreError::from(rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_FULL),
        None,
    ));

    assert!(matches!(error, StateStoreError::DiskFull { .. }));
}

#[test]
fn snapshot_round_trip_preserves_special_characters() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let mut store = StateStore::open(StateStoreConfig::for_path(temp_dir.path().join("state.db")))
        .expect("db should open")
        .store;

    let snapshot = ScanSnapshot {
        recorded_at_unix_ms: 1_763_573_200_000,
        summary: ScanSummary {
            total_findings: 1,
            highest_severity: Some(Severity::High),
        },
        findings: vec![Finding {
            id: "finding-special".to_string(),
            detector_id: "state-db-test".to_string(),
            severity: Severity::High,
            category: FindingCategory::Config,
            runtime_confidence: RuntimeConfidence::ActiveRuntime,
            path: "/tmp/中文/路径.json".to_string(),
            line: Some(7),
            evidence: Some("he said \"hello\"".to_string()),
            plain_english_explanation: "line one\nline two".to_string(),
            recommended_action: RecommendedAction {
                label: "review unicode payload".to_string(),
                command_hint: None,
            },
            fixability: Fixability::AdvisoryOnly,
            fix: None,
            owasp_asi: None,
        }],
    };

    store
        .record_scan_snapshot(&snapshot)
        .expect("snapshot should persist");

    assert_eq!(store.latest_scan_snapshot().unwrap(), Some(snapshot));
}

fn sample_snapshot() -> ScanSnapshot {
    ScanSnapshot {
        recorded_at_unix_ms: 1_763_573_000_000,
        summary: ScanSummary {
            total_findings: 2,
            highest_severity: Some(Severity::High),
        },
        findings: vec![
            sample_finding("finding-high", Severity::High),
            sample_finding("finding-low", Severity::Low),
        ],
    }
}

fn sample_finding(id: &str, severity: Severity) -> Finding {
    Finding {
        id: id.to_string(),
        detector_id: "state-db-test".to_string(),
        severity,
        category: FindingCategory::Config,
        runtime_confidence: RuntimeConfidence::ActiveRuntime,
        path: format!("/tmp/{id}.json"),
        line: Some(1),
        evidence: Some("example evidence".to_string()),
        plain_english_explanation: "example explanation".to_string(),
        recommended_action: RecommendedAction {
            label: "review the finding".to_string(),
            command_hint: None,
        },
        fixability: Fixability::AdvisoryOnly,
        fix: None,
        owasp_asi: None,
    }
}

fn baseline_record(path: &str, sha256: &str) -> BaselineRecord {
    BaselineRecord {
        path: path.to_string(),
        sha256: sha256.to_string(),
        approved_at_unix_ms: 1_763_573_000_000,
        source_label: "test-fixture".to_string(),
        git_remote_url: None,
        git_head_sha: None,
    }
}

fn baseline_record_with_source(path: &str, sha256: &str, source_label: &str) -> BaselineRecord {
    BaselineRecord {
        source_label: source_label.to_string(),
        ..baseline_record(path, sha256)
    }
}

fn alert_record(alert_id: &str, finding_id: &str, status: AlertStatus) -> AlertRecord {
    AlertRecord {
        alert_id: alert_id.to_string(),
        finding_id: finding_id.to_string(),
        status,
        created_at_unix_ms: 1_763_573_000_000,
        finding: sample_finding(finding_id, Severity::High),
    }
}

fn restore_payload_record(
    path: &str,
    sha256: &str,
    source_label: &str,
    content: &str,
) -> RestorePayloadRecord {
    RestorePayloadRecord {
        path: path.to_string(),
        sha256: sha256.to_string(),
        captured_at_unix_ms: 1_763_573_000_000,
        source_label: source_label.to_string(),
        content: content.to_string(),
    }
}

fn hold_exclusive_lock(path: &std::path::Path) -> Connection {
    let connection = Connection::open(path).expect("lock connection should open");
    connection
        .busy_timeout(Duration::from_millis(10))
        .expect("busy timeout should be configured");
    connection
        .execute_batch("BEGIN EXCLUSIVE;")
        .expect("exclusive transaction should start");

    connection
}
