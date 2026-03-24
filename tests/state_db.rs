use std::fs;
use std::time::Duration;

use clawguard::scan::{
    Finding, FindingCategory, Fixability, RecommendedAction, RuntimeConfidence, ScanSummary,
    Severity,
};
use clawguard::state::db::{StateStore, StateStoreConfig, StateStoreError};
use clawguard::state::model::{
    AlertRecord, AlertStatus, BaselineRecord, RestorePayloadRecord, ScanSnapshot, StateWarningKind,
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
    }
}

fn baseline_record(path: &str, sha256: &str) -> BaselineRecord {
    BaselineRecord {
        path: path.to_string(),
        sha256: sha256.to_string(),
        approved_at_unix_ms: 1_763_573_000_000,
        source_label: "test-fixture".to_string(),
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
