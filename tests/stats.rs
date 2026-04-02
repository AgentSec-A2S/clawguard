use clawguard::scan::ScanSummary;
use clawguard::scan::{Finding, FindingCategory, Fixability, RecommendedAction, Severity};
use clawguard::state::db::{StateStore, StateStoreConfig};
use clawguard::state::model::{AlertRecord, AlertStatus, ScanSnapshot};
use tempfile::TempDir;

fn setup_state() -> (TempDir, StateStore) {
    let dir = tempfile::tempdir().expect("temp dir");
    let db_path = dir.path().join("state.db");
    let result = StateStore::open(StateStoreConfig::for_path(db_path)).expect("open state");
    (dir, result.store)
}

fn make_finding(id: &str, severity: Severity) -> Finding {
    Finding {
        id: id.to_string(),
        detector_id: "test-detector".to_string(),
        severity,
        category: FindingCategory::Config,
        path: "/test/path".to_string(),
        line: None,
        evidence: Some("test evidence".to_string()),
        plain_english_explanation: "Test finding".to_string(),
        recommended_action: RecommendedAction {
            label: "Review this finding".to_string(),
            command_hint: None,
        },
        fixability: Fixability::Manual,
        runtime_confidence: clawguard::scan::RuntimeConfidence::ActiveRuntime,
        owasp_asi: None,
        fix: None,
    }
}

fn make_snapshot(total: usize, severity: Option<Severity>) -> ScanSnapshot {
    let mut findings = Vec::new();
    for i in 0..total {
        findings.push(make_finding(
            &format!("f-{i}"),
            severity.unwrap_or(Severity::Medium),
        ));
    }
    ScanSnapshot {
        recorded_at_unix_ms: now_ms(),
        summary: ScanSummary {
            total_findings: total,
            highest_severity: severity,
        },
        findings,
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ---- Stats query tests ----

#[test]
fn stats_empty_db() {
    let (_dir, store) = setup_state();

    let scan_stats = store.count_scan_snapshots(None).unwrap();
    assert_eq!(scan_stats.total, 0);
    assert!(scan_stats.first_at_unix_ms.is_none());
    assert!(scan_stats.last_at_unix_ms.is_none());

    let alert_stats = store.count_alerts_by_status(None).unwrap();
    assert_eq!(alert_stats.open, 0);
    assert_eq!(alert_stats.acknowledged, 0);
    assert_eq!(alert_stats.resolved, 0);

    let baseline_count = store.count_baselines(None).unwrap();
    assert_eq!(baseline_count, 0);

    let audit_by_cat = store.count_audit_events_by_category(None).unwrap();
    assert!(audit_by_cat.is_empty());
}

#[test]
fn stats_basic_output() {
    let (_dir, mut store) = setup_state();

    // Insert 3 snapshots
    for _ in 0..3 {
        let snap = make_snapshot(2, Some(Severity::High));
        store.record_scan_snapshot(&snap).unwrap();
    }

    // Insert current findings
    let findings = vec![
        make_finding("cur-1", Severity::High),
        make_finding("cur-2", Severity::Medium),
        make_finding("cur-3", Severity::Medium),
    ];
    store.replace_current_findings(&findings).unwrap();

    let scan_stats = store.count_scan_snapshots(None).unwrap();
    assert_eq!(scan_stats.total, 3);
    assert!(scan_stats.first_at_unix_ms.is_some());
    assert!(scan_stats.last_at_unix_ms.is_some());

    let current = store.list_current_findings().unwrap();
    assert_eq!(current.len(), 3);
}

#[test]
fn stats_since_filter() {
    let (_dir, mut store) = setup_state();

    // Insert old snapshot (simulated via direct SQL)
    let old_snap = ScanSnapshot {
        recorded_at_unix_ms: 1000,
        summary: ScanSummary {
            total_findings: 5,
            highest_severity: Some(Severity::High),
        },
        findings: vec![],
    };
    store.record_scan_snapshot(&old_snap).unwrap();

    // Insert recent snapshot
    let recent_snap = make_snapshot(2, Some(Severity::Medium));
    store.record_scan_snapshot(&recent_snap).unwrap();

    // Filter since recent time — should count only 1
    let since = now_ms() - 5_000; // 5 seconds ago
    let stats = store.count_scan_snapshots(Some(since)).unwrap();
    assert_eq!(stats.total, 1, "only recent snapshot should count");

    // Without filter — should count both
    let all_stats = store.count_scan_snapshots(None).unwrap();
    assert_eq!(all_stats.total, 2);
}

#[test]
fn stats_json_output_structure() {
    let (_dir, mut store) = setup_state();

    let snap = make_snapshot(3, Some(Severity::High));
    store.record_scan_snapshot(&snap).unwrap();

    // Verify alert stats with mixed statuses
    let alert1 = AlertRecord {
        alert_id: "a-1".to_string(),
        finding_id: "f-1".to_string(),
        status: AlertStatus::Open,
        created_at_unix_ms: now_ms(),
        finding: make_finding("f-1", Severity::High),
    };
    let alert2 = AlertRecord {
        alert_id: "a-2".to_string(),
        finding_id: "f-2".to_string(),
        status: AlertStatus::Resolved,
        created_at_unix_ms: now_ms(),
        finding: make_finding("f-2", Severity::Medium),
    };
    store.append_alert(&alert1).unwrap();
    store.append_alert(&alert2).unwrap();
    store
        .update_alert_status("a-2", AlertStatus::Resolved)
        .unwrap();

    let alert_stats = store.count_alerts_by_status(None).unwrap();
    assert_eq!(alert_stats.open, 1);
    assert_eq!(alert_stats.resolved, 1);
}

#[test]
fn stats_trend_improved() {
    let (_dir, mut store) = setup_state();

    // Earliest snapshot: 5 findings
    let early = ScanSnapshot {
        recorded_at_unix_ms: now_ms() - 60_000,
        summary: ScanSummary {
            total_findings: 5,
            highest_severity: Some(Severity::High),
        },
        findings: vec![],
    };
    store.record_scan_snapshot(&early).unwrap();

    // Latest snapshot: 3 findings
    let latest = make_snapshot(3, Some(Severity::Medium));
    store.record_scan_snapshot(&latest).unwrap();

    // Replace current findings with 3
    let findings = vec![
        make_finding("cur-1", Severity::Medium),
        make_finding("cur-2", Severity::Medium),
        make_finding("cur-3", Severity::Low),
    ];
    store.replace_current_findings(&findings).unwrap();

    // Verify trend: earliest had 5, current has 3 → improved
    let earliest = store.earliest_scan_snapshot(None).unwrap().unwrap();
    assert_eq!(earliest.summary.total_findings, 5);

    let current = store.list_current_findings().unwrap();
    assert_eq!(current.len(), 3);
    assert!(
        current.len() < earliest.summary.total_findings,
        "should show improvement"
    );
}
