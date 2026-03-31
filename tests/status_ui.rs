use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use clawguard::scan::{
    Finding, FindingCategory, Fixability, RecommendedAction, RuntimeConfidence, ScanSummary,
    Severity,
};
use clawguard::state::db::{StateStore, StateStoreConfig};
use clawguard::state::model::{
    AlertRecord, AlertStatus, ScanSnapshot, StateWarning, StateWarningKind,
};
use serde_json::Value;
use tempfile::tempdir;

fn fixture_path(relative: &str) -> PathBuf {
    Path::new("tests").join("fixtures").join(relative)
}

fn stderr_text(assert: &assert_cmd::assert::Assert) -> String {
    String::from_utf8_lossy(&assert.get_output().stderr).into_owned()
}

fn stdout_text(assert: &assert_cmd::assert::Assert) -> String {
    String::from_utf8_lossy(&assert.get_output().stdout).into_owned()
}

fn prepare_openclaw_home() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let temp_dir = tempdir().expect("temp dir should be created");
    let home_dir = temp_dir.path().join("home");
    let state_dir = home_dir.join(".openclaw");
    fs::create_dir_all(&state_dir).expect("openclaw state dir should exist");

    fs::copy(
        fixture_path("openclaw/insecure-openclaw.json"),
        state_dir.join("openclaw.json"),
    )
    .expect("openclaw config fixture should copy");
    fs::copy(
        fixture_path("openclaw/insecure-exec-approvals.json"),
        state_dir.join("exec-approvals.json"),
    )
    .expect("exec approvals fixture should copy");

    (temp_dir, home_dir, state_dir)
}

fn bootstrap_saved_config(home_dir: &Path) {
    Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", home_dir)
        .args(["scan", "--no-interactive"])
        .assert()
        .success();
}

fn approve_baseline(home_dir: &Path) {
    Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", home_dir)
        .args(["baseline", "approve"])
        .assert()
        .success();
}

fn open_state_store(home_dir: &Path) -> StateStore {
    StateStore::open(StateStoreConfig::for_path(
        home_dir.join(".clawguard").join("state.db"),
    ))
    .expect("state db should open")
    .store
}

fn append_alert(
    home_dir: &Path,
    alert_id: &str,
    path: &Path,
    status: AlertStatus,
    created_at_unix_ms: u64,
) {
    let mut store = open_state_store(home_dir);
    store
        .append_alert(&AlertRecord {
            alert_id: alert_id.to_string(),
            finding_id: format!("baseline:modified:{}", path.display()),
            status,
            created_at_unix_ms,
            finding: drift_finding(&path.display().to_string()),
        })
        .expect("alert should persist");
}

fn record_latest_snapshot(home_dir: &Path, warning: Option<&str>) {
    let mut store = open_state_store(home_dir);
    let findings = vec![Finding {
        id: "snapshot-finding".to_string(),
        detector_id: "snapshot-test".to_string(),
        severity: Severity::Medium,
        category: FindingCategory::Config,
        runtime_confidence: RuntimeConfidence::ActiveRuntime,
        path: "/tmp/snapshot.json".to_string(),
        line: Some(1),
        evidence: Some("example snapshot evidence".to_string()),
        plain_english_explanation: "example snapshot explanation".to_string(),
        recommended_action: RecommendedAction {
            label: "review snapshot".to_string(),
            command_hint: Some("clawguard scan".to_string()),
        },
        fixability: Fixability::AdvisoryOnly,
        fix: None,
        owasp_asi: None,
    }];
    let snapshot = ScanSnapshot {
        recorded_at_unix_ms: 1_764_100_000_000,
        summary: ScanSummary {
            total_findings: findings.len(),
            highest_severity: Some(Severity::Medium),
        },
        findings,
    };
    store
        .record_scan_snapshot(&snapshot)
        .expect("snapshot should persist");

    if let Some(message) = warning {
        store
            .record_scan_snapshot_and_replace_current_findings(&ScanSnapshot {
                recorded_at_unix_ms: 1_764_100_000_001,
                summary: ScanSummary {
                    total_findings: 0,
                    highest_severity: None,
                },
                findings: vec![],
            })
            .expect("snapshot refresh should succeed");
        let _ = StateWarning {
            kind: StateWarningKind::DatabaseCorruptRecreated,
            message: message.to_string(),
            path: None,
        };
    }
}

fn drift_finding(path: &str) -> Finding {
    Finding {
        id: format!("baseline:modified:{path}"),
        detector_id: "baseline".to_string(),
        severity: Severity::High,
        category: FindingCategory::Drift,
        runtime_confidence: RuntimeConfidence::ActiveRuntime,
        path: path.to_string(),
        line: None,
        evidence: Some("approved=aaa,current=bbb".to_string()),
        plain_english_explanation:
            "This file differs from the approved baseline and should be reviewed.".to_string(),
        recommended_action: RecommendedAction {
            label: "Review the changed file".to_string(),
            command_hint: Some("clawguard trust openclaw-config".to_string()),
        },
        fixability: Fixability::Manual,
        fix: None,
        owasp_asi: None,
    }
}

#[test]
fn root_with_saved_config_renders_status_view_from_persisted_state() {
    let (_temp_dir, home_dir, state_dir) = prepare_openclaw_home();
    let config_path = state_dir.join("openclaw.json");

    bootstrap_saved_config(&home_dir);
    approve_baseline(&home_dir);
    record_latest_snapshot(&home_dir, None);
    append_alert(
        &home_dir,
        "alert-openclaw-config",
        &config_path,
        AlertStatus::Open,
        1_764_100_010_000,
    );

    let assert = Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .assert()
        .success();
    let stdout = stdout_text(&assert);

    assert!(
        stdout.contains("Open alerts"),
        "human root output should switch to a persisted status view when saved config exists"
    );
    assert!(
        stdout.contains("alert-openclaw-config"),
        "status view should surface persisted alert ids so operators can ignore or trust them deliberately"
    );
    assert!(
        stdout.contains("clawguard trust openclaw-config"),
        "status view should point operators at the narrow trust command instead of silently remediating"
    );
}

#[test]
fn explicit_status_command_renders_the_same_human_status_view() {
    let (_temp_dir, home_dir, state_dir) = prepare_openclaw_home();
    let config_path = state_dir.join("openclaw.json");

    bootstrap_saved_config(&home_dir);
    approve_baseline(&home_dir);
    append_alert(
        &home_dir,
        "alert-explicit-status",
        &config_path,
        AlertStatus::Open,
        1_764_100_015_000,
    );

    let assert = Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .arg("status")
        .assert()
        .success();
    let stdout = stdout_text(&assert);

    assert!(stdout.contains("ClawGuard Status"));
    assert!(stdout.contains("Open alerts"));
    assert!(stdout.contains("alert-explicit-status"));
}

#[test]
fn status_without_snapshot_shows_onboarding_hints() {
    let (_temp_dir, home_dir, _state_dir) = prepare_openclaw_home();

    bootstrap_saved_config(&home_dir);

    let assert = Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .arg("status")
        .assert()
        .success();
    let stdout = stdout_text(&assert);

    assert!(stdout.contains("No snapshot recorded yet"));
    assert!(stdout.contains("clawguard baseline approve"));
    assert!(stdout.contains("clawguard watch"));
}

#[test]
fn root_json_stays_scan_compatible() {
    let (_temp_dir, home_dir, _state_dir) = prepare_openclaw_home();
    bootstrap_saved_config(&home_dir);

    let assert = Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .arg("--json")
        .assert()
        .success();
    let parsed: Value = serde_json::from_str(stdout_text(&assert).trim())
        .expect("root json output should be valid json");

    assert!(
        parsed.get("summary").is_some() && parsed.get("findings").is_some(),
        "root --json must retain the findings-first scan contract for automation compatibility"
    );
    assert!(
        parsed.get("mode").is_none(),
        "root --json should not silently switch to the new status contract"
    );
}

#[test]
fn status_json_exposes_persisted_state_contract() {
    let (_temp_dir, home_dir, state_dir) = prepare_openclaw_home();
    let config_path = state_dir.join("openclaw.json");
    let approvals_path = state_dir.join("exec-approvals.json");

    bootstrap_saved_config(&home_dir);
    approve_baseline(&home_dir);
    record_latest_snapshot(&home_dir, None);
    append_alert(
        &home_dir,
        "alert-open",
        &config_path,
        AlertStatus::Open,
        1_764_100_020_000,
    );
    append_alert(
        &home_dir,
        "alert-ack",
        &approvals_path,
        AlertStatus::Acknowledged,
        1_764_100_010_000,
    );

    let assert = Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args(["status", "--json"])
        .assert()
        .success();
    let parsed: Value = serde_json::from_str(stdout_text(&assert).trim())
        .expect("status json output should be valid json");

    assert_eq!(parsed["mode"].as_str(), Some("status"));
    assert_eq!(parsed["open_alert_count"].as_u64(), Some(1));
    assert_eq!(parsed["acknowledged_alert_count"].as_u64(), Some(1));
    assert_eq!(parsed["baseline_count"].as_u64(), Some(2));
    assert_eq!(
        parsed["latest_snapshot_summary"]["total_findings"].as_u64(),
        Some(1)
    );
    assert!(
        parsed["trust_targets"].as_array().is_some_and(|targets| {
            targets
                .iter()
                .any(|value| value.as_str() == Some("openclaw-config"))
                && targets
                    .iter()
                    .any(|value| value.as_str() == Some("exec-approvals"))
        }),
        "status json should enumerate the narrow allowlisted trust targets"
    );
    assert!(
        parsed["warnings"].is_array(),
        "status json should always include a warnings array"
    );
}

#[test]
fn alerts_json_exposes_recent_alerts_and_warnings_contract() {
    let (_temp_dir, home_dir, state_dir) = prepare_openclaw_home();
    let config_path = state_dir.join("openclaw.json");

    bootstrap_saved_config(&home_dir);
    append_alert(
        &home_dir,
        "alert-json",
        &config_path,
        AlertStatus::Open,
        1_764_100_025_000,
    );

    let assert = Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args(["alerts", "--json"])
        .assert()
        .success();
    let parsed: Value = serde_json::from_str(stdout_text(&assert).trim())
        .expect("alerts json output should be valid json");

    assert_eq!(parsed["mode"].as_str(), Some("alerts"));
    assert!(parsed["alerts"].is_array());
    assert!(parsed["warnings"].is_array());
    assert!(
        parsed["alerts"].as_array().is_some_and(|alerts| alerts
            .iter()
            .any(|alert| alert["alert_id"].as_str() == Some("alert-json"))),
        "alerts json should enumerate recent persisted alerts"
    );
}

#[test]
fn alerts_command_renders_recent_persisted_alerts() {
    let (_temp_dir, home_dir, state_dir) = prepare_openclaw_home();
    let config_path = state_dir.join("openclaw.json");
    let approvals_path = state_dir.join("exec-approvals.json");

    bootstrap_saved_config(&home_dir);
    append_alert(
        &home_dir,
        "alert-newest",
        &config_path,
        AlertStatus::Open,
        1_764_100_030_000,
    );
    append_alert(
        &home_dir,
        "alert-history",
        &approvals_path,
        AlertStatus::Acknowledged,
        1_764_100_020_000,
    );

    let assert = Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .arg("alerts")
        .assert()
        .success();
    let stdout = stdout_text(&assert);

    assert!(
        stdout.contains("Recent alerts"),
        "alerts command should render a dedicated recent-alert history view"
    );
    assert!(
        stdout.contains("alert-newest") && stdout.contains("alert-history"),
        "alerts view should surface persisted alert ids so operators can trace and ignore them"
    );
}

#[test]
fn alerts_ignore_acknowledges_one_alert() {
    let (_temp_dir, home_dir, state_dir) = prepare_openclaw_home();
    let config_path = state_dir.join("openclaw.json");

    bootstrap_saved_config(&home_dir);
    append_alert(
        &home_dir,
        "alert-open",
        &config_path,
        AlertStatus::Open,
        1_764_100_040_000,
    );

    let assert = Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args(["alerts", "ignore", "alert-open", "--json"])
        .assert()
        .success();
    let parsed: Value = serde_json::from_str(stdout_text(&assert).trim())
        .expect("alerts ignore json output should be valid json");

    assert_eq!(parsed["alert_id"].as_str(), Some("alert-open"));
    assert_eq!(parsed["previous_status"].as_str(), Some("open"));
    assert_eq!(parsed["new_status"].as_str(), Some("acknowledged"));
    assert!(
        parsed["warnings"].is_array(),
        "alerts ignore json should include a warnings array for consistency with other operational commands"
    );

    let store = open_state_store(&home_dir);
    let ignored = store
        .list_unresolved_alerts()
        .expect("unresolved alerts should load")
        .into_iter()
        .find(|alert| alert.alert_id == "alert-open")
        .expect("acknowledged alert should remain queryable in history");
    assert_eq!(ignored.status, AlertStatus::Acknowledged);
}

#[test]
fn status_requires_a_detected_runtime() {
    let (_temp_dir, home_dir, state_dir) = prepare_openclaw_home();

    bootstrap_saved_config(&home_dir);
    fs::remove_dir_all(&state_dir).expect("runtime state should be removable for the test");

    let assert = Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .arg("status")
        .assert()
        .failure();
    let stderr = stderr_text(&assert);

    assert!(stderr.contains("requires a detected supported runtime"));
}

#[test]
fn trust_requires_a_detected_runtime() {
    let (_temp_dir, home_dir, state_dir) = prepare_openclaw_home();

    bootstrap_saved_config(&home_dir);
    approve_baseline(&home_dir);
    fs::remove_dir_all(&state_dir).expect("runtime state should be removable for the test");

    let assert = Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args(["trust", "openclaw-config"])
        .assert()
        .failure();
    let stderr = stderr_text(&assert);

    assert!(stderr.contains("requires a detected supported runtime"));
}

#[test]
fn trust_openclaw_config_restores_payload_and_resolves_matching_alerts() {
    let (_temp_dir, home_dir, state_dir) = prepare_openclaw_home();
    let config_path = state_dir.join("openclaw.json");
    let approvals_path = state_dir.join("exec-approvals.json");
    let approved_content =
        fs::read_to_string(&config_path).expect("fixture content should be readable before drift");

    bootstrap_saved_config(&home_dir);
    approve_baseline(&home_dir);
    fs::write(&config_path, "{ drifted: true }").expect("drifted config should be written");
    append_alert(
        &home_dir,
        "alert-config",
        &config_path,
        AlertStatus::Open,
        1_764_100_050_000,
    );
    append_alert(
        &home_dir,
        "alert-other",
        &approvals_path,
        AlertStatus::Open,
        1_764_100_049_000,
    );

    let assert = Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args(["trust", "openclaw-config", "--json"])
        .assert()
        .success();
    let parsed: Value = serde_json::from_str(stdout_text(&assert).trim())
        .expect("trust json output should be valid json");

    assert_eq!(parsed["trust_target"].as_str(), Some("openclaw-config"));
    assert_eq!(
        parsed["restored_path"].as_str(),
        Some(config_path.display().to_string().as_str())
    );
    assert_eq!(parsed["resolved_alert_count"].as_u64(), Some(1));
    assert_eq!(
        fs::read_to_string(&config_path).expect("restored file should be readable"),
        approved_content
    );

    let store = open_state_store(&home_dir);
    let remaining = store
        .list_unresolved_alerts()
        .expect("unresolved alerts should load");
    assert!(
        remaining
            .iter()
            .all(|alert| alert.alert_id != "alert-config"),
        "trust should resolve only the drift alert for the exact restored path"
    );
    assert!(
        remaining
            .iter()
            .any(|alert| alert.alert_id == "alert-other"),
        "trust should not resolve unrelated alerts just because they are also drift findings"
    );
}

#[test]
fn trust_exec_approvals_restores_payload_and_resolves_matching_alerts() {
    let (_temp_dir, home_dir, state_dir) = prepare_openclaw_home();
    let approvals_path = state_dir.join("exec-approvals.json");
    let approved_content = fs::read_to_string(&approvals_path)
        .expect("fixture approvals content should be readable before drift");

    bootstrap_saved_config(&home_dir);
    approve_baseline(&home_dir);
    fs::write(&approvals_path, "{ drifted: true }")
        .expect("drifted exec approvals should be written");
    append_alert(
        &home_dir,
        "alert-approvals",
        &approvals_path,
        AlertStatus::Open,
        1_764_100_060_000,
    );

    let assert = Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args(["trust", "exec-approvals", "--json"])
        .assert()
        .success();
    let parsed: Value = serde_json::from_str(stdout_text(&assert).trim())
        .expect("trust json output should be valid json");

    assert_eq!(parsed["trust_target"].as_str(), Some("exec-approvals"));
    assert_eq!(parsed["resolved_alert_count"].as_u64(), Some(1));
    assert_eq!(
        fs::read_to_string(&approvals_path).expect("restored file should be readable"),
        approved_content
    );
}

#[test]
fn unknown_trust_target_fails_clearly() {
    let (_temp_dir, home_dir, _state_dir) = prepare_openclaw_home();
    bootstrap_saved_config(&home_dir);

    let assert = Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args(["trust", "totally-unknown"])
        .assert()
        .failure();
    let stderr = stderr_text(&assert);

    assert!(
        stderr.contains("unknown trust target"),
        "unknown trust targets should fail with an explicit narrow-allowlist error"
    );
}

#[test]
fn trust_fails_when_no_approved_payload_exists() {
    let (_temp_dir, home_dir, _state_dir) = prepare_openclaw_home();
    bootstrap_saved_config(&home_dir);

    let assert = Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args(["trust", "openclaw-config"])
        .assert()
        .failure();
    let stderr = stderr_text(&assert);

    assert!(
        stderr.contains("no approved restore payload"),
        "trust should fail clearly instead of silently restoring from an unapproved source"
    );
}
