use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use clawguard::config::schema::AlertStrategy;
use clawguard::config::store::{load_config_from_path, save_config_for_home};
use clawguard::state::db::{StateStore, StateStoreConfig};
use clawguard::state::model::NotificationCursorRecord;
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

fn open_state_store(home_dir: &Path) -> StateStore {
    StateStore::open(StateStoreConfig::for_path(
        home_dir.join(".clawguard").join("state.db"),
    ))
    .expect("state db should open")
    .store
}

fn set_saved_alert_strategy(home_dir: &Path, strategy: AlertStrategy, webhook_url: Option<&str>) {
    let config_path = home_dir.join(".clawguard").join("config.toml");
    let mut config = load_config_from_path(&config_path)
        .expect("saved config should load")
        .expect("saved config should exist");
    config.alert_strategy = strategy;
    config.webhook_url = webhook_url.map(str::to_string);
    save_config_for_home(&config, home_dir).expect("config should save");
}

fn set_notification_cursor(home_dir: &Path, route_key: &str, unix_ms: u64) {
    let mut store = open_state_store(home_dir);
    store
        .set_notification_cursor(&NotificationCursorRecord {
            cursor_key: format!("daily_digest:{route_key}"),
            unix_ms,
        })
        .expect("notification cursor should save");
}

fn mutate_openclaw_config(state_dir: &Path) {
    let config_path = state_dir.join("openclaw.json");
    let original = fs::read_to_string(&config_path).expect("openclaw config should be readable");
    fs::write(
        &config_path,
        format!("{original}\n// task13 drift fixture\n"),
    )
    .expect("openclaw config mutation should persist");
}

#[test]
fn baseline_approve_persists_baselines_and_restore_payloads() {
    let (_temp_dir, home_dir, state_dir) = prepare_openclaw_home();
    bootstrap_saved_config(&home_dir);

    Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args(["baseline", "approve"])
        .assert()
        .success();

    let store = open_state_store(&home_dir);
    let config_path = state_dir.join("openclaw.json").display().to_string();
    let approvals_path = state_dir.join("exec-approvals.json").display().to_string();

    assert!(
        store
            .baseline_for_path(&config_path)
            .expect("baseline lookup should succeed")
            .is_some(),
        "baseline approve should persist an approved baseline for openclaw.json"
    );
    assert!(
        store
            .baseline_for_path(&approvals_path)
            .expect("baseline lookup should succeed")
            .is_some(),
        "baseline approve should persist an approved baseline for exec-approvals.json"
    );
    assert!(
        store
            .restore_payload_for_path(&config_path)
            .expect("restore payload lookup should succeed")
            .is_some(),
        "baseline approve should persist a restore payload for openclaw.json"
    );
    assert!(
        store
            .restore_payload_for_path(&approvals_path)
            .expect("restore payload lookup should succeed")
            .is_some(),
        "baseline approve should persist a restore payload for exec-approvals.json"
    );
}

#[test]
fn watch_command_runs_cold_boot_and_records_snapshot() {
    let (_temp_dir, home_dir, _state_dir) = prepare_openclaw_home();
    bootstrap_saved_config(&home_dir);

    let store_before = open_state_store(&home_dir);
    assert!(
        store_before
            .latest_scan_snapshot()
            .expect("snapshot lookup should succeed")
            .is_none(),
        "watch command should be the thing that writes the first daemon snapshot in this scenario"
    );

    Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args(["watch", "--iterations", "1", "--poll-interval-ms", "0"])
        .assert()
        .success();

    let store_after = open_state_store(&home_dir);
    let snapshot = store_after
        .latest_scan_snapshot()
        .expect("snapshot lookup should succeed");
    assert!(
        snapshot.is_some(),
        "watch command should run the cold-boot scan and record a daemon snapshot"
    );
}

#[test]
fn baseline_approve_json_is_machine_readable() {
    let (_temp_dir, home_dir, _state_dir) = prepare_openclaw_home();
    bootstrap_saved_config(&home_dir);

    let assert = Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args(["baseline", "approve", "--json"])
        .assert()
        .success();
    let stdout = stdout_text(&assert);

    let parsed: Value = serde_json::from_str(&stdout).expect("output should be valid json");
    assert!(
        parsed["baseline_count"]
            .as_u64()
            .is_some_and(|count| count >= 2),
        "baseline approve json should report the number of approved baseline artifacts"
    );
    assert!(
        parsed["restore_payload_count"]
            .as_u64()
            .is_some_and(|count| count >= 2),
        "baseline approve json should report the number of restore payloads captured"
    );
    assert!(
        parsed["state_db_path"].as_str().is_some(),
        "baseline approve json should include the state db path"
    );
}

#[test]
fn watch_json_warns_when_no_approved_baseline_exists() {
    let (_temp_dir, home_dir, _state_dir) = prepare_openclaw_home();
    bootstrap_saved_config(&home_dir);

    let assert = Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args([
            "watch",
            "--iterations",
            "1",
            "--poll-interval-ms",
            "0",
            "--json",
        ])
        .assert()
        .success();
    let stdout = stdout_text(&assert);
    let parsed: Value = serde_json::from_str(stdout.trim()).expect("output should be valid json");
    let warnings = parsed["warnings"]
        .as_array()
        .expect("watch json should include a warnings array");

    assert!(
        warnings.iter().any(|warning| {
            warning["message"].as_str().is_some_and(|message| {
                message.contains("no approved baselines exist yet")
                    && message.contains("baseline approve")
            })
        }),
        "watch should explicitly warn when the runtime has no approved baseline yet"
    );
    assert!(
        parsed["cold_boot"].is_object(),
        "single-iteration watch json should include the cold-boot outcome"
    );
}

#[test]
fn watch_json_reports_cold_boot_only_once_across_multiple_iterations() {
    let (_temp_dir, home_dir, _state_dir) = prepare_openclaw_home();
    bootstrap_saved_config(&home_dir);

    Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args(["baseline", "approve"])
        .assert()
        .success();

    let assert = Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args([
            "watch",
            "--iterations",
            "2",
            "--poll-interval-ms",
            "0",
            "--json",
        ])
        .assert()
        .success();
    let stdout = stdout_text(&assert);
    let lines: Vec<_> = stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();

    assert_eq!(lines.len(), 2, "two iterations should emit two json lines");

    let first: Value = serde_json::from_str(lines[0]).expect("first line should be valid json");
    let second: Value = serde_json::from_str(lines[1]).expect("second line should be valid json");

    assert_eq!(first["iteration"].as_u64(), Some(1));
    assert_eq!(second["iteration"].as_u64(), Some(2));
    assert!(
        first["cold_boot"].is_object(),
        "the first iteration should include the cold-boot payload"
    );
    assert!(
        second["cold_boot"].is_null(),
        "subsequent iterations should not rerun the cold-boot path"
    );
}

#[test]
fn baseline_approve_requires_saved_config() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let home_dir = temp_dir.path().join("home");
    fs::create_dir_all(&home_dir).expect("home dir should exist");

    let assert = Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args(["baseline", "approve"])
        .assert()
        .failure();
    let stderr = stderr_text(&assert);

    assert!(stderr.contains("requires saved configuration"));
}

#[test]
fn watch_requires_saved_config() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let home_dir = temp_dir.path().join("home");
    fs::create_dir_all(&home_dir).expect("home dir should exist");

    let assert = Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .arg("watch")
        .assert()
        .failure();
    let stderr = stderr_text(&assert);

    assert!(stderr.contains("requires saved configuration"));
}

#[test]
fn watch_log_only_records_notification_receipt_for_new_alert() {
    let (_temp_dir, home_dir, state_dir) = prepare_openclaw_home();
    bootstrap_saved_config(&home_dir);

    Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args(["baseline", "approve"])
        .assert()
        .success();
    set_saved_alert_strategy(&home_dir, AlertStrategy::LogOnly, None);
    mutate_openclaw_config(&state_dir);

    let assert = Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args([
            "watch",
            "--iterations",
            "1",
            "--poll-interval-ms",
            "0",
            "--json",
        ])
        .assert()
        .success();
    let stdout = stdout_text(&assert);
    let parsed: Value = serde_json::from_str(stdout.trim()).expect("output should be valid json");

    assert_eq!(parsed["alerts_notified"].as_u64(), Some(1));
    assert!(
        parsed["notification_logs"]
            .as_array()
            .is_some_and(|logs| logs.len() == 1),
        "log-only alert delivery should surface one notification log line"
    );

    let store = open_state_store(&home_dir);
    let alert = store
        .list_unresolved_alerts()
        .expect("unresolved alerts should load")
        .into_iter()
        .next()
        .expect("watch should persist one unresolved drift alert");
    assert!(
        store
            .notification_receipt_for_alert(&alert.alert_id, "log_only")
            .expect("receipt lookup should succeed")
            .is_some(),
        "handled log-only notifications should record a per-route receipt"
    );
}

#[test]
fn watch_restart_does_not_redeliver_alerts_with_receipts() {
    let (_temp_dir, home_dir, state_dir) = prepare_openclaw_home();
    bootstrap_saved_config(&home_dir);

    Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args(["baseline", "approve"])
        .assert()
        .success();
    set_saved_alert_strategy(&home_dir, AlertStrategy::LogOnly, None);
    mutate_openclaw_config(&state_dir);

    let first = Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args([
            "watch",
            "--iterations",
            "1",
            "--poll-interval-ms",
            "0",
            "--json",
        ])
        .assert()
        .success();
    let first_output: Value = serde_json::from_str(stdout_text(&first).trim())
        .expect("first output should be valid json");
    assert_eq!(first_output["alerts_notified"].as_u64(), Some(1));

    let second = Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args([
            "watch",
            "--iterations",
            "1",
            "--poll-interval-ms",
            "0",
            "--json",
        ])
        .assert()
        .success();
    let second_output: Value = serde_json::from_str(stdout_text(&second).trim())
        .expect("second output should be valid json");
    assert_eq!(second_output["alerts_notified"].as_u64(), Some(0));
    assert!(
        second_output["notification_logs"]
            .as_array()
            .is_some_and(|logs| logs.is_empty()),
        "alerts with existing receipts should not be redelivered on restart"
    );
}

#[test]
fn watch_continues_when_notification_delivery_warns() {
    let (_temp_dir, home_dir, state_dir) = prepare_openclaw_home();
    bootstrap_saved_config(&home_dir);

    Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args(["baseline", "approve"])
        .assert()
        .success();
    set_saved_alert_strategy(&home_dir, AlertStrategy::Webhook, None);
    mutate_openclaw_config(&state_dir);

    let assert = Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args([
            "watch",
            "--iterations",
            "1",
            "--poll-interval-ms",
            "0",
            "--json",
        ])
        .assert()
        .success();
    let parsed: Value =
        serde_json::from_str(stdout_text(&assert).trim()).expect("output should be valid json");
    let warnings = parsed["warnings"]
        .as_array()
        .expect("watch json should include warnings");

    assert_eq!(parsed["alerts_notified"].as_u64(), Some(0));
    assert!(
        warnings.iter().any(|warning| {
            warning["message"]
                .as_str()
                .is_some_and(|message| message.contains("webhook_url"))
        }),
        "watch should surface delivery warnings without exiting"
    );

    let store = open_state_store(&home_dir);
    let alert = store
        .list_unresolved_alerts()
        .expect("unresolved alerts should load")
        .into_iter()
        .next()
        .expect("watch should still persist the unresolved alert");
    assert!(
        store
            .notification_receipt_for_alert(&alert.alert_id, "webhook")
            .expect("receipt lookup should succeed")
            .is_none(),
        "warning-only notification failures must not record receipts"
    );
}

#[test]
fn watch_human_output_reports_notification_state_even_when_idle() {
    let (_temp_dir, home_dir, _state_dir) = prepare_openclaw_home();
    bootstrap_saved_config(&home_dir);

    Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args(["baseline", "approve"])
        .assert()
        .success();
    set_saved_alert_strategy(&home_dir, AlertStrategy::LogOnly, None);

    let assert = Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args(["watch", "--iterations", "1", "--poll-interval-ms", "0"])
        .assert()
        .success();
    let stdout = stdout_text(&assert);

    assert!(
        stdout.contains("notifications handled: 0, daily digest delivered: false"),
        "human watch output should always show the notification status line"
    );
}

#[test]
fn watch_json_reports_daily_digest_when_cursor_is_due() {
    let (_temp_dir, home_dir, state_dir) = prepare_openclaw_home();
    bootstrap_saved_config(&home_dir);

    Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args(["baseline", "approve"])
        .assert()
        .success();
    set_saved_alert_strategy(&home_dir, AlertStrategy::LogOnly, None);
    mutate_openclaw_config(&state_dir);

    let first = Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args([
            "watch",
            "--iterations",
            "1",
            "--poll-interval-ms",
            "0",
            "--json",
        ])
        .assert()
        .success();
    let first_output: Value = serde_json::from_str(stdout_text(&first).trim())
        .expect("first output should be valid json");
    assert_eq!(first_output["alerts_notified"].as_u64(), Some(1));
    assert_eq!(first_output["digest_delivered"].as_bool(), Some(false));

    set_notification_cursor(&home_dir, "log_only", 0);

    let second = Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args([
            "watch",
            "--iterations",
            "1",
            "--poll-interval-ms",
            "0",
            "--json",
        ])
        .assert()
        .success();
    let second_output: Value = serde_json::from_str(stdout_text(&second).trim())
        .expect("second output should be valid json");

    assert_eq!(second_output["alerts_notified"].as_u64(), Some(0));
    assert_eq!(second_output["digest_delivered"].as_bool(), Some(true));
    assert!(
        second_output["notification_logs"]
            .as_array()
            .is_some_and(|logs| logs.iter().any(|line| {
                line.as_str()
                    .is_some_and(|text| text.contains("[clawguard:digest:"))
            })),
        "daily digest delivery should surface a digest log line in the CLI JSON output"
    );
}
