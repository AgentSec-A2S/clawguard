use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use assert_cmd::Command;
use clawguard::config::schema::AlertStrategy;
use clawguard::config::store::{load_config_from_path, save_config_for_home};
use clawguard::state::db::{StateStore, StateStoreConfig};
use clawguard::state::model::{AlertStatus, NotificationCursorRecord};
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

fn spawn_webhook_capture_server() -> (String, mpsc::Receiver<String>, thread::JoinHandle<()>) {
    let listener =
        TcpListener::bind("127.0.0.1:0").expect("webhook capture server should bind locally");
    let addr = listener
        .local_addr()
        .expect("webhook capture server should expose a local address");
    let (sender, receiver) = mpsc::channel();

    let handle = thread::spawn(move || {
        let (mut stream, _) = listener
            .accept()
            .expect("webhook capture server should accept one request");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("webhook capture server should set a read timeout");

        let mut request = Vec::new();
        let mut content_length = None;
        let mut body_start = None;

        loop {
            let mut chunk = [0_u8; 1024];
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(read) => {
                    request.extend_from_slice(&chunk[..read]);

                    if body_start.is_none() {
                        if let Some(idx) =
                            request.windows(4).position(|window| window == b"\r\n\r\n")
                        {
                            let body_offset = idx + 4;
                            let headers = String::from_utf8_lossy(&request[..body_offset]);
                            content_length = headers.lines().find_map(|line| {
                                line.strip_prefix("Content-Length:")
                                    .map(str::trim)
                                    .and_then(|value| value.parse::<usize>().ok())
                            });
                            body_start = Some(body_offset);
                        }
                    }

                    if let (Some(start), Some(expected_len)) = (body_start, content_length) {
                        if request.len() >= start + expected_len {
                            break;
                        }
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    break;
                }
                Err(error) => panic!("webhook capture server should read request: {error}"),
            }
        }

        let request_text = String::from_utf8_lossy(&request);
        let body = body_start
            .map(|start| request_text[start..].to_string())
            .unwrap_or_default();

        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .expect("webhook capture server should return HTTP 200");
        stream.flush().expect("webhook capture server should flush");
        sender
            .send(body)
            .expect("webhook capture server should send captured body");
    });

    (format!("http://{addr}/hook"), receiver, handle)
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
    let canonical_state_dir = state_dir.canonicalize().unwrap_or(state_dir);
    let config_path = canonical_state_dir
        .join("openclaw.json")
        .display()
        .to_string();
    let approvals_path = canonical_state_dir
        .join("exec-approvals.json")
        .display()
        .to_string();

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
fn watch_json_reports_structured_sse_bind_conflict_when_port_is_in_use() {
    let (_temp_dir, home_dir, _state_dir) = prepare_openclaw_home();
    bootstrap_saved_config(&home_dir);

    Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args(["baseline", "approve"])
        .assert()
        .success();

    let occupied_listener =
        TcpListener::bind("127.0.0.1:0").expect("port fixture should bind locally");
    let occupied_port = occupied_listener
        .local_addr()
        .expect("occupied listener should expose a local address")
        .port();

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
            "--sse-port",
            &occupied_port.to_string(),
        ])
        .assert()
        .success();
    let parsed: Value =
        serde_json::from_str(stdout_text(&assert).trim()).expect("output should be valid json");
    let warnings = parsed["warnings"]
        .as_array()
        .expect("watch json should include a warnings array");
    let bind_warning = warnings
        .iter()
        .find(|warning| warning["kind"].as_str() == Some("sse_bind_conflict"))
        .expect("watch json should include a structured SSE bind-conflict warning");

    assert_eq!(bind_warning["bind"].as_str(), Some("127.0.0.1"));
    assert_eq!(bind_warning["port"].as_u64(), Some(occupied_port as u64));
    assert!(
        bind_warning["message"].as_str().is_some_and(|message| {
            message.contains("local SSE server unavailable")
                && message.contains("watch will continue")
        }),
        "bind conflict warning should explain the degraded local-SSE behavior"
    );
    assert!(
        parsed["cold_boot"].is_object(),
        "bind conflicts should not abort the watch cold-boot scan"
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
fn watch_route_change_skips_acknowledged_history_and_delivers_only_fresh_realert() {
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

    let store = open_state_store(&home_dir);
    let original_alert = store
        .list_unresolved_alerts()
        .expect("unresolved alerts should load after first watch")
        .into_iter()
        .find(|alert| alert.status == AlertStatus::Open)
        .expect("first watch should create one open drift alert");
    drop(store);

    let ignored = Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args(["alerts", "ignore", &original_alert.alert_id, "--json"])
        .assert()
        .success();
    let ignored_output: Value = serde_json::from_str(stdout_text(&ignored).trim())
        .expect("alerts ignore output should be valid json");
    assert_eq!(ignored_output["new_status"].as_str(), Some("acknowledged"));

    thread::sleep(Duration::from_millis(10));

    let (webhook_url, webhook_rx, webhook_thread) = spawn_webhook_capture_server();
    set_saved_alert_strategy(&home_dir, AlertStrategy::Webhook, Some(&webhook_url));

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
    assert_eq!(
        second_output["alerts_notified"].as_u64(),
        Some(1),
        "route changes should deliver only the fresh re-alert, not replay acknowledged history"
    );

    let payload_body = webhook_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("webhook route should receive exactly one alert payload");
    webhook_thread
        .join()
        .expect("webhook capture server should shut down cleanly");
    let payload: Value =
        serde_json::from_str(&payload_body).expect("captured webhook body should be valid json");
    let delivered_alert_id = payload["alert_id"]
        .as_str()
        .expect("webhook payload should include alert_id")
        .to_string();
    assert_ne!(
        delivered_alert_id, original_alert.alert_id,
        "newly enabled routes must not replay the previously acknowledged alert"
    );

    let store = open_state_store(&home_dir);
    let original = store
        .alert_by_id(&original_alert.alert_id)
        .expect("original alert lookup should succeed")
        .expect("original alert should still exist");
    assert_eq!(original.status, AlertStatus::Acknowledged);
    assert!(
        store
            .notification_receipt_for_alert(&original_alert.alert_id, "webhook")
            .expect("receipt lookup should succeed")
            .is_none(),
        "acknowledged historical alerts must not get a new-route receipt"
    );
    assert!(
        store
            .notification_receipt_for_alert(&delivered_alert_id, "webhook")
            .expect("receipt lookup should succeed")
            .is_some(),
        "fresh re-alert should record a receipt on the newly enabled route"
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
