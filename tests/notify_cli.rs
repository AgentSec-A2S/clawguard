use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
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

fn prepare_openclaw_home() -> (tempfile::TempDir, PathBuf) {
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

    (temp_dir, home_dir)
}

fn bootstrap_saved_config(home_dir: &Path) {
    Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", home_dir)
        .args(["scan", "--no-interactive"])
        .assert()
        .success();
}

fn read_config_toml(home_dir: &Path) -> String {
    fs::read_to_string(home_dir.join(".clawguard").join("config.toml"))
        .expect("config.toml should exist")
}

// -- show --

#[test]
fn notify_show_requires_config() {
    let temp_dir = tempdir().expect("temp dir");
    let home_dir = temp_dir.path().join("home");
    fs::create_dir_all(&home_dir).unwrap();

    let assert = Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args(["notify"])
        .assert()
        .failure();

    let err = stderr_text(&assert);
    assert!(
        err.contains("clawguard scan"),
        "should tell user to run scan first: {err}"
    );
}

#[test]
fn notify_show_displays_current_config() {
    let (_temp, home_dir) = prepare_openclaw_home();
    bootstrap_saved_config(&home_dir);

    let assert = Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args(["notify"])
        .assert()
        .success();

    let out = stdout_text(&assert);
    assert!(out.contains("Strategy:"), "should show strategy: {out}");
    assert!(out.contains("SSE:"), "should show SSE status: {out}");
    assert!(
        out.contains("Telegram:"),
        "should show Telegram status: {out}"
    );
}

#[test]
fn notify_show_json() {
    let (_temp, home_dir) = prepare_openclaw_home();
    bootstrap_saved_config(&home_dir);

    let assert = Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args(["notify", "--json"])
        .assert()
        .success();

    let out = stdout_text(&assert);
    let json: Value = serde_json::from_str(&out).expect("should be valid JSON");
    assert_eq!(json["mode"], "notify");
    assert!(json["alert_strategy"].is_string());
    assert!(json["sse_port"].is_number());
}

// -- desktop --

#[test]
fn notify_desktop_updates_config() {
    let (_temp, home_dir) = prepare_openclaw_home();
    bootstrap_saved_config(&home_dir);

    Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args(["notify", "desktop"])
        .assert()
        .success();

    let config = read_config_toml(&home_dir);
    assert!(
        config.contains("Desktop"),
        "strategy should be Desktop: {config}"
    );
}

// -- webhook --

#[test]
fn notify_webhook_updates_config() {
    let (_temp, home_dir) = prepare_openclaw_home();
    bootstrap_saved_config(&home_dir);

    Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args(["notify", "webhook", "https://hooks.example.com/test"])
        .assert()
        .success();

    let config = read_config_toml(&home_dir);
    assert!(
        config.contains("Webhook"),
        "strategy should be Webhook: {config}"
    );
    assert!(
        config.contains("https://hooks.example.com/test"),
        "webhook_url should be set: {config}"
    );
}

#[test]
fn notify_webhook_rejects_invalid_url() {
    let (_temp, home_dir) = prepare_openclaw_home();
    bootstrap_saved_config(&home_dir);

    let assert = Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args(["notify", "webhook", "ftp://not-valid.example.com"])
        .assert()
        .failure();

    let err = stderr_text(&assert);
    assert!(
        err.contains("http://") || err.contains("https://"),
        "should mention valid URL schemes: {err}"
    );
}

// -- telegram --

#[test]
fn notify_telegram_enables_sse() {
    let (_temp, home_dir) = prepare_openclaw_home();
    bootstrap_saved_config(&home_dir);

    let assert = Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args(["notify", "telegram", "123456789"])
        .assert()
        .success();

    let config = read_config_toml(&home_dir);
    assert!(
        config.contains("LogOnly"),
        "strategy should be LogOnly: {config}"
    );
    assert!(
        config.contains("37776"),
        "SSE port should be 37776: {config}"
    );

    let out = stdout_text(&assert);
    assert!(
        out.contains("openclaw.json"),
        "should print plugin snippet: {out}"
    );
    assert!(
        out.contains("123456789"),
        "should include chat id in snippet: {out}"
    );
}

#[test]
fn notify_telegram_saves_chat_id() {
    let (_temp, home_dir) = prepare_openclaw_home();
    bootstrap_saved_config(&home_dir);

    Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args(["notify", "telegram", "987654321"])
        .assert()
        .success();

    let config = read_config_toml(&home_dir);
    assert!(
        config.contains("987654321"),
        "telegram_chat_id should be stored: {config}"
    );
}

#[test]
fn notify_telegram_without_chat_id_keeps_existing() {
    let (_temp, home_dir) = prepare_openclaw_home();
    bootstrap_saved_config(&home_dir);

    // First set a chat id
    Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args(["notify", "telegram", "111222333"])
        .assert()
        .success();

    // Then run telegram without chat id
    Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args(["notify", "telegram"])
        .assert()
        .success();

    let config = read_config_toml(&home_dir);
    assert!(
        config.contains("111222333"),
        "existing chat_id should be preserved: {config}"
    );
}

#[test]
fn notify_telegram_preserves_existing_sse_port() {
    let (_temp, home_dir) = prepare_openclaw_home();
    bootstrap_saved_config(&home_dir);

    // First set a custom SSE port via telegram
    Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args(["notify", "telegram", "123"])
        .assert()
        .success();

    // Manually change the SSE port in config
    let config_path = home_dir.join(".clawguard").join("config.toml");
    let config = fs::read_to_string(&config_path).unwrap();
    let updated = config.replace("37776", "45000");
    fs::write(&config_path, updated).unwrap();

    // Run telegram again - should NOT overwrite the port
    Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args(["notify", "telegram", "456"])
        .assert()
        .success();

    let config = read_config_toml(&home_dir);
    assert!(
        config.contains("45000"),
        "existing non-zero SSE port should be preserved: {config}"
    );
    assert!(
        !config.contains("37776"),
        "should not reset to default port: {config}"
    );
}

// -- off --

#[test]
fn notify_off_disables_all() {
    let (_temp, home_dir) = prepare_openclaw_home();
    bootstrap_saved_config(&home_dir);

    // First enable telegram
    Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args(["notify", "telegram", "999"])
        .assert()
        .success();

    // Then turn off
    Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args(["notify", "off"])
        .assert()
        .success();

    let config = read_config_toml(&home_dir);
    assert!(
        config.contains("LogOnly"),
        "strategy should be LogOnly: {config}"
    );

    // SSE port should be 0 (disabled)
    // The TOML serializer writes port = 0
    let parsed: toml::Value = config.parse().expect("valid TOML");
    let sse_port = parsed
        .get("sse")
        .and_then(|s| s.get("port"))
        .and_then(|p| p.as_integer())
        .unwrap_or(-1);
    assert_eq!(sse_port, 0, "SSE port should be disabled");
}

#[test]
fn notify_off_clears_webhook_url() {
    let (_temp, home_dir) = prepare_openclaw_home();
    bootstrap_saved_config(&home_dir);

    // First set webhook
    Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args(["notify", "webhook", "https://example.com/hook"])
        .assert()
        .success();

    // Then turn off
    Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args(["notify", "off"])
        .assert()
        .success();

    let config = read_config_toml(&home_dir);
    assert!(
        !config.contains("example.com"),
        "webhook_url should be cleared: {config}"
    );
}

// -- edge cases (Codex review follow-ups) --

#[test]
fn notify_telegram_without_stored_chat_id_fails() {
    let (_temp, home_dir) = prepare_openclaw_home();
    bootstrap_saved_config(&home_dir);

    // Run telegram with no argument and no stored chat_id
    let assert = Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args(["notify", "telegram"])
        .assert()
        .failure();

    let err = stderr_text(&assert);
    assert!(
        err.contains("chat ID") || err.contains("chat-id"),
        "should tell user to provide a chat ID: {err}"
    );
}

#[test]
fn notify_telegram_rejects_empty_chat_id() {
    let (_temp, home_dir) = prepare_openclaw_home();
    bootstrap_saved_config(&home_dir);

    let assert = Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args(["notify", "telegram", ""])
        .assert()
        .failure();

    let err = stderr_text(&assert);
    assert!(err.contains("empty"), "should reject empty chat ID: {err}");
}

#[test]
fn notify_webhook_rejects_scheme_only_url() {
    let (_temp, home_dir) = prepare_openclaw_home();
    bootstrap_saved_config(&home_dir);

    let assert = Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args(["notify", "webhook", "https://"])
        .assert()
        .failure();

    let err = stderr_text(&assert);
    assert!(
        err.contains("host"),
        "should reject URL without host: {err}"
    );
}

// -- auto-detect chat IDs from OpenClaw config --

fn write_openclaw_telegram_config(home_dir: &Path, json5_content: &str) {
    let state_dir = home_dir.join(".openclaw");
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(state_dir.join("openclaw.json"), json5_content).unwrap();
}

#[test]
fn notify_telegram_auto_detects_single_chat_id() {
    let (_temp, home_dir) = prepare_openclaw_home();
    bootstrap_saved_config(&home_dir);

    // Write OpenClaw config with a single defaultTo
    write_openclaw_telegram_config(
        &home_dir,
        r#"{
            "channels": {
                "telegram": {
                    "defaultTo": "555444333"
                }
            }
        }"#,
    );

    // Run telegram without explicit chat ID
    let assert = Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args(["notify", "telegram"])
        .assert()
        .success();

    let config = read_config_toml(&home_dir);
    assert!(
        config.contains("555444333"),
        "should auto-detect chat ID from defaultTo: {config}"
    );

    let out = stdout_text(&assert);
    assert!(
        out.contains("555444333"),
        "should show auto-detected ID: {out}"
    );
}

#[test]
fn notify_telegram_shows_multiple_ids_and_fails() {
    let (_temp, home_dir) = prepare_openclaw_home();
    bootstrap_saved_config(&home_dir);

    write_openclaw_telegram_config(
        &home_dir,
        r#"{
            "channels": {
                "telegram": {
                    "defaultTo": "111",
                    "allowFrom": [222, 333]
                }
            }
        }"#,
    );

    let assert = Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args(["notify", "telegram"])
        .assert()
        .failure();

    let err = stderr_text(&assert);
    assert!(err.contains("111"), "should list first ID: {err}");
    assert!(err.contains("222"), "should list second ID: {err}");
    assert!(
        err.contains("Re-run"),
        "should tell user to re-run with explicit ID: {err}"
    );
}

#[test]
fn notify_telegram_json_returns_detected_ids_on_multiple() {
    let (_temp, home_dir) = prepare_openclaw_home();
    bootstrap_saved_config(&home_dir);

    // Two defaultTo values (top-level + account) → ambiguous, no auto-select
    write_openclaw_telegram_config(
        &home_dir,
        r#"{
            "channels": {
                "telegram": {
                    "defaultTo": "100",
                    "accounts": {
                        "bot-2": {
                            "defaultTo": "200"
                        }
                    }
                }
            }
        }"#,
    );

    let assert = Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args(["notify", "telegram", "--json"])
        .assert()
        .failure();

    let out = stdout_text(&assert);
    let json: serde_json::Value = serde_json::from_str(&out).expect("should be valid JSON");
    assert!(
        json["detected_chat_ids"].is_array(),
        "should include detected_chat_ids array"
    );
    assert_eq!(
        json["detected_chat_ids"].as_array().unwrap().len(),
        2,
        "should detect 2 IDs"
    );
}

#[test]
fn notify_telegram_apply_writes_openclaw_config() {
    let (_temp, home_dir) = prepare_openclaw_home();
    bootstrap_saved_config(&home_dir);

    Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args(["notify", "telegram", "999888777", "--apply"])
        .assert()
        .success();

    let openclaw_config =
        fs::read_to_string(home_dir.join(".openclaw").join("openclaw.json")).unwrap();
    assert!(
        openclaw_config.contains("clawguard"),
        "should write clawguard plugin entry: {openclaw_config}"
    );
    assert!(
        openclaw_config.contains("999888777"),
        "should include chat ID in plugin config: {openclaw_config}"
    );

    // Verify backup was created
    let backup = home_dir
        .join(".openclaw")
        .join("openclaw.json.clawguard-backup");
    assert!(backup.exists(), "should create backup file");
}

#[test]
fn notify_telegram_apply_preserves_existing_config() {
    let (_temp, home_dir) = prepare_openclaw_home();
    bootstrap_saved_config(&home_dir);

    // Read original config
    let original = fs::read_to_string(home_dir.join(".openclaw").join("openclaw.json")).unwrap();

    Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .args(["notify", "telegram", "123", "--apply"])
        .assert()
        .success();

    let updated = fs::read_to_string(home_dir.join(".openclaw").join("openclaw.json")).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&updated).expect("valid JSON");

    // Original config sections should still exist
    assert!(
        parsed.get("plugins").is_some(),
        "should have plugins section"
    );
    // Backup should contain original content
    let backup = fs::read_to_string(
        home_dir
            .join(".openclaw")
            .join("openclaw.json.clawguard-backup"),
    )
    .unwrap();
    assert_eq!(
        backup, original,
        "backup should contain original file content"
    );
}
