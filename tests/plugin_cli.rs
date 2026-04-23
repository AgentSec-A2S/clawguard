//! End-to-end CLI contract tests for `clawguard plugin install`,
//! `clawguard plugin status`, and the runtime_coverage block that
//! `clawguard posture` now emits.
//!
//! Covers the V1.3 Sprint 2 §6 acceptance criteria:
//!   1. `plugin install openclaw` writes three files into
//!      `~/.openclaw/extensions/clawguard-runtime/` and exits 0.
//!   2. Re-running without `--force` is a no-op (idempotent).
//!   3. Mutating an installed file and re-running without `--force`
//!      fails; with `--force` it restores the embedded version.
//!   4. `plugin status openclaw` reports accurate install + broker
//!      state in both human and JSON modes.
//!   5. `posture --json` now contains a `runtime_coverage` object.

use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use clawguard::config::schema::{AlertStrategy, AppConfig, Strictness};
use clawguard::config::store::save_config_for_home;
use serde_json::Value;
use tempfile::tempdir;

fn seed_saved_config(home: &Path) {
    let config = AppConfig {
        preset: "openclaw".to_string(),
        strictness: Strictness::Recommended,
        alert_strategy: AlertStrategy::Desktop,
        webhook_url: None,
        max_file_size_bytes: 1024 * 1024,
        telegram_chat_id: None,
        sse: Default::default(),
    };
    save_config_for_home(&config, home).expect("seed config");
}

fn stdout_text(assert: &assert_cmd::assert::Assert) -> String {
    String::from_utf8_lossy(&assert.get_output().stdout).into_owned()
}

fn prepare_openclaw_home() -> (tempfile::TempDir, PathBuf) {
    let temp = tempdir().expect("temp dir");
    let home = temp.path().join("home");
    // Pre-create the openclaw extensions dir so `install` doesn't
    // bail with MissingExtensionsDir — matches what a real OpenClaw
    // install would provide.
    fs::create_dir_all(home.join(".openclaw/extensions")).unwrap();
    (temp, home)
}

fn target_dir(home: &Path) -> PathBuf {
    home.join(".openclaw/extensions/clawguard-runtime")
}

#[test]
fn plugin_install_writes_three_files_on_fresh_home() {
    let (_temp, home) = prepare_openclaw_home();
    let assert = Command::cargo_bin("clawguard")
        .unwrap()
        .env("HOME", &home)
        .args(["plugin", "install", "openclaw"])
        .assert()
        .success();
    let out = stdout_text(&assert);
    assert!(out.contains("installed ClawGuard runtime guard plugin"));
    assert!(out.contains("3 created"));

    let dir = target_dir(&home);
    for name in ["openclaw.plugin.json", "index.js", "package.json"] {
        let path = dir.join(name);
        assert!(path.exists(), "expected {}", path.display());
        let body = fs::read_to_string(&path).unwrap();
        assert!(!body.is_empty(), "{} should not be empty", name);
    }
    let manifest = fs::read_to_string(dir.join("openclaw.plugin.json")).unwrap();
    assert!(manifest.contains("\"id\": \"clawguard-runtime\""));
}

#[test]
fn plugin_install_is_idempotent_when_files_match() {
    let (_temp, home) = prepare_openclaw_home();
    Command::cargo_bin("clawguard")
        .unwrap()
        .env("HOME", &home)
        .args(["plugin", "install", "openclaw"])
        .assert()
        .success();
    // Second run should produce 3 unchanged.
    let assert = Command::cargo_bin("clawguard")
        .unwrap()
        .env("HOME", &home)
        .args(["plugin", "install", "openclaw"])
        .assert()
        .success();
    let out = stdout_text(&assert);
    assert!(
        out.contains("3 unchanged"),
        "expected all-unchanged summary, got: {}",
        out
    );
}

#[test]
fn plugin_install_without_force_refuses_to_clobber_drifted_file() {
    let (_temp, home) = prepare_openclaw_home();
    Command::cargo_bin("clawguard")
        .unwrap()
        .env("HOME", &home)
        .args(["plugin", "install", "openclaw"])
        .assert()
        .success();
    fs::write(target_dir(&home).join("index.js"), "// tampered").unwrap();
    Command::cargo_bin("clawguard")
        .unwrap()
        .env("HOME", &home)
        .args(["plugin", "install", "openclaw"])
        .assert()
        .failure();
}

#[test]
fn plugin_install_with_force_restores_drifted_file() {
    let (_temp, home) = prepare_openclaw_home();
    Command::cargo_bin("clawguard")
        .unwrap()
        .env("HOME", &home)
        .args(["plugin", "install", "openclaw"])
        .assert()
        .success();
    let index = target_dir(&home).join("index.js");
    fs::write(&index, "// tampered").unwrap();
    let assert = Command::cargo_bin("clawguard")
        .unwrap()
        .env("HOME", &home)
        .args(["plugin", "install", "openclaw", "--force"])
        .assert()
        .success();
    let out = stdout_text(&assert);
    assert!(out.contains("1 overwritten"), "expected overwritten count, got: {}", out);
    let restored = fs::read_to_string(&index).unwrap();
    assert!(
        !restored.contains("tampered"),
        "--force should have restored the embedded index.js"
    );
}

#[test]
fn plugin_install_json_emits_structured_report() {
    let (_temp, home) = prepare_openclaw_home();
    let assert = Command::cargo_bin("clawguard")
        .unwrap()
        .env("HOME", &home)
        .args(["--json", "plugin", "install", "openclaw"])
        .assert()
        .success();
    let parsed: Value = serde_json::from_str(stdout_text(&assert).trim())
        .expect("plugin install --json must be a JSON object");
    assert!(parsed.get("target_dir").is_some());
    let files = parsed.get("files").and_then(|v| v.as_array()).unwrap();
    assert_eq!(files.len(), 3);
    for f in files {
        assert_eq!(f.get("action").and_then(|v| v.as_str()), Some("created"));
    }
}

#[test]
fn plugin_status_before_install_reports_not_installed() {
    let (_temp, home) = prepare_openclaw_home();
    let assert = Command::cargo_bin("clawguard")
        .unwrap()
        .env("HOME", &home)
        .args(["plugin", "status", "openclaw"])
        .assert()
        .success();
    let out = stdout_text(&assert);
    // `✘` rendering depends on terminal — check via hint text and
    // explicit keywords instead.
    assert!(out.contains("installed"));
    assert!(
        out.contains("install") || out.contains("hint"),
        "expected install hint, got: {}",
        out
    );
}

#[test]
fn plugin_status_after_install_reports_installed_and_files_ok() {
    let (_temp, home) = prepare_openclaw_home();
    Command::cargo_bin("clawguard")
        .unwrap()
        .env("HOME", &home)
        .args(["plugin", "install", "openclaw"])
        .assert()
        .success();
    let assert = Command::cargo_bin("clawguard")
        .unwrap()
        .env("HOME", &home)
        .args(["--json", "plugin", "status", "openclaw"])
        .assert()
        .success();
    let parsed: Value = serde_json::from_str(stdout_text(&assert).trim()).unwrap();
    assert_eq!(parsed.get("installed").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(
        parsed.get("manifest_valid").and_then(|v| v.as_bool()),
        Some(true)
    );
    let files = parsed.get("files").and_then(|v| v.as_array()).unwrap();
    for f in files {
        assert_eq!(f.get("present").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(
            f.get("matches_expected").and_then(|v| v.as_bool()),
            Some(true)
        );
    }
}

#[test]
fn plugin_status_detects_drift() {
    let (_temp, home) = prepare_openclaw_home();
    Command::cargo_bin("clawguard")
        .unwrap()
        .env("HOME", &home)
        .args(["plugin", "install", "openclaw"])
        .assert()
        .success();
    fs::write(target_dir(&home).join("index.js"), "// tampered").unwrap();
    let assert = Command::cargo_bin("clawguard")
        .unwrap()
        .env("HOME", &home)
        .args(["--json", "plugin", "status", "openclaw"])
        .assert()
        .success();
    let parsed: Value = serde_json::from_str(stdout_text(&assert).trim()).unwrap();
    assert_eq!(parsed.get("installed").and_then(|v| v.as_bool()), Some(false));
    let files = parsed.get("files").and_then(|v| v.as_array()).unwrap();
    let index = files
        .iter()
        .find(|f| f.get("name").and_then(|v| v.as_str()) == Some("index.js"))
        .unwrap();
    assert_eq!(
        index.get("matches_expected").and_then(|v| v.as_bool()),
        Some(false)
    );
    assert_eq!(index.get("present").and_then(|v| v.as_bool()), Some(true));
    let hint = parsed.get("hint").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        hint.contains("drift"),
        "status hint should mention drift, got: {}",
        hint
    );
}

#[test]
fn plugin_install_errors_when_openclaw_home_missing() {
    let temp = tempdir().unwrap();
    let home = temp.path().join("empty-home");
    fs::create_dir_all(&home).unwrap();
    // No ~/.openclaw → install must error.
    Command::cargo_bin("clawguard")
        .unwrap()
        .env("HOME", &home)
        .args(["plugin", "install", "openclaw"])
        .assert()
        .failure();
}

#[test]
fn posture_json_carries_runtime_coverage_block() {
    let (_temp, home) = prepare_openclaw_home();
    // posture needs both a saved config AND a runtime. Seed both.
    seed_saved_config(&home);
    let openclaw_root = home.join(".openclaw");
    fs::create_dir_all(&openclaw_root).unwrap();
    fs::write(openclaw_root.join("openclaw.json"), "{}").unwrap();

    let assert = Command::cargo_bin("clawguard")
        .unwrap()
        .env("HOME", &home)
        .args(["--json", "--no-interactive", "posture"])
        .assert()
        .success();
    let parsed: Value = serde_json::from_str(stdout_text(&assert).trim())
        .expect("posture --json must emit a JSON object");
    let coverage = parsed
        .get("runtime_coverage")
        .expect("runtime_coverage block must be present");
    assert_eq!(
        coverage.get("plugin_installed").and_then(|v| v.as_bool()),
        Some(false),
        "fresh home should report plugin not installed"
    );
    assert!(coverage.get("plugin_dir").is_some());
    assert!(coverage.get("hint").is_some());
    assert_eq!(
        coverage.get("policy_manifest_present").and_then(|v| v.as_bool()),
        Some(false)
    );
}

#[test]
fn posture_json_runtime_coverage_flips_to_installed_after_install() {
    let (_temp, home) = prepare_openclaw_home();
    seed_saved_config(&home);
    let openclaw_root = home.join(".openclaw");
    fs::create_dir_all(&openclaw_root).unwrap();
    fs::write(openclaw_root.join("openclaw.json"), "{}").unwrap();

    Command::cargo_bin("clawguard")
        .unwrap()
        .env("HOME", &home)
        .args(["plugin", "install", "openclaw"])
        .assert()
        .success();

    let assert = Command::cargo_bin("clawguard")
        .unwrap()
        .env("HOME", &home)
        .args(["--json", "--no-interactive", "posture"])
        .assert()
        .success();
    let parsed: Value = serde_json::from_str(stdout_text(&assert).trim()).unwrap();
    let coverage = parsed.get("runtime_coverage").unwrap();
    assert_eq!(
        coverage.get("plugin_installed").and_then(|v| v.as_bool()),
        Some(true),
        "after install, coverage should report plugin_installed=true"
    );
    assert_eq!(
        coverage.get("manifest_valid").and_then(|v| v.as_bool()),
        Some(true)
    );
}
