use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use serde_json::Value;
use tempfile::tempdir;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

fn stdout_text(assert: &assert_cmd::assert::Assert) -> String {
    String::from_utf8_lossy(&assert.get_output().stdout).into_owned()
}

#[test]
fn first_run_launches_setup_and_then_renders_findings() {
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

    let mut cmd = Command::cargo_bin("clawguard").expect("binary should exist");
    let assert = cmd
        .env("HOME", &home_dir)
        // Two newlines: accept default alert strategy + default strictness.
        .write_stdin("\n\n")
        .assert()
        .success();
    let stdout = stdout_text(&assert);

    assert!(stdout.contains("Starting first-run setup."));
    assert!(stdout.contains("Severity:"));
    assert!(stdout.contains("Recommended action"));

    let config_path = home_dir.join(".clawguard").join("config.toml");
    assert!(
        config_path.exists(),
        "first-run setup should persist config"
    );
    let saved = fs::read_to_string(config_path).expect("saved config should read");
    assert!(saved.contains("preset = \"openclaw\""));
    assert!(saved.contains("alert_strategy = \"Desktop\""));
    assert!(saved.contains("strictness = \"Recommended\""));
}

#[test]
fn scan_json_is_machine_readable_for_minimal_openclaw_state() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let home_dir = temp_dir.path().join("home");
    let state_dir = home_dir.join(".openclaw");
    fs::create_dir_all(&state_dir).expect("openclaw state dir should exist");
    let config_path = state_dir.join("openclaw.json");
    fs::write(&config_path, "{}").expect("minimal config should be written");
    restrict_permissions_if_supported(&config_path);

    let mut cmd = Command::cargo_bin("clawguard").expect("binary should exist");
    let assert = cmd
        .env("HOME", &home_dir)
        .args(["scan", "--no-interactive", "--json"])
        .assert()
        .success();
    let stdout = stdout_text(&assert);

    let parsed: Value =
        serde_json::from_str(&stdout).expect("scan output should be valid machine-readable JSON");
    assert!(parsed.get("summary").is_some(), "json summary should exist");
    assert!(
        parsed.get("findings").is_some(),
        "json findings should exist"
    );
    let severity_levels: Vec<&str> = parsed["findings"]
        .as_array()
        .expect("findings should be an array")
        .iter()
        .filter_map(|finding| finding["severity"].as_str())
        .collect();
    let detector_ids: Vec<&str> = parsed["findings"]
        .as_array()
        .expect("findings should be an array")
        .iter()
        .filter_map(|finding| finding["detector_id"].as_str())
        .collect();
    assert!(
        !severity_levels.contains(&"critical"),
        "minimal state should not produce critical findings"
    );
    assert!(
        !severity_levels.contains(&"high"),
        "minimal state should not produce high findings"
    );
    assert!(
        !detector_ids.contains(&"cve"),
        "minimal state should not claim advisory matching without version evidence"
    );

    let saved_config_path = home_dir.join(".clawguard").join("config.toml");
    assert!(
        saved_config_path.exists(),
        "non-interactive scan should persist config"
    );
}

#[test]
fn repeat_scan_uses_existing_config_without_reopening_the_wizard() {
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

    Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .write_stdin("\n\n")
        .assert()
        .success();

    let mut cmd = Command::cargo_bin("clawguard").expect("binary should exist");
    let assert = cmd.env("HOME", &home_dir).arg("scan").assert().success();
    let stdout = stdout_text(&assert);

    assert!(!stdout.contains("Starting first-run setup."));
    assert!(stdout.contains("Severity:"));
    assert!(stdout.contains("Recommended action"));
}

#[test]
fn saved_config_with_runtime_deleted_reports_structured_runtime_missing_finding() {
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

    Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home_dir)
        .write_stdin("\n\n")
        .assert()
        .success();

    fs::remove_dir_all(&state_dir).expect("openclaw runtime dir should be removed");

    let mut cmd = Command::cargo_bin("clawguard").expect("binary should exist");
    let assert = cmd
        .env("HOME", &home_dir)
        .args(["scan", "--no-interactive", "--json"])
        .assert()
        .success();
    let stdout = stdout_text(&assert);

    let parsed: Value =
        serde_json::from_str(&stdout).expect("scan output should be valid machine-readable JSON");
    let findings = parsed["findings"]
        .as_array()
        .expect("findings should be an array");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["detector_id"].as_str(), Some("discovery"));
    assert_eq!(findings[0]["severity"].as_str(), Some("info"));
    assert!(
        findings[0]["id"]
            .as_str()
            .is_some_and(|id| id.starts_with("discovery:runtime-not-detected:")),
        "saved-config but runtime-missing path should report the structured runtime-missing finding"
    );
}

fn fixture_path(relative: &str) -> PathBuf {
    Path::new("tests").join("fixtures").join(relative)
}

fn restrict_permissions_if_supported(path: &Path) {
    #[cfg(unix)]
    {
        let permissions = fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, permissions).expect("permissions should be updated");
    }

    #[cfg(not(unix))]
    {
        let _ = path;
    }
}
