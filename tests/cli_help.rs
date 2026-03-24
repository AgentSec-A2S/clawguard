use assert_cmd::Command;
use serde_json::Value;
use tempfile::tempdir;

fn stdout_text(assert: &assert_cmd::assert::Assert) -> String {
    String::from_utf8_lossy(&assert.get_output().stdout).into_owned()
}

#[test]
fn help_mentions_product_name() {
    let mut cmd = Command::cargo_bin("clawguard").unwrap();
    let assert = cmd.arg("--help").assert().success();
    let stdout = stdout_text(&assert);

    assert!(stdout.contains("clawguard"));
    assert!(stdout.contains("scan"));
    assert!(stdout.contains("status"));
    assert!(stdout.contains("alerts"));
    assert!(stdout.contains("baseline"));
    assert!(stdout.contains("trust"));
    assert!(stdout.contains("watch"));
}

#[test]
fn version_exits_successfully() {
    let mut cmd = Command::cargo_bin("clawguard").unwrap();
    cmd.arg("--version").assert().success();
}

#[test]
fn scan_exits_successfully() {
    let temp_dir = tempdir().unwrap();
    let home_dir = temp_dir.path().join("home");
    std::fs::create_dir_all(&home_dir).unwrap();

    let mut cmd = Command::cargo_bin("clawguard").unwrap();
    let assert = cmd.env("HOME", &home_dir).arg("scan").assert().success();
    let stdout = stdout_text(&assert);

    assert!(stdout.contains("Supported Runtime Not Detected"));
    assert!(stdout.contains("Severity: Info"));
    assert!(stdout.contains("Install OpenClaw"));
}

#[test]
fn no_args_exits_successfully() {
    let temp_dir = tempdir().unwrap();
    let home_dir = temp_dir.path().join("home");
    std::fs::create_dir_all(&home_dir).unwrap();

    let mut cmd = Command::cargo_bin("clawguard").unwrap();
    let assert = cmd.env("HOME", &home_dir).assert().success();
    let stdout = stdout_text(&assert);

    assert!(stdout.contains("Supported Runtime Not Detected"));
    assert!(stdout.contains("Severity: Info"));
}

#[test]
fn scan_json_reports_missing_runtime_as_structured_info_finding() {
    let temp_dir = tempdir().unwrap();
    let home_dir = temp_dir.path().join("home");
    std::fs::create_dir_all(&home_dir).unwrap();

    let mut cmd = Command::cargo_bin("clawguard").unwrap();
    let assert = cmd
        .env("HOME", &home_dir)
        .args(["scan", "--json"])
        .assert()
        .success();
    let stdout = stdout_text(&assert);

    let parsed: Value = serde_json::from_str(&stdout).unwrap();
    let findings = parsed["findings"].as_array().unwrap();

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["detector_id"].as_str(), Some("discovery"));
    assert_eq!(findings[0]["severity"].as_str(), Some("info"));
    assert_eq!(
        findings[0]["recommended_action"]["label"].as_str(),
        Some("Install OpenClaw or rerun `clawguard scan` after a supported runtime exists")
    );
}

#[test]
fn existing_config_without_runtime_still_reports_missing_runtime() {
    let temp_dir = tempdir().unwrap();
    let home_dir = temp_dir.path().join("home");
    let config_dir = home_dir.join(".clawguard");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(
        config_dir.join("config.toml"),
        r#"
preset = "openclaw"
alert_strategy = "Desktop"
strictness = "Recommended"
max_file_size_bytes = 1048576
"#,
    )
    .unwrap();

    let mut cmd = Command::cargo_bin("clawguard").unwrap();
    let assert = cmd.env("HOME", &home_dir).arg("scan").assert().success();
    let stdout = stdout_text(&assert);

    assert!(stdout.contains("Supported Runtime Not Detected"));
    assert!(stdout.contains("Severity: Info"));
}
