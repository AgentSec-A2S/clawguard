//! End-to-end CLI contract tests for `clawguard policy init` + `policy
//! validate` (V1.3 Sprint 2 §4).

use std::fs;

use assert_cmd::Command;
use tempfile::tempdir;

fn stdout_text(assert: &assert_cmd::assert::Assert) -> String {
    String::from_utf8_lossy(&assert.get_output().stdout).into_owned()
}

#[test]
fn policy_init_writes_default_manifest_when_absent() {
    let temp = tempdir().unwrap();
    let home = temp.path().join("home");
    fs::create_dir_all(&home).unwrap();

    let assert = Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home)
        .args(["policy", "init"])
        .assert()
        .success();
    let stdout = stdout_text(&assert);

    let manifest = home.join(".clawguard").join("policy.toml");
    assert!(
        manifest.is_file(),
        "policy init must create {} (stdout: {stdout})",
        manifest.display()
    );
    let body = fs::read_to_string(&manifest).unwrap();
    assert!(body.contains("[[destructive_actions.patterns]]"));
    assert!(body.contains("[rate_limit]"));
}

#[test]
fn policy_init_refuses_to_clobber_without_force() {
    let temp = tempdir().unwrap();
    let home = temp.path().join("home");
    let cfg = home.join(".clawguard");
    fs::create_dir_all(&cfg).unwrap();
    let manifest = cfg.join("policy.toml");
    fs::write(&manifest, "[rate_limit]\ndestructive_per_window = 42\nwindow_seconds = 1\n")
        .unwrap();

    Command::cargo_bin("clawguard")
        .unwrap()
        .env("HOME", &home)
        .args(["policy", "init"])
        .assert()
        .success();

    let body = fs::read_to_string(&manifest).unwrap();
    assert!(
        body.contains("destructive_per_window = 42"),
        "existing manifest must be preserved when --force is absent"
    );
}

#[test]
fn policy_init_overwrites_with_force() {
    let temp = tempdir().unwrap();
    let home = temp.path().join("home");
    let cfg = home.join(".clawguard");
    fs::create_dir_all(&cfg).unwrap();
    let manifest = cfg.join("policy.toml");
    fs::write(&manifest, "custom = 1\n").unwrap();

    Command::cargo_bin("clawguard")
        .unwrap()
        .env("HOME", &home)
        .args(["policy", "init", "--force"])
        .assert()
        .success();

    let body = fs::read_to_string(&manifest).unwrap();
    assert!(body.contains("[[destructive_actions.patterns]]"));
    assert!(
        !body.contains("custom = 1"),
        "--force must overwrite the existing manifest"
    );
}

#[test]
fn policy_validate_reports_ok_for_default_manifest() {
    let temp = tempdir().unwrap();
    let home = temp.path().join("home");
    fs::create_dir_all(&home).unwrap();

    Command::cargo_bin("clawguard")
        .unwrap()
        .env("HOME", &home)
        .args(["policy", "init"])
        .assert()
        .success();

    let assert = Command::cargo_bin("clawguard")
        .unwrap()
        .env("HOME", &home)
        .args(["policy", "validate"])
        .assert()
        .success();
    let stdout = stdout_text(&assert);
    assert!(stdout.contains("ok"), "expected 'ok' in stdout, got: {stdout}");
}

#[test]
fn policy_validate_reports_error_for_malformed_manifest() {
    let temp = tempdir().unwrap();
    let home = temp.path().join("home");
    let cfg = home.join(".clawguard");
    fs::create_dir_all(&cfg).unwrap();
    fs::write(cfg.join("policy.toml"), "this is [[[[[ not toml").unwrap();

    let assert = Command::cargo_bin("clawguard")
        .unwrap()
        .env("HOME", &home)
        .args(["policy", "validate"])
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        stderr.contains("parse") || stderr.contains("TOML") || stderr.contains("toml"),
        "expected parse error in stderr, got: {stderr}"
    );
}

#[test]
fn policy_validate_handles_explicit_path() {
    let temp = tempdir().unwrap();
    let home = temp.path().join("home");
    fs::create_dir_all(&home).unwrap();
    let custom_dir = temp.path().join("custom");
    fs::create_dir_all(&custom_dir).unwrap();
    let custom_manifest = custom_dir.join("my-policy.toml");
    fs::write(
        &custom_manifest,
        r#"
        [[destructive_actions.patterns]]
        label = "rm-rf"
        tokens = ["rm", "-rf"]
        "#,
    )
    .unwrap();

    Command::cargo_bin("clawguard")
        .unwrap()
        .env("HOME", &home)
        .args(["policy", "validate", "--path", custom_manifest.to_str().unwrap()])
        .assert()
        .success();
}
