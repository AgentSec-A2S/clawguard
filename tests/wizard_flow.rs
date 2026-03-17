use std::fs;

use assert_cmd::Command;
use clawguard::config::schema::{AlertStrategy, Strictness};
use clawguard::discovery::{DetectedRuntime, DiscoveryReport};
use clawguard::wizard::{run_non_interactive, WizardAnswers};
use tempfile::tempdir;

#[test]
fn recommended_detected_runtime_is_persisted_with_selected_preferences() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let home_dir = temp_dir.path().join("home");
    fs::create_dir(&home_dir).expect("home dir should be created");

    let discovery = DiscoveryReport {
        runtimes: vec![DetectedRuntime {
            preset_id: "openclaw".to_string(),
            root: None,
            targets: Vec::new(),
            warnings: Vec::new(),
            recommended: true,
        }],
        warnings: Vec::new(),
    };

    run_non_interactive(
        &discovery,
        WizardAnswers {
            selected_preset: None,
            alert_strategy: AlertStrategy::Desktop,
            strictness: Strictness::Recommended,
        },
        &home_dir,
    )
    .expect("wizard should persist config");

    let config_path = home_dir.join(".clawguard").join("config.toml");
    let saved = fs::read_to_string(config_path).expect("config file should be written");

    assert!(saved.contains("preset = \"openclaw\""));
    assert!(saved.contains("alert_strategy = \"Desktop\""));
    assert!(saved.contains("strictness = \"Recommended\""));
}

#[test]
fn cli_without_config_runs_wizard_and_writes_default_setup() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let home_dir = temp_dir.path().join("home");
    let state_dir = home_dir.join(".openclaw");
    fs::create_dir_all(&state_dir).expect("openclaw dir should exist");
    fs::write(state_dir.join("openclaw.json"), "{/* json5 placeholder */}")
        .expect("openclaw config should exist");

    let mut cmd = Command::cargo_bin("clawguard").expect("binary should exist");
    cmd.env("HOME", &home_dir)
        // Two blank lines accept the remaining wizard defaults:
        // alert strategy and strictness.
        .write_stdin("\n\n")
        .assert()
        .success();

    let config_path = home_dir.join(".clawguard").join("config.toml");
    let saved = fs::read_to_string(config_path).expect("config file should be written");

    assert!(saved.contains("preset = \"openclaw\""));
}
