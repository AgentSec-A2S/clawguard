use std::fs;

use assert_cmd::Command;
use clawguard::config::schema::{AlertStrategy, Strictness};
use clawguard::config::store::load_config_from_path;
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
            webhook_url: None,
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
fn webhook_strategy_round_trips_with_webhook_url() {
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

    let config = run_non_interactive(
        &discovery,
        WizardAnswers {
            selected_preset: None,
            alert_strategy: AlertStrategy::Webhook,
            webhook_url: Some("https://example.invalid/clawguard".to_string()),
            strictness: Strictness::Recommended,
        },
        &home_dir,
    )
    .expect("wizard should persist webhook config");

    assert_eq!(config.alert_strategy, AlertStrategy::Webhook);
    assert_eq!(
        config.webhook_url.as_deref(),
        Some("https://example.invalid/clawguard")
    );

    let config_path = home_dir.join(".clawguard").join("config.toml");
    let saved = fs::read_to_string(&config_path).expect("config file should be written");
    assert!(saved.contains("alert_strategy = \"Webhook\""));
    assert!(saved.contains("webhook_url = \"https://example.invalid/clawguard\""));

    let loaded = load_config_from_path(&config_path)
        .expect("config should deserialize")
        .expect("config should exist");
    assert_eq!(loaded.webhook_url, config.webhook_url);
}

#[test]
fn webhook_strategy_requires_webhook_url_in_non_interactive_mode() {
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

    let error = run_non_interactive(
        &discovery,
        WizardAnswers {
            selected_preset: None,
            alert_strategy: AlertStrategy::Webhook,
            webhook_url: None,
            strictness: Strictness::Recommended,
        },
        &home_dir,
    )
    .expect_err("webhook mode should require a webhook URL");

    assert!(
        error
            .to_string()
            .contains("requires a configured webhook URL"),
        "missing webhook configuration should return a specific validation error"
    );
}

#[test]
fn webhook_strategy_rejects_non_http_url_in_non_interactive_mode() {
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

    let error = run_non_interactive(
        &discovery,
        WizardAnswers {
            selected_preset: None,
            alert_strategy: AlertStrategy::Webhook,
            webhook_url: Some("ftp://example.invalid/clawguard".to_string()),
            strictness: Strictness::Recommended,
        },
        &home_dir,
    )
    .expect_err("non-http webhook URLs should be rejected");

    assert!(
        error.to_string().contains("http:// or https://"),
        "invalid webhook URLs should explain the accepted schemes"
    );
}

#[test]
fn legacy_config_without_webhook_url_still_loads() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let config_path = temp_dir.path().join("config.toml");
    fs::write(
        &config_path,
        r#"
preset = "openclaw"
strictness = "Recommended"
alert_strategy = "Desktop"
max_file_size_bytes = 1048576
"#,
    )
    .expect("legacy config fixture should write");

    let loaded = load_config_from_path(&config_path)
        .expect("legacy config should deserialize")
        .expect("legacy config should exist");

    assert_eq!(loaded.alert_strategy, AlertStrategy::Desktop);
    assert_eq!(loaded.webhook_url, None);
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
