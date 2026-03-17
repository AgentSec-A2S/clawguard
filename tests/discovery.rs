use std::fs;
use std::path::PathBuf;

use clawguard::config::schema::ScanDomain;
use clawguard::discovery::{
    discover_from_builtin_presets, discover_openclaw, DetectedRuntime, DiscoveryOptions,
};
use tempfile::TempDir;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[test]
fn detects_openclaw_from_default_home_layout() {
    let home = TempDir::new().expect("temp home should be created");
    let state_dir = home.path().join(".openclaw");
    let config_path = state_dir.join("openclaw.json");
    let env_path = state_dir.join(".env");
    let skills_dir = state_dir.join("skills");

    fs::create_dir_all(&skills_dir).expect("skills dir should be created");
    fs::write(&config_path, "{ }\n").expect("config file should be written");
    fs::write(&env_path, "OPENCLAW_GATEWAY_TOKEN=test\n").expect("env file should be written");

    let runtime = discover_openclaw(&DiscoveryOptions {
        home_dir: Some(home.path().to_path_buf()),
        ..DiscoveryOptions::default()
    })
    .expect("openclaw should be detected");

    assert_eq!(runtime.preset_id, "openclaw");
    assert_eq!(runtime.root, Some(state_dir.clone()));
    assert!(runtime.recommended);
    assert_eq!(
        target_paths(&runtime, ScanDomain::Config),
        vec![config_path.clone()]
    );
    assert_eq!(target_paths(&runtime, ScanDomain::Skills), vec![skills_dir]);
    assert_eq!(target_paths(&runtime, ScanDomain::Env), vec![env_path]);
}

#[test]
fn returns_empty_when_openclaw_is_absent() {
    let home = TempDir::new().expect("temp home should be created");

    let report = discover_from_builtin_presets(&DiscoveryOptions {
        home_dir: Some(home.path().to_path_buf()),
        ..DiscoveryOptions::default()
    });

    assert!(report.runtimes.is_empty());
}

#[test]
fn respects_openclaw_state_dir_override() {
    let home = TempDir::new().expect("temp home should be created");
    let state_root = TempDir::new().expect("temp state root should be created");
    let config_path = state_root.path().join("openclaw.json");

    fs::write(&config_path, "{ }\n").expect("config file should be written");

    let runtime = discover_openclaw(&DiscoveryOptions {
        home_dir: Some(home.path().to_path_buf()),
        openclaw_state_dir: Some(state_root.path().to_path_buf()),
        ..DiscoveryOptions::default()
    })
    .expect("openclaw should be detected from explicit state dir");

    assert_eq!(runtime.root, Some(state_root.path().to_path_buf()));
    assert_eq!(
        target_paths(&runtime, ScanDomain::Config),
        vec![config_path]
    );
}

#[test]
fn respects_openclaw_config_path_override() {
    let home = TempDir::new().expect("temp home should be created");
    let config_dir = TempDir::new().expect("temp config dir should be created");
    let config_path = config_dir.path().join("custom-openclaw.json");

    fs::write(&config_path, "{ }\n").expect("config file should be written");

    let runtime = discover_openclaw(&DiscoveryOptions {
        home_dir: Some(home.path().to_path_buf()),
        openclaw_config_path: Some(config_path.clone()),
        ..DiscoveryOptions::default()
    })
    .expect("openclaw should be detected from explicit config path");

    assert_eq!(runtime.root, Some(config_dir.path().to_path_buf()));
    assert_eq!(
        target_paths(&runtime, ScanDomain::Config),
        vec![config_path.clone()]
    );
    assert_eq!(target_paths(&runtime, ScanDomain::Mcp), vec![config_path]);
}

#[test]
fn expands_auth_profile_glob_for_multiple_agents() {
    let home = TempDir::new().expect("temp home should be created");
    let state_dir = home.path().join(".openclaw");
    let agents_dir = state_dir.join("agents");
    let config_path = state_dir.join("openclaw.json");
    let auth_profile_a = agents_dir
        .join("alpha")
        .join("agent")
        .join("auth-profiles.json");
    let auth_profile_b = agents_dir
        .join("beta")
        .join("agent")
        .join("auth-profiles.json");

    fs::create_dir_all(
        auth_profile_a
            .parent()
            .expect("auth profile parent should exist"),
    )
    .expect("alpha auth dir should be created");
    fs::create_dir_all(
        auth_profile_b
            .parent()
            .expect("auth profile parent should exist"),
    )
    .expect("beta auth dir should be created");
    fs::write(&config_path, "{ }\n").expect("config file should be written");
    fs::write(&auth_profile_a, "{ }\n").expect("alpha auth profile should be written");
    fs::write(&auth_profile_b, "{ }\n").expect("beta auth profile should be written");

    let runtime = discover_openclaw(&DiscoveryOptions {
        home_dir: Some(home.path().to_path_buf()),
        ..DiscoveryOptions::default()
    })
    .expect("openclaw should be detected");

    let mut config_paths = target_paths(&runtime, ScanDomain::Config);
    config_paths.sort();

    assert_eq!(
        config_paths,
        vec![auth_profile_a, auth_profile_b, config_path]
    );
}

#[cfg(unix)]
#[test]
fn unreadable_openclaw_root_returns_warning_not_panic() {
    let home = TempDir::new().expect("temp home should be created");
    let state_dir = home.path().join(".openclaw");

    fs::create_dir_all(&state_dir).expect("state dir should be created");
    fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o000))
        .expect("state dir permissions should be updated");

    let report = discover_from_builtin_presets(&DiscoveryOptions {
        home_dir: Some(home.path().to_path_buf()),
        ..DiscoveryOptions::default()
    });

    fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o755))
        .expect("state dir permissions should be restored");

    assert!(report.runtimes.is_empty());
    assert_eq!(report.warnings.len(), 1);
    assert_eq!(report.warnings[0].path, state_dir);
}

#[cfg(unix)]
#[test]
fn partial_detection_keeps_accessible_targets_and_reports_warning() {
    let home = TempDir::new().expect("temp home should be created");
    let state_dir = home.path().join(".openclaw");
    let config_path = state_dir.join("openclaw.json");
    let agents_dir = state_dir.join("agents");
    let good_auth_profile = agents_dir
        .join("alpha")
        .join("agent")
        .join("auth-profiles.json");
    let blocked_auth_profile = agents_dir
        .join("beta")
        .join("agent")
        .join("auth-profiles.json");

    fs::create_dir_all(
        good_auth_profile
            .parent()
            .expect("auth profile parent should exist"),
    )
    .expect("alpha auth dir should be created");
    fs::create_dir_all(
        blocked_auth_profile
            .parent()
            .expect("auth profile parent should exist"),
    )
    .expect("beta auth dir should be created");
    fs::write(&config_path, "{ }\n").expect("config file should be written");
    fs::write(&good_auth_profile, "{ }\n").expect("good auth profile should be written");
    fs::write(&blocked_auth_profile, "{ }\n").expect("blocked auth profile should be written");
    fs::set_permissions(&blocked_auth_profile, fs::Permissions::from_mode(0o000))
        .expect("blocked auth profile permissions should be updated");

    let runtime = discover_openclaw(&DiscoveryOptions {
        home_dir: Some(home.path().to_path_buf()),
        ..DiscoveryOptions::default()
    })
    .expect("openclaw should still be partially detected");

    fs::set_permissions(&blocked_auth_profile, fs::Permissions::from_mode(0o600))
        .expect("blocked auth profile permissions should be restored");

    let config_paths = target_paths(&runtime, ScanDomain::Config);

    assert!(config_paths.contains(&config_path));
    assert!(config_paths.contains(&good_auth_profile));
    assert!(!config_paths.contains(&blocked_auth_profile));
    assert_eq!(runtime.warnings.len(), 1);
    assert_eq!(runtime.warnings[0].path, blocked_auth_profile);
}

fn target_paths(runtime: &DetectedRuntime, domain: ScanDomain) -> Vec<PathBuf> {
    runtime
        .targets
        .iter()
        .find(|target| target.domain == domain)
        .map(|target| target.paths.clone())
        .unwrap_or_default()
}
