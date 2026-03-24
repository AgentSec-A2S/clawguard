use std::fs;
use std::path::PathBuf;

use clawguard::daemon::recovery::restore_policy_file;
use clawguard::scan::baseline::{
    collect_restore_payload_candidates, restore_target_kind_for_path, RestoreTargetKind,
};
use clawguard::scan::{BaselineArtifact, FindingCategory};
use clawguard::state::db::{StateStore, StateStoreConfig};
use clawguard::state::model::RestorePayloadRecord;
use tempfile::tempdir;

#[test]
fn policy_files_are_classified_as_restorable() {
    assert_eq!(
        restore_target_kind_for_path("/tmp/.openclaw/openclaw.json", "config"),
        Some(RestoreTargetKind::OpenClawConfig)
    );
    assert_eq!(
        restore_target_kind_for_path("/tmp/.openclaw/exec-approvals.json", "config"),
        Some(RestoreTargetKind::ExecApprovals)
    );
}

#[test]
fn non_policy_files_are_not_restorable() {
    assert_eq!(
        restore_target_kind_for_path("/tmp/.openclaw/.env", "env"),
        None
    );
    assert_eq!(
        restore_target_kind_for_path("/tmp/.openclaw/skills/demo/SKILL.md", "skills"),
        None
    );
    assert_eq!(
        restore_target_kind_for_path(
            "/tmp/.openclaw/agents/alice/agent/auth-profiles.json",
            "config"
        ),
        None
    );
    assert_eq!(
        restore_target_kind_for_path("/tmp/.openclaw/openclaw.json", "mcp"),
        None
    );
}

#[test]
fn restorable_policy_files_produce_restore_payload_candidates() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let runtime_root = temp_dir.path().join(".openclaw");
    fs::create_dir_all(&runtime_root).expect("runtime root should exist");
    let config_path = runtime_root.join("openclaw.json");
    let approvals_path = runtime_root.join("exec-approvals.json");
    fs::write(&config_path, "{ agents: {} }").expect("config should be written");
    fs::write(&approvals_path, "{ mode: \"review\" }").expect("approvals should be written");

    let candidates = collect_restore_payload_candidates(
        1_763_900_000_000,
        &[
            BaselineArtifact {
                path: config_path.display().to_string(),
                sha256: "aaa".to_string(),
                source_label: "config".to_string(),
                category: FindingCategory::Config,
            },
            BaselineArtifact {
                path: approvals_path.display().to_string(),
                sha256: "bbb".to_string(),
                source_label: "config".to_string(),
                category: FindingCategory::Config,
            },
        ],
    );

    assert_eq!(candidates.len(), 2);
    assert!(candidates.iter().any(|candidate| {
        candidate.path == config_path.display().to_string()
            && candidate.sha256 == "aaa"
            && candidate.content == "{ agents: {} }"
    }));
    assert!(candidates.iter().any(|candidate| {
        candidate.path == approvals_path.display().to_string()
            && candidate.sha256 == "bbb"
            && candidate.content == "{ mode: \"review\" }"
    }));
}

#[test]
fn missing_or_non_utf8_policy_files_are_skipped() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let runtime_root = temp_dir.path().join(".openclaw");
    fs::create_dir_all(&runtime_root).expect("runtime root should exist");
    let missing_path = runtime_root.join("openclaw.json");
    let binary_path = runtime_root.join("exec-approvals.json");
    fs::write(&binary_path, [0xff, 0xfe, 0xfd]).expect("binary file should be written");

    let candidates = collect_restore_payload_candidates(
        1_763_900_000_000,
        &[
            BaselineArtifact {
                path: missing_path.display().to_string(),
                sha256: "aaa".to_string(),
                source_label: "config".to_string(),
                category: FindingCategory::Config,
            },
            BaselineArtifact {
                path: binary_path.display().to_string(),
                sha256: "bbb".to_string(),
                source_label: "config".to_string(),
                category: FindingCategory::Config,
            },
        ],
    );

    assert!(
        candidates.is_empty(),
        "missing or non-utf8 policy files should not produce restore payloads"
    );
}

#[test]
fn restore_helper_replays_openclaw_json_payload() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let runtime_root = temp_dir.path().join(".openclaw");
    let config_path = runtime_root.join("openclaw.json");
    fs::create_dir_all(&runtime_root).expect("runtime root should exist");
    fs::write(&config_path, "{ current: true }").expect("current file should be written");

    let mut store = open_state_store(temp_dir.path());
    store
        .replace_restore_payloads_for_source(
            "config",
            &[restore_payload_record(
                &config_path,
                "aaa",
                "config",
                "{ restored: true }",
            )],
        )
        .expect("approved payload should persist");

    restore_policy_file(&store, &config_path).expect("restore should succeed");

    assert_eq!(
        fs::read_to_string(&config_path).expect("restored file should be readable"),
        "{ restored: true }"
    );
}

#[test]
fn restore_helper_recreates_exec_approvals_file_from_payload() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let runtime_root = temp_dir.path().join(".openclaw");
    let approvals_path = runtime_root.join("exec-approvals.json");
    fs::create_dir_all(&runtime_root).expect("runtime root should exist");

    let mut store = open_state_store(temp_dir.path());
    store
        .replace_restore_payloads_for_source(
            "config",
            &[restore_payload_record(
                &approvals_path,
                "bbb",
                "config",
                "{ mode: \"review\" }",
            )],
        )
        .expect("approved payload should persist");

    restore_policy_file(&store, &approvals_path).expect("restore should recreate file");

    assert_eq!(
        fs::read_to_string(&approvals_path).expect("restored file should be readable"),
        "{ mode: \"review\" }"
    );
}

#[test]
fn restore_helper_rejects_non_restorable_paths() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let runtime_root = temp_dir.path().join(".openclaw");
    let env_path = runtime_root.join(".env");
    fs::create_dir_all(&runtime_root).expect("runtime root should exist");

    let store = open_state_store(temp_dir.path());
    let error = restore_policy_file(&store, &env_path)
        .expect_err("non-restorable path should be rejected before any write");

    assert!(
        error.to_string().contains("not restorable"),
        "error should explain that the requested path is outside the narrow recovery allowlist"
    );
    assert!(
        !env_path.exists(),
        "rejecting a non-restorable path should not create or modify files"
    );
}

fn open_state_store(home_dir: &std::path::Path) -> StateStore {
    let state_path = home_dir.join(".clawguard").join("state.db");
    StateStore::open(StateStoreConfig::for_path(state_path))
        .expect("state store should open")
        .store
}

fn restore_payload_record(
    path: &PathBuf,
    sha256: &str,
    source_label: &str,
    content: &str,
) -> RestorePayloadRecord {
    RestorePayloadRecord {
        path: path.display().to_string(),
        sha256: sha256.to_string(),
        captured_at_unix_ms: 1_763_900_000_000,
        source_label: source_label.to_string(),
        content: content.to_string(),
    }
}
