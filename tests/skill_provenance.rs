use std::fs;

use clawguard::scan::baseline::provenance_findings_for_artifacts;
use clawguard::scan::{BaselineArtifact, FindingCategory, Severity};
use clawguard::state::db::{StateStore, StateStoreConfig};
use clawguard::state::model::BaselineRecord;
use tempfile::TempDir;

fn setup_state() -> (TempDir, StateStore) {
    let dir = tempfile::tempdir().expect("temp dir");
    let db_path = dir.path().join("state.db");
    let result = StateStore::open(StateStoreConfig::for_path(db_path)).expect("open state");
    (dir, result.store)
}

fn make_skill_artifact(path: &str, sha256: &str) -> BaselineArtifact {
    BaselineArtifact {
        path: path.to_string(),
        sha256: sha256.to_string(),
        source_label: "skills".to_string(),
        category: FindingCategory::Skills,
        git_remote_url: None,
        git_head_sha: None,
    }
}

fn make_skill_baseline(path: &str, sha256: &str) -> BaselineRecord {
    BaselineRecord {
        path: path.to_string(),
        sha256: sha256.to_string(),
        approved_at_unix_ms: 1000,
        source_label: "skills".to_string(),
        git_remote_url: None,
        git_head_sha: None,
    }
}

// ---- Provenance finding tests ----

#[test]
fn skill_no_baseline_info() {
    let artifact = make_skill_artifact("/skills/my-skill/handler.js", "abc123");
    let baselines: Vec<BaselineRecord> = vec![];

    let findings = provenance_findings_for_artifacts(&baselines, &[artifact]);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::Info);
    assert!(findings[0].id.contains("skill-no-provenance"));
    assert!(findings[0].owasp_asi.as_deref() == Some("ASI06"));
}

#[test]
fn skill_hash_changed_without_approve() {
    let artifact = make_skill_artifact("/skills/my-skill/handler.js", "new_hash");
    let baseline = make_skill_baseline("/skills/my-skill/handler.js", "old_hash");

    let findings = provenance_findings_for_artifacts(&[baseline], &[artifact]);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::Medium);
    assert!(findings[0].id.contains("skill-unapproved-change"));
    assert!(findings[0].evidence.as_ref().unwrap().contains("old_hash"));
}

#[test]
fn skill_remote_url_changed() {
    let mut artifact = make_skill_artifact("/skills/my-skill/handler.js", "same_hash");
    artifact.git_remote_url = Some("https://github.com/attacker/skill.git".to_string());

    let mut baseline = make_skill_baseline("/skills/my-skill/handler.js", "same_hash");
    baseline.git_remote_url = Some("https://github.com/trusted-org/skill.git".to_string());

    let findings = provenance_findings_for_artifacts(&[baseline], &[artifact]);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::High);
    assert!(findings[0].id.contains("skill-remote-redirect"));
    assert!(findings[0].evidence.as_ref().unwrap().contains("attacker"));
}

#[test]
fn skill_approved_baseline_clean() {
    let artifact = make_skill_artifact("/skills/my-skill/handler.js", "matching_hash");
    let baseline = make_skill_baseline("/skills/my-skill/handler.js", "matching_hash");

    let findings = provenance_findings_for_artifacts(&[baseline], &[artifact]);
    assert!(
        findings.is_empty(),
        "matching hash should produce no finding"
    );
}

#[test]
fn skill_no_git_no_provenance_finding() {
    // Skill without git provenance, but has a matching baseline → no finding
    let artifact = make_skill_artifact("/skills/npm-skill/index.js", "hash_a");
    let baseline = make_skill_baseline("/skills/npm-skill/index.js", "hash_a");

    let findings = provenance_findings_for_artifacts(&[baseline], &[artifact]);
    assert!(
        findings.is_empty(),
        "npm skill with matching hash should produce no finding"
    );
}

#[test]
fn git_provenance_extraction_from_fake_repo() {
    let dir = tempfile::tempdir().expect("temp dir");
    let skill_dir = dir.path().join("my-skill");
    let git_dir = skill_dir.join(".git");

    // Create fake .git structure
    fs::create_dir_all(&git_dir).unwrap();
    fs::create_dir_all(git_dir.join("refs").join("heads")).unwrap();

    // Write .git/config with remote origin
    fs::write(
        git_dir.join("config"),
        r#"[core]
    repositoryformatversion = 0
[remote "origin"]
    url = https://github.com/test-org/test-skill.git
    fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
    remote = origin
"#,
    )
    .unwrap();

    // Write .git/HEAD pointing to main
    fs::write(git_dir.join("HEAD"), "ref: refs/heads/main\n").unwrap();

    // Write the ref with a SHA
    fs::write(
        git_dir.join("refs").join("heads").join("main"),
        "abcdef1234567890abcdef1234567890abcdef12\n",
    )
    .unwrap();

    // Write a skill file
    let handler = skill_dir.join("handler.js");
    fs::write(&handler, "console.log('hello');").unwrap();

    // Test extraction — use the public scan function
    let output = clawguard::scan::skills::scan_skill_dir(&skill_dir, 1_048_576, &[]);

    // Should have artifacts with git provenance
    assert!(
        !output.artifacts.is_empty(),
        "should have at least one artifact"
    );
    let art = &output.artifacts[0];
    assert!(art.git_provenance.is_some(), "should have git provenance");
    let prov = art.git_provenance.as_ref().unwrap();
    assert_eq!(
        prov.remote_url.as_deref(),
        Some("https://github.com/test-org/test-skill.git")
    );
    assert_eq!(
        prov.head_sha.as_deref(),
        Some("abcdef1234567890abcdef1234567890abcdef12")
    );
}

// ---- DB migration test ----

#[test]
fn baseline_record_round_trips_with_provenance() {
    let (_dir, mut store) = setup_state();

    let baseline = BaselineRecord {
        path: "/skills/test/handler.js".to_string(),
        sha256: "abc123".to_string(),
        approved_at_unix_ms: 1000,
        source_label: "skills".to_string(),
        git_remote_url: Some("https://github.com/org/skill.git".to_string()),
        git_head_sha: Some("deadbeef".repeat(5)),
    };

    store.upsert_baseline(&baseline).unwrap();

    let loaded = store
        .baseline_for_path("/skills/test/handler.js")
        .unwrap()
        .expect("baseline should exist");

    assert_eq!(loaded.git_remote_url, baseline.git_remote_url);
    assert_eq!(loaded.git_head_sha, baseline.git_head_sha);
    assert_eq!(loaded.sha256, "abc123");
}
