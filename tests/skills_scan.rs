use std::fs;
use std::path::PathBuf;

use clawguard::scan::skills::{scan_skill_dir, SkillSourceHint};
use clawguard::scan::{FindingCategory, Severity};
use tempfile::tempdir;

#[test]
fn skill_with_shell_execution_is_flagged() {
    let output = scan_fixture("risky-shell");

    assert!(output
        .findings
        .iter()
        .any(|finding| finding.category == FindingCategory::Skills
            && finding.severity == Severity::High
            && finding
                .evidence
                .as_deref()
                .is_some_and(|evidence| evidence.contains("child_process.exec"))));
}

#[test]
fn skill_with_outbound_network_usage_is_flagged() {
    let output = scan_fixture("risky-network");

    assert!(output
        .findings
        .iter()
        .any(|finding| finding.category == FindingCategory::Skills
            && finding.severity == Severity::Medium
            && finding
                .evidence
                .as_deref()
                .is_some_and(|evidence| evidence.contains("curl https://example.com"))));
}

#[test]
fn skill_with_install_instructions_is_flagged() {
    let output = scan_fixture("risky-install");

    assert!(output
        .findings
        .iter()
        .any(|finding| finding.category == FindingCategory::Skills
            && finding.severity == Severity::Medium
            && finding
                .evidence
                .as_deref()
                .is_some_and(|evidence| evidence.contains("npm install -g"))));
}

#[test]
fn safe_skill_produces_no_findings() {
    let output = scan_fixture("safe-skill");

    assert_eq!(output.findings.len(), 0);
    assert_eq!(output.artifacts.len(), 1);
}

#[test]
fn missing_skill_directory_produces_no_findings() {
    let missing_dir = PathBuf::from("tests/fixtures/skills/does-not-exist");
    let output = scan_skill_dir(&missing_dir, 1024 * 1024, &["node_modules".to_string()]);

    assert_eq!(output.findings.len(), 0);
    assert_eq!(output.artifacts.len(), 0);
}

#[test]
fn scanned_skill_files_produce_hash_artifacts() {
    let output = scan_fixture("risky-shell");

    assert_eq!(output.artifacts.len(), 1);
    assert!(output.artifacts[0].path.ends_with("SKILL.md"));
    assert_eq!(output.artifacts[0].sha256.len(), 64);
    assert_eq!(
        output.artifacts[0].source_hint,
        Some(SkillSourceHint::LocalInstall)
    );
}

#[test]
fn local_skill_directory_records_local_install_source_hint() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let skill_dir = temp_dir.path().join("local-skill");
    fs::create_dir(&skill_dir).expect("skill dir should be created");
    fs::write(
        skill_dir.join("SKILL.md"),
        "# Local Skill\n\nPrint a summary without shelling out.\n",
    )
    .expect("skill file should be written");

    let output = scan_skill_dir(&skill_dir, 1024 * 1024, &["node_modules".to_string()]);

    assert_eq!(output.artifacts.len(), 1);
    assert_eq!(
        output.artifacts[0].source_hint,
        Some(SkillSourceHint::LocalInstall)
    );
}

#[test]
fn git_backed_skill_directory_records_vcs_source_hint() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let skill_dir = temp_dir.path().join("git-skill");
    fs::create_dir_all(skill_dir.join(".git")).expect("git dir should be created");
    fs::write(
        skill_dir.join("SKILL.md"),
        "# Git Skill\n\nFetch a local summary.\n",
    )
    .expect("skill file should be written");

    let output = scan_skill_dir(&skill_dir, 1024 * 1024, &["node_modules".to_string()]);

    assert_eq!(output.artifacts.len(), 1);
    assert_eq!(
        output.artifacts[0].source_hint,
        Some(SkillSourceHint::VcsRepository)
    );
}

fn scan_fixture(name: &str) -> clawguard::scan::skills::SkillScanOutput {
    let path = PathBuf::from("tests/fixtures/skills").join(name);
    scan_skill_dir(&path, 1024 * 1024, &["node_modules".to_string()])
}
