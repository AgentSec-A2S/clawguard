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

// --- Sprint 1 Task 3.2: byte-first file-type mismatch detection ---

fn write_bytes(root: &std::path::Path, name: &str, bytes: &[u8]) -> PathBuf {
    fs::create_dir_all(root).unwrap();
    let p = root.join(name);
    fs::write(&p, bytes).unwrap();
    p
}

fn has_file_type_mismatch(output: &clawguard::scan::skills::SkillScanOutput) -> bool {
    output
        .findings
        .iter()
        .any(|f| f.id.contains("file-type-mismatch"))
}

#[test]
fn elf_payload_disguised_as_markdown_is_flagged() {
    let dir = tempdir().unwrap();
    let skill_root = dir.path().join("evil-skill");
    write_bytes(&skill_root, "SKILL.md", b"\x7FELF\x02\x01\x01\x00extra junk");

    let output = scan_skill_dir(&skill_root, 1024 * 1024, &["node_modules".to_string()]);

    let f = output
        .findings
        .iter()
        .find(|f| f.id.contains("file-type-mismatch"))
        .expect("file-type-mismatch finding");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.category, FindingCategory::Skills);
    assert_eq!(f.owasp_asi.as_deref(), Some("ASI06"));
    // Binary contents must not produce an artifact entry.
    assert!(output.artifacts.is_empty());
}

#[test]
fn plain_markdown_content_is_not_flagged_as_file_type_mismatch() {
    let dir = tempdir().unwrap();
    let skill_root = dir.path().join("safe-skill");
    write_bytes(&skill_root, "SKILL.md", b"# Safe Skill\n\nHello world.\n");

    let output = scan_skill_dir(&skill_root, 1024 * 1024, &["node_modules".to_string()]);
    assert!(!has_file_type_mismatch(&output));
}

#[test]
fn native_extension_with_binary_header_is_not_flagged() {
    // .node, .wasm, .so, .dylib, .dll, .exe, .bin, .o, .a are never scanned
    // by the skill walker anyway, but the file-type helper itself must
    // short-circuit these extensions regardless of how they reach it.
    // Place a .node file with an ELF header in a skill dir, confirm no
    // file-type-mismatch finding is emitted (the walker will skip the file
    // because .node isn't in the scan extension allowlist).
    let dir = tempdir().unwrap();
    let skill_root = dir.path().join("binary-named");
    write_bytes(&skill_root, "native.node", b"\x7FELF\x02\x01\x01\x00");

    let output = scan_skill_dir(&skill_root, 1024 * 1024, &["node_modules".to_string()]);
    assert!(!has_file_type_mismatch(&output));
}

#[cfg(unix)]
#[test]
fn symlink_escape_outside_scan_root_is_not_inspected() {
    use std::os::unix::fs::symlink;
    let outside_dir = tempdir().unwrap();
    let outside_target = outside_dir.path().join("hidden.bin");
    fs::write(&outside_target, b"\x7FELF\x02\x01\x01\x00").unwrap();

    let scan_dir = tempdir().unwrap();
    let skill_root = scan_dir.path().join("skill");
    fs::create_dir_all(&skill_root).unwrap();
    // Symlink named as a .md file pointing at a binary outside the scan root.
    let link = skill_root.join("escape.md");
    symlink(&outside_target, &link).unwrap();

    let output = scan_skill_dir(&skill_root, 1024 * 1024, &["node_modules".to_string()]);
    assert!(
        !has_file_type_mismatch(&output),
        "scanner must not inspect symlink target outside scan root"
    );
}

#[test]
fn mach_o_mh_magic_in_markdown_is_flagged() {
    let dir = tempdir().unwrap();
    let skill_root = dir.path().join("macho");
    write_bytes(&skill_root, "SKILL.md", b"\xFE\xED\xFA\xCE\x07\x00\x00\x00");
    let output = scan_skill_dir(&skill_root, 1024 * 1024, &["node_modules".to_string()]);
    assert!(has_file_type_mismatch(&output));
}

#[test]
fn mach_o_mh_magic_64_in_markdown_is_flagged() {
    let dir = tempdir().unwrap();
    let skill_root = dir.path().join("macho64");
    write_bytes(&skill_root, "SKILL.md", b"\xFE\xED\xFA\xCF\x07\x00\x00\x01");
    let output = scan_skill_dir(&skill_root, 1024 * 1024, &["node_modules".to_string()]);
    assert!(has_file_type_mismatch(&output));
}

#[test]
fn mach_o_mh_cigam_in_markdown_is_flagged() {
    let dir = tempdir().unwrap();
    let skill_root = dir.path().join("cigam");
    write_bytes(&skill_root, "SKILL.md", b"\xCE\xFA\xED\xFE\x07\x00\x00\x00");
    let output = scan_skill_dir(&skill_root, 1024 * 1024, &["node_modules".to_string()]);
    assert!(has_file_type_mismatch(&output));
}

#[test]
fn mach_o_mh_cigam_64_in_markdown_is_flagged() {
    let dir = tempdir().unwrap();
    let skill_root = dir.path().join("cigam64");
    write_bytes(&skill_root, "SKILL.md", b"\xCF\xFA\xED\xFE\x07\x00\x00\x01");
    let output = scan_skill_dir(&skill_root, 1024 * 1024, &["node_modules".to_string()]);
    assert!(has_file_type_mismatch(&output));
}

#[test]
fn fat_universal_mach_o_in_markdown_is_flagged() {
    let dir = tempdir().unwrap();
    let skill_root = dir.path().join("fat");
    write_bytes(&skill_root, "SKILL.md", b"\xCA\xFE\xBA\xBE\x00\x00\x00\x02");
    let output = scan_skill_dir(&skill_root, 1024 * 1024, &["node_modules".to_string()]);
    assert!(has_file_type_mismatch(&output));
}

#[test]
fn fat_universal_cigam_in_markdown_is_flagged() {
    let dir = tempdir().unwrap();
    let skill_root = dir.path().join("fat-cigam");
    write_bytes(&skill_root, "SKILL.md", b"\xBE\xBA\xFE\xCA\x02\x00\x00\x00");
    let output = scan_skill_dir(&skill_root, 1024 * 1024, &["node_modules".to_string()]);
    assert!(has_file_type_mismatch(&output));
}
