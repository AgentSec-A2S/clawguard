use std::fs;
use std::path::{Path, PathBuf};

use clawguard::scan::cve::{scan_openclaw_advisories, scan_openclaw_advisories_from_feed};
use clawguard::scan::{Finding, FindingCategory, Severity};
use tempfile::tempdir;

#[test]
fn vulnerable_openclaw_version_matches_fixture_advisory() {
    let findings = scan_openclaw_advisories(
        &[package_fixture_path()],
        &advisory_fixture_path(),
        1024 * 1024,
    );
    let finding = finding_with_id_fragment(&findings, "CG-OPENCLAW-2026-0001");

    assert_eq!(finding.category, FindingCategory::Advisory);
    assert_eq!(finding.detector_id, "cve");
    assert_eq!(finding.severity, Severity::High);
    assert_eq!(finding.evidence.as_deref(), Some("openclaw@2026.3.14"));
}

#[test]
fn safe_openclaw_version_does_not_match_fixture_advisory() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let package_path = temp_dir.path().join("package.json");
    fs::write(
        &package_path,
        r#"
        {
          "name": "openclaw",
          "version": "2026.3.20"
        }
        "#,
    )
    .expect("safe package manifest should be written");

    let findings = scan_openclaw_advisories(&[package_path], &advisory_fixture_path(), 1024 * 1024);

    assert_eq!(findings.len(), 0);
}

#[test]
fn missing_advisory_feed_returns_info_finding() {
    let findings = scan_openclaw_advisories(
        &[package_fixture_path()],
        Path::new("tests/fixtures/advisories/missing-openclaw.json"),
        1024 * 1024,
    );
    let finding = finding_with_action(
        &findings,
        "Restore the local advisory feed before trusting CVE results",
    );

    assert_eq!(finding.category, FindingCategory::Advisory);
    assert_eq!(finding.severity, Severity::Info);
}

#[test]
fn corrupt_advisory_feed_returns_info_finding() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let advisory_path = temp_dir.path().join("openclaw.json");
    // Advisory feeds are ClawGuard-owned strict JSON, not JSON5.
    fs::write(&advisory_path, "{ advisories: [").expect("corrupt advisory should be written");

    let findings = scan_openclaw_advisories(&[package_fixture_path()], &advisory_path, 1024 * 1024);
    let finding = finding_with_action(
        &findings,
        "Restore the local advisory feed before trusting CVE results",
    );

    assert_eq!(finding.category, FindingCategory::Advisory);
    assert_eq!(finding.severity, Severity::Info);
}

#[test]
fn non_semver_package_version_returns_info_finding() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let package_path = temp_dir.path().join("package.json");
    fs::write(
        &package_path,
        r#"
        {
          "name": "openclaw",
          "version": "2026.03.14"
        }
        "#,
    )
    .expect("non-semver package manifest should be written");

    let findings = scan_openclaw_advisories(&[package_path], &advisory_fixture_path(), 1024 * 1024);
    let finding = finding_with_action(
        &findings,
        "Provide OpenClaw version evidence before trusting CVE results",
    );

    assert_eq!(finding.category, FindingCategory::Advisory);
    assert_eq!(finding.severity, Severity::Info);
}

#[test]
fn missing_package_manifest_returns_info_finding() {
    let findings = scan_openclaw_advisories(
        &[PathBuf::from(
            "tests/fixtures/openclaw/missing-package.json",
        )],
        &advisory_fixture_path(),
        1024 * 1024,
    );
    let finding = finding_with_action(
        &findings,
        "Provide OpenClaw version evidence before trusting CVE results",
    );

    assert_eq!(finding.category, FindingCategory::Advisory);
    assert_eq!(finding.severity, Severity::Info);
}

#[test]
fn package_manifest_in_common_subdirectory_is_used_for_advisories() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let root_manifest = temp_dir.path().join("package.json");
    let fallback_manifest = temp_dir
        .path()
        .join("packages")
        .join("core")
        .join("package.json");
    fs::create_dir_all(
        fallback_manifest
            .parent()
            .expect("fallback parent should exist"),
    )
    .expect("fallback package dir should be created");
    write_package_manifest(&fallback_manifest, "openclaw", "2026.3.14");

    let findings =
        scan_openclaw_advisories(&[root_manifest], &advisory_fixture_path(), 1024 * 1024);
    let finding = finding_with_id_fragment(&findings, "CG-OPENCLAW-2026-0001");
    let expected_path = fs::canonicalize(&fallback_manifest)
        .expect("fallback manifest should canonicalize")
        .to_string_lossy()
        .to_string();

    assert_eq!(finding.category, FindingCategory::Advisory);
    assert_eq!(finding.path, expected_path);
    assert_eq!(finding.evidence.as_deref(), Some("openclaw@2026.3.14"));
    assert!(!findings
        .iter()
        .any(|finding| finding.id.contains("package-version-unavailable")));
}

#[test]
fn advisory_scan_prefers_root_manifest_when_both_root_and_fallback_exist() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let root_manifest = temp_dir.path().join("package.json");
    let fallback_manifest = temp_dir
        .path()
        .join("packages")
        .join("core")
        .join("package.json");
    fs::create_dir_all(
        fallback_manifest
            .parent()
            .expect("fallback parent should exist"),
    )
    .expect("fallback package dir should be created");
    write_package_manifest(&root_manifest, "openclaw", "2026.3.20");
    write_package_manifest(&fallback_manifest, "openclaw", "2026.3.14");

    let findings =
        scan_openclaw_advisories(&[root_manifest], &advisory_fixture_path(), 1024 * 1024);

    assert_eq!(findings.len(), 0);
}

#[test]
fn only_matching_advisory_is_emitted_for_package_version() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let advisory_path = temp_dir.path().join("openclaw.json");
    fs::write(
        &advisory_path,
        r#"
        {
          "advisories": [
            {
              "id": "CG-OPENCLAW-2026-0001",
              "package": "openclaw",
              "affected": ">=2026.3.0, <2026.3.20",
              "severity": "high",
              "summary": "Matching advisory",
              "recommendation": "Upgrade"
            },
            {
              "id": "CG-OPENCLAW-2026-0002",
              "package": "openclaw",
              "affected": ">=2026.3.20, <2026.3.25",
              "severity": "critical",
              "summary": "Non-matching advisory",
              "recommendation": "Upgrade"
            }
          ]
        }
        "#,
    )
    .expect("advisory feed should be written");

    let findings = scan_openclaw_advisories(&[package_fixture_path()], &advisory_path, 1024 * 1024);

    assert_eq!(findings.len(), 1);
    assert!(findings[0].id.contains("CG-OPENCLAW-2026-0001"));
}

#[test]
fn multiple_advisories_are_filtered_to_matching_package() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let advisory_path = temp_dir.path().join("openclaw.json");
    fs::write(
        &advisory_path,
        r#"
        {
          "advisories": [
            {
              "id": "CG-OPENCLAW-2026-0001",
              "package": "openclaw",
              "affected": ">=2026.3.0, <2026.3.20",
              "severity": "high",
              "summary": "Matching advisory",
              "recommendation": "Upgrade"
            },
            {
              "id": "CG-OTHER-2026-0001",
              "package": "other-package",
              "affected": ">=1.0.0, <2.0.0",
              "severity": "critical",
              "summary": "Different package",
              "recommendation": "Upgrade"
            }
          ]
        }
        "#,
    )
    .expect("advisory feed should be written");

    let findings = scan_openclaw_advisories(&[package_fixture_path()], &advisory_path, 1024 * 1024);

    assert_eq!(findings.len(), 1);
    assert!(findings[0].id.contains("CG-OPENCLAW-2026-0001"));
}

#[test]
fn embedded_advisory_feed_matches_fixture_version() {
    let feed = fs::read_to_string(advisory_fixture_path()).expect("fixture advisory should read");

    let findings =
        scan_openclaw_advisories_from_feed(&[package_fixture_path()], &feed, 1024 * 1024);
    let finding = finding_with_id_fragment(&findings, "CG-OPENCLAW-2026-0001");

    assert_eq!(finding.category, FindingCategory::Advisory);
    assert_eq!(finding.severity, Severity::High);
}

#[test]
fn modern_openclaw_advisory_feed_schema_is_supported() {
    let feed = r#"
        {
          "advisories": [
            {
              "id": "CVE-2026-25253",
              "title": "1-Click Remote Code Execution (RCE)",
              "severity": "Critical",
              "description": "Query-string-controlled gateway URL enabled token theft and RCE.",
              "affected_versions": "< 2026.3.20",
              "fixed_version": "2026.3.20",
              "references": [
                "https://example.com/advisories/CVE-2026-25253"
              ]
            }
          ]
        }
    "#;

    let findings = scan_openclaw_advisories_from_feed(&[package_fixture_path()], feed, 1024 * 1024);
    let finding = finding_with_id_fragment(&findings, "CVE-2026-25253");

    assert_eq!(finding.category, FindingCategory::Advisory);
    assert_eq!(finding.severity, Severity::Critical);
    assert_eq!(finding.evidence.as_deref(), Some("openclaw@2026.3.14"));
}

#[test]
fn bundled_advisory_feed_does_not_ship_example_matches() {
    let feed = fs::read_to_string(Path::new("advisories/openclaw.json"))
        .expect("bundled advisory feed should read");

    let findings =
        scan_openclaw_advisories_from_feed(&[package_fixture_path()], &feed, 1024 * 1024);

    assert_eq!(findings.len(), 0);
}

fn advisory_fixture_path() -> PathBuf {
    PathBuf::from("tests/fixtures/advisories/openclaw.json")
}

fn package_fixture_path() -> PathBuf {
    PathBuf::from("tests/fixtures/openclaw/package.json")
}

fn finding_with_action<'a>(findings: &'a [Finding], action_label: &str) -> &'a Finding {
    findings
        .iter()
        .find(|finding| finding.recommended_action.label == action_label)
        .unwrap_or_else(|| panic!("expected finding with action label: {action_label}"))
}

fn finding_with_id_fragment<'a>(findings: &'a [Finding], id_fragment: &str) -> &'a Finding {
    findings
        .iter()
        .find(|finding| finding.id.contains(id_fragment))
        .unwrap_or_else(|| panic!("expected finding with id fragment: {id_fragment}"))
}

fn write_package_manifest(path: &Path, name: &str, version: &str) {
    fs::write(
        path,
        format!(
            r#"
        {{
          "name": "{name}",
          "version": "{version}"
        }}
        "#
        ),
    )
    .expect("package manifest should be written");
}
