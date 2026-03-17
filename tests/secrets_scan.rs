use std::fs;
use std::path::PathBuf;

use clawguard::scan::secrets::scan_secret_files;
use clawguard::scan::{Finding, FindingCategory, Severity};
use tempfile::tempdir;

#[test]
fn env_file_with_openai_key_is_flagged() {
    let output = scan_secret_files(&[fixture_path("unsafe.env")], 1024 * 1024);
    finding_with_evidence(&output.findings, "OPENAI_API_KEY=sk-...redacted");
}

#[test]
fn secret_findings_use_secrets_category() {
    let output = scan_secret_files(&[fixture_path("unsafe.env")], 1024 * 1024);
    let finding = finding_with_evidence(&output.findings, "OPENAI_API_KEY=sk-...redacted");

    assert_eq!(finding.category, FindingCategory::Secrets);
    assert_eq!(finding.detector_id, "secrets");
}

#[test]
fn secret_evidence_is_redacted() {
    let output = scan_secret_files(&[fixture_path("unsafe.env")], 1024 * 1024);
    let finding = finding_with_evidence(&output.findings, "OPENAI_API_KEY=sk-...redacted");

    assert_ne!(
        finding.evidence.as_deref(),
        Some("OPENAI_API_KEY=sk-live-super-secret-demo-value")
    );
}

#[test]
fn secret_finding_recommends_rotation() {
    let output = scan_secret_files(&[fixture_path("unsafe.env")], 1024 * 1024);
    let finding = finding_with_evidence(&output.findings, "OPENAI_API_KEY=sk-...redacted");

    assert_eq!(
        finding.recommended_action.label,
        "Rotate and remove the exposed secret from local state"
    );
}

#[test]
fn config_file_with_hardcoded_api_key_is_flagged() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let config_path = temp_dir.path().join("openclaw.json");
    fs::write(
        &config_path,
        r#"
        {
          "providers": {
            "openai": {
              "api_key": "sk-hardcoded-config-secret"
            }
          }
        }
        "#,
    )
    .expect("config fixture should be written");

    let output = scan_secret_files(&[config_path], 1024 * 1024);
    finding_with_evidence(&output.findings, "api_key=sk-...redacted");
}

#[test]
fn config_file_with_secret_like_url_value_is_not_flagged() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let config_path = temp_dir.path().join("openclaw.json");
    fs::write(
        &config_path,
        r#"
        {
          "providers": {
            "openai": {
              "api_key_endpoint": "https://api.openai.com/v1/"
            }
          }
        }
        "#,
    )
    .expect("config fixture should be written");

    let output = scan_secret_files(&[config_path], 1024 * 1024);

    assert_eq!(output.findings.len(), 0);
}

#[test]
fn ssh_private_key_file_is_flagged() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let key_path = temp_dir.path().join("id_ed25519");
    fs::write(
        &key_path,
        r#"
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAE
        -----END OPENSSH PRIVATE KEY-----
        "#,
    )
    .expect("private key fixture should be written");

    let output = scan_secret_files(&[key_path], 1024 * 1024);
    finding_with_evidence(&output.findings, "-----BEGIN OPENSSH PRIVATE KEY-----");
}

#[test]
fn openssh_private_key_is_critical() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let key_path = temp_dir.path().join("id_ed25519");
    fs::write(
        &key_path,
        r#"
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAE
        -----END OPENSSH PRIVATE KEY-----
        "#,
    )
    .expect("private key fixture should be written");

    let output = scan_secret_files(&[key_path], 1024 * 1024);
    let finding = finding_with_evidence(&output.findings, "-----BEGIN OPENSSH PRIVATE KEY-----");

    assert_eq!(finding.severity, Severity::Critical);
}

#[test]
fn pem_private_key_header_is_flagged() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let key_path = temp_dir.path().join("id_rsa");
    fs::write(
        &key_path,
        r#"
        -----BEGIN RSA PRIVATE KEY-----
        MIICXAIBAAKBgQC7
        -----END RSA PRIVATE KEY-----
        "#,
    )
    .expect("pem private key fixture should be written");

    let output = scan_secret_files(&[key_path], 1024 * 1024);
    finding_with_evidence(&output.findings, "-----BEGIN RSA PRIVATE KEY-----");
}

#[test]
fn safe_env_file_produces_no_findings() {
    let output = scan_secret_files(&[fixture_path("safe.env")], 1024 * 1024);

    assert_eq!(output.findings.len(), 0);
}

#[test]
fn generic_high_entropy_text_without_secret_context_is_not_flagged() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let notes_path = temp_dir.path().join("notes.txt");
    fs::write(
        &notes_path,
        "build id: sk-just-a-demo-fragment\nrandom string: 9d3f4a7c2b5e8f1a6c0d4e2b7f9a1c3d",
    )
    .expect("notes fixture should be written");

    let output = scan_secret_files(&[notes_path], 1024 * 1024);

    assert_eq!(output.findings.len(), 0);
}

#[test]
fn missing_secret_file_produces_no_findings() {
    let output = scan_secret_files(
        &[PathBuf::from("tests/fixtures/env/missing.env")],
        1024 * 1024,
    );

    assert_eq!(output.findings.len(), 0);
    assert_eq!(output.artifacts.len(), 0);
}

#[test]
fn scanned_secret_files_produce_hash_artifacts() {
    let output = scan_secret_files(&[fixture_path("unsafe.env")], 1024 * 1024);

    assert_eq!(output.artifacts.len(), 1);
    assert!(output.artifacts[0].path.ends_with("unsafe.env"));
    assert_eq!(output.artifacts[0].sha256.len(), 64);
}

#[test]
fn auth_profile_env_reference_is_not_flagged() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let auth_path = temp_dir.path().join("auth-profiles.json");
    fs::write(
        &auth_path,
        r#"
        {
          "profiles": {
            "primary": {
              "type": "api_key",
              "keyRef": "env:OPENAI_API_KEY"
            }
          }
        }
        "#,
    )
    .expect("auth profile fixture should be written");

    let output = scan_secret_files(&[auth_path], 1024 * 1024);

    assert_eq!(output.findings.len(), 0);
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from("tests/fixtures/env").join(name)
}

fn finding_with_evidence<'a>(findings: &'a [Finding], evidence: &str) -> &'a Finding {
    findings
        .iter()
        .find(|finding| finding.evidence.as_deref() == Some(evidence))
        .unwrap_or_else(|| panic!("expected finding with evidence: {evidence}"))
}
