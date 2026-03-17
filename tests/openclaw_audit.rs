use std::fs;
use std::path::{Path, PathBuf};

use clawguard::scan::openclaw::scan_openclaw_state;
use clawguard::scan::{Finding, FindingCategory, Severity};
use tempfile::{tempdir, TempDir};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[test]
fn exec_approvals_with_full_security_mode_is_flagged() {
    let (_temp_dir, approvals_path) =
        materialize_fixture("insecure-exec-approvals.json", "exec-approvals.json");
    let output = scan_openclaw_state(&[approvals_path], 1024 * 1024);
    let finding = finding_with_evidence(&output.findings, "defaults.security=full");

    assert_eq!(finding.category, FindingCategory::Config);
    assert_eq!(finding.detector_id, "openclaw-config");
    assert_eq!(finding.severity, Severity::High);
    assert_eq!(
        finding.recommended_action.label,
        "Tighten exec approval defaults before using host exec"
    );
}

#[test]
fn dangerous_exec_approval_finding_includes_review_recommendation() {
    let (_temp_dir, approvals_path) =
        materialize_fixture("insecure-exec-approvals.json", "exec-approvals.json");
    let output = scan_openclaw_state(&[approvals_path], 1024 * 1024);
    let finding = finding_with_evidence(&output.findings, "defaults.ask=off");

    assert_eq!(
        finding.recommended_action.label,
        "Tighten exec approval defaults before using host exec"
    );
}

#[test]
fn sandbox_off_with_exec_host_sandbox_is_flagged() {
    let (_temp_dir, config_path) = materialize_fixture("insecure-openclaw.json", "openclaw.json");
    let output = scan_openclaw_state(&[config_path], 1024 * 1024);
    let finding = finding_with_evidence(&output.findings, "tools.exec.host=sandbox");

    assert_eq!(finding.category, FindingCategory::Config);
    assert_eq!(finding.severity, Severity::Medium);
    assert_eq!(
        finding.recommended_action.label,
        "Enable sandboxing or stop routing exec through host fallback"
    );
}

#[test]
fn dangerous_sandbox_network_mode_is_flagged() {
    let (_temp_dir, config_path) = materialize_fixture("insecure-openclaw.json", "openclaw.json");
    let output = scan_openclaw_state(&[config_path], 1024 * 1024);
    let finding = finding_with_evidence(
        &output.findings,
        "agents.defaults.sandbox.docker.network=host",
    );

    assert_eq!(finding.category, FindingCategory::Config);
    assert_eq!(
        finding.recommended_action.label,
        "Use a non-dangerous sandbox network mode"
    );
}

#[test]
fn dangerous_sandbox_network_mode_is_critical() {
    let (_temp_dir, config_path) = materialize_fixture("insecure-openclaw.json", "openclaw.json");
    let output = scan_openclaw_state(&[config_path], 1024 * 1024);
    let finding = finding_with_evidence(
        &output.findings,
        "agents.defaults.sandbox.docker.network=host",
    );

    assert_eq!(finding.severity, Severity::Critical);
}

#[test]
fn per_agent_sandbox_override_is_flagged() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let config_path = temp_dir.path().join("openclaw.json");
    fs::write(
        &config_path,
        r#"
        {
          agents: {
            defaults: {
              sandbox: {
                mode: "all",
                docker: {
                  network: "none",
                },
              },
            },
            list: [
              {
                id: "worker",
                sandbox: {
                  mode: "off",
                  docker: {
                    network: "container:shared-net",
                  },
                },
                tools: {
                  exec: {
                    host: "sandbox",
                  },
                },
              },
            ],
          },
        }
        "#,
    )
    .expect("per-agent config should be written");
    set_mode(&config_path, 0o600);

    let output = scan_openclaw_state(&[config_path], 1024 * 1024);

    assert!(output.findings.iter().any(|finding| {
        finding.evidence.as_deref() == Some("agents.list[worker].tools.exec.host=sandbox")
            && finding.severity == Severity::Medium
    }));
    assert!(output.findings.iter().any(|finding| {
        finding.evidence.as_deref()
            == Some("agents.list[worker].sandbox.docker.network=container:shared-net")
            && finding.severity == Severity::Critical
    }));
}

#[test]
fn per_agent_exec_approvals_override_is_flagged() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let approvals_path = temp_dir.path().join("exec-approvals.json");
    fs::write(
        &approvals_path,
        r#"
        {
          "version": 1,
          "defaults": {
            "security": "deny",
            "ask": "on-miss"
          },
          "agents": {
            "worker": {
              "security": "full",
              "ask": "off",
              "autoAllowSkills": true
            }
          }
        }
        "#,
    )
    .expect("per-agent approvals should be written");
    set_mode(&approvals_path, 0o600);

    let output = scan_openclaw_state(&[approvals_path], 1024 * 1024);

    assert!(output.findings.iter().any(|finding| {
        finding.evidence.as_deref() == Some("agents.worker.security=full")
            && finding.severity == Severity::High
    }));
    assert!(output.findings.iter().any(|finding| {
        finding.evidence.as_deref() == Some("agents.worker.ask=off")
            && finding.severity == Severity::High
    }));
    assert!(output.findings.iter().any(|finding| {
        finding.evidence.as_deref() == Some("agents.worker.autoAllowSkills=true")
            && finding.severity == Severity::High
    }));
}

#[cfg(unix)]
#[test]
fn world_readable_auth_profile_is_flagged() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let auth_path = temp_dir.path().join("auth-profiles.json");
    fs::write(
        &auth_path,
        r#"{"profiles":{"primary":{"provider":"openai"}}}"#,
    )
    .expect("auth profile fixture should be written");
    set_mode(&auth_path, 0o644);

    let output = scan_openclaw_state(&[auth_path], 1024 * 1024);
    let finding = finding_with_action(
        &output.findings,
        "Restrict local file permissions to the current user",
    );

    assert_eq!(finding.category, FindingCategory::Config);
    assert_eq!(finding.severity, Severity::High);
}

#[cfg(unix)]
#[test]
fn config_permission_finding_uses_real_path() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let auth_path = temp_dir.path().join("auth-profiles.json");
    fs::write(
        &auth_path,
        r#"{"profiles":{"primary":{"provider":"openai"}}}"#,
    )
    .expect("auth profile fixture should be written");
    set_mode(&auth_path, 0o644);

    let output = scan_openclaw_state(&[auth_path.clone()], 1024 * 1024);
    let finding = finding_with_action(
        &output.findings,
        "Restrict local file permissions to the current user",
    );

    assert_eq!(finding.path, canonical_path_string(&auth_path));
}

#[test]
fn malformed_openclaw_state_file_does_not_panic() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let malformed_path = temp_dir.path().join("openclaw.json");
    fs::write(
        &malformed_path,
        r#"
        {
          agents: {
            defaults: {
              sandbox: {
                mode: "off",
        "#,
    )
    .expect("malformed state file should be written");
    set_mode(&malformed_path, 0o600);

    let output = scan_openclaw_state(&[malformed_path], 1024 * 1024);

    assert_eq!(output.findings.len(), 0);
    assert_eq!(output.artifacts.len(), 1);
}

#[test]
fn safe_openclaw_state_produces_no_findings() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let config_path = temp_dir.path().join("openclaw.json");
    let approvals_path = temp_dir.path().join("exec-approvals.json");
    let auth_path = temp_dir.path().join("auth-profiles.json");

    fs::write(
        &config_path,
        r#"
        {
          agents: {
            defaults: {
              sandbox: {
                mode: "all",
                docker: {
                  network: "none",
                },
              },
            },
          },
          tools: {
            exec: {
              host: "sandbox",
            },
          },
        }
        "#,
    )
    .expect("safe openclaw config should be written");
    fs::write(
        &approvals_path,
        r#"
        {
          "version": 1,
          "defaults": {
            "security": "deny",
            "ask": "on-miss",
            "autoAllowSkills": false
          }
        }
        "#,
    )
    .expect("safe exec approvals should be written");
    fs::write(
        &auth_path,
        r#"{"profiles":{"primary":{"provider":"openai"}}}"#,
    )
    .expect("safe auth profile should be written");
    set_mode(&config_path, 0o600);
    set_mode(&approvals_path, 0o600);
    set_mode(&auth_path, 0o600);

    let output = scan_openclaw_state(&[config_path, approvals_path, auth_path], 1024 * 1024);

    assert_eq!(output.findings.len(), 0);
    assert_eq!(output.artifacts.len(), 3);
}

#[test]
fn empty_openclaw_config_produces_no_findings() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let config_path = temp_dir.path().join("openclaw.json");
    fs::write(&config_path, "{}").expect("empty config should be written");
    set_mode(&config_path, 0o600);

    let output = scan_openclaw_state(&[config_path], 1024 * 1024);

    assert_eq!(output.findings.len(), 0);
    assert_eq!(output.artifacts.len(), 1);
}

#[test]
fn lookalike_file_name_is_not_treated_as_openclaw_state() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let config_path = temp_dir.path().join("not-openclaw.json");
    fs::write(
        &config_path,
        r#"
        {
          agents: {
            defaults: {
              sandbox: {
                mode: "off",
                docker: {
                  network: "host",
                },
              },
            },
          },
          tools: {
            exec: {
              host: "sandbox",
            },
          },
        }
        "#,
    )
    .expect("lookalike config should be written");
    set_mode(&config_path, 0o600);

    let output = scan_openclaw_state(&[config_path], 1024 * 1024);

    assert_eq!(output.findings.len(), 0);
    assert_eq!(output.artifacts.len(), 1);
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from("tests/fixtures/openclaw").join(name)
}

fn materialize_fixture(source_name: &str, target_name: &str) -> (TempDir, PathBuf) {
    let temp_dir = tempdir().expect("temp dir should be created");
    let target_path = temp_dir.path().join(target_name);
    let contents =
        fs::read_to_string(fixture_path(source_name)).expect("fixture contents should be read");
    fs::write(&target_path, contents).expect("fixture contents should be written");
    set_mode(&target_path, 0o600);
    (temp_dir, target_path)
}

fn finding_with_action<'a>(findings: &'a [Finding], action_label: &str) -> &'a Finding {
    findings
        .iter()
        .find(|finding| finding.recommended_action.label == action_label)
        .unwrap_or_else(|| panic!("expected finding with action label: {action_label}"))
}

fn finding_with_evidence<'a>(findings: &'a [Finding], evidence: &str) -> &'a Finding {
    findings
        .iter()
        .find(|finding| finding.evidence.as_deref() == Some(evidence))
        .unwrap_or_else(|| panic!("expected finding with evidence: {evidence}"))
}

fn canonical_path_string(path: &Path) -> String {
    fs::canonicalize(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .into_owned()
}

fn set_mode(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        let permissions = fs::Permissions::from_mode(mode);
        fs::set_permissions(path, permissions).expect("permissions should be set");
    }

    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
}
