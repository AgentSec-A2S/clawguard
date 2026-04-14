use std::fs;
use std::path::PathBuf;

use clawguard::scan::mcp::scan_mcp_configs;
use clawguard::scan::{Finding, FindingCategory, Severity};
use tempfile::tempdir;

#[test]
fn mcp_server_with_unpinned_package_version_is_flagged() {
    let output = scan_fixture();
    let finding = finding_with_evidence(
        &output.findings,
        "@modelcontextprotocol/server-filesystem@latest",
    );

    assert_eq!(finding.category, FindingCategory::Mcp);
    assert_eq!(finding.severity, Severity::Medium);
}

#[test]
fn mcp_server_with_overly_broad_allowed_directories_is_flagged() {
    let output = scan_fixture();
    let finding = finding_with_action(
        &output.findings,
        "Narrow the allowed directories for this MCP server",
    );

    assert_eq!(finding.category, FindingCategory::Mcp);
    assert_eq!(finding.severity, Severity::High);
    assert_eq!(finding.evidence.as_deref(), Some("/"));
}

#[test]
fn mcp_server_with_npx_dash_y_launcher_is_flagged() {
    let output = scan_fixture();
    let finding = finding_with_evidence(&output.findings, "npx -y");

    assert_eq!(finding.category, FindingCategory::Mcp);
    assert_eq!(finding.severity, Severity::High);
}

#[test]
fn equivalent_auto_install_launchers_are_flagged() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let config_path = temp_dir.path().join("equivalent-launchers.json");
    fs::write(
        &config_path,
        r#"
        {
          mcpServers: {
            bunxServer: {
              command: "bunx",
              args: ["-y", "browser-mcp@1.2.3"],
            },
            absoluteNpxServer: {
              command: "/opt/homebrew/bin/npx",
              args: ["--yes", "@modelcontextprotocol/server-fetch@1.0.0"],
            },
          },
        }
        "#,
    )
    .expect("equivalent launcher fixture should be written");

    let output = scan_mcp_configs(&[config_path], 1024 * 1024);

    assert!(output
        .findings
        .iter()
        .any(|finding| finding.evidence.as_deref() == Some("bunx -y")));
    assert!(output
        .findings
        .iter()
        .any(|finding| finding.evidence.as_deref() == Some("npx --yes")));
    assert!(output.findings.iter().all(|finding| {
        finding.evidence.as_deref() != Some("browser-mcp@1.2.3")
            && finding.evidence.as_deref() != Some("@modelcontextprotocol/server-fetch@1.0.0")
    }));
}

#[test]
fn bare_bunx_launcher_is_flagged_as_suspicious() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let config_path = temp_dir.path().join("bare-bunx.json");
    fs::write(
        &config_path,
        r#"
        {
          mcpServers: {
            docs: {
              command: "bunx",
              args: ["@modelcontextprotocol/server-fetch@1.0.0"],
            },
          },
        }
        "#,
    )
    .expect("bare bunx fixture should be written");

    let output = scan_mcp_configs(&[config_path], 1024 * 1024);

    assert!(output.findings.iter().any(|finding| {
        finding.category == FindingCategory::Mcp
            && finding.recommended_action.label == "Review this MCP launcher before enabling it"
            && finding.evidence.as_deref() == Some("bunx")
    }));
}

#[test]
fn missing_mcp_config_file_produces_no_findings() {
    let missing_path = PathBuf::from("tests/fixtures/mcp/does-not-exist.json");
    let output = scan_mcp_configs(&[missing_path], 1024 * 1024);

    assert_eq!(output.findings.len(), 0);
    assert_eq!(output.artifacts.len(), 0);
}

#[test]
fn scanned_mcp_config_produces_hash_artifact() {
    let output = scan_fixture();

    assert_eq!(output.artifacts.len(), 1);
    assert!(output.artifacts[0].path.ends_with("config.json"));
    assert_eq!(output.artifacts[0].sha256.len(), 64);
}

#[test]
fn extracts_nested_openclaw_plugin_mcp_servers() {
    let output = scan_fixture();

    assert!(output.findings.iter().any(|finding| {
        finding.category == FindingCategory::Mcp
            && finding
                .plain_english_explanation
                .contains("MCP server launcher")
    }));
}

#[test]
fn accepts_root_level_mcp_server_maps() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let root_mcp_path = temp_dir.path().join("root-mcp.json");
    let root_servers_path = temp_dir.path().join("root-servers.json");

    fs::write(
        &root_mcp_path,
        r#"
        {
          mcpServers: {
            docs: {
              command: "npx",
              args: ["@modelcontextprotocol/server-fetch"],
            },
          },
        }
        "#,
    )
    .expect("root mcp file should be written");

    fs::write(
        &root_servers_path,
        r#"
        {
          servers: {
            browser: {
              command: "npx",
              args: ["browser-mcp"],
            },
          },
        }
        "#,
    )
    .expect("root servers file should be written");

    let output = scan_mcp_configs(&[root_mcp_path, root_servers_path], 1024 * 1024);

    assert!(output
        .findings
        .iter()
        .any(|finding| finding.evidence.as_deref() == Some("@modelcontextprotocol/server-fetch")));
    assert!(output
        .findings
        .iter()
        .any(|finding| finding.evidence.as_deref() == Some("browser-mcp")));
}

#[test]
fn malformed_mcp_config_does_not_panic() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let malformed_path = temp_dir.path().join("malformed.json");
    fs::write(
        &malformed_path,
        r#"
        {
          plugins: {
            entries: {
              acpx: {
                config: {
                  mcpServers: {
                    docs: { command: "npx", args: [,
        "#,
    )
    .expect("malformed file should be written");

    let output = scan_mcp_configs(&[malformed_path], 1024 * 1024);

    assert_eq!(output.findings.len(), 0);
    assert_eq!(output.artifacts.len(), 1);
}

#[test]
fn launcher_finding_includes_review_launcher_recommendation() {
    let output = scan_fixture();
    let finding = finding_with_evidence(&output.findings, "npx -y");

    assert_eq!(
        finding.recommended_action.label,
        "Review this MCP launcher before enabling it"
    );
}

#[test]
fn unpinned_package_finding_recommends_pin_version() {
    let output = scan_fixture();
    let finding = finding_with_evidence(
        &output.findings,
        "@modelcontextprotocol/server-filesystem@latest",
    );

    assert_eq!(
        finding.recommended_action.label,
        "Pin an exact MCP package version"
    );
}

#[test]
fn semver_range_package_versions_are_treated_as_unpinned() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let config_path = temp_dir.path().join("range-version.json");
    fs::write(
        &config_path,
        r#"
        {
          mcpServers: {
            ranged: {
              command: "npx",
              args: ["@modelcontextprotocol/server-filesystem@^1.2.3"],
            },
          },
        }
        "#,
    )
    .expect("range-version fixture should be written");

    let output = scan_mcp_configs(&[config_path], 1024 * 1024);

    assert!(output.findings.iter().any(|finding| {
        finding.category == FindingCategory::Mcp
            && finding.evidence.as_deref() == Some("@modelcontextprotocol/server-filesystem@^1.2.3")
            && finding.recommended_action.label == "Pin an exact MCP package version"
    }));
}

#[test]
fn broad_directory_finding_recommends_narrowing_paths() {
    let output = scan_fixture();
    let finding = finding_with_action(
        &output.findings,
        "Narrow the allowed directories for this MCP server",
    );

    assert_eq!(
        finding.recommended_action.label,
        "Narrow the allowed directories for this MCP server"
    );
}

fn scan_fixture() -> clawguard::scan::mcp::McpScanOutput {
    scan_mcp_configs(
        &[PathBuf::from("tests/fixtures/mcp/config.json")],
        1024 * 1024,
    )
}

fn finding_with_evidence<'a>(findings: &'a [Finding], needle: &str) -> &'a Finding {
    findings
        .iter()
        .find(|finding| {
            finding.category == FindingCategory::Mcp
                && finding
                    .evidence
                    .as_deref()
                    .is_some_and(|evidence| evidence.contains(needle))
        })
        .expect("expected MCP finding to exist")
}

fn finding_with_action<'a>(findings: &'a [Finding], label: &str) -> &'a Finding {
    findings
        .iter()
        .find(|finding| {
            finding.category == FindingCategory::Mcp && finding.recommended_action.label == label
        })
        .expect("expected MCP finding to exist")
}

// --- Upstream sync: busybox/toybox as suspicious launchers ---

#[test]
fn busybox_launcher_is_flagged_as_suspicious() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let config_path = temp_dir.path().join("busybox-mcp.json");
    fs::write(
        &config_path,
        r#"
        {
          mcpServers: {
            proxy: {
              command: "busybox",
              args: ["httpd", "-f", "-p", "8080"],
            },
          },
        }
        "#,
    )
    .expect("busybox fixture should be written");

    let output = scan_mcp_configs(&[config_path], 1024 * 1024);

    assert!(output.findings.iter().any(|finding| {
        finding.category == FindingCategory::Mcp
            && finding.recommended_action.label == "Review this MCP launcher before enabling it"
            && finding.evidence.as_deref() == Some("busybox")
    }));
}

#[test]
fn toybox_launcher_is_flagged_as_suspicious() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let config_path = temp_dir.path().join("toybox-mcp.json");
    fs::write(
        &config_path,
        r#"
        {
          mcpServers: {
            shell: {
              command: "toybox",
              args: ["sh", "-c", "echo hello"],
            },
          },
        }
        "#,
    )
    .expect("toybox fixture should be written");

    let output = scan_mcp_configs(&[config_path], 1024 * 1024);

    assert!(output.findings.iter().any(|finding| {
        finding.category == FindingCategory::Mcp
            && finding.recommended_action.label == "Review this MCP launcher before enabling it"
            && finding.evidence.as_deref() == Some("toybox")
    }));
}
