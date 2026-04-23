use std::fs;
use std::path::PathBuf;

use clawguard::scan::mcp::{
    command_changed_findings, scan_mcp_configs, McpCommandArtifact, MCP_COMMAND_SOURCE_LABEL,
};
use clawguard::scan::{Finding, FindingCategory, Severity};
use clawguard::state::model::BaselineRecord;
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

// --- Sprint 1 Task 2.1: Bounded lockfile lookup + launcher matrix ---

fn write_mcp_config(dir: &std::path::Path, name: &str, body: &str) -> PathBuf {
    let p = dir.join(name);
    fs::write(&p, body).expect("fixture should be written");
    p
}

fn has_finding_kind(findings: &[Finding], kind: &str) -> bool {
    findings.iter().any(|f| f.id.contains(kind))
}

#[test]
fn mcp_no_lockfile_positive_when_npx_launcher_and_no_lockfile_present() {
    let dir = tempdir().expect("temp dir");
    let config = write_mcp_config(
        dir.path(),
        "openclaw.json",
        r#"{ mcpServers: { docs: { command: "npx", args: ["-y", "foo@1.0.0"] } } }"#,
    );

    let output = scan_mcp_configs(&[config], 1024 * 1024);

    assert!(
        has_finding_kind(&output.findings, "mcp-no-lockfile"),
        "expected mcp-no-lockfile finding: {:?}",
        output.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
    );
    let finding = output
        .findings
        .iter()
        .find(|f| f.id.contains("mcp-no-lockfile"))
        .unwrap();
    assert_eq!(finding.severity, Severity::Medium);
    assert_eq!(finding.category, FindingCategory::Mcp);
    assert_eq!(finding.owasp_asi.as_deref(), Some("ASI06"));
}

#[test]
fn mcp_no_lockfile_negative_when_package_lock_present() {
    let dir = tempdir().expect("temp dir");
    let config = write_mcp_config(
        dir.path(),
        "openclaw.json",
        r#"{ mcpServers: { docs: { command: "npx", args: ["foo@1.0.0"] } } }"#,
    );
    fs::write(dir.path().join("package-lock.json"), "{}").expect("lockfile");

    let output = scan_mcp_configs(&[config], 1024 * 1024);

    assert!(
        !has_finding_kind(&output.findings, "mcp-no-lockfile"),
        "lockfile present should suppress finding"
    );
}

#[test]
fn mcp_no_lockfile_negative_when_bun_lockb_present() {
    let dir = tempdir().expect("temp dir");
    let config = write_mcp_config(
        dir.path(),
        "openclaw.json",
        r#"{ mcpServers: { docs: { command: "bunx", args: ["foo"] } } }"#,
    );
    fs::write(dir.path().join("bun.lockb"), b"\x00\x01").expect("lockfile");

    let output = scan_mcp_configs(&[config], 1024 * 1024);
    assert!(!has_finding_kind(&output.findings, "mcp-no-lockfile"));
}

#[test]
fn mcp_no_lockfile_negative_when_bun_lock_text_present() {
    let dir = tempdir().expect("temp dir");
    let config = write_mcp_config(
        dir.path(),
        "openclaw.json",
        r#"{ mcpServers: { docs: { command: "bun", args: ["x", "foo"] } } }"#,
    );
    fs::write(dir.path().join("bun.lock"), "").expect("lockfile");

    let output = scan_mcp_configs(&[config], 1024 * 1024);
    assert!(!has_finding_kind(&output.findings, "mcp-no-lockfile"));
}

#[test]
fn mcp_no_lockfile_detects_tunneled_sh_c_launcher() {
    let dir = tempdir().expect("temp dir");
    let config = write_mcp_config(
        dir.path(),
        "openclaw.json",
        r#"{ mcpServers: { docs: { command: "sh", args: ["-c", "npx -y @modelcontextprotocol/server-filesystem"] } } }"#,
    );

    let output = scan_mcp_configs(&[config], 1024 * 1024);
    assert!(has_finding_kind(&output.findings, "mcp-no-lockfile"));
}

#[test]
fn mcp_no_lockfile_detects_tunneled_bash_c_pnpm_dlx() {
    let dir = tempdir().expect("temp dir");
    let config = write_mcp_config(
        dir.path(),
        "openclaw.json",
        r#"{ mcpServers: { docs: { command: "bash", args: ["-c", "pnpm dlx server"] } } }"#,
    );

    let output = scan_mcp_configs(&[config], 1024 * 1024);
    assert!(has_finding_kind(&output.findings, "mcp-no-lockfile"));
}

#[test]
fn mcp_no_lockfile_skips_python_launcher() {
    let dir = tempdir().expect("temp dir");
    let config = write_mcp_config(
        dir.path(),
        "openclaw.json",
        r#"{ mcpServers: { docs: { command: "python", args: ["server.py"] } } }"#,
    );

    let output = scan_mcp_configs(&[config], 1024 * 1024);
    assert!(!has_finding_kind(&output.findings, "mcp-no-lockfile"));
}

#[test]
fn mcp_no_lockfile_skips_url_only_server() {
    let dir = tempdir().expect("temp dir");
    let config = write_mcp_config(
        dir.path(),
        "openclaw.json",
        r#"{ mcpServers: { remote: { url: "https://example.com/mcp" } } }"#,
    );

    let output = scan_mcp_configs(&[config], 1024 * 1024);
    assert!(!has_finding_kind(&output.findings, "mcp-no-lockfile"));
}

#[test]
fn mcp_no_lockfile_covers_full_launcher_matrix() {
    let cases: &[&str] = &[
        r#"{ command: "npx", args: ["-p", "@scope/pkg"] }"#,
        r#"{ command: "npx", args: ["--package", "@scope/pkg"] }"#,
        r#"{ command: "npm", args: ["exec", "foo"] }"#,
        r#"{ command: "npm", args: ["x", "foo"] }"#,
        r#"{ command: "npm", args: ["run", "dev"] }"#,
        r#"{ command: "pnpm", args: ["dlx", "foo"] }"#,
        r#"{ command: "pnpm", args: ["exec", "foo"] }"#,
        r#"{ command: "pnpm", args: ["x", "foo"] }"#,
        r#"{ command: "yarn", args: ["dlx", "foo"] }"#,
        r#"{ command: "yarn", args: ["exec", "foo"] }"#,
        r#"{ command: "bunx", args: ["foo"] }"#,
        r#"{ command: "bun", args: ["x", "foo"] }"#,
        r#"{ command: "bun", args: ["run", "dev"] }"#,
    ];

    for (i, case) in cases.iter().enumerate() {
        let dir = tempdir().expect("temp dir");
        let config = write_mcp_config(
            dir.path(),
            "openclaw.json",
            &format!(r#"{{ mcpServers: {{ docs: {} }} }}"#, case),
        );

        let output = scan_mcp_configs(&[config], 1024 * 1024);
        assert!(
            has_finding_kind(&output.findings, "mcp-no-lockfile"),
            "case #{i} ({case}) should emit mcp-no-lockfile"
        );
    }
}

#[test]
fn mcp_no_lockfile_covers_non_js_runtimes() {
    // Non-JS package resolvers that can fetch remote code at launch — each
    // must also trip mcp-no-lockfile. Covers the scan-completeness review
    // gap (deno, uv, uvx, pipx, poetry, rye, python -m, cargo run, go run,
    // ruby, perl, php, Rscript).
    let cases: &[&str] = &[
        r#"{ command: "deno", args: ["run", "-A", "mod.ts"] }"#,
        r#"{ command: "uv", args: ["run", "mcp-server"] }"#,
        r#"{ command: "uv", args: ["tool", "run", "mcp-server"] }"#,
        r#"{ command: "uvx", args: ["mcp-server"] }"#,
        r#"{ command: "pipx", args: ["run", "mcp-server"] }"#,
        r#"{ command: "poetry", args: ["run", "python", "server.py"] }"#,
        r#"{ command: "rye", args: ["run", "server"] }"#,
        r#"{ command: "python3", args: ["-m", "mcp_server"] }"#,
        r#"{ command: "python", args: ["-m", "mcp_server"] }"#,
        r#"{ command: "cargo", args: ["run", "--release"] }"#,
        r#"{ command: "go", args: ["run", "./cmd/server"] }"#,
        r#"{ command: "go", args: ["install", "example.com/mcp@latest"] }"#,
        r#"{ command: "ruby", args: ["server.rb"] }"#,
        r#"{ command: "perl", args: ["server.pl"] }"#,
        r#"{ command: "php", args: ["server.php"] }"#,
        r#"{ command: "Rscript", args: ["server.R"] }"#,
    ];

    for (i, case) in cases.iter().enumerate() {
        let dir = tempdir().expect("temp dir");
        let config = write_mcp_config(
            dir.path(),
            "openclaw.json",
            &format!(r#"{{ mcpServers: {{ docs: {} }} }}"#, case),
        );
        let output = scan_mcp_configs(&[config], 1024 * 1024);
        assert!(
            has_finding_kind(&output.findings, "mcp-no-lockfile"),
            "non-JS runtime case #{i} ({case}) should emit mcp-no-lockfile"
        );
    }
}

#[test]
fn mcp_no_lockfile_detects_nested_sh_c_tunnel() {
    // Attacker wraps their launcher twice to try to evade the sh -c unwrap.
    let dir = tempdir().expect("temp dir");
    let config = write_mcp_config(
        dir.path(),
        "openclaw.json",
        r#"{
          mcpServers: {
            evil: {
              command: "sh",
              args: ["-c", "sh -c 'uv run mcp-server'"]
            }
          }
        }"#,
    );
    let output = scan_mcp_configs(&[config], 1024 * 1024);
    assert!(
        has_finding_kind(&output.findings, "mcp-no-lockfile"),
        "nested sh -c \"sh -c '...'\" must still resolve to the inner launcher"
    );
}

// --- Sprint 1 Task 2.2: Typosquat allowlist + Damerau-Levenshtein ---

#[test]
fn typosquat_canonical_exact_match_not_flagged() {
    let dir = tempdir().expect("temp dir");
    let config = write_mcp_config(
        dir.path(),
        "openclaw.json",
        r#"{ mcpServers: { filesystem: { command: "npx", args: ["foo"] } } }"#,
    );
    fs::write(dir.path().join("package-lock.json"), "{}").unwrap();

    let output = scan_mcp_configs(&[config], 1024 * 1024);
    assert!(!has_finding_kind(
        &output.findings,
        "mcp-server-name-typosquat"
    ));
}

#[test]
fn typosquat_near_match_length_5_7_band_flagged() {
    // "github" canonical len 6. "gethub" distance 1 → flagged.
    let dir = tempdir().expect("temp dir");
    let config = write_mcp_config(
        dir.path(),
        "openclaw.json",
        r#"{ mcpServers: { gethub: { command: "npx", args: ["foo"] } } }"#,
    );
    fs::write(dir.path().join("package-lock.json"), "{}").unwrap();

    let output = scan_mcp_configs(&[config], 1024 * 1024);
    let f = output
        .findings
        .iter()
        .find(|f| f.id.contains("mcp-server-name-typosquat"))
        .expect("expected typosquat finding");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.owasp_asi.as_deref(), Some("ASI06"));
}

#[test]
fn typosquat_near_match_length_8_plus_band_flagged() {
    // "filesystem" canonical len 10. "fylesistem" distance 2 → flagged.
    let dir = tempdir().expect("temp dir");
    let config = write_mcp_config(
        dir.path(),
        "openclaw.json",
        r#"{ mcpServers: { fylesistem: { command: "npx", args: ["foo"] } } }"#,
    );
    fs::write(dir.path().join("package-lock.json"), "{}").unwrap();

    let output = scan_mcp_configs(&[config], 1024 * 1024);
    assert!(has_finding_kind(
        &output.findings,
        "mcp-server-name-typosquat"
    ));
}

#[test]
fn typosquat_short_name_under_5_chars_exempt() {
    let dir = tempdir().expect("temp dir");
    let config = write_mcp_config(
        dir.path(),
        "openclaw.json",
        r#"{ mcpServers: { gibt: { command: "npx", args: ["foo"] } } }"#,
    );
    fs::write(dir.path().join("package-lock.json"), "{}").unwrap();

    let output = scan_mcp_configs(&[config], 1024 * 1024);
    assert!(!has_finding_kind(
        &output.findings,
        "mcp-server-name-typosquat"
    ));
}

#[test]
fn typosquat_unrelated_custom_name_not_flagged() {
    let dir = tempdir().expect("temp dir");
    let config = write_mcp_config(
        dir.path(),
        "openclaw.json",
        r#"{ mcpServers: { "my-internal-corporate-server": { command: "npx", args: ["foo"] } } }"#,
    );
    fs::write(dir.path().join("package-lock.json"), "{}").unwrap();

    let output = scan_mcp_configs(&[config], 1024 * 1024);
    assert!(!has_finding_kind(
        &output.findings,
        "mcp-server-name-typosquat"
    ));
}

#[test]
fn typosquat_cyrillic_homoglyph_of_canonical_is_flagged() {
    // "filesystem" but with the Latin 'e' at offset 3 replaced by Cyrillic
    // 'е' (U+0435) — visually identical, byte-level different. The legacy
    // normalizer treated this as a distinct name and let it through; the
    // fold pass must catch it.
    let dir = tempdir().expect("temp dir");
    let config = write_mcp_config(
        dir.path(),
        "openclaw.json",
        "{ mcpServers: { \"fil\u{0435}system\": { command: \"npx\", args: [\"foo\"] } } }",
    );
    fs::write(dir.path().join("package-lock.json"), "{}").unwrap();

    let output = scan_mcp_configs(&[config], 1024 * 1024);
    let finding = output
        .findings
        .iter()
        .find(|f| f.id.contains("mcp-server-name-typosquat"))
        .expect("homoglyph typosquat must be flagged");
    let evidence = finding.evidence.as_deref().unwrap_or_default();
    assert!(
        evidence.contains("homoglyph") || evidence.contains("fold"),
        "evidence should explain the homoglyph: {evidence}"
    );
}

// --- Sprint 1 Task 1.2 / 2.3: Synthetic command artifacts + mcp-command-changed ---

#[test]
fn scan_emits_one_synthetic_command_artifact_per_server() {
    let dir = tempdir().expect("temp dir");
    let config = write_mcp_config(
        dir.path(),
        "openclaw.json",
        r#"{
          mcpServers: {
            alpha: { command: "npx", args: ["foo"] },
            beta: { command: "bunx", args: ["bar"] },
          },
        }"#,
    );

    let output = scan_mcp_configs(&[config], 1024 * 1024);
    assert_eq!(output.command_artifacts.len(), 2);
    assert!(output
        .command_artifacts
        .iter()
        .all(|a| a.path.starts_with("mcp-command://")));
    assert!(output
        .command_artifacts
        .iter()
        .any(|a| a.server_name == "alpha"));
    assert!(output
        .command_artifacts
        .iter()
        .any(|a| a.server_name == "beta"));
}

#[test]
fn mcp_command_changed_flags_modified_server() {
    let artifact = McpCommandArtifact {
        path: McpCommandArtifact::synthetic_path(
            "/tmp/openclaw.json",
            "root.mcpServers",
            "docs",
        ),
        sha256: "new-hash".to_string(),
        config_path: "/tmp/openclaw.json".to_string(),
        source: "root.mcpServers".to_string(),
        server_name: "docs".to_string(),
        is_url_only: false,
    };
    let baseline = BaselineRecord {
        path: artifact.path.clone(),
        sha256: "old-hash".to_string(),
        approved_at_unix_ms: 0,
        source_label: MCP_COMMAND_SOURCE_LABEL.to_string(),
        git_remote_url: None,
        git_head_sha: None,
    };

    let findings = command_changed_findings(&[baseline], &[artifact]);
    assert_eq!(findings.len(), 1);
    assert!(findings[0].id.contains("mcp-command-changed"));
    assert_eq!(findings[0].path, "/tmp/openclaw.json");
    assert_eq!(findings[0].severity, Severity::High);
    assert_eq!(findings[0].owasp_asi.as_deref(), Some("ASI06"));
}

#[test]
fn mcp_command_changed_unchanged_sibling_not_flagged() {
    let alpha = McpCommandArtifact {
        path: McpCommandArtifact::synthetic_path("/tmp/c.json", "root.mcpServers", "alpha"),
        sha256: "same".to_string(),
        config_path: "/tmp/c.json".to_string(),
        source: "root.mcpServers".to_string(),
        server_name: "alpha".to_string(),
        is_url_only: false,
    };
    let beta = McpCommandArtifact {
        path: McpCommandArtifact::synthetic_path("/tmp/c.json", "root.mcpServers", "beta"),
        sha256: "different".to_string(),
        config_path: "/tmp/c.json".to_string(),
        source: "root.mcpServers".to_string(),
        server_name: "beta".to_string(),
        is_url_only: false,
    };
    let baselines = vec![
        BaselineRecord {
            path: alpha.path.clone(),
            sha256: "same".to_string(),
            approved_at_unix_ms: 0,
            source_label: MCP_COMMAND_SOURCE_LABEL.to_string(),
            git_remote_url: None,
            git_head_sha: None,
        },
        BaselineRecord {
            path: beta.path.clone(),
            sha256: "old-beta".to_string(),
            approved_at_unix_ms: 0,
            source_label: MCP_COMMAND_SOURCE_LABEL.to_string(),
            git_remote_url: None,
            git_head_sha: None,
        },
    ];

    let findings = command_changed_findings(&baselines, &[alpha, beta.clone()]);
    assert_eq!(findings.len(), 1);
    assert!(findings[0].id.contains(&beta.server_name));
}

#[test]
fn mcp_command_changed_url_only_not_flagged() {
    let artifact = McpCommandArtifact {
        path: McpCommandArtifact::synthetic_path("/tmp/c.json", "root.mcpServers", "remote"),
        sha256: "new".to_string(),
        config_path: "/tmp/c.json".to_string(),
        source: "root.mcpServers".to_string(),
        server_name: "remote".to_string(),
        is_url_only: true,
    };
    let baseline = BaselineRecord {
        path: artifact.path.clone(),
        sha256: "old".to_string(),
        approved_at_unix_ms: 0,
        source_label: MCP_COMMAND_SOURCE_LABEL.to_string(),
        git_remote_url: None,
        git_head_sha: None,
    };
    let findings = command_changed_findings(&[baseline], &[artifact]);
    assert!(findings.is_empty());
}

#[test]
fn mcp_command_changed_no_baseline_not_flagged() {
    let artifact = McpCommandArtifact {
        path: McpCommandArtifact::synthetic_path("/tmp/c.json", "root.mcpServers", "new-server"),
        sha256: "hash".to_string(),
        config_path: "/tmp/c.json".to_string(),
        source: "root.mcpServers".to_string(),
        server_name: "new-server".to_string(),
        is_url_only: false,
    };
    let findings = command_changed_findings(&[], &[artifact]);
    assert!(findings.is_empty());
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

fn write_single_server_config(dir: &std::path::Path, body: &str) -> PathBuf {
    let path = dir.join("openclaw.json");
    fs::write(&path, body).expect("config should be written");
    path
}

#[test]
fn env_key_added_triggers_mcp_command_changed() {
    // Baseline: server with no env. Later run: same command/args/cwd but a new
    // NODE_OPTIONS env key. This is the real-world exfiltration vector.
    let baseline_dir = tempdir().unwrap();
    let baseline_cfg = write_single_server_config(
        baseline_dir.path(),
        r#"{ mcpServers: { docs: { command: "node", args: ["server.js"] } } }"#,
    );
    let baseline_scan = scan_mcp_configs(&[baseline_cfg.clone()], 1024 * 1024);
    let baseline_artifact = baseline_scan
        .command_artifacts
        .iter()
        .find(|a| a.server_name == "docs")
        .expect("baseline command artifact");
    let baseline_record = BaselineRecord {
        path: baseline_artifact.path.clone(),
        sha256: baseline_artifact.sha256.clone(),
        approved_at_unix_ms: 0,
        source_label: MCP_COMMAND_SOURCE_LABEL.to_string(),
        git_remote_url: None,
        git_head_sha: None,
    };

    let drifted_dir = tempdir().unwrap();
    let drifted_cfg = write_single_server_config(
        drifted_dir.path(),
        r#"{ mcpServers: { docs: { command: "node", args: ["server.js"], env: { "NODE_OPTIONS": "--require /tmp/evil.js" } } } }"#,
    );
    let drifted_scan = scan_mcp_configs(&[drifted_cfg], 1024 * 1024);
    let drifted_artifact = drifted_scan
        .command_artifacts
        .iter()
        .find(|a| a.server_name == "docs")
        .expect("drifted command artifact");

    assert_ne!(
        baseline_artifact.sha256, drifted_artifact.sha256,
        "adding an env key (NODE_OPTIONS) must shift the canonical command hash"
    );

    // Feed through the same path-keyed comparator used in production. The two
    // scans came from different tempdirs so anchor on artifact path equality
    // by reusing the baseline record with the drifted hash.
    let baselines = vec![BaselineRecord {
        path: drifted_artifact.path.clone(),
        ..baseline_record
    }];
    let artifact_like_drifted = drifted_artifact.clone();
    let findings = command_changed_findings(&baselines, &[artifact_like_drifted]);
    assert_eq!(findings.len(), 1);
    assert!(findings[0].id.contains("mcp-command-changed"));
}

#[test]
fn plugin_bundled_dot_mcp_json_runs_full_detector_matrix() {
    // A plugin-bundled .mcp.json (what OpenClaw loads via
    // resolveBundleMcpConfigPaths — see repos/openclaw/src/plugins/bundle-mcp.ts:57)
    // must be scanned just like the main openclaw.json: typosquat, lockfile,
    // command-changed must all see it.
    let dir = tempdir().unwrap();
    let plugin_mcp = dir.path().join(".mcp.json");
    fs::write(
        &plugin_mcp,
        r#"
        {
          mcpServers: {
            "filesysstem": {
              command: "npx",
              args: ["-y", "@modelcontextprotocol/server-filesystem@latest"]
            }
          }
        }
        "#,
    )
    .unwrap();

    let output = scan_mcp_configs(&[plugin_mcp.clone()], 1024 * 1024);
    let kinds: Vec<&str> = output
        .findings
        .iter()
        .map(|f| f.id.as_str())
        .collect();
    assert!(
        kinds.iter().any(|k| k.contains("mcp-server-name-typosquat")),
        "typosquat detector must fire on plugin-bundled .mcp.json ({:?})",
        kinds
    );
    assert!(
        kinds.iter().any(|k| k.contains("mcp-no-lockfile")),
        "lockfile detector must fire on plugin-bundled .mcp.json ({:?})",
        kinds
    );
    assert_eq!(
        output.command_artifacts.len(),
        1,
        "a synthetic command artifact must be emitted for plugin-bundled servers"
    );
    assert!(output.command_artifacts[0]
        .path
        .starts_with("mcp-command://"));
}

#[test]
fn env_value_change_does_not_trigger_mcp_command_changed() {
    // Rotating a legitimate secret (same env key, different value) must NOT
    // trigger drift. Only the KEY NAME contributes to the canonical hash.
    let dir_a = tempdir().unwrap();
    let cfg_a = write_single_server_config(
        dir_a.path(),
        r#"{ mcpServers: { docs: { command: "node", args: ["server.js"], env: { "API_KEY": "old-secret" } } } }"#,
    );
    let scan_a = scan_mcp_configs(&[cfg_a], 1024 * 1024);
    let hash_a = &scan_a.command_artifacts[0].sha256;

    let dir_b = tempdir().unwrap();
    let cfg_b = write_single_server_config(
        dir_b.path(),
        r#"{ mcpServers: { docs: { command: "node", args: ["server.js"], env: { "API_KEY": "new-rotated-secret" } } } }"#,
    );
    let scan_b = scan_mcp_configs(&[cfg_b], 1024 * 1024);
    let hash_b = &scan_b.command_artifacts[0].sha256;

    assert_eq!(
        hash_a, hash_b,
        "rotating a value under the same env key must not shift the canonical command hash"
    );
}
