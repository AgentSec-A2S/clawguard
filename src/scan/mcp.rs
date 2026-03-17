use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::{Finding, FindingCategory, Fixability, RecommendedAction, RuntimeConfidence, Severity};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpArtifact {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct McpScanOutput {
    pub findings: Vec<Finding>,
    pub artifacts: Vec<McpArtifact>,
}

#[derive(Debug, Clone)]
struct McpServerEvidence {
    source: String,
    server_name: String,
    config: Map<String, Value>,
}

pub fn scan_mcp_configs(paths: &[PathBuf], max_file_size_bytes: u64) -> McpScanOutput {
    let mut findings = Vec::new();
    let mut artifacts = Vec::new();

    let mut sorted_paths = paths.to_vec();
    sorted_paths.sort();

    for path in sorted_paths {
        let Ok(metadata) = fs::metadata(&path) else {
            continue;
        };

        if !metadata.is_file() || metadata.len() > max_file_size_bytes {
            continue;
        }

        let Ok(contents) = fs::read_to_string(&path) else {
            continue;
        };
        let resolved_path = resolved_path_string(&path);

        artifacts.push(McpArtifact {
            path: resolved_path.clone(),
            sha256: sha256_hex(contents.as_bytes()),
        });

        let Ok(raw) = json5::from_str::<Value>(&contents) else {
            continue;
        };

        for server in extract_mcp_servers(&raw) {
            findings.extend(findings_for_server(&resolved_path, &server));
        }
    }

    findings.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then_with(|| left.path.cmp(&right.path))
            .then_with(|| left.id.cmp(&right.id))
    });

    McpScanOutput {
        findings,
        artifacts,
    }
}

fn extract_mcp_servers(raw: &Value) -> Vec<McpServerEvidence> {
    let Some(root) = raw.as_object() else {
        return Vec::new();
    };

    let mut servers = Vec::new();

    if let Some(mcp_servers) = object_field(root, "mcpServers") {
        extend_server_evidence("root.mcpServers", mcp_servers, &mut servers);
    }

    if let Some(servers_map) = object_field(root, "servers") {
        extend_server_evidence("root.servers", servers_map, &mut servers);
    }

    let Some(plugin_entries) =
        object_field(root, "plugins").and_then(|plugins| object_field(plugins, "entries"))
    else {
        return servers;
    };

    let mut plugin_ids: Vec<_> = plugin_entries.keys().cloned().collect();
    plugin_ids.sort();

    for plugin_id in plugin_ids {
        let Some(plugin_entry) = plugin_entries.get(&plugin_id).and_then(Value::as_object) else {
            continue;
        };
        let Some(config) = object_field(plugin_entry, "config") else {
            continue;
        };
        let Some(mcp_servers) = object_field(config, "mcpServers") else {
            continue;
        };

        extend_server_evidence(
            &format!("plugins.entries.{plugin_id}.config.mcpServers"),
            mcp_servers,
            &mut servers,
        );
    }

    servers
}

fn extend_server_evidence(
    source: &str,
    servers_map: &Map<String, Value>,
    output: &mut Vec<McpServerEvidence>,
) {
    let mut server_names: Vec<_> = servers_map.keys().cloned().collect();
    server_names.sort();

    for server_name in server_names {
        let Some(server) = servers_map.get(&server_name).and_then(Value::as_object) else {
            continue;
        };

        output.push(McpServerEvidence {
            source: source.to_string(),
            server_name,
            config: server.clone(),
        });
    }
}

fn findings_for_server(path: &str, server: &McpServerEvidence) -> Vec<Finding> {
    let mut findings = Vec::new();
    let command = string_field(&server.config, "command");
    let args = string_array_field(&server.config, "args");

    if let Some(evidence) = suspicious_launcher_evidence(command.as_deref(), &args) {
        findings.push(build_finding(
            path,
            server,
            "launcher",
            Severity::High,
            Some(evidence),
            "This MCP server launcher can auto-install packages before execution, which expands the trust boundary.",
            "Review this MCP launcher before enabling it",
        ));
    }

    if let Some(package) = unpinned_package_evidence(command.as_deref(), &args) {
        findings.push(build_finding(
            path,
            server,
            "unpinned-package",
            Severity::Medium,
            Some(package),
            "This MCP server package reference is not pinned to an exact version, so the installed code can drift over time.",
            "Pin an exact MCP package version",
        ));
    }

    if let Some(directory) = overly_broad_directory_evidence(&server.config) {
        findings.push(build_finding(
            path,
            server,
            "broad-directory",
            Severity::High,
            Some(directory),
            "This MCP server is allowed to access a very broad filesystem scope, which increases the blast radius of mistakes or compromise.",
            "Narrow the allowed directories for this MCP server",
        ));
    }

    findings
}

fn build_finding(
    path: &str,
    server: &McpServerEvidence,
    kind: &str,
    severity: Severity,
    evidence: Option<String>,
    explanation: &str,
    action_label: &str,
) -> Finding {
    Finding {
        id: format!("mcp:{kind}:{path}:{}:{}", server.source, server.server_name),
        detector_id: "mcp".to_string(),
        severity,
        category: FindingCategory::Mcp,
        runtime_confidence: RuntimeConfidence::ActiveRuntime,
        path: path.to_string(),
        line: None,
        evidence,
        plain_english_explanation: explanation.to_string(),
        recommended_action: RecommendedAction {
            label: action_label.to_string(),
            command_hint: None,
        },
        fixability: Fixability::Manual,
        fix: None,
    }
}

fn suspicious_launcher_evidence(command: Option<&str>, args: &[String]) -> Option<String> {
    let command = command?.trim();
    let lowered = command.to_ascii_lowercase();
    let launcher_name = normalized_launcher_name(command);

    if lowered.contains("npx -y") {
        return Some("npx -y".to_string());
    }
    if lowered.contains("npx --yes") {
        return Some("npx --yes".to_string());
    }
    if lowered.contains("bunx -y") {
        return Some("bunx -y".to_string());
    }
    if lowered.contains("bunx --yes") {
        return Some("bunx --yes".to_string());
    }
    if lowered.contains("npm exec -y") {
        return Some("npm exec -y".to_string());
    }
    if lowered.contains("npm exec --yes") {
        return Some("npm exec --yes".to_string());
    }

    if launcher_name == "npx" {
        if args.iter().any(|arg| arg == "-y") {
            return Some("npx -y".to_string());
        }
        if args.iter().any(|arg| arg == "--yes") {
            return Some("npx --yes".to_string());
        }
    }

    if launcher_name == "bunx" {
        if args.iter().any(|arg| arg == "-y") {
            return Some("bunx -y".to_string());
        }
        if args.iter().any(|arg| arg == "--yes") {
            return Some("bunx --yes".to_string());
        }
        return Some("bunx".to_string());
    }

    if launcher_name == "npm" && args.iter().any(|arg| arg == "exec") {
        if args.iter().any(|arg| arg == "-y") {
            return Some("npm exec -y".to_string());
        }
        if args.iter().any(|arg| arg == "--yes") {
            return Some("npm exec --yes".to_string());
        }
    }

    None
}

fn unpinned_package_evidence(command: Option<&str>, args: &[String]) -> Option<String> {
    let package = package_argument(command?, args)?;
    if is_unpinned_package(package) {
        return Some(package.to_string());
    }
    None
}

fn package_argument<'a>(command: &'a str, args: &'a [String]) -> Option<&'a str> {
    let launcher_name = normalized_launcher_name(command);

    if launcher_name == "npx" || launcher_name == "bunx" {
        return first_non_flag_arg(args);
    }

    if launcher_name == "npm" {
        let exec_index = args.iter().position(|arg| arg == "exec")?;
        return first_non_flag_arg(&args[exec_index + 1..]);
    }

    None
}

fn first_non_flag_arg(args: &[String]) -> Option<&str> {
    args.iter()
        .map(String::as_str)
        .find(|arg| *arg != "--" && !arg.starts_with('-'))
}

fn is_unpinned_package(package: &str) -> bool {
    let version = package_version(package);

    match version {
        None => true,
        Some(value) => !is_exact_package_version(value),
    }
}

fn package_version(package: &str) -> Option<&str> {
    if package.starts_with('@') {
        let (_, version) = package.rsplit_once('@')?;
        if version.contains('/') {
            return None;
        }
        return Some(version);
    }

    package.rsplit_once('@').map(|(_, version)| version)
}

fn is_exact_package_version(version: &str) -> bool {
    let trimmed = version.trim();
    if trimmed.is_empty() {
        return false;
    }

    if trimmed.eq_ignore_ascii_case("latest")
        || trimmed.eq_ignore_ascii_case("any")
        || trimmed.eq_ignore_ascii_case("x")
        || trimmed == "*"
    {
        return false;
    }

    if trimmed.contains(['^', '~', '*', '>', '<', '|', ',', ' ', '=']) {
        return false;
    }

    let lowered = trimmed.to_ascii_lowercase();
    !(lowered.ends_with(".x") || lowered.ends_with(".latest") || lowered.ends_with(".any"))
}

fn overly_broad_directory_evidence(server: &Map<String, Value>) -> Option<String> {
    let directories = server.get("allowedDirectories")?.as_array()?;
    let mut matched = directories
        .iter()
        .filter_map(Value::as_str)
        .find(|directory| matches!(directory.trim(), "/" | "~" | "." | "./" | ".." | "../"))?;

    if matched.ends_with('/') && matched.len() > 1 {
        matched = matched.trim_end_matches('/');
    }

    Some(matched.to_string())
}

fn object_field<'a>(map: &'a Map<String, Value>, key: &str) -> Option<&'a Map<String, Value>> {
    map.get(key)?.as_object()
}

fn string_field(map: &Map<String, Value>, key: &str) -> Option<String> {
    map.get(key)?.as_str().map(str::to_string)
}

fn string_array_field(map: &Map<String, Value>, key: &str) -> Vec<String> {
    let Some(values) = map.get(key).and_then(Value::as_array) else {
        return Vec::new();
    };

    values
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}

fn normalized_launcher_name(command: &str) -> String {
    let normalized = command.trim().replace('\\', "/");
    let basename = normalized.rsplit('/').next().unwrap_or(normalized.as_str());
    basename
        .to_ascii_lowercase()
        .trim_end_matches(".cmd")
        .trim_end_matches(".exe")
        .trim_end_matches(".bat")
        .to_string()
}

fn resolved_path_string(path: &Path) -> String {
    fs::canonicalize(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .into_owned()
}

fn sha256_hex(contents: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(contents);
    format!("{:x}", hasher.finalize())
}
