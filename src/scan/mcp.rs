use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use super::{Finding, FindingCategory, Fixability, RecommendedAction, RuntimeConfidence, Severity};
use crate::state::model::BaselineRecord;

pub const MCP_COMMAND_SCHEME: &str = "mcp-command://";
pub const MCP_COMMAND_SOURCE_LABEL: &str = "mcp-command";

/// Curated canonical MCP server names loaded at compile time. Short entries
/// (normalized length < 5) are intentionally allowed through the matcher's
/// length gate; this list remains the documentation anchor.
const MCP_SERVER_ALLOWLIST_RAW: &str = include_str!("../../data/mcp_server_allowlist.txt");

/// JS package manager lockfiles. Presence of any of these in a scan dir is
/// treated as a pinned supply chain.
const JS_LOCKFILE_NAMES: &[&str] = &[
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lockb",
    "bun.lock",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpArtifact {
    pub path: String,
    pub sha256: String,
}

/// Stable per-server synthetic artifact for baseline + drift detection of an MCP
/// server's command signature (command/args/url/cwd).
///
/// `path` is a synthetic URI and never refers to a real file on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpCommandArtifact {
    pub path: String,
    pub sha256: String,
    pub config_path: String,
    pub source: String,
    pub server_name: String,
    pub is_url_only: bool,
}

impl McpCommandArtifact {
    pub fn synthetic_path(config_path: &str, source: &str, server_name: &str) -> String {
        // Server names should not contain `::`; sources should not contain `#`;
        // config paths should not contain `#`. Guard in debug only.
        debug_assert!(
            !server_name.contains("::") && !source.contains('#') && !config_path.contains('#'),
            "synthetic MCP command path components contain reserved separators",
        );
        format!("{MCP_COMMAND_SCHEME}{config_path}#{source}::{server_name}")
    }

    pub fn parse_synthetic_path(path: &str) -> Option<(String, String, String)> {
        let rest = path.strip_prefix(MCP_COMMAND_SCHEME)?;
        let (left, server_name) = rest.rsplit_once("::")?;
        let (config_path, source) = left.rsplit_once('#')?;
        Some((
            config_path.to_string(),
            source.to_string(),
            server_name.to_string(),
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct McpScanOutput {
    pub findings: Vec<Finding>,
    pub artifacts: Vec<McpArtifact>,
    pub command_artifacts: Vec<McpCommandArtifact>,
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
    let mut command_artifacts = Vec::new();

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
        let config_dir = path.parent().map(Path::to_path_buf);

        artifacts.push(McpArtifact {
            path: resolved_path.clone(),
            sha256: sha256_hex(contents.as_bytes()),
        });

        let Ok(raw) = json5::from_str::<Value>(&contents) else {
            continue;
        };

        for server in extract_mcp_servers(&raw) {
            findings.extend(findings_for_server(
                &resolved_path,
                config_dir.as_deref(),
                &server,
            ));
            command_artifacts.push(command_artifact_for_server(&resolved_path, &server));
        }
    }

    findings.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then_with(|| left.path.cmp(&right.path))
            .then_with(|| left.id.cmp(&right.id))
    });

    command_artifacts.sort_by(|left, right| left.path.cmp(&right.path));

    McpScanOutput {
        findings,
        artifacts,
        command_artifacts,
    }
}

/// Emit `mcp-command-changed` findings for synthetic command artifacts that no
/// longer match their approved baseline. Remote/URL-only entries are skipped.
/// Each finding is anchored to the real config file path, not the synthetic path.
pub fn command_changed_findings(
    baselines: &[BaselineRecord],
    current: &[McpCommandArtifact],
) -> Vec<Finding> {
    let baseline_by_path: std::collections::BTreeMap<&str, &BaselineRecord> = baselines
        .iter()
        .filter(|b| b.source_label == MCP_COMMAND_SOURCE_LABEL)
        .map(|b| (b.path.as_str(), b))
        .collect();

    let mut findings = Vec::new();

    for artifact in current {
        if artifact.is_url_only {
            continue;
        }
        let Some(baseline) = baseline_by_path.get(artifact.path.as_str()) else {
            continue;
        };
        if baseline.sha256 == artifact.sha256 {
            continue;
        }

        findings.push(Finding {
            id: format!(
                "mcp:mcp-command-changed:{}:{}:{}",
                artifact.config_path, artifact.source, artifact.server_name
            ),
            detector_id: "mcp".to_string(),
            severity: Severity::High,
            category: FindingCategory::Mcp,
            runtime_confidence: RuntimeConfidence::ActiveRuntime,
            path: artifact.config_path.clone(),
            line: None,
            evidence: Some(format!(
                "server={} approved={} current={}",
                artifact.server_name, baseline.sha256, artifact.sha256
            )),
            plain_english_explanation:
                "This MCP server's command signature has changed since it was last approved. A launcher, package spec, or cwd change can redirect the server to different code.".to_string(),
            recommended_action: RecommendedAction {
                label: "Review the changed MCP server and re-approve the baseline if expected".to_string(),
                command_hint: Some("clawguard baseline approve".to_string()),
            },
            fixability: Fixability::Manual,
            fix: None,
            owasp_asi: super::finding::owasp_asi_for_kind("mcp-command-changed"),
        });
    }

    findings.sort_by(|a, b| a.id.cmp(&b.id));
    findings
}

/// Generic adapter: take BaselineArtifacts from the scan pipeline (where the
/// mcp scanner's rich `McpCommandArtifact` has already been flattened into
/// `source_label == "mcp-command"` generic artifacts) and run the mcp-command
/// comparison. URL-only servers are not distinguishable at this level and are
/// not skipped here — callers that need the url-only skip should use
/// `command_changed_findings` directly with `McpCommandArtifact`.
pub fn command_changed_findings_from_baseline_artifacts(
    baselines: &[BaselineRecord],
    artifacts: &[super::BaselineArtifact],
) -> Vec<Finding> {
    let mut rich = Vec::new();
    for artifact in artifacts {
        if artifact.source_label != MCP_COMMAND_SOURCE_LABEL {
            continue;
        }
        let Some((config_path, source, server_name)) =
            McpCommandArtifact::parse_synthetic_path(&artifact.path)
        else {
            continue;
        };
        rich.push(McpCommandArtifact {
            path: artifact.path.clone(),
            sha256: artifact.sha256.clone(),
            config_path,
            source,
            server_name,
            // Without rich metadata at this layer we can't know is_url_only.
            // Downstream receivers treat it as false; filtering to url-only
            // happens at the scan site via findings_for_server.
            is_url_only: false,
        });
    }
    command_changed_findings(baselines, &rich)
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

fn command_artifact_for_server(config_path: &str, server: &McpServerEvidence) -> McpCommandArtifact {
    let command = string_field(&server.config, "command");
    let args = string_array_field(&server.config, "args");
    let url = string_field(&server.config, "url");
    let cwd = string_field(&server.config, "cwd");
    let env_keys = sorted_env_key_names(&server.config);

    // Canonical JSON for the server's command signature. We hash fields that
    // change what code gets executed, including env *key names* — an attacker
    // who injects NODE_OPTIONS=--require /tmp/evil.js, LD_PRELOAD=/tmp/evil.so,
    // or proxy env must trip this detector. Env *values* are still excluded so
    // secret rotation doesn't drift.
    let canonical = json!({
        "command": command,
        "args": args,
        "url": url,
        "cwd": cwd,
        "env_keys": env_keys,
    });

    // Deterministic serialization: json!() builds a serde_json::Map which is
    // insertion-ordered (IndexMap when the `preserve_order` feature is on,
    // otherwise BTreeMap). Add new keys only at the end of the object literal
    // to keep baseline hashes stable.
    let serialized = serde_json::to_string(&canonical).unwrap_or_default();

    let is_url_only = command.is_none() && url.is_some();

    McpCommandArtifact {
        path: McpCommandArtifact::synthetic_path(config_path, &server.source, &server.server_name),
        sha256: sha256_hex(serialized.as_bytes()),
        config_path: config_path.to_string(),
        source: server.source.clone(),
        server_name: server.server_name.clone(),
        is_url_only,
    }
}

fn findings_for_server(
    path: &str,
    config_dir: Option<&Path>,
    server: &McpServerEvidence,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let command = string_field(&server.config, "command");
    let args = string_array_field(&server.config, "args");
    let cwd = string_field(&server.config, "cwd");
    let url = string_field(&server.config, "url");
    let is_url_only = command.is_none() && url.is_some();

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

    // Sprint 1: supply-chain lockfile presence. Only for command-using servers
    // (URL-only remote servers launch no local code, so there's no local
    // lockfile to inspect).
    if !is_url_only {
        if let Some(evidence) = no_lockfile_evidence(command.as_deref(), &args, config_dir, cwd.as_deref()) {
            findings.push(build_finding(
                path,
                server,
                "mcp-no-lockfile",
                Severity::Medium,
                Some(evidence),
                "This MCP server is launched by a JavaScript package manager, but no lockfile was found in the config directory or the server's cwd. Without a lockfile, the resolved package version can drift between runs.",
                "Ship a lockfile (package-lock.json, pnpm-lock.yaml, yarn.lock, bun.lockb, or bun.lock) alongside the MCP config",
            ));
        }
    }

    // Sprint 1: server-name typosquat detection. Applies to all servers
    // regardless of launcher type; a remote URL server with a typo-similar name
    // is still a social-engineering signal.
    if let Some(evidence) = typosquat_evidence(&server.server_name) {
        findings.push(build_finding(
            path,
            server,
            "mcp-server-name-typosquat",
            Severity::High,
            Some(evidence),
            "This MCP server name is very close to a known-legitimate server name. Typosquat-style names are a common social-engineering vector for tricking operators into trusting malicious servers.",
            "Verify the MCP server name matches the intended vendor before approving",
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
        owasp_asi: super::finding::owasp_asi_for_kind(kind),
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

    // Multi-call binaries that can invoke any standard Unix utility
    if launcher_name == "busybox" || launcher_name == "toybox" {
        return Some(launcher_name.to_string());
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

/// Extract the sorted list of env key names from a server config. Values are
/// intentionally omitted so that rotating a legitimate secret does not trigger
/// drift; key names alone are sufficient to catch injection vectors like
/// NODE_OPTIONS, LD_PRELOAD, HTTP_PROXY, PYTHONPATH, etc.
fn sorted_env_key_names(map: &Map<String, Value>) -> Vec<String> {
    let Some(env) = map.get("env").and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut keys: Vec<String> = env.keys().cloned().collect();
    keys.sort();
    keys
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

// ---- Lockfile / launcher-matrix detection (Sprint 1 Task 2.1) ----

/// Identify launchers that resolve through a package manager (and therefore
/// are expected to have a lockfile in scope). Covers:
///   - JS:      npx, bunx, npm exec/x/run, pnpm dlx/exec/x, yarn dlx/exec,
///              bun x/run, pnpx
///   - Python:  uv run, uvx, pipx run, poetry run, rye run, python3 -m,
///              python -m
///   - Other:   deno run, cargo run, go run, Rscript, ruby, perl, php
/// Also unwraps `sh -c` / `bash -c` tunneled invocations (up to 3 levels deep).
fn requires_lockfile_scan(command: Option<&str>, args: &[String]) -> bool {
    let Some(command) = command else {
        return false;
    };
    if is_direct_pm_launcher(command, args) {
        return true;
    }
    // Tunneled: sh -c "npx foo" / bash -c "sh -c 'uv run mcp'"
    if let Some(inner) = sh_c_inner_command(command, args) {
        return tunneled_invokes_pm_launcher(inner, 3);
    }
    false
}

fn is_direct_pm_launcher(command: &str, args: &[String]) -> bool {
    let launcher = normalized_launcher_name(command);
    match launcher.as_str() {
        // JS launchers that always resolve packages
        "npx" | "bunx" | "pnpx" => true,
        // JS wrappers — lockfile only matters for the package-resolving subcmds
        "npm" => matches!(
            args.first().map(String::as_str),
            Some("exec") | Some("x") | Some("run")
        ),
        "pnpm" => matches!(
            args.first().map(String::as_str),
            Some("dlx") | Some("exec") | Some("x")
        ),
        "yarn" => matches!(
            args.first().map(String::as_str),
            Some("dlx") | Some("exec")
        ),
        "bun" => matches!(args.first().map(String::as_str), Some("x") | Some("run")),
        // Python resolvers
        "uv" => matches!(args.first().map(String::as_str), Some("run") | Some("tool")),
        "uvx" | "pipx" => true,
        "poetry" | "rye" => matches!(args.first().map(String::as_str), Some("run")),
        "python" | "python3" => matches!(args.first().map(String::as_str), Some("-m")),
        // Deno / Rust / Go / scripting runtimes that fetch remote code
        "deno" => matches!(
            args.first().map(String::as_str),
            Some("run") | Some("install")
        ),
        "cargo" => matches!(args.first().map(String::as_str), Some("run")),
        "go" => matches!(
            args.first().map(String::as_str),
            Some("run") | Some("install")
        ),
        "rscript" | "ruby" | "perl" | "php" => true,
        _ => false,
    }
}

/// If `command args` is a `sh -c <STRING>` / `bash -c <STRING>` invocation,
/// return the inner command string. Also handles `env -i sh -c ...`-style
/// prefixes by falling back to None (caller re-enters through higher-level
/// scanners for those).
fn sh_c_inner_command<'a>(command: &str, args: &'a [String]) -> Option<&'a str> {
    let launcher = normalized_launcher_name(command);
    if launcher != "sh" && launcher != "bash" {
        return None;
    }
    let idx = args.iter().position(|arg| arg == "-c")?;
    args.get(idx + 1).map(String::as_str)
}

/// Recursive: unwrap up to `depth` levels of nested `sh -c "sh -c '...'"`
/// before deciding whether the innermost command is a PM launcher.
fn tunneled_invokes_pm_launcher(line: &str, depth: usize) -> bool {
    if depth == 0 {
        return false;
    }
    let mut tokens = line.split_whitespace();
    let Some(first_token) = tokens.next() else {
        return false;
    };
    let launcher = normalized_launcher_name(first_token);

    // Another layer of sh -c / bash -c — peel it.
    if launcher == "sh" || launcher == "bash" {
        // Find the -c flag; the remainder of the line (possibly quoted) is the
        // inner command. For our best-effort check we just recurse on whatever
        // follows "-c" as a whitespace-separated stream.
        let after_flag = line
            .split_once(" -c ")
            .or_else(|| line.split_once("\t-c\t"))
            .map(|(_, rest)| rest.trim().trim_matches(|c: char| c == '"' || c == '\''));
        if let Some(inner) = after_flag {
            return tunneled_invokes_pm_launcher(inner, depth - 1);
        }
        return false;
    }

    match launcher.as_str() {
        // JS
        "npx" | "bunx" | "pnpx" | "uvx" | "pipx" | "rscript" | "ruby" | "perl" | "php" => true,
        "npm" | "pnpm" | "yarn" | "bun" | "uv" | "poetry" | "rye" | "deno" | "cargo" | "go"
        | "python" | "python3" => {
            let subcmd = tokens.next().unwrap_or("");
            matches!(
                (launcher.as_str(), subcmd),
                ("npm", "exec")
                    | ("npm", "x")
                    | ("npm", "run")
                    | ("pnpm", "dlx")
                    | ("pnpm", "exec")
                    | ("pnpm", "x")
                    | ("yarn", "dlx")
                    | ("yarn", "exec")
                    | ("bun", "x")
                    | ("bun", "run")
                    | ("uv", "run")
                    | ("uv", "tool")
                    | ("poetry", "run")
                    | ("rye", "run")
                    | ("deno", "run")
                    | ("deno", "install")
                    | ("cargo", "run")
                    | ("go", "run")
                    | ("go", "install")
                    | ("python", "-m")
                    | ("python3", "-m")
            )
        }
        _ => false,
    }
}

fn find_lockfile_in_dir(dir: &Path) -> Option<String> {
    for name in JS_LOCKFILE_NAMES {
        if dir.join(name).is_file() {
            return Some((*name).to_string());
        }
    }
    None
}

fn no_lockfile_evidence(
    command: Option<&str>,
    args: &[String],
    config_dir: Option<&Path>,
    cwd: Option<&str>,
) -> Option<String> {
    if !requires_lockfile_scan(command, args) {
        return None;
    }

    // Bounded set of candidate directories: the config file's parent plus the
    // server's resolved cwd. No parent-walk — that would be unbounded and
    // blast-radius-prone.
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(dir) = config_dir {
        candidates.push(dir.to_path_buf());
    }
    if let Some(cwd) = cwd {
        let cwd_path = PathBuf::from(cwd);
        if cwd_path.is_absolute() {
            candidates.push(cwd_path);
        } else if let Some(base) = config_dir {
            candidates.push(base.join(cwd_path));
        }
    }

    for dir in &candidates {
        if find_lockfile_in_dir(dir).is_some() {
            return None;
        }
    }

    let inspected: Vec<String> = candidates
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    let launcher_display = command.unwrap_or("").trim();
    Some(format!(
        "launcher={launcher_display} inspected=[{}]",
        inspected.join(", ")
    ))
}

// ---- Typosquat detection (Sprint 1 Task 2.2) ----

/// Parsed + normalized allowlist cached for the lifetime of the process.
/// Parsing is idempotent and pure, so a `OnceLock` is safe across threads and
/// avoids re-walking `MCP_SERVER_ALLOWLIST_RAW` on every typosquat check.
fn curated_allowlist() -> &'static [String] {
    static CURATED: OnceLock<Vec<String>> = OnceLock::new();
    CURATED
        .get_or_init(|| {
            MCP_SERVER_ALLOWLIST_RAW
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                .map(normalize_server_name)
                .collect()
        })
        .as_slice()
}

/// NFKC + lowercase + collapse separators (`-_. `) by stripping them.
///
/// Idempotent: applying twice yields the same result. Collapsing separators to
/// nothing (rather than to a single delimiter) matches how users conflate
/// `file-system` / `file_system` / `filesystem` in the wild, so a misspelling
/// doesn't get a free pass just by swapping separators.
fn normalize_server_name(raw: &str) -> String {
    let nfkc: String = raw.nfkc().collect();
    let lowered = nfkc.to_lowercase();
    lowered
        .chars()
        .filter(|c| !matches!(c, '-' | '_' | ' ' | '.'))
        .collect()
}

/// Second-pass normalization for homoglyph defense. Same pipeline as
/// [`normalize_server_name`] but additionally folds Cyrillic/Greek
/// look-alikes to ASCII. If the fold changes a string, the original
/// contained at least one non-ASCII homoglyph — a strong typosquat signal.
fn normalize_server_name_fold(raw: &str) -> String {
    normalize_server_name(raw).chars().map(fold_homoglyph).collect()
}

/// Map a single `char` that visually resembles an ASCII letter/digit to the
/// corresponding ASCII `char`. Characters that are not known homoglyphs are
/// returned unchanged. The table intentionally covers the high-value cases
/// (Cyrillic lower-case alphabet + a few Greek/fullwidth) that attackers use
/// to mint typosquat MCP server names.
fn fold_homoglyph(c: char) -> char {
    match c {
        // Cyrillic lowercase look-alikes
        'а' => 'a', // U+0430
        'в' => 'b', // approximate — rarely used alone
        'с' => 'c', // U+0441
        'е' => 'e', // U+0435
        'һ' => 'h', // U+04BB
        'і' => 'i', // U+0456
        'ј' => 'j', // U+0458
        'к' => 'k', // U+043A
        'ӏ' => 'l', // U+04CF
        'м' => 'm', // approximate
        'н' => 'h', // U+043D — visually matches Latin 'h' far better than 'n'
        'о' => 'o', // U+043E
        'р' => 'p', // U+0440
        'ԛ' => 'q', // U+051B
        'ѕ' => 's', // U+0455
        'т' => 't', // U+0442
        'у' => 'y', // U+0443
        'х' => 'x', // U+0445
        // Greek lowercase look-alikes
        'α' => 'a',
        'ο' => 'o',
        'ν' => 'v',
        'ρ' => 'p',
        // Fullwidth Latin is handled by the earlier NFKC step; nothing to do here.
        other => other,
    }
}

fn damerau_levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let m = a.len();
    let n = b.len();
    if m == 0 {
        return n;
    }
    if n == 0 {
        return m;
    }
    let mut d = vec![vec![0usize; n + 1]; m + 1];
    for i in 0..=m {
        d[i][0] = i;
    }
    for j in 0..=n {
        d[0][j] = j;
    }
    for i in 1..=m {
        for j in 1..=n {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            let mut val = d[i - 1][j]
                .saturating_add(1)
                .min(d[i][j - 1].saturating_add(1))
                .min(d[i - 1][j - 1].saturating_add(cost));
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                val = val.min(d[i - 2][j - 2].saturating_add(1));
            }
            d[i][j] = val;
        }
    }
    d[m][n]
}

fn typosquat_evidence(server_name: &str) -> Option<String> {
    let normalized = normalize_server_name(server_name);
    let normalized_len = normalized.chars().count();
    if normalized_len < 5 {
        return None;
    }

    let threshold = if normalized_len <= 7 { 1 } else { 2 };
    let allowlist = curated_allowlist();

    // Exact-match pass first (no homoglyph fold): if the configured name
    // normalizes directly to a canonical allowlist entry, it's legitimate.
    if allowlist.iter().any(|canonical| canonical == &normalized) {
        return None;
    }

    // Homoglyph-fold pass: if the name only matches an allowlist entry AFTER
    // folding Cyrillic/Greek look-alikes to ASCII, the original contained a
    // homoglyph attack. Distance is zero in fold-space, so this is a hard
    // signal — flag it with explicit evidence.
    let folded = normalize_server_name_fold(server_name);
    if folded != normalized {
        if let Some(canonical_match) = allowlist.iter().find(|canonical| **canonical == folded) {
            return Some(format!(
                "{server_name} uses non-ASCII homoglyphs of {canonical_match} (fold distance 0)"
            ));
        }
    }

    // Near-match pass: flag the first canonical within Damerau-Levenshtein
    // threshold on the fold-normalized form (so homoglyph + typo combos are
    // still caught). Allowlist entries below the length floor are skipped so
    // 3-4 char names can't pull near-matches from the short-name corner.
    let haystack = if folded != normalized { &folded } else { &normalized };
    for canonical_norm in allowlist {
        if canonical_norm.chars().count() < 5 {
            continue;
        }
        let d = damerau_levenshtein(haystack, canonical_norm);
        if d > 0 && d <= threshold {
            return Some(format!(
                "{server_name} resembles {canonical_norm} (distance {d})"
            ));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_path_roundtrips() {
        let path = McpCommandArtifact::synthetic_path(
            "/tmp/openclaw.json",
            "plugins.entries.acpx.config.mcpServers",
            "docs",
        );
        let parsed = McpCommandArtifact::parse_synthetic_path(&path).expect("parse");
        assert_eq!(parsed.0, "/tmp/openclaw.json");
        assert_eq!(parsed.1, "plugins.entries.acpx.config.mcpServers");
        assert_eq!(parsed.2, "docs");
    }

    #[test]
    fn parse_synthetic_path_rejects_non_scheme() {
        assert!(McpCommandArtifact::parse_synthetic_path("/tmp/openclaw.json").is_none());
        assert!(McpCommandArtifact::parse_synthetic_path("https://example.com").is_none());
    }

    #[test]
    fn url_only_server_is_marked_is_url_only() {
        let evidence = McpServerEvidence {
            source: "root.mcpServers".into(),
            server_name: "remote".into(),
            config: {
                let mut m = Map::new();
                m.insert(
                    "url".to_string(),
                    Value::String("https://example.com/mcp".to_string()),
                );
                m
            },
        };
        let artifact = command_artifact_for_server("/tmp/openclaw.json", &evidence);
        assert!(artifact.is_url_only);
        assert_eq!(artifact.server_name, "remote");
    }

    #[test]
    fn command_server_is_not_url_only() {
        let evidence = McpServerEvidence {
            source: "root.mcpServers".into(),
            server_name: "docs".into(),
            config: {
                let mut m = Map::new();
                m.insert("command".to_string(), Value::String("npx".to_string()));
                m.insert(
                    "args".to_string(),
                    Value::Array(vec![Value::String("-y".into())]),
                );
                m
            },
        };
        let artifact = command_artifact_for_server("/tmp/openclaw.json", &evidence);
        assert!(!artifact.is_url_only);
    }

    #[test]
    fn command_artifact_sha_changes_when_args_change() {
        let mut config = Map::new();
        config.insert("command".to_string(), Value::String("npx".to_string()));
        config.insert(
            "args".to_string(),
            Value::Array(vec![Value::String("foo@1.0.0".into())]),
        );
        let evidence_a = McpServerEvidence {
            source: "root.mcpServers".into(),
            server_name: "docs".into(),
            config: config.clone(),
        };
        let a = command_artifact_for_server("/tmp/c.json", &evidence_a);

        let mut config_b = config;
        config_b.insert(
            "args".to_string(),
            Value::Array(vec![Value::String("foo@2.0.0".into())]),
        );
        let evidence_b = McpServerEvidence {
            source: "root.mcpServers".into(),
            server_name: "docs".into(),
            config: config_b,
        };
        let b = command_artifact_for_server("/tmp/c.json", &evidence_b);

        assert_eq!(a.path, b.path);
        assert_ne!(a.sha256, b.sha256);
    }

    #[test]
    fn normalize_collapses_separators_and_case() {
        assert_eq!(normalize_server_name("File-System"), "filesystem");
        assert_eq!(normalize_server_name("file__system"), "filesystem");
        assert_eq!(normalize_server_name("file system"), "filesystem");
        assert_eq!(normalize_server_name("file.system"), "filesystem");
        assert_eq!(normalize_server_name("File--System__v.1"), "filesystemv1");
        // Idempotent
        let once = normalize_server_name("File-System");
        assert_eq!(normalize_server_name(&once), once);
    }

    #[test]
    fn damerau_levenshtein_matches_known_distances() {
        assert_eq!(damerau_levenshtein("", ""), 0);
        assert_eq!(damerau_levenshtein("a", ""), 1);
        assert_eq!(damerau_levenshtein("", "a"), 1);
        assert_eq!(damerau_levenshtein("abc", "abc"), 0);
        assert_eq!(damerau_levenshtein("abc", "acb"), 1); // transposition
        assert_eq!(damerau_levenshtein("filesystem", "fylesystem"), 1); // substitution
        assert_eq!(damerau_levenshtein("filesystem", "filesysten"), 1); // substitution
        assert_eq!(damerau_levenshtein("filesystem", "flesystem"), 1); // deletion
    }

    #[test]
    fn typosquat_catches_near_match_per_length_band() {
        // Length 5-7 band: threshold 1. "github" is len 6 canonical.
        // "githhub" → distance 1 → flagged.
        assert!(typosquat_evidence("githhub").is_some());
        // Length ≥ 8 band: threshold 2. "filesystem" is len 10 canonical.
        // "fylesistem" → distance 2 → flagged.
        assert!(typosquat_evidence("fylesistem").is_some());
    }

    #[test]
    fn typosquat_canonical_name_is_not_flagged() {
        assert!(typosquat_evidence("filesystem").is_none());
        assert!(typosquat_evidence("github").is_none());
        assert!(typosquat_evidence("File-System").is_none()); // normalized match
    }

    #[test]
    fn typosquat_exempts_short_names() {
        // 3-4 char names are short-name-exempt even if they're typo-adjacent to
        // short canonical entries like "git" / "time".
        assert!(typosquat_evidence("gxt").is_none()); // len 3
        assert!(typosquat_evidence("gibt").is_none()); // len 4
    }

    #[test]
    fn typosquat_ignores_unrelated_custom_names() {
        assert!(typosquat_evidence("my-internal-corporate-server").is_none());
        assert!(typosquat_evidence("clawguard-internal").is_none());
    }

    #[test]
    fn requires_lockfile_scan_covers_full_matrix() {
        // Direct launchers
        assert!(requires_lockfile_scan(Some("npx"), &[]));
        assert!(requires_lockfile_scan(Some("bunx"), &[]));
        assert!(requires_lockfile_scan(
            Some("npm"),
            &["exec".into(), "foo".into()]
        ));
        assert!(requires_lockfile_scan(
            Some("npm"),
            &["run".into(), "dev".into()]
        ));
        assert!(requires_lockfile_scan(
            Some("pnpm"),
            &["dlx".into(), "foo".into()]
        ));
        assert!(requires_lockfile_scan(
            Some("yarn"),
            &["dlx".into(), "foo".into()]
        ));
        assert!(requires_lockfile_scan(
            Some("bun"),
            &["x".into(), "foo".into()]
        ));
        // Tunneled
        assert!(requires_lockfile_scan(
            Some("sh"),
            &["-c".into(), "npx -y foo".into()]
        ));
        assert!(requires_lockfile_scan(
            Some("bash"),
            &["-c".into(), "pnpm dlx bar".into()]
        ));
        // Not a JS launcher
        assert!(!requires_lockfile_scan(
            Some("python"),
            &["server.py".into()]
        ));
        assert!(!requires_lockfile_scan(Some("sh"), &["-c".into(), "ls".into()]));
    }

    #[test]
    fn lockfile_detection_skips_url_only() {
        // Covered via findings_for_server with url-only payload — url-only
        // servers never enter the lockfile code path.
        let evidence = McpServerEvidence {
            source: "root.mcpServers".into(),
            server_name: "remote".into(),
            config: {
                let mut m = Map::new();
                m.insert(
                    "url".to_string(),
                    Value::String("https://example.com/mcp".into()),
                );
                m
            },
        };
        let findings = findings_for_server("/tmp/c.json", None, &evidence);
        assert!(findings.iter().all(|f| !f.id.contains("mcp-no-lockfile")));
    }

    #[test]
    fn command_changed_findings_skips_url_only() {
        let current = vec![McpCommandArtifact {
            path: McpCommandArtifact::synthetic_path("/tmp/c.json", "root.mcpServers", "remote"),
            sha256: "new".into(),
            config_path: "/tmp/c.json".into(),
            source: "root.mcpServers".into(),
            server_name: "remote".into(),
            is_url_only: true,
        }];
        let baselines = vec![BaselineRecord {
            path: current[0].path.clone(),
            sha256: "old".into(),
            source_label: MCP_COMMAND_SOURCE_LABEL.into(),
            approved_at_unix_ms: 0,
            git_remote_url: None,
            git_head_sha: None,
        }];
        let findings = command_changed_findings(&baselines, &current);
        assert!(findings.is_empty());
    }
}
