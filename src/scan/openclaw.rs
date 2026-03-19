use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::{Finding, FindingCategory, Fixability, RecommendedAction, RuntimeConfidence, Severity};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenClawArtifact {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OpenClawAuditOutput {
    pub findings: Vec<Finding>,
    pub artifacts: Vec<OpenClawArtifact>,
}

pub fn scan_openclaw_state(paths: &[PathBuf], max_file_size_bytes: u64) -> OpenClawAuditOutput {
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
        let file_name = path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("");
        let file_kind = file_kind(file_name);

        artifacts.push(OpenClawArtifact {
            path: resolved_path.clone(),
            sha256: sha256_hex(contents.as_bytes()),
        });

        findings.extend(permission_findings(&resolved_path, file_kind, &metadata));

        let Ok(raw) = json5::from_str::<Value>(&contents) else {
            continue;
        };

        match file_kind {
            FileKind::OpenClawConfig => {
                findings.extend(findings_for_openclaw_config(&resolved_path, &raw))
            }
            FileKind::ExecApprovals => {
                findings.extend(findings_for_exec_approvals(&resolved_path, &raw))
            }
            FileKind::AuthProfiles | FileKind::Other => {}
        }
    }

    findings.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then_with(|| left.path.cmp(&right.path))
            .then_with(|| left.id.cmp(&right.id))
    });

    OpenClawAuditOutput {
        findings,
        artifacts,
    }
}

fn findings_for_openclaw_config(path: &str, raw: &Value) -> Vec<Finding> {
    let Some(root) = raw.as_object() else {
        return Vec::new();
    };

    let global_host = global_exec_host(root);
    let global_mode = global_sandbox_mode(root);
    let global_host_explicit = root
        .get("tools")
        .and_then(Value::as_object)
        .and_then(|tools| object_field(tools, "exec"))
        .and_then(|exec| exec.get("host"))
        .is_some();
    let global_mode_explicit = root
        .get("agents")
        .and_then(Value::as_object)
        .and_then(|agents| object_field(agents, "defaults"))
        .and_then(|defaults| object_field(defaults, "sandbox"))
        .and_then(|sandbox| sandbox.get("mode"))
        .is_some();

    let mut findings = Vec::new();

    if global_host == "sandbox"
        && global_mode == "off"
        && (global_host_explicit || global_mode_explicit)
    {
        findings.push(build_config_finding(
            path,
            "sandbox-host-fallback",
            "defaults",
            Severity::Medium,
            Some("tools.exec.host=sandbox".to_string()),
            "Sandbox mode is off, so exec requests routed to the sandbox host fall back to host execution.",
            "Enable sandboxing or stop routing exec through host fallback",
        ));
    }

    if let Some(network) = global_sandbox_network(root) {
        if is_dangerous_network_mode(&network) {
            findings.push(build_config_finding(
                path,
                "dangerous-network",
                "defaults",
                Severity::Critical,
                Some(format!("agents.defaults.sandbox.docker.network={network}")),
                "This sandbox network mode weakens container isolation and is treated as a dangerous OpenClaw posture.",
                "Use a non-dangerous sandbox network mode",
            ));
        }
    }

    findings.extend(findings_for_channel_policies(path, root, &global_host));
    findings.extend(findings_for_gateway_bind(path, root));
    findings.extend(findings_for_plugin_hooks(path, root));
    findings.extend(findings_for_webhook_token(path, root));

    let Some(agent_list) = root
        .get("agents")
        .and_then(Value::as_object)
        .and_then(|agents| agents.get("list"))
        .and_then(Value::as_array)
    else {
        return findings;
    };

    for (index, entry) in agent_list.iter().enumerate() {
        let Some(agent) = entry.as_object() else {
            continue;
        };

        let agent_scope = agent_scope(agent, index);
        let agent_host = agent_exec_host(agent).unwrap_or_else(|| global_host.clone());
        let agent_mode = agent_sandbox_mode(agent).unwrap_or_else(|| global_mode.clone());
        let agent_host_explicit = agent
            .get("tools")
            .and_then(Value::as_object)
            .and_then(|tools| object_field(tools, "exec"))
            .and_then(|exec| exec.get("host"))
            .is_some();
        let agent_mode_explicit = agent
            .get("sandbox")
            .and_then(Value::as_object)
            .and_then(|sandbox| sandbox.get("mode"))
            .is_some();

        if agent_host == "sandbox"
            && agent_mode == "off"
            && (agent_host_explicit || agent_mode_explicit)
        {
            findings.push(build_config_finding(
                path,
                "sandbox-host-fallback",
                &agent_scope,
                Severity::Medium,
                Some(format!("{agent_scope}.tools.exec.host=sandbox")),
                "This agent disables sandboxing while still routing exec through the sandbox host, which falls back to host execution.",
                "Enable sandboxing or stop routing exec through host fallback",
            ));
        }

        if let Some(network) = agent_sandbox_network(agent) {
            if is_dangerous_network_mode(&network) {
                findings.push(build_config_finding(
                    path,
                    "dangerous-network",
                    &agent_scope,
                    Severity::Critical,
                    Some(format!("{agent_scope}.sandbox.docker.network={network}")),
                    "This per-agent sandbox network mode weakens container isolation and is treated as a dangerous OpenClaw posture.",
                    "Use a non-dangerous sandbox network mode",
                ));
            }
        }
    }

    findings
}

fn findings_for_channel_policies(
    path: &str,
    root: &Map<String, Value>,
    global_host: &str,
) -> Vec<Finding> {
    let Some(channels) = object_field(root, "channels") else {
        return Vec::new();
    };

    let mut channel_names: Vec<_> = channels.keys().cloned().collect();
    channel_names.sort();

    let mut findings = Vec::new();

    for channel_name in channel_names {
        let Some(channel) = channels.get(&channel_name).and_then(Value::as_object) else {
            continue;
        };
        let Some(dm_policy) = string_field(channel, "dmPolicy").map(normalize_lower) else {
            continue;
        };

        if dm_policy != "open" {
            continue;
        }

        findings.push(build_config_finding(
            path,
            "open-dm-policy",
            &format!("channels.{channel_name}"),
            inbound_dm_severity(global_host),
            Some(format!("channels.{channel_name}.dmPolicy=open")),
            "This channel accepts direct messages from anyone, which increases the chance that untrusted prompts can reach host-exec paths.",
            "Restrict inbound DM exposure before accepting remote commands",
        ));
    }

    findings
}

fn findings_for_gateway_bind(path: &str, root: &Map<String, Value>) -> Vec<Finding> {
    let Some(gateway) = object_field(root, "gateway") else {
        return Vec::new();
    };
    let Some(bind) = string_field(gateway, "bind") else {
        return Vec::new();
    };

    let bind = bind.trim().to_string();
    if bind.is_empty() || is_loopback_bind(&bind) {
        return Vec::new();
    }

    vec![build_config_finding(
        path,
        "gateway-bind-exposed",
        "gateway",
        Severity::Medium,
        Some(format!("gateway.bind={bind}")),
        "This gateway bind value exposes OpenClaw endpoints beyond loopback, which expands remote attack surface.",
        "Bind the gateway to loopback before exposing OpenClaw endpoints",
    )]
}

fn findings_for_plugin_hooks(path: &str, root: &Map<String, Value>) -> Vec<Finding> {
    let Some(plugin_entries) =
        object_field(root, "plugins").and_then(|plugins| object_field(plugins, "entries"))
    else {
        return Vec::new();
    };

    let mut entry_ids: Vec<_> = plugin_entries.keys().cloned().collect();
    entry_ids.sort();

    let mut findings = Vec::new();

    for entry_id in entry_ids {
        let Some(entry) = plugin_entries.get(&entry_id).and_then(Value::as_object) else {
            continue;
        };
        let Some(hooks) = object_field(entry, "hooks") else {
            continue;
        };

        if bool_field(hooks, "allowPromptInjection").unwrap_or(false) {
            findings.push(build_config_finding(
                path,
                "plugin-hook-prompt-injection",
                &format!("plugins.entries.{entry_id}.hooks"),
                Severity::High,
                Some(format!(
                    "plugins.entries.{entry_id}.hooks.allowPromptInjection=true"
                )),
                "This plugin explicitly allows prompt injection into hook execution, which weakens prompt-boundary trust.",
                "Disable plugin prompt injection before enabling untrusted hooks",
            ));
        }
    }

    findings
}

fn findings_for_webhook_token(path: &str, root: &Map<String, Value>) -> Vec<Finding> {
    let Some(hooks) = object_field(root, "hooks") else {
        return Vec::new();
    };
    if bool_field(hooks, "enabled") == Some(false) {
        return Vec::new();
    }

    let token_evidence = match hooks.get("token") {
        Some(Value::String(token)) if !token.trim().is_empty() => None,
        Some(Value::String(_)) => Some("hooks.token=<empty>".to_string()),
        _ => Some("hooks.token=<missing>".to_string()),
    };

    token_evidence.map_or_else(Vec::new, |evidence| {
        vec![build_config_finding(
            path,
            "webhook-token-missing",
            "hooks",
            Severity::High,
            Some(evidence),
            "This hooks configuration does not set a usable token, which weakens authentication on inbound OpenClaw hook endpoints.",
            "Set a webhook token before exposing OpenClaw hook endpoints",
        )]
    })
}

fn findings_for_exec_approvals(path: &str, raw: &Value) -> Vec<Finding> {
    let Some(root) = raw.as_object() else {
        return Vec::new();
    };

    let mut findings = Vec::new();

    if let Some(defaults) = object_field(root, "defaults") {
        findings.extend(findings_for_exec_scope(path, "defaults", defaults));
    }

    if let Some(agents) = object_field(root, "agents") {
        let mut agent_ids: Vec<_> = agents.keys().cloned().collect();
        agent_ids.sort();

        for agent_id in agent_ids {
            let Some(agent) = agents.get(&agent_id).and_then(Value::as_object) else {
                continue;
            };
            findings.extend(findings_for_exec_scope(
                path,
                &format!("agents.{agent_id}"),
                agent,
            ));
        }
    }

    findings
}

fn findings_for_exec_scope(path: &str, scope: &str, config: &Map<String, Value>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let security = string_field(config, "security").map(normalize_lower);
    let ask = string_field(config, "ask").map(normalize_lower);
    let auto_allow_skills = bool_field(config, "autoAllowSkills").unwrap_or(false);

    if security.as_deref() == Some("full") {
        findings.push(build_config_finding(
            path,
            "exec-security-full",
            scope,
            Severity::High,
            Some(format!("{scope}.security=full")),
            "This exec approval scope allows unrestricted host execution, which weakens operator review guardrails.",
            "Tighten exec approval defaults before using host exec",
        ));
    }

    if ask.as_deref() == Some("off")
        && matches!(security.as_deref(), Some("full") | Some("allowlist"))
    {
        findings.push(build_config_finding(
            path,
            "exec-ask-off",
            scope,
            Severity::High,
            Some(format!("{scope}.ask=off")),
            "This exec approval scope disables approval prompts while still allowing permissive host-exec policy.",
            "Tighten exec approval defaults before using host exec",
        ));
    }

    if auto_allow_skills {
        findings.push(build_config_finding(
            path,
            "auto-allow-skills",
            scope,
            Severity::High,
            Some(format!("{scope}.autoAllowSkills=true")),
            "This exec approval scope auto-allows skill-launched commands, which weakens explicit approval boundaries.",
            "Tighten exec approval defaults before using host exec",
        ));
    }

    findings
}

fn build_config_finding(
    path: &str,
    kind: &str,
    scope: &str,
    severity: Severity,
    evidence: Option<String>,
    explanation: &str,
    action_label: &str,
) -> Finding {
    Finding {
        id: format!("openclaw-config:{kind}:{path}:{scope}"),
        detector_id: "openclaw-config".to_string(),
        severity,
        category: FindingCategory::Config,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileKind {
    OpenClawConfig,
    ExecApprovals,
    AuthProfiles,
    Other,
}

fn file_kind(file_name: &str) -> FileKind {
    if file_name == "openclaw.json" {
        return FileKind::OpenClawConfig;
    }
    if file_name == "exec-approvals.json" {
        return FileKind::ExecApprovals;
    }
    if file_name == "auth-profiles.json" {
        return FileKind::AuthProfiles;
    }
    FileKind::Other
}

#[cfg(unix)]
fn permission_findings(path: &str, file_kind: FileKind, metadata: &fs::Metadata) -> Vec<Finding> {
    use std::os::unix::fs::PermissionsExt;

    if matches!(file_kind, FileKind::Other) {
        return Vec::new();
    }

    let mode = metadata.permissions().mode() & 0o777;
    let mut findings = Vec::new();
    let scope = match file_kind {
        FileKind::OpenClawConfig => "openclaw.json",
        FileKind::ExecApprovals => "exec-approvals.json",
        FileKind::AuthProfiles => "auth-profiles.json",
        FileKind::Other => return findings,
    };

    if mode & 0o002 != 0 {
        findings.push(build_config_finding(
            path,
            "permissions-world-writable",
            scope,
            Severity::Critical,
            Some(format!("mode={mode:03o}")),
            "This OpenClaw state file is writable by other local users, which allows local tampering.",
            "Restrict local file permissions to the current user",
        ));
        return findings;
    }

    if mode & 0o004 != 0 {
        findings.push(build_config_finding(
            path,
            "permissions-world-readable",
            scope,
            Severity::High,
            Some(format!("mode={mode:03o}")),
            "This OpenClaw state file is readable by other local users, which can leak local credentials or policy state.",
            "Restrict local file permissions to the current user",
        ));
    }

    findings
}

#[cfg(not(unix))]
fn permission_findings(
    _path: &str,
    _file_kind: FileKind,
    _metadata: &fs::Metadata,
) -> Vec<Finding> {
    Vec::new()
}

fn global_exec_host(root: &Map<String, Value>) -> String {
    object_field(root, "tools")
        .and_then(|tools| object_field(tools, "exec"))
        .and_then(|exec| string_field(exec, "host"))
        .map(normalize_lower)
        .unwrap_or_else(|| "sandbox".to_string())
}

fn global_sandbox_mode(root: &Map<String, Value>) -> String {
    object_field(root, "agents")
        .and_then(|agents| object_field(agents, "defaults"))
        .and_then(|defaults| object_field(defaults, "sandbox"))
        .and_then(|sandbox| string_field(sandbox, "mode"))
        .map(normalize_lower)
        .unwrap_or_else(|| "off".to_string())
}

fn global_sandbox_network(root: &Map<String, Value>) -> Option<String> {
    object_field(root, "agents")
        .and_then(|agents| object_field(agents, "defaults"))
        .and_then(|defaults| object_field(defaults, "sandbox"))
        .and_then(sandbox_network)
}

fn agent_exec_host(agent: &Map<String, Value>) -> Option<String> {
    object_field(agent, "tools")
        .and_then(|tools| object_field(tools, "exec"))
        .and_then(|exec| string_field(exec, "host"))
        .map(normalize_lower)
}

fn agent_sandbox_mode(agent: &Map<String, Value>) -> Option<String> {
    object_field(agent, "sandbox")
        .and_then(|sandbox| string_field(sandbox, "mode"))
        .map(normalize_lower)
}

fn agent_sandbox_network(agent: &Map<String, Value>) -> Option<String> {
    object_field(agent, "sandbox").and_then(sandbox_network)
}

fn sandbox_network(sandbox: &Map<String, Value>) -> Option<String> {
    object_field(sandbox, "docker")
        .and_then(|docker| string_field(docker, "network"))
        .map(|value| value.trim().to_string())
}

fn agent_scope(agent: &Map<String, Value>, index: usize) -> String {
    let identifier = string_field(agent, "id").unwrap_or_else(|| index.to_string());
    format!("agents.list[{identifier}]")
}

fn is_dangerous_network_mode(value: &str) -> bool {
    let normalized = normalize_lower(value);
    normalized == "host" || normalized.starts_with("container:")
}

fn inbound_dm_severity(exec_host: &str) -> Severity {
    if normalize_lower(exec_host) == "node" {
        Severity::Critical
    } else {
        Severity::High
    }
}

fn is_loopback_bind(value: &str) -> bool {
    let normalized = normalize_lower(value);
    normalized == "loopback"
        || normalized == "localhost"
        || normalized.starts_with("localhost:")
        || normalized == "127.0.0.1"
        || normalized.starts_with("127.0.0.1:")
        || normalized == "::1"
        || normalized.starts_with("::1:")
        || normalized == "[::1]"
        || normalized.starts_with("[::1]:")
}

fn object_field<'a>(map: &'a Map<String, Value>, key: &str) -> Option<&'a Map<String, Value>> {
    map.get(key)?.as_object()
}

fn string_field(map: &Map<String, Value>, key: &str) -> Option<String> {
    map.get(key)?.as_str().map(str::to_string)
}

fn bool_field(map: &Map<String, Value>, key: &str) -> Option<bool> {
    map.get(key)?.as_bool()
}

fn normalize_lower(value: impl AsRef<str>) -> String {
    value.as_ref().trim().to_ascii_lowercase()
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
