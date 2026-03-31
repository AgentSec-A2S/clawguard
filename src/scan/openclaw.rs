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

    findings.extend(findings_for_control_ui(path, root));
    findings.extend(findings_for_channel_policies(path, root, &global_host));
    findings.extend(findings_for_gateway_bind(path, root));
    findings.extend(findings_for_plugin_hooks(path, root));
    findings.extend(findings_for_plugin_installs(path, root));
    findings.extend(findings_for_hook_security(path, root));
    findings.extend(findings_for_hook_mappings(path, root));
    findings.extend(findings_for_exec_host(path, root));
    findings.extend(findings_for_sandbox_posture(path, root));
    findings.extend(findings_for_acp_posture(path, root));

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

        // Per-agent exec host = node (uses agent_exec_host directly to avoid
        // double-flagging when the agent merely inherits the global setting).
        if agent_exec_host(agent).as_deref() == Some("node") {
            findings.push(build_config_finding(
                path,
                "exec-host-node",
                &format!("{agent_scope}.tools.exec"),
                Severity::Medium,
                Some(format!("{agent_scope}.tools.exec.host=node")),
                "This agent routes exec commands directly through the host Node process without sandbox isolation.",
                "Set this agent's tools.exec.host to 'sandbox' or remove the override to inherit the global setting",
            ));
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

        // Check top-level dmPolicy
        if let Some(dm_policy) = string_field(channel, "dmPolicy").map(normalize_lower) {
            if dm_policy == "open" {
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
        }

        // Walk nested accounts.*.dmPolicy
        if let Some(accounts) = object_field(channel, "accounts") {
            let mut account_names: Vec<_> = accounts.keys().cloned().collect();
            account_names.sort();
            for account_name in account_names {
                let Some(acct) = accounts.get(&account_name).and_then(Value::as_object) else {
                    continue;
                };
                let Some(acct_dm) = string_field(acct, "dmPolicy").map(normalize_lower) else {
                    continue;
                };
                if acct_dm == "open" {
                    findings.push(build_config_finding(
                        path,
                        "open-dm-policy",
                        &format!("channels.{channel_name}.accounts.{account_name}"),
                        inbound_dm_severity(global_host),
                        Some(format!(
                            "channels.{channel_name}.accounts.{account_name}.dmPolicy=open"
                        )),
                        "This account accepts direct messages from anyone, which increases the chance that untrusted prompts can reach host-exec paths.",
                        "Restrict inbound DM exposure before accepting remote commands",
                    ));
                }
            }
        }
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

fn findings_for_control_ui(path: &str, root: &Map<String, Value>) -> Vec<Finding> {
    let dangerously_disabled = root
        .get("gateway")
        .and_then(Value::as_object)
        .and_then(|gw| object_field(gw, "controlUi"))
        .and_then(|ui| bool_field(ui, "dangerouslyDisableDeviceAuth"))
        .unwrap_or(false);

    if !dangerously_disabled {
        return Vec::new();
    }

    vec![build_config_finding(
        path,
        "dangerous-disable-device-auth",
        "gateway.controlUi",
        Severity::Critical,
        Some("gateway.controlUi.dangerouslyDisableDeviceAuth=true".to_string()),
        "Device authentication is disabled on the control UI. Anyone on the local network can control the gateway without device-level auth.",
        "Remove dangerouslyDisableDeviceAuth or set it to false",
    )]
}

fn findings_for_plugin_installs(path: &str, root: &Map<String, Value>) -> Vec<Finding> {
    let Some(installs) =
        object_field(root, "plugins").and_then(|plugins| object_field(plugins, "installs"))
    else {
        return Vec::new();
    };

    let mut entry_ids: Vec<_> = installs.keys().cloned().collect();
    entry_ids.sort();

    let mut findings = Vec::new();

    for entry_id in entry_ids {
        let Some(entry) = installs.get(&entry_id).and_then(Value::as_object) else {
            continue;
        };

        let source = string_field(entry, "source").map(normalize_lower);
        let source_path = string_field(entry, "sourcePath");

        if let Some(ref sp) = source_path {
            if is_temp_path(sp) {
                findings.push(build_config_finding(
                    path,
                    "insecure-plugin-install-path",
                    &format!("plugins.installs.{entry_id}"),
                    Severity::Medium,
                    Some(format!("plugins.installs.{entry_id}.sourcePath={sp}")),
                    "This plugin was installed from a temporary directory. The source is non-reproducible and could have been tampered with before installation.",
                    "Reinstall this plugin from a stable path or registry",
                ));
            }
        }

        if source.as_deref() == Some("path") {
            findings.push(build_config_finding(
                path,
                "plugin-source-path-install",
                &format!("plugins.installs.{entry_id}"),
                Severity::Info,
                Some(format!("plugins.installs.{entry_id}.source=path")),
                "This plugin was installed from a local filesystem path, bypassing registry integrity checks.",
                "Consider installing from a registry for supply-chain assurance",
            ));
        }
    }

    findings
}

fn is_temp_path(path: &str) -> bool {
    let normalized = path.replace('\\', "/");
    normalized.starts_with("/tmp/")
        || normalized.starts_with("/tmp.")
        || normalized.starts_with("/var/tmp/")
        || normalized.starts_with("/private/var/folders/")
        || normalized.starts_with("/private/tmp/")
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

fn findings_for_hook_security(path: &str, root: &Map<String, Value>) -> Vec<Finding> {
    let Some(hooks) = object_field(root, "hooks") else {
        return Vec::new();
    };
    if bool_field(hooks, "enabled") == Some(false) {
        return Vec::new();
    }

    let mut findings = Vec::new();

    // Existing: webhook token missing/empty
    let token_evidence = match hooks.get("token") {
        Some(Value::String(token)) if !token.trim().is_empty() => None,
        Some(Value::String(_)) => Some("hooks.token=<empty>".to_string()),
        _ => Some("hooks.token=<missing>".to_string()),
    };
    if let Some(evidence) = token_evidence {
        findings.push(build_config_finding(
            path,
            "webhook-token-missing",
            "hooks",
            Severity::High,
            Some(evidence),
            "This hooks configuration does not set a usable token, which weakens authentication on inbound OpenClaw hook endpoints.",
            "Set a webhook token before exposing OpenClaw hook endpoints",
        ));
    }

    // New: allowRequestSessionKey
    if bool_field(hooks, "allowRequestSessionKey").unwrap_or(false) {
        findings.push(build_config_finding(
            path,
            "hook-allows-request-session-key",
            "hooks",
            Severity::High,
            Some("hooks.allowRequestSessionKey=true".to_string()),
            "External webhook callers can set session keys, enabling session hijacking or replay attacks.",
            "Remove allowRequestSessionKey or set it to false",
        ));
    }

    findings
}

fn findings_for_hook_mappings(path: &str, root: &Map<String, Value>) -> Vec<Finding> {
    let Some(hooks) = object_field(root, "hooks") else {
        return Vec::new();
    };
    if bool_field(hooks, "enabled") == Some(false) {
        return Vec::new();
    }

    let mut findings = Vec::new();

    // Walk hooks.mappings[]
    if let Some(mappings) = hooks.get("mappings").and_then(Value::as_array) {
        for (i, mapping) in mappings.iter().enumerate() {
            let Some(m) = mapping.as_object() else {
                continue;
            };
            let label = string_field(m, "id").unwrap_or_else(|| format!("{i}"));

            if bool_field(m, "allowUnsafeExternalContent").unwrap_or(false) {
                findings.push(build_config_finding(
                    path,
                    "hook-allows-unsafe-external-content",
                    &format!("hooks.mappings[{label}]"),
                    Severity::High,
                    Some(format!(
                        "hooks.mappings[{label}].allowUnsafeExternalContent=true"
                    )),
                    "External webhook content bypasses safety wrapping for this mapping, allowing prompt injection via webhook.",
                    "Remove allowUnsafeExternalContent from this hook mapping",
                ));
            }

            if let Some(transform) = object_field(m, "transform") {
                if let Some(module_path) = string_field(transform, "module") {
                    let normalized = module_path.replace('\\', "/");
                    let has_traversal = normalized.split('/').any(|segment| segment == "..");
                    if normalized.starts_with('/')
                        || normalized.starts_with('~')
                        || normalized.contains(':')
                        || has_traversal
                    {
                        findings.push(build_config_finding(
                            path,
                            "hook-transform-external-module",
                            &format!("hooks.mappings[{label}].transform"),
                            Severity::Medium,
                            Some(format!(
                                "hooks.mappings[{label}].transform.module={module_path}"
                            )),
                            "Hook transform references a module outside the workspace boundary, which could execute untrusted code on webhook receipt.",
                            "Use a workspace-relative path for transform modules",
                        ));
                    }
                }
            }
        }
    }

    // Check hooks.gmail.allowUnsafeExternalContent
    if let Some(gmail) = object_field(hooks, "gmail") {
        if bool_field(gmail, "allowUnsafeExternalContent").unwrap_or(false) {
            findings.push(build_config_finding(
                path,
                "hook-allows-unsafe-external-content",
                "hooks.gmail",
                Severity::High,
                Some("hooks.gmail.allowUnsafeExternalContent=true".to_string()),
                "Gmail hook content bypasses safety wrapping, allowing prompt injection via email.",
                "Remove allowUnsafeExternalContent from hooks.gmail",
            ));
        }
    }

    findings
}

fn findings_for_exec_host(path: &str, root: &Map<String, Value>) -> Vec<Finding> {
    let host = object_field(root, "tools")
        .and_then(|t| object_field(t, "exec"))
        .and_then(|e| string_field(e, "host"))
        .map(normalize_lower);

    if host.as_deref() == Some("node") {
        return vec![build_config_finding(
            path,
            "exec-host-node",
            "tools.exec",
            Severity::Medium,
            Some("tools.exec.host=node".to_string()),
            "Exec commands run directly on the host Node process without sandbox isolation.",
            "Set tools.exec.host to 'sandbox' or 'gateway' for containment",
        )];
    }
    Vec::new()
}

fn findings_for_sandbox_posture(path: &str, root: &Map<String, Value>) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check agents.defaults.sandbox.mode
    let defaults_mode = object_field(root, "agents")
        .and_then(|a| object_field(a, "defaults"))
        .and_then(|d| object_field(d, "sandbox"))
        .and_then(|s| string_field(s, "mode"))
        .map(normalize_lower);

    if defaults_mode.as_deref() == Some("off") {
        findings.push(build_config_finding(
            path,
            "sandbox-disabled",
            "agents.defaults.sandbox",
            Severity::Medium,
            Some("agents.defaults.sandbox.mode=off".to_string()),
            "Default sandbox is disabled; all agents run without containment unless overridden per-agent.",
            "Set agents.defaults.sandbox.mode to 'all' or 'non-main'",
        ));
    }

    // Check agents.list[*].sandbox.mode (agents.list is an array in OpenClaw schema)
    let agent_list = root
        .get("agents")
        .and_then(Value::as_object)
        .and_then(|agents| agents.get("list"))
        .and_then(Value::as_array);

    if let Some(list) = agent_list {
        for (index, entry) in list.iter().enumerate() {
            let Some(agent) = entry.as_object() else {
                continue;
            };
            let agent_id = string_field(agent, "id").unwrap_or_else(|| format!("{index}"));
            let agent_mode = object_field(agent, "sandbox")
                .and_then(|s| string_field(s, "mode"))
                .map(normalize_lower);

            if agent_mode.as_deref() == Some("off") {
                findings.push(build_config_finding(
                    path,
                    "sandbox-disabled",
                    &format!("agents.list[{agent_id}].sandbox"),
                    Severity::Medium,
                    Some(format!("agents.list[{agent_id}].sandbox.mode=off")),
                    "This agent runs without sandbox containment.",
                    "Set sandbox.mode to 'all' or 'non-main'",
                ));
            }
        }
    }

    findings
}

fn findings_for_acp_posture(path: &str, root: &Map<String, Value>) -> Vec<Finding> {
    let Some(plugin_entries) =
        object_field(root, "plugins").and_then(|p| object_field(p, "entries"))
    else {
        return Vec::new();
    };
    let Some(acpx) = object_field(plugin_entries, "acpx") else {
        return Vec::new();
    };
    // Skip disabled plugins — stale config remnants should not produce findings.
    if bool_field(acpx, "enabled") == Some(false) {
        return Vec::new();
    }
    let Some(config) = object_field(acpx, "config") else {
        return Vec::new();
    };
    let Some(mode) = string_field(config, "permissionMode").map(normalize_lower) else {
        return Vec::new();
    };
    if mode == "approve-all" {
        return vec![build_config_finding(
            path,
            "acp-approve-all",
            "plugins.entries.acpx.config",
            Severity::High,
            Some("plugins.entries.acpx.config.permissionMode=approve-all".to_string()),
            "The ACPX plugin auto-approves all tool calls including exec, spawn, shell, and filesystem writes.",
            "Set permissionMode to 'approve-reads' or 'deny-all'",
        )];
    }
    Vec::new()
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
            let scope = format!("agents.{agent_id}");
            findings.extend(findings_for_exec_scope(path, &scope, agent));

            if let Some(allowlist) = agent.get("allowlist").and_then(Value::as_array) {
                findings.extend(findings_for_allowlist_entries(path, &scope, allowlist));
            }
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

    let ask_fallback = string_field(config, "askFallback").map(normalize_lower);
    if let Some(fallback) = &ask_fallback {
        if fallback != "deny" {
            findings.push(build_config_finding(
                path,
                "exec-ask-fallback-weak",
                scope,
                Severity::Medium,
                Some(format!("{scope}.askFallback={fallback}")),
                "This exec approval scope uses a weak ask fallback, which means commands proceed without review when the companion app is unavailable.",
                "Set askFallback to deny to block unapproved commands when the approval UI is not reachable",
            ));
        }
    }

    findings
}

const DANGEROUS_EXECUTABLES: &[&str] = &["curl", "wget", "nc", "ncat", "telnet"];
const INTERPRETER_EXECUTABLES: &[&str] = &[
    "python", "python3", "node", "ruby", "bash", "sh", "zsh", "perl",
];

fn findings_for_allowlist_entries(path: &str, scope: &str, allowlist: &[Value]) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (index, entry) in allowlist.iter().enumerate() {
        let (entry_id, pattern, last_used_command, last_resolved_path) = match entry {
            Value::String(s) => (s.clone(), Some(s.clone()), None, None),
            Value::Object(obj) => {
                let id = string_field(obj, "id").unwrap_or_else(|| index.to_string());
                let pat = string_field(obj, "pattern");
                let cmd = string_field(obj, "lastUsedCommand");
                let resolved = string_field(obj, "lastResolvedPath");
                (id, pat, cmd, resolved)
            }
            _ => continue,
        };

        let basename = extract_basename(last_resolved_path.as_deref(), pattern.as_deref());
        let entry_scope = format!("{scope}.allowlist[{entry_id}]");

        // Check for catastrophic commands first (highest severity).
        if let Some(cmd) = &last_used_command {
            if let Some(evidence) = catastrophic_command_evidence(cmd) {
                findings.push(build_config_finding(
                    path,
                    "allowlist-catastrophic-command",
                    &entry_scope,
                    Severity::Critical,
                    Some(format!("{entry_scope}.lastUsedCommand: {evidence}")),
                    "This exec-approval allowlist entry records a catastrophic command that could destroy data or open a reverse shell.",
                    "Remove or reset this allowlist entry and audit how it was approved",
                ));
            }
        }

        // Check dangerous executables.
        if let Some(base) = &basename {
            let base_lower = normalize_lower(base);
            if DANGEROUS_EXECUTABLES.iter().any(|&d| d == base_lower) {
                findings.push(build_config_finding(
                    path,
                    "allowlist-dangerous-executable",
                    &entry_scope,
                    Severity::High,
                    Some(format!("{entry_scope}.executable={base}")),
                    "This exec-approval allowlist entry permits a dangerous executable that is commonly used for data exfiltration or remote code execution.",
                    "Remove this allowlist entry or restrict it to a safer command scope",
                ));
            }

            // Check interpreter executables.
            if INTERPRETER_EXECUTABLES.iter().any(|&i| i == base_lower) {
                findings.push(build_config_finding(
                    path,
                    "allowlist-interpreter",
                    &entry_scope,
                    Severity::High,
                    Some(format!("{entry_scope}.executable={base}")),
                    "This exec-approval allowlist entry permits a general-purpose interpreter. Verify that strictInlineEval is enabled in openclaw.json to limit eval-style execution.",
                    "Verify strictInlineEval is enabled or remove this allowlist entry",
                ));
            }
        }
    }

    findings
}

/// Extract the basename of the executable from the resolved path or pattern.
fn extract_basename(resolved_path: Option<&str>, pattern: Option<&str>) -> Option<String> {
    if let Some(resolved) = resolved_path {
        let trimmed = resolved.trim();
        if !trimmed.is_empty() {
            return std::path::Path::new(trimmed)
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::to_string);
        }
    }
    if let Some(pat) = pattern {
        let trimmed = pat.trim();
        if !trimmed.is_empty() {
            // Pattern like "**/curl" — extract the last path component.
            return std::path::Path::new(trimmed)
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::to_string);
        }
    }
    None
}

/// Shell sink names recognized by the pipe-to-shell detector.
const SHELL_SINKS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh", "fish"];

/// Extract the basename of a token that may be a full path (e.g. `/usr/bin/env` -> `env`).
/// If the basename is `env` and a `next_token` is provided, unwrap and return that
/// token's basename instead so that `/usr/bin/env bash` resolves to `bash`.
fn command_basename(token: &str, next_token: Option<&str>) -> String {
    let base = std::path::Path::new(token)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(token);
    let base_lower = normalize_lower(base);
    if base_lower == "env" {
        if let Some(next) = next_token {
            let next_base = std::path::Path::new(next)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(next);
            return normalize_lower(next_base);
        }
    }
    base_lower
}

/// Check if a command string contains catastrophic patterns.
/// Returns `Some(description)` if a catastrophic pattern is found.
fn catastrophic_command_evidence(command: &str) -> Option<String> {
    // Check for /dev/tcp anywhere (reverse shell indicator).
    if command.contains("/dev/tcp") {
        return Some("reverse shell via /dev/tcp".to_string());
    }

    // Split on pipe, &&, and ; to get command segments with delimiter info.
    let segments = split_command_segments(command);

    for (segment, is_pipe_target) in &segments {
        let tokens = tokenize_segment(segment);
        if tokens.is_empty() {
            continue;
        }

        let lead = command_basename(&tokens[0], tokens.get(1).map(|s| s.as_str()));

        // Check if this segment receives piped input into a shell.
        if *is_pipe_target && SHELL_SINKS.iter().any(|&s| s == lead) {
            return Some("pipe to shell".to_string());
        }

        // rm -rf / or rm -rf ~ or rm -rf /*
        if lead == "rm" && is_rm_rf_catastrophic(&tokens) {
            return Some("rm -rf on critical path".to_string());
        }

        // mkfs as leading command
        if lead == "mkfs" || lead.starts_with("mkfs.") {
            return Some("mkfs (filesystem format)".to_string());
        }

        // chmod 777 / or chmod -R 777
        if lead == "chmod" && is_chmod_catastrophic(&tokens) {
            return Some("chmod 777 on critical path".to_string());
        }

        // dd if=/dev/zero of=/dev/sd*
        if lead == "dd" && is_dd_catastrophic(&tokens) {
            return Some("dd targeting block device".to_string());
        }

        // nc -e or ncat -e as leading tokens
        if (lead == "nc" || lead == "ncat") && tokens.iter().any(|t| t == "-e") {
            return Some("nc/ncat with -e (exec)".to_string());
        }
    }

    None
}

/// Split a command string on `|`, `&&`, and `;` to get individual segments.
/// Returns `Vec<(segment, is_pipe_target)>` where `is_pipe_target` is true only
/// when the preceding delimiter was a pipe (`|`).
/// Quote-aware: delimiters inside single or double quotes are not treated as splits.
fn split_command_segments(command: &str) -> Vec<(String, bool)> {
    let mut segments = Vec::new();
    let mut current = String::new();
    let mut next_is_pipe = false;
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let chars: Vec<char> = command.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        let ch = chars[i];

        // Track quote state.
        if !in_double_quote && ch == '\'' {
            in_single_quote = !in_single_quote;
            current.push(ch);
            i += 1;
            continue;
        }
        if !in_single_quote && ch == '"' {
            in_double_quote = !in_double_quote;
            current.push(ch);
            i += 1;
            continue;
        }

        // Inside quotes, never split.
        if in_single_quote || in_double_quote {
            current.push(ch);
            i += 1;
            continue;
        }

        if ch == '|' && (i + 1 >= len || chars[i + 1] != '|') {
            segments.push((std::mem::take(&mut current), next_is_pipe));
            next_is_pipe = true;
            i += 1;
        } else if ch == '&' && i + 1 < len && chars[i + 1] == '&' {
            segments.push((std::mem::take(&mut current), next_is_pipe));
            next_is_pipe = false;
            i += 2;
        } else if ch == ';' {
            segments.push((std::mem::take(&mut current), next_is_pipe));
            next_is_pipe = false;
            i += 1;
        } else {
            current.push(ch);
            i += 1;
        }
    }

    if !current.is_empty() {
        segments.push((current, next_is_pipe));
    }

    segments
}

/// Simple whitespace tokenizer that respects single and double quotes.
fn tokenize_segment(segment: &str) -> Vec<String> {
    let trimmed = segment.trim();
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_single_quote = false;
    let mut in_double_quote = false;

    for ch in trimmed.chars() {
        if in_single_quote {
            if ch == '\'' {
                in_single_quote = false;
            } else {
                current.push(ch);
            }
        } else if in_double_quote {
            if ch == '"' {
                in_double_quote = false;
            } else {
                current.push(ch);
            }
        } else if ch == '\'' {
            in_single_quote = true;
        } else if ch == '"' {
            in_double_quote = true;
        } else if ch.is_whitespace() {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
        } else {
            current.push(ch);
        }
    }

    if !current.is_empty() {
        tokens.push(current);
    }

    tokens
}

/// Check if an rm command is catastrophically dangerous.
fn is_rm_rf_catastrophic(tokens: &[String]) -> bool {
    // Look for -rf or -r -f or equivalent flag combinations, plus a dangerous target.
    let has_r = tokens.iter().any(|t| {
        let lower = normalize_lower(t);
        lower == "-rf"
            || lower == "-fr"
            || lower == "-r"
            || lower.starts_with("-") && lower.contains('r') && lower.contains('f')
    });

    if !has_r {
        return false;
    }

    // Check if any non-flag token (after the command) is a critical path.
    tokens.iter().skip(1).any(|t| {
        if t.starts_with('-') {
            return false;
        }
        let trimmed = t.trim();
        trimmed == "/" || trimmed == "~" || trimmed == "/*" || trimmed == "~/*"
    })
}

/// Check if a chmod command is catastrophically dangerous.
/// Requires both `777` mode and a critical path target (`/` or `/*`).
/// The recursive flag alone without a critical path is not catastrophic
/// (e.g. `chmod -R 777 ./cache` is broad but not system-destroying).
fn is_chmod_catastrophic(tokens: &[String]) -> bool {
    let has_777 = tokens.iter().any(|t| t == "777");
    if !has_777 {
        return false;
    }

    // chmod 777 / or chmod -R 777 /
    tokens.iter().skip(1).any(|t| {
        if t.starts_with('-') || t == "777" {
            return false;
        }
        let trimmed = t.trim();
        trimmed == "/" || trimmed == "/*"
    })
}

/// Check if a dd command is catastrophically dangerous (targeting a block device).
fn is_dd_catastrophic(tokens: &[String]) -> bool {
    tokens.iter().any(|t| {
        let lower = normalize_lower(t);
        lower.starts_with("of=/dev/sd")
            || lower.starts_with("of=/dev/nvm")
            || lower.starts_with("of=/dev/hd")
    })
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
