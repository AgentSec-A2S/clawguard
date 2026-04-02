use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::finding::owasp_asi_for_kind;
use super::{Finding, FindingCategory, Fixability, RecommendedAction, RuntimeConfidence, Severity};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookArtifact {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HookScanOutput {
    pub findings: Vec<Finding>,
    pub artifacts: Vec<HookArtifact>,
}

/// Scan all hook directories for dangerous handler patterns.
/// `hooks_dirs` should include `~/.openclaw/hooks/` plus any `extraDirs` from config.
pub fn scan_hooks_dirs(hooks_dirs: &[PathBuf], max_file_size_bytes: u64) -> HookScanOutput {
    let mut output = HookScanOutput::default();
    for dir in hooks_dirs {
        if !dir.exists() || !dir.is_dir() {
            continue;
        }
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let hook_dir = entry.path();
            if !hook_dir.is_dir() {
                continue;
            }
            scan_single_hook(&hook_dir, max_file_size_bytes, &mut output);
        }
    }
    output
}

fn scan_single_hook(hook_dir: &Path, max_file_size_bytes: u64, output: &mut HookScanOutput) {
    // Hash HOOK.md metadata if present (metadata drift detection)
    let hook_md_path = hook_dir.join("HOOK.md");
    if let Ok(md_contents) = fs::read_to_string(&hook_md_path) {
        output.artifacts.push(HookArtifact {
            path: resolved_path_string(&hook_md_path),
            sha256: sha256_hex(md_contents.as_bytes()),
        });
    }

    // Handler file priority matches upstream OpenClaw loader order:
    // handler.ts → handler.js → index.ts → index.js
    let handler_names = [
        "handler.ts",
        "handler.js",
        "index.ts",
        "index.js",
        "handler.mjs",
        "handler.cjs",
    ];

    for name in &handler_names {
        let handler_path = hook_dir.join(name);
        if !handler_path.is_file() {
            continue;
        }
        let Ok(meta) = handler_path.metadata() else {
            continue;
        };
        if meta.len() > max_file_size_bytes {
            continue;
        }
        let Ok(contents) = fs::read_to_string(&handler_path) else {
            continue;
        };
        let resolved = resolved_path_string(&handler_path);

        output.artifacts.push(HookArtifact {
            path: resolved.clone(),
            sha256: sha256_hex(contents.as_bytes()),
        });

        output
            .findings
            .extend(findings_for_handler(&contents, &resolved));
        // Only scan the handler OpenClaw would actually execute (first match)
        break;
    }
}

fn findings_for_handler(contents: &str, path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut in_block_comment = false;
    for (line_number, line) in contents.lines().enumerate() {
        let trimmed = line.trim();

        // Track block comment state
        if in_block_comment {
            if trimmed.contains("*/") {
                in_block_comment = false;
            }
            continue;
        }
        if trimmed.starts_with("/*") {
            if !trimmed.contains("*/") {
                in_block_comment = true;
            }
            continue;
        }
        // Skip single-line comments
        if trimmed.starts_with("//") {
            continue;
        }
        let lowered = trimmed.to_ascii_lowercase();

        if let Some(f) = shell_exec_finding(&lowered, trimmed, path, line_number + 1) {
            findings.push(f);
        }
        if let Some(f) = network_exfil_finding(&lowered, trimmed, path, line_number + 1) {
            findings.push(f);
        }
        if let Some(f) = identity_mutation_finding(&lowered, trimmed, path, line_number + 1) {
            findings.push(f);
        }
        if let Some(f) = config_mutation_finding(&lowered, trimmed, path, line_number + 1) {
            findings.push(f);
        }
    }
    findings
}

fn shell_exec_finding(
    lowered: &str,
    evidence_line: &str,
    path: &str,
    line_number: usize,
) -> Option<Finding> {
    let triggers = [
        "child_process",
        "require(\"child_process",
        "require('child_process",
        "require(`child_process",
        "from \"child_process",
        "from 'child_process",
        "import(\"child_process",
        "import('child_process",
        "import(`child_process",
        "execsync(",
        "execfilesync(",
        "spawnsync(",
        "spawn(",
        "execfile(",
        "process.binding(",
    ];
    if !triggers.iter().any(|t| lowered.contains(t)) {
        return None;
    }
    Some(build_hook_finding(
        path,
        "hook-shell-exec",
        Severity::High,
        evidence_line,
        line_number,
        "Hook handler executes shell commands, which can be used for arbitrary code execution on the host.",
        "Review whether shell execution is necessary; consider removing or restricting the handler",
    ))
}

fn network_exfil_finding(
    lowered: &str,
    evidence_line: &str,
    path: &str,
    line_number: usize,
) -> Option<Finding> {
    let triggers = [
        "fetch(",
        "http.request(",
        "https.request(",
        "axios(",
        "axios.",
        "got(",
        "node-fetch",
        "undici",
        "websocket(",
        "new websocket(",
        "net.connect(",
        "net.createconnection(",
        "dns.resolve(",
        "xmlhttprequest(",
        "new xmlhttprequest(",
        "eventsource(",
        "new eventsource(",
    ];
    if !triggers.iter().any(|t| lowered.contains(t)) {
        return None;
    }
    Some(build_hook_finding(
        path,
        "hook-network-exfil",
        Severity::High,
        evidence_line,
        line_number,
        "Hook handler makes network requests, which can be used to exfiltrate session data or configuration.",
        "Review whether outbound network access is necessary; restrict to known endpoints if needed",
    ))
}

fn identity_mutation_finding(
    lowered: &str,
    evidence_line: &str,
    path: &str,
    line_number: usize,
) -> Option<Finding> {
    let identity_files = [
        "soul.md",
        "memory.md",
        "identity.md",
        "agents.md",
        "tools.md",
        "user.md",
    ];
    // Look for write patterns targeting identity files
    let has_write = lowered.contains("writefile")
        || lowered.contains("appendfile")
        || lowered.contains("fs.write")
        || lowered.contains("fs.append")
        || lowered.contains("createwritestream");
    if !has_write {
        return None;
    }
    if !identity_files.iter().any(|f| lowered.contains(f)) {
        return None;
    }
    Some(build_hook_finding(
        path,
        "hook-identity-mutation",
        Severity::Medium,
        evidence_line,
        line_number,
        "Hook handler writes to agent identity/bootstrap files, which can alter agent behavior across sessions.",
        "Review whether identity file writes are intentional; consider read-only access patterns",
    ))
}

fn config_mutation_finding(
    lowered: &str,
    evidence_line: &str,
    path: &str,
    line_number: usize,
) -> Option<Finding> {
    let config_files = ["openclaw.json", "exec-approvals.json"];
    let has_write = lowered.contains("writefile")
        || lowered.contains("appendfile")
        || lowered.contains("fs.write")
        || lowered.contains("fs.append")
        || lowered.contains("createwritestream");
    if !has_write {
        return None;
    }
    if !config_files.iter().any(|f| lowered.contains(f)) {
        return None;
    }
    Some(build_hook_finding(
        path,
        "hook-config-mutation",
        Severity::High,
        evidence_line,
        line_number,
        "Hook handler writes to OpenClaw configuration files, which can weaken security posture without operator awareness.",
        "Review whether config writes are intentional; hooks should not modify security-critical config",
    ))
}

fn build_hook_finding(
    path: &str,
    kind: &str,
    severity: Severity,
    evidence_line: &str,
    line_number: usize,
    explanation: &str,
    action_label: &str,
) -> Finding {
    Finding {
        id: format!("hook-handler:{kind}:{path}:{line_number}"),
        detector_id: "hook-handler".to_string(),
        severity,
        category: FindingCategory::Config,
        runtime_confidence: RuntimeConfidence::ActiveRuntime,
        path: path.to_string(),
        line: Some(line_number),
        evidence: Some(evidence_line.to_string()),
        plain_english_explanation: explanation.to_string(),
        recommended_action: RecommendedAction {
            label: action_label.to_string(),
            command_hint: None,
        },
        fixability: Fixability::Manual,
        fix: None,
        owasp_asi: owasp_asi_for_kind(kind),
    }
}

fn resolved_path_string(path: &Path) -> String {
    fs::canonicalize(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .into_owned()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}
