use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::file_type::{classify_leading_bytes, detect_binary_signature, BinarySignature};
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
        let boundary = fs::canonicalize(dir).unwrap_or_else(|_| dir.clone());
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let hook_dir = entry.path();
            if !hook_dir.is_dir() {
                continue;
            }
            scan_single_hook(&hook_dir, &boundary, max_file_size_bytes, &mut output);
        }
    }
    output
}

fn scan_single_hook(
    hook_dir: &Path,
    scan_boundary: &Path,
    max_file_size_bytes: u64,
    output: &mut HookScanOutput,
) {
    // Phase 1 — byte-first integrity sweep: flag any file in the hook dir
    // that claims a text-like extension (or no extension) but begins with a
    // native executable header.
    file_type_mismatch_sweep(hook_dir, scan_boundary, max_file_size_bytes, output);

    // Phase 2 — HOOK.md metadata hash (drift detection).
    let hook_md_path = hook_dir.join("HOOK.md");
    if path_within_boundary(&hook_md_path, scan_boundary)
        && detect_binary_signature(&hook_md_path).is_none()
    {
        if let Ok(md_contents) = fs::read_to_string(&hook_md_path) {
            output.artifacts.push(HookArtifact {
                path: resolved_path_string(&hook_md_path),
                sha256: sha256_hex(md_contents.as_bytes()),
            });
        }
    }

    // Phase 3 — JS handler content findings. Priority matches upstream
    // OpenClaw loader order: handler.ts → handler.js → index.ts → index.js.
    let handler_names = [
        "handler.ts",
        "handler.js",
        "index.ts",
        "index.js",
        "handler.mjs",
        "handler.cjs",
    ];

    // Enumerate ALL present handler files in priority order before picking one,
    // so we can warn about shadowed siblings. An attacker who plants a clean
    // handler.ts (wins the loader) plus a malicious handler.js would otherwise
    // leave the malicious file content-unscanned.
    let present_handlers: Vec<&&str> = handler_names
        .iter()
        .filter(|name| hook_dir.join(name).is_file())
        .collect();

    if present_handlers.len() > 1 {
        let executed = present_handlers[0];
        let shadowed: Vec<String> = present_handlers[1..]
            .iter()
            .map(|name| (**name).to_string())
            .collect();
        let hook_label = resolved_path_string(hook_dir);
        output.findings.push(build_multiple_handlers_finding(
            &hook_label,
            executed,
            &shadowed,
        ));
    }

    for name in present_handlers {
        let handler_path = hook_dir.join(name);
        if !path_within_boundary(&handler_path, scan_boundary) {
            continue;
        }
        let Ok(meta) = handler_path.metadata() else {
            continue;
        };
        if meta.len() > max_file_size_bytes {
            continue;
        }
        // Single-open gate: read the file once as bytes, classify leading
        // bytes against the binary-signature table, then only UTF-8-decode
        // if the file is text. This replaces a previous two-open flow
        // (detect_binary_signature + fs::read_to_string) that did the work
        // with two separate syscall round-trips per handler.
        let Ok(raw) = fs::read(&handler_path) else {
            continue;
        };
        if classify_leading_bytes(&raw).is_some() {
            // Phase 1 (file_type_mismatch_sweep) already emitted the
            // file-type-mismatch finding; stop scanning this hook's handler
            // chain because OpenClaw will only execute the first one anyway.
            break;
        }
        let Ok(contents) = String::from_utf8(raw) else {
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
        // Only the first (highest-priority) handler is actually executed by
        // OpenClaw. We have already warned about the shadowed siblings above.
        break;
    }
}

fn file_type_mismatch_sweep(
    hook_dir: &Path,
    scan_boundary: &Path,
    max_file_size_bytes: u64,
    output: &mut HookScanOutput,
) {
    let Ok(entries) = fs::read_dir(hook_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        if meta.len() > max_file_size_bytes {
            continue;
        }
        if !is_hook_text_candidate(&path) {
            continue;
        }
        if !path_within_boundary(&path, scan_boundary) {
            continue;
        }
        if let Some(signature) = detect_binary_signature(&path) {
            let resolved = resolved_path_string(&path);
            output
                .findings
                .push(build_file_type_mismatch_finding(&resolved, signature));
        }
    }
}

fn is_hook_text_candidate(path: &Path) -> bool {
    match path.extension().and_then(|e| e.to_str()) {
        None => true, // extensionless hook scripts are candidates
        Some(ext) => matches!(
            ext.to_ascii_lowercase().as_str(),
            "sh" | "bash"
                | "zsh"
                | "fish"
                | "py"
                | "js"
                | "mjs"
                | "cjs"
                | "ts"
                | "json"
                | "yaml"
                | "yml"
                | "toml"
                | "md"
                | "txt"
        ),
    }
}

/// Canonicalize `path` and verify the result stays under `boundary`. This is
/// a best-effort check: if `fs::canonicalize` fails, we fall back to the
/// original path (which won't satisfy `starts_with` on a canonical boundary).
///
/// Known TOCTOU window: between this check and the subsequent open, a
/// symlink swap can redirect the read target. The impact is bounded — the
/// hook scanner only reads, and any disguised binary is caught by the
/// downstream `classify_leading_bytes` gate — but callers that need strong
/// guarantees must use an `openat`-style primitive. For ClawGuard's
/// passive-scan threat model the remaining window is accepted risk.
fn path_within_boundary(path: &Path, boundary: &Path) -> bool {
    let resolved = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    resolved.starts_with(boundary)
}

fn build_file_type_mismatch_finding(path: &str, signature: BinarySignature) -> Finding {
    Finding {
        id: format!("hooks:file-type-mismatch:{path}"),
        detector_id: "file-type".to_string(),
        severity: Severity::High,
        category: FindingCategory::Config,
        runtime_confidence: RuntimeConfidence::ActiveRuntime,
        path: path.to_string(),
        line: None,
        evidence: Some(format!("signature={}", signature.as_kind())),
        plain_english_explanation: "This hook file has a text-like extension but starts with a native executable header. A disguised binary in a hook dir is a high-signal supply-chain integrity red flag.".to_string(),
        recommended_action: RecommendedAction {
            label: "Inspect this file by hand; restore the legitimate hook content or delete it"
                .to_string(),
            command_hint: None,
        },
        fixability: Fixability::Manual,
        fix: None,
        owasp_asi: owasp_asi_for_kind("file-type-mismatch"),
    }
}

fn build_multiple_handlers_finding(
    hook_path: &str,
    executed: &str,
    shadowed: &[String],
) -> Finding {
    let shadowed_list = shadowed.join(", ");
    Finding {
        id: format!("hook-handler:hook-multiple-handlers:{hook_path}"),
        detector_id: "hook-handler".to_string(),
        severity: Severity::Medium,
        category: FindingCategory::Config,
        runtime_confidence: RuntimeConfidence::ActiveRuntime,
        path: hook_path.to_string(),
        line: None,
        evidence: Some(format!(
            "executed={executed} shadowed=[{shadowed_list}]"
        )),
        plain_english_explanation:
            "This hook dir has multiple handler files that match the OpenClaw loader priority list. Only the highest-priority file is executed, but a shadowed sibling can still be swapped into place by a later edit without tripping content scans — a classic hide-the-payload pattern.".to_string(),
        recommended_action: RecommendedAction {
            label:
                "Remove the shadowed handler file(s) so only the intended entry point exists"
                    .to_string(),
            command_hint: None,
        },
        fixability: Fixability::Manual,
        fix: None,
        owasp_asi: owasp_asi_for_kind("hook-multiple-handlers"),
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
