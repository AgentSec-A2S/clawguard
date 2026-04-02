use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::finding::owasp_asi_for_kind;
use super::{Finding, FindingCategory, Fixability, RecommendedAction, RuntimeConfidence, Severity};

/// Bootstrap files injected into every agent session by OpenClaw.
pub(crate) const BOOTSTRAP_FILES: &[&str] = &[
    "AGENTS.md",
    "SOUL.md",
    "TOOLS.md",
    "IDENTITY.md",
    "USER.md",
    "HEARTBEAT.md",
    "BOOTSTRAP.md",
    "MEMORY.md",
    "memory.md",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapArtifact {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BootstrapScanOutput {
    pub findings: Vec<Finding>,
    pub artifacts: Vec<BootstrapArtifact>,
}

/// Scan bootstrap files in the given agent root directories.
/// Accepts either direct workspace dirs (containing .md files) or parent dirs
/// like `~/.openclaw/agents` which are auto-expanded to `agents/*/agent/`.
pub fn scan_bootstrap_dirs(dirs: &[PathBuf], max_file_size_bytes: u64) -> BootstrapScanOutput {
    let mut output = BootstrapScanOutput::default();
    for dir in dirs {
        if !dir.exists() || !dir.is_dir() {
            continue;
        }
        let workspace_dirs = discover_workspace_dirs(dir);
        for workspace in &workspace_dirs {
            scan_workspace(workspace, max_file_size_bytes, &mut output);
        }
    }
    output
}

pub(crate) fn discover_workspace_dirs(dir: &Path) -> Vec<PathBuf> {
    let mut workspaces = Vec::new();

    // Always enumerate agent subdirs: dir/*/agent/
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let agent_dir = entry.path().join("agent");
            if agent_dir.is_dir() {
                workspaces.push(agent_dir);
            }
        }
    }

    // If no agent subdirs found but dir itself has bootstrap files, scan it directly
    if workspaces.is_empty() && BOOTSTRAP_FILES.iter().any(|f| dir.join(f).is_file()) {
        workspaces.push(dir.to_path_buf());
    }

    workspaces
}

fn scan_workspace(dir: &Path, max_file_size_bytes: u64, output: &mut BootstrapScanOutput) {
    if !dir.exists() || !dir.is_dir() {
        return;
    }
    for file_name in BOOTSTRAP_FILES {
        let file_path = dir.join(file_name);
        if !file_path.is_file() {
            continue;
        }
        let Ok(meta) = file_path.metadata() else {
            continue;
        };
        if meta.len() > max_file_size_bytes {
            continue;
        }
        let Ok(contents) = fs::read_to_string(&file_path) else {
            continue;
        };
        let resolved = resolved_path_string(&file_path);

        output.artifacts.push(BootstrapArtifact {
            path: resolved.clone(),
            sha256: sha256_hex(contents.as_bytes()),
        });

        output
            .findings
            .extend(findings_for_bootstrap_content(&contents, &resolved));
    }
}

fn findings_for_bootstrap_content(contents: &str, path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (line_number, line) in contents.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Some(f) = encoded_payload_finding(trimmed, path, line_number + 1) {
            findings.push(f);
        }
        if let Some(f) = shell_injection_finding(trimmed, path, line_number + 1) {
            findings.push(f);
        }
        if let Some(f) = prompt_injection_finding(trimmed, path, line_number + 1) {
            findings.push(f);
        }
        if let Some(f) = obfuscated_content_finding(trimmed, path, line_number + 1) {
            findings.push(f);
        }
    }
    findings
}

/// Detect base64-encoded payloads longer than 100 characters.
fn encoded_payload_finding(line: &str, path: &str, line_number: usize) -> Option<Finding> {
    // Look for long base64-like strings (alphanumeric + /+=, at least 100 chars contiguous)
    for word in line.split_whitespace() {
        if word.len() >= 100 && is_base64_like(word) {
            return Some(build_bootstrap_finding(
                path,
                "bootstrap-encoded-payload",
                Severity::High,
                line,
                line_number,
                "Bootstrap file contains a long encoded payload that may hide executable content from human review.",
                "Decode and inspect the payload; remove if not intentional",
            ));
        }
    }
    None
}

fn is_base64_like(s: &str) -> bool {
    // Accept both standard (+/) and URL-safe (-_) base64 characters
    let valid_chars = s.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' || c == '-' || c == '_'
    });
    // Must have mix of upper/lower/digits to look like base64, not just a long word
    let has_upper = s.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = s.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = s.chars().any(|c| c.is_ascii_digit());
    valid_chars && has_upper && has_lower && has_digit
}

/// Detect shell command injection patterns: `$(...)` and backtick command substitution.
fn shell_injection_finding(line: &str, path: &str, line_number: usize) -> Option<Finding> {
    let trimmed = line.trim();
    // Exclude markdown code fences
    if trimmed.starts_with("```") {
        return None;
    }

    // Check $(...) command substitution
    if line.contains("$(") {
        return Some(build_bootstrap_finding(
            path,
            "bootstrap-shell-injection",
            Severity::High,
            line,
            line_number,
            "Bootstrap file contains shell command substitution that could execute arbitrary commands when processed.",
            "Remove shell command substitution from bootstrap files",
        ));
    }

    // Check ${} variable expansion (common shell injection vector)
    if line.contains("${") && !trimmed.starts_with('#') {
        let lowered = line.to_ascii_lowercase();
        // Only flag if it looks like shell injection, not markdown template variables
        if lowered.contains("curl")
            || lowered.contains("wget")
            || lowered.contains("bash")
            || lowered.contains("|")
            || lowered.contains("ifs")
        {
            return Some(build_bootstrap_finding(
                path,
                "bootstrap-shell-injection",
                Severity::High,
                line,
                line_number,
                "Bootstrap file contains shell variable expansion that could execute arbitrary commands.",
                "Remove shell variable expansion from bootstrap files",
            ));
        }
    }

    // Check backtick command substitution
    let backtick_count = line.matches('`').count();
    if backtick_count >= 2 {
        // Single pair of backticks with content between them that looks like a command
        if let Some(start) = line.find('`') {
            if let Some(end) = line[start + 1..].find('`') {
                let inner = &line[start + 1..start + 1 + end];
                let inner_lower = inner.to_ascii_lowercase();
                // Only flag if the backtick content looks like shell execution
                if inner_lower.contains("curl ")
                    || inner_lower.contains("wget ")
                    || inner_lower.contains("sh ")
                    || inner_lower.contains("bash ")
                    || inner_lower.contains("eval ")
                    || inner_lower.contains("exec ")
                    || inner_lower.contains(" | sh")
                    || inner_lower.contains(" | bash")
                {
                    return Some(build_bootstrap_finding(
                        path,
                        "bootstrap-shell-injection",
                        Severity::High,
                        line,
                        line_number,
                        "Bootstrap file contains backtick command substitution that could execute arbitrary commands.",
                        "Remove shell command substitution from bootstrap files",
                    ));
                }
            }
        }
    }

    None
}

/// Detect prompt injection markers (case-insensitive).
fn prompt_injection_finding(line: &str, path: &str, line_number: usize) -> Option<Finding> {
    let lowered = line.to_ascii_lowercase();
    let markers = [
        "ignore previous instructions",
        "ignore all previous",
        "disregard previous",
        "you are now",
        "new instructions:",
        "system override",
        "admin override",
        "forget everything",
        "reset your instructions",
    ];
    for marker in &markers {
        if lowered.contains(marker) {
            return Some(build_bootstrap_finding(
                path,
                "bootstrap-prompt-injection",
                Severity::Critical,
                line,
                line_number,
                "Bootstrap file contains a prompt injection marker that attempts to override agent instructions.",
                "Remove the prompt injection payload from this bootstrap file",
            ));
        }
    }
    None
}

/// Detect obfuscated content: long hex-encoded or unicode escape sequences.
fn obfuscated_content_finding(line: &str, path: &str, line_number: usize) -> Option<Finding> {
    // Detect \x hex sequences (e.g., \x48\x65\x6c\x6c\x6f)
    let hex_escape_count = line.matches("\\x").count();
    if hex_escape_count >= 10 {
        return Some(build_bootstrap_finding(
            path,
            "bootstrap-obfuscated-content",
            Severity::Medium,
            line,
            line_number,
            "Bootstrap file contains obfuscated content using hex escape sequences that may hide malicious instructions.",
            "Decode and inspect the obfuscated content; replace with plaintext",
        ));
    }

    // Detect \u unicode escapes (e.g., \u0048\u0065)
    let unicode_escape_count = line.matches("\\u").count();
    if unicode_escape_count >= 10 {
        return Some(build_bootstrap_finding(
            path,
            "bootstrap-obfuscated-content",
            Severity::Medium,
            line,
            line_number,
            "Bootstrap file contains obfuscated content using unicode escape sequences that may hide malicious instructions.",
            "Decode and inspect the obfuscated content; replace with plaintext",
        ));
    }

    None
}

fn build_bootstrap_finding(
    path: &str,
    kind: &str,
    severity: Severity,
    evidence_line: &str,
    line_number: usize,
    explanation: &str,
    action_label: &str,
) -> Finding {
    Finding {
        id: format!("bootstrap-integrity:{kind}:{path}:{line_number}"),
        detector_id: "bootstrap-integrity".to_string(),
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
