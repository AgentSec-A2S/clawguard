use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::file_type::{detect_binary_signature, BinarySignature};
use super::finding::owasp_asi_for_kind;
use super::{Finding, FindingCategory, Fixability, RecommendedAction, RuntimeConfidence, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkillSourceHint {
    LocalInstall,
    VcsRepository,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitProvenance {
    pub remote_url: Option<String>,
    pub head_sha: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillArtifact {
    pub path: String,
    pub sha256: String,
    pub source_hint: Option<SkillSourceHint>,
    pub git_provenance: Option<GitProvenance>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SkillScanOutput {
    pub findings: Vec<Finding>,
    pub artifacts: Vec<SkillArtifact>,
}

pub fn scan_skill_dir(
    dir: &Path,
    max_file_size_bytes: u64,
    excluded_dirs: &[String],
) -> SkillScanOutput {
    let mut files = Vec::new();
    let excluded: HashSet<_> = excluded_dirs.iter().map(|value| value.as_str()).collect();
    collect_scannable_files(dir, max_file_size_bytes, &excluded, &mut files);
    files.sort();

    let mut findings = Vec::new();
    let mut artifacts = Vec::new();

    // Precompute the canonicalized scan boundary so symlink escapes out of the
    // scan root can be recognized and skipped (must not inspect the target).
    let boundary = canonicalized_boundary(dir);

    for file_path in files {
        let resolved_path = resolved_path_string(&file_path);

        // Boundary check: if the file resolves outside the scan root, skip it
        // entirely — we must not inspect a symlink target outside the scan
        // boundary even for integrity checks.
        if let Some(ref boundary) = boundary {
            let canonical = fs::canonicalize(&file_path).unwrap_or_else(|_| file_path.clone());
            if !canonical.starts_with(boundary) {
                continue;
            }
        }

        // Byte-first integrity: if the file claims a text-like skill extension
        // but begins with a native executable header, emit file-type-mismatch
        // and skip the UTF-8 decode. This prevents a disguised binary from
        // being silently dropped by `read_to_string` and sneaking past the
        // skill content scanner.
        if let Some(signature) = detect_binary_signature(&file_path) {
            findings.push(build_file_type_mismatch_finding(&resolved_path, signature));
            continue;
        }

        let Ok(contents) = fs::read_to_string(&file_path) else {
            continue;
        };

        let source_hint = detect_source_hint(dir, &file_path);
        let git_provenance = extract_git_provenance(dir, &file_path);
        artifacts.push(SkillArtifact {
            path: resolved_path.clone(),
            sha256: sha256_hex(contents.as_bytes()),
            source_hint,
            git_provenance,
        });

        findings.extend(findings_for_content(&contents, &resolved_path));
    }

    SkillScanOutput {
        findings,
        artifacts,
    }
}

fn detect_source_hint(scan_root: &Path, file_path: &Path) -> Option<SkillSourceHint> {
    let scan_root = canonicalized_boundary(scan_root)?;
    let path = fs::canonicalize(file_path).unwrap_or_else(|_| file_path.to_path_buf());
    let mut current = if path.is_dir() {
        Some(path.as_path())
    } else {
        path.parent()
    };

    while let Some(candidate) = current {
        if !candidate.starts_with(&scan_root) {
            break;
        }

        if candidate.join(".git").exists() {
            return Some(SkillSourceHint::VcsRepository);
        }

        if candidate == scan_root {
            break;
        }

        current = candidate.parent();
    }

    Some(SkillSourceHint::LocalInstall)
}

fn canonicalized_boundary(path: &Path) -> Option<PathBuf> {
    let boundary = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if boundary.is_dir() {
        Some(boundary)
    } else {
        boundary.parent().map(Path::to_path_buf)
    }
}

// ---- Git provenance extraction ----

/// Extract git provenance (remote URL + HEAD SHA) for a skill file.
/// Walks up from file_path within scan_root looking for .git.
/// Handles .git as directory (normal repo) or file (worktree/submodule).
fn extract_git_provenance(scan_root: &Path, file_path: &Path) -> Option<GitProvenance> {
    let git_dir = find_git_dir(scan_root, file_path)?;
    let remote_url = parse_git_config_remote_url(&git_dir);
    let head_sha = parse_git_head_sha(&git_dir);

    if remote_url.is_none() && head_sha.is_none() {
        return None;
    }

    Some(GitProvenance {
        remote_url,
        head_sha,
    })
}

/// Find the .git directory for a file, walking up from file_path within scan_root.
/// Handles .git as a file (worktrees/submodules: contains `gitdir: <path>`).
fn find_git_dir(scan_root: &Path, file_path: &Path) -> Option<PathBuf> {
    let scan_root = canonicalized_boundary(scan_root)?;
    let path = fs::canonicalize(file_path).unwrap_or_else(|_| file_path.to_path_buf());
    let mut current = if path.is_dir() {
        Some(path.as_path())
    } else {
        path.parent()
    };

    while let Some(candidate) = current {
        if !candidate.starts_with(&scan_root) {
            break;
        }

        let git_path = candidate.join(".git");
        if git_path.is_dir() {
            return Some(git_path);
        }
        // .git can be a file for worktrees/submodules: "gitdir: /path/to/real/.git"
        if git_path.is_file() {
            if let Ok(content) = fs::read_to_string(&git_path) {
                let trimmed = content.trim();
                if let Some(gitdir) = trimmed.strip_prefix("gitdir:") {
                    let resolved = candidate.join(gitdir.trim());
                    let resolved = fs::canonicalize(&resolved).unwrap_or(resolved);
                    // Boundary guard: reject gitdir paths that escape scan_root
                    // (e.g. attacker-crafted .git file pointing outside)
                    if resolved.is_dir() && resolved.starts_with(&scan_root) {
                        return Some(resolved);
                    }
                }
            }
        }

        if candidate == scan_root {
            break;
        }
        current = candidate.parent();
    }

    None
}

/// Parse the remote origin URL from .git/config.
/// Simple line-by-line INI parser — no external crate needed.
/// Parse remote origin URL from git config content string.
/// Exposed as pub(crate) for fuzz testing.
pub fn parse_git_config_remote_url_from_str(content: &str) -> Option<String> {
    let mut in_remote_origin = false;
    for line in content.lines() {
        if line.len() > 4096 {
            continue;
        }
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_remote_origin = trimmed == "[remote \"origin\"]";
            continue;
        }
        if in_remote_origin {
            if let Some(value) = trimmed.strip_prefix("url") {
                let value = value.trim_start();
                if let Some(url) = value.strip_prefix('=') {
                    let url = url.trim();
                    if !url.is_empty() && url.is_ascii() {
                        return Some(url.to_string());
                    }
                }
            }
        }
    }
    None
}

/// Parse HEAD SHA from git HEAD content + optional packed-refs content.
/// Exposed as pub(crate) for fuzz testing.
pub fn parse_git_head_sha_from_str(
    head_content: &str,
    ref_content: Option<&str>,
    packed_refs_content: Option<&str>,
) -> Option<String> {
    let trimmed = head_content.trim();
    if let Some(ref_path) = trimmed.strip_prefix("ref: ") {
        // Try loose ref
        if let Some(ref_data) = ref_content {
            let sha = ref_data.trim();
            if is_hex_sha(sha) {
                return Some(sha.to_string());
            }
        }
        // Try packed-refs
        if let Some(packed) = packed_refs_content {
            let ref_name = ref_path.trim();
            for line in packed.lines() {
                let line = line.trim();
                if line.starts_with('#') || line.starts_with('^') {
                    continue;
                }
                if let Some((sha, name)) = line.split_once(' ') {
                    if name == ref_name && is_hex_sha(sha) {
                        return Some(sha.to_string());
                    }
                }
            }
        }
        None
    } else if is_hex_sha(trimmed) {
        Some(trimmed.to_string())
    } else {
        None
    }
}

fn parse_git_config_remote_url(git_dir: &Path) -> Option<String> {
    let config_path = git_dir.join("config");
    let content = fs::read_to_string(&config_path).ok()?;

    let mut in_remote_origin = false;
    for line in content.lines() {
        if line.len() > 4096 {
            continue; // skip extremely long lines
        }
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_remote_origin = trimmed == "[remote \"origin\"]";
            continue;
        }
        if in_remote_origin {
            if let Some(value) = trimmed.strip_prefix("url") {
                let value = value.trim_start();
                if let Some(url) = value.strip_prefix('=') {
                    let url = url.trim();
                    if !url.is_empty() && url.is_ascii() {
                        return Some(url.to_string());
                    }
                }
            }
        }
    }

    None
}

/// Parse the HEAD SHA from .git/HEAD.
/// Supports symbolic refs (ref: refs/heads/X) and detached HEAD (raw SHA).
/// Falls back to .git/packed-refs when loose ref file is missing.
fn parse_git_head_sha(git_dir: &Path) -> Option<String> {
    let head_path = git_dir.join("HEAD");
    let content = fs::read_to_string(&head_path).ok()?;
    let trimmed = content.trim();

    if let Some(ref_path) = trimmed.strip_prefix("ref: ") {
        // Symbolic ref — try loose ref file first
        let ref_file = git_dir.join(ref_path.trim());
        if let Ok(sha) = fs::read_to_string(&ref_file) {
            let sha = sha.trim();
            if is_hex_sha(sha) {
                return Some(sha.to_string());
            }
        }
        // Fallback: parse packed-refs
        let packed_refs = git_dir.join("packed-refs");
        if let Ok(packed) = fs::read_to_string(&packed_refs) {
            let ref_name = ref_path.trim();
            for line in packed.lines() {
                let line = line.trim();
                if line.starts_with('#') || line.starts_with('^') {
                    continue;
                }
                // Format: "<sha> <ref>"
                if let Some((sha, name)) = line.split_once(' ') {
                    if name == ref_name && is_hex_sha(sha) {
                        return Some(sha.to_string());
                    }
                }
            }
        }
        None
    } else if is_hex_sha(trimmed) {
        // Detached HEAD — raw SHA
        Some(trimmed.to_string())
    } else {
        None
    }
}

fn is_hex_sha(s: &str) -> bool {
    s.len() >= 40 && s.len() <= 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn collect_scannable_files(
    path: &Path,
    max_file_size_bytes: u64,
    excluded_dirs: &HashSet<&str>,
    files: &mut Vec<PathBuf>,
) {
    let Ok(metadata) = fs::metadata(path) else {
        return;
    };

    if metadata.is_file() {
        if metadata.len() <= max_file_size_bytes && is_scannable_skill_file(path) {
            files.push(path.to_path_buf());
        }
        return;
    }

    if !metadata.is_dir() {
        return;
    }

    let Ok(entries) = fs::read_dir(path) else {
        return;
    };

    for entry in entries.flatten() {
        let entry_path = entry.path();
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();

        if entry_path.is_dir() && excluded_dirs.contains(file_name.as_ref()) {
            continue;
        }

        collect_scannable_files(&entry_path, max_file_size_bytes, excluded_dirs, files);
    }
}

fn is_scannable_skill_file(path: &Path) -> bool {
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };

    if file_name.eq_ignore_ascii_case("SKILL.md") {
        return true;
    }

    let Some(extension) = path.extension().and_then(|value| value.to_str()) else {
        return false;
    };

    matches!(
        extension.to_ascii_lowercase().as_str(),
        "md" | "markdown"
            | "txt"
            | "js"
            | "cjs"
            | "mjs"
            | "ts"
            | "cts"
            | "mts"
            | "py"
            | "sh"
            | "bash"
            | "zsh"
    )
}

fn findings_for_content(contents: &str, resolved_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (index, line) in contents.lines().enumerate() {
        let line_number = index + 1;
        let trimmed = line.trim();
        let lowered = trimmed.to_ascii_lowercase();

        if let Some(finding) =
            shell_execution_finding(&lowered, trimmed, resolved_path, line_number)
        {
            findings.push(finding);
        }

        if let Some(finding) = network_finding(&lowered, trimmed, resolved_path, line_number) {
            findings.push(finding);
        }

        if let Some(finding) = install_finding(&lowered, trimmed, resolved_path, line_number) {
            findings.push(finding);
        }
    }

    findings
}

fn shell_execution_finding(
    lowered: &str,
    evidence_line: &str,
    path: &str,
    line_number: usize,
) -> Option<Finding> {
    let is_shell_exec = lowered.contains("child_process.exec")
        || lowered.contains("bash -c")
        || lowered.contains("sh -c")
        || lowered.contains("zsh -c")
        || (lowered.contains("subprocess.run(") && lowered.contains("shell=true"))
        || lowered.contains("| sh")
        || lowered.contains("| bash")
        || lowered.contains("| zsh");

    if !is_shell_exec {
        return None;
    }

    let severity =
        if lowered.contains("| sh") || lowered.contains("| bash") || lowered.contains("| zsh") {
            Severity::Critical
        } else {
            Severity::High
        };

    Some(Finding {
        id: format!("skill:shell_exec:{path}:{line_number}"),
        detector_id: "skills".to_string(),
        severity,
        category: FindingCategory::Skills,
        runtime_confidence: RuntimeConfidence::ActiveRuntime,
        path: path.to_string(),
        line: Some(line_number),
        evidence: Some(evidence_line.to_string()),
        plain_english_explanation:
            "This skill contains command-execution behavior that could run unsafe shell commands."
                .to_string(),
        recommended_action: RecommendedAction {
            label: "Review or disable this skill before using it".to_string(),
            command_hint: None,
        },
        fixability: Fixability::AdvisoryOnly,
        fix: None,
        owasp_asi: None,
    })
}

fn network_finding(
    lowered: &str,
    evidence_line: &str,
    path: &str,
    line_number: usize,
) -> Option<Finding> {
    let uses_network = (lowered.contains("curl ") || lowered.contains("wget "))
        && !(lowered.contains("| sh") || lowered.contains("| bash") || lowered.contains("| zsh"))
        || lowered.contains("requests.get(")
        || lowered.contains("requests.post(")
        || lowered.contains("fetch(\"http")
        || lowered.contains("fetch('http");

    if !uses_network {
        return None;
    }

    Some(Finding {
        id: format!("skill:network:{path}:{line_number}"),
        detector_id: "skills".to_string(),
        severity: Severity::Medium,
        category: FindingCategory::Skills,
        runtime_confidence: RuntimeConfidence::ActiveRuntime,
        path: path.to_string(),
        line: Some(line_number),
        evidence: Some(evidence_line.to_string()),
        plain_english_explanation:
            "This skill appears to make outbound network requests and should be reviewed for remote trust boundaries."
                .to_string(),
        recommended_action: RecommendedAction {
            label: "Verify the remote endpoint before enabling this skill".to_string(),
            command_hint: None,
        },
        fixability: Fixability::AdvisoryOnly,
        fix: None,
        owasp_asi: None,
    })
}

fn install_finding(
    lowered: &str,
    evidence_line: &str,
    path: &str,
    line_number: usize,
) -> Option<Finding> {
    let suspicious_install = lowered.contains("npm install -g")
        || lowered.contains("pip install ")
        || lowered.contains("cargo install ")
        || lowered.contains("brew install ");

    if !suspicious_install {
        return None;
    }

    Some(Finding {
        id: format!("skill:install:{path}:{line_number}"),
        detector_id: "skills".to_string(),
        severity: Severity::Medium,
        category: FindingCategory::Skills,
        runtime_confidence: RuntimeConfidence::ActiveRuntime,
        path: path.to_string(),
        line: Some(line_number),
        evidence: Some(evidence_line.to_string()),
        plain_english_explanation:
            "This skill instructs the user to install additional software, which expands the trust boundary and should be reviewed manually."
                .to_string(),
        recommended_action: RecommendedAction {
            label: "Review install steps manually before following them".to_string(),
            command_hint: None,
        },
        fixability: Fixability::AdvisoryOnly,
        fix: None,
        owasp_asi: None,
    })
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

fn build_file_type_mismatch_finding(path: &str, signature: BinarySignature) -> Finding {
    Finding {
        id: format!("skills:file-type-mismatch:{path}"),
        detector_id: "file-type".to_string(),
        severity: Severity::High,
        category: FindingCategory::Skills,
        runtime_confidence: RuntimeConfidence::ActiveRuntime,
        path: path.to_string(),
        line: None,
        evidence: Some(format!("signature={}", signature.as_kind())),
        plain_english_explanation: "This skill file has a text-like extension but starts with a native executable header. A binary disguised as a skill file is a high-signal supply-chain integrity red flag.".to_string(),
        recommended_action: RecommendedAction {
            label: "Inspect this file by hand; restore the legitimate skill content or delete it".to_string(),
            command_hint: None,
        },
        fixability: Fixability::Manual,
        fix: None,
        owasp_asi: owasp_asi_for_kind("file-type-mismatch"),
    }
}
