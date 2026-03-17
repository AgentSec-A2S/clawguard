use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::{Finding, FindingCategory, Fixability, RecommendedAction, RuntimeConfidence, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkillSourceHint {
    LocalInstall,
    VcsRepository,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillArtifact {
    pub path: String,
    pub sha256: String,
    pub source_hint: Option<SkillSourceHint>,
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

    for file_path in files {
        let Ok(contents) = fs::read_to_string(&file_path) else {
            continue;
        };
        let resolved_path = resolved_path_string(&file_path);

        artifacts.push(SkillArtifact {
            path: resolved_path.clone(),
            sha256: sha256_hex(contents.as_bytes()),
            source_hint: detect_source_hint(dir, &file_path),
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
