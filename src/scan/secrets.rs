use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::{Finding, FindingCategory, Fixability, RecommendedAction, RuntimeConfidence, Severity};

const PRIVATE_KEY_HEADERS: &[&str] = &[
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretArtifact {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SecretsScanOutput {
    pub findings: Vec<Finding>,
    pub artifacts: Vec<SecretArtifact>,
}

pub fn scan_secret_files(paths: &[PathBuf], max_file_size_bytes: u64) -> SecretsScanOutput {
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
        artifacts.push(SecretArtifact {
            path: resolved_path.clone(),
            sha256: sha256_hex(contents.as_bytes()),
        });

        findings.extend(findings_for_contents(&contents, &resolved_path));
    }

    findings.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then_with(|| left.path.cmp(&right.path))
            .then_with(|| left.id.cmp(&right.id))
    });

    SecretsScanOutput {
        findings,
        artifacts,
    }
}

fn findings_for_contents(contents: &str, resolved_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (index, line) in contents.lines().enumerate() {
        let line_number = index + 1;
        let trimmed = line.trim();

        if trimmed.is_empty() {
            continue;
        }

        if let Some(header) = private_key_header(trimmed) {
            findings.push(build_finding(
                resolved_path,
                "private-key",
                Severity::Critical,
                Some(header.to_string()),
                line_number,
                "This file contains private key material, which is a direct credential exposure risk.",
            ));
            continue;
        }

        let Some((key, value)) = parse_assignment(trimmed) else {
            continue;
        };

        if !should_flag_literal_secret(&key, &value) {
            continue;
        }

        findings.push(build_finding(
            resolved_path,
            &normalize_key(&key),
            Severity::High,
            Some(format!("{key}={}", redacted_value(&value))),
            line_number,
            "This file contains a literal secret value instead of a safer reference or external secret source.",
        ));
    }

    findings
}

fn private_key_header(line: &str) -> Option<&'static str> {
    PRIVATE_KEY_HEADERS
        .iter()
        .copied()
        .find(|header| *header == line)
}

fn parse_assignment(line: &str) -> Option<(String, String)> {
    if line.starts_with('#') || line.starts_with("//") {
        return None;
    }

    if let Some((raw_key, raw_value)) = line.split_once('=') {
        let key = clean_key(raw_key);
        let value = clean_value(raw_value);
        if key.is_empty() || value.is_empty() {
            return None;
        }
        return Some((key, value));
    }

    if let Some((raw_key, raw_value)) = line.split_once(':') {
        let key = clean_key(raw_key);
        let value = clean_value(raw_value);
        if key.is_empty() || value.is_empty() {
            return None;
        }
        return Some((key, value));
    }

    None
}

fn clean_key(raw: &str) -> String {
    raw.trim()
        .trim_matches(',')
        .trim_matches('{')
        .trim_matches('}')
        .trim_matches('"')
        .trim_matches('\'')
        .to_string()
}

fn clean_value(raw: &str) -> String {
    raw.trim()
        .trim_matches(',')
        .trim_matches('{')
        .trim_matches('}')
        .trim_matches('"')
        .trim_matches('\'')
        .to_string()
}

fn should_flag_literal_secret(key: &str, value: &str) -> bool {
    let normalized_key = normalize_key(key);
    if normalized_key.is_empty() || normalized_key.ends_with("ref") {
        return false;
    }

    if is_safe_reference(value) {
        return false;
    }

    is_secret_like_key(&normalized_key) && looks_like_literal_secret(value)
}

fn normalize_key(key: &str) -> String {
    key.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_lowercase())
        .collect()
}

fn is_safe_reference(value: &str) -> bool {
    let lowered = value.trim().to_ascii_lowercase();
    lowered.starts_with("env:")
        || lowered.starts_with("file:")
        || lowered.starts_with("secretref-env:")
        || lowered.starts_with("secretref-managed")
}

fn is_secret_like_key(key: &str) -> bool {
    [
        "apikey",
        "token",
        "secret",
        "password",
        "accesskey",
        "privatekey",
    ]
    .iter()
    .any(|needle| key.contains(needle))
}

fn looks_like_literal_secret(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() < 10 {
        return false;
    }

    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return false;
    }

    if trimmed.starts_with("sk-") || trimmed.starts_with("ghp_") || trimmed.starts_with("AKIA") {
        return true;
    }

    if trimmed.contains(' ') {
        return false;
    }

    let lowered = trimmed.to_ascii_lowercase();
    if ["changeme", "example", "placeholder", "demo", "default"]
        .iter()
        .any(|needle| lowered.contains(needle))
    {
        return false;
    }

    trimmed.len() >= 16
}

fn redacted_value(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.starts_with("sk-") {
        return "sk-...redacted".to_string();
    }
    if trimmed.starts_with("ghp_") {
        return "ghp_...redacted".to_string();
    }
    if trimmed.starts_with("AKIA") {
        return "AKIA...redacted".to_string();
    }
    "***redacted".to_string()
}

fn build_finding(
    path: &str,
    kind: &str,
    severity: Severity,
    evidence: Option<String>,
    line_number: usize,
    explanation: &str,
) -> Finding {
    Finding {
        id: format!("secrets:{kind}:{path}:{line_number}"),
        detector_id: "secrets".to_string(),
        severity,
        category: FindingCategory::Secrets,
        runtime_confidence: RuntimeConfidence::ActiveRuntime,
        path: path.to_string(),
        line: Some(line_number),
        evidence,
        plain_english_explanation: explanation.to_string(),
        recommended_action: RecommendedAction {
            label: "Rotate and remove the exposed secret from local state".to_string(),
            command_hint: None,
        },
        fixability: Fixability::Manual,
        fix: None,
        owasp_asi: Some("ASI09".into()), // All secrets findings map to ASI09
    }
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
