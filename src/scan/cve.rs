use std::fs;
use std::path::{Path, PathBuf};

use semver::{Version, VersionReq};
use serde::Deserialize;

use super::{Finding, FindingCategory, Fixability, RecommendedAction, RuntimeConfidence, Severity};

#[derive(Debug, Deserialize)]
struct AdvisoryFeed {
    #[serde(default)]
    advisories: Vec<AdvisoryEntry>,
}

#[derive(Debug, Deserialize)]
struct AdvisoryEntry {
    id: String,
    #[serde(default = "default_openclaw_package")]
    package: String,
    #[serde(alias = "affected_versions")]
    affected: String,
    severity: String,
    #[serde(default, alias = "title")]
    summary: String,
    #[serde(default)]
    recommendation: String,
    #[serde(default)]
    fixed_version: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PackageManifest {
    name: Option<String>,
    version: Option<String>,
}

#[derive(Debug, Clone)]
struct PackageEvidence {
    path: String,
    package: String,
    version: Version,
    version_text: String,
}

pub fn scan_openclaw_advisories(
    package_manifest_paths: &[PathBuf],
    advisory_feed_path: &Path,
    max_file_size_bytes: u64,
) -> Vec<Finding> {
    let Some(feed) = load_advisory_feed(advisory_feed_path, max_file_size_bytes) else {
        return vec![info_finding(
            advisory_feed_path,
            "advisory-feed-unavailable",
            "The local advisory feed could not be loaded, so OpenClaw CVE matching is incomplete.",
            "Restore the local advisory feed before trusting CVE results",
        )];
    };

    scan_with_feed(
        package_manifest_paths,
        &feed,
        advisory_feed_path,
        max_file_size_bytes,
    )
}

pub fn scan_openclaw_advisories_from_feed(
    package_manifest_paths: &[PathBuf],
    advisory_feed_json: &str,
    max_file_size_bytes: u64,
) -> Vec<Finding> {
    let feed: AdvisoryFeed =
        serde_json::from_str(advisory_feed_json).expect("bundled advisory feed should parse");

    scan_with_feed(
        package_manifest_paths,
        &feed,
        Path::new("advisories/openclaw.json"),
        max_file_size_bytes,
    )
}

fn scan_with_feed(
    package_manifest_paths: &[PathBuf],
    feed: &AdvisoryFeed,
    fallback_path: &Path,
    max_file_size_bytes: u64,
) -> Vec<Finding> {
    let packages = load_package_evidence(package_manifest_paths, max_file_size_bytes);
    if packages.is_empty() {
        let missing_version_path = package_manifest_paths
            .first()
            .map(PathBuf::as_path)
            .unwrap_or(fallback_path);
        return vec![info_finding(
            missing_version_path,
            "package-version-unavailable",
            "No readable OpenClaw package manifest with a parseable version was found, so advisory matching cannot be trusted.",
            "Provide OpenClaw version evidence before trusting CVE results",
        )];
    }

    let mut findings = Vec::new();

    for package in packages {
        for advisory in &feed.advisories {
            if advisory.package != package.package {
                continue;
            }

            let Ok(requirement) = VersionReq::parse(&advisory.affected) else {
                continue;
            };

            if !requirement.matches(&package.version) {
                continue;
            }

            findings.push(build_advisory_finding(&package, advisory));
        }
    }

    findings.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then_with(|| left.path.cmp(&right.path))
            .then_with(|| left.id.cmp(&right.id))
    });

    findings
}

fn load_advisory_feed(path: &Path, max_file_size_bytes: u64) -> Option<AdvisoryFeed> {
    let metadata = fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > max_file_size_bytes {
        return None;
    }

    let contents = fs::read_to_string(path).ok()?;
    serde_json::from_str(&contents).ok()
}

fn load_package_evidence(paths: &[PathBuf], max_file_size_bytes: u64) -> Vec<PackageEvidence> {
    let mut sorted_paths = paths.to_vec();
    sorted_paths.sort();

    let mut evidence = Vec::new();

    for path in sorted_paths {
        for candidate in expand_manifest_candidates(&path) {
            let Some(package_evidence) = load_package_manifest(&candidate, max_file_size_bytes)
            else {
                continue;
            };

            evidence.push(package_evidence);
            break;
        }
    }

    evidence
}

fn expand_manifest_candidates(path: &Path) -> Vec<PathBuf> {
    let mut candidates = vec![path.to_path_buf()];

    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return candidates;
    };
    if file_name != "package.json" {
        return candidates;
    }

    let Some(root) = path.parent() else {
        return candidates;
    };
    let fallback = root.join("packages").join("core").join("package.json");
    if fallback != path {
        candidates.push(fallback);
    }

    candidates
}

fn load_package_manifest(path: &Path, max_file_size_bytes: u64) -> Option<PackageEvidence> {
    let metadata = fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > max_file_size_bytes {
        return None;
    }

    let contents = fs::read_to_string(path).ok()?;
    let manifest = serde_json::from_str::<PackageManifest>(&contents).ok()?;

    let package = manifest.name.map(|value| value.trim().to_string())?;
    let version_text = manifest.version.map(|value| value.trim().to_string())?;
    let version = Version::parse(&version_text).ok()?;

    Some(PackageEvidence {
        path: resolved_path_string(path),
        package,
        version,
        version_text,
    })
}

fn build_advisory_finding(package: &PackageEvidence, advisory: &AdvisoryEntry) -> Finding {
    Finding {
        id: format!("cve:{}:{}", advisory.id, package.path),
        detector_id: "cve".to_string(),
        severity: severity_from_advisory(&advisory.severity),
        category: FindingCategory::Advisory,
        runtime_confidence: RuntimeConfidence::ActiveRuntime,
        path: package.path.clone(),
        line: None,
        evidence: Some(format!("{}@{}", package.package, package.version_text)),
        plain_english_explanation: format!(
            "{} matches advisory {} ({})",
            package.package,
            advisory.id,
            advisory_summary(advisory)
        ),
        recommended_action: RecommendedAction {
            label: "Upgrade OpenClaw to a non-vulnerable version".to_string(),
            command_hint: Some(advisory_recommendation(advisory)),
        },
        fixability: Fixability::Manual,
        fix: None,
        owasp_asi: None,
    }
}

fn info_finding(path: &Path, kind: &str, explanation: &str, action_label: &str) -> Finding {
    Finding {
        id: format!("cve:{kind}:{}", resolved_path_string(path)),
        detector_id: "cve".to_string(),
        severity: Severity::Info,
        category: FindingCategory::Advisory,
        runtime_confidence: RuntimeConfidence::ActiveRuntime,
        path: resolved_path_string(path),
        line: None,
        evidence: None,
        plain_english_explanation: explanation.to_string(),
        recommended_action: RecommendedAction {
            label: action_label.to_string(),
            command_hint: None,
        },
        fixability: Fixability::AdvisoryOnly,
        fix: None,
        owasp_asi: None,
    }
}

fn severity_from_advisory(value: &str) -> Severity {
    match value.trim().to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" | "moderate" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

fn default_openclaw_package() -> String {
    "openclaw".to_string()
}

fn advisory_summary(advisory: &AdvisoryEntry) -> &str {
    if advisory.summary.trim().is_empty() {
        "OpenClaw advisory"
    } else {
        advisory.summary.trim()
    }
}

fn advisory_recommendation(advisory: &AdvisoryEntry) -> String {
    if !advisory.recommendation.trim().is_empty() {
        return advisory.recommendation.trim().to_string();
    }

    if let Some(fixed_version) = advisory.fixed_version.as_deref() {
        let fixed_version = fixed_version.trim();
        if !fixed_version.is_empty() {
            return format!("Upgrade to {fixed_version} or later");
        }
    }

    "Review the advisory and upgrade OpenClaw".to_string()
}

fn resolved_path_string(path: &Path) -> String {
    fs::canonicalize(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .into_owned()
}
