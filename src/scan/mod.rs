pub mod baseline;
pub mod bootstrap;
pub mod cve;
pub mod finding;
pub mod hooks;
pub mod mcp;
pub mod openclaw;
pub mod secrets;
pub mod severity;
pub mod skills;

use std::collections::{btree_map::Entry, BTreeMap};
use std::path::{Path, PathBuf};

use crate::config::presets::preset_by_id;
use crate::config::schema::{AppConfig, ScanDomain};
use crate::discovery::{DetectedRuntime, DiscoveryReport};

use serde::{Deserialize, Serialize};

pub use finding::{
    Finding, FindingCategory, FindingFix, Fixability, RecommendedAction, RuntimeConfidence,
};
pub use severity::Severity;

const BUILTIN_OPENCLAW_ADVISORIES: &str = include_str!("../../advisories/openclaw.json");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanSummary {
    pub total_findings: usize,
    pub highest_severity: Option<Severity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanReport {
    pub summary: ScanSummary,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScanMeta {
    pub runtime_label: String,
    pub runtime_root: Option<String>,
    pub strictness: String,
    pub config_file_count: usize,
    pub skill_dir_count: usize,
    pub mcp_file_count: usize,
    pub env_file_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanResult {
    findings: Vec<Finding>,
    pub meta: ScanMeta,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineArtifact {
    pub path: String,
    pub sha256: String,
    pub source_label: String,
    pub category: FindingCategory,
    pub git_remote_url: Option<String>,
    pub git_head_sha: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanEvidence {
    pub result: ScanResult,
    pub artifacts: Vec<BaselineArtifact>,
}

impl ScanResult {
    /// Flatten detector batches into a single ordered result set.
    ///
    /// Findings are sorted by severity (descending), then `detector_id`, then `path`.
    /// Duplicate findings are preserved; deduplication is detector-owned behavior.
    pub fn from_batches(batches: Vec<Vec<Finding>>) -> Self {
        Self::from_batches_with_meta(batches, ScanMeta::default())
    }

    pub fn from_batches_with_meta(batches: Vec<Vec<Finding>>, meta: ScanMeta) -> Self {
        let mut findings: Vec<_> = batches.into_iter().flatten().collect();
        findings.sort_by(|left, right| {
            right
                .severity
                .cmp(&left.severity)
                .then_with(|| left.detector_id.cmp(&right.detector_id))
                .then_with(|| left.path.cmp(&right.path))
        });

        Self { findings, meta }
    }

    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    pub fn finding_count(&self) -> usize {
        self.findings.len()
    }

    pub fn highest_severity(&self) -> Option<Severity> {
        self.findings.first().map(|finding| finding.severity)
    }

    pub fn summary(&self) -> ScanSummary {
        ScanSummary {
            total_findings: self.finding_count(),
            highest_severity: self.highest_severity(),
        }
    }

    pub fn report(&self) -> ScanReport {
        ScanReport {
            summary: self.summary(),
            findings: self.findings.clone(),
        }
    }

    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(&self.report())
    }

    pub fn to_json_pretty(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(&self.report())
    }
}

pub fn run_scan(config: &AppConfig, discovery: &DiscoveryReport) -> ScanResult {
    collect_scan_evidence(config, discovery).result
}

pub fn collect_scan_evidence(config: &AppConfig, discovery: &DiscoveryReport) -> ScanEvidence {
    // V0 is still effectively single-preset. If more presets are added later,
    // tighten this fallback instead of silently scanning a different runtime.
    let Some(runtime) = discovery
        .runtimes
        .iter()
        .find(|runtime| runtime.preset_id == config.preset)
        .or_else(|| discovery.runtimes.first())
    else {
        return ScanEvidence {
            result: ScanResult::from_batches(vec![]),
            artifacts: Vec::new(),
        };
    };

    let preset = preset_by_id(&runtime.preset_id).or_else(|| preset_by_id(&config.preset));
    let excluded_dirs = preset
        .as_ref()
        .map(|preset| preset.excluded_dirs.as_slice())
        .unwrap_or(&[]);

    let mut batches = Vec::new();
    let mut artifacts_by_path = BTreeMap::new();
    let mut meta = ScanMeta {
        runtime_label: preset
            .as_ref()
            .map_or_else(String::new, |p| p.label.clone()),
        runtime_root: runtime
            .root
            .as_ref()
            .map(|p| p.to_string_lossy().to_string()),
        strictness: format!("{:?}", config.strictness),
        ..ScanMeta::default()
    };

    for target in &runtime.targets {
        match target.domain {
            ScanDomain::Config => {
                meta.config_file_count += target.paths.len();
                let output =
                    openclaw::scan_openclaw_state(&target.paths, config.max_file_size_bytes);
                batches.push(output.findings);
                for artifact in output.artifacts {
                    insert_artifact(
                        &mut artifacts_by_path,
                        BaselineArtifact {
                            path: artifact.path,
                            sha256: artifact.sha256,
                            source_label: "config".to_string(),
                            category: FindingCategory::Config,
                            git_remote_url: None,
                            git_head_sha: None,
                        },
                    );
                }
            }
            ScanDomain::Skills => {
                meta.skill_dir_count += target.paths.len();
                for path in &target.paths {
                    let output =
                        skills::scan_skill_dir(path, config.max_file_size_bytes, excluded_dirs);
                    batches.push(output.findings);
                    for artifact in output.artifacts {
                        let (git_remote_url, git_head_sha) = match &artifact.git_provenance {
                            Some(prov) => (prov.remote_url.clone(), prov.head_sha.clone()),
                            None => (None, None),
                        };
                        insert_artifact(
                            &mut artifacts_by_path,
                            BaselineArtifact {
                                path: artifact.path,
                                sha256: artifact.sha256,
                                source_label: "skills".to_string(),
                                category: FindingCategory::Skills,
                                git_remote_url,
                                git_head_sha,
                            },
                        );
                    }
                }
            }
            ScanDomain::Mcp => {
                meta.mcp_file_count += target.paths.len();
                let output = mcp::scan_mcp_configs(&target.paths, config.max_file_size_bytes);
                batches.push(output.findings);
                for artifact in output.artifacts {
                    insert_artifact(
                        &mut artifacts_by_path,
                        BaselineArtifact {
                            path: artifact.path,
                            sha256: artifact.sha256,
                            source_label: "mcp".to_string(),
                            category: FindingCategory::Mcp,
                            git_remote_url: None,
                            git_head_sha: None,
                        },
                    );
                }
            }
            ScanDomain::Env => {
                meta.env_file_count += target.paths.len();
                let output = secrets::scan_secret_files(&target.paths, config.max_file_size_bytes);
                batches.push(output.findings);
                for artifact in output.artifacts {
                    insert_artifact(
                        &mut artifacts_by_path,
                        BaselineArtifact {
                            path: artifact.path,
                            sha256: artifact.sha256,
                            source_label: "env".to_string(),
                            category: FindingCategory::Secrets,
                            git_remote_url: None,
                            git_head_sha: None,
                        },
                    );
                }
            }
            ScanDomain::Hooks => {
                let output = hooks::scan_hooks_dirs(&target.paths, config.max_file_size_bytes);
                batches.push(output.findings);
                for artifact in output.artifacts {
                    insert_artifact(
                        &mut artifacts_by_path,
                        BaselineArtifact {
                            path: artifact.path,
                            sha256: artifact.sha256,
                            source_label: "hooks".to_string(),
                            category: FindingCategory::Config,
                            git_remote_url: None,
                            git_head_sha: None,
                        },
                    );
                }
            }
            ScanDomain::Bootstrap => {
                let output =
                    bootstrap::scan_bootstrap_dirs(&target.paths, config.max_file_size_bytes);
                batches.push(output.findings);
                for artifact in output.artifacts {
                    insert_artifact(
                        &mut artifacts_by_path,
                        BaselineArtifact {
                            path: artifact.path,
                            sha256: artifact.sha256,
                            source_label: "bootstrap".to_string(),
                            category: FindingCategory::Config,
                            git_remote_url: None,
                            git_head_sha: None,
                        },
                    );
                }
            }
        }
    }

    let manifest_candidates = package_manifest_candidates(runtime);
    if manifest_candidates.iter().any(|path| path.is_file()) {
        batches.push(cve::scan_openclaw_advisories_from_feed(
            &manifest_candidates,
            BUILTIN_OPENCLAW_ADVISORIES,
            config.max_file_size_bytes,
        ));
    }

    ScanEvidence {
        result: ScanResult::from_batches_with_meta(batches, meta),
        artifacts: artifacts_by_path.into_values().collect(),
    }
}

fn insert_artifact(
    artifacts_by_path: &mut BTreeMap<String, BaselineArtifact>,
    artifact: BaselineArtifact,
) {
    match artifacts_by_path.entry(artifact.path.clone()) {
        Entry::Vacant(entry) => {
            entry.insert(artifact);
        }
        Entry::Occupied(existing) => {
            // Baselines are path-keyed. If multiple detector domains observe the same file,
            // keep the first canonical owner and assert the file hash agrees.
            debug_assert_eq!(
                existing.get().sha256,
                artifact.sha256,
                "shared artifact path {} produced conflicting hashes across detector domains",
                artifact.path
            );
        }
    }
}

pub fn runtime_not_detected_result(expected_config_path: &Path) -> ScanResult {
    ScanResult::from_batches(vec![vec![Finding {
        id: format!(
            "discovery:runtime-not-detected:{}",
            expected_config_path.display()
        ),
        detector_id: "discovery".to_string(),
        severity: Severity::Info,
        category: FindingCategory::Config,
        runtime_confidence: RuntimeConfidence::TemplateExample,
        path: expected_config_path.display().to_string(),
        line: None,
        evidence: None,
        plain_english_explanation: "ClawGuard could not find a supported runtime in the expected local state locations, so no live scan evidence was collected.".to_string(),
        recommended_action: RecommendedAction {
            label: "Install OpenClaw or rerun `clawguard scan` after a supported runtime exists"
                .to_string(),
            command_hint: None,
        },
        fixability: Fixability::AdvisoryOnly,
        fix: None,
        owasp_asi: None,
    }]])
}

fn package_manifest_candidates(runtime: &DetectedRuntime) -> Vec<PathBuf> {
    runtime
        .root
        .iter()
        .map(|root| root.join("package.json"))
        .collect()
}
