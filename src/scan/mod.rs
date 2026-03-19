pub mod cve;
pub mod finding;
pub mod mcp;
pub mod openclaw;
pub mod secrets;
pub mod severity;
pub mod skills;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanResult {
    findings: Vec<Finding>,
}

impl ScanResult {
    /// Flatten detector batches into a single ordered result set.
    ///
    /// Findings are sorted by severity (descending), then `detector_id`, then `path`.
    /// Duplicate findings are preserved; deduplication is detector-owned behavior.
    pub fn from_batches(batches: Vec<Vec<Finding>>) -> Self {
        let mut findings: Vec<_> = batches.into_iter().flatten().collect();
        findings.sort_by(|left, right| {
            right
                .severity
                .cmp(&left.severity)
                .then_with(|| left.detector_id.cmp(&right.detector_id))
                .then_with(|| left.path.cmp(&right.path))
        });

        Self { findings }
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
    // V0 is still effectively single-preset. If more presets are added later,
    // tighten this fallback instead of silently scanning a different runtime.
    let Some(runtime) = discovery
        .runtimes
        .iter()
        .find(|runtime| runtime.preset_id == config.preset)
        .or_else(|| discovery.runtimes.first())
    else {
        return ScanResult::from_batches(vec![]);
    };

    let preset = preset_by_id(&runtime.preset_id).or_else(|| preset_by_id(&config.preset));
    let excluded_dirs = preset
        .as_ref()
        .map(|preset| preset.excluded_dirs.as_slice())
        .unwrap_or(&[]);

    let mut batches = Vec::new();

    for target in &runtime.targets {
        match target.domain {
            ScanDomain::Config => batches.push(
                openclaw::scan_openclaw_state(&target.paths, config.max_file_size_bytes).findings,
            ),
            ScanDomain::Skills => {
                for path in &target.paths {
                    batches.push(
                        skills::scan_skill_dir(path, config.max_file_size_bytes, excluded_dirs)
                            .findings,
                    );
                }
            }
            ScanDomain::Mcp => batches
                .push(mcp::scan_mcp_configs(&target.paths, config.max_file_size_bytes).findings),
            ScanDomain::Env => batches.push(
                secrets::scan_secret_files(&target.paths, config.max_file_size_bytes).findings,
            ),
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

    ScanResult::from_batches(batches)
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
    }]])
}

fn package_manifest_candidates(runtime: &DetectedRuntime) -> Vec<PathBuf> {
    runtime
        .root
        .iter()
        .map(|root| root.join("package.json"))
        .collect()
}
