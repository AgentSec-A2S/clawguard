pub mod cve;
pub mod finding;
pub mod mcp;
pub mod openclaw;
pub mod severity;
pub mod skills;

use serde::{Deserialize, Serialize};

pub use finding::{
    Finding, FindingCategory, FindingFix, Fixability, RecommendedAction, RuntimeConfidence,
};
pub use severity::Severity;

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
