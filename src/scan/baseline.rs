use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use crate::scan::{
    Finding, FindingCategory, Fixability, RecommendedAction, RuntimeConfidence, Severity,
};
use crate::state::model::{BaselineRecord, RestorePayloadRecord};

use super::BaselineArtifact;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreTargetKind {
    OpenClawConfig,
    ExecApprovals,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BaselineDriftKind {
    Added,
    Modified,
    Removed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineDrift {
    pub path: String,
    pub source_label: String,
    pub kind: BaselineDriftKind,
    pub expected_sha256: Option<String>,
    pub actual_sha256: Option<String>,
}

pub fn restore_target_kind_for_path(path: &str, source_label: &str) -> Option<RestoreTargetKind> {
    if source_label != "config" {
        return None;
    }

    match Path::new(path).file_name().and_then(|name| name.to_str()) {
        Some("openclaw.json") => Some(RestoreTargetKind::OpenClawConfig),
        Some("exec-approvals.json") => Some(RestoreTargetKind::ExecApprovals),
        _ => None,
    }
}

pub fn collect_restore_payload_candidates(
    recorded_at_unix_ms: u64,
    artifacts: &[BaselineArtifact],
) -> Vec<RestorePayloadRecord> {
    artifacts
        .iter()
        .filter(|artifact| {
            restore_target_kind_for_path(&artifact.path, &artifact.source_label).is_some()
        })
        .filter_map(|artifact| {
            let bytes = fs::read(&artifact.path).ok()?;
            let content = String::from_utf8(bytes).ok()?;

            Some(RestorePayloadRecord {
                path: artifact.path.clone(),
                sha256: artifact.sha256.clone(),
                captured_at_unix_ms: recorded_at_unix_ms,
                source_label: artifact.source_label.clone(),
                content,
            })
        })
        .collect()
}

pub fn diff_artifacts_against_baselines(
    baselines: &[BaselineRecord],
    artifacts: &[BaselineArtifact],
) -> Vec<BaselineDrift> {
    let baseline_by_path: BTreeMap<_, _> = baselines
        .iter()
        .map(|baseline| (baseline.path.as_str(), baseline))
        .collect();
    let artifact_by_path: BTreeMap<_, _> = artifacts
        .iter()
        .map(|artifact| (artifact.path.as_str(), artifact))
        .collect();

    debug_assert_eq!(
        baseline_by_path.len(),
        baselines.len(),
        "baseline diff expects unique baseline paths"
    );
    debug_assert_eq!(
        artifact_by_path.len(),
        artifacts.len(),
        "baseline diff expects unique artifact paths"
    );

    let mut drifts = Vec::new();

    for (path, baseline) in &baseline_by_path {
        match artifact_by_path.get(path) {
            Some(artifact) if artifact.sha256 != baseline.sha256 => {
                drifts.push(BaselineDrift {
                    path: baseline.path.clone(),
                    source_label: artifact.source_label.clone(),
                    kind: BaselineDriftKind::Modified,
                    expected_sha256: Some(baseline.sha256.clone()),
                    actual_sha256: Some(artifact.sha256.clone()),
                });
            }
            Some(_) => {}
            None => drifts.push(BaselineDrift {
                path: baseline.path.clone(),
                source_label: baseline.source_label.clone(),
                kind: BaselineDriftKind::Removed,
                expected_sha256: Some(baseline.sha256.clone()),
                actual_sha256: None,
            }),
        }
    }

    for (path, artifact) in &artifact_by_path {
        if baseline_by_path.contains_key(path) {
            continue;
        }

        drifts.push(BaselineDrift {
            path: artifact.path.clone(),
            source_label: artifact.source_label.clone(),
            kind: BaselineDriftKind::Added,
            expected_sha256: None,
            actual_sha256: Some(artifact.sha256.clone()),
        });
    }

    drifts.sort_by(|left, right| left.path.cmp(&right.path).then(left.kind.cmp(&right.kind)));
    drifts
}

pub fn drifts_to_findings(drifts: &[BaselineDrift]) -> Vec<Finding> {
    drifts.iter().map(finding_for_drift).collect()
}

fn finding_for_drift(drift: &BaselineDrift) -> Finding {
    Finding {
        id: format!("baseline:{}:{}", drift_kind_slug(drift.kind), drift.path),
        detector_id: "baseline".to_string(),
        severity: severity_for_drift(drift.kind),
        category: FindingCategory::Drift,
        runtime_confidence: RuntimeConfidence::ActiveRuntime,
        path: drift.path.clone(),
        line: None,
        evidence: Some(evidence_for_drift(drift)),
        plain_english_explanation: explanation_for_drift(drift.kind).to_string(),
        recommended_action: RecommendedAction {
            label: action_label_for_drift(drift.kind).to_string(),
            command_hint: None,
        },
        fixability: Fixability::Manual,
        fix: None,
        owasp_asi: None,
    }
}

fn drift_kind_slug(kind: BaselineDriftKind) -> &'static str {
    match kind {
        BaselineDriftKind::Added => "added",
        BaselineDriftKind::Modified => "modified",
        BaselineDriftKind::Removed => "removed",
    }
}

fn severity_for_drift(kind: BaselineDriftKind) -> Severity {
    match kind {
        BaselineDriftKind::Added => Severity::Medium,
        BaselineDriftKind::Modified | BaselineDriftKind::Removed => Severity::High,
    }
}

fn explanation_for_drift(kind: BaselineDriftKind) -> &'static str {
    match kind {
        BaselineDriftKind::Added => {
            "This file is present in the current runtime state but not in the approved baseline."
        }
        BaselineDriftKind::Modified => {
            "This file differs from the approved baseline and should be reviewed before trusting this runtime again."
        }
        BaselineDriftKind::Removed => {
            "This file is missing from the current runtime state even though it exists in the approved baseline."
        }
    }
}

fn action_label_for_drift(kind: BaselineDriftKind) -> &'static str {
    match kind {
        BaselineDriftKind::Added => "Review the new file and approve it only if it is expected",
        BaselineDriftKind::Modified => {
            "Review the changed file against the approved baseline before trusting it again"
        }
        BaselineDriftKind::Removed => {
            "Restore or intentionally re-approve the missing file before trusting this runtime"
        }
    }
}

fn evidence_for_drift(drift: &BaselineDrift) -> String {
    match (&drift.expected_sha256, &drift.actual_sha256) {
        (Some(expected), Some(actual)) => format!("approved={expected}, current={actual}"),
        (Some(expected), None) => format!("approved={expected}, current=missing"),
        (None, Some(actual)) => format!("approved=none, current={actual}"),
        (None, None) => "approved=none, current=missing".to_string(),
    }
}
