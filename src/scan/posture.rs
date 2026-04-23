use serde::{Deserialize, Serialize};

use super::{Finding, Severity};

/// Posture score band labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PostureBand {
    Clean,
    Low,
    Moderate,
    Elevated,
    Critical,
}

impl std::fmt::Display for PostureBand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Clean => write!(f, "Clean"),
            Self::Low => write!(f, "Low"),
            Self::Moderate => write!(f, "Moderate"),
            Self::Elevated => write!(f, "Elevated"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

/// A single row in the posture breakdown table.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PostureContribution {
    pub kind: String,
    pub count: usize,
    pub weight: f64,
    pub subtotal: f64,
}

/// The full posture report returned by `compute_posture`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PostureReport {
    pub score: f64,
    pub band: PostureBand,
    pub breakdown: Vec<PostureContribution>,
    pub finding_count: usize,
}

/// Compute the permission posture score from a set of findings.
pub fn compute_posture(findings: &[Finding]) -> PostureReport {
    let mut kind_counts: std::collections::BTreeMap<String, (usize, f64)> =
        std::collections::BTreeMap::new();

    for finding in findings {
        let kind = extract_kind(&finding.id);
        let weight = weight_for_kind(&kind, finding.severity);
        kind_counts
            .entry(kind)
            .and_modify(|(count, _)| *count += 1)
            .or_insert((1, weight));
    }

    let mut breakdown: Vec<PostureContribution> = kind_counts
        .into_iter()
        .map(|(kind, (count, weight))| {
            let subtotal = weight * count as f64;
            PostureContribution {
                kind,
                count,
                weight,
                subtotal,
            }
        })
        .collect();

    // Sort by subtotal descending, then kind ascending for stability
    breakdown.sort_by(|a, b| {
        b.subtotal
            .partial_cmp(&a.subtotal)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.kind.cmp(&b.kind))
    });

    let score: f64 = breakdown.iter().map(|c| c.subtotal).sum();
    let band = band_for_score(score);

    PostureReport {
        score,
        band,
        breakdown,
        finding_count: findings.len(),
    }
}

/// Map score to band.
pub fn band_for_score(score: f64) -> PostureBand {
    if score <= 0.0 {
        PostureBand::Clean
    } else if score <= 10.0 {
        PostureBand::Low
    } else if score <= 25.0 {
        PostureBand::Moderate
    } else if score <= 50.0 {
        PostureBand::Elevated
    } else {
        PostureBand::Critical
    }
}

/// Extract the finding kind from a finding ID.
///
/// IDs follow patterns like `openclaw-config:exec-security-full:/path:scope`
/// or `mcp:launcher:/path`. The kind is always the second `:` segment.
pub fn extract_kind(finding_id: &str) -> String {
    finding_id
        .split(':')
        .nth(1)
        .unwrap_or("unknown")
        .to_string()
}

/// Per-kind weight table. Returns a specific weight if the kind is known,
/// otherwise falls back to a severity-based default.
fn weight_for_kind(kind: &str, severity: Severity) -> f64 {
    match kind {
        // Highest risk: full exec without guardrails
        "exec-security-full"
        | "acp-approve-all"
        | "dangerous-disable-device-auth"
        | "runtime-destructive-action" => 5.0,
        // High risk: approval/sandbox bypasses
        "exec-ask-off" | "sandbox-disabled" | "allowlist-catastrophic-command" => 4.0,
        // Significant risk: weakened boundaries
        "exec-host-node"
        | "auto-allow-skills"
        | "exec-approvals-missing"
        | "gateway-node-dangerous-command"
        | "hook-allows-request-session-key"
        | "hook-allows-unsafe-external-content"
        | "sandbox-dangerous-reserved-targets"
        | "sandbox-dangerous-external-sources"
        | "allowlist-dangerous-executable"
        | "shell_exec"
        | "hook-shell-exec"
        | "mcp-server-name-typosquat"
        | "mcp-command-changed"
        | "file-type-mismatch"
        | "runtime-lethal-trifecta-precondition"
        | "runtime-path-escape" => 3.0,
        // Moderate risk: exposure expansion
        "sandbox-host-fallback"
        | "open-dm-policy"
        | "tool-profile-escalation"
        | "hook-transform-external-module"
        | "exec-ask-fallback-weak"
        | "sandbox-bind-symlink"
        | "sandbox-bind-temp-dir"
        | "allowlist-interpreter"
        | "launcher"
        | "unpinned-package"
        | "broad-directory"
        | "mcp-no-lockfile"
        | "hook-multiple-handlers"
        | "runtime-rate-limit-exceeded"
        | "runtime-prompt-injection-shape" => 2.0,
        // Low risk: config drift / awareness
        "plugin-not-in-allowlist"
        | "plugin-in-denylist"
        | "network"
        | "install"
        | "skill-no-provenance" => 1.0,
        // Unknown kinds: fall back to severity
        _ => severity_weight(severity),
    }
}

fn severity_weight(severity: Severity) -> f64 {
    match severity {
        Severity::Critical => 5.0,
        Severity::High => 3.0,
        Severity::Medium => 2.0,
        Severity::Low => 1.0,
        Severity::Info => 0.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_finding(id: &str, severity: Severity) -> Finding {
        Finding {
            id: id.to_string(),
            detector_id: "test".to_string(),
            severity,
            category: super::super::FindingCategory::Config,
            runtime_confidence: super::super::RuntimeConfidence::ActiveRuntime,
            path: "/test".to_string(),
            line: None,
            evidence: None,
            plain_english_explanation: String::new(),
            recommended_action: super::super::RecommendedAction {
                label: String::new(),
                command_hint: None,
            },
            fixability: super::super::Fixability::Manual,
            fix: None,
            owasp_asi: None,
        }
    }

    #[test]
    fn clean_scan_produces_zero_score() {
        let report = compute_posture(&[]);
        assert_eq!(report.score, 0.0);
        assert_eq!(report.band, PostureBand::Clean);
        assert_eq!(report.finding_count, 0);
        assert!(report.breakdown.is_empty());
    }

    #[test]
    fn single_high_finding_scored_correctly() {
        let findings = vec![make_finding(
            "openclaw-config:exec-security-full:/path:defaults",
            Severity::High,
        )];
        let report = compute_posture(&findings);
        assert_eq!(report.score, 5.0);
        assert_eq!(report.band, PostureBand::Low);
        assert_eq!(report.breakdown.len(), 1);
        assert_eq!(report.breakdown[0].kind, "exec-security-full");
        assert_eq!(report.breakdown[0].weight, 5.0);
    }

    #[test]
    fn multiple_findings_summed() {
        let findings = vec![
            make_finding(
                "openclaw-config:exec-security-full:/path:defaults",
                Severity::High,
            ),
            make_finding(
                "openclaw-config:sandbox-disabled:/path:defaults",
                Severity::Medium,
            ),
            make_finding(
                "openclaw-config:sandbox-disabled:/path:agent",
                Severity::Medium,
            ),
            make_finding(
                "openclaw-config:open-dm-policy:/path:telegram",
                Severity::High,
            ),
        ];
        let report = compute_posture(&findings);
        // exec-security-full: 5×1=5, sandbox-disabled: 4×2=8, open-dm-policy: 2×1=2
        assert_eq!(report.score, 15.0);
        assert_eq!(report.band, PostureBand::Moderate);
        assert_eq!(report.finding_count, 4);
    }

    #[test]
    fn severity_fallback_for_unknown_kind() {
        let findings = vec![make_finding(
            "custom:unknown-future-kind:/path",
            Severity::Critical,
        )];
        let report = compute_posture(&findings);
        assert_eq!(report.score, 5.0); // Critical severity default
    }

    #[test]
    fn band_boundaries() {
        assert_eq!(band_for_score(0.0), PostureBand::Clean);
        assert_eq!(band_for_score(1.0), PostureBand::Low);
        assert_eq!(band_for_score(10.0), PostureBand::Low);
        assert_eq!(band_for_score(11.0), PostureBand::Moderate);
        assert_eq!(band_for_score(25.0), PostureBand::Moderate);
        assert_eq!(band_for_score(26.0), PostureBand::Elevated);
        assert_eq!(band_for_score(50.0), PostureBand::Elevated);
        assert_eq!(band_for_score(51.0), PostureBand::Critical);
    }

    #[test]
    fn extract_kind_from_standard_id() {
        assert_eq!(
            extract_kind("openclaw-config:exec-security-full:/path:scope"),
            "exec-security-full"
        );
        assert_eq!(extract_kind("mcp:launcher:/path"), "launcher");
        assert_eq!(extract_kind("skill:shell_exec:/path"), "shell_exec");
    }

    #[test]
    fn extract_kind_without_colon_returns_unknown() {
        assert_eq!(extract_kind("no-colon-id"), "unknown");
        assert_eq!(extract_kind("/some/path/leaked"), "unknown");
    }

    #[test]
    fn hook_shell_exec_uses_specific_weight() {
        let findings = vec![make_finding(
            "hooks:hook-shell-exec:/path:handler.ts",
            Severity::High,
        )];
        let report = compute_posture(&findings);
        assert_eq!(report.score, 3.0); // Specific weight, not severity default of 3.0
        assert_eq!(report.breakdown[0].kind, "hook-shell-exec");
    }

    // --- V1.3 Sprint 2 §3 — runtime finding kind weights ---

    #[test]
    fn runtime_destructive_action_weighted_critical() {
        let findings = vec![make_finding(
            "runtime:runtime-destructive-action:session-1:shell",
            Severity::Critical,
        )];
        let report = compute_posture(&findings);
        assert_eq!(report.score, 5.0);
        assert_eq!(report.breakdown[0].kind, "runtime-destructive-action");
    }

    #[test]
    fn runtime_lethal_trifecta_precondition_weighted_high() {
        let findings = vec![make_finding(
            "runtime:runtime-lethal-trifecta-precondition:session-1:fs-read",
            Severity::High,
        )];
        let report = compute_posture(&findings);
        assert_eq!(report.score, 3.0);
    }

    #[test]
    fn runtime_path_escape_weighted_high() {
        let findings = vec![make_finding(
            "runtime:runtime-path-escape:session-1:fs-write",
            Severity::High,
        )];
        let report = compute_posture(&findings);
        assert_eq!(report.score, 3.0);
    }

    #[test]
    fn runtime_rate_limit_exceeded_weighted_medium() {
        let findings = vec![make_finding(
            "runtime:runtime-rate-limit-exceeded:session-1:shell",
            Severity::Medium,
        )];
        let report = compute_posture(&findings);
        assert_eq!(report.score, 2.0);
    }

    #[test]
    fn runtime_prompt_injection_shape_weighted_medium() {
        let findings = vec![make_finding(
            "runtime:runtime-prompt-injection-shape:session-1:fetch",
            Severity::Medium,
        )];
        let report = compute_posture(&findings);
        assert_eq!(report.score, 2.0);
    }

    #[test]
    fn runtime_owasp_mappings_are_registered() {
        use crate::scan::finding::owasp_asi_for_kind;
        assert_eq!(
            owasp_asi_for_kind("runtime-destructive-action").as_deref(),
            Some("ASI02")
        );
        assert_eq!(
            owasp_asi_for_kind("runtime-path-escape").as_deref(),
            Some("ASI02")
        );
        assert_eq!(
            owasp_asi_for_kind("runtime-rate-limit-exceeded").as_deref(),
            Some("ASI02")
        );
        assert_eq!(
            owasp_asi_for_kind("runtime-lethal-trifecta-precondition").as_deref(),
            Some("ASI06")
        );
        assert_eq!(
            owasp_asi_for_kind("runtime-prompt-injection-shape").as_deref(),
            Some("ASI07")
        );
    }
}
