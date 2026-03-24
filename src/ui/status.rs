use crate::scan::Severity;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusAlertItem {
    pub alert_id: String,
    pub severity: Severity,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusSnapshotSummary {
    pub total_findings: usize,
    pub highest_severity: Option<Severity>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusView {
    pub open_alerts: Vec<StatusAlertItem>,
    pub acknowledged_alert_count: usize,
    pub latest_snapshot_summary: Option<StatusSnapshotSummary>,
    pub baseline_count: usize,
    pub trust_targets: Vec<String>,
    pub command_hints: Vec<String>,
}

impl StatusView {
    pub fn render(&self) -> String {
        let mut lines = vec!["ClawGuard Status".to_string(), String::new()];

        if self.open_alerts.is_empty() {
            lines.push("No open alerts right now.".to_string());
        } else {
            lines.push(format!("Open alerts ({})", self.open_alerts.len()));
            for alert in &self.open_alerts {
                lines.push(format!(
                    "- [{}] {}",
                    severity_badge(alert.severity),
                    alert.alert_id
                ));
                lines.push(format!("  {}", alert.path));
            }
        }

        lines.push(String::new());
        lines.push(format!(
            "Acknowledged alerts in history: {}",
            self.acknowledged_alert_count
        ));

        lines.push(String::new());
        lines.push("Latest snapshot".to_string());
        match &self.latest_snapshot_summary {
            Some(summary) => {
                lines.push(format!("- Findings: {}", summary.total_findings));
                lines.push(format!(
                    "- Highest severity: {}",
                    summary
                        .highest_severity
                        .map(severity_title_case)
                        .unwrap_or("None")
                ));
            }
            None => lines.push(
                "- No snapshot recorded yet. Run `clawguard scan` or `clawguard watch`."
                    .to_string(),
            ),
        }

        lines.push(String::new());
        lines.push("Baseline posture".to_string());
        lines.push(format!(
            "- Approved baseline artifacts: {}",
            self.baseline_count
        ));
        if self.trust_targets.is_empty() {
            lines.push("- Trust targets: none approved yet".to_string());
        } else {
            lines.push("- Trust targets:".to_string());
            for target in &self.trust_targets {
                lines.push(format!("  clawguard trust {target}"));
            }
        }

        lines.push(String::new());
        lines.push("Next commands".to_string());
        for hint in &self.command_hints {
            lines.push(format!("- {hint}"));
        }

        lines.join("\n")
    }
}

fn severity_badge(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "INFO",
        Severity::Low => "LOW",
        Severity::Medium => "MEDIUM",
        Severity::High => "HIGH",
        Severity::Critical => "CRITICAL",
    }
}

fn severity_title_case(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "Info",
        Severity::Low => "Low",
        Severity::Medium => "Medium",
        Severity::High => "High",
        Severity::Critical => "Critical",
    }
}
