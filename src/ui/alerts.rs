use crate::scan::Severity;
use crate::state::model::AlertStatus;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertListItem {
    pub alert_id: String,
    pub status: AlertStatus,
    pub severity: Severity,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertsView {
    pub alerts: Vec<AlertListItem>,
    pub command_hints: Vec<String>,
}

impl AlertsView {
    pub fn render(&self) -> String {
        let mut lines = vec!["Recent alerts".to_string(), String::new()];

        if self.alerts.is_empty() {
            lines.push("No persisted alerts yet.".to_string());
        } else {
            for alert in &self.alerts {
                lines.push(format!(
                    "- [{} / {}] {}",
                    status_label(alert.status),
                    severity_badge(alert.severity),
                    alert.alert_id
                ));
                lines.push(format!("  {}", alert.path));
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

fn status_label(status: AlertStatus) -> &'static str {
    match status {
        AlertStatus::Open => "open",
        AlertStatus::Acknowledged => "acknowledged",
        AlertStatus::Resolved => "resolved",
    }
}
