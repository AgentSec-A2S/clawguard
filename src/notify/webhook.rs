use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::scan::Severity;
use crate::state::model::AlertRecord;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebhookRecommendedAction {
    pub label: String,
    pub command_hint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebhookPayload {
    pub product: String,
    pub alert_id: String,
    pub finding_id: String,
    pub created_at_unix_ms: u64,
    pub detector_id: String,
    pub severity: String,
    pub path: String,
    pub explanation: String,
    pub recommended_action: WebhookRecommendedAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebhookDigestPayload {
    pub product: String,
    pub cursor_key: String,
    pub delivered_at_unix_ms: u64,
    pub alert_count: usize,
    pub highest_severity: String,
    pub affected_paths: Vec<String>,
}

pub trait WebhookTransport {
    fn post_json(&self, url: &str, payload: &WebhookPayload) -> Result<(), String>;
    fn post_digest_json(&self, url: &str, payload: &WebhookDigestPayload) -> Result<(), String>;
}

pub struct UreqWebhookTransport {
    agent: ureq::Agent,
}

impl Default for UreqWebhookTransport {
    fn default() -> Self {
        Self {
            agent: ureq::AgentBuilder::new()
                .timeout_connect(Duration::from_secs(5))
                .timeout_read(Duration::from_secs(5))
                .build(),
        }
    }
}

impl WebhookTransport for UreqWebhookTransport {
    fn post_json(&self, url: &str, payload: &WebhookPayload) -> Result<(), String> {
        send_payload(&self.agent, url, payload, "alert")
    }

    fn post_digest_json(&self, url: &str, payload: &WebhookDigestPayload) -> Result<(), String> {
        send_payload(&self.agent, url, payload, "digest")
    }
}

pub fn build_webhook_payload(alert: &AlertRecord) -> WebhookPayload {
    WebhookPayload {
        product: "clawguard".to_string(),
        alert_id: alert.alert_id.clone(),
        finding_id: alert.finding_id.clone(),
        created_at_unix_ms: alert.created_at_unix_ms,
        detector_id: alert.finding.detector_id.clone(),
        severity: severity_slug(alert.finding.severity).to_string(),
        path: alert.finding.path.clone(),
        explanation: alert.finding.plain_english_explanation.clone(),
        recommended_action: WebhookRecommendedAction {
            label: alert.finding.recommended_action.label.clone(),
            command_hint: alert.finding.recommended_action.command_hint.clone(),
        },
    }
}

fn severity_slug(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn send_payload<T: Serialize>(
    agent: &ureq::Agent,
    url: &str,
    payload: &T,
    payload_kind: &str,
) -> Result<(), String> {
    let body = serde_json::to_string(payload)
        .map_err(|error| format!("failed to serialize webhook {payload_kind} payload: {error}"))?;

    agent
        .post(url)
        .set("content-type", "application/json")
        .send_string(&body)
        .map(|_| ())
        .map_err(|error| format!("webhook {payload_kind} delivery failed: {error}"))
}
