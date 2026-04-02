pub mod ingest;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditCategory {
    Config,
    Hook,
    Plugin,
    Tool,
    Skill,
}

impl AuditCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::Hook => "hook",
            Self::Plugin => "plugin",
            Self::Tool => "tool",
            Self::Skill => "skill",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "config" => Self::Config,
            "hook" => Self::Hook,
            "plugin" => Self::Plugin,
            "tool" => Self::Tool,
            "skill" => Self::Skill,
            _ => Self::Config,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditSource {
    Passive,
    Active,
}

impl AuditSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Passive => "passive",
            Self::Active => "active",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "passive" => Self::Passive,
            "active" => Self::Active,
            _ => Self::Passive,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: i64,
    pub recorded_at_unix_ms: u64,
    pub event_at_unix_ms: u64,
    pub category: AuditCategory,
    pub event_type: String,
    pub source: AuditSource,
    pub summary: String,
    pub payload_json: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

impl AuditEvent {
    pub fn new_passive(
        event_at_unix_ms: u64,
        category: AuditCategory,
        event_type: impl Into<String>,
        summary: impl Into<String>,
        payload_json: impl Into<String>,
    ) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        Self {
            id: 0,
            recorded_at_unix_ms: now,
            event_at_unix_ms,
            category,
            event_type: event_type.into(),
            source: AuditSource::Passive,
            summary: summary.into(),
            payload_json: payload_json.into(),
            session_key: None,
            agent_id: None,
            path: None,
        }
    }

    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }
}
