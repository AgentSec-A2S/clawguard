use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::scan::{Finding, ScanSummary};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateWarningKind {
    DatabaseCorruptRecreated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateWarning {
    pub kind: StateWarningKind,
    pub message: String,
    pub path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanSnapshot {
    pub recorded_at_unix_ms: u64,
    pub summary: ScanSummary,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineRecord {
    pub path: String,
    pub sha256: String,
    pub approved_at_unix_ms: u64,
    pub source_label: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestorePayloadRecord {
    pub path: String,
    pub sha256: String,
    pub captured_at_unix_ms: u64,
    pub source_label: String,
    pub content: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertStatus {
    Open,
    Acknowledged,
    Resolved,
}

impl AlertStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Acknowledged => "acknowledged",
            Self::Resolved => "resolved",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertRecord {
    pub alert_id: String,
    pub finding_id: String,
    pub status: AlertStatus,
    pub created_at_unix_ms: u64,
    pub finding: Finding,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationReceiptRecord {
    pub alert_id: String,
    pub delivery_route: String,
    pub delivered_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationCursorRecord {
    pub cursor_key: String,
    pub unix_ms: u64,
}
