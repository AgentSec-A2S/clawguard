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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertStatus {
    Open,
    Acknowledged,
    Resolved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertRecord {
    pub alert_id: String,
    pub finding_id: String,
    pub status: AlertStatus,
    pub created_at_unix_ms: u64,
    pub finding: Finding,
}
