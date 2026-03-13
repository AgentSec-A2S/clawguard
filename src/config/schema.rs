use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Strictness {
    Recommended,
    Relaxed,
    Strict,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AlertStrategy {
    Desktop,
    Webhook,
    LogOnly,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ScanDomain {
    Config,
    Skills,
    Mcp,
    Env,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PathPattern {
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanTarget {
    pub domain: ScanDomain,
    pub paths: Vec<PathPattern>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Preset {
    pub id: String,
    pub label: String,
    pub detection_paths: Vec<PathPattern>,
    pub scan_targets: Vec<ScanTarget>,
    pub critical_files: Vec<PathPattern>,
    pub excluded_dirs: Vec<String>,
    pub max_file_size_bytes: u64,
    pub default_strictness: Strictness,
    pub default_alert_strategy: AlertStrategy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppConfig {
    pub preset: String,
    pub strictness: Strictness,
    pub alert_strategy: AlertStrategy,
    pub max_file_size_bytes: u64,
}
