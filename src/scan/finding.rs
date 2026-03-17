use serde::{Deserialize, Serialize};

use super::severity::Severity;

/// Broad detector-owned category used to group findings at the scan-engine level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingCategory {
    Config,
    Skills,
    Mcp,
    Secrets,
    Advisory,
    Drift,
}

/// How confident ClawGuard is that the finding reflects active runtime state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeConfidence {
    /// Found in the active OpenClaw state that is currently in use.
    ActiveRuntime,
    /// Found through an explicit config/state-path override rather than the default home layout.
    OverridePath,
    /// Found in optional local-only state that may not be active for every user workflow.
    OptionalLocalState,
    /// Found in a template, example, or starter config rather than confirmed runtime state.
    TemplateExample,
    /// Found in a backup, snapshot, or other archival artifact near the runtime.
    BackupArtifact,
}

/// Whether the recommended action is advisory only, manual, or safe to offer interactively.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Fixability {
    AdvisoryOnly,
    Manual,
    /// Safe to offer after explicit user confirmation; never implies silent auto-remediation.
    AutoSafe,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecommendedAction {
    pub label: String,
    pub command_hint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingFix {
    pub summary: String,
    pub reversible: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Stable identifier for this finding across renders and later trust/baseline flows.
    pub id: String,
    /// Detector that produced this finding, such as `openclaw-config` or `mcp`.
    pub detector_id: String,
    pub severity: Severity,
    pub category: FindingCategory,
    pub runtime_confidence: RuntimeConfidence,
    /// Resolved filesystem path for the evidence source; never a preset template like `~/.openclaw/...`.
    pub path: String,
    pub line: Option<usize>,
    pub evidence: Option<String>,
    pub plain_english_explanation: String,
    pub recommended_action: RecommendedAction,
    pub fixability: Fixability,
    pub fix: Option<FindingFix>,
}
