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
    /// OWASP Agentic Security Initiative (ASI) Top 10 category, if mapped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owasp_asi: Option<String>,
}

/// Map a finding kind to its OWASP ASI Top 10 category.
pub fn owasp_asi_for_kind(kind: &str) -> Option<String> {
    match kind {
        // ASI02: Tool Misuse & Abuse
        "exec-host-node"
        | "acp-approve-all"
        | "gateway-node-dangerous-command"
        | "tool-profile-escalation"
        | "hook-shell-exec" => Some("ASI02".into()),
        // ASI02: Excessive Agency (missing approval guardrails)
        "exec-approvals-missing" => Some("ASI02".into()),
        // ASI03: Privilege Escalation
        "exec-security-full"
        | "exec-ask-off"
        | "auto-allow-skills"
        | "sandbox-disabled"
        | "sandbox-host-fallback"
        | "sandbox-bind-symlink"
        | "sandbox-bind-temp-dir"
        | "sandbox-dangerous-reserved-targets"
        | "sandbox-dangerous-external-sources" => Some("ASI03".into()),
        // ASI04: Data Exfiltration
        "dangerous-network" | "open-dm-policy" | "hook-network-exfil" => Some("ASI04".into()),
        // ASI05: Configuration Drift
        "exec-ask-fallback-weak"
        | "tripwire-catastrophic"
        | "approval-drift-dangerous-executable"
        | "approval-drift-interpreter"
        | "hook-config-mutation" => Some("ASI05".into()),
        // ASI06: Supply Chain Compromise
        "insecure-plugin-install-path"
        | "plugin-not-in-allowlist"
        | "plugin-in-denylist"
        | "skill-no-provenance"
        | "skill-unapproved-change"
        | "skill-remote-redirect" => Some("ASI06".into()),
        // ASI07: Prompt Injection
        "hook-allows-unsafe-external-content"
        | "hook-allows-request-session-key"
        | "plugin-hook-prompt-injection"
        | "hook-identity-mutation"
        | "bootstrap-encoded-payload"
        | "bootstrap-shell-injection"
        | "bootstrap-prompt-injection"
        | "bootstrap-obfuscated-content" => Some("ASI07".into()),
        // ASI09: Secrets Exposure (note: secrets detector sets ASI09 directly, this is a fallback)
        "private-key" => Some("ASI09".into()),
        // ASI10: Insecure Defaults
        "dangerous-disable-device-auth" | "gateway-bind-exposed" => Some("ASI10".into()),
        _ => None,
    }
}
