//! Shared runtime policy engine.
//!
//! The engine is deliberately host-agnostic. A single `PolicyEngine`
//! instance serves every adapter (OpenClaw today, Claude Code / Hermes in
//! later sprints) and evaluates proposed + completed tool calls against a
//! TOML manifest of Tier-1 deterministic rules.

use crate::scan::Finding;

pub mod manifest;
pub mod rules;

/// Per-call verdict returned by the engine.
///
/// Ordering (`worst-verdict-wins`): `Allow` < `Warn` < `Suspect` < `Block`.
/// When multiple rules fire on the same payload, the reducer picks the
/// maximum variant and concatenates their evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PolicyDecision {
    Allow,
    Warn,
    Suspect,
    Block,
}

impl PolicyDecision {
    /// `true` for any decision that should NOT reach the runtime (currently
    /// only `Block`). `Warn` and `Suspect` let the call through with a
    /// finding attached; Sprint 3's Tier-2 escalates `Suspect`.
    pub fn blocks(self) -> bool {
        matches!(self, PolicyDecision::Block)
    }
}

/// Result of evaluating one tool call against the engine.
///
/// Carries the aggregate `decision`, a human-readable `reason`, an
/// `evidence` fragment suitable for logs, and zero or more `findings`
/// bridged back into the shared `src/scan/finding.rs` pipeline so runtime
/// verdicts feed the same posture score and persistence layer as scan
/// findings.
#[derive(Debug, Clone)]
pub struct PolicyVerdict {
    pub decision: PolicyDecision,
    pub reason: String,
    pub evidence: Option<String>,
    pub findings: Vec<Finding>,
}

impl PolicyVerdict {
    /// Construct an `Allow` verdict with no findings.
    pub fn allow() -> Self {
        Self {
            decision: PolicyDecision::Allow,
            reason: "allowed".to_string(),
            evidence: None,
            findings: Vec::new(),
        }
    }

    /// Merge `other` into `self` using the worst-verdict-wins rule.
    /// Findings are appended; evidence and reason follow the higher
    /// decision when `other` escalates, otherwise keep `self`.
    pub fn merge(mut self, other: PolicyVerdict) -> Self {
        if other.decision > self.decision {
            self.decision = other.decision;
            self.reason = other.reason;
            self.evidence = other.evidence;
        }
        self.findings.extend(other.findings);
        self
    }
}

/// Host-agnostic policy evaluator. Adapters hand in normalized hook
/// payloads; the engine returns a single `PolicyVerdict` aggregating every
/// rule's opinion.
pub trait PolicyEngine: Send + Sync {
    /// Evaluate a tool call before it reaches the runtime.
    fn evaluate_pre_tool_call(
        &self,
        payload: &crate::runtime::adapter::common::HookPayload,
    ) -> PolicyVerdict;

    /// Evaluate a tool call after it has executed (primarily for prompt-
    /// injection shape checks on tool *results*).
    fn evaluate_post_tool_call(
        &self,
        payload: &crate::runtime::adapter::common::HookPayload,
    ) -> PolicyVerdict;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_ordering_is_worst_wins() {
        assert!(PolicyDecision::Block > PolicyDecision::Suspect);
        assert!(PolicyDecision::Suspect > PolicyDecision::Warn);
        assert!(PolicyDecision::Warn > PolicyDecision::Allow);
    }

    #[test]
    fn only_block_short_circuits() {
        assert!(PolicyDecision::Block.blocks());
        assert!(!PolicyDecision::Suspect.blocks());
        assert!(!PolicyDecision::Warn.blocks());
        assert!(!PolicyDecision::Allow.blocks());
    }

    #[test]
    fn merge_picks_higher_decision() {
        let a = PolicyVerdict::allow();
        let b = PolicyVerdict {
            decision: PolicyDecision::Warn,
            reason: "b".to_string(),
            evidence: Some("e".to_string()),
            findings: Vec::new(),
        };
        let merged = a.merge(b);
        assert_eq!(merged.decision, PolicyDecision::Warn);
        assert_eq!(merged.reason, "b");
    }

    #[test]
    fn merge_keeps_self_when_other_lower() {
        let a = PolicyVerdict {
            decision: PolicyDecision::Suspect,
            reason: "a".to_string(),
            evidence: None,
            findings: Vec::new(),
        };
        let b = PolicyVerdict::allow();
        let merged = a.merge(b);
        assert_eq!(merged.decision, PolicyDecision::Suspect);
        assert_eq!(merged.reason, "a");
    }
}
