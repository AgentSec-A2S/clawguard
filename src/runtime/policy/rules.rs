//! Tier-1 deterministic rules.
//!
//! Each function in this module inspects a `HookPayload` + current
//! `PolicyManifest` snapshot and returns a `PolicyVerdict`. The
//! `PolicyEngine` implementation in `super` composes them with a
//! worst-verdict-wins reducer.
//!
//! Full implementations land in Sprint 2 §2. This stub defines the
//! signatures and a pass-through `evaluate` function so the module tree
//! compiles and adapters can be wired up in parallel.

use super::manifest::PolicyManifest;
use super::PolicyVerdict;
use crate::runtime::adapter::common::HookPayload;

/// Run every Tier-1 rule against `payload` under `manifest` and return the
/// merged verdict. Sprint 2 §2 fills in the real rule bodies; for now
/// every payload is `Allow`.
pub fn evaluate_pre(payload: &HookPayload, manifest: &PolicyManifest) -> PolicyVerdict {
    let mut verdict = PolicyVerdict::allow();
    verdict = verdict.merge(destructive_action_check(payload, manifest));
    verdict = verdict.merge(lethal_trifecta_precondition_check(payload, manifest));
    verdict = verdict.merge(path_boundary_check(payload, manifest));
    verdict = verdict.merge(rate_limit_check(payload, manifest));
    verdict
}

/// Post-call rules (currently just prompt-injection shape on tool
/// results). Pre-call rules do not re-run here.
pub fn evaluate_post(payload: &HookPayload, manifest: &PolicyManifest) -> PolicyVerdict {
    let verdict = PolicyVerdict::allow();
    verdict.merge(prompt_injection_shape_check(payload, manifest))
}

// --- Rule stubs — bodies land in Sprint 2 §2 ---

pub fn destructive_action_check(
    _payload: &HookPayload,
    _manifest: &PolicyManifest,
) -> PolicyVerdict {
    PolicyVerdict::allow()
}

pub fn lethal_trifecta_precondition_check(
    _payload: &HookPayload,
    _manifest: &PolicyManifest,
) -> PolicyVerdict {
    PolicyVerdict::allow()
}

pub fn path_boundary_check(
    _payload: &HookPayload,
    _manifest: &PolicyManifest,
) -> PolicyVerdict {
    PolicyVerdict::allow()
}

pub fn rate_limit_check(_payload: &HookPayload, _manifest: &PolicyManifest) -> PolicyVerdict {
    PolicyVerdict::allow()
}

pub fn prompt_injection_shape_check(
    _payload: &HookPayload,
    _manifest: &PolicyManifest,
) -> PolicyVerdict {
    PolicyVerdict::allow()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::adapter::common::{HookPayload, HookPhase};
    use crate::runtime::policy::PolicyDecision;

    #[test]
    fn default_manifest_allows_benign_payload() {
        let manifest = PolicyManifest::default();
        let payload = HookPayload::new(HookPhase::BeforeToolCall, "s1", "shell", "ls /tmp");
        assert_eq!(evaluate_pre(&payload, &manifest).decision, PolicyDecision::Allow);
    }

    #[test]
    fn post_evaluation_passes_through_on_empty_result() {
        let manifest = PolicyManifest::default();
        let payload = HookPayload::new(HookPhase::AfterToolCall, "s1", "fetch", "https://example.com");
        assert_eq!(evaluate_post(&payload, &manifest).decision, PolicyDecision::Allow);
    }
}
