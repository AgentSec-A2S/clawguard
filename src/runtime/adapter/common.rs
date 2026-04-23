//! Shared hook-payload type and canonicalization helpers consumed by every
//! runtime adapter.
//!
//! The `HookPayload` is deliberately host-agnostic so the `PolicyEngine`
//! trait does not leak OpenClaw / Claude Code specifics. Adapters are
//! responsible for building one of these from their runtime's native hook
//! event struct.

use std::collections::BTreeMap;

use crate::scan::{
    Finding, FindingCategory, Fixability, RecommendedAction, RuntimeConfidence, Severity,
};

/// Which lifecycle point produced this payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HookPhase {
    BeforeToolCall,
    AfterToolCall,
    SessionStart,
    SessionEnd,
}

/// Normalized tool-call payload shared by every adapter.
///
/// `args_raw` is the verbatim argument stream the host passed us.
/// `args_canonical` is the output of [`canonicalize_args`] — prefer it for
/// detector logic so `sh -c "rm -rf ~"` and `rm -rf ~` hash the same.
#[derive(Debug, Clone)]
pub struct HookPayload {
    pub phase: HookPhase,
    pub session_id: String,
    pub agent_id: Option<String>,
    pub tool_name: String,
    pub args_raw: String,
    pub args_canonical: String,
    pub result_text: Option<String>,
    pub metadata: BTreeMap<String, String>,
}

impl HookPayload {
    /// Convenience constructor for tests and adapter glue.
    pub fn new(phase: HookPhase, session_id: impl Into<String>, tool_name: impl Into<String>, args_raw: impl Into<String>) -> Self {
        let args_raw = args_raw.into();
        let args_canonical = canonicalize_args(&args_raw);
        Self {
            phase,
            session_id: session_id.into(),
            agent_id: None,
            tool_name: tool_name.into(),
            args_raw,
            args_canonical,
            result_text: None,
            metadata: BTreeMap::new(),
        }
    }
}

/// Canonicalize a command / argument string so equivalent invocations hash
/// identically. Each pass applies, in order:
///
/// 1. Unicode NFKC normalization (compatibility-fold fullwidth lookalikes
///    and other visual collisions).
/// 2. Zero-width / BOM stripping (ZWSP, ZWJ, BOM).
/// 3. Percent-decode of `%HH` triplets (single pass per outer iteration).
/// 4. Whitespace collapse — runs of any Unicode whitespace become a single
///    ASCII space; leading/trailing whitespace dropped.
///
/// The full pipeline is then re-applied until the output reaches a fixed
/// point (bounded at [`MAX_CANONICALIZE_PASSES`] iterations). Looping the
/// whole pipeline — not just the percent-decode — defeats two classes of
/// bypass:
///
/// * Pure double-encoding: `5%5%4545` → pass 1 → `5%5E45` → pass 2 → `5^45`.
/// * Decode-then-compose: percent-decode can emit a byte that, together
///   with an adjacent combining character, NFKC-recomposes on the next
///   pass — e.g. `%77` + `\u{308}` → `w\u{308}` → `ẅ`. A single pass would
///   let `canonicalize(canonicalize(x)) ≠ canonicalize(x)`.
///
/// This function is deliberately conservative about `sh -c` / `bash -c`
/// unwrapping — it does NOT try to unwrap them, that's the rule layer's
/// job because the unwrap strategy is rule-specific.
pub fn canonicalize_args(raw: &str) -> String {
    let mut current = raw.to_string();
    for _ in 0..MAX_CANONICALIZE_PASSES {
        let next = canonicalize_once(&current);
        if next == current {
            return next;
        }
        current = next;
    }
    current
}

/// Upper bound on canonicalize pipeline iterations. Each pass can only
/// shrink the string (decode consumes 2 bytes per triplet, NFKC
/// composition reduces combining pairs, whitespace collapse removes
/// characters), so convergence is guaranteed; this bound is a defence
/// against pathological inputs that somehow cycle without shrinking.
const MAX_CANONICALIZE_PASSES: usize = 8;

fn canonicalize_once(raw: &str) -> String {
    use unicode_normalization::UnicodeNormalization;

    let nfkc: String = raw.nfkc().collect();
    let stripped: String = nfkc
        .chars()
        .filter(|c| !is_zero_width(*c))
        .collect();
    let decoded = percent_decode_once(&stripped);
    collapse_whitespace(&decoded)
}

fn is_zero_width(c: char) -> bool {
    matches!(
        c as u32,
        0x200B..=0x200F  // zero-width + directional marks
            | 0x2028..=0x202F  // line/para separators + narrow/word joiner
            | 0xFEFF  // BOM
            | 0x180E  // Mongolian vowel separator
            | 0x00AD  // soft hyphen
    )
}

/// Percent-decode exactly once. Invalid triplets are left verbatim.
/// Prefer [`percent_decode_to_fixed_point`] for canonicalization — single-pass
/// decoding is NOT idempotent under composition, see fuzz target
/// `fuzz_canonicalize_args`.
fn percent_decode_once(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_value(bytes[i + 1]), hex_value(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn collapse_whitespace(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut prev_space = true; // skip leading whitespace
    for c in input.chars() {
        if c.is_whitespace() {
            if !prev_space {
                out.push(' ');
                prev_space = true;
            }
        } else {
            out.push(c);
            prev_space = false;
        }
    }
    if out.ends_with(' ') {
        out.pop();
    }
    out
}

/// Bridge a runtime verdict to a `Finding` so the scan + posture pipelines
/// can persist it. `kind` should be one of the runtime kinds registered in
/// `src/scan/finding.rs` (e.g. `"runtime-destructive-action"`).
pub fn payload_to_finding(
    payload: &HookPayload,
    kind: &str,
    severity: Severity,
    explanation: &str,
    action_label: &str,
    evidence: Option<&str>,
) -> Finding {
    Finding {
        id: format!(
            "runtime:{kind}:{session}:{tool}",
            session = payload.session_id,
            tool = payload.tool_name
        ),
        detector_id: "runtime".to_string(),
        severity,
        category: FindingCategory::Config,
        runtime_confidence: RuntimeConfidence::ActiveRuntime,
        path: payload.tool_name.clone(),
        line: None,
        evidence: evidence.map(str::to_string),
        plain_english_explanation: explanation.to_string(),
        recommended_action: RecommendedAction {
            label: action_label.to_string(),
            command_hint: None,
        },
        fixability: Fixability::Manual,
        fix: None,
        owasp_asi: crate::scan::finding::owasp_asi_for_kind(kind),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalize_folds_fullwidth_to_ascii() {
        // Fullwidth 'ｒｍ' should NFKC-fold to ASCII 'rm'.
        assert_eq!(canonicalize_args("ｒｍ -rf ~"), "rm -rf ~");
    }

    #[test]
    fn canonicalize_strips_zero_width() {
        // Zero-width space between `r` and `m` must not hide the intent.
        let sneaky = "r\u{200B}m -rf ~";
        assert_eq!(canonicalize_args(sneaky), "rm -rf ~");
    }

    // Regression — `fuzz_canonicalize_args` found that single-pass
    // percent-decode produces a new `%HH` triplet for this input
    // (`5%5%4545` → `5%5E45` → `5^45`), which meant the rule engine
    // and a downstream consumer (e.g. an HTTP client that would
    // percent-decode a URL arg) could see different strings. We now
    // loop to fixed point so `canonicalize_args(canonicalize_args(x))
    // == canonicalize_args(x)` holds for arbitrary input.
    #[test]
    fn canonicalize_is_idempotent_under_double_percent_encoding() {
        let input = "5%5%4545";
        let once = canonicalize_args(input);
        let twice = canonicalize_args(&once);
        assert_eq!(once, twice, "canonicalize must be idempotent; once={once:?}, twice={twice:?}");
        // Also pin the canonical value — a future reader debugging
        // this should see exactly what the decoded form looks like.
        assert_eq!(once, "5^45");
    }

    #[test]
    fn canonicalize_handles_layered_percent_encoding_of_rm() {
        // `%2572m` single-pass decodes to `%72m`, which single-pass
        // decodes to `rm`. A single-pass canonicalize would let this
        // string slip past token matchers that compare against `rm`.
        // With fixed-point decode, the canonical form collapses to
        // `rm`.
        assert_eq!(canonicalize_args("%2572m -rf ~"), "rm -rf ~");
    }

    #[test]
    fn canonicalize_collapses_whitespace() {
        assert_eq!(canonicalize_args("  rm   -rf    ~  "), "rm -rf ~");
    }

    #[test]
    fn canonicalize_percent_decodes_to_fixed_point() {
        // %20 = space; simple single-layer decode.
        assert_eq!(canonicalize_args("rm%20-rf%20~"), "rm -rf ~");
        // %2525 now decodes all the way: %2525 → %25 → %.
        // (Policy change in Sprint 2 §7 — single-pass decode was not
        // idempotent and allowed double-encoding bypasses; see the
        // `canonicalize_is_idempotent_under_double_percent_encoding`
        // regression test and `fuzz_canonicalize_args` for the finding.)
        assert_eq!(canonicalize_args("a%2525b"), "a%b");
    }

    #[test]
    fn canonicalize_is_idempotent() {
        let input = "  ｒm\u{200B}  -rf%20~  ";
        let once = canonicalize_args(input);
        let twice = canonicalize_args(&once);
        assert_eq!(once, twice);
    }

    #[test]
    fn canonicalize_handles_empty() {
        assert_eq!(canonicalize_args(""), "");
        assert_eq!(canonicalize_args("   "), "");
    }

    #[test]
    fn hook_payload_new_populates_canonical() {
        let p = HookPayload::new(HookPhase::BeforeToolCall, "s1", "shell", "  ls   /tmp  ");
        assert_eq!(p.args_canonical, "ls /tmp");
        assert_eq!(p.args_raw, "  ls   /tmp  ");
    }
}
