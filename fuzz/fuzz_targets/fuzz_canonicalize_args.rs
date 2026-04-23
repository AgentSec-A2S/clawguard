#![no_main]

//! Fuzz the shared `canonicalize_args` canonicalization pipeline.
//!
//! Every Tier-1 rule runs incoming tool-call args through
//! `canonicalize_args` (NFKC → zero-width strip → single-pass
//! percent-decode → whitespace collapse). A panic here would take
//! down the broker subprocess; an output that changes under repeated
//! application would let attackers craft inputs that slip past rules
//! the second time around.
//!
//! Invariants asserted:
//! 1. No panic on any UTF-8 input.
//! 2. Idempotence: canonicalize(canonicalize(x)) == canonicalize(x).
//!    (Single-pass percent-decode is deliberate; feeding the output
//!    back in must be a stable fixed point so attackers cannot chain
//!    decodes by layering percent-encodings.)

use libfuzzer_sys::fuzz_target;
use clawguard::runtime::adapter::common::canonicalize_args;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let once = canonicalize_args(text);
        let twice = canonicalize_args(&once);
        assert_eq!(
            once, twice,
            "canonicalize_args must be idempotent; input: {:?}",
            text
        );
    }
});
