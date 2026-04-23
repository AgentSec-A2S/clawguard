#![no_main]

//! Fuzz the broker's stdin-event deserializer.
//!
//! The runtime broker reads one JSON line per stdin line and feeds it
//! to `serde_json::from_str::<OpenClawHookEvent>`. Any panic here
//! escapes to the OpenClaw plugin host. `run_broker` currently
//! converts parse errors into allow-verdicts, so the fuzz target only
//! needs to prove that deserialization itself cannot panic on
//! arbitrary bytes — the adapter's `catch_unwind` boundary is a
//! second, independent defence.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        for line in text.split('\n') {
            let _ = serde_json::from_str::<clawguard::runtime::adapter::openclaw::OpenClawHookEvent>(line);
        }
    }
});
