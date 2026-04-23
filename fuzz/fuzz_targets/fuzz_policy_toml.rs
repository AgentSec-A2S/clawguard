#![no_main]

//! Fuzz the `policy.toml` loader.
//!
//! The runtime broker loads `~/.clawguard/policy.toml` at spawn (or
//! falls back to built-in defaults). `load_manifest` layers path
//! canonicalization and symlink-escape checks on top of the toml
//! parser; those are filesystem concerns, not input-shape concerns,
//! and are covered by unit tests. This target focuses on the string
//! → `PolicyManifest` deserializer, which is where arbitrary operator
//! (or attacker-tampered) bytes land.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = toml::from_str::<clawguard::runtime::policy::manifest::PolicyManifest>(text);
    }
});
