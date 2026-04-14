//! End-to-end CLI contract tests for `clawguard audit`.
//!
//! Regression coverage for the v1.2.0-beta UAT finding where `audit --json`
//! emitted empty stdout on empty result sets and NDJSON (one object per line)
//! on populated sets — neither was a valid JSON document, which broke `jq`
//! pipelines and was inconsistent with every other `--json` subcommand.

use std::fs;
use std::path::Path;

use assert_cmd::Command;
use clawguard::audit::{AuditCategory, AuditEvent};
use clawguard::state::db::{StateStore, StateStoreConfig};
use serde_json::Value;
use tempfile::tempdir;

fn stdout_text(assert: &assert_cmd::assert::Assert) -> String {
    String::from_utf8_lossy(&assert.get_output().stdout).into_owned()
}

fn prepare_home() -> (tempfile::TempDir, std::path::PathBuf) {
    let temp = tempdir().expect("temp dir");
    let home = temp.path().join("home");
    fs::create_dir_all(&home).unwrap();
    (temp, home)
}

fn open_state_store(home: &Path) -> StateStore {
    let state_dir = home.join(".clawguard");
    fs::create_dir_all(&state_dir).unwrap();
    let db_path = state_dir.join("state.db");
    StateStore::open(StateStoreConfig::for_path(db_path))
        .expect("open state store")
        .store
}

/// `clawguard audit --json` MUST emit a valid JSON array even when the DB has
/// no audit rows yet. Emitting empty stdout silently breaks `jq` pipelines
/// (UAT 2026-04-15, BUG #1).
#[test]
fn audit_json_returns_empty_array_when_no_events() {
    let (_temp, home) = prepare_home();
    // Seed an empty DB so we exercise the `DB exists + no rows` branch, not
    // the `DB missing` early return.
    let _store = open_state_store(&home);

    let assert = Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home)
        .args(["audit", "--json"])
        .assert()
        .success();

    let stdout = stdout_text(&assert);
    let trimmed = stdout.trim();
    assert!(
        !trimmed.is_empty(),
        "audit --json on empty DB must emit a JSON array, got empty stdout"
    );
    let parsed: Value =
        serde_json::from_str(trimmed).expect("audit --json output must be valid JSON");
    let array = parsed
        .as_array()
        .expect("audit --json output must be an array");
    assert!(array.is_empty(), "expected [], got {parsed}");
}

/// `clawguard audit --json` MUST emit a single JSON array (not NDJSON) when
/// events exist, for parity with every other `--json` subcommand.
#[test]
fn audit_json_returns_single_array_when_events_exist() {
    let (_temp, home) = prepare_home();
    let mut store = open_state_store(&home);

    store
        .insert_audit_events(&[
            AuditEvent::new_passive(
                1_000,
                AuditCategory::Config,
                "config.write",
                "first",
                r#"{"k":1}"#,
            ),
            AuditEvent::new_passive(
                2_000,
                AuditCategory::Plugin,
                "plugin.install",
                "second",
                r#"{"k":2}"#,
            ),
        ])
        .unwrap();
    drop(store);

    let assert = Command::cargo_bin("clawguard")
        .expect("binary should exist")
        .env("HOME", &home)
        .args(["audit", "--json"])
        .assert()
        .success();

    let stdout = stdout_text(&assert);
    let trimmed = stdout.trim();
    let parsed: Value =
        serde_json::from_str(trimmed).expect("audit --json output must parse as a single JSON doc");
    let array = parsed
        .as_array()
        .expect("audit --json output must be an array");
    assert_eq!(array.len(), 2, "expected 2 events, got {parsed}");

    // Order is newest-first per list_audit_events contract.
    let summaries: Vec<&str> = array
        .iter()
        .map(|ev| ev.get("summary").and_then(Value::as_str).unwrap_or(""))
        .collect();
    assert!(
        summaries.contains(&"first") && summaries.contains(&"second"),
        "expected summaries [first, second], got {summaries:?}"
    );
}
