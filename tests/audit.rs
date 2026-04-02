use std::fs;
use std::path::PathBuf;

use clawguard::audit::ingest::{
    ingest_bootstrap_changes, ingest_config_audit_jsonl, ingest_plugin_catalog,
    ingest_skill_changes,
};
use clawguard::audit::{AuditCategory, AuditEvent};
use clawguard::state::db::{StateStore, StateStoreConfig};
use tempfile::TempDir;

fn setup_state() -> (TempDir, StateStore) {
    let dir = tempfile::tempdir().expect("temp dir");
    let db_path = dir.path().join("state.db");
    let result = StateStore::open(StateStoreConfig::for_path(db_path)).expect("open state");
    (dir, result.store)
}

fn list_all_events(state: &StateStore) -> Vec<AuditEvent> {
    state
        .list_audit_events(None, None, 1000)
        .expect("list events")
}

fn list_events_by_category(state: &StateStore, category: &str) -> Vec<AuditEvent> {
    state
        .list_audit_events(Some(category), None, 1000)
        .expect("list events")
}

// ---- Config audit JSONL tests ----

#[test]
fn config_audit_jsonl_ingested() {
    let (dir, mut state) = setup_state();
    let jsonl_path = dir.path().join("config-audit.jsonl");
    fs::write(
        &jsonl_path,
        r#"{"ts":"2026-04-02T10:00:00Z","source":"config-io","event":"config.write","result":"rename","path":"/home/user/.openclaw/openclaw.json"}
{"ts":"2026-04-02T11:00:00Z","source":"config-io","event":"config.write","result":"copy-fallback","path":"/home/user/.openclaw/openclaw.json"}
"#,
    )
    .unwrap();

    let count = ingest_config_audit_jsonl(&mut state, &jsonl_path).unwrap();
    assert_eq!(count, 2);

    let events = list_events_by_category(&state, "config");
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].event_type, "config.write");
    assert!(events[0].summary.contains("rename") || events[1].summary.contains("rename"));
}

#[test]
fn config_audit_cursor_prevents_re_ingestion() {
    let (dir, mut state) = setup_state();
    let jsonl_path = dir.path().join("config-audit.jsonl");
    fs::write(
        &jsonl_path,
        r#"{"ts":"2026-04-02T10:00:00Z","event":"config.write","result":"rename"}
"#,
    )
    .unwrap();

    let count1 = ingest_config_audit_jsonl(&mut state, &jsonl_path).unwrap();
    assert_eq!(count1, 1);

    // Second call should not re-ingest
    let count2 = ingest_config_audit_jsonl(&mut state, &jsonl_path).unwrap();
    assert_eq!(count2, 0);

    let events = list_events_by_category(&state, "config");
    assert_eq!(events.len(), 1, "should not have duplicates");
}

#[test]
fn config_audit_malformed_line_skipped() {
    let (dir, mut state) = setup_state();
    let jsonl_path = dir.path().join("config-audit.jsonl");
    fs::write(
        &jsonl_path,
        r#"{"ts":"2026-04-02T10:00:00Z","event":"config.write","result":"rename"}
NOT VALID JSON AT ALL
{"ts":"2026-04-02T12:00:00Z","event":"config.write","result":"copy-fallback"}
"#,
    )
    .unwrap();

    let count = ingest_config_audit_jsonl(&mut state, &jsonl_path).unwrap();
    assert_eq!(
        count, 2,
        "malformed line should be skipped, valid lines ingested"
    );
}

#[test]
fn config_audit_empty_file_clean() {
    let (_dir, mut state) = setup_state();
    let missing_path = PathBuf::from("/nonexistent/config-audit.jsonl");

    let count = ingest_config_audit_jsonl(&mut state, &missing_path).unwrap();
    assert_eq!(
        count, 0,
        "missing file should return 0 events, not an error"
    );
}

// ---- Skill change detection tests ----

#[test]
fn skill_added_detected() {
    let (dir, mut state) = setup_state();
    let skills_dir = dir.path().join("skills");
    fs::create_dir_all(&skills_dir).unwrap();

    // First call establishes the snapshot (empty)
    let count1 = ingest_skill_changes(&mut state, &skills_dir).unwrap();
    assert_eq!(
        count1, 0,
        "first call with empty dir should detect nothing new"
    );

    // Add a skill directory
    fs::create_dir_all(skills_dir.join("web-search")).unwrap();

    // Second call should detect the addition
    let count2 = ingest_skill_changes(&mut state, &skills_dir).unwrap();
    assert_eq!(count2, 1);

    let events = list_events_by_category(&state, "skill");
    // Filter out snapshot events
    let real_events: Vec<_> = events
        .iter()
        .filter(|e| e.event_type != "skill.snapshot")
        .collect();
    assert_eq!(real_events.len(), 1);
    assert_eq!(real_events[0].event_type, "skill.added");
    assert!(real_events[0].summary.contains("web-search"));
}

#[test]
fn skill_removed_detected() {
    let (dir, mut state) = setup_state();
    let skills_dir = dir.path().join("skills");
    fs::create_dir_all(skills_dir.join("old-skill")).unwrap();

    // First call: establish snapshot with old-skill
    ingest_skill_changes(&mut state, &skills_dir).unwrap();

    // Remove the skill
    fs::remove_dir_all(skills_dir.join("old-skill")).unwrap();

    // Second call: detect removal
    let count = ingest_skill_changes(&mut state, &skills_dir).unwrap();
    assert_eq!(count, 1);

    let events = list_events_by_category(&state, "skill");
    let real_events: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == "skill.removed")
        .collect();
    assert_eq!(real_events.len(), 1);
    assert!(real_events[0].summary.contains("old-skill"));
}

// ---- Plugin catalog detection tests ----

#[test]
fn plugin_installed_detected() {
    let (dir, mut state) = setup_state();
    let catalog_path = dir.path().join("catalog.json");

    // First call: empty catalog
    fs::write(&catalog_path, "{}").unwrap();
    ingest_plugin_catalog(&mut state, &catalog_path).unwrap();

    // Add a plugin
    fs::write(&catalog_path, r#"{"claude-mem": {"version": "1.0"}}"#).unwrap();
    let count = ingest_plugin_catalog(&mut state, &catalog_path).unwrap();
    assert_eq!(count, 1);

    let events = list_events_by_category(&state, "plugin");
    let real_events: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == "plugin.installed")
        .collect();
    assert_eq!(real_events.len(), 1);
    assert!(real_events[0].summary.contains("claude-mem"));
}

// ---- Query/filter tests ----

#[test]
fn audit_list_category_filter() {
    let (_dir, mut state) = setup_state();

    state
        .insert_audit_events(&[
            AuditEvent::new_passive(1000, AuditCategory::Config, "config.write", "test1", "{}"),
            AuditEvent::new_passive(2000, AuditCategory::Skill, "skill.added", "test2", "{}"),
            AuditEvent::new_passive(
                3000,
                AuditCategory::Plugin,
                "plugin.installed",
                "test3",
                "{}",
            ),
        ])
        .unwrap();

    let config_events = list_events_by_category(&state, "config");
    assert_eq!(config_events.len(), 1);
    assert_eq!(config_events[0].event_type, "config.write");

    let skill_events = list_events_by_category(&state, "skill");
    assert_eq!(skill_events.len(), 1);
    assert_eq!(skill_events[0].event_type, "skill.added");
}

#[test]
fn audit_list_since_filter() {
    let (_dir, mut state) = setup_state();

    state
        .insert_audit_events(&[
            AuditEvent::new_passive(1000, AuditCategory::Config, "old", "old event", "{}"),
            AuditEvent::new_passive(5000, AuditCategory::Config, "new", "new event", "{}"),
        ])
        .unwrap();

    let events = state.list_audit_events(None, Some(3000), 100).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, "new");
}

#[test]
fn audit_list_json_output() {
    let (_dir, mut state) = setup_state();

    state
        .insert_audit_events(&[AuditEvent::new_passive(
            1000,
            AuditCategory::Config,
            "config.write",
            "test summary",
            r#"{"raw":"data"}"#,
        )])
        .unwrap();

    let events = list_all_events(&state);
    assert_eq!(events.len(), 1);

    let json = serde_json::to_string(&events[0]).unwrap();
    assert!(json.contains("config.write"));
    assert!(json.contains("test summary"));
    assert!(json.contains("raw") && json.contains("data"));
    assert!(json.contains("\"category\":\"Config\""));
    assert!(json.contains("\"source\":\"Passive\""));
}

// ---- Codex review regression tests ----

#[test]
fn config_audit_log_rotation_resets_cursor() {
    let (dir, mut state) = setup_state();
    let jsonl_path = dir.path().join("config-audit.jsonl");

    // Write initial content (two lines to make the file longer)
    fs::write(
        &jsonl_path,
        r#"{"ts":"2026-04-02T10:00:00Z","event":"config.write","result":"rename"}
{"ts":"2026-04-02T10:30:00Z","event":"config.write","result":"rename"}
"#,
    )
    .unwrap();
    let count1 = ingest_config_audit_jsonl(&mut state, &jsonl_path).unwrap();
    assert_eq!(count1, 2);

    // Simulate log rotation: replace with shorter file (1 line < 2 lines)
    fs::write(
        &jsonl_path,
        r#"{"ts":"2026-04-02T12:00:00Z","event":"config.write","result":"new"}
"#,
    )
    .unwrap();
    let count2 = ingest_config_audit_jsonl(&mut state, &jsonl_path).unwrap();
    assert_eq!(count2, 1, "should re-read after file shrink (rotation)");

    let events = list_events_by_category(&state, "config");
    assert_eq!(events.len(), 3, "2 from first + 1 after rotation");
}

#[test]
fn config_audit_timestamp_is_parsed_not_now() {
    let (dir, mut state) = setup_state();
    let jsonl_path = dir.path().join("config-audit.jsonl");
    fs::write(
        &jsonl_path,
        r#"{"ts":"2026-01-15T08:30:00Z","event":"config.write","result":"rename"}
"#,
    )
    .unwrap();

    ingest_config_audit_jsonl(&mut state, &jsonl_path).unwrap();
    let events = list_events_by_category(&state, "config");
    assert_eq!(events.len(), 1);

    // 2026-01-15T08:30:00Z should be well in the past
    let event_time = events[0].event_at_unix_ms;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    assert!(
        event_time < now - 60_000,
        "event_at should be parsed as the past timestamp, not now (event_at={event_time}, now={now})"
    );
}

#[test]
fn config_audit_reads_config_path_field() {
    let (dir, mut state) = setup_state();
    let jsonl_path = dir.path().join("config-audit.jsonl");
    fs::write(
        &jsonl_path,
        r#"{"ts":"2026-04-02T10:00:00Z","event":"config.write","result":"rename","configPath":"/home/user/.openclaw/openclaw.json"}
"#,
    )
    .unwrap();

    ingest_config_audit_jsonl(&mut state, &jsonl_path).unwrap();
    let events = list_events_by_category(&state, "config");
    assert_eq!(events.len(), 1);
    assert!(
        events[0].summary.contains(".openclaw/openclaw.json"),
        "summary should include configPath"
    );
    assert_eq!(
        events[0].path.as_deref(),
        Some("/home/user/.openclaw/openclaw.json")
    );
}

#[test]
fn skill_file_content_change_detected() {
    let (dir, mut state) = setup_state();
    let skills_dir = dir.path().join("skills");
    let skill_dir = skills_dir.join("my-skill");
    fs::create_dir_all(&skill_dir).unwrap();
    fs::write(skill_dir.join("handler.js"), "console.log('v1')").unwrap();

    // First call: establish snapshot
    ingest_skill_changes(&mut state, &skills_dir).unwrap();

    // Modify a file inside the skill (in-place edit, dir mtime may not change)
    fs::write(
        skill_dir.join("handler.js"),
        "console.log('v2 - malicious')",
    )
    .unwrap();

    // Second call: should detect the content change via SHA-256
    let count = ingest_skill_changes(&mut state, &skills_dir).unwrap();
    assert_eq!(count, 1);

    let events: Vec<_> = list_events_by_category(&state, "skill")
        .into_iter()
        .filter(|e| e.event_type == "skill.changed")
        .collect();
    assert_eq!(events.len(), 1);
    assert!(events[0].summary.contains("my-skill"));
}

#[test]
fn skill_unreadable_dir_preserves_previous_snapshot() {
    let (_dir, mut state) = setup_state();
    // Point to a nonexistent directory
    let missing_dir = std::path::PathBuf::from("/nonexistent/skills");

    let count = ingest_skill_changes(&mut state, &missing_dir).unwrap();
    assert_eq!(
        count, 0,
        "unreadable dir should return 0, not emit removals"
    );

    // Verify no removal events were created
    let events: Vec<_> = list_events_by_category(&state, "skill")
        .into_iter()
        .filter(|e| e.event_type == "skill.removed")
        .collect();
    assert!(events.is_empty(), "should not emit false removals");
}

// ---- Bootstrap file audit tracking tests ----

#[test]
fn bootstrap_file_added_detected() {
    let (dir, mut state) = setup_state();
    let agents_dir = dir.path().join("agents");
    let workspace = agents_dir.join("default").join("agent");
    fs::create_dir_all(&workspace).unwrap();
    fs::write(workspace.join("SOUL.md"), "You are a helpful assistant.").unwrap();

    let count = ingest_bootstrap_changes(&mut state, &agents_dir).unwrap();
    assert_eq!(count, 1);

    let events: Vec<_> = list_all_events(&state)
        .into_iter()
        .filter(|e| e.event_type == "bootstrap.added")
        .collect();
    assert_eq!(events.len(), 1);
    assert!(events[0].summary.contains("SOUL.md"));
}

#[test]
fn bootstrap_file_changed_detected() {
    let (dir, mut state) = setup_state();
    let agents_dir = dir.path().join("agents");
    let workspace = agents_dir.join("default").join("agent");
    fs::create_dir_all(&workspace).unwrap();
    fs::write(workspace.join("SOUL.md"), "Version 1").unwrap();

    // First ingestion — file added
    let count1 = ingest_bootstrap_changes(&mut state, &agents_dir).unwrap();
    assert_eq!(count1, 1);

    // Modify the file
    fs::write(workspace.join("SOUL.md"), "Version 2 — updated content").unwrap();

    // Second ingestion — file changed
    let count2 = ingest_bootstrap_changes(&mut state, &agents_dir).unwrap();
    assert_eq!(count2, 1);

    let events: Vec<_> = list_all_events(&state)
        .into_iter()
        .filter(|e| e.event_type == "bootstrap.changed")
        .collect();
    assert_eq!(events.len(), 1);
    assert!(events[0].summary.contains("SOUL.md"));
    assert!(events[0].payload_json.contains("prev_hash"));
    assert!(events[0].payload_json.contains("new_hash"));
}

#[test]
fn bootstrap_file_removed_detected() {
    let (dir, mut state) = setup_state();
    let agents_dir = dir.path().join("agents");
    let workspace = agents_dir.join("default").join("agent");
    fs::create_dir_all(&workspace).unwrap();
    fs::write(workspace.join("AGENTS.md"), "Agent config here").unwrap();

    // First ingestion — file added
    ingest_bootstrap_changes(&mut state, &agents_dir).unwrap();

    // Remove the file
    fs::remove_file(workspace.join("AGENTS.md")).unwrap();

    // Second ingestion — file removed
    let count = ingest_bootstrap_changes(&mut state, &agents_dir).unwrap();
    assert_eq!(count, 1);

    let events: Vec<_> = list_all_events(&state)
        .into_iter()
        .filter(|e| e.event_type == "bootstrap.removed")
        .collect();
    assert_eq!(events.len(), 1);
    assert!(events[0].summary.contains("AGENTS.md"));
}

#[test]
fn bootstrap_no_agents_dir_clean() {
    let (_dir, mut state) = setup_state();
    let missing = PathBuf::from("/nonexistent/agents");

    let count = ingest_bootstrap_changes(&mut state, &missing).unwrap();
    assert_eq!(count, 0, "missing agents dir should return 0 events");
}
