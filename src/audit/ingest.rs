use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::Path;

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::{AuditCategory, AuditEvent, AuditSource};
use crate::state::db::StateStore;
use crate::state::model::NotificationCursorRecord;

const CONFIG_AUDIT_CURSOR_KEY: &str = "audit:config-audit.jsonl";

/// Run all passive ingestion sources against the given OpenClaw home directory.
/// Returns the number of new events ingested, or an error string.
pub fn run_passive_ingestion(
    state: &mut StateStore,
    openclaw_home: &Path,
) -> Result<usize, String> {
    let mut total = 0;

    let config_audit_path = openclaw_home.join("logs").join("config-audit.jsonl");
    total += ingest_config_audit_jsonl(state, &config_audit_path)
        .map_err(|e| format!("config-audit: {e}"))?;

    let skills_dir = openclaw_home.join("skills");
    total += ingest_skill_changes(state, &skills_dir).map_err(|e| format!("skill-changes: {e}"))?;

    let catalog_path = openclaw_home.join("plugins").join("catalog.json");
    total +=
        ingest_plugin_catalog(state, &catalog_path).map_err(|e| format!("plugin-catalog: {e}"))?;

    let agents_dir = openclaw_home.join("agents");
    total += ingest_bootstrap_changes(state, &agents_dir)
        .map_err(|e| format!("bootstrap-changes: {e}"))?;

    Ok(total)
}

/// Ingest new lines from `config-audit.jsonl`, tracking byte offset to avoid re-ingestion.
/// Detects file shrink/rotation and resets the cursor when needed.
pub fn ingest_config_audit_jsonl(
    state: &mut StateStore,
    jsonl_path: &Path,
) -> Result<usize, String> {
    if !jsonl_path.exists() {
        return Ok(0);
    }

    let file = fs::File::open(jsonl_path)
        .map_err(|e| format!("failed to open {}: {e}", jsonl_path.display()))?;
    let file_len = file.metadata().map(|m| m.len()).unwrap_or(0);

    let last_offset = state
        .notification_cursor(CONFIG_AUDIT_CURSOR_KEY)
        .map_err(|e| format!("cursor read: {e}"))?
        .map(|c| c.unix_ms)
        .unwrap_or(0);

    // Fix #3: Detect log rotation/truncation — if file shrank, reset cursor to 0
    let effective_offset = if file_len < last_offset {
        0
    } else {
        last_offset
    };

    if file_len == 0 || (file_len <= effective_offset && effective_offset > 0) {
        return Ok(0);
    }

    let mut reader = BufReader::new(file);
    if effective_offset > 0 {
        reader
            .seek(SeekFrom::Start(effective_offset))
            .map_err(|e| format!("seek: {e}"))?;
    }

    let mut events = Vec::new();
    let mut current_offset = effective_offset;
    let mut line = String::new();

    loop {
        line.clear();
        let bytes_read = reader
            .read_line(&mut line)
            .map_err(|e| format!("read: {e}"))?;
        if bytes_read == 0 {
            break;
        }
        current_offset += bytes_read as u64;

        // Security: skip lines exceeding 1 MiB to prevent memory exhaustion
        // from adversarially crafted JSONL with multi-GB lines
        if line.len() > 1_048_576 {
            continue;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let Ok(parsed) = serde_json::from_str::<Value>(trimmed) else {
            continue; // skip malformed lines
        };

        let event_type = parsed
            .get("event")
            .and_then(Value::as_str)
            .unwrap_or("config.write")
            .to_string();
        let ts_str = parsed.get("ts").and_then(Value::as_str).unwrap_or("");
        // Fix #4: Parse real ISO-8601 timestamp
        let event_at = parse_iso_timestamp_ms(ts_str);
        let result = parsed
            .get("result")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        // Fix #4: Read configPath (OpenClaw's actual field name), fallback to path
        let config_path = parsed
            .get("configPath")
            .or_else(|| parsed.get("path"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let summary = format!(
            "{event_type} ({result}){}",
            if config_path.is_empty() {
                String::new()
            } else {
                format!(" — {config_path}")
            }
        );

        let mut audit_event = AuditEvent::new_passive(
            event_at,
            AuditCategory::Config,
            &event_type,
            &summary,
            trimmed,
        );
        if !config_path.is_empty() {
            audit_event = audit_event.with_path(config_path);
        }
        events.push(audit_event);
    }

    let count = events.len();
    if !events.is_empty() {
        state
            .insert_audit_events(&events)
            .map_err(|e| format!("insert: {e}"))?;
    }

    state
        .set_notification_cursor(&NotificationCursorRecord {
            cursor_key: CONFIG_AUDIT_CURSOR_KEY.to_string(),
            unix_ms: current_offset,
        })
        .map_err(|e| format!("cursor write: {e}"))?;

    Ok(count)
}

/// Detect skill directory additions, removals, and modifications.
/// Fix #1: Uses file-level SHA-256 hashes instead of directory mtime for change detection.
/// Fix #2: Preserves previous snapshot on read failure to avoid false removals.
pub fn ingest_skill_changes(state: &mut StateStore, skills_dir: &Path) -> Result<usize, String> {
    // Fix #2: If the directory is unreadable, preserve previous snapshot and return 0
    let current_snapshot = match scan_skill_directory_hashes(skills_dir) {
        Some(snapshot) => snapshot,
        None => return Ok(0), // directory unreadable — preserve previous state
    };

    // Read previous snapshot from the latest "skill.snapshot" audit event
    let previous_snapshot: HashMap<String, String> =
        read_latest_snapshot_payload(state, "skill.snapshot")
            .and_then(|json| serde_json::from_str(&json).ok())
            .unwrap_or_default();

    let now = now_ms();
    let mut events = Vec::new();

    for (name, hash) in &current_snapshot {
        match previous_snapshot.get(name) {
            None => {
                events.push(
                    AuditEvent::new_passive(
                        now,
                        AuditCategory::Skill,
                        "skill.added",
                        format!("Skill installed: {name}"),
                        serde_json::json!({"name": name}).to_string(),
                    )
                    .with_path(skills_dir.join(name).to_string_lossy().to_string()),
                );
            }
            Some(prev_hash) if prev_hash != hash => {
                events.push(
                    AuditEvent::new_passive(
                        now,
                        AuditCategory::Skill,
                        "skill.changed",
                        format!("Skill modified: {name}"),
                        serde_json::json!({"name": name, "prev_hash": prev_hash, "new_hash": hash})
                            .to_string(),
                    )
                    .with_path(skills_dir.join(name).to_string_lossy().to_string()),
                );
            }
            _ => {}
        }
    }

    for name in previous_snapshot.keys() {
        if !current_snapshot.contains_key(name) {
            events.push(AuditEvent::new_passive(
                now,
                AuditCategory::Skill,
                "skill.removed",
                format!("Skill removed: {name}"),
                serde_json::json!({"name": name}).to_string(),
            ));
        }
    }

    let count = events.len();
    if !events.is_empty() {
        state
            .insert_audit_events(&events)
            .map_err(|e| format!("insert: {e}"))?;
    }

    // Persist current snapshot as an audit event for next-run diffing
    let snapshot_json =
        serde_json::to_string(&current_snapshot).unwrap_or_else(|_| "{}".to_string());
    state
        .insert_audit_events(&[AuditEvent {
            id: 0,
            recorded_at_unix_ms: now,
            event_at_unix_ms: now,
            category: AuditCategory::Skill,
            event_type: "skill.snapshot".to_string(),
            source: AuditSource::Passive,
            summary: format!("{} skills tracked", current_snapshot.len()),
            payload_json: snapshot_json,
            session_key: None,
            agent_id: None,
            path: None,
        }])
        .map_err(|e| format!("snapshot insert: {e}"))?;

    Ok(count)
}

/// Detect plugin catalog additions and removals.
/// Fix #2: Preserves previous snapshot on read/parse failure to avoid false removals.
pub fn ingest_plugin_catalog(state: &mut StateStore, catalog_path: &Path) -> Result<usize, String> {
    if !catalog_path.exists() {
        return Ok(0);
    }

    // Security: check file size before reading to prevent OOM from oversized catalog
    if let Ok(meta) = fs::metadata(catalog_path) {
        if meta.len() > 1_048_576 {
            return Ok(0); // >1 MiB — skip, consistent with DEFAULT_MAX_FILE_SIZE_BYTES
        }
    }

    // Fix #2: On read/parse failure, preserve previous snapshot
    let contents = match fs::read_to_string(catalog_path) {
        Ok(c) => c,
        Err(_) => return Ok(0), // unreadable — preserve previous state
    };
    let current_ids = extract_plugin_ids_from_catalog(&contents);
    if current_ids.is_empty() && !contents.trim().is_empty() {
        // Non-empty file but no IDs extracted — likely malformed, preserve previous state
        return Ok(0);
    }

    // Read previous snapshot from latest "plugin.snapshot" event
    let previous_ids = read_latest_snapshot_payload(state, "plugin.snapshot")
        .and_then(|json| serde_json::from_str::<Vec<String>>(&json).ok())
        .unwrap_or_default();

    let now = now_ms();
    let mut events = Vec::new();

    for id in &current_ids {
        if !previous_ids.contains(id) {
            events.push(
                AuditEvent::new_passive(
                    now,
                    AuditCategory::Plugin,
                    "plugin.installed",
                    format!("Plugin installed: {id}"),
                    serde_json::json!({"plugin_id": id}).to_string(),
                )
                .with_path(catalog_path.to_string_lossy().to_string()),
            );
        }
    }

    for id in &previous_ids {
        if !current_ids.contains(id) {
            events.push(AuditEvent::new_passive(
                now,
                AuditCategory::Plugin,
                "plugin.removed",
                format!("Plugin removed: {id}"),
                serde_json::json!({"plugin_id": id}).to_string(),
            ));
        }
    }

    let count = events.len();
    if !events.is_empty() {
        state
            .insert_audit_events(&events)
            .map_err(|e| format!("insert: {e}"))?;
    }

    // Persist current snapshot
    let snapshot_json = serde_json::to_string(&current_ids).unwrap_or_else(|_| "[]".to_string());
    state
        .insert_audit_events(&[AuditEvent {
            id: 0,
            recorded_at_unix_ms: now,
            event_at_unix_ms: now,
            category: AuditCategory::Plugin,
            event_type: "plugin.snapshot".to_string(),
            source: AuditSource::Passive,
            summary: format!("{} plugins tracked", current_ids.len()),
            payload_json: snapshot_json,
            session_key: None,
            agent_id: None,
            path: None,
        }])
        .map_err(|e| format!("snapshot insert: {e}"))?;

    Ok(count)
}

/// Detect bootstrap file additions, removals, and modifications across agent workspaces.
/// Uses the same snapshot diffing pattern as `ingest_skill_changes()`.
pub fn ingest_bootstrap_changes(
    state: &mut StateStore,
    agents_dir: &Path,
) -> Result<usize, String> {
    let current_snapshot = match hash_bootstrap_files(agents_dir) {
        Some(snapshot) => snapshot,
        None => return Ok(0), // directory unreadable — preserve previous state
    };

    let previous_snapshot: HashMap<String, String> =
        read_latest_snapshot_payload(state, "bootstrap.snapshot")
            .and_then(|json| serde_json::from_str(&json).ok())
            .unwrap_or_default();

    let now = now_ms();
    let mut events = Vec::new();

    for (rel_path, hash) in &current_snapshot {
        match previous_snapshot.get(rel_path) {
            None => {
                events.push(
                    AuditEvent::new_passive(
                        now,
                        AuditCategory::Config,
                        "bootstrap.added",
                        format!("Bootstrap file added: {rel_path}"),
                        serde_json::json!({"path": rel_path, "sha256": hash}).to_string(),
                    )
                    .with_path(agents_dir.join(rel_path).to_string_lossy().to_string()),
                );
            }
            Some(prev_hash) if prev_hash != hash => {
                events.push(
                    AuditEvent::new_passive(
                        now,
                        AuditCategory::Config,
                        "bootstrap.changed",
                        format!("Bootstrap file changed: {rel_path}"),
                        serde_json::json!({
                            "path": rel_path,
                            "prev_hash": prev_hash,
                            "new_hash": hash,
                        })
                        .to_string(),
                    )
                    .with_path(agents_dir.join(rel_path).to_string_lossy().to_string()),
                );
            }
            _ => {}
        }
    }

    for rel_path in previous_snapshot.keys() {
        if !current_snapshot.contains_key(rel_path) {
            events.push(AuditEvent::new_passive(
                now,
                AuditCategory::Config,
                "bootstrap.removed",
                format!("Bootstrap file removed: {rel_path}"),
                serde_json::json!({"path": rel_path}).to_string(),
            ));
        }
    }

    let count = events.len();
    if !events.is_empty() {
        state
            .insert_audit_events(&events)
            .map_err(|e| format!("insert: {e}"))?;
    }

    // Count workspaces for summary
    let workspace_count = current_snapshot
        .keys()
        .filter_map(|p| p.split('/').next())
        .collect::<std::collections::HashSet<_>>()
        .len();
    let snapshot_json =
        serde_json::to_string(&current_snapshot).unwrap_or_else(|_| "{}".to_string());
    state
        .insert_audit_events(&[AuditEvent {
            id: 0,
            recorded_at_unix_ms: now,
            event_at_unix_ms: now,
            category: AuditCategory::Config,
            event_type: "bootstrap.snapshot".to_string(),
            source: AuditSource::Passive,
            summary: format!(
                "Bootstrap snapshot: {} files across {} workspaces",
                current_snapshot.len(),
                workspace_count
            ),
            payload_json: snapshot_json,
            session_key: None,
            agent_id: None,
            path: None,
        }])
        .map_err(|e| format!("snapshot insert: {e}"))?;

    Ok(count)
}

/// Maximum file size for bootstrap hashing (same bound as scan_workspace).
const BOOTSTRAP_MAX_HASH_BYTES: u64 = 1_048_576; // 1 MiB

/// Hash all bootstrap files across agent workspace directories.
/// Returns None if the agents directory is unreadable.
/// Skips symlinks and oversized files to prevent oracle attacks and OOM.
fn hash_bootstrap_files(agents_dir: &Path) -> Option<HashMap<String, String>> {
    use crate::scan::bootstrap::{discover_workspace_dirs, BOOTSTRAP_FILES};

    if !agents_dir.exists() || !agents_dir.is_dir() {
        return None;
    }

    let workspaces = discover_workspace_dirs(agents_dir);
    let mut snapshot = HashMap::new();

    for workspace in &workspaces {
        for file_name in BOOTSTRAP_FILES {
            let file_path = workspace.join(file_name);

            // Skip symlinks to prevent oracle attacks (hash known-file contents)
            let Ok(meta) = fs::symlink_metadata(&file_path) else {
                continue;
            };
            if meta.file_type().is_symlink() || !meta.is_file() {
                continue;
            }
            // Skip oversized files to prevent OOM
            if meta.len() > BOOTSTRAP_MAX_HASH_BYTES {
                continue;
            }

            let Ok(contents) = fs::read(&file_path) else {
                continue;
            };
            let mut hasher = Sha256::new();
            hasher.update(&contents);
            let hash = format!("sha256:{:x}", hasher.finalize());

            // Relative path from agents_dir for readability
            let rel = file_path
                .strip_prefix(agents_dir)
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| file_path.to_string_lossy().to_string());
            snapshot.insert(rel, hash);
        }
    }

    Some(snapshot)
}

// ---- Helpers ----

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Parse an ISO 8601 timestamp string into Unix milliseconds.
/// Supports formats: "2026-04-02T10:15:03.123Z", "2026-04-02T10:15:03Z", "2026-04-02T10:15:03"
/// Falls back to now_ms() on parse failure.
pub fn parse_iso_timestamp_ms(ts: &str) -> u64 {
    if ts.is_empty() {
        return now_ms();
    }

    // Extract date and time parts
    let ts = ts.trim().trim_end_matches('Z');
    let parts: Vec<&str> = ts.split('T').collect();
    if parts.len() != 2 {
        return now_ms();
    }

    let date_parts: Vec<u64> = parts[0].split('-').filter_map(|p| p.parse().ok()).collect();
    if date_parts.len() != 3 {
        return now_ms();
    }
    let (year, month, day) = (date_parts[0], date_parts[1], date_parts[2]);

    // Parse time, handling optional fractional seconds
    let time_str = parts[1].split('.').next().unwrap_or("");
    let time_parts: Vec<u64> = time_str.split(':').filter_map(|p| p.parse().ok()).collect();
    if time_parts.len() != 3 {
        return now_ms();
    }
    let (hour, minute, second) = (time_parts[0], time_parts[1], time_parts[2]);

    // Convert to Unix timestamp (simplified, assumes UTC, no leap seconds)
    let mut days: u64 = 0;
    for y in 1970..year {
        days += if is_leap_year(y) { 366 } else { 365 };
    }
    let month_days = [
        31,
        if is_leap_year(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    for m in 0..(month.saturating_sub(1) as usize) {
        if m < 12 {
            days += month_days[m];
        }
    }
    days += day.saturating_sub(1);

    let secs = days * 86400 + hour * 3600 + minute * 60 + second;
    secs * 1000
}

fn is_leap_year(y: u64) -> bool {
    y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
}

/// Fix #1: Scan skill directories using file-level SHA-256 hashes instead of dir mtime.
/// Returns None if the directory is unreadable (Fix #2).
fn scan_skill_directory_hashes(dir: &Path) -> Option<HashMap<String, String>> {
    let entries = fs::read_dir(dir).ok()?;
    let mut snapshot = HashMap::new();
    for entry in entries.flatten() {
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if !meta.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        let hash = hash_skill_directory(&entry.path());
        snapshot.insert(name, hash);
    }
    Some(snapshot)
}

/// Compute a composite SHA-256 hash over security-relevant files in a skill directory.
/// Walks recursively to catch nested scripts/, bin/, references/ content.
fn hash_skill_directory(skill_dir: &Path) -> String {
    let mut hasher = Sha256::new();
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    collect_hashable_files(skill_dir, &mut files);
    files.sort();
    for file in &files {
        // Include relative path in hash so renames are detected
        if let Ok(rel) = file.strip_prefix(skill_dir) {
            hasher.update(rel.to_string_lossy().as_bytes());
        }
        if let Ok(contents) = fs::read(file) {
            hasher.update(&contents);
        }
    }
    format!("{:x}", hasher.finalize())
}

fn collect_hashable_files(dir: &Path, files: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_hashable_files(&path, files);
        } else if path.is_file() && is_hashable_skill_file(&path) {
            files.push(path);
        }
    }
}

fn is_hashable_skill_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let lower = name.to_lowercase();
    lower == "skill.md"
        || lower == "hook.md"
        || lower == "package.json"
        || lower.ends_with(".js")
        || lower.ends_with(".ts")
        || lower.ends_with(".mjs")
        || lower.ends_with(".cjs")
        || lower.ends_with(".sh")
        || lower.ends_with(".py")
}

/// Parse plugin IDs from OpenClaw's catalog.json.
/// Real upstream format: `{ entries: [{ name: "@openclaw/plugin-name", openclaw: { ... } }] }`
/// Also supports flat object format `{ "plugin-id": { ... } }` as fallback.
fn extract_plugin_ids_from_catalog(contents: &str) -> Vec<String> {
    let Ok(parsed) = serde_json::from_str::<Value>(contents) else {
        return Vec::new();
    };
    let Some(obj) = parsed.as_object() else {
        return Vec::new();
    };

    // Primary: { entries: [ { name: "..." } ] } (upstream schema)
    if let Some(entries) = obj.get("entries").and_then(Value::as_array) {
        let ids: Vec<String> = entries
            .iter()
            .filter_map(|entry| {
                entry
                    .get("name")
                    .or_else(|| {
                        entry
                            .get("openclaw")
                            .and_then(|oc| oc.get("channel"))
                            .and_then(|ch| ch.get("id"))
                    })
                    .and_then(Value::as_str)
                    .map(String::from)
            })
            .collect();
        if !ids.is_empty() {
            return ids;
        }
    }

    // Fallback: flat object where keys are plugin IDs (e.g. plugins.entries in openclaw.json)
    // Skip known wrapper keys
    obj.keys()
        .filter(|k| *k != "entries" && *k != "version" && *k != "schema")
        .cloned()
        .collect()
}

fn read_latest_snapshot_payload(state: &StateStore, event_type: &str) -> Option<String> {
    state
        .latest_audit_event_by_type(event_type)
        .ok()?
        .map(|e| e.payload_json)
}
