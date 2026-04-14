use std::fmt::{Display, Formatter};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, Error as SqlError, ErrorCode, OptionalExtension, Params};

use crate::scan::Finding;

use super::model::{
    AlertRecord, AlertStats, AlertStatus, BaselineRecord, NotificationCursorRecord,
    NotificationReceiptRecord, RestorePayloadRecord, ScanSnapshot, ScanStats, StateWarning,
    StateWarningKind,
};

const DEFAULT_BUSY_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_LOCK_RETRY_COUNT: u32 = 3;
const DEFAULT_LOCK_RETRY_BACKOFF_MS: u64 = 100;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateStoreConfig {
    path: PathBuf,
    busy_timeout_ms: u64,
    lock_retry_count: u32,
    lock_retry_backoff_ms: u64,
}

impl StateStoreConfig {
    pub fn for_path(path: PathBuf) -> Self {
        Self {
            path,
            busy_timeout_ms: DEFAULT_BUSY_TIMEOUT_MS,
            lock_retry_count: DEFAULT_LOCK_RETRY_COUNT,
            lock_retry_backoff_ms: DEFAULT_LOCK_RETRY_BACKOFF_MS,
        }
    }

    pub fn with_busy_timeout_ms(mut self, busy_timeout_ms: u64) -> Self {
        self.busy_timeout_ms = busy_timeout_ms;
        self
    }

    pub fn with_lock_retry_count(mut self, lock_retry_count: u32) -> Self {
        self.lock_retry_count = lock_retry_count;
        self
    }

    pub fn with_lock_retry_backoff_ms(mut self, lock_retry_backoff_ms: u64) -> Self {
        self.lock_retry_backoff_ms = lock_retry_backoff_ms;
        self
    }
}

#[derive(Debug)]
pub struct StateOpenResult {
    pub store: StateStore,
    pub warnings: Vec<StateWarning>,
}

#[derive(Debug)]
pub struct StateStore {
    path: PathBuf,
    conn: Connection,
    lock_retry_count: u32,
    lock_retry_backoff_ms: u64,
}

impl StateStore {
    pub fn open(config: StateStoreConfig) -> Result<StateOpenResult, StateStoreError> {
        if let Some(parent) = config.path.parent() {
            fs::create_dir_all(parent).map_err(|error| StateStoreError::Open {
                message: format!(
                    "failed to create state database directory {}: {error}",
                    parent.display()
                ),
            })?;
        }

        if !config.path.exists() {
            let conn = open_connection(&config.path, config.busy_timeout_ms)?;
            return Ok(StateOpenResult {
                store: Self {
                    path: config.path,
                    conn,
                    lock_retry_count: config.lock_retry_count,
                    lock_retry_backoff_ms: config.lock_retry_backoff_ms,
                },
                warnings: Vec::new(),
            });
        }

        match open_connection(&config.path, config.busy_timeout_ms) {
            Ok(conn) => Ok(StateOpenResult {
                store: Self {
                    path: config.path,
                    conn,
                    lock_retry_count: config.lock_retry_count,
                    lock_retry_backoff_ms: config.lock_retry_backoff_ms,
                },
                warnings: Vec::new(),
            }),
            Err(error) if is_corrupt_database_error(&error) => {
                let renamed_path = rename_corrupt_database(&config.path)?;
                let recreated_path = config.path.display().to_string();
                let conn = open_connection(&config.path, config.busy_timeout_ms)?;

                Ok(StateOpenResult {
                    store: Self {
                        path: config.path,
                        conn,
                        lock_retry_count: config.lock_retry_count,
                        lock_retry_backoff_ms: config.lock_retry_backoff_ms,
                    },
                    warnings: vec![StateWarning {
                        kind: StateWarningKind::DatabaseCorruptRecreated,
                        message: format!(
                            "ClawGuard detected a corrupt state database at {} and moved it aside to {} before recreating a fresh database.",
                            recreated_path,
                            renamed_path.display()
                        ),
                        path: Some(renamed_path),
                    }],
                })
            }
            Err(error) => Err(error),
        }
    }

    pub fn latest_scan_snapshot(&self) -> Result<Option<ScanSnapshot>, StateStoreError> {
        let mut statement = self.conn.prepare(
            "SELECT snapshot_json FROM scan_snapshots ORDER BY recorded_at_unix_ms DESC, id DESC LIMIT 1",
        )?;
        let mut rows = statement.query([])?;

        let Some(row) = rows.next()? else {
            return Ok(None);
        };

        let snapshot_json: String = row.get(0)?;
        let snapshot =
            serde_json::from_str(&snapshot_json).map_err(|error| StateStoreError::Serialize {
                message: format!("failed to deserialize stored snapshot: {error}"),
            })?;

        Ok(Some(snapshot))
    }

    pub fn record_scan_snapshot(
        &mut self,
        snapshot: &ScanSnapshot,
        posture_score: Option<f64>,
    ) -> Result<(), StateStoreError> {
        let (snapshot_json, summary_json) = serialize_snapshot(snapshot)?;

        self.run_write_with_retry(|conn| {
            conn.execute(
                "INSERT INTO scan_snapshots (recorded_at_unix_ms, summary_json, snapshot_json, posture_score)
                 VALUES (?1, ?2, ?3, ?4)",
                (
                    snapshot.recorded_at_unix_ms as i64,
                    &summary_json,
                    &snapshot_json,
                    posture_score,
                ),
            )?;

            Ok(())
        })
    }

    pub fn replace_current_findings(
        &mut self,
        findings: &[Finding],
    ) -> Result<(), StateStoreError> {
        let serialized_findings = serialize_current_findings(findings)?;

        self.run_write_with_retry(|conn| {
            let transaction = conn.unchecked_transaction()?;
            transaction.execute("DELETE FROM current_findings", [])?;

            for (position, finding_id, finding_json) in &serialized_findings {
                transaction.execute(
                    "INSERT INTO current_findings (position, finding_id, finding_json)
                     VALUES (?1, ?2, ?3)",
                    (position, finding_id, finding_json),
                )?;
            }

            transaction.commit()?;

            Ok(())
        })
    }

    pub fn record_scan_snapshot_and_replace_current_findings(
        &mut self,
        snapshot: &ScanSnapshot,
        posture_score: Option<f64>,
    ) -> Result<(), StateStoreError> {
        let (snapshot_json, summary_json) = serialize_snapshot(snapshot)?;
        let serialized_findings = serialize_current_findings(&snapshot.findings)?;

        self.run_write_with_retry(|conn| {
            let transaction = conn.unchecked_transaction()?;
            transaction.execute(
                "INSERT INTO scan_snapshots (recorded_at_unix_ms, summary_json, snapshot_json, posture_score)
                 VALUES (?1, ?2, ?3, ?4)",
                (
                    snapshot.recorded_at_unix_ms as i64,
                    &summary_json,
                    &snapshot_json,
                    posture_score,
                ),
            )?;
            transaction.execute("DELETE FROM current_findings", [])?;

            for (position, finding_id, finding_json) in &serialized_findings {
                transaction.execute(
                    "INSERT INTO current_findings (position, finding_id, finding_json)
                     VALUES (?1, ?2, ?3)",
                    (position, finding_id, finding_json),
                )?;
            }

            transaction.commit()?;

            Ok(())
        })
    }

    pub fn list_current_findings(&self) -> Result<Vec<Finding>, StateStoreError> {
        let mut statement = self
            .conn
            .prepare("SELECT finding_json FROM current_findings ORDER BY position ASC")?;
        let finding_rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut findings = Vec::new();

        for finding_row in finding_rows {
            let finding_json = finding_row?;
            let finding = serde_json::from_str(&finding_json).map_err(|error| {
                StateStoreError::Serialize {
                    message: format!("failed to deserialize current finding: {error}"),
                }
            })?;
            findings.push(finding);
        }

        Ok(findings)
    }

    pub fn upsert_baseline(&mut self, baseline: &BaselineRecord) -> Result<(), StateStoreError> {
        self.run_write_with_retry(|conn| {
            conn.execute(
                "INSERT INTO baselines (path, sha256, approved_at_unix_ms, source_label, git_remote_url, git_head_sha)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(path) DO UPDATE SET
                     sha256 = excluded.sha256,
                     approved_at_unix_ms = excluded.approved_at_unix_ms,
                     source_label = excluded.source_label,
                     git_remote_url = excluded.git_remote_url,
                     git_head_sha = excluded.git_head_sha",
                (
                    &baseline.path,
                    &baseline.sha256,
                    baseline.approved_at_unix_ms as i64,
                    &baseline.source_label,
                    &baseline.git_remote_url,
                    &baseline.git_head_sha,
                ),
            )?;

            Ok(())
        })
    }

    pub fn replace_baselines_for_source(
        &mut self,
        source_label: &str,
        baselines: &[BaselineRecord],
    ) -> Result<(), StateStoreError> {
        for baseline in baselines {
            if baseline.source_label != source_label {
                return Err(StateStoreError::Query {
                    message: format!(
                        "baseline source_label mismatch for path {}: expected {source_label}, found {}",
                        baseline.path, baseline.source_label
                    ),
                });
            }
        }

        self.run_write_with_retry(|conn| {
            let transaction = conn.unchecked_transaction()?;

            for baseline in baselines {
                let existing_source_label: Option<String> = transaction
                    .query_row(
                        "SELECT source_label FROM baselines WHERE path = ?1",
                        [&baseline.path],
                        |row| row.get(0),
                    )
                    .optional()?;

                if let Some(existing_source_label) = existing_source_label {
                    if existing_source_label != source_label {
                        return Err(StateStoreError::Query {
                            message: format!(
                                "baseline path {} is already owned by source {}",
                                baseline.path, existing_source_label
                            ),
                        });
                    }
                }
            }

            transaction.execute(
                "DELETE FROM baselines WHERE source_label = ?1",
                [source_label],
            )?;

            for baseline in baselines {
                transaction.execute(
                    "INSERT INTO baselines (path, sha256, approved_at_unix_ms, source_label, git_remote_url, git_head_sha)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                     ON CONFLICT(path) DO UPDATE SET
                         sha256 = excluded.sha256,
                         approved_at_unix_ms = excluded.approved_at_unix_ms,
                         source_label = excluded.source_label,
                         git_remote_url = excluded.git_remote_url,
                         git_head_sha = excluded.git_head_sha",
                    (
                        &baseline.path,
                        &baseline.sha256,
                        baseline.approved_at_unix_ms as i64,
                        &baseline.source_label,
                        &baseline.git_remote_url,
                        &baseline.git_head_sha,
                    ),
                )?;
            }

            transaction.commit()?;

            Ok(())
        })
    }

    pub fn list_baselines(&self) -> Result<Vec<BaselineRecord>, StateStoreError> {
        let mut statement = self.conn.prepare(
            "SELECT path, sha256, approved_at_unix_ms, source_label, git_remote_url, git_head_sha
             FROM baselines
             ORDER BY path ASC",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(BaselineRecord {
                path: row.get(0)?,
                sha256: row.get(1)?,
                approved_at_unix_ms: row.get::<_, i64>(2)? as u64,
                source_label: row.get(3)?,
                git_remote_url: row.get(4)?,
                git_head_sha: row.get(5)?,
            })
        })?;

        let mut baselines = Vec::new();
        for row in rows {
            baselines.push(row?);
        }

        Ok(baselines)
    }

    pub fn baseline_for_path(
        &self,
        requested_path: &str,
    ) -> Result<Option<BaselineRecord>, StateStoreError> {
        let mut statement = self.conn.prepare(
            "SELECT path, sha256, approved_at_unix_ms, source_label, git_remote_url, git_head_sha
             FROM baselines
             WHERE path = ?1",
        )?;
        let mut rows = statement.query([requested_path])?;

        let Some(row) = rows.next()? else {
            return Ok(None);
        };

        Ok(Some(BaselineRecord {
            path: row.get(0)?,
            sha256: row.get(1)?,
            approved_at_unix_ms: row.get::<_, i64>(2)? as u64,
            source_label: row.get(3)?,
            git_remote_url: row.get(4)?,
            git_head_sha: row.get(5)?,
        }))
    }

    pub fn replace_restore_payloads_for_source(
        &mut self,
        source_label: &str,
        payloads: &[RestorePayloadRecord],
    ) -> Result<(), StateStoreError> {
        for payload in payloads {
            if payload.source_label != source_label {
                return Err(StateStoreError::Query {
                    message: format!(
                        "restore payload source_label mismatch for path {}: expected {source_label}, found {}",
                        payload.path, payload.source_label
                    ),
                });
            }
        }

        self.run_write_with_retry(|conn| {
            let transaction = conn.unchecked_transaction()?;

            for payload in payloads {
                let existing_source_label: Option<String> = transaction
                    .query_row(
                        "SELECT source_label FROM restore_payloads WHERE path = ?1",
                        [&payload.path],
                        |row| row.get(0),
                    )
                    .optional()?;

                if let Some(existing_source_label) = existing_source_label {
                    if existing_source_label != source_label {
                        return Err(StateStoreError::Query {
                            message: format!(
                                "restore payload path {} is already owned by source {}",
                                payload.path, existing_source_label
                            ),
                        });
                    }
                }
            }

            transaction.execute(
                "DELETE FROM restore_payloads WHERE source_label = ?1",
                [source_label],
            )?;

            for payload in payloads {
                transaction.execute(
                    "INSERT INTO restore_payloads (path, sha256, captured_at_unix_ms, source_label, content)
                     VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT(path) DO UPDATE SET
                         sha256 = excluded.sha256,
                         captured_at_unix_ms = excluded.captured_at_unix_ms,
                         source_label = excluded.source_label,
                         content = excluded.content",
                    (
                        &payload.path,
                        &payload.sha256,
                        payload.captured_at_unix_ms as i64,
                        &payload.source_label,
                        &payload.content,
                    ),
                )?;
            }

            transaction.commit()?;

            Ok(())
        })
    }

    pub fn restore_payload_for_path(
        &self,
        requested_path: &str,
    ) -> Result<Option<RestorePayloadRecord>, StateStoreError> {
        let mut statement = self.conn.prepare(
            "SELECT path, sha256, captured_at_unix_ms, source_label, content
             FROM restore_payloads
             WHERE path = ?1",
        )?;
        let mut rows = statement.query([requested_path])?;

        let Some(row) = rows.next()? else {
            return Ok(None);
        };

        Ok(Some(RestorePayloadRecord {
            path: row.get(0)?,
            sha256: row.get(1)?,
            captured_at_unix_ms: row.get::<_, i64>(2)? as u64,
            source_label: row.get(3)?,
            content: row.get(4)?,
        }))
    }

    pub fn append_alert(&mut self, alert: &AlertRecord) -> Result<(), StateStoreError> {
        let finding_json =
            serde_json::to_string(&alert.finding).map_err(|error| StateStoreError::Serialize {
                message: format!("failed to serialize alert finding: {error}"),
            })?;

        self.run_write_with_retry(|conn| {
            conn.execute(
                "INSERT INTO alerts (alert_id, finding_id, status, created_at_unix_ms, finding_json)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                (
                    &alert.alert_id,
                    &alert.finding_id,
                    status_as_str(alert.status),
                    alert.created_at_unix_ms as i64,
                    &finding_json,
                ),
            )?;

            Ok(())
        })
    }

    pub fn list_unresolved_alerts(&self) -> Result<Vec<AlertRecord>, StateStoreError> {
        self.query_alerts(
            "SELECT alert_id, finding_id, status, created_at_unix_ms, finding_json
             FROM alerts
             WHERE status IN ('open', 'acknowledged')
             ORDER BY created_at_unix_ms ASC, alert_id ASC",
            [],
        )
    }

    pub fn list_recent_alerts(&self, limit: usize) -> Result<Vec<AlertRecord>, StateStoreError> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        self.query_alerts(
            "SELECT alert_id, finding_id, status, created_at_unix_ms, finding_json
             FROM alerts
             ORDER BY created_at_unix_ms DESC, alert_id DESC
             LIMIT ?1",
            [i64::try_from(limit).unwrap_or(i64::MAX)],
        )
    }

    pub fn list_open_alerts(&self) -> Result<Vec<AlertRecord>, StateStoreError> {
        self.query_alerts(
            "SELECT alert_id, finding_id, status, created_at_unix_ms, finding_json
             FROM alerts
             WHERE status = 'open'
             ORDER BY created_at_unix_ms ASC, alert_id ASC",
            [],
        )
    }

    pub fn list_undelivered_alerts_for_route(
        &self,
        delivery_route: &str,
    ) -> Result<Vec<AlertRecord>, StateStoreError> {
        self.query_alerts(
            "SELECT a.alert_id, a.finding_id, a.status, a.created_at_unix_ms, a.finding_json
             FROM alerts a
             LEFT JOIN notification_receipts r
               ON r.alert_id = a.alert_id
              AND r.delivery_route = ?1
             WHERE a.status IN ('open', 'acknowledged')
               AND r.alert_id IS NULL
             ORDER BY a.created_at_unix_ms ASC, a.alert_id ASC",
            [delivery_route],
        )
    }

    pub fn list_alerts_created_after(
        &self,
        unix_ms_exclusive: u64,
    ) -> Result<Vec<AlertRecord>, StateStoreError> {
        self.query_alerts(
            "SELECT alert_id, finding_id, status, created_at_unix_ms, finding_json
             FROM alerts
             WHERE created_at_unix_ms > ?1
             ORDER BY created_at_unix_ms ASC, alert_id ASC",
            [unix_ms_exclusive as i64],
        )
    }

    pub fn list_open_alerts_created_after(
        &self,
        unix_ms_exclusive: u64,
    ) -> Result<Vec<AlertRecord>, StateStoreError> {
        self.query_alerts(
            "SELECT alert_id, finding_id, status, created_at_unix_ms, finding_json
             FROM alerts
             WHERE status = 'open'
               AND created_at_unix_ms > ?1
             ORDER BY created_at_unix_ms ASC, alert_id ASC",
            [unix_ms_exclusive as i64],
        )
    }

    pub fn alert_by_id(&self, alert_id: &str) -> Result<Option<AlertRecord>, StateStoreError> {
        let mut statement = self.conn.prepare(
            "SELECT alert_id, finding_id, status, created_at_unix_ms, finding_json
             FROM alerts
             WHERE alert_id = ?1
             LIMIT 1",
        )?;
        let mut rows = statement.query([alert_id])?;

        let Some(row) = rows.next()? else {
            return Ok(None);
        };

        Ok(Some(alert_record_from_row(row)?))
    }

    pub fn count_acknowledged_alerts(&self) -> Result<usize, StateStoreError> {
        let count = self.conn.query_row(
            "SELECT COUNT(*) FROM alerts WHERE status = 'acknowledged'",
            [],
            |row| row.get::<_, i64>(0),
        )?;

        Ok(count.max(0) as usize)
    }

    pub fn update_alert_status(
        &mut self,
        alert_id: &str,
        status: AlertStatus,
    ) -> Result<(), StateStoreError> {
        self.run_write_with_retry(|conn| {
            let rows_affected = conn.execute(
                "UPDATE alerts SET status = ?1 WHERE alert_id = ?2",
                (status_as_str(status), alert_id),
            )?;

            if rows_affected == 0 {
                return Err(StateStoreError::Query {
                    message: format!("no stored alert exists with id {alert_id}"),
                });
            }

            Ok(())
        })
    }

    pub fn record_notification_receipt(
        &mut self,
        receipt: &NotificationReceiptRecord,
    ) -> Result<(), StateStoreError> {
        self.run_write_with_retry(|conn| {
            conn.execute(
                "INSERT INTO notification_receipts (alert_id, delivery_route, delivered_at_unix_ms)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(alert_id, delivery_route) DO UPDATE SET
                     delivered_at_unix_ms = excluded.delivered_at_unix_ms",
                (
                    &receipt.alert_id,
                    &receipt.delivery_route,
                    receipt.delivered_at_unix_ms as i64,
                ),
            )?;

            Ok(())
        })
    }

    pub fn notification_receipt_for_alert(
        &self,
        alert_id: &str,
        delivery_route: &str,
    ) -> Result<Option<NotificationReceiptRecord>, StateStoreError> {
        let mut statement = self.conn.prepare(
            "SELECT alert_id, delivery_route, delivered_at_unix_ms
             FROM notification_receipts
             WHERE alert_id = ?1 AND delivery_route = ?2",
        )?;
        let mut rows = statement.query((alert_id, delivery_route))?;

        let Some(row) = rows.next()? else {
            return Ok(None);
        };

        Ok(Some(NotificationReceiptRecord {
            alert_id: row.get(0)?,
            delivery_route: row.get(1)?,
            delivered_at_unix_ms: row.get::<_, i64>(2)? as u64,
        }))
    }

    pub fn set_notification_cursor(
        &mut self,
        cursor: &NotificationCursorRecord,
    ) -> Result<(), StateStoreError> {
        self.run_write_with_retry(|conn| {
            conn.execute(
                "INSERT INTO notification_cursors (cursor_key, unix_ms)
                 VALUES (?1, ?2)
                 ON CONFLICT(cursor_key) DO UPDATE SET
                     unix_ms = excluded.unix_ms",
                (&cursor.cursor_key, cursor.unix_ms as i64),
            )?;

            Ok(())
        })
    }

    pub fn notification_cursor(
        &self,
        cursor_key: &str,
    ) -> Result<Option<NotificationCursorRecord>, StateStoreError> {
        let mut statement = self.conn.prepare(
            "SELECT cursor_key, unix_ms
             FROM notification_cursors
             WHERE cursor_key = ?1",
        )?;
        let mut rows = statement.query([cursor_key])?;

        let Some(row) = rows.next()? else {
            return Ok(None);
        };

        Ok(Some(NotificationCursorRecord {
            cursor_key: row.get(0)?,
            unix_ms: row.get::<_, i64>(1)? as u64,
        }))
    }

    // ---- Audit events ----

    pub fn insert_audit_events(
        &mut self,
        events: &[crate::audit::AuditEvent],
    ) -> Result<(), StateStoreError> {
        if events.is_empty() {
            return Ok(());
        }
        self.run_write_with_retry(|conn| {
            let transaction = conn.unchecked_transaction()?;
            for event in events {
                transaction.execute(
                    "INSERT INTO audit_events
                        (recorded_at_unix_ms, event_at_unix_ms, category, event_type, source,
                         summary, payload_json, session_key, agent_id, path)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    (
                        event.recorded_at_unix_ms as i64,
                        event.event_at_unix_ms as i64,
                        event.category.as_str(),
                        &event.event_type,
                        event.source.as_str(),
                        &event.summary,
                        &event.payload_json,
                        &event.session_key,
                        &event.agent_id,
                        &event.path,
                    ),
                )?;
            }
            transaction.commit()?;
            Ok(())
        })
    }

    pub fn list_audit_events(
        &self,
        category: Option<&str>,
        since_unix_ms: Option<u64>,
        limit: u32,
    ) -> Result<Vec<crate::audit::AuditEvent>, StateStoreError> {
        let mut sql = String::from(
            "SELECT id, recorded_at_unix_ms, event_at_unix_ms, category, event_type, source,
                    summary, payload_json, session_key, agent_id, path
             FROM audit_events",
        );
        let mut conditions: Vec<String> = Vec::new();
        if category.is_some() {
            conditions.push("category = ?1".to_string());
        }
        if since_unix_ms.is_some() {
            let param_idx = if category.is_some() { 2 } else { 1 };
            conditions.push(format!("event_at_unix_ms >= ?{param_idx}"));
        }
        if !conditions.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&conditions.join(" AND "));
        }
        sql.push_str(" ORDER BY event_at_unix_ms DESC, id DESC");
        let limit_param = if category.is_some() && since_unix_ms.is_some() {
            3
        } else if category.is_some() || since_unix_ms.is_some() {
            2
        } else {
            1
        };
        sql.push_str(&format!(" LIMIT ?{limit_param}"));

        let mut statement = self.conn.prepare(&sql)?;

        let rows = match (category, since_unix_ms) {
            (Some(cat), Some(since)) => {
                statement.query_map((cat, since as i64, limit), audit_event_from_row)?
            }
            (Some(cat), None) => statement.query_map((cat, limit), audit_event_from_row)?,
            (None, Some(since)) => {
                statement.query_map((since as i64, limit), audit_event_from_row)?
            }
            (None, None) => statement.query_map([limit], audit_event_from_row)?,
        };

        let mut events = Vec::new();
        for row in rows {
            events.push(row?);
        }
        Ok(events)
    }

    pub fn latest_audit_event_by_type(
        &self,
        event_type: &str,
    ) -> Result<Option<crate::audit::AuditEvent>, StateStoreError> {
        let mut statement = self.conn.prepare(
            "SELECT id, recorded_at_unix_ms, event_at_unix_ms, category, event_type, source,
                    summary, payload_json, session_key, agent_id, path
             FROM audit_events
             WHERE event_type = ?1
             ORDER BY id DESC
             LIMIT 1",
        )?;
        let mut rows = statement.query([event_type])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        Ok(Some(audit_event_from_row(row)?))
    }

    pub fn list_restore_payloads(&self) -> Result<Vec<RestorePayloadRecord>, StateStoreError> {
        let mut statement = self.conn.prepare(
            "SELECT path, sha256, captured_at_unix_ms, source_label, content
             FROM restore_payloads
             ORDER BY path ASC",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(RestorePayloadRecord {
                path: row.get(0)?,
                sha256: row.get(1)?,
                captured_at_unix_ms: row.get::<_, i64>(2)? as u64,
                source_label: row.get(3)?,
                content: row.get(4)?,
            })
        })?;

        let mut payloads = Vec::new();
        for row in rows {
            payloads.push(row?);
        }

        Ok(payloads)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn query_alerts<P: Params>(
        &self,
        query: &str,
        params: P,
    ) -> Result<Vec<AlertRecord>, StateStoreError> {
        let mut statement = self.conn.prepare(query)?;
        let rows = statement.query_map(params, alert_record_from_row)?;

        let mut alerts = Vec::new();
        for row in rows {
            alerts.push(row?);
        }

        Ok(alerts)
    }

    // ---- Stats aggregation queries ----

    pub fn count_scan_snapshots(
        &self,
        since_unix_ms: Option<u64>,
    ) -> Result<ScanStats, StateStoreError> {
        let (sql, params): (&str, Vec<Box<dyn rusqlite::types::ToSql>>) = match since_unix_ms {
            Some(since) => (
                "SELECT COUNT(*), MIN(recorded_at_unix_ms), MAX(recorded_at_unix_ms) FROM scan_snapshots WHERE recorded_at_unix_ms >= ?1",
                vec![Box::new(since as i64)],
            ),
            None => (
                "SELECT COUNT(*), MIN(recorded_at_unix_ms), MAX(recorded_at_unix_ms) FROM scan_snapshots",
                vec![],
            ),
        };
        let mut statement = self.conn.prepare(sql)?;
        let row = statement.query_row(rusqlite::params_from_iter(params.iter()), |row| {
            let total = row.get::<_, i64>(0)? as u64;
            let first: Option<i64> = row.get(1)?;
            let last: Option<i64> = row.get(2)?;
            Ok(ScanStats {
                total,
                first_at_unix_ms: first.map(|v| v as u64),
                last_at_unix_ms: last.map(|v| v as u64),
            })
        })?;
        Ok(row)
    }

    /// Returns the most recent posture score before the current scan, if any.
    pub fn previous_posture_score(&self) -> Result<Option<f64>, StateStoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT posture_score FROM scan_snapshots
             WHERE posture_score IS NOT NULL
             ORDER BY recorded_at_unix_ms DESC, id DESC
             LIMIT 1 OFFSET 1",
        )?;
        let mut rows = stmt.query([])?;
        match rows.next()? {
            Some(row) => Ok(row.get(0)?),
            None => Ok(None),
        }
    }

    pub fn earliest_scan_snapshot(
        &self,
        since_unix_ms: Option<u64>,
    ) -> Result<Option<ScanSnapshot>, StateStoreError> {
        let (sql, params): (&str, Vec<Box<dyn rusqlite::types::ToSql>>) = match since_unix_ms {
            Some(since) => (
                "SELECT snapshot_json FROM scan_snapshots WHERE recorded_at_unix_ms >= ?1 ORDER BY recorded_at_unix_ms ASC, id ASC LIMIT 1",
                vec![Box::new(since as i64)],
            ),
            None => (
                "SELECT snapshot_json FROM scan_snapshots ORDER BY recorded_at_unix_ms ASC, id ASC LIMIT 1",
                vec![],
            ),
        };
        let mut statement = self.conn.prepare(sql)?;
        let mut rows = statement.query(rusqlite::params_from_iter(params.iter()))?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        let json: String = row.get(0)?;
        let snapshot: ScanSnapshot =
            serde_json::from_str(&json).map_err(|e| StateStoreError::Serialize {
                message: format!("failed to parse snapshot: {e}"),
            })?;
        Ok(Some(snapshot))
    }

    pub fn count_alerts_by_status(
        &self,
        since_unix_ms: Option<u64>,
    ) -> Result<AlertStats, StateStoreError> {
        let (sql, params): (&str, Vec<Box<dyn rusqlite::types::ToSql>>) = match since_unix_ms {
            Some(since) => (
                "SELECT status, COUNT(*) FROM alerts WHERE created_at_unix_ms >= ?1 GROUP BY status",
                vec![Box::new(since as i64)],
            ),
            None => (
                "SELECT status, COUNT(*) FROM alerts GROUP BY status",
                vec![],
            ),
        };
        let mut statement = self.conn.prepare(sql)?;
        let rows = statement.query_map(rusqlite::params_from_iter(params.iter()), |row| {
            let status: String = row.get(0)?;
            let count = row.get::<_, i64>(1)? as u64;
            Ok((status, count))
        })?;

        let mut stats = AlertStats {
            open: 0,
            acknowledged: 0,
            resolved: 0,
        };
        for row in rows {
            let (status, count) = row?;
            match status.as_str() {
                "open" => stats.open = count,
                "acknowledged" => stats.acknowledged = count,
                "resolved" => stats.resolved = count,
                _ => {}
            }
        }
        Ok(stats)
    }

    pub fn count_baselines(&self, since_unix_ms: Option<u64>) -> Result<u64, StateStoreError> {
        let (sql, params): (&str, Vec<Box<dyn rusqlite::types::ToSql>>) = match since_unix_ms {
            Some(since) => (
                "SELECT COUNT(*) FROM baselines WHERE approved_at_unix_ms >= ?1",
                vec![Box::new(since as i64)],
            ),
            None => ("SELECT COUNT(*) FROM baselines", vec![]),
        };
        let mut statement = self.conn.prepare(sql)?;
        let count = statement.query_row(rusqlite::params_from_iter(params.iter()), |row| {
            row.get::<_, i64>(0)
        })?;
        Ok(count.max(0) as u64)
    }

    pub fn count_audit_events_by_category(
        &self,
        since_unix_ms: Option<u64>,
    ) -> Result<std::collections::HashMap<String, u64>, StateStoreError> {
        let (sql, params): (&str, Vec<Box<dyn rusqlite::types::ToSql>>) = match since_unix_ms {
            Some(since) => (
                "SELECT category, COUNT(*) FROM audit_events WHERE event_at_unix_ms >= ?1 GROUP BY category",
                vec![Box::new(since as i64)],
            ),
            None => (
                "SELECT category, COUNT(*) FROM audit_events GROUP BY category",
                vec![],
            ),
        };
        let mut statement = self.conn.prepare(sql)?;
        let rows = statement.query_map(rusqlite::params_from_iter(params.iter()), |row| {
            let category: String = row.get(0)?;
            let count = row.get::<_, i64>(1)? as u64;
            Ok((category, count))
        })?;

        let mut map = std::collections::HashMap::new();
        for row in rows {
            let (category, count) = row?;
            map.insert(category, count);
        }
        Ok(map)
    }

    fn run_write_with_retry<T, F>(&mut self, mut operation: F) -> Result<T, StateStoreError>
    where
        F: FnMut(&Connection) -> Result<T, StateStoreError>,
    {
        let attempts = self.lock_retry_count.max(1);

        for attempt in 0..attempts {
            match operation(&self.conn) {
                Ok(value) => return Ok(value),
                Err(StateStoreError::Locked { message: _ }) if attempt + 1 < attempts => {
                    let multiplier = u64::from(attempt) + 1;
                    std::thread::sleep(Duration::from_millis(
                        self.lock_retry_backoff_ms.saturating_mul(multiplier),
                    ));
                    continue;
                }
                Err(error) => return Err(error),
            }
        }

        Err(StateStoreError::Locked {
            message: "sqlite write remained locked after retries".to_string(),
        })
    }
}

#[derive(Debug)]
pub enum StateStoreError {
    Open { message: String },
    Corrupt { message: String },
    Locked { message: String },
    DiskFull { message: String },
    Query { message: String },
    Serialize { message: String },
}

impl Display for StateStoreError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open { message }
            | Self::Corrupt { message }
            | Self::Locked { message }
            | Self::DiskFull { message }
            | Self::Query { message }
            | Self::Serialize { message } => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for StateStoreError {}

impl From<rusqlite::Error> for StateStoreError {
    fn from(value: rusqlite::Error) -> Self {
        classify_sqlite_error("sqlite operation failed", value)
    }
}

fn open_connection(path: &Path, busy_timeout_ms: u64) -> Result<Connection, StateStoreError> {
    let conn = Connection::open(path).map_err(|error| {
        classify_sqlite_error(
            &format!("failed to open sqlite database {}", path.display()),
            error,
        )
    })?;
    configure_connection(&conn, busy_timeout_ms)?;
    validate_connection(&conn)?;
    bootstrap_schema(&conn)?;

    Ok(conn)
}

fn serialize_snapshot(snapshot: &ScanSnapshot) -> Result<(String, String), StateStoreError> {
    let snapshot_json =
        serde_json::to_string(snapshot).map_err(|error| StateStoreError::Serialize {
            message: format!("failed to serialize snapshot: {error}"),
        })?;
    let summary_json =
        serde_json::to_string(&snapshot.summary).map_err(|error| StateStoreError::Serialize {
            message: format!("failed to serialize snapshot summary: {error}"),
        })?;

    Ok((snapshot_json, summary_json))
}

fn serialize_current_findings(
    findings: &[Finding],
) -> Result<Vec<(i64, String, String)>, StateStoreError> {
    findings
        .iter()
        .enumerate()
        .map(|(position, finding)| {
            serde_json::to_string(finding)
                .map(|finding_json| (position as i64, finding.id.clone(), finding_json))
                .map_err(|error| StateStoreError::Serialize {
                    message: format!("failed to serialize current finding: {error}"),
                })
        })
        .collect()
}

fn configure_connection(conn: &Connection, busy_timeout_ms: u64) -> Result<(), StateStoreError> {
    conn.busy_timeout(Duration::from_millis(busy_timeout_ms))?;
    conn.pragma_update(None, "journal_mode", "WAL")?;

    Ok(())
}

fn validate_connection(conn: &Connection) -> Result<(), StateStoreError> {
    conn.query_row("PRAGMA schema_version", [], |row| row.get::<_, i64>(0))?;
    Ok(())
}

fn bootstrap_schema(conn: &Connection) -> Result<(), StateStoreError> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY
        );
        INSERT OR IGNORE INTO schema_version(version) VALUES (1);

        CREATE TABLE IF NOT EXISTS scan_snapshots (
            id INTEGER PRIMARY KEY,
            recorded_at_unix_ms INTEGER NOT NULL,
            summary_json TEXT NOT NULL,
            snapshot_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS current_findings (
            finding_id TEXT PRIMARY KEY,
            position INTEGER NOT NULL,
            finding_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS baselines (
            path TEXT PRIMARY KEY,
            sha256 TEXT NOT NULL,
            approved_at_unix_ms INTEGER NOT NULL,
            source_label TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS restore_payloads (
            path TEXT PRIMARY KEY,
            sha256 TEXT NOT NULL,
            captured_at_unix_ms INTEGER NOT NULL,
            source_label TEXT NOT NULL,
            content TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS alerts (
            alert_id TEXT PRIMARY KEY,
            finding_id TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at_unix_ms INTEGER NOT NULL,
            finding_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS notification_receipts (
            alert_id TEXT NOT NULL,
            delivery_route TEXT NOT NULL,
            delivered_at_unix_ms INTEGER NOT NULL,
            PRIMARY KEY (alert_id, delivery_route)
        );

        CREATE TABLE IF NOT EXISTS notification_cursors (
            cursor_key TEXT PRIMARY KEY,
            unix_ms INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recorded_at_unix_ms INTEGER NOT NULL,
            event_at_unix_ms INTEGER NOT NULL,
            category TEXT NOT NULL,
            event_type TEXT NOT NULL,
            source TEXT NOT NULL,
            summary TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            session_key TEXT,
            agent_id TEXT,
            path TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_audit_events_category
            ON audit_events(category);
        CREATE INDEX IF NOT EXISTS idx_audit_events_event_at
            ON audit_events(event_at_unix_ms);
        CREATE INDEX IF NOT EXISTS idx_audit_events_event_type
            ON audit_events(event_type);
        ",
    )?;

    migrate_baselines_provenance(conn)?;
    migrate_snapshots_posture_score(conn)?;

    Ok(())
}

/// Idempotent migration: add provenance columns to baselines table (v1 → v2).
fn migrate_baselines_provenance(conn: &Connection) -> Result<(), StateStoreError> {
    let mut has_git_remote_url = false;
    let mut has_git_head_sha = false;

    let mut stmt = conn.prepare("PRAGMA table_info(baselines)")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
    for row in rows {
        let col_name = row?;
        if col_name == "git_remote_url" {
            has_git_remote_url = true;
        }
        if col_name == "git_head_sha" {
            has_git_head_sha = true;
        }
    }

    if !has_git_remote_url {
        conn.execute_batch("ALTER TABLE baselines ADD COLUMN git_remote_url TEXT")?;
    }
    if !has_git_head_sha {
        conn.execute_batch("ALTER TABLE baselines ADD COLUMN git_head_sha TEXT")?;
    }

    Ok(())
}

/// Idempotent migration: add posture_score column to scan_snapshots table.
fn migrate_snapshots_posture_score(conn: &Connection) -> Result<(), StateStoreError> {
    let mut has_posture_score = false;

    let mut stmt = conn.prepare("PRAGMA table_info(scan_snapshots)")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
    for row in rows {
        if row? == "posture_score" {
            has_posture_score = true;
        }
    }

    if !has_posture_score {
        conn.execute_batch("ALTER TABLE scan_snapshots ADD COLUMN posture_score REAL")?;
    }

    Ok(())
}

fn rename_corrupt_database(path: &Path) -> Result<PathBuf, StateStoreError> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| StateStoreError::Corrupt {
            message: format!("failed to timestamp corrupt database rename: {error}"),
        })?
        .as_secs();
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| StateStoreError::Corrupt {
            message: "database path has no file name".to_string(),
        })?;
    let renamed_path = path.with_file_name(format!("{file_name}.corrupt.{timestamp}"));

    fs::rename(path, &renamed_path).map_err(|error| StateStoreError::Corrupt {
        message: format!(
            "failed to move corrupt state database {} aside: {error}",
            path.display()
        ),
    })?;

    Ok(renamed_path)
}

fn is_corrupt_database_error(error: &StateStoreError) -> bool {
    matches!(error, StateStoreError::Corrupt { .. })
}

fn status_as_str(status: AlertStatus) -> &'static str {
    status.as_str()
}

fn status_from_str(status: &str) -> Result<AlertStatus, rusqlite::Error> {
    match status {
        "open" => Ok(AlertStatus::Open),
        "acknowledged" => Ok(AlertStatus::Acknowledged),
        "resolved" => Ok(AlertStatus::Resolved),
        other => Err(rusqlite::Error::FromSqlConversionFailure(
            2,
            rusqlite::types::Type::Text,
            Box::new(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown alert status {other}"),
            )),
        )),
    }
}

fn audit_event_from_row(
    row: &rusqlite::Row<'_>,
) -> Result<crate::audit::AuditEvent, rusqlite::Error> {
    let category_str: String = row.get(3)?;
    let source_str: String = row.get(5)?;
    Ok(crate::audit::AuditEvent {
        id: row.get(0)?,
        recorded_at_unix_ms: row.get::<_, i64>(1)? as u64,
        event_at_unix_ms: row.get::<_, i64>(2)? as u64,
        category: crate::audit::AuditCategory::from_str(&category_str),
        event_type: row.get(4)?,
        source: crate::audit::AuditSource::from_str(&source_str),
        summary: row.get(6)?,
        payload_json: row.get(7)?,
        session_key: row.get(8)?,
        agent_id: row.get(9)?,
        path: row.get(10)?,
    })
}

fn alert_record_from_row(row: &rusqlite::Row<'_>) -> Result<AlertRecord, rusqlite::Error> {
    let status_text: String = row.get(2)?;
    let finding_json: String = row.get(4)?;
    let finding = serde_json::from_str(&finding_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            4,
            rusqlite::types::Type::Text,
            Box::new(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to deserialize alert finding: {error}"),
            )),
        )
    })?;

    Ok(AlertRecord {
        alert_id: row.get(0)?,
        finding_id: row.get(1)?,
        status: status_from_str(&status_text)?,
        created_at_unix_ms: row.get::<_, i64>(3)? as u64,
        finding,
    })
}

fn classify_sqlite_error(context: &str, error: rusqlite::Error) -> StateStoreError {
    match &error {
        SqlError::SqliteFailure(sqlite_error, _) => match sqlite_error.code {
            ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase => StateStoreError::Corrupt {
                message: format!("{context}: {error}"),
            },
            ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked => StateStoreError::Locked {
                message: format!("{context}: {error}"),
            },
            ErrorCode::DiskFull => StateStoreError::DiskFull {
                message: format!("{context}: {error}"),
            },
            _ => StateStoreError::Query {
                message: format!("{context}: {error}"),
            },
        },
        _ => StateStoreError::Query {
            message: format!("{context}: {error}"),
        },
    }
}
