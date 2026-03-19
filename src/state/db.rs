use std::fmt::{Display, Formatter};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, Error as SqlError, ErrorCode};

use crate::scan::Finding;

use super::model::{
    AlertRecord, AlertStatus, BaselineRecord, ScanSnapshot, StateWarning, StateWarningKind,
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

    pub fn record_scan_snapshot(&mut self, snapshot: &ScanSnapshot) -> Result<(), StateStoreError> {
        let snapshot_json =
            serde_json::to_string(snapshot).map_err(|error| StateStoreError::Serialize {
                message: format!("failed to serialize snapshot: {error}"),
            })?;
        let summary_json = serde_json::to_string(&snapshot.summary).map_err(|error| {
            StateStoreError::Serialize {
                message: format!("failed to serialize snapshot summary: {error}"),
            }
        })?;

        self.run_write_with_retry(|conn| {
            conn.execute(
                "INSERT INTO scan_snapshots (recorded_at_unix_ms, summary_json, snapshot_json)
                 VALUES (?1, ?2, ?3)",
                (
                    snapshot.recorded_at_unix_ms as i64,
                    &summary_json,
                    &snapshot_json,
                ),
            )?;

            Ok(())
        })
    }

    pub fn replace_current_findings(
        &mut self,
        findings: &[Finding],
    ) -> Result<(), StateStoreError> {
        let serialized_findings: Vec<_> = findings
            .iter()
            .enumerate()
            .map(|(position, finding)| {
                serde_json::to_string(finding)
                    .map(|finding_json| (position as i64, finding.id.clone(), finding_json))
                    .map_err(|error| StateStoreError::Serialize {
                        message: format!("failed to serialize current finding: {error}"),
                    })
            })
            .collect::<Result<_, _>>()?;

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
                "INSERT INTO baselines (path, sha256, approved_at_unix_ms, source_label)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(path) DO UPDATE SET
                     sha256 = excluded.sha256,
                     approved_at_unix_ms = excluded.approved_at_unix_ms,
                     source_label = excluded.source_label",
                (
                    &baseline.path,
                    &baseline.sha256,
                    baseline.approved_at_unix_ms as i64,
                    &baseline.source_label,
                ),
            )?;

            Ok(())
        })
    }

    pub fn list_baselines(&self) -> Result<Vec<BaselineRecord>, StateStoreError> {
        let mut statement = self.conn.prepare(
            "SELECT path, sha256, approved_at_unix_ms, source_label
             FROM baselines
             ORDER BY path ASC",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(BaselineRecord {
                path: row.get(0)?,
                sha256: row.get(1)?,
                approved_at_unix_ms: row.get::<_, i64>(2)? as u64,
                source_label: row.get(3)?,
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
            "SELECT path, sha256, approved_at_unix_ms, source_label
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
        let mut statement = self.conn.prepare(
            "SELECT alert_id, finding_id, status, created_at_unix_ms, finding_json
             FROM alerts
             WHERE status IN ('open', 'acknowledged')
             ORDER BY created_at_unix_ms ASC, alert_id ASC",
        )?;
        let rows = statement.query_map([], |row| {
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
        })?;

        let mut alerts = Vec::new();
        for row in rows {
            alerts.push(row?);
        }

        Ok(alerts)
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

    pub fn path(&self) -> &Path {
        &self.path
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

        CREATE TABLE IF NOT EXISTS alerts (
            alert_id TEXT PRIMARY KEY,
            finding_id TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at_unix_ms INTEGER NOT NULL,
            finding_json TEXT NOT NULL
        );
        ",
    )?;

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
    match status {
        AlertStatus::Open => "open",
        AlertStatus::Acknowledged => "acknowledged",
        AlertStatus::Resolved => "resolved",
    }
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
