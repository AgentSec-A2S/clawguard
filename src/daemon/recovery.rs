use std::fmt::{Display, Formatter};
use std::fs;
use std::path::Path;

use crate::scan::baseline::restore_target_kind_for_path;
use crate::state::db::{StateStore, StateStoreError};

#[derive(Debug)]
pub enum RecoveryError {
    NotRestorable(String),
    MissingApprovedPayload(String),
    Io(String),
    State(StateStoreError),
}

impl Display for RecoveryError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotRestorable(message)
            | Self::MissingApprovedPayload(message)
            | Self::Io(message) => write!(f, "{message}"),
            Self::State(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for RecoveryError {}

impl From<StateStoreError> for RecoveryError {
    fn from(value: StateStoreError) -> Self {
        Self::State(value)
    }
}

pub fn restore_policy_file(store: &StateStore, path: &Path) -> Result<(), RecoveryError> {
    let path_str = path.display().to_string();
    if restore_target_kind_for_path(&path_str, "config").is_none() {
        return Err(RecoveryError::NotRestorable(format!(
            "requested path is not restorable: {}",
            path.display()
        )));
    }

    let payload = store.restore_payload_for_path(&path_str)?.ok_or_else(|| {
        RecoveryError::MissingApprovedPayload(format!(
            "no approved restore payload exists for {}",
            path.display()
        ))
    })?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            RecoveryError::Io(format!(
                "failed to prepare restore parent directory {}: {error}",
                parent.display()
            ))
        })?;
    }

    fs::write(path, payload.content).map_err(|error| {
        RecoveryError::Io(format!(
            "failed to restore approved payload to {}: {error}",
            path.display()
        ))
    })?;

    Ok(())
}
