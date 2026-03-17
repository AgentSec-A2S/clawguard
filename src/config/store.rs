use std::env;
use std::fmt::{Display, Formatter};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use super::schema::AppConfig;

const CONFIG_DIR_NAME: &str = ".clawguard";
const CONFIG_FILE_NAME: &str = "config.toml";

#[derive(Debug)]
pub enum ConfigStoreError {
    Io(io::Error),
    Serialize(String),
    Deserialize(String),
}

impl Display for ConfigStoreError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "{error}"),
            Self::Serialize(error) => write!(f, "{error}"),
            Self::Deserialize(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for ConfigStoreError {}

pub fn config_path() -> PathBuf {
    config_path_for_home(&resolve_home_dir())
}

pub fn config_path_for_home(home_dir: &Path) -> PathBuf {
    home_dir.join(CONFIG_DIR_NAME).join(CONFIG_FILE_NAME)
}

pub(crate) fn resolve_home_dir() -> PathBuf {
    env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn load_config() -> Result<Option<AppConfig>, ConfigStoreError> {
    load_config_from_path(&config_path())
}

pub fn load_config_from_path(path: &Path) -> Result<Option<AppConfig>, ConfigStoreError> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(ConfigStoreError::Io(error)),
    };

    toml::from_str(&contents)
        .map(Some)
        .map_err(|error| ConfigStoreError::Deserialize(error.to_string()))
}

pub fn save_config_for_home(
    config: &AppConfig,
    home_dir: &Path,
) -> Result<PathBuf, ConfigStoreError> {
    let path = config_path_for_home(home_dir);
    let parent = path
        .parent()
        .ok_or_else(|| ConfigStoreError::Serialize("config path has no parent".to_string()))?;

    fs::create_dir_all(parent).map_err(ConfigStoreError::Io)?;
    let contents =
        toml::to_string(config).map_err(|error| ConfigStoreError::Serialize(error.to_string()))?;
    fs::write(&path, contents).map_err(ConfigStoreError::Io)?;

    Ok(path)
}
