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
    clawguard_dir_for_home(home_dir).join(CONFIG_FILE_NAME)
}

pub fn clawguard_dir_for_home(home_dir: &Path) -> PathBuf {
    home_dir.join(CONFIG_DIR_NAME)
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

pub fn validate_webhook_url(url: &str) -> Result<String, String> {
    let url = url.trim();
    if url.is_empty() {
        return Err("webhook URL cannot be empty".to_string());
    }
    if url.len() > 2048 {
        return Err("webhook URL is too long (max 2048 characters)".to_string());
    }
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err("webhook URL must start with http:// or https://".to_string());
    }
    let after_scheme = if url.starts_with("https://") {
        &url[8..]
    } else {
        &url[7..]
    };
    if after_scheme.is_empty() || after_scheme.starts_with('/') || after_scheme.starts_with(':') {
        return Err("webhook URL must include a host".to_string());
    }

    // Security: block private/loopback/link-local IPs to prevent SSRF
    let host = after_scheme.split('/').next().unwrap_or("");
    let host_no_port = host.split(':').next().unwrap_or(host);
    if let Ok(ip) = host_no_port.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(v4) => {
                if v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified()
                {
                    return Err(format!(
                        "webhook URL must not use private/loopback address: {v4}"
                    ));
                }
            }
            std::net::IpAddr::V6(v6) => {
                if v6.is_loopback() || v6.is_unspecified() {
                    return Err(format!(
                        "webhook URL must not use loopback address: {v6}"
                    ));
                }
            }
        }
    }

    Ok(url.to_string())
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

    // Security: restrict directory permissions to owner-only (Unix)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
    }

    let contents =
        toml::to_string(config).map_err(|error| ConfigStoreError::Serialize(error.to_string()))?;
    fs::write(&path, contents).map_err(ConfigStoreError::Io)?;

    // Security: restrict config file permissions to owner-only (Unix)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }

    Ok(path)
}
