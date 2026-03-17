use std::collections::BTreeSet;
use std::env;
use std::fs::{self, File};
use std::path::PathBuf;

use glob::glob;

use crate::config::presets::preset_by_id;
use crate::config::schema::{PathPattern, ScanDomain};

const OPENCLAW_STATE_ROOT: &str = "~/.openclaw";
const OPENCLAW_CONFIG_PATH: &str = "~/.openclaw/openclaw.json";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiscoveryOptions {
    pub home_dir: Option<PathBuf>,
    pub openclaw_state_dir: Option<PathBuf>,
    pub openclaw_config_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryWarning {
    pub path: PathBuf,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredTarget {
    pub domain: ScanDomain,
    pub paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedRuntime {
    pub preset_id: String,
    pub root: Option<PathBuf>,
    pub targets: Vec<DiscoveredTarget>,
    pub warnings: Vec<DiscoveryWarning>,
    pub recommended: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiscoveryReport {
    pub runtimes: Vec<DetectedRuntime>,
    pub warnings: Vec<DiscoveryWarning>,
}

pub fn discover_from_builtin_presets(options: &DiscoveryOptions) -> DiscoveryReport {
    let (runtime, warnings) = discover_openclaw_internal(options);
    let runtimes = runtime.into_iter().collect();

    DiscoveryReport { runtimes, warnings }
}

pub fn discover_openclaw(options: &DiscoveryOptions) -> Option<DetectedRuntime> {
    discover_openclaw_internal(options).0
}

fn discover_openclaw_internal(
    options: &DiscoveryOptions,
) -> (Option<DetectedRuntime>, Vec<DiscoveryWarning>) {
    let Some(preset) = preset_by_id("openclaw") else {
        return (None, Vec::new());
    };
    let state_root = resolve_state_root(options);
    let config_path = resolve_config_path(options, &state_root);
    let mut report_warnings = Vec::new();
    let state_status = inspect_path(&state_root, &mut report_warnings);
    let config_status = if state_status == PathStatus::Unreadable && !has_config_override(options) {
        PathStatus::Missing
    } else {
        inspect_path(&config_path, &mut report_warnings)
    };
    let detected = state_status == PathStatus::Readable || config_status == PathStatus::Readable;

    if !detected {
        return (None, report_warnings);
    }

    let mut runtime_warnings = Vec::new();
    let targets = preset
        .scan_targets
        .iter()
        .filter_map(|target| {
            let paths: Vec<_> = target
                .paths
                .iter()
                .flat_map(|pattern| {
                    resolve_pattern_matches(pattern, &state_root, &config_path, options)
                })
                .filter_map(|path| match inspect_path(&path, &mut runtime_warnings) {
                    PathStatus::Readable => Some(path),
                    PathStatus::Missing | PathStatus::Unreadable => None,
                })
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();

            if paths.is_empty() {
                None
            } else {
                Some(DiscoveredTarget {
                    domain: target.domain,
                    paths,
                })
            }
        })
        .collect();

    runtime_warnings.extend(report_warnings);

    (
        Some(DetectedRuntime {
            preset_id: preset.id,
            root: Some(resolve_runtime_root(
                &state_root,
                &config_path,
                state_status,
                config_status,
            )),
            targets,
            warnings: runtime_warnings,
            recommended: true,
        }),
        Vec::new(),
    )
}

fn resolve_runtime_root(
    state_root: &PathBuf,
    config_path: &PathBuf,
    state_status: PathStatus,
    _config_status: PathStatus,
) -> PathBuf {
    if state_status == PathStatus::Readable {
        state_root.clone()
    } else {
        config_path
            .parent()
            .map(PathBuf::from)
            .unwrap_or_else(|| config_path.clone())
    }
}

fn resolve_state_root(options: &DiscoveryOptions) -> PathBuf {
    if let Some(path) = options.openclaw_state_dir.as_ref() {
        return path.clone();
    }

    if let Some(path) =
        env::var_os("OPENCLAW_STATE_DIR").or_else(|| env::var_os("CLAWDBOT_STATE_DIR"))
    {
        return PathBuf::from(path);
    }

    resolve_home_dir(options).join(".openclaw")
}

fn resolve_config_path(options: &DiscoveryOptions, state_root: &PathBuf) -> PathBuf {
    if let Some(path) = options.openclaw_config_path.as_ref() {
        return path.clone();
    }

    if let Some(path) =
        env::var_os("OPENCLAW_CONFIG_PATH").or_else(|| env::var_os("CLAWDBOT_CONFIG_PATH"))
    {
        return PathBuf::from(path);
    }

    state_root.join("openclaw.json")
}

fn has_config_override(options: &DiscoveryOptions) -> bool {
    options.openclaw_config_path.is_some()
        || env::var_os("OPENCLAW_CONFIG_PATH").is_some()
        || env::var_os("CLAWDBOT_CONFIG_PATH").is_some()
}

fn resolve_home_dir(options: &DiscoveryOptions) -> PathBuf {
    options
        .home_dir
        .clone()
        .or_else(|| env::var_os("HOME").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("."))
}

fn resolve_pattern_matches(
    pattern: &PathPattern,
    state_root: &PathBuf,
    config_path: &PathBuf,
    options: &DiscoveryOptions,
) -> Vec<PathBuf> {
    let resolved = resolve_pattern(pattern, state_root, config_path, options);

    if !contains_glob(&resolved) {
        return vec![resolved];
    }

    let Ok(matches) = glob(&resolved.to_string_lossy()) else {
        return Vec::new();
    };

    matches.filter_map(Result::ok).collect()
}

fn resolve_pattern(
    pattern: &PathPattern,
    state_root: &PathBuf,
    config_path: &PathBuf,
    options: &DiscoveryOptions,
) -> PathBuf {
    if pattern.path == OPENCLAW_STATE_ROOT {
        return state_root.clone();
    }

    if pattern.path == OPENCLAW_CONFIG_PATH {
        return config_path.clone();
    }

    if let Some(suffix) = pattern.path.strip_prefix("~/.openclaw/") {
        return state_root.join(suffix);
    }

    if let Some(path) = pattern.path.strip_prefix("~/") {
        return resolve_home_dir(options).join(path);
    }

    PathBuf::from(&pattern.path)
}

fn contains_glob(path: &PathBuf) -> bool {
    let path = path.to_string_lossy();

    path.contains('*') || path.contains('?')
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathStatus {
    Readable,
    Missing,
    Unreadable,
}

fn inspect_path(path: &PathBuf, warnings: &mut Vec<DiscoveryWarning>) -> PathStatus {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return PathStatus::Missing,
        Err(error) => {
            warnings.push(DiscoveryWarning {
                path: path.clone(),
                message: format!("failed to inspect path: {error}"),
            });
            return PathStatus::Unreadable;
        }
    };

    let access_result = if metadata.is_dir() {
        fs::read_dir(path).map(|_| ())
    } else {
        File::open(path).map(|_| ())
    };

    match access_result {
        Ok(()) => PathStatus::Readable,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => PathStatus::Missing,
        Err(error) => {
            warnings.push(DiscoveryWarning {
                path: path.clone(),
                message: format!("failed to read path: {error}"),
            });
            PathStatus::Unreadable
        }
    }
}
