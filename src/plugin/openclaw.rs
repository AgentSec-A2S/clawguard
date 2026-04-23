//! OpenClaw-first plugin installer and status probe.
//!
//! The runtime guard ships as an OpenClaw plugin at
//! `openclaw-plugin-runtime/`. Before §6 an operator had to copy that
//! directory into `~/.openclaw/extensions/clawguard-runtime/` by hand
//! (see `docs/runbooks/clawguard-runtime-guard.md` §1). This module
//! performs the same copy in-process, using files embedded into the
//! binary so the install works even when the operator only has the
//! single binary on disk.
//!
//! Security posture:
//! * Plugin files are embedded at compile time via `include_str!`, so we
//!   never read from a mutable location on the operator's filesystem
//!   when deciding what to install.
//! * Existing regular files inside the destination are overwritten only
//!   when the caller passes `force = true`. Symlinks are rejected
//!   outright (to defeat a planted `index.js -> /etc/passwd` trap
//!   inside the extensions dir).
//! * Plugin files are written 0644; the destination dir is 0755. These
//!   match the OpenClaw extensions loader expectations and carry no
//!   secrets.

use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub const EXTENSION_DIR_NAME: &str = "clawguard-runtime";
pub const OPENCLAW_EXTENSIONS_DIR: &str = ".openclaw/extensions";

const PLUGIN_MANIFEST: &str =
    include_str!("../../openclaw-plugin-runtime/openclaw.plugin.json");
const PLUGIN_ENTRY: &str = include_str!("../../openclaw-plugin-runtime/index.js");
const PLUGIN_PACKAGE: &str = include_str!("../../openclaw-plugin-runtime/package.json");

/// What a single file write accomplished.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallAction {
    Created,
    Overwritten,
    Unchanged,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct InstallReport {
    pub target_dir: PathBuf,
    pub files: Vec<FileReport>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct FileReport {
    pub path: PathBuf,
    pub action: InstallAction,
}

#[derive(Debug)]
pub enum InstallError {
    MissingOpenclawHome(PathBuf),
    MissingExtensionsDir(PathBuf),
    ExistingSymlink(PathBuf),
    ExistingFileNeedsForce(PathBuf),
    Io(PathBuf, io::Error),
}

impl std::fmt::Display for InstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InstallError::MissingOpenclawHome(p) => write!(
                f,
                "OpenClaw home not found at {} — is OpenClaw installed for this user?",
                p.display()
            ),
            InstallError::MissingExtensionsDir(p) => write!(
                f,
                "OpenClaw extensions dir not found at {} — create it or pass --dir",
                p.display()
            ),
            InstallError::ExistingSymlink(p) => write!(
                f,
                "refusing to overwrite symlink at {} — delete it manually before reinstalling",
                p.display()
            ),
            InstallError::ExistingFileNeedsForce(p) => write!(
                f,
                "file {} already exists with different content — rerun with --force to overwrite",
                p.display()
            ),
            InstallError::Io(p, err) => write!(f, "{}: {err}", p.display()),
        }
    }
}

impl std::error::Error for InstallError {}

/// Default install destination: `<home>/.openclaw/extensions/clawguard-runtime/`.
pub fn default_install_dir(home: &Path) -> PathBuf {
    home.join(OPENCLAW_EXTENSIONS_DIR).join(EXTENSION_DIR_NAME)
}

/// Install the runtime-guard plugin into `target_dir`.
///
/// When `force` is `false`, existing regular files with different
/// content cause an `ExistingFileNeedsForce` error. Existing symlinks
/// always cause an `ExistingSymlink` error, regardless of `force`.
pub fn install_runtime_plugin(
    target_dir: &Path,
    force: bool,
) -> Result<InstallReport, InstallError> {
    // Destination parent must exist — otherwise either OpenClaw isn't
    // installed, or the operator pointed `--dir` somewhere typo'd.
    if let Some(parent) = target_dir.parent() {
        if !parent.exists() {
            // Two layers of missing parent → "no OpenClaw home". One
            // layer → "no extensions dir". Distinguishing improves the
            // error message without changing behavior.
            if let Some(grandparent) = parent.parent() {
                if !grandparent.exists() {
                    return Err(InstallError::MissingOpenclawHome(grandparent.to_path_buf()));
                }
            }
            return Err(InstallError::MissingExtensionsDir(parent.to_path_buf()));
        }
    }

    fs::create_dir_all(target_dir)
        .map_err(|e| InstallError::Io(target_dir.to_path_buf(), e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(target_dir, fs::Permissions::from_mode(0o755));
    }

    let mut files = Vec::with_capacity(3);
    for (name, body) in PLUGIN_FILES {
        let path = target_dir.join(name);
        let action = write_plugin_file(&path, body, force)?;
        files.push(FileReport { path, action });
    }

    Ok(InstallReport {
        target_dir: target_dir.to_path_buf(),
        files,
    })
}

const PLUGIN_FILES: &[(&str, &str)] = &[
    ("openclaw.plugin.json", PLUGIN_MANIFEST),
    ("index.js", PLUGIN_ENTRY),
    ("package.json", PLUGIN_PACKAGE),
];

fn write_plugin_file(
    path: &Path,
    contents: &str,
    force: bool,
) -> Result<InstallAction, InstallError> {
    // `symlink_metadata` does NOT follow symlinks, so we can reject a
    // planted `clawguard-runtime/index.js -> /etc/passwd` before any
    // write touches the symlink target.
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(InstallError::ExistingSymlink(path.to_path_buf()));
        }
        Ok(_) => {
            let existing = fs::read_to_string(path)
                .map_err(|e| InstallError::Io(path.to_path_buf(), e))?;
            if existing == contents {
                return Ok(InstallAction::Unchanged);
            }
            if !force {
                return Err(InstallError::ExistingFileNeedsForce(path.to_path_buf()));
            }
            fs::write(path, contents)
                .map_err(|e| InstallError::Io(path.to_path_buf(), e))?;
            set_readable_mode(path);
            Ok(InstallAction::Overwritten)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            fs::write(path, contents)
                .map_err(|e| InstallError::Io(path.to_path_buf(), e))?;
            set_readable_mode(path);
            Ok(InstallAction::Created)
        }
        Err(e) => Err(InstallError::Io(path.to_path_buf(), e)),
    }
}

fn set_readable_mode(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o644));
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Snapshot of the plugin's install state plus adjacent facts an
/// operator needs to debug "why doesn't the guard fire?".
#[derive(Debug, Clone, serde::Serialize)]
pub struct PluginStatus {
    /// Destination directory inspected.
    pub target_dir: PathBuf,
    /// `true` if all expected plugin files are present and byte-exact
    /// matches of the embedded versions.
    pub installed: bool,
    /// `true` if the manifest file is present AND parses to the
    /// expected plugin id `clawguard-runtime`.
    pub manifest_valid: bool,
    /// Per-file presence + drift status.
    pub files: Vec<PluginFileStatus>,
    /// Absolute path of the `clawguard` binary resolved via PATH, if
    /// any. The plugin's TS shim defaults to spawning the binary by
    /// bare name, so `None` here means the spawn will fail until the
    /// operator sets `clawguardBin` in plugin config.
    pub broker_resolvable: Option<PathBuf>,
    /// Presence of the runtime policy manifest at
    /// `<home>/.clawguard/policy.toml`.
    pub policy_manifest_present: bool,
    /// Human-readable hint about the next action.
    pub hint: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PluginFileStatus {
    pub name: String,
    pub path: PathBuf,
    pub present: bool,
    pub matches_expected: bool,
}

/// Inspect the plugin install state without modifying anything.
pub fn plugin_status(home: &Path) -> PluginStatus {
    let target_dir = default_install_dir(home);
    let policy_manifest_present = home.join(".clawguard").join("policy.toml").exists();
    let broker = detect_broker_resolvable();

    let mut files = Vec::with_capacity(3);
    let mut all_present_and_matching = true;
    let mut manifest_valid = false;

    for (name, expected) in PLUGIN_FILES {
        let path = target_dir.join(name);
        let (present, matches_expected, actual) = probe_file(&path, expected);
        if !present || !matches_expected {
            all_present_and_matching = false;
        }
        if *name == "openclaw.plugin.json" && present {
            if let Some(body) = actual {
                manifest_valid = serde_json::from_str::<serde_json::Value>(&body)
                    .ok()
                    .and_then(|v| v.get("id").and_then(|id| id.as_str()).map(|s| s.to_string()))
                    .map(|id| id == "clawguard-runtime")
                    .unwrap_or(false);
            }
        }
        files.push(PluginFileStatus {
            name: (*name).to_string(),
            path,
            present,
            matches_expected,
        });
    }

    let installed = all_present_and_matching && manifest_valid;

    let hint = hint_for(installed, manifest_valid, broker.is_some(), policy_manifest_present);

    PluginStatus {
        target_dir,
        installed,
        manifest_valid,
        files,
        broker_resolvable: broker,
        policy_manifest_present,
        hint,
    }
}

fn probe_file(path: &Path, expected: &str) -> (bool, bool, Option<String>) {
    // Reject symlinks so a planted link is never silently "installed".
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => return (false, false, None),
        Ok(_) => {}
        Err(_) => return (false, false, None),
    }
    match fs::read_to_string(path) {
        Ok(actual) => {
            let matches_expected = actual == expected;
            (true, matches_expected, Some(actual))
        }
        Err(_) => (false, false, None),
    }
}

fn hint_for(installed: bool, manifest_valid: bool, broker: bool, policy: bool) -> String {
    if !installed && !manifest_valid {
        return "run `clawguard plugin install openclaw` to install the runtime guard plugin"
            .to_string();
    }
    if !installed {
        return "plugin files drifted from the embedded version — run \
                `clawguard plugin install openclaw --force`"
            .to_string();
    }
    if !broker {
        return "plugin installed but `clawguard` is not on PATH — the plugin will fail to spawn \
                the broker until you set `clawguardBin` in plugin config or add clawguard to PATH"
            .to_string();
    }
    if !policy {
        return "plugin installed — run `clawguard policy init` to write a custom manifest \
                (optional; built-in defaults will apply otherwise)"
            .to_string();
    }
    "runtime guard installed; restart the OpenClaw session to activate the plugin".to_string()
}

/// Resolve `clawguard` against `$PATH` without shelling out. Returns
/// the first executable match, matching the resolution order a child
/// `std::process::Command::new("clawguard").spawn()` would use.
pub fn detect_broker_resolvable() -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    let exe_name = if cfg!(windows) { "clawguard.exe" } else { "clawguard" };
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(exe_name);
        if is_executable_regular_file(&candidate) {
            return Some(candidate);
        }
    }
    None
}

fn is_executable_regular_file(path: &Path) -> bool {
    match fs::metadata(path) {
        Ok(meta) if meta.is_file() => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                meta.permissions().mode() & 0o111 != 0
            }
            #[cfg(not(unix))]
            {
                // On Windows we already filtered by the .exe suffix.
                let _ = path;
                true
            }
        }
        _ => false,
    }
}

/// Convenience for callers who want the plugin root name ("clawguard-runtime")
/// without depending on the constant directly.
#[inline]
pub fn extension_dir_name() -> &'static OsStr {
    OsStr::new(EXTENSION_DIR_NAME)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn fake_openclaw_home(home: &Path) {
        fs::create_dir_all(home.join(OPENCLAW_EXTENSIONS_DIR)).unwrap();
    }

    #[test]
    fn install_creates_all_three_plugin_files() {
        let tmp = tempdir().unwrap();
        fake_openclaw_home(tmp.path());
        let target = default_install_dir(tmp.path());
        let report = install_runtime_plugin(&target, false).expect("install ok");
        assert_eq!(report.files.len(), 3);
        for file in &report.files {
            assert_eq!(file.action, InstallAction::Created);
            assert!(file.path.exists());
        }
        let manifest = fs::read_to_string(target.join("openclaw.plugin.json")).unwrap();
        assert!(manifest.contains("\"id\": \"clawguard-runtime\""));
    }

    #[test]
    fn install_is_idempotent_when_files_already_match() {
        let tmp = tempdir().unwrap();
        fake_openclaw_home(tmp.path());
        let target = default_install_dir(tmp.path());
        let _ = install_runtime_plugin(&target, false).unwrap();
        let report2 = install_runtime_plugin(&target, false).unwrap();
        for file in &report2.files {
            assert_eq!(file.action, InstallAction::Unchanged);
        }
    }

    #[test]
    fn install_refuses_to_overwrite_drifted_file_without_force() {
        let tmp = tempdir().unwrap();
        fake_openclaw_home(tmp.path());
        let target = default_install_dir(tmp.path());
        install_runtime_plugin(&target, false).unwrap();
        fs::write(target.join("index.js"), "// tampered").unwrap();
        let err = install_runtime_plugin(&target, false)
            .err()
            .expect("drift must error without --force");
        assert!(matches!(err, InstallError::ExistingFileNeedsForce(_)));
    }

    #[test]
    fn install_overwrites_drifted_file_with_force() {
        let tmp = tempdir().unwrap();
        fake_openclaw_home(tmp.path());
        let target = default_install_dir(tmp.path());
        install_runtime_plugin(&target, false).unwrap();
        fs::write(target.join("index.js"), "// tampered").unwrap();
        let report = install_runtime_plugin(&target, true).unwrap();
        let index_js = report
            .files
            .iter()
            .find(|f| f.path.file_name() == Some(OsStr::new("index.js")))
            .unwrap();
        assert_eq!(index_js.action, InstallAction::Overwritten);
        let restored = fs::read_to_string(target.join("index.js")).unwrap();
        assert!(!restored.contains("tampered"));
    }

    #[test]
    fn install_rejects_symlink_even_with_force() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let tmp = tempdir().unwrap();
            fake_openclaw_home(tmp.path());
            let target = default_install_dir(tmp.path());
            fs::create_dir_all(&target).unwrap();
            let decoy = tmp.path().join("decoy.txt");
            fs::write(&decoy, "decoy").unwrap();
            symlink(&decoy, target.join("index.js")).unwrap();
            let err = install_runtime_plugin(&target, true)
                .err()
                .expect("symlink must be rejected even with --force");
            assert!(matches!(err, InstallError::ExistingSymlink(_)));
            assert_eq!(fs::read_to_string(&decoy).unwrap(), "decoy");
        }
    }

    #[test]
    fn install_errors_when_openclaw_home_is_missing() {
        let tmp = tempdir().unwrap();
        let target = default_install_dir(tmp.path());
        let err = install_runtime_plugin(&target, false)
            .err()
            .expect("missing openclaw home must error");
        assert!(
            matches!(err, InstallError::MissingOpenclawHome(_) | InstallError::MissingExtensionsDir(_))
        );
    }

    #[test]
    fn status_reports_not_installed_for_empty_home() {
        let tmp = tempdir().unwrap();
        let status = plugin_status(tmp.path());
        assert!(!status.installed);
        assert!(!status.manifest_valid);
        assert!(!status.policy_manifest_present);
        assert_eq!(status.files.len(), 3);
        for f in &status.files {
            assert!(!f.present);
            assert!(!f.matches_expected);
        }
        assert!(status.hint.contains("install"));
    }

    #[test]
    fn status_reports_installed_after_install() {
        let tmp = tempdir().unwrap();
        fake_openclaw_home(tmp.path());
        install_runtime_plugin(&default_install_dir(tmp.path()), false).unwrap();
        let status = plugin_status(tmp.path());
        assert!(status.installed);
        assert!(status.manifest_valid);
        for f in &status.files {
            assert!(f.present);
            assert!(f.matches_expected);
        }
    }

    #[test]
    fn status_reports_drift_when_files_mutated() {
        let tmp = tempdir().unwrap();
        fake_openclaw_home(tmp.path());
        let target = default_install_dir(tmp.path());
        install_runtime_plugin(&target, false).unwrap();
        fs::write(target.join("index.js"), "// tampered").unwrap();
        let status = plugin_status(tmp.path());
        assert!(!status.installed, "drifted install should not report installed");
        let index = status
            .files
            .iter()
            .find(|f| f.name == "index.js")
            .unwrap();
        assert!(index.present);
        assert!(!index.matches_expected);
        assert!(status.hint.contains("drift"));
    }

    #[test]
    fn status_reports_manifest_invalid_for_non_matching_id() {
        let tmp = tempdir().unwrap();
        fake_openclaw_home(tmp.path());
        let target = default_install_dir(tmp.path());
        fs::create_dir_all(&target).unwrap();
        fs::write(
            target.join("openclaw.plugin.json"),
            r#"{"id": "some-other-plugin"}"#,
        )
        .unwrap();
        fs::write(target.join("index.js"), "// minimal").unwrap();
        fs::write(target.join("package.json"), "{}").unwrap();
        let status = plugin_status(tmp.path());
        assert!(!status.manifest_valid);
        assert!(!status.installed);
    }

    #[test]
    fn status_flags_policy_manifest_presence() {
        let tmp = tempdir().unwrap();
        fake_openclaw_home(tmp.path());
        install_runtime_plugin(&default_install_dir(tmp.path()), false).unwrap();
        fs::create_dir_all(tmp.path().join(".clawguard")).unwrap();
        fs::write(tmp.path().join(".clawguard/policy.toml"), "").unwrap();
        let status = plugin_status(tmp.path());
        assert!(status.policy_manifest_present);
    }
}
