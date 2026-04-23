//! TOML policy manifest loader.
//!
//! The manifest lives at `~/.clawguard/policy.toml` by default and is
//! hot-reloaded by the adapter when the file mtime changes. The loader
//! defends against two attack shapes:
//!
//! 1. **Symlink escape** — the canonical path of the loaded manifest must
//!    remain inside the configured clawguard config root. Any path that
//!    resolves elsewhere is rejected.
//! 2. **Malformed TOML** — surfaced as `ManifestError::Parse` with the
//!    underlying `toml::de::Error` attached; the caller decides whether
//!    to keep the previously-loaded manifest or fail-closed.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use serde::Deserialize;

/// Errors the manifest loader can return.
#[derive(Debug)]
pub enum ManifestError {
    /// The manifest's canonical path does not live under the configured
    /// clawguard config root.
    SymlinkEscape {
        attempted: PathBuf,
        resolved: PathBuf,
        root: PathBuf,
    },
    /// Filesystem I/O failed.
    Io(std::io::Error),
    /// TOML parse failed.
    Parse(toml::de::Error),
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ManifestError::SymlinkEscape { attempted, resolved, root } => write!(
                f,
                "policy manifest path {} resolved to {} which is outside the config root {}",
                attempted.display(),
                resolved.display(),
                root.display()
            ),
            ManifestError::Io(e) => write!(f, "policy manifest I/O error: {e}"),
            ManifestError::Parse(e) => write!(f, "policy manifest parse error: {e}"),
        }
    }
}

impl std::error::Error for ManifestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ManifestError::Io(e) => Some(e),
            ManifestError::Parse(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ManifestError {
    fn from(e: std::io::Error) -> Self {
        ManifestError::Io(e)
    }
}

impl From<toml::de::Error> for ManifestError {
    fn from(e: toml::de::Error) -> Self {
        ManifestError::Parse(e)
    }
}

/// Fully-parsed policy manifest. Each section is optional so partial
/// overrides on top of the default are ergonomic.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct PolicyManifest {
    pub destructive_actions: DestructiveActionsSection,
    pub lethal_trifecta: LethalTrifectaSection,
    pub path_boundary: PathBoundarySection,
    pub rate_limit: RateLimitSection,
    pub prompt_injection: PromptInjectionSection,
}

/// Patterns that should block destructive shell / SQL / git calls before
/// they execute.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct DestructiveActionsSection {
    pub patterns: Vec<DestructivePattern>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DestructivePattern {
    /// Human-readable label emitted in the finding evidence.
    pub label: String,
    /// Tokens that must all appear as whitespace-bounded substrings after
    /// canonicalization.
    pub tokens: Vec<String>,
    /// When `true`, the pattern still fires when wrapped inside
    /// `sh -c "..."` / `bash -c "..."`.
    #[serde(default = "default_true")]
    pub match_in_shell_tunnel: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct LethalTrifectaSection {
    /// Absolute paths (tilde-expanded) whose read or write trips a
    /// lethal-trifecta precondition finding.
    pub sensitive_paths: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct PathBoundarySection {
    /// Paths a tool call may NEVER write into.
    pub forbidden_writes: Vec<String>,
    /// If set, tool-call write paths outside this root trigger a finding.
    pub workspace_root: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RateLimitSection {
    pub destructive_per_window: u32,
    pub window_seconds: u32,
}

impl Default for RateLimitSection {
    fn default() -> Self {
        Self {
            destructive_per_window: 5,
            window_seconds: 60,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct PromptInjectionSection {
    pub score_threshold: u32,
    pub role_override_markers: Vec<String>,
    pub instruction_override_phrases: Vec<String>,
}

impl Default for PromptInjectionSection {
    fn default() -> Self {
        Self {
            score_threshold: 3,
            role_override_markers: vec![
                "<|system|>".to_string(),
                "<|im_start|>system".to_string(),
                "[SYSTEM]".to_string(),
            ],
            instruction_override_phrases: vec![
                "ignore previous instructions".to_string(),
                "disregard the above".to_string(),
                "you are now".to_string(),
                "new instructions:".to_string(),
            ],
        }
    }
}

/// Default manifest compiled into the binary. Consumed by `policy init`
/// and by callers that want a sensible starting point when the on-disk
/// manifest is absent.
pub const DEFAULT_MANIFEST_TOML: &str = include_str!("../../../data/policy.default.toml");

/// Parse the built-in default manifest. This should never fail; the
/// `include_str!` contents are authored in-repo and covered by a unit
/// test so a malformed default is caught at build time.
pub fn default_manifest() -> PolicyManifest {
    toml::from_str(DEFAULT_MANIFEST_TOML).expect("built-in default manifest must parse")
}

/// Load a manifest, enforcing that its canonical path stays within
/// `config_root`.
pub fn load_manifest(path: &Path, config_root: &Path) -> Result<PolicyManifest, ManifestError> {
    let resolved = fs::canonicalize(path)?;
    let root_canonical = fs::canonicalize(config_root)?;
    if !resolved.starts_with(&root_canonical) {
        return Err(ManifestError::SymlinkEscape {
            attempted: path.to_path_buf(),
            resolved,
            root: root_canonical,
        });
    }
    let raw = fs::read_to_string(&resolved)?;
    let manifest: PolicyManifest = toml::from_str(&raw)?;
    Ok(manifest)
}

/// Hot-reload handle. Wraps the parsed manifest in `Arc<RwLock<_>>` so
/// readers (adapter callbacks) can take a snapshot without blocking the
/// writer (file-watcher thread).
#[derive(Debug, Clone)]
pub struct ManifestHandle {
    inner: Arc<RwLock<PolicyManifest>>,
}

impl ManifestHandle {
    pub fn new(manifest: PolicyManifest) -> Self {
        Self {
            inner: Arc::new(RwLock::new(manifest)),
        }
    }

    /// Cheap snapshot. Returns a clone so the read lock is released before
    /// the caller does any real work.
    pub fn snapshot(&self) -> PolicyManifest {
        self.inner.read().expect("manifest lock poisoned").clone()
    }

    /// Swap in a new manifest. Called by the file-watcher thread.
    pub fn replace(&self, manifest: PolicyManifest) {
        *self.inner.write().expect("manifest lock poisoned") = manifest;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_toml(dir: &Path, body: &str) -> PathBuf {
        let p = dir.join("policy.toml");
        let mut f = fs::File::create(&p).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        p
    }

    #[test]
    fn default_manifest_is_usable() {
        let m = PolicyManifest::default();
        assert_eq!(m.rate_limit.destructive_per_window, 5);
        assert_eq!(m.rate_limit.window_seconds, 60);
        assert!(!m.prompt_injection.role_override_markers.is_empty());
    }

    #[test]
    fn load_valid_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_toml(
            dir.path(),
            r#"
            [[destructive_actions.patterns]]
            label = "rm-rf-root"
            tokens = ["rm", "-rf", "/"]

            [rate_limit]
            destructive_per_window = 3
            window_seconds = 30
            "#,
        );
        let m = load_manifest(&path, dir.path()).expect("manifest should parse");
        assert_eq!(m.destructive_actions.patterns.len(), 1);
        assert_eq!(m.destructive_actions.patterns[0].label, "rm-rf-root");
        assert_eq!(m.rate_limit.destructive_per_window, 3);
    }

    #[test]
    fn load_rejects_malformed_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_toml(dir.path(), "this is [[[ not toml");
        let err = load_manifest(&path, dir.path()).unwrap_err();
        assert!(matches!(err, ManifestError::Parse(_)));
    }

    #[cfg(unix)]
    #[test]
    fn load_rejects_symlink_escape() {
        use std::os::unix::fs::symlink;
        let outside = tempfile::tempdir().unwrap();
        let evil = outside.path().join("evil.toml");
        fs::write(&evil, "[rate_limit]\ndestructive_per_window = 9999\n").unwrap();

        let config_root = tempfile::tempdir().unwrap();
        let link = config_root.path().join("policy.toml");
        symlink(&evil, &link).unwrap();

        let err = load_manifest(&link, config_root.path()).unwrap_err();
        assert!(
            matches!(err, ManifestError::SymlinkEscape { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn built_in_default_manifest_parses() {
        let m = default_manifest();
        assert!(
            !m.destructive_actions.patterns.is_empty(),
            "default must ship at least one destructive-action pattern"
        );
        assert!(
            m.destructive_actions
                .patterns
                .iter()
                .any(|p| p.label == "rm-rf-root-or-home"),
            "rm -rf must be in the default curated set"
        );
        assert!(
            !m.lethal_trifecta.sensitive_paths.is_empty(),
            "default must ship a lethal-trifecta path list"
        );
        assert!(m.rate_limit.destructive_per_window >= 1);
        assert!(m.prompt_injection.score_threshold >= 1);
    }

    #[test]
    fn manifest_handle_round_trips() {
        let handle = ManifestHandle::new(PolicyManifest::default());
        let snap = handle.snapshot();
        assert_eq!(snap.rate_limit.destructive_per_window, 5);

        let mut new_manifest = PolicyManifest::default();
        new_manifest.rate_limit.destructive_per_window = 99;
        handle.replace(new_manifest);

        let snap2 = handle.snapshot();
        assert_eq!(snap2.rate_limit.destructive_per_window, 99);
    }
}
