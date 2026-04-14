use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Display, Formatter};
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver};
use std::time::{SystemTime, UNIX_EPOCH};

use glob::glob;
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};

use crate::config::presets::preset_by_id;
use crate::config::schema::{AppConfig, PathPattern, Preset, ScanDomain};
use crate::discovery::{
    discover_from_builtin_presets, DetectedRuntime, DiscoveryOptions, DiscoveryReport,
    DiscoveryWarning,
};
use crate::scan::baseline::{
    diff_artifacts_against_baselines, drifts_to_findings, provenance_findings_for_artifacts,
};
use crate::scan::{Finding, ScanResult};
use crate::state::db::{StateStore, StateStoreError};
use crate::state::model::{AlertRecord, AlertStatus, ScanSnapshot};

const DEFAULT_DEBOUNCE_WINDOW_MS: u64 = 2_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchKind {
    File,
    Directory,
    RecursiveDirectory,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchTarget {
    pub logical_path: PathBuf,
    pub watch_root: PathBuf,
    pub watch_kind: WatchKind,
    pub source_label: String,
    pub excluded_subpaths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WatchPlan {
    pub targets: Vec<WatchTarget>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchBackendKind {
    Notify,
    Polling,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchBackendCapabilities {
    pub recursive_directory_supported: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchEvent {
    pub logical_path: PathBuf,
    pub observed_at_unix_ms: u64,
}

impl WatchEvent {
    pub fn new(logical_path: PathBuf, observed_at_unix_ms: u64) -> Self {
        Self {
            logical_path,
            observed_at_unix_ms,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchWarning {
    pub path: Option<PathBuf>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchCycleOutcome {
    pub snapshot: ScanSnapshot,
    pub watch_plan: WatchPlan,
    pub alerts_created: Vec<String>,
    pub warnings: Vec<WatchWarning>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchIterationOutcome {
    pub cold_boot: Option<WatchCycleOutcome>,
    pub event_outcomes: Vec<WatchEventOutcome>,
    pub warnings: Vec<WatchWarning>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchBackendSelection {
    pub kind: WatchBackendKind,
    pub warnings: Vec<WatchWarning>,
}

pub trait WatchBackend {
    fn poll(&mut self) -> Result<Vec<WatchEvent>, WatchBackendError>;
    fn drain_warnings(&mut self) -> Vec<WatchWarning>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchEventOutcome {
    Rescanned(WatchCycleOutcome),
    Debounced,
}

#[derive(Debug)]
pub struct WatchService {
    config: AppConfig,
    discovery_options: DiscoveryOptions,
    state: StateStore,
    debounce_window_ms: u64,
    last_rescan_at_by_path: BTreeMap<PathBuf, u64>,
    pending_warnings: Vec<WatchWarning>,
    bootstrapped: bool,
}

impl WatchService {
    pub fn new(config: AppConfig, discovery_options: DiscoveryOptions, state: StateStore) -> Self {
        Self {
            config,
            discovery_options,
            state,
            debounce_window_ms: DEFAULT_DEBOUNCE_WINDOW_MS,
            last_rescan_at_by_path: BTreeMap::new(),
            pending_warnings: Vec::new(),
            bootstrapped: false,
        }
    }

    pub fn with_debounce_window_ms(mut self, debounce_window_ms: u64) -> Self {
        self.debounce_window_ms = debounce_window_ms;
        self
    }

    pub fn state(&self) -> &StateStore {
        &self.state
    }

    pub fn state_mut(&mut self) -> &mut StateStore {
        &mut self.state
    }

    pub fn take_pending_warnings(&mut self) -> Vec<WatchWarning> {
        std::mem::take(&mut self.pending_warnings)
    }

    pub fn cold_boot_scan(
        &mut self,
        recorded_at_unix_ms: u64,
    ) -> Result<WatchCycleOutcome, WatchServiceError> {
        let outcome = self.run_scan_cycle(recorded_at_unix_ms)?;
        self.seed_debounce_targets(&outcome.watch_plan, recorded_at_unix_ms);
        self.bootstrapped = true;
        Ok(outcome)
    }

    pub fn handle_event(
        &mut self,
        event: WatchEvent,
    ) -> Result<WatchEventOutcome, WatchServiceError> {
        if let Some(previous_scan_at) = self.last_rescan_at_by_path.get(&event.logical_path) {
            if event.observed_at_unix_ms.saturating_sub(*previous_scan_at) < self.debounce_window_ms
            {
                return Ok(WatchEventOutcome::Debounced);
            }
        }

        let outcome = self.run_scan_cycle(event.observed_at_unix_ms)?;
        self.last_rescan_at_by_path
            .insert(event.logical_path, event.observed_at_unix_ms);
        Ok(WatchEventOutcome::Rescanned(outcome))
    }

    pub fn run_backend_batch(
        &mut self,
        backend: &mut dyn WatchBackend,
    ) -> Result<Vec<WatchEventOutcome>, WatchServiceError> {
        self.pending_warnings.extend(backend.drain_warnings());
        let events = backend.poll()?;
        self.pending_warnings.extend(backend.drain_warnings());
        let events = dedupe_events_by_logical_path(events);

        let mut outcomes = Vec::with_capacity(events.len());
        for event in events {
            if let Some(warning) = probe_event_target(&event.logical_path) {
                self.pending_warnings.push(warning);
                continue;
            }
            outcomes.push(self.handle_event(event)?);
        }

        Ok(outcomes)
    }

    pub fn run_iteration(
        &mut self,
        backend: &mut dyn WatchBackend,
        cold_boot_recorded_at_unix_ms: u64,
    ) -> Result<WatchIterationOutcome, WatchServiceError> {
        let cold_boot = if self.bootstrapped {
            None
        } else {
            Some(self.cold_boot_scan(cold_boot_recorded_at_unix_ms)?)
        };
        let event_outcomes = self.run_backend_batch(backend)?;
        let warnings = self.take_pending_warnings();

        Ok(WatchIterationOutcome {
            cold_boot,
            event_outcomes,
            warnings,
        })
    }

    fn run_scan_cycle(
        &mut self,
        recorded_at_unix_ms: u64,
    ) -> Result<WatchCycleOutcome, WatchServiceError> {
        let discovery = discover_from_builtin_presets(&self.discovery_options);
        let watch_plan = build_watch_plan(&discovery)?;
        let warnings = discovery_warnings(&discovery);
        let evidence = crate::scan::collect_scan_evidence(&self.config, &discovery);

        let baselines = self.state.list_baselines()?;
        let drift_findings = drifts_to_findings(&diff_artifacts_against_baselines(
            &baselines,
            &evidence.artifacts,
        ));
        let provenance_findings =
            provenance_findings_for_artifacts(&baselines, &evidence.artifacts);
        let combined = ScanResult::from_batches(vec![
            evidence.result.findings().to_vec(),
            drift_findings.clone(),
            provenance_findings,
        ]);
        let snapshot = ScanSnapshot {
            recorded_at_unix_ms,
            summary: combined.summary(),
            findings: combined.findings().to_vec(),
        };

        self.state
            .record_scan_snapshot_and_replace_current_findings(&snapshot, None)?;
        let alerts_created = self.append_new_drift_alerts(recorded_at_unix_ms, &drift_findings)?;

        // Run passive audit ingestion for discovered runtimes
        for runtime in &discovery.runtimes {
            if let Some(root) = &runtime.root {
                if let Err(e) = crate::audit::ingest::run_passive_ingestion(&mut self.state, root) {
                    self.pending_warnings.push(WatchWarning {
                        path: None,
                        message: format!("audit ingestion: {e}"),
                    });
                }
            }
        }

        Ok(WatchCycleOutcome {
            snapshot,
            watch_plan,
            alerts_created,
            warnings,
        })
    }

    fn append_new_drift_alerts(
        &mut self,
        recorded_at_unix_ms: u64,
        drift_findings: &[Finding],
    ) -> Result<Vec<String>, WatchServiceError> {
        let unresolved_finding_ids: BTreeSet<_> = self
            .state
            .list_unresolved_alerts()?
            .into_iter()
            .map(|alert| alert.finding_id)
            .collect();
        let mut alerts_created = Vec::new();

        for finding in drift_findings {
            if unresolved_finding_ids.contains(&finding.id) {
                continue;
            }

            let alert_id = format!("alert:{recorded_at_unix_ms}:{}", finding.id);
            self.state.append_alert(&AlertRecord {
                alert_id: alert_id.clone(),
                finding_id: finding.id.clone(),
                status: AlertStatus::Open,
                created_at_unix_ms: recorded_at_unix_ms,
                finding: finding.clone(),
            })?;
            alerts_created.push(alert_id);
        }

        Ok(alerts_created)
    }

    fn seed_debounce_targets(&mut self, watch_plan: &WatchPlan, recorded_at_unix_ms: u64) {
        for target in &watch_plan.targets {
            self.last_rescan_at_by_path
                .insert(target.logical_path.clone(), recorded_at_unix_ms);
        }
    }
}

pub fn select_watch_backend(
    plan: &WatchPlan,
    capabilities: WatchBackendCapabilities,
) -> WatchBackendSelection {
    let requires_recursive_directory = plan
        .targets
        .iter()
        .any(|target| target.watch_kind == WatchKind::RecursiveDirectory);
    if requires_recursive_directory && !capabilities.recursive_directory_supported {
        return WatchBackendSelection {
            kind: WatchBackendKind::Polling,
            warnings: vec![WatchWarning {
                path: None,
                message:
                    "recursive watch support is unavailable for this plan; falling back to polling"
                        .to_string(),
            }],
        };
    }

    WatchBackendSelection {
        kind: WatchBackendKind::Notify,
        warnings: Vec::new(),
    }
}

pub fn create_watch_backend(
    plan: &WatchPlan,
    capabilities: WatchBackendCapabilities,
) -> Result<(Box<dyn WatchBackend>, Vec<WatchWarning>), WatchBackendError> {
    let selection = select_watch_backend(plan, capabilities);
    let backend: Box<dyn WatchBackend> = match selection.kind {
        WatchBackendKind::Notify => Box::new(NotifyWatchBackend::new(plan)?),
        WatchBackendKind::Polling => Box::new(PollingWatchBackend::new(plan)),
    };

    Ok((backend, selection.warnings))
}

pub fn build_watch_plan(discovery: &DiscoveryReport) -> Result<WatchPlan, WatchPlanError> {
    let Some(runtime) = discovery.runtimes.first() else {
        return Ok(WatchPlan::default());
    };

    let Some(preset) = preset_by_id(&runtime.preset_id) else {
        return Err(WatchPlanError::UnsupportedPreset(runtime.preset_id.clone()));
    };

    let mut targets_by_logical_path = BTreeMap::new();

    for target in &runtime.targets {
        let source_label = source_label_for_domain(target.domain);
        for path in &target.paths {
            insert_watch_target(
                &mut targets_by_logical_path,
                path.clone(),
                source_label,
                excluded_subpaths_for_target(source_label, &preset),
            );
        }
    }

    for path in resolve_missing_skill_watch_paths(runtime, &preset) {
        insert_watch_target(
            &mut targets_by_logical_path,
            path,
            "skills",
            excluded_subpaths_for_target("skills", &preset),
        );
    }

    for path in resolve_critical_file_paths(runtime, &preset) {
        let source_label = infer_source_label(&path);
        insert_watch_target(
            &mut targets_by_logical_path,
            path,
            source_label,
            excluded_subpaths_for_target(source_label, &preset),
        );
    }

    Ok(WatchPlan {
        targets: targets_by_logical_path.into_values().collect(),
    })
}

fn insert_watch_target(
    targets_by_logical_path: &mut BTreeMap<PathBuf, WatchTarget>,
    logical_path: PathBuf,
    source_label: &str,
    excluded_subpaths: Vec<String>,
) {
    targets_by_logical_path
        .entry(logical_path.clone())
        .or_insert_with(|| WatchTarget {
            watch_root: nearest_existing_ancestor(&logical_path),
            watch_kind: watch_kind_for_path(&logical_path, source_label),
            logical_path,
            source_label: source_label.to_string(),
            excluded_subpaths,
        });
}

fn excluded_subpaths_for_target(source_label: &str, preset: &Preset) -> Vec<String> {
    if source_label == "skills" {
        return preset.excluded_dirs.clone();
    }

    Vec::new()
}

fn source_label_for_domain(domain: ScanDomain) -> &'static str {
    match domain {
        ScanDomain::Config => "config",
        ScanDomain::Skills => "skills",
        ScanDomain::Mcp => "mcp",
        ScanDomain::Env => "env",
        ScanDomain::Hooks => "hooks",
        ScanDomain::Bootstrap => "bootstrap",
    }
}

fn resolve_critical_file_paths(runtime: &DetectedRuntime, preset: &Preset) -> Vec<PathBuf> {
    let Some(runtime_root) = runtime.root.as_ref() else {
        return Vec::new();
    };

    let mut resolved = Vec::new();

    for pattern in &preset.critical_files {
        let path = resolve_openclaw_pattern(runtime_root, pattern);
        let path_str = path.to_string_lossy();

        if contains_glob(&path) {
            if let Ok(matches) = glob(&path_str) {
                let mut found_match = false;
                for entry in matches.filter_map(Result::ok) {
                    found_match = true;
                    resolved.push(entry);
                }
                if !found_match {
                    if let Some(anchor) = glob_anchor_path(&path) {
                        resolved.push(anchor);
                    }
                }
            }
        } else {
            resolved.push(path);
        }
    }

    resolved.sort();
    resolved.dedup();
    resolved
}

fn resolve_missing_skill_watch_paths(runtime: &DetectedRuntime, preset: &Preset) -> Vec<PathBuf> {
    let Some(runtime_root) = runtime.root.as_ref() else {
        return Vec::new();
    };

    let mut resolved = Vec::new();
    for target in &preset.scan_targets {
        if target.domain != ScanDomain::Skills {
            continue;
        }

        for pattern in &target.paths {
            let path = resolve_openclaw_pattern(runtime_root, pattern);
            let path_str = path.to_string_lossy();

            if contains_glob(&path) {
                if let Ok(matches) = glob(&path_str) {
                    let mut found_match = false;
                    for entry in matches.filter_map(Result::ok) {
                        found_match = true;
                        resolved.push(entry);
                    }
                    if !found_match {
                        if let Some(anchor) = glob_anchor_path(&path) {
                            resolved.push(anchor);
                        }
                    }
                }
            } else {
                resolved.push(path);
            }
        }
    }

    resolved.sort();
    resolved.dedup();
    resolved
}

fn resolve_openclaw_pattern(runtime_root: &Path, pattern: &PathPattern) -> PathBuf {
    if pattern.path == "~/.openclaw" {
        return runtime_root.to_path_buf();
    }

    if let Some(suffix) = pattern.path.strip_prefix("~/.openclaw/") {
        return runtime_root.join(suffix);
    }

    PathBuf::from(&pattern.path)
}

fn contains_glob(path: &Path) -> bool {
    let path = path.to_string_lossy();
    path.contains('*') || path.contains('?')
}

fn glob_anchor_path(path: &Path) -> Option<PathBuf> {
    let mut anchor = PathBuf::new();

    for component in path.components() {
        let component_str = component.as_os_str().to_string_lossy();
        if component_str.contains('*') || component_str.contains('?') {
            break;
        }
        anchor.push(component.as_os_str());
    }

    if anchor.as_os_str().is_empty() {
        None
    } else {
        Some(nearest_existing_ancestor(&anchor))
    }
}

fn infer_source_label(path: &Path) -> &'static str {
    let path_str = path.to_string_lossy();
    let file_name = path.file_name().and_then(|name| name.to_str());

    if path_str.contains("/skills/") {
        return "skills";
    }
    if file_name == Some(".env") {
        return "env";
    }
    if file_name == Some("openclaw.json") {
        return "config";
    }
    if file_name == Some("exec-approvals.json") {
        return "config";
    }
    if file_name == Some("auth-profiles.json") {
        return "config";
    }
    if path_str.contains("/credentials/") {
        return "config";
    }

    "config"
}

fn watch_kind_for_path(path: &Path, source_label: &str) -> WatchKind {
    if source_label == "skills" {
        return WatchKind::RecursiveDirectory;
    }
    if path.is_file() {
        return WatchKind::File;
    }

    WatchKind::Directory
}

fn nearest_existing_ancestor(path: &Path) -> PathBuf {
    let mut candidate = path.to_path_buf();

    loop {
        if candidate.exists() {
            return candidate;
        }

        if !candidate.pop() {
            return path
                .parent()
                .map(PathBuf::from)
                .unwrap_or_else(|| path.to_path_buf());
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchPlanError {
    UnsupportedPreset(String),
}

impl Display for WatchPlanError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedPreset(preset) => {
                write!(f, "unsupported preset for watch plan: {preset}")
            }
        }
    }
}

impl std::error::Error for WatchPlanError {}

#[derive(Debug)]
pub enum WatchServiceError {
    State(StateStoreError),
    WatchPlan(WatchPlanError),
    Backend(WatchBackendError),
}

impl Display for WatchServiceError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::State(error) => write!(f, "{error}"),
            Self::WatchPlan(error) => write!(f, "{error}"),
            Self::Backend(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for WatchServiceError {}

impl From<StateStoreError> for WatchServiceError {
    fn from(value: StateStoreError) -> Self {
        Self::State(value)
    }
}

impl From<WatchPlanError> for WatchServiceError {
    fn from(value: WatchPlanError) -> Self {
        Self::WatchPlan(value)
    }
}

impl From<WatchBackendError> for WatchServiceError {
    fn from(value: WatchBackendError) -> Self {
        Self::Backend(value)
    }
}

#[derive(Debug)]
pub enum WatchBackendError {
    Create(String),
    Poll(String),
}

impl Display for WatchBackendError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Create(message) | Self::Poll(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for WatchBackendError {}

pub struct NotifyWatchBackend {
    _watcher: RecommendedWatcher,
    receiver: Receiver<Result<Event, notify::Error>>,
    targets: Vec<WatchTarget>,
    warnings: Vec<WatchWarning>,
}

impl NotifyWatchBackend {
    pub fn new(plan: &WatchPlan) -> Result<Self, WatchBackendError> {
        let (sender, receiver) = mpsc::channel();
        let mut watcher = notify::recommended_watcher(move |result| {
            let _ = sender.send(result);
        })
        .map_err(|error| {
            WatchBackendError::Create(format!("failed to create notify watcher: {error}"))
        })?;

        for target in &plan.targets {
            watcher
                .watch(
                    &target.watch_root,
                    recursive_mode_for_kind(target.watch_kind),
                )
                .map_err(|error| {
                    WatchBackendError::Create(format!(
                        "failed to watch {}: {error}",
                        target.watch_root.display()
                    ))
                })?;
        }

        Ok(Self {
            _watcher: watcher,
            receiver,
            targets: plan.targets.clone(),
            warnings: Vec::new(),
        })
    }
}

impl WatchBackend for NotifyWatchBackend {
    fn poll(&mut self) -> Result<Vec<WatchEvent>, WatchBackendError> {
        let mut events = Vec::new();

        while let Ok(result) = self.receiver.try_recv() {
            match result {
                Ok(event) => events.extend(watch_events_from_notify_event(&self.targets, &event)),
                Err(error) => self.warnings.push(WatchWarning {
                    path: None,
                    message: format!("notify backend error: {error}"),
                }),
            }
        }

        Ok(events)
    }

    fn drain_warnings(&mut self) -> Vec<WatchWarning> {
        std::mem::take(&mut self.warnings)
    }
}

pub struct PollingWatchBackend {
    targets: Vec<WatchTarget>,
    fingerprints: BTreeMap<PathBuf, TargetFingerprint>,
    warnings: Vec<WatchWarning>,
}

impl PollingWatchBackend {
    pub fn new(plan: &WatchPlan) -> Self {
        Self {
            targets: plan.targets.clone(),
            fingerprints: BTreeMap::new(),
            warnings: Vec::new(),
        }
    }
}

impl WatchBackend for PollingWatchBackend {
    fn poll(&mut self) -> Result<Vec<WatchEvent>, WatchBackendError> {
        let mut events = Vec::new();

        for target in &self.targets {
            match fingerprint_for_target(target) {
                Ok(fingerprint) => match self.fingerprints.get(&target.logical_path) {
                    None => {
                        self.fingerprints
                            .insert(target.logical_path.clone(), fingerprint);
                    }
                    Some(previous) if previous != &fingerprint => {
                        self.fingerprints
                            .insert(target.logical_path.clone(), fingerprint);
                        events.push(WatchEvent::new(target.logical_path.clone(), now_unix_ms()));
                    }
                    Some(_) => {}
                },
                Err(error) => self.warnings.push(WatchWarning {
                    path: Some(target.logical_path.clone()),
                    message: format!(
                        "polling backend could not inspect {}: {error}",
                        target.logical_path.display()
                    ),
                }),
            }
        }

        Ok(events)
    }

    fn drain_warnings(&mut self) -> Vec<WatchWarning> {
        std::mem::take(&mut self.warnings)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TargetFingerprint {
    entries: Vec<FingerprintEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FingerprintEntry {
    path: String,
    stamp: FingerprintStamp,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum FingerprintStamp {
    Missing,
    Present {
        modified_at_unix_ms: u64,
        len: u64,
        is_dir: bool,
    },
}

fn discovery_warnings(discovery: &DiscoveryReport) -> Vec<WatchWarning> {
    discovery
        .warnings
        .iter()
        .chain(
            discovery
                .runtimes
                .iter()
                .flat_map(|runtime| runtime.warnings.iter()),
        )
        .map(watch_warning_from_discovery)
        .collect()
}

fn watch_warning_from_discovery(warning: &DiscoveryWarning) -> WatchWarning {
    WatchWarning {
        path: Some(warning.path.clone()),
        message: warning.message.clone(),
    }
}

fn probe_event_target(path: &Path) -> Option<WatchWarning> {
    if !path.exists() {
        return Some(WatchWarning {
            path: Some(path.to_path_buf()),
            message: format!("watched target is missing: {}", path.display()),
        });
    }

    let access_result = if path.is_dir() {
        fs::read_dir(path).map(|_| ())
    } else {
        File::open(path).map(|_| ())
    };

    match access_result {
        Ok(()) => None,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => Some(WatchWarning {
            path: Some(path.to_path_buf()),
            message: format!("watched target is unreadable: {}", path.display()),
        }),
        Err(error) => Some(WatchWarning {
            path: Some(path.to_path_buf()),
            message: format!(
                "watched target could not be inspected ({}): {error}",
                path.display()
            ),
        }),
    }
}

fn fingerprint_for_target(target: &WatchTarget) -> Result<TargetFingerprint, io::Error> {
    let mut entries = Vec::new();

    match target.watch_kind {
        WatchKind::File => {
            entries.push(FingerprintEntry {
                path: target.logical_path.display().to_string(),
                stamp: fingerprint_stamp_for_path(&target.logical_path)?,
            });
        }
        WatchKind::Directory => {
            entries.push(FingerprintEntry {
                path: target.logical_path.display().to_string(),
                stamp: fingerprint_stamp_for_path(&target.logical_path)?,
            });
            if target.logical_path.exists() {
                for entry in fs::read_dir(&target.logical_path)? {
                    let entry = entry?;
                    entries.push(FingerprintEntry {
                        path: entry.path().display().to_string(),
                        stamp: fingerprint_stamp_for_path(&entry.path())?,
                    });
                }
            }
        }
        WatchKind::RecursiveDirectory => {
            collect_recursive_fingerprint_entries(
                &target.logical_path,
                &target.excluded_subpaths,
                &mut entries,
            )?;
        }
    }

    entries.sort();
    Ok(TargetFingerprint { entries })
}

fn collect_recursive_fingerprint_entries(
    path: &Path,
    excluded_subpaths: &[String],
    entries: &mut Vec<FingerprintEntry>,
) -> Result<(), io::Error> {
    if is_excluded_path(path, excluded_subpaths) {
        return Ok(());
    }

    entries.push(FingerprintEntry {
        path: path.display().to_string(),
        stamp: fingerprint_stamp_for_path(path)?,
    });

    if !path.is_dir() {
        return Ok(());
    }

    for entry in fs::read_dir(path)? {
        let entry = entry?;
        collect_recursive_fingerprint_entries(&entry.path(), excluded_subpaths, entries)?;
    }

    Ok(())
}

fn is_excluded_path(path: &Path, excluded_subpaths: &[String]) -> bool {
    path.components().any(|component| {
        let name = component.as_os_str().to_string_lossy();
        excluded_subpaths.iter().any(|excluded| excluded == &name)
    })
}

fn fingerprint_stamp_for_path(path: &Path) -> Result<FingerprintStamp, io::Error> {
    match fs::metadata(path) {
        Ok(metadata) => {
            let modified_at_unix_ms = metadata
                .modified()
                .ok()
                .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
                .map(|duration| duration.as_millis() as u64)
                .unwrap_or(0);
            Ok(FingerprintStamp::Present {
                modified_at_unix_ms,
                len: metadata.len(),
                is_dir: metadata.is_dir(),
            })
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(FingerprintStamp::Missing),
        Err(error) => Err(error),
    }
}

fn recursive_mode_for_kind(kind: WatchKind) -> RecursiveMode {
    match kind {
        WatchKind::RecursiveDirectory => RecursiveMode::Recursive,
        WatchKind::File | WatchKind::Directory => RecursiveMode::NonRecursive,
    }
}

fn watch_events_from_notify_event(targets: &[WatchTarget], event: &Event) -> Vec<WatchEvent> {
    let observed_at_unix_ms = now_unix_ms();
    let mut seen_paths = BTreeSet::new();
    let mut mapped = Vec::new();

    for path in &event.paths {
        for target in targets {
            if notify_event_path_matches_target(target, path)
                && seen_paths.insert(target.logical_path.clone())
            {
                mapped.push(WatchEvent::new(
                    target.logical_path.clone(),
                    observed_at_unix_ms,
                ));
            }
        }
    }

    mapped
}

fn notify_event_path_matches_target(target: &WatchTarget, path: &Path) -> bool {
    match target.watch_kind {
        WatchKind::File => path == target.logical_path.as_path(),
        WatchKind::Directory => {
            path == target.logical_path.as_path() || path.starts_with(&target.logical_path)
        }
        WatchKind::RecursiveDirectory => {
            (path == target.logical_path.as_path() || path.starts_with(&target.logical_path))
                && !is_excluded_path(path, &target.excluded_subpaths)
        }
    }
}

fn dedupe_events_by_logical_path(events: Vec<WatchEvent>) -> Vec<WatchEvent> {
    let mut seen_paths = BTreeSet::new();
    let mut deduped = Vec::with_capacity(events.len());

    for event in events {
        if seen_paths.insert(event.logical_path.clone()) {
            deduped.push(event);
        }
    }

    deduped
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use notify::{event::EventAttributes, EventKind};

    use super::*;

    #[test]
    fn notify_mapping_ignores_sibling_changes_for_ancestor_directory_targets() {
        let target = WatchTarget {
            logical_path: PathBuf::from("/tmp/.openclaw/exec-approvals.json"),
            watch_root: PathBuf::from("/tmp/.openclaw"),
            watch_kind: WatchKind::Directory,
            source_label: "config".to_string(),
            excluded_subpaths: Vec::new(),
        };
        let sibling_event = Event {
            kind: EventKind::Any,
            paths: vec![PathBuf::from("/tmp/.openclaw/.env")],
            attrs: EventAttributes::new(),
        };
        let exact_event = Event {
            kind: EventKind::Any,
            paths: vec![PathBuf::from("/tmp/.openclaw/exec-approvals.json")],
            attrs: EventAttributes::new(),
        };

        assert!(
            watch_events_from_notify_event(&[target.clone()], &sibling_event).is_empty(),
            "ancestor directory watches should not treat sibling file changes as changes to the logical target"
        );
        assert_eq!(
            watch_events_from_notify_event(&[target], &exact_event).len(),
            1,
            "the logical target itself should still map into one watch event"
        );
    }

    #[test]
    fn notify_mapping_ignores_excluded_recursive_subtrees() {
        let target = WatchTarget {
            logical_path: PathBuf::from("/tmp/.openclaw/skills"),
            watch_root: PathBuf::from("/tmp/.openclaw/skills"),
            watch_kind: WatchKind::RecursiveDirectory,
            source_label: "skills".to_string(),
            excluded_subpaths: vec!["node_modules".to_string()],
        };
        let excluded_event = Event {
            kind: EventKind::Any,
            paths: vec![PathBuf::from(
                "/tmp/.openclaw/skills/node_modules/pkg/SKILL.md",
            )],
            attrs: EventAttributes::new(),
        };
        let allowed_event = Event {
            kind: EventKind::Any,
            paths: vec![PathBuf::from("/tmp/.openclaw/skills/local-skill/SKILL.md")],
            attrs: EventAttributes::new(),
        };

        assert!(
            watch_events_from_notify_event(&[target.clone()], &excluded_event).is_empty(),
            "excluded recursive subtrees should not trigger notify-derived watch events"
        );
        assert_eq!(
            watch_events_from_notify_event(&[target], &allowed_event).len(),
            1,
            "non-excluded descendants should still map into one watch event"
        );
    }
}
