use std::fs;

use clawguard::config::schema::{AlertStrategy, AppConfig, ScanDomain, Strictness};
use clawguard::daemon::watch::{
    build_watch_plan, select_watch_backend, WatchBackend, WatchBackendCapabilities,
    WatchBackendError, WatchBackendKind, WatchEvent, WatchEventOutcome, WatchKind, WatchService,
    WatchWarning,
};
use clawguard::discovery::{
    discover_from_builtin_presets, DetectedRuntime, DiscoveredTarget, DiscoveryOptions,
    DiscoveryReport,
};
use clawguard::scan::baseline::{
    diff_artifacts_against_baselines, drifts_to_findings, BaselineDrift, BaselineDriftKind,
};
use clawguard::scan::{
    collect_scan_evidence, BaselineArtifact, FindingCategory, Fixability, Severity,
};
use clawguard::state::db::{StateStore, StateStoreConfig};
use clawguard::state::model::{BaselineRecord, RestorePayloadRecord};
use tempfile::tempdir;

#[test]
fn collect_scan_evidence_includes_hash_artifacts_from_detectors() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let home_dir = temp_dir.path();
    let state_dir = home_dir.join(".openclaw");
    let skill_dir = state_dir.join("skills").join("local-skill");

    fs::create_dir_all(&skill_dir).expect("skill dir should be created");
    fs::write(state_dir.join("openclaw.json"), "{ }").expect("config should be written");
    fs::write(
        state_dir.join(".env"),
        "OPENAI_API_KEY=env:OPENAI_API_KEY\n",
    )
    .expect("env file should be written");
    fs::write(
        skill_dir.join("SKILL.md"),
        "# Local Skill\n\nThis is a safe local skill.\n",
    )
    .expect("skill file should be written");

    let discovery = discover_from_builtin_presets(&DiscoveryOptions {
        home_dir: Some(home_dir.to_path_buf()),
        ..DiscoveryOptions::default()
    });
    let config = app_config();

    let evidence = collect_scan_evidence(&config, &discovery);
    let artifact_paths: Vec<String> = evidence
        .artifacts
        .iter()
        .map(|artifact| artifact.path.clone())
        .collect();

    assert!(
        artifact_paths
            .iter()
            .any(|path| path.ends_with(".openclaw/openclaw.json")),
        "config file should produce a hash artifact"
    );
    assert!(
        artifact_paths
            .iter()
            .any(|path| path.ends_with(".openclaw/.env")),
        "env file should produce a hash artifact"
    );
    assert!(
        artifact_paths.iter().any(|path| path.ends_with("SKILL.md")),
        "skill file should produce a hash artifact"
    );
    assert!(
        evidence
            .artifacts
            .iter()
            .all(|artifact| artifact.sha256.len() == 64),
        "every collected artifact should expose a sha256 hash"
    );
    assert_eq!(
        artifact_paths
            .iter()
            .filter(|path| path.ends_with(".openclaw/openclaw.json"))
            .count(),
        1,
        "shared config/MCP evidence should deduplicate the same file path"
    );
}

#[test]
fn collect_scan_evidence_maps_mcp_only_targets_into_artifacts() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let runtime_root = temp_dir.path().join(".openclaw");
    fs::create_dir_all(&runtime_root).expect("runtime root should be created");
    let config_path = runtime_root.join("openclaw.json");
    fs::write(
        &config_path,
        r#"
        {
          mcpServers: {
            demo: {
              command: "node",
              args: ["server.js"],
            },
          },
        }
        "#,
    )
    .expect("openclaw config should be written");

    let discovery = DiscoveryReport {
        runtimes: vec![DetectedRuntime {
            preset_id: "openclaw".to_string(),
            root: Some(runtime_root),
            targets: vec![DiscoveredTarget {
                domain: ScanDomain::Mcp,
                paths: vec![config_path],
            }],
            warnings: vec![],
            recommended: true,
        }],
        warnings: vec![],
    };

    let evidence = collect_scan_evidence(&app_config(), &discovery);

    assert_eq!(evidence.artifacts.len(), 1);
    assert_eq!(evidence.artifacts[0].source_label, "mcp");
    assert_eq!(evidence.artifacts[0].category, FindingCategory::Mcp);
}

#[test]
fn baseline_diff_reports_added_modified_and_removed_paths() {
    let drifts = diff_artifacts_against_baselines(
        &[
            BaselineRecord {
                path: "/tmp/openclaw.json".to_string(),
                sha256: "aaa".to_string(),
                approved_at_unix_ms: 1_710_000_000_000,
                source_label: "config".to_string(),
            },
            BaselineRecord {
                path: "/tmp/skills/old/SKILL.md".to_string(),
                sha256: "bbb".to_string(),
                approved_at_unix_ms: 1_710_000_000_000,
                source_label: "skills".to_string(),
            },
        ],
        &[
            BaselineArtifact {
                path: "/tmp/openclaw.json".to_string(),
                sha256: "changed".to_string(),
                source_label: "config".to_string(),
                category: FindingCategory::Config,
            },
            BaselineArtifact {
                path: "/tmp/skills/new/SKILL.md".to_string(),
                sha256: "ccc".to_string(),
                source_label: "skills".to_string(),
                category: FindingCategory::Skills,
            },
        ],
    );

    assert_eq!(drifts.len(), 3);
    assert!(drifts.iter().any(|drift| {
        drift.path == "/tmp/openclaw.json" && drift.kind == BaselineDriftKind::Modified
    }));
    assert!(drifts.iter().any(|drift| {
        drift.path == "/tmp/skills/new/SKILL.md" && drift.kind == BaselineDriftKind::Added
    }));
    assert!(drifts.iter().any(|drift| {
        drift.path == "/tmp/skills/old/SKILL.md" && drift.kind == BaselineDriftKind::Removed
    }));
}

#[test]
fn baseline_diff_ignores_source_label_only_changes_and_empty_inputs() {
    let unchanged = diff_artifacts_against_baselines(
        &[BaselineRecord {
            path: "/tmp/openclaw.json".to_string(),
            sha256: "aaa".to_string(),
            approved_at_unix_ms: 1_710_000_000_000,
            source_label: "config".to_string(),
        }],
        &[BaselineArtifact {
            path: "/tmp/openclaw.json".to_string(),
            sha256: "aaa".to_string(),
            source_label: "mcp".to_string(),
            category: FindingCategory::Mcp,
        }],
    );

    assert!(
        unchanged.is_empty(),
        "source label changes alone should not be treated as content drift"
    );
    assert!(
        diff_artifacts_against_baselines(&[], &[]).is_empty(),
        "empty baseline and empty artifact sets should produce no drifts"
    );
}

#[test]
fn baseline_diff_handles_added_removed_and_no_change_boundaries() {
    let added = diff_artifacts_against_baselines(
        &[],
        &[BaselineArtifact {
            path: "/tmp/new.env".to_string(),
            sha256: "aaa".to_string(),
            source_label: "env".to_string(),
            category: FindingCategory::Secrets,
        }],
    );
    assert_eq!(added.len(), 1);
    assert_eq!(added[0].kind, BaselineDriftKind::Added);

    let removed = diff_artifacts_against_baselines(
        &[BaselineRecord {
            path: "/tmp/old.env".to_string(),
            sha256: "bbb".to_string(),
            approved_at_unix_ms: 1_710_000_000_000,
            source_label: "env".to_string(),
        }],
        &[],
    );
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0].kind, BaselineDriftKind::Removed);

    let no_change = diff_artifacts_against_baselines(
        &[BaselineRecord {
            path: "/tmp/same.env".to_string(),
            sha256: "ccc".to_string(),
            approved_at_unix_ms: 1_710_000_000_000,
            source_label: "env".to_string(),
        }],
        &[BaselineArtifact {
            path: "/tmp/same.env".to_string(),
            sha256: "ccc".to_string(),
            source_label: "env".to_string(),
            category: FindingCategory::Secrets,
        }],
    );
    assert!(no_change.is_empty());
}

#[test]
fn baseline_modified_drift_converts_to_high_severity_finding() {
    let findings = drifts_to_findings(&[BaselineDrift {
        path: "/tmp/openclaw.json".to_string(),
        source_label: "config".to_string(),
        kind: BaselineDriftKind::Modified,
        expected_sha256: Some("aaa".to_string()),
        actual_sha256: Some("bbb".to_string()),
    }]);

    assert_eq!(findings.len(), 1);
    let finding = &findings[0];
    assert_eq!(finding.detector_id, "baseline");
    assert_eq!(finding.category, FindingCategory::Drift);
    assert_eq!(finding.severity, Severity::High);
    assert_eq!(finding.fixability, Fixability::Manual);
    assert_eq!(
        finding.evidence.as_deref(),
        Some("approved=aaa, current=bbb")
    );
}

#[test]
fn baseline_removed_drift_converts_to_high_severity_finding() {
    let findings = drifts_to_findings(&[BaselineDrift {
        path: "/tmp/openclaw.json".to_string(),
        source_label: "config".to_string(),
        kind: BaselineDriftKind::Removed,
        expected_sha256: Some("aaa".to_string()),
        actual_sha256: None,
    }]);

    assert_eq!(findings.len(), 1);
    let finding = &findings[0];
    assert_eq!(finding.severity, Severity::High);
    assert!(finding
        .plain_english_explanation
        .contains("missing from the current runtime state"));
    assert_eq!(
        finding.recommended_action.label,
        "Restore or intentionally re-approve the missing file before trusting this runtime"
    );
}

#[test]
fn baseline_added_drift_converts_to_medium_severity_finding() {
    let findings = drifts_to_findings(&[BaselineDrift {
        path: "/tmp/skills/new/SKILL.md".to_string(),
        source_label: "skills".to_string(),
        kind: BaselineDriftKind::Added,
        expected_sha256: None,
        actual_sha256: Some("ccc".to_string()),
    }]);

    assert_eq!(findings.len(), 1);
    let finding = &findings[0];
    assert_eq!(finding.severity, Severity::Medium);
    assert_eq!(finding.fixability, Fixability::Manual);
    assert!(
        !finding.recommended_action.label.contains("Restore"),
        "added drift should not imply restore behavior in this slice"
    );
}

#[test]
fn drift_findings_use_stable_ids() {
    let findings = drifts_to_findings(&[
        BaselineDrift {
            path: "/tmp/openclaw.json".to_string(),
            source_label: "config".to_string(),
            kind: BaselineDriftKind::Modified,
            expected_sha256: Some("aaa".to_string()),
            actual_sha256: Some("bbb".to_string()),
        },
        BaselineDrift {
            path: "/tmp/skills/new/SKILL.md".to_string(),
            source_label: "skills".to_string(),
            kind: BaselineDriftKind::Added,
            expected_sha256: None,
            actual_sha256: Some("ccc".to_string()),
        },
    ]);

    assert_eq!(findings[0].id, "baseline:modified:/tmp/openclaw.json");
    assert_eq!(findings[1].id, "baseline:added:/tmp/skills/new/SKILL.md");
}

#[test]
fn build_watch_plan_includes_skill_roots_and_critical_file_targets() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let home_dir = temp_dir.path();
    let state_dir = home_dir.join(".openclaw");
    let skill_dir = state_dir.join("skills");
    fs::create_dir_all(&skill_dir).expect("skills root should be created");
    fs::write(state_dir.join("openclaw.json"), "{ }").expect("config should be written");
    fs::write(
        state_dir.join(".env"),
        "OPENAI_API_KEY=env:OPENAI_API_KEY\n",
    )
    .expect("env should be written");

    let discovery = discover_from_builtin_presets(&DiscoveryOptions {
        home_dir: Some(home_dir.to_path_buf()),
        ..DiscoveryOptions::default()
    });

    let plan = build_watch_plan(&discovery).expect("watch plan should build");

    assert!(plan.targets.iter().any(|target| {
        target.logical_path == skill_dir
            && target.watch_root == skill_dir
            && target.watch_kind == WatchKind::RecursiveDirectory
            && target.source_label == "skills"
    }));
    assert!(plan.targets.iter().any(|target| {
        target.logical_path == state_dir.join("openclaw.json")
            && target.watch_kind == WatchKind::File
            && target.source_label == "config"
    }));
    assert!(plan.targets.iter().any(|target| {
        target.logical_path == state_dir.join(".env")
            && target.watch_kind == WatchKind::File
            && target.source_label == "env"
    }));
}

#[test]
fn build_watch_plan_uses_nearest_existing_ancestor_for_missing_files() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let home_dir = temp_dir.path();
    let state_dir = home_dir.join(".openclaw");
    fs::create_dir_all(&state_dir).expect("state dir should be created");
    fs::write(state_dir.join("openclaw.json"), "{ }").expect("config should be written");

    let discovery = discover_from_builtin_presets(&DiscoveryOptions {
        home_dir: Some(home_dir.to_path_buf()),
        ..DiscoveryOptions::default()
    });

    let plan = build_watch_plan(&discovery).expect("watch plan should build");
    let exec_target = plan
        .targets
        .iter()
        .find(|target| target.logical_path == state_dir.join("exec-approvals.json"))
        .expect("missing exec approvals target should still produce a watch target");

    assert_eq!(exec_target.watch_root, state_dir);
    assert_eq!(exec_target.watch_kind, WatchKind::Directory);
}

#[test]
fn build_watch_plan_deduplicates_shared_config_and_mcp_paths() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let runtime_root = temp_dir.path().join(".openclaw");
    fs::create_dir_all(&runtime_root).expect("runtime root should be created");
    let config_path = runtime_root.join("openclaw.json");
    fs::write(&config_path, "{ }").expect("config should be written");

    let discovery = DiscoveryReport {
        runtimes: vec![DetectedRuntime {
            preset_id: "openclaw".to_string(),
            root: Some(runtime_root),
            targets: vec![
                DiscoveredTarget {
                    domain: ScanDomain::Config,
                    paths: vec![config_path.clone()],
                },
                DiscoveredTarget {
                    domain: ScanDomain::Mcp,
                    paths: vec![config_path.clone()],
                },
            ],
            warnings: vec![],
            recommended: true,
        }],
        warnings: vec![],
    };

    let plan = build_watch_plan(&discovery).expect("watch plan should build");
    let matching: Vec<_> = plan
        .targets
        .iter()
        .filter(|target| target.logical_path == config_path)
        .collect();

    assert_eq!(matching.len(), 1);
    assert_eq!(matching[0].source_label, "config");
}

#[test]
fn build_watch_plan_does_not_watch_runtime_root_recursively() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let home_dir = temp_dir.path();
    let state_dir = home_dir.join(".openclaw");
    let skill_dir = state_dir.join("skills");
    fs::create_dir_all(&skill_dir).expect("skills root should be created");
    fs::write(state_dir.join("openclaw.json"), "{ }").expect("config should be written");

    let discovery = discover_from_builtin_presets(&DiscoveryOptions {
        home_dir: Some(home_dir.to_path_buf()),
        ..DiscoveryOptions::default()
    });

    let plan = build_watch_plan(&discovery).expect("watch plan should build");

    assert!(
        plan.targets.iter().all(|target| {
            !(target.watch_root == state_dir && target.watch_kind == WatchKind::RecursiveDirectory)
        }),
        "the whole runtime root should never be watched recursively"
    );
}

#[test]
fn build_watch_plan_keeps_missing_skill_root_observable() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let home_dir = temp_dir.path();
    let state_dir = home_dir.join(".openclaw");
    let skill_dir = state_dir.join("skills");
    fs::create_dir_all(&state_dir).expect("state dir should be created");
    fs::write(state_dir.join("openclaw.json"), "{ }").expect("config should be written");

    let discovery = discover_from_builtin_presets(&DiscoveryOptions {
        home_dir: Some(home_dir.to_path_buf()),
        ..DiscoveryOptions::default()
    });

    let plan = build_watch_plan(&discovery).expect("watch plan should build");
    let skill_target = plan
        .targets
        .iter()
        .find(|target| target.logical_path == skill_dir)
        .expect("missing skills root should still produce a watch target");

    assert_eq!(skill_target.watch_root, state_dir);
    assert_eq!(skill_target.watch_kind, WatchKind::RecursiveDirectory);
    assert_eq!(skill_target.source_label, "skills");
    assert!(skill_target
        .excluded_subpaths
        .contains(&"node_modules".to_string()));
    assert!(skill_target.excluded_subpaths.contains(&"dist".to_string()));
}

#[test]
fn backend_selection_falls_back_to_polling_without_recursive_support() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let home_dir = temp_dir.path();
    let state_dir = home_dir.join(".openclaw");
    let skill_dir = state_dir.join("skills");
    fs::create_dir_all(&skill_dir).expect("skills root should be created");
    fs::write(state_dir.join("openclaw.json"), "{ }").expect("config should be written");

    let discovery = discover_from_builtin_presets(&DiscoveryOptions {
        home_dir: Some(home_dir.to_path_buf()),
        ..DiscoveryOptions::default()
    });
    let plan = build_watch_plan(&discovery).expect("watch plan should build");

    let selection = select_watch_backend(
        &plan,
        WatchBackendCapabilities {
            recursive_directory_supported: false,
        },
    );

    assert_eq!(selection.kind, WatchBackendKind::Polling);
    assert!(
        selection
            .warnings
            .iter()
            .any(|warning| warning.message.contains("recursive watch support")),
        "fallback should explain why polling was selected"
    );
}

#[test]
fn backend_selection_prefers_notify_when_recursive_support_exists() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let home_dir = temp_dir.path();
    let state_dir = home_dir.join(".openclaw");
    let skill_dir = state_dir.join("skills");
    fs::create_dir_all(&skill_dir).expect("skills root should be created");
    fs::write(state_dir.join("openclaw.json"), "{ }").expect("config should be written");

    let discovery = discover_from_builtin_presets(&DiscoveryOptions {
        home_dir: Some(home_dir.to_path_buf()),
        ..DiscoveryOptions::default()
    });
    let plan = build_watch_plan(&discovery).expect("watch plan should build");

    let selection = select_watch_backend(
        &plan,
        WatchBackendCapabilities {
            recursive_directory_supported: true,
        },
    );

    assert_eq!(selection.kind, WatchBackendKind::Notify);
    assert!(
        selection.warnings.is_empty(),
        "notify backend should not emit a fallback warning when capabilities match"
    );
}

#[derive(Default)]
struct FakeWatchBackend {
    events: Vec<WatchEvent>,
    warnings: Vec<WatchWarning>,
}

impl FakeWatchBackend {
    fn with_event(mut self, event: WatchEvent) -> Self {
        self.events.push(event);
        self
    }

    fn with_warning(mut self, warning: WatchWarning) -> Self {
        self.warnings.push(warning);
        self
    }
}

impl WatchBackend for FakeWatchBackend {
    fn poll(&mut self) -> Result<Vec<WatchEvent>, WatchBackendError> {
        Ok(std::mem::take(&mut self.events))
    }

    fn drain_warnings(&mut self) -> Vec<WatchWarning> {
        std::mem::take(&mut self.warnings)
    }
}

#[test]
fn polling_backend_reports_file_changes_for_tracked_targets() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let home_dir = temp_dir.path();
    let state_dir = home_dir.join(".openclaw");
    let config_path = state_dir.join("openclaw.json");
    fs::create_dir_all(&state_dir).expect("state dir should be created");
    fs::write(&config_path, "{ }").expect("config should be written");

    let discovery = discover_from_builtin_presets(&DiscoveryOptions {
        home_dir: Some(home_dir.to_path_buf()),
        ..DiscoveryOptions::default()
    });
    let plan = build_watch_plan(&discovery).expect("watch plan should build");
    let mut backend = clawguard::daemon::watch::PollingWatchBackend::new(&plan);

    assert!(
        backend
            .poll()
            .expect("initial poll should succeed")
            .is_empty(),
        "first poll should only seed the baseline view"
    );

    fs::write(
        &config_path,
        r#"{ agents: { defaults: { sandbox: { mode: "off" } } } }"#,
    )
    .expect("config should be updated");

    let events = backend.poll().expect("second poll should succeed");
    assert!(
        events.iter().any(|event| event.logical_path == config_path),
        "tracked config change should produce a watch event"
    );
}

#[test]
fn polling_backend_ignores_changes_inside_excluded_recursive_subtrees() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let home_dir = temp_dir.path();
    let state_dir = home_dir.join(".openclaw");
    let skill_root = state_dir.join("skills");
    let excluded_dir = skill_root.join("node_modules");
    let excluded_skill = excluded_dir.join("ignored").join("SKILL.md");
    fs::create_dir_all(
        excluded_skill
            .parent()
            .expect("excluded fixture parent should exist"),
    )
    .expect("excluded tree should be created");
    fs::write(state_dir.join("openclaw.json"), "{ }").expect("config should be written");
    fs::write(&excluded_skill, "# ignored").expect("excluded skill should be written");

    let discovery = discover_from_builtin_presets(&DiscoveryOptions {
        home_dir: Some(home_dir.to_path_buf()),
        ..DiscoveryOptions::default()
    });
    let plan = build_watch_plan(&discovery).expect("watch plan should build");
    let mut backend = clawguard::daemon::watch::PollingWatchBackend::new(&plan);
    assert!(
        backend
            .poll()
            .expect("initial poll should succeed")
            .is_empty(),
        "first poll should seed the baseline view"
    );

    fs::write(&excluded_skill, "# ignored\n\nchanged\n").expect("excluded skill should update");

    assert!(
        backend
            .poll()
            .expect("poll after excluded change should succeed")
            .is_empty(),
        "changes inside excluded recursive subtrees should be ignored"
    );
}

#[test]
fn watch_service_can_poll_events_from_fake_backend() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let home_dir = temp_dir.path();
    let state_dir = home_dir.join(".openclaw");
    let config_path = state_dir.join("openclaw.json");
    fs::create_dir_all(&state_dir).expect("state dir should be created");
    fs::write(
        &config_path,
        r#"
        {
          agents: {
            defaults: {
              sandbox: {
                mode: "all",
                docker: {
                  network: "none",
                },
              },
            },
          },
          tools: {
            exec: {
              host: "sandbox",
            },
          },
        }
        "#,
    )
    .expect("safe config should be written");

    let mut service = WatchService::new(
        app_config(),
        DiscoveryOptions {
            home_dir: Some(home_dir.to_path_buf()),
            ..DiscoveryOptions::default()
        },
        open_state_store(home_dir),
    );

    service
        .cold_boot_scan(1_763_900_000_000)
        .expect("cold boot should succeed");

    fs::write(
        &config_path,
        r#"
        {
          agents: {
            defaults: {
              sandbox: {
                mode: "off",
                docker: {
                  network: "host",
                },
              },
            },
          },
          tools: {
            exec: {
              host: "sandbox",
            },
          },
        }
        "#,
    )
    .expect("updated config should be written");

    let mut backend =
        FakeWatchBackend::default().with_event(WatchEvent::new(config_path, 1_763_900_003_000));

    let outcomes = service
        .run_backend_batch(&mut backend)
        .expect("backend batch should succeed");

    assert_eq!(outcomes.len(), 1);
    let WatchEventOutcome::Rescanned(cycle) = &outcomes[0] else {
        panic!("fake backend event should trigger a rescan");
    };
    assert_eq!(cycle.snapshot.recorded_at_unix_ms, 1_763_900_003_000);
}

#[test]
fn watch_service_records_backend_warning_without_crashing() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let home_dir = temp_dir.path();
    let state_dir = home_dir.join(".openclaw");
    fs::create_dir_all(&state_dir).expect("state dir should be created");
    fs::write(state_dir.join("openclaw.json"), "{ }").expect("config should be written");

    let mut service = WatchService::new(
        app_config(),
        DiscoveryOptions {
            home_dir: Some(home_dir.to_path_buf()),
            ..DiscoveryOptions::default()
        },
        open_state_store(home_dir),
    );

    service
        .cold_boot_scan(1_763_900_000_000)
        .expect("cold boot should succeed");

    let mut backend = FakeWatchBackend::default().with_warning(WatchWarning {
        path: Some(state_dir.clone()),
        message: "backend warning: recursive watch degraded".to_string(),
    });

    let outcomes = service
        .run_backend_batch(&mut backend)
        .expect("warning-only backend batch should succeed");

    assert!(
        outcomes.is_empty(),
        "warning-only backend batch should not force a rescan"
    );
    assert_eq!(
        service
            .take_pending_warnings()
            .into_iter()
            .map(|warning| warning.message)
            .collect::<Vec<_>>(),
        vec!["backend warning: recursive watch degraded".to_string()]
    );
}

#[test]
fn deleted_watched_directory_warns_and_keeps_service_alive() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let home_dir = temp_dir.path();
    let state_dir = home_dir.join(".openclaw");
    let skill_dir = state_dir.join("skills").join("local-skill");
    fs::create_dir_all(&skill_dir).expect("skill dir should be created");
    fs::write(state_dir.join("openclaw.json"), "{ }").expect("config should be written");
    fs::write(skill_dir.join("SKILL.md"), "# skill").expect("skill file should be written");

    let mut service = WatchService::new(
        app_config(),
        DiscoveryOptions {
            home_dir: Some(home_dir.to_path_buf()),
            ..DiscoveryOptions::default()
        },
        open_state_store(home_dir),
    );
    service
        .cold_boot_scan(1_763_900_000_000)
        .expect("cold boot should succeed");

    fs::remove_dir_all(&skill_dir).expect("skill dir should be removed");
    let mut backend = FakeWatchBackend::default()
        .with_event(WatchEvent::new(skill_dir.clone(), 1_763_900_003_000));

    let outcomes = service
        .run_backend_batch(&mut backend)
        .expect("deleted target should not crash the service");

    assert!(outcomes.is_empty(), "missing target should be skipped");
    assert!(
        service
            .take_pending_warnings()
            .into_iter()
            .any(|warning| warning.path.as_ref() == Some(&skill_dir)
                && warning.message.contains("missing")),
        "deleted watched directory should become a warning"
    );
}

#[cfg(unix)]
#[test]
fn permission_denied_target_warns_and_skips_without_crash() {
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = tempdir().expect("temp dir should be created");
    let home_dir = temp_dir.path();
    let state_dir = home_dir.join(".openclaw");
    let config_path = state_dir.join("openclaw.json");
    fs::create_dir_all(&state_dir).expect("state dir should be created");
    fs::write(&config_path, "{ }").expect("config should be written");

    let mut service = WatchService::new(
        app_config(),
        DiscoveryOptions {
            home_dir: Some(home_dir.to_path_buf()),
            ..DiscoveryOptions::default()
        },
        open_state_store(home_dir),
    );
    service
        .cold_boot_scan(1_763_900_000_000)
        .expect("cold boot should succeed");

    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o000))
        .expect("config permissions should be restricted");
    let mut backend = FakeWatchBackend::default()
        .with_event(WatchEvent::new(config_path.clone(), 1_763_900_003_000));

    let outcomes = service
        .run_backend_batch(&mut backend)
        .expect("permission denied target should not crash the service");

    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600))
        .expect("config permissions should be restored");

    assert!(outcomes.is_empty(), "unreadable target should be skipped");
    assert!(
        service
            .take_pending_warnings()
            .into_iter()
            .any(|warning| warning.path.as_ref() == Some(&config_path)
                && warning.message.contains("unreadable")),
        "permission denied target should become a warning"
    );
}

#[test]
fn watch_loop_processes_cold_boot_then_event_batches() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let home_dir = temp_dir.path();
    let state_dir = home_dir.join(".openclaw");
    let config_path = state_dir.join("openclaw.json");
    fs::create_dir_all(&state_dir).expect("state dir should be created");
    fs::write(&config_path, "{ }").expect("config should be written");

    let mut service = WatchService::new(
        app_config(),
        DiscoveryOptions {
            home_dir: Some(home_dir.to_path_buf()),
            ..DiscoveryOptions::default()
        },
        open_state_store(home_dir),
    );
    let mut backend = FakeWatchBackend::default();

    let first = service
        .run_iteration(&mut backend, 1_763_900_000_000)
        .expect("first iteration should succeed");
    assert!(
        first.cold_boot.is_some(),
        "first iteration should cold boot"
    );
    assert!(first.event_outcomes.is_empty());

    fs::write(
        &config_path,
        r#"
        {
          agents: {
            defaults: {
              sandbox: {
                mode: "off",
                docker: {
                  network: "host",
                },
              },
            },
          },
          tools: {
            exec: {
              host: "sandbox",
            },
          },
        }
        "#,
    )
    .expect("updated config should be written");

    let mut backend =
        FakeWatchBackend::default().with_event(WatchEvent::new(config_path, 1_763_900_003_000));
    let second = service
        .run_iteration(&mut backend, 1_763_900_001_000)
        .expect("second iteration should succeed");

    assert!(second.cold_boot.is_none(), "cold boot should only run once");
    assert_eq!(second.event_outcomes.len(), 1);
}

#[test]
fn burst_events_are_debounced_into_single_rescan() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let home_dir = temp_dir.path();
    let state_dir = home_dir.join(".openclaw");
    let config_path = state_dir.join("openclaw.json");
    fs::create_dir_all(&state_dir).expect("state dir should be created");
    fs::write(
        &config_path,
        r#"
        {
          agents: {
            defaults: {
              sandbox: {
                mode: "all",
                docker: {
                  network: "none",
                },
              },
            },
          },
          tools: {
            exec: {
              host: "sandbox",
            },
          },
        }
        "#,
    )
    .expect("config should be written");

    let mut service = WatchService::new(
        app_config(),
        DiscoveryOptions {
            home_dir: Some(home_dir.to_path_buf()),
            ..DiscoveryOptions::default()
        },
        open_state_store(home_dir),
    );
    service
        .cold_boot_scan(1_763_900_000_000)
        .expect("cold boot should succeed");

    let mut backend = FakeWatchBackend::default()
        .with_event(WatchEvent::new(config_path.clone(), 1_763_900_001_000))
        .with_event(WatchEvent::new(config_path, 1_763_900_001_500));

    let outcomes = service
        .run_backend_batch(&mut backend)
        .expect("burst event batch should succeed");

    assert_eq!(outcomes.len(), 1, "duplicate burst events should collapse");
    assert_eq!(outcomes[0], WatchEventOutcome::Debounced);
}

#[test]
fn duplicate_events_for_inflight_target_are_suppressed() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let home_dir = temp_dir.path();
    let state_dir = home_dir.join(".openclaw");
    let config_path = state_dir.join("openclaw.json");
    fs::create_dir_all(&state_dir).expect("state dir should be created");
    fs::write(
        &config_path,
        r#"
        {
          agents: {
            defaults: {
              sandbox: {
                mode: "off",
                docker: {
                  network: "host",
                },
              },
            },
          },
          tools: {
            exec: {
              host: "sandbox",
            },
          },
        }
        "#,
    )
    .expect("config should be written");

    let mut service = WatchService::new(
        app_config(),
        DiscoveryOptions {
            home_dir: Some(home_dir.to_path_buf()),
            ..DiscoveryOptions::default()
        },
        open_state_store(home_dir),
    );
    service
        .cold_boot_scan(1_763_900_000_000)
        .expect("cold boot should succeed");

    let mut backend = FakeWatchBackend::default()
        .with_event(WatchEvent::new(config_path.clone(), 1_763_900_003_000))
        .with_event(WatchEvent::new(config_path, 1_763_900_003_000));

    let outcomes = service
        .run_backend_batch(&mut backend)
        .expect("duplicate event batch should succeed");

    assert_eq!(outcomes.len(), 1);
    assert!(
        matches!(outcomes[0], WatchEventOutcome::Rescanned(_)),
        "duplicate events for the same target should be reduced to one rescan"
    );
}

#[test]
fn cold_boot_scan_records_snapshot_and_current_findings() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let home_dir = temp_dir.path();
    let state_dir = home_dir.join(".openclaw");
    fs::create_dir_all(&state_dir).expect("state dir should be created");
    fs::write(
        state_dir.join("openclaw.json"),
        r#"
        {
          agents: {
            defaults: {
              sandbox: {
                mode: "all",
                docker: {
                  network: "none",
                },
              },
            },
          },
          tools: {
            exec: {
              host: "sandbox",
            },
          },
        }
        "#,
    )
    .expect("safe config should be written");

    let mut service = WatchService::new(
        app_config(),
        DiscoveryOptions {
            home_dir: Some(home_dir.to_path_buf()),
            ..DiscoveryOptions::default()
        },
        open_state_store(home_dir),
    );

    let outcome = service
        .cold_boot_scan(1_763_900_000_000)
        .expect("cold boot scan should succeed");

    let stored_snapshot = service
        .state()
        .latest_scan_snapshot()
        .expect("snapshot lookup should succeed")
        .expect("snapshot should be recorded");
    assert_eq!(stored_snapshot, outcome.snapshot);
    assert_eq!(
        service
            .state()
            .list_current_findings()
            .expect("current findings should be readable"),
        outcome.snapshot.findings
    );
    assert!(
        outcome.watch_plan.targets.iter().any(|target| {
            target.logical_path == state_dir.join("openclaw.json")
                && target.watch_kind == WatchKind::File
        }),
        "cold boot should also materialize a watch plan from discovery"
    );
}

#[test]
fn event_rescan_records_drift_alerts_and_debounces_burst_events() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let home_dir = temp_dir.path();
    let state_dir = home_dir.join(".openclaw");
    fs::create_dir_all(&state_dir).expect("state dir should be created");
    let config_path = state_dir.join("openclaw.json");
    fs::write(
        &config_path,
        r#"
        {
          agents: {
            defaults: {
              sandbox: {
                mode: "all",
                docker: {
                  network: "none",
                },
              },
            },
          },
          tools: {
            exec: {
              host: "sandbox",
            },
          },
        }
        "#,
    )
    .expect("safe config should be written");

    let discovery = discover_from_builtin_presets(&DiscoveryOptions {
        home_dir: Some(home_dir.to_path_buf()),
        ..DiscoveryOptions::default()
    });
    let initial_evidence = collect_scan_evidence(&app_config(), &discovery);
    let config_artifact = initial_evidence
        .artifacts
        .iter()
        .find(|artifact| artifact.path == config_path.display().to_string())
        .expect("config artifact should be collected");

    let mut service = WatchService::new(
        app_config(),
        DiscoveryOptions {
            home_dir: Some(home_dir.to_path_buf()),
            ..DiscoveryOptions::default()
        },
        open_state_store(home_dir),
    );

    service
        .state_mut()
        .replace_baselines_for_source(
            "config",
            &[BaselineRecord {
                path: config_artifact.path.clone(),
                sha256: config_artifact.sha256.clone(),
                approved_at_unix_ms: 1_763_899_999_000,
                source_label: "config".to_string(),
            }],
        )
        .expect("baseline seeding should succeed");

    service
        .cold_boot_scan(1_763_900_000_000)
        .expect("initial scan should succeed");

    fs::write(
        &config_path,
        r#"
        {
          agents: {
            defaults: {
              sandbox: {
                mode: "off",
                docker: {
                  network: "host",
                },
              },
            },
          },
          tools: {
            exec: {
              host: "sandbox",
            },
          },
        }
        "#,
    )
    .expect("risky config should be written");

    let first = service
        .handle_event(WatchEvent::new(config_path.clone(), 1_763_900_003_000))
        .expect("rescan should succeed");
    let WatchEventOutcome::Rescanned(first_cycle) = first else {
        panic!("first event should trigger a rescan");
    };

    assert!(
        first_cycle
            .snapshot
            .findings
            .iter()
            .any(|finding| finding.detector_id == "openclaw-config"),
        "detector findings should be included in the new snapshot"
    );
    assert!(
        first_cycle
            .snapshot
            .findings
            .iter()
            .any(|finding| finding.detector_id == "baseline"),
        "baseline drift findings should be included in the new snapshot"
    );
    assert_eq!(
        service
            .state()
            .list_unresolved_alerts()
            .expect("alerts should be readable")
            .len(),
        1,
        "a new baseline drift should create one alert"
    );

    let debounced = service
        .handle_event(WatchEvent::new(config_path.clone(), 1_763_900_004_000))
        .expect("debounced event should not fail");
    assert_eq!(debounced, WatchEventOutcome::Debounced);
    assert_eq!(
        service
            .state()
            .latest_scan_snapshot()
            .expect("snapshot lookup should succeed")
            .expect("latest snapshot should exist")
            .recorded_at_unix_ms,
        1_763_900_003_000
    );

    let second = service
        .handle_event(WatchEvent::new(config_path, 1_763_900_006_500))
        .expect("second rescan should succeed");
    let WatchEventOutcome::Rescanned(second_cycle) = second else {
        panic!("event outside the debounce window should trigger a rescan");
    };
    assert_eq!(second_cycle.snapshot.recorded_at_unix_ms, 1_763_900_006_500);
    assert_eq!(
        service
            .state()
            .list_unresolved_alerts()
            .expect("alerts should still be readable")
            .len(),
        1,
        "the same unresolved drift should not create duplicate alerts"
    );
}

#[test]
fn missing_baseline_does_not_auto_approve_new_state() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let home_dir = temp_dir.path();
    let state_dir = home_dir.join(".openclaw");
    let config_path = state_dir.join("openclaw.json");
    fs::create_dir_all(&state_dir).expect("state dir should be created");
    fs::write(
        &config_path,
        r#"
        {
          agents: {
            defaults: {
              sandbox: {
                mode: "all",
                docker: {
                  network: "none",
                },
              },
            },
          },
          tools: {
            exec: {
              host: "sandbox",
            },
          },
        }
        "#,
    )
    .expect("safe config should be written");

    let mut service = WatchService::new(
        app_config(),
        DiscoveryOptions {
            home_dir: Some(home_dir.to_path_buf()),
            ..DiscoveryOptions::default()
        },
        open_state_store(home_dir),
    );

    let cold_boot = service
        .cold_boot_scan(1_763_900_000_000)
        .expect("cold boot should succeed without approved baselines");
    assert!(
        cold_boot
            .snapshot
            .findings
            .iter()
            .any(|finding| finding.detector_id == "baseline"),
        "without approved baselines, the runtime should remain untrusted rather than being silently approved"
    );
    assert!(
        service
            .state()
            .list_baselines()
            .expect("baseline lookup should succeed")
            .is_empty(),
        "cold boot should not auto-create approved baselines"
    );

    fs::write(
        &config_path,
        r#"
        {
          agents: {
            defaults: {
              sandbox: {
                mode: "off",
                docker: {
                  network: "host",
                },
              },
            },
          },
          tools: {
            exec: {
              host: "sandbox",
            },
          },
        }
        "#,
    )
    .expect("updated config should be written");

    let outcome = service
        .handle_event(WatchEvent::new(config_path, 1_763_900_003_000))
        .expect("event rescan should succeed");
    let WatchEventOutcome::Rescanned(cycle) = outcome else {
        panic!("event outside the debounce window should trigger a rescan");
    };

    assert!(
        cycle
            .snapshot
            .findings
            .iter()
            .any(|finding| finding.detector_id == "baseline"),
        "event rescans without baselines should continue to surface drift instead of auto-approving the new state"
    );
    assert!(
        service
            .state()
            .list_baselines()
            .expect("baseline lookup should succeed after rescan")
            .is_empty(),
        "event rescans should not auto-refresh approved baselines"
    );
}

#[test]
fn watch_rescans_do_not_refresh_restore_payloads_without_explicit_approval() {
    let temp_dir = tempdir().expect("temp dir should be created");
    let home_dir = temp_dir.path();
    let state_dir = home_dir.join(".openclaw");
    let config_path = state_dir.join("openclaw.json");
    fs::create_dir_all(&state_dir).expect("state dir should be created");
    fs::write(
        &config_path,
        r#"
        {
          agents: {
            defaults: {
              sandbox: {
                mode: "all",
                docker: {
                  network: "none",
                },
              },
            },
          },
          tools: {
            exec: {
              host: "sandbox",
            },
          },
        }
        "#,
    )
    .expect("initial config should be written");

    let mut service = WatchService::new(
        app_config(),
        DiscoveryOptions {
            home_dir: Some(home_dir.to_path_buf()),
            ..DiscoveryOptions::default()
        },
        open_state_store(home_dir),
    );

    let approved_payload = restore_payload_record(
        &config_path.display().to_string(),
        "approved",
        "config",
        "{ approved: true }",
    );
    service
        .state_mut()
        .replace_restore_payloads_for_source("config", std::slice::from_ref(&approved_payload))
        .expect("approved restore payload should persist");

    service
        .cold_boot_scan(1_763_900_000_000)
        .expect("cold boot should succeed");

    fs::write(
        &config_path,
        r#"
        {
          agents: {
            defaults: {
              sandbox: {
                mode: "off",
                docker: {
                  network: "host",
                },
              },
            },
          },
          tools: {
            exec: {
              host: "sandbox",
            },
          },
        }
        "#,
    )
    .expect("updated config should be written");

    let _ = service
        .handle_event(WatchEvent::new(config_path.clone(), 1_763_900_003_000))
        .expect("event rescan should succeed");

    assert_eq!(
        service
            .state()
            .restore_payload_for_path(&config_path.display().to_string())
            .expect("restore payload lookup should succeed"),
        Some(approved_payload),
        "watch rescans should not silently replace approved restore payloads"
    );
}

fn app_config() -> AppConfig {
    AppConfig {
        preset: "openclaw".to_string(),
        strictness: Strictness::Recommended,
        alert_strategy: AlertStrategy::Desktop,
        max_file_size_bytes: 1024 * 1024,
    }
}

fn open_state_store(home_dir: &std::path::Path) -> StateStore {
    let state_path = home_dir.join(".clawguard").join("state.db");
    StateStore::open(StateStoreConfig::for_path(state_path))
        .expect("state store should open")
        .store
}

fn restore_payload_record(
    path: &str,
    sha256: &str,
    source_label: &str,
    content: &str,
) -> RestorePayloadRecord {
    RestorePayloadRecord {
        path: path.to_string(),
        sha256: sha256.to_string(),
        captured_at_unix_ms: 1_763_900_000_000,
        source_label: source_label.to_string(),
        content: content.to_string(),
    }
}
