use clawguard::config::presets::{builtin_presets, preset_by_id};
use clawguard::config::schema::{AlertStrategy, ScanDomain, Strictness};

#[test]
fn builtin_presets_cover_supported_targets() {
    let presets = builtin_presets();
    let ids: Vec<_> = presets.iter().map(|preset| preset.id.as_str()).collect();

    assert_eq!(ids, vec!["openclaw"]);
}

#[test]
fn openclaw_preset_exposes_required_metadata() {
    let preset = preset_by_id("openclaw").expect("openclaw preset should exist");
    let domains: Vec<_> = preset
        .scan_targets
        .iter()
        .map(|target| target.domain)
        .collect();

    assert!(!preset.label.is_empty());
    assert!(!preset.detection_paths.is_empty());
    assert!(!preset.scan_targets.is_empty());
    assert!(!preset.critical_files.is_empty());
    assert!(preset.max_file_size_bytes > 0);
    assert!(domains.contains(&ScanDomain::Config));
    assert!(domains.contains(&ScanDomain::Skills));
    assert!(domains.contains(&ScanDomain::Mcp));
    assert!(domains.contains(&ScanDomain::Env));
}

#[test]
fn openclaw_preset_uses_verified_openclaw_paths() {
    let preset = preset_by_id("openclaw").expect("openclaw preset should exist");
    let detection_paths: Vec<_> = preset
        .detection_paths
        .iter()
        .map(|pattern| pattern.path.as_str())
        .collect();
    let critical_files: Vec<_> = preset
        .critical_files
        .iter()
        .map(|pattern| pattern.path.as_str())
        .collect();

    assert_eq!(detection_paths, vec!["~/.openclaw"]);

    assert!(critical_files.contains(&"~/.openclaw/openclaw.json"));
    assert!(critical_files.contains(&"~/.openclaw/.env"));
    assert!(critical_files.contains(&"~/.openclaw/exec-approvals.json"));
    assert!(critical_files.contains(&"~/.openclaw/credentials/"));
    assert!(critical_files.contains(&"~/.openclaw/agents/*/agent/auth-profiles.json"));

    assert!(!critical_files.contains(&"~/.openclaw/config.toml"));
    assert!(!critical_files.contains(&"~/.openclaw/mcp.json"));
}

#[test]
fn openclaw_mcp_target_reuses_main_config_instead_of_fake_directory() {
    let preset = preset_by_id("openclaw").expect("openclaw preset should exist");
    let mcp_target = preset
        .scan_targets
        .iter()
        .find(|target| target.domain == ScanDomain::Mcp)
        .expect("openclaw preset should include an MCP target");
    let paths: Vec<_> = mcp_target
        .paths
        .iter()
        .map(|pattern| pattern.path.as_str())
        .collect();

    assert_eq!(paths, vec!["~/.openclaw/openclaw.json"]);
    assert!(!paths.iter().any(|path| path.contains("/mcp")));
}

#[test]
fn preset_lookup_handles_known_and_unknown_ids() {
    assert!(preset_by_id("openclaw").is_some());
    assert!(preset_by_id("missing").is_none());
}

#[test]
fn schema_enums_cover_v0_choices() {
    let strict = Strictness::Recommended;
    let alert = AlertStrategy::Desktop;
    let domain = ScanDomain::Skills;

    assert!(matches!(strict, Strictness::Recommended));
    assert!(matches!(alert, AlertStrategy::Desktop));
    assert!(matches!(domain, ScanDomain::Skills));
}
