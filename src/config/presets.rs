use super::schema::{
    AlertStrategy, PathPattern, Preset, ScanDomain, ScanTarget, Strictness,
};

const DEFAULT_MAX_FILE_SIZE_BYTES: u64 = 1024 * 1024;

pub fn builtin_presets() -> Vec<Preset> {
    vec![openclaw_preset()]
}

pub fn preset_by_id(id: &str) -> Option<Preset> {
    builtin_presets().into_iter().find(|preset| preset.id == id)
}

fn openclaw_preset() -> Preset {
    Preset {
        id: "openclaw".to_string(),
        label: "OpenClaw".to_string(),
        detection_paths: paths(["~/.openclaw", "~/.config/openclaw"]),
        scan_targets: vec![
            scan_target(ScanDomain::Config, ["~/.openclaw", "~/.config/openclaw"]),
            scan_target(
                ScanDomain::Skills,
                ["~/.openclaw/skills", "~/.config/openclaw/skills"],
            ),
            scan_target(
                ScanDomain::Mcp,
                ["~/.openclaw/mcp", "~/.config/openclaw/mcp"],
            ),
            scan_target(
                ScanDomain::Env,
                ["~/.openclaw/.env", "~/.config/openclaw/.env"],
            ),
        ],
        critical_files: paths([
            "~/.openclaw/config.toml",
            "~/.openclaw/.env",
            "~/.openclaw/mcp.json",
            "~/.config/openclaw/config.toml",
        ]),
        excluded_dirs: vec![
            ".git".to_string(),
            "node_modules".to_string(),
            "dist".to_string(),
            "build".to_string(),
            ".venv".to_string(),
            "venv".to_string(),
        ],
        max_file_size_bytes: DEFAULT_MAX_FILE_SIZE_BYTES,
        default_strictness: Strictness::Recommended,
        default_alert_strategy: AlertStrategy::Desktop,
    }
}

fn paths<const N: usize>(values: [&str; N]) -> Vec<PathPattern> {
    values.into_iter().map(path).collect()
}

fn scan_target<const N: usize>(domain: ScanDomain, values: [&str; N]) -> ScanTarget {
    ScanTarget {
        domain,
        paths: paths(values),
    }
}

fn path(value: &str) -> PathPattern {
    PathPattern {
        path: value.to_string(),
    }
}
