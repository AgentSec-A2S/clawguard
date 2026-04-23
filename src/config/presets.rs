use super::schema::{AlertStrategy, PathPattern, Preset, ScanDomain, ScanTarget, Strictness};

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
        detection_paths: paths(["~/.openclaw"]),
        scan_targets: vec![
            scan_target(
                ScanDomain::Config,
                [
                    "~/.openclaw/openclaw.json",
                    "~/.openclaw/exec-approvals.json",
                    "~/.openclaw/agents/*/agent/auth-profiles.json",
                ],
            ),
            scan_target(ScanDomain::Skills, ["~/.openclaw/skills"]),
            // OpenClaw MCP configuration currently lives inside the main JSON5 config,
            // plus any plugin-bundled `.mcp.json` at ~/.openclaw/extensions/<id>/.mcp.json
            // (a 4th MCP mount point OpenClaw reads via resolveBundleMcpConfigPaths —
            // see repos/openclaw/src/plugins/bundle-mcp.ts). Without this, plugin-bundled
            // servers are invisible to typosquat, lockfile, and command-drift detectors.
            scan_target(
                ScanDomain::Mcp,
                [
                    "~/.openclaw/openclaw.json",
                    "~/.openclaw/extensions/*/.mcp.json",
                ],
            ),
            scan_target(ScanDomain::Env, ["~/.openclaw/.env"]),
            scan_target(ScanDomain::Hooks, ["~/.openclaw/hooks"]),
            scan_target(ScanDomain::Bootstrap, ["~/.openclaw/agents"]),
        ],
        critical_files: paths([
            "~/.openclaw/openclaw.json",
            "~/.openclaw/.env",
            "~/.openclaw/exec-approvals.json",
            "~/.openclaw/credentials/",
            "~/.openclaw/agents/*/agent/auth-profiles.json",
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
