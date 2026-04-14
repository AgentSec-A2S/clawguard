# Changelog

## [1.2.0-beta.1] - 2026-04-14

### V1.1 — Config Audit Detectors (3 sprints)

- 7 new config audit detectors: `hook-allows-request-session-key`, `hook-allows-unsafe-external-content`, `hook-transform-external-module`, `exec-host-node`, `sandbox-disabled`, nested `open-dm-policy`
- 2 new detectors: `acp-approve-all` (ACPX auto-approve), per-agent `exec-host-node`
- 2 new detectors: `gateway-node-dangerous-command`, `tool-profile-escalation`
- OWASP ASI Top 10 mapping on every finding (`owasp_asi` field, ASI02–ASI10)

### V1.2 — Hook Integrity + Supply Chain Trust (5 sprints)

**Sprint 1: Sandbox bind-mount + plugin config drift**
- `sandbox-bind-symlink`, `sandbox-bind-temp-dir`: TOCTOU + temp dir risks
- `sandbox-dangerous-reserved-targets`, `sandbox-dangerous-external-sources`: dangerous docker booleans
- `plugin-not-in-allowlist`, `plugin-in-denylist`: config drift detection
- Per-agent effective sandbox scope resolution

**Sprint 2: Audit log infrastructure**
- Passive ingestion of `config-audit.jsonl` (ISO-8601 timestamps, log rotation safe)
- Skill SHA-256 hash tracking, plugin catalog change detection
- `clawguard audit [--category X] [--since 1h] [--limit N] [--json]`
- Wired into watch cycle for continuous event capture

**Sprint 3: Hook scanning + bootstrap file integrity**
- Hook handler scanning: shell-exec, network-exfil, identity/config mutation detection
- Bootstrap file integrity: encoded payloads, shell injection, prompt injection, obfuscation
- 9 bootstrap files across `~/.openclaw/agents/*/agent/`
- Block comment tracking prevents detection bypass

**Sprint 4: Stats command + bootstrap audit tracking**
- `clawguard stats [--since 7d] [--json]`: scan history, finding trends, alert resolution rates
- Bootstrap file change tracking via SHA-256 snapshot diffing with symlink protection

**Sprint 5: Skill TOFU provenance + posture scoring**
- Skill TOFU (trust-on-first-use) provenance: git remote URL + HEAD SHA tracking
- 3 provenance findings: `skill-no-provenance` (Info), `skill-unapproved-change` (Medium), `skill-remote-redirect` (High)
- Git metadata extraction without subprocess, worktree/submodule support with boundary guard
- `clawguard posture [--json]`: weighted permission surface score (33 finding-specific weights)
- 5 score bands: Clean, Low, Moderate, Elevated, Critical
- Read-only design: computes trend from latest persisted snapshot without writing authoritative state
- 3 cargo-fuzz targets for git parsers

**OpenClaw upstream sync (7,212 commits analyzed)**
- `exec-approvals-missing`: detect absent exec-approvals.json (upstream defaults changed to fail-open)
- `groupPolicy: "open"` detection alongside `dmPolicy`
- `busybox`/`toybox` added as suspicious MCP launchers
- `OPENCLAW_AGENT_DIR` env var support for bootstrap scanning
- Config-driven extra scan dirs from `skills.load.extraDirs` and `hooks.internal.load.extraDirs`

### Test Suite

- 298+ tests across all suites (114 openclaw_audit, 19 audit, 8 posture, 7 provenance, 5 stats)
- 3 cargo-fuzz targets (git config, git HEAD, ISO timestamp parsers)

## [1.0.0-beta.2] - 2026-03-31

### Beta 2

- `clawguard notify telegram` auto-detects chat IDs from OpenClaw `channels.telegram` config
- `--apply` flag writes plugin config into openclaw.json automatically (with backup)
- 3 new detectors: `dangerous-disable-device-auth` (Critical), `insecure-plugin-install-path` (Medium), `plugin-source-path-install` (Info)
- Zero-findings UX shows scan summary (runtime, file counts, strictness)
- SSE CORS wildcard removed for security
- Alert dedup restored to `list_unresolved_alerts` so `alerts ignore` is durable
- `is_temp_path` false positive fix
- Docker SSE bind auto-detection and plugin API alignment
- 8 new regression tests

## [1.0.0-beta.1] - 2026-03-26

### Beta Pre-release

First public beta for release workflow validation and early testing.
All V1 features included — see 1.0.0 section below for full feature list.

**New since last push:**
- `clawguard notify` command family (desktop, webhook, telegram, off)
- OpenClaw advisory feed with known CVEs
- Input validation hardening (chat ID, webhook URL)

## [1.0.0] - 2026-03-26

### V1 GA Release

ClawGuard V1 ships as a single Rust binary for OpenClaw runtime security scanning, baseline-driven drift detection, foreground watching with notifications, and operator trust/alerts flows.

### Features

- **Discovery & Setup** — Auto-detect OpenClaw runtime, first-run wizard, preset-driven config
- **OpenClaw Config Audit** — Dangerous exec-approval posture, sandbox fallback, gateway bind exposure, DM policy, webhook token, plugin hook injection
- **Tripwire Detection** — Allowlist entries pre-approving catastrophic commands (rm -rf /, pipe-to-shell, reverse shells, mkfs, dd). Full-path executable recognition, expanded shell sink detection, token-aware + quote-aware matching
- **Approval Drift** — askFallback weakening, dangerous executables/interpreters in allowlist
- **Skills Scan** — Shell, network, and local-install behaviors in skill directories
- **MCP Scan** — Suspicious auto-install launchers, unpinned packages, wide filesystem reach
- **Secrets & Env Scan** — Hardcoded secrets, token-like literals, PEM/SSH private key material
- **Advisory Matching** — Local OpenClaw version evidence matched against bundled advisory feed
- **SQLite Persistence** — Scan snapshots, current findings, baselines, alert state, notification receipts (WAL mode, corrupt-db auto-recovery)
- **Baseline Approval** — Record current file-hash evidence as approved baseline for drift detection
- **Watch Loop** — Foreground watcher with notify/polling backends, debounce, cold boot scan, drift alert creation
- **Notification Delivery** — Desktop notifications (macOS osascript, Linux notify-send), webhook delivery, log-only fallback, daily digest with cursor semantics
- **Status View** — `clawguard` / `clawguard status` shows persisted state: open alerts, snapshot summary, baseline posture, trust targets
- **Alerts** — `clawguard alerts` history view, `clawguard alerts ignore <id>` acknowledgement flow
- **Trust** — `clawguard trust openclaw-config` / `exec-approvals` restores approved payload and resolves matching drift alerts
- **JSON Contracts** — `--json` on all commands for automation integration

### Design Principles

- Alert-by-default, no real-time command blocking in V1
- Fail-open: ClawGuard never blocks OpenClaw operation
- Findings are structured first, rendered second (JSON + terminal from same model)
- Conservative scope: no broad auto-remediation, no hidden mutation of OpenClaw state
