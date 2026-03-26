# Changelog

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
