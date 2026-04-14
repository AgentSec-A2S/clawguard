# ClawGuard

**Current version: v1.0.0-beta.2**

> [Why ClawGuard Exists](#why-clawguard-exists) | [Current Features](#current-features) | [What It Checks](#what-it-checks-today) | [How It Works](#how-it-works) | [Requirements](#requirements) | [Install](#install) | [Usage](#first-run-and-usage) | [Notifications](#notifications) | [Output Model](#output-model) | [Scope & Limits](#current-v0-scope-and-limits) | [Development](#development)

ClawGuard is a host-side integrity guardian for OpenClaw.

It exists to give you a fast, opinionated answer before you trust a local agent runtime:

`Does this machine's OpenClaw state still look safe enough to use?`

ClawGuard is intentionally not a new runtime, not a sandbox, and not a general-purpose EDR.
It stays focused on local integrity, risky configuration drift, dangerous extensions, and a
small set of high-signal checks that can make an otherwise normal OpenClaw setup unsafe.

## Why ClawGuard Exists

OpenClaw's most security-sensitive surfaces live on the host:

- `~/.openclaw/openclaw.json`
- `~/.openclaw/exec-approvals.json`
- `~/.openclaw/.env`
- `~/.openclaw/agents/*/agent/auth-profiles.json`
- `~/.openclaw/skills/`
- MCP launcher definitions embedded in OpenClaw config

Runtime isolation can reduce blast radius, but it does not tell you whether the local
configuration was already weakened, drifted, or tampered with.

ClawGuard exists to give you an action-oriented answer:

- before first use: is this install obviously risky?
- after changes: did something important drift?
- during triage: what evidence matters, how severe is it, and what should I do next?

## Current Features

- OpenClaw-first runtime discovery from the expected local state layout, including symlinked `~/.openclaw` homes
- First-run setup that immediately scans the detected runtime instead of stopping at wizard completion
- Action-first findings UI for terminal use
- Shared structured findings model for both human output and `--json`
- OpenClaw config audit for:
  - risky exec-approval posture
  - sandbox-off plus host-fallback behavior
  - dangerous sandbox network modes
  - exposed `gateway.bind` settings
  - `channels.*.dmPolicy="open"` inbound exposure
  - risky hook/plugin settings such as missing webhook tokens and `allowPromptInjection=true`
  - weak local permissions on sensitive OpenClaw files
- Skill scanning for dangerous shell, network, and install behaviors
- MCP scanning for suspicious launchers, unpinned package references, and overly broad directories
- Secrets and env scanning for literal secrets and private-key material
- Advisory/version matching when readable version evidence exists, including a bounded fallback to common source-layout manifests such as `packages/core/package.json`
- Skill TOFU (trust-on-first-use) provenance tracking:
  - git remote URL and HEAD SHA extraction from `.git/config` and `.git/HEAD` (no subprocess, handles worktrees and submodules via `gitdir:` indirection)
  - boundary-guarded `.git` resolution prevents escape from scan root
  - 3 provenance findings: `skill-no-provenance` (Info), `skill-unapproved-change` (Medium), `skill-remote-redirect` (High)
  - provenance checks run in both `clawguard scan` and `clawguard watch` pipelines
  - `baseline approve` captures git provenance alongside file hashes for future drift comparison
- Explicit baseline approval for the current runtime state
- Foreground watch loop that records cold-boot snapshots and drift-triggered rescans into ClawGuard state
- Watch-driven notification routing for persisted alerts:
  - desktop notifications when the local environment supports them
  - webhook delivery through a persisted webhook URL
  - log-only fallback in headless or unsupported environments
- Once-per-day digest delivery from stored alert history during `watch`
- Persisted operator surfaces for:
  - `clawguard` / `clawguard status` human status view
  - `clawguard alerts` history plus `clawguard alerts ignore <alert-id>`
  - `clawguard trust openclaw-config` and `clawguard trust exec-approvals`
- Embedded SSE server for real-time alert streaming to external consumers:
  - `--sse-port` or `[sse]` config section enables the server on a dedicated thread
  - Config hot-reload: change `port` or `bind` in `config.toml` while watching, server restarts automatically
  - Endpoints: `/stream` (SSE events), `/health`, `/status`, `/alerts`
  - Localhost-only binding, max 16 clients, 30s heartbeats
- OpenClaw gateway plugin (`openclaw-plugin/`) for Telegram/Discord/Slack alerts:
  - Connects to ClawGuard SSE stream with automatic reconnection
  - Forwards alert and daily digest events to any configured OpenClaw channel
  - Slash commands: `/clawguard_help`, `/clawguard_feed`, `/clawguard_status`, `/clawguard_alerts`
- Conservative scope: no broad auto-remediation, no background trust UI, no hidden mutation of OpenClaw state

## What It Checks Today

ClawGuard keeps the detector catalog intentionally small and high-signal.

- `OpenClaw config audit`
  - looks for dangerous local runtime posture in `openclaw.json`, `exec-approvals.json`, and auth-profile state
  - tripwire detection: flags allowlist entries pre-approving catastrophic commands (`rm -rf /`, pipe-to-shell, reverse shells, `mkfs`, `dd` to block devices)
  - handles full-path executables (`/bin/rm`, `/usr/bin/env bash`) and expands shell sink detection to `sh`, `bash`, `zsh`, `dash`, `ksh`, `fish`
  - token-aware, quote-aware command matching prevents false positives on quoted strings
  - approval drift: detects policy weakening (`askFallback` relaxed, dangerous executables or interpreters in allowlist)
  - V1 is alert-only with no real-time command blocking — OpenClaw's exec-approval system is a closed trust boundary with no stable external interception API
- `Skills scan`
  - looks for shell, network, and local-install behaviors that deserve human review
- `MCP scan`
  - looks for suspicious auto-install launchers, unpinned packages, and wide filesystem reach
- `Secrets and env scan`
  - looks for hardcoded secrets, token-like literals, and PEM / SSH private-key material
- `Device auth and plugin path audit`
  - flags `dangerouslyDisableDeviceAuth=true` (Critical)
  - flags plugins installed from insecure paths like `/tmp` (Medium)
  - flags local filesystem path plugin installs for awareness (Info)
- `Hook and webhook security`
  - flags `hooks.allowRequestSessionKey=true` — external session hijacking risk (High)
  - flags `hooks.mappings[].allowUnsafeExternalContent=true` — webhook prompt injection (High)
  - flags `hooks.gmail.allowUnsafeExternalContent=true` — email prompt injection (High)
  - flags `hooks.mappings[].transform.module` pointing outside workspace boundary (Medium)
- `Exec and sandbox posture`
  - flags `tools.exec.host=node` — unsandboxed host execution, global and per-agent (Medium)
  - flags `agents.defaults.sandbox.mode=off` or per-agent sandbox disabled (Medium)
  - flags `channels.*.accounts.*.dmPolicy=open` at nested account level (Medium)
- `ACP plugin posture`
  - flags `plugins.entries.acpx.config.permissionMode=approve-all` — auto-approves all tool calls including exec, spawn, shell, and filesystem writes (High)
  - skips disabled plugins to avoid false positives on stale config remnants
- `Gateway node command policy`
  - flags dangerous commands in `gateway.nodes.allowCommands` — enables sensitive device access via paired nodes (High)
  - dangerous set: `camera.snap`, `camera.clip`, `screen.record`, `contacts.add`, `calendar.add`, `reminders.add`, `sms.send`, `sms.search`
  - respects `gateway.nodes.denyCommands` — explicitly denied commands are not flagged
- `Tool profile escalation`
  - flags per-agent `tools.profile` overriding global `minimal` profile — grants access to additional tools beyond intended baseline (Medium)
- `Sandbox bind-mount security`
  - flags symlink bind-mount sources — TOCTOU risk where the target can be swapped after validation (Medium)
  - flags temp directory bind-mount sources (`/tmp`, `/var/tmp`) — any local user can write to them (Medium)
  - flags `dangerouslyAllowReservedContainerTargets=true` — allows bind into /workspace or /agent (High)
  - flags `dangerouslyAllowExternalBindSources=true` — allows bind from outside allowlisted roots (High)
  - checks both `docker.binds` and `browser.binds` in defaults and per-agent configs
  - resolves per-agent effective sandbox scope (including `perSession` flag) to avoid false positives
- `Plugin allowlist/denylist config drift`
  - flags plugin entries not in `plugins.allow` when an allowlist is configured — config policy conflict (Medium)
  - flags plugin entries that are also in `plugins.deny` — contradictory config (Medium)
  - skips disabled plugins (`enabled: false`) and the entire check when plugin system is disabled
  - framed as config drift detection, not active plugin exposure — runtime precedence determines actual state
- `OWASP ASI Top 10 mapping`
  - findings carry an optional `owasp_asi` field mapping to the OWASP Agentic Security Initiative Top 10 categories (ASI02–ASI10)
  - rendered in `--json` output for compliance and reporting workflows
- `Hook handler scanning`
  - scans managed hooks (`~/.openclaw/hooks/`) and `hooks.internal.load.extraDirs` directories
  - follows upstream handler load order: `handler.ts` → `handler.js` → `index.ts` → `index.js`
  - hashes `HOOK.md` metadata for baseline drift detection
  - detects shell execution: `child_process`, `exec(`, `spawn(`, `execFile(`, `import("child_process")`, `process.binding()` (High)
  - detects network exfiltration: `fetch(`, `http.request`, `WebSocket`, `net.connect`, `dns.resolve`, `XMLHttpRequest`, `EventSource` (High)
  - detects identity file mutation: writes to SOUL.md, MEMORY.md, AGENTS.md, TOOLS.md, USER.md (Medium)
  - detects config mutation: writes to openclaw.json, exec-approvals.json (High)
  - proper block comment tracking (multi-line `/* ... */`) to prevent detection bypass
- `Bootstrap file integrity`
  - scans 9 workspace bootstrap files across all agent workspaces (`~/.openclaw/agents/*/agent/`)
  - files: AGENTS.md, SOUL.md, TOOLS.md, IDENTITY.md, USER.md, HEARTBEAT.md, BOOTSTRAP.md, MEMORY.md, memory.md
  - detects encoded payloads: base64 strings ≥100 chars, supports standard and URL-safe encoding (High)
  - detects shell injection: `$(...)` command substitution, `${}` variable expansion with shell context, backtick substitution (High)
  - detects prompt injection markers: "ignore previous instructions", "system override", "forget everything", etc. (Critical)
  - detects obfuscated content: ≥10 hex (`\x`) or unicode (`\u`) escape sequences per line (Medium)
  - workspace discovery cannot be suppressed by decoy files in the parent directory
- `Skill TOFU provenance`
  - trust-on-first-use model: first `baseline approve` captures skill file hashes + git remote URL + HEAD SHA as the trusted state
  - skills with no baseline at all: `skill-no-provenance` (Info, ASI06) — awareness only, no action needed until user approves
  - skill hash changed without `baseline approve`: `skill-unapproved-change` (Medium, ASI06) — possible unauthorized modification
  - skill git remote URL differs from approved baseline: `skill-remote-redirect` (High, ASI06) — supply chain redirect, skill source changed to a different repository
  - provenance checks run automatically in both `clawguard scan` and `clawguard watch` pipelines
  - git metadata extracted without spawning subprocesses (parses `.git/config` and `.git/HEAD` directly)
  - handles git worktrees and submodules via `.git` file `gitdir:` indirection, with scan boundary enforcement
- `Advisory matching`
  - matches local OpenClaw version evidence against the bundled advisory feed when version evidence is available
- `Baseline approval`
  - turns the current observed file-hash evidence into the approved baseline set used for drift detection
- `Audit log`
  - passive ingestion of OpenClaw's `config-audit.jsonl` (config write events with real ISO-8601 timestamps)
  - skill directory change detection using file-level SHA-256 hashes (catches in-place edits)
  - plugin catalog change detection (install/remove events)
  - bootstrap file change tracking across agent workspaces (SHA-256 snapshot diffing for SOUL.md, MEMORY.md, AGENTS.md, etc.)
  - log rotation safe: detects file shrink and resets cursor automatically
  - `clawguard audit [--category X] [--since 1h] [--limit N] [--json]`
- `Security statistics`
  - aggregates scan history, finding trends, alert resolution rates, baseline counts, and audit event breakdowns
  - supports `--since` timeframe filter (1h, 7d, 30d) and `--json` machine-readable output
  - `clawguard stats [--since 7d] [--json]`
- `Watch loop`
  - watches protected files and skill roots, re-scans on change, records snapshots, appends drift alerts, and delivers notifications from persisted alert state
  - runs passive audit ingestion after each scan cycle for continuous event capture

## How It Works

At a high level, ClawGuard follows one pipeline:

```text
preset
  -> discovery
  -> evidence collection
  -> source-context annotation
  -> detectors
  -> finding aggregation
  -> renderers
```

In practical terms:

1. `Discovery`
   ClawGuard finds a supported runtime from the expected local layout and known OpenClaw paths.
2. `Setup`
   On first run, it writes ClawGuard's own config and keeps the setup choices narrow.
3. `Evidence collection`
   It reads local OpenClaw state such as config files, exec approvals, auth profiles, skills, and `.env`.
4. `Detectors`
   It runs a small set of focused detectors instead of a large generic rule soup.
5. `Finding aggregation`
   It normalizes results into a shared finding model with severity, confidence, evidence, and recommended action.
6. `Rendering`
   It renders that same structured result either as terminal findings output or machine-readable JSON.

## What ClawGuard Is Not

- Not a replacement runtime for OpenClaw
- Not a sandbox or network policy engine
- Not a broad host monitoring suite
- Not a deep multi-agent analysis product
- Not an auto-remediation system in V0

## Requirements

| Requirement | Details |
|-------------|---------|
| **OS** | macOS (Intel / Apple Silicon), Linux (x86_64 / ARM64) |
| **OpenClaw** | v2026.2.2 or later recommended. Verified against v2026.3.x |
| **Runtime** | No external runtime dependencies — single static binary |
| **Build from source** | Rust 1.75+ and Cargo |

ClawGuard detects and scans OpenClaw installations automatically. Other agent runtimes (Claude Code, Codex) are supported via presets but OpenClaw is the primary target.

## Install

### Quick install (pre-built binary)

```bash
curl -fsSL https://raw.githubusercontent.com/AgentSec-A2S/clawguard/main/install.sh | sh
```

Or download a specific release from the [GitHub Releases](https://github.com/AgentSec-A2S/clawguard/releases) page.

### Build from source

```bash
cargo install --path .
```

For local development:

```bash
cargo build --release
./target/release/clawguard --help
```

## First Run And Usage

- `clawguard`
  - on first run, detects OpenClaw, launches the setup wizard, runs an immediate scan, and renders findings
  - after configuration, human output opens the persisted status view instead of immediately re-running the scan
  - `clawguard --json` intentionally remains scan-compatible for automation
- `clawguard scan`
  - runs the scan flow directly
- `clawguard status`
  - renders the persisted-state status view explicitly
  - `clawguard status --json` emits the status JSON contract instead of scan findings JSON
- `clawguard alerts`
  - shows recent persisted alerts, newest first
- `clawguard alerts ignore <alert-id>`
  - marks one alert as acknowledged without deleting its history
- `clawguard baseline approve`
  - explicitly records the current OpenClaw file-hash evidence as the approved baseline set for drift detection
- `clawguard trust openclaw-config`
  - restores the last approved `openclaw.json` payload captured during `baseline approve`
- `clawguard trust exec-approvals`
  - restores the last approved `exec-approvals.json` payload captured during `baseline approve`
- `clawguard notify`
  - shows current notification configuration (strategy, webhook, Telegram, SSE)
  - `clawguard notify --json` emits the notification config as JSON
- `clawguard notify desktop`
  - switches to desktop notifications
- `clawguard notify webhook <url>`
  - switches to webhook notifications with URL validation
- `clawguard notify telegram [chat-id]`
  - enables SSE server and configures Telegram alerts via OpenClaw plugin
  - if chat-id is omitted, auto-detects from OpenClaw's `channels.telegram` config (`defaultTo`, `groups`, `direct`, `allowFrom`)
  - if multiple IDs are detected, prints a numbered list for the user to choose from
  - if exactly one ID is found, auto-selects it
  - falls back to previously saved value if no OpenClaw config exists
  - prints a ready-to-paste `openclaw.json` plugin config snippet
  - `--apply` writes the plugin config into `openclaw.json` automatically (creates backup first)
- `clawguard notify off`
  - disables all notifications (log-only) and stops the SSE server
- `clawguard watch`
  - starts a foreground watcher loop that continuously monitors the detected OpenClaw runtime
  - **cold boot**: runs a full scan on startup — discovery, all detectors, baseline drift comparison, snapshot + findings persisted to SQLite
  - **event loop**: uses OS filesystem notifications (`notify` crate on macOS/Linux) to detect changes to watched files; re-scans on change with 2-second debounce
  - **each scan cycle**: re-discovers runtime → runs all detectors → diffs against approved baselines → persists snapshot → creates alerts for new drift findings (dedup against existing open alerts) → ingests audit events from OpenClaw logs
  - **notifications**: delivers pending alerts via the configured route (desktop/webhook/telegram) and evaluates daily digest delivery after each iteration
  - **SSE broadcasting**: with `--sse-port`, starts an SSE server that pushes real-time alert events to connected clients (e.g., the OpenClaw gateway plugin)
  - `--iterations N` stops after N iterations (0 = run forever, default)
  - `--poll-interval-ms N` sets the sleep between iterations (default 1000ms)
  - `--sse-port N` enables the SSE server on the specified port (0 = disabled, default)
  - `--iterations 1` is useful for smoke-testing the cold-boot path without leaving a long-running process behind
- `clawguard audit`
  - shows recent audit events (config changes, skill/plugin installs, removals)
  - `--category config|hook|plugin|tool|skill` filters by event category
  - `--since 1h|24h|7d` filters by time range
  - `--limit N` limits output (default 50)
  - `--json` emits machine-readable JSONL output
- `clawguard stats`
  - shows aggregate scan and security statistics over time
  - `--since 1h|7d|30d` filters statistics to a time window
  - `--json` emits machine-readable JSON with trend data
- `clawguard --json` or `clawguard scan --json`
  - emits machine-readable findings JSON derived from the shared scan result model
- `clawguard --no-interactive` or `clawguard scan --no-interactive`
  - accepts default first-run setup values instead of prompting
- if no supported runtime is detected
  - human output and `--json` both emit the same structured Info finding instead of a placeholder success message

Common examples:

```bash
clawguard
clawguard status
clawguard alerts
clawguard alerts ignore alert-openclaw-config
clawguard scan
clawguard baseline approve
clawguard trust openclaw-config
clawguard notify
clawguard notify telegram                          # auto-detect chat ID
clawguard notify telegram 123456789                # explicit chat ID
clawguard notify telegram 123456789 --apply        # auto-write to openclaw.json
clawguard notify webhook https://hooks.example.com/clawguard
clawguard notify off
clawguard watch --iterations 1
clawguard scan --json
clawguard status --json
clawguard scan --no-interactive --json
```

## Notifications

ClawGuard has two independent notification paths that can run simultaneously. Both are triggered during `clawguard watch` — manual `scan` does not send notifications.

```
watch loop iteration
  ├── Built-in notifications (alert_strategy in config.toml)
  │   ├── Desktop → macOS osascript / Linux notify-send
  │   ├── Webhook → HTTP POST to configured URL
  │   └── LogOnly → terminal output only
  │
  └── SSE stream (optional, [sse] in config.toml)
      └── Real-time events → OpenClaw plugin → Telegram / Discord / Slack
```

### Built-in notifications

The first-run wizard saves the selected notification route into `~/.clawguard/config.toml`.
Edit it directly to change later:

```toml
alert_strategy = "Desktop"
webhook_url = "https://hooks.example.com/clawguard"
```

- `Desktop` — desktop notifications when the local session supports them, falls back to log-only
- `Webhook` — requires `webhook_url` starting with `http://` or `https://`
- `LogOnly` — all notification output stays in the foreground `watch` terminal

Daily digest cadence starts on the first `watch` evaluation. ClawGuard seeds the cursor then — the first digest only includes alerts created after that point.

### SSE server (real-time streaming)

An embedded SSE server streams alert and digest events to external consumers on a dedicated thread.

Enable in `~/.clawguard/config.toml`:

```toml
[sse]
port = 37776
bind = "127.0.0.1"   # use "0.0.0.0" for Docker or remote access
```

In Docker containers, ClawGuard auto-detects `/.dockerenv` and suggests `host.docker.internal` for plugin connectivity.

Or via CLI: `clawguard watch --sse-port 37776`

Config hot-reload: changing `port` or `bind` while watching automatically restarts the server.

| Endpoint | Description |
|----------|-------------|
| `GET /stream` | SSE event stream (`event: alert`, `event: digest`, `event: heartbeat`) |
| `GET /health` | Health check: `{"ok":true}` |
| `GET /status` | Current state: client count, mode |
| `GET /alerts?limit=10` | Recent alerts as JSON |

Test with curl:

```bash
clawguard watch --sse-port 37776    # terminal 1
curl -N http://127.0.0.1:37776/stream  # terminal 2
```

### Messaging via OpenClaw gateway plugin

The `openclaw-plugin/` directory contains a plugin that consumes the SSE stream and forwards alerts to Telegram, Discord, Slack, or any other OpenClaw channel.

Add to your `openclaw.json`:

```json5
{
  plugins: {
    entries: {
      clawguard: {
        enabled: true,
        config: {
          port: 37776,
          channel: "telegram",
          to: "123456789"
        }
      }
    }
  }
}
```

Slash commands available in your messaging channel:

| Command | Description | Status |
|---------|-------------|--------|
| `/clawguard_help` | Show all commands and usage guide | V1 |
| `/clawguard_feed` | Toggle alert feed on/off | V1 |
| `/clawguard_status` | Show current security status | V1 |
| `/clawguard_alerts` | Show 10 most recent alerts | V1 |
| `/clawguard_ignore <id>` | Acknowledge an alert from chat | V1.5 |
| `/clawguard_trust <target>` | Restore approved config from chat | V1.5 |
| `/clawguard_scan` | Trigger an immediate rescan | V1.5 |
| `/clawguard_config <key> <value>` | Update ClawGuard config remotely | V1.5 |

V1 commands are read-only. V1.5 will add mutation commands backed by an authenticated local API (`POST /command` with Unix socket + token).

Alert messages look like:

```
🛡️ ClawGuard Alert [HIGH]
📁 ~/.openclaw/exec-approvals.json
⚠️ Allowlist entry permits curl — dangerous executable
💡 Remove this allowlist entry or restrict it
```

## Output Model

ClawGuard is findings-first.

Each finding is designed to carry:

- severity
- detector/category
- runtime confidence
- evidence path and optional line context
- plain-English explanation
- recommended action

The terminal UI and `--json` output are both generated from the same underlying structured result.

## Current V0 Scope And Limits

- V0.5 is OpenClaw-first; it is not a multi-runtime product yet
- V0.5 now includes baseline approval, a foreground watcher loop, watch-scoped notification delivery, and persisted status/alerts/trust commands
- manual `scan` remains findings-first and side-effect free; notifications belong to `watch`
- `trust` is intentionally narrow and allowlisted; it only restores payloads previously captured during `baseline approve`
- it is still not a background service manager, retry queue, broad trust UI, or broad remediation system
- ClawGuard does not silently change OpenClaw state
- The bundled advisory feed is intentionally empty until curated production advisories are shipped
- Advisory matching only runs when ClawGuard can read OpenClaw version evidence
  - today that means a colocated `package.json` or a bounded fallback such as `packages/core/package.json`
- `dmPolicy=open` severity is currently derived from global exec-host posture only
  - ClawGuard does not yet correlate per-agent exec-host overrides back to channel-level DM exposure
- V0 exit codes
  - scan commands currently exit `0` even when findings are present
  - automation should inspect `--json` output rather than rely on exit status alone

## Development

```bash
cargo test
cargo build --release
```
