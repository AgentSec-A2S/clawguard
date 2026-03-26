# ClawGuard

> [Why ClawGuard Exists](#why-clawguard-exists) | [Current Features](#current-features) | [What It Checks](#what-it-checks-today) | [How It Works](#how-it-works) | [Install](#install) | [Usage](#first-run-and-usage) | [Notifications](#notification-configuration) | [SSE & Messaging](#sse-server--messaging-integration) | [Output Model](#output-model) | [Scope & Limits](#current-v0-scope-and-limits) | [Development](#development)

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
  - Slash commands: `/clawguard_feed`, `/clawguard_status`, `/clawguard_alerts`
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
- `Advisory matching`
  - matches local OpenClaw version evidence against the bundled advisory feed when version evidence is available
- `Baseline approval`
  - turns the current observed file-hash evidence into the approved baseline set used for drift detection
- `Watch loop`
  - watches protected files and skill roots, re-scans on change, records snapshots, appends drift alerts, and delivers notifications from persisted alert state

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
- `clawguard watch`
  - starts the foreground watcher loop for the saved config
  - delivers immediate notifications for newly persisted alerts and evaluates the daily digest during the watch loop
  - `--iterations 1` is useful for smoke-testing the cold-boot path without leaving a long-running process behind
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
clawguard watch --iterations 1
clawguard scan --json
clawguard status --json
clawguard scan --no-interactive --json
```

## Notification Configuration

The first-run wizard saves the selected notification route into `~/.clawguard/config.toml`.
If you want to change it later without rerunning the wizard, edit that file directly:

```toml
alert_strategy = "Desktop"
webhook_url = "https://hooks.example.com/clawguard"
```

- `alert_strategy = "Desktop"` uses desktop notifications when the local session supports them and falls back to log-only output when it does not
- `alert_strategy = "Webhook"` requires `webhook_url` and the URL must start with `http://` or `https://`
- `alert_strategy = "LogOnly"` keeps all notification delivery inside the foreground `watch` output

Daily digest cadence starts when `clawguard watch` first evaluates digest delivery for the saved route.
ClawGuard seeds the digest cursor on that first evaluation instead of backfilling older alerts, so the first delivered digest only includes alerts created after digest cadence starts.

## SSE Server & Messaging Integration

ClawGuard can stream alerts in real-time to external consumers via an embedded SSE (Server-Sent Events) server.

### Enable the SSE server

Add to `~/.clawguard/config.toml`:

```toml
[sse]
port = 37776
bind = "127.0.0.1"
```

Or use the CLI flag: `clawguard watch --sse-port 37776`

The server runs on a dedicated thread and never blocks the watch loop. Changing `port` or `bind` in the config file while watching triggers an automatic server restart.

### SSE endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /stream` | SSE event stream (`event: alert`, `event: digest`, `event: heartbeat`) |
| `GET /health` | Health check: `{"ok":true}` |
| `GET /status` | Current state: client count, mode |
| `GET /alerts?limit=10` | Recent alerts as JSON |

### Test with curl

```bash
# Start watch with SSE
clawguard watch --sse-port 37776

# In another terminal
curl -N http://127.0.0.1:37776/stream
curl http://127.0.0.1:37776/health
```

### OpenClaw gateway plugin

The `openclaw-plugin/` directory contains a ready-to-use OpenClaw gateway plugin that consumes the SSE stream and forwards alerts to messaging channels (Telegram, Discord, Slack, etc.) through OpenClaw's channel infrastructure.

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

Available slash commands in your messaging channel:

| Command | Description |
|---------|-------------|
| `/clawguard_feed` | Toggle alert feed on/off |
| `/clawguard_status` | Show current security status |
| `/clawguard_alerts` | Show 10 most recent alerts |

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
