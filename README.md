# ClawGuard

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
- Conservative scope: no auto-remediation, no daemon loop, no hidden mutation of OpenClaw state

## What It Checks Today

ClawGuard keeps the detector catalog intentionally small and high-signal.

- `OpenClaw config audit`
  - looks for dangerous local runtime posture in `openclaw.json`, `exec-approvals.json`, and auth-profile state
- `Skills scan`
  - looks for shell, network, and local-install behaviors that deserve human review
- `MCP scan`
  - looks for suspicious auto-install launchers, unpinned packages, and wide filesystem reach
- `Secrets and env scan`
  - looks for hardcoded secrets, token-like literals, and PEM / SSH private-key material
- `Advisory matching`
  - matches local OpenClaw version evidence against the bundled advisory feed when version evidence is available

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

From `clawguard/`:

```bash
source ~/.cargo/env
cargo install --path .
```

For local development you can also build the release binary directly:

```bash
source ~/.cargo/env
cargo build --release
./target/release/clawguard --help
```

## First Run And Usage

- `clawguard`
  - on first run, detects OpenClaw, launches the setup wizard, runs an immediate scan, and renders findings
  - after configuration, runs the current scan flow and renders the latest findings view
- `clawguard scan`
  - runs the scan flow directly
- `clawguard --json` or `clawguard scan --json`
  - emits machine-readable findings JSON derived from the shared scan result model
- `clawguard --no-interactive` or `clawguard scan --no-interactive`
  - accepts default first-run setup values instead of prompting
- if no supported runtime is detected
  - human output and `--json` both emit the same structured Info finding instead of a placeholder success message

Common examples:

```bash
clawguard
clawguard scan
clawguard scan --json
clawguard scan --no-interactive --json
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
- V0.5 is a CLI scanner, not a daemon or background monitor
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

Run from `clawguard/`:

```bash
source ~/.cargo/env
cargo test
cargo build --release
```
