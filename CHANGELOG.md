# Changelog

## [1.2.0-beta.5] - 2026-04-23

### Added — V1.3 Sprint 1: MCP Supply-Chain Hardening

Four new detectors, all mapped to OWASP ASI06 (Supply Chain):

- **`mcp-no-lockfile`** (Medium) — MCP servers launched via package-manager launchers without a lockfile in scope. JS launcher matrix covers `npx` (incl. `-p` / `--package` / `-y`), `npm exec/x/run`, `pnpm dlx/exec/x`, `yarn dlx/exec`, `bunx`, `bun x/run`, plus `sh -c` / `bash -c` tunnelled invocations. Non-JS runtimes also covered: `deno run/install`, `uv run/tool`, `uvx`, `pipx`, `poetry run`, `rye run`, `python3 -m`, `cargo run`, `go run/install`, `ruby`, `perl`, `php`, `Rscript`, `pnpx`. Lockfile detection accepts `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lockb`, and `bun.lock`. Nested `sh -c "sh -c '...'"` wrappers unwrapped up to depth 3.
- **`mcp-server-name-typosquat`** (High) — configured server name is a near-match of a curated allowlist entry. NFKC + lowercase + separator-strip normalization, Damerau–Levenshtein distance ≤1 for normalized length 5–7 and ≤2 for length ≥8. Short names (<5 normalized) exempt. Allowlist ships at `data/mcp_server_allowlist.txt` with 30+ canonical entries.
- **`mcp-command-changed`** (High) — per-server baseline drift on the canonical `{command, args, url, cwd, env_keys}` tuple. Env *key names* are included (catches `NODE_OPTIONS=--require /tmp/evil.js`, `LD_PRELOAD`, proxy env injection); env *values* are excluded so legitimate secret rotation does not drift. Emitted via synthetic `mcp-command://<config>#<source>::<server_name>` artifact threaded through the existing `BaselineArtifact` pipeline with a dedicated `source_label = "mcp-command"`; the real config file path anchors the finding.
- **`file-type-mismatch`** (High) — byte-first signature sweep of skill and hook directories. Flags any file with a text-like extension (or extensionless hook) whose first 16 bytes match a native executable header: ELF, PE/MZ, Mach-O MH_MAGIC · MH_MAGIC_64 · MH_CIGAM · MH_CIGAM_64, fat-universal FAT_MAGIC · FAT_CIGAM. Short-circuits on the binary-extension allowlist (`.node`, `.wasm`, `.so`, `.dylib`, `.dll`, `.exe`, `.bin`, `.o`, `.a`). Scan-boundary symlink-escape guards.

### Added — Other Sprint 1 Coverage

- **`hook-multiple-handlers`** (Medium, ASI06) — warns when more than one priority handler file (`handler.ts` / `handler.js` / `index.ts` / `index.js` / `handler.mjs` / `handler.cjs`) coexists in a single hook directory. Only the highest-priority file is actually executed by OpenClaw, so a shadowed sibling is a classic hide-the-payload pattern (benign `handler.ts` wins loader, malicious `handler.js` sits parked until a later edit swaps them).
- **Plugin-bundled `.mcp.json` discovery** — the openclaw preset now scans `~/.openclaw/extensions/*/.mcp.json`, the 4th MCP mount point that OpenClaw loads via `resolveBundleMcpConfigPaths` in `src/plugins/bundle-mcp.ts`. Previously invisible to typosquat, lockfile, and command-drift detectors.

### Infrastructure

- New shared module `src/scan/file_type.rs` — byte-first signature detector with 8-row table (ELF / PE-MZ / Mach-O 4 variants / fat-universal 2 variants), `SIGNATURE_MAX_INSPECT_BYTES = 16`, and a structural completeness test that fails if a row is dropped from the table.
- New data file `data/mcp_server_allowlist.txt` loaded via `include_str!`.
- `src/scan/skills.rs` + `src/scan/hooks.rs` refactored so the byte-first signature check runs BEFORE any `fs::read_to_string`; both paths now enforce scan-boundary symlink-escape guards.
- New dependency: `unicode-normalization = "0.1"` (NFKC normalization for typosquat matcher).

### Tests

- 498 tests passing across all suites (was 490). Sprint 1 added 19 tests to `mcp_scan.rs`, 9 to `skills_scan.rs`, 7 to `hooks_scan.rs`, and 13 unit tests in `file_type.rs`. The post-ship patch bundle added a further 2 `mcp_scan.rs` regressions (env-key drift + env-value stability), 1 discovery test, 1 end-to-end `mcp_scan.rs` test (plugin-bundled `.mcp.json` runs the full detector matrix), 2 `hooks_scan.rs` tests (shadow-handler warning + single-handler negative), 16 `mcp-no-lockfile` cases for non-JS runtimes, and 1 nested-`sh -c` tunnel test.

## [1.2.0-beta.4] - 2026-04-15

### Security — Trail of Bits Audit Fixes

- Bound SSE request `read_line` to 8 KiB to prevent memory exhaustion from slow-drip clients
- Cap JSONL ingestion line length to 1 MiB — skip oversized lines instead of OOM
- Add `metadata().len()` size guard before `catalog.json` read (was the only scanner missing it)
- Block private/loopback/link-local IPs in webhook URL validation (SSRF prevention)
- Set `0o700` directory + `0o600` file permissions on config and DB files (Unix)
- Downgrade transient scan cycle errors to warnings instead of aborting watch loop

### Audit Results

- Semgrep scan (227 rules, 8 rulesets): 0 findings
- Supply chain: 0 yanked versions, 0 unsafe blocks, 0 hardcoded secrets
- Confirmed secure: parameterized SQL, TLS on by default, path traversal protected, no ReDoS

## [1.2.0-beta.3] - 2026-04-15

### Fixed — Deep Docker UAT follow-up

- **SSE `/alerts` contract** — the embedded SSE server now returns recent `open` alerts by default, honors query-safe `status` and `limit` filters, and keeps known routes working when query strings are present.
- **Notification route replay suppression** — newly enabled routes now deliver only fresh `open` alerts. Previously an acknowledged historical alert could be replayed when a webhook route was enabled after the acknowledgement.
- **Missing `exec-approvals.json` remediation path** — the OpenClaw audit finding now points at the real expected root path under `~/.openclaw/exec-approvals.json` instead of a nested agent directory.
- **Degraded local SSE startup reporting** — `clawguard watch --json` now emits structured warnings with `kind`, `bind`, and `port`, and bind conflicts are reported as degraded local SSE startup instead of an ambiguous failure.
- **`notify off` operator guidance** — the CLI now explicitly states that `notify off` disables only ClawGuard’s local SSE config and does not stop externally managed or plugin-owned SSE servers.

### Docs

- Added durable repo copies of the deep Docker UAT report and the focused fix retest report.
- Updated the README set and architecture docs to reflect the current `audit --json` array contract and the ClawGuard-owned SSE semantics.

### Tests

- Expanded `tests/sse_server.rs` to pin the `/alerts` default view, `status=all`, `limit`, invalid-query fallback, and query-string-safe routing behavior.
- Added notification and watcher regression coverage for acknowledged-alert route replay, structured SSE bind-conflict warnings, `notify off` messaging, and fresh re-alert IDs.
- Added OpenClaw audit coverage for the corrected missing `exec-approvals.json` path rendering.

## [1.2.0-beta.2] - 2026-04-15

### Fixed — UAT 2026-04-15

- **`audit --json` contract** — now emits a single valid JSON array (was: empty stdout on empty result set; NDJSON on populated set). Fixes `jq` pipelines and matches every other `--json` subcommand.
- **Drift alert dedup regression** — `append_new_drift_alerts` now suppresses only while an identical drift is still **open**. Previously used `list_unresolved_alerts()` which also matched acknowledged alerts, so acking an alert silently disabled all future re-alerts for the same file. (`watch.rs:272`)
- **OpenClaw gateway plugin `register()` TypeError** — switched `registerCommand` calls from `id:` → `name:` and wrapped handler returns in `{ text: ... }` to match the current OpenClaw plugin SDK. Previously the framework called `command.name.trim()` on `undefined` and aborted plugin registration, leaving slash commands `/clawguard_*` unregistered (SSE service still ran because `registerService` came first). (`openclaw-plugin/index.js` → `@clawguard/openclaw-plugin@1.0.1`)

### Tests

- New `tests/audit_cli.rs`: 2 contract tests pin `audit --json` output shape for both empty and populated DBs.
- `tests/watchers.rs::acknowledged_drift_alert_does_not_suppress_re_alerting_on_next_rescan` (renamed) now pins the correct behavior — acking no longer gags re-alerting.

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
