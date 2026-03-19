# ClawGuard

ClawGuard is a host-side integrity guardian for OpenClaw.

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

## Current V0 Flow

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
- V0 exit codes
  - scan commands currently exit `0` even when findings are present
  - automation should inspect `--json` output rather than rely on exit status alone

## Notes

- Advisory matching only runs when ClawGuard can read a colocated OpenClaw `package.json` for version evidence.
- The bundled advisory feed is intentionally empty until curated production advisories are shipped.

## Development

Run from `clawguard/`:

```bash
source ~/.cargo/env
cargo test
cargo build --release
```
