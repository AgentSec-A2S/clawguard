// ClawGuard Runtime Guard — OpenClaw plugin.
//
// This plugin spawns `clawguard runtime broker` as a long-lived child
// process per session. It serializes OpenClaw's before_tool_call and
// after_tool_call events into newline-delimited JSON, sends them to the
// broker's stdin, and parses the one-line JSON verdict from stdout.
//
// Design decisions:
// - One broker per session keeps the RateLimiter counters + manifest
//   handle scoped correctly.
// - The plugin never blocks tool calls on its own; the broker always
//   returns a verdict (even on parse error / panic it returns an Allow
//   with an explanation string). Fail-open is intentional for Sprint 2.
// - Communication is synchronous within a tool-call by design: we await
//   one response line before returning the hook result. If the broker
//   hangs, the per-request timeout (`HOOK_TIMEOUT_MS`) forces a
//   fail-open Allow so the host runtime is never wedged.

const { spawn } = require("node:child_process");
const path = require("node:path");

const HOOK_TIMEOUT_MS = 2500;

function register(api) {
  const log = api.logger;
  const cfg = api.pluginConfig || {};
  const clawguardBin = cfg.clawguardBin || "clawguard";
  const manifestPath = cfg.manifestPath || "";
  const bypassTools = new Set(cfg.bypassTools || []);
  const logLevel = cfg.logLevel || "info";

  let broker = null;
  let stderrBuffer = "";
  const pending = []; // queued resolver callbacks waiting on the next line
  let stdoutBuffer = "";

  function spawnBroker() {
    const args = ["runtime", "broker"];
    if (manifestPath) {
      args.push("--manifest", manifestPath);
    }
    const child = spawn(clawguardBin, args, {
      stdio: ["pipe", "pipe", "pipe"],
      env: process.env,
    });

    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");

    child.stdout.on("data", (chunk) => {
      stdoutBuffer += chunk;
      let nl;
      while ((nl = stdoutBuffer.indexOf("\n")) >= 0) {
        const line = stdoutBuffer.slice(0, nl).trim();
        stdoutBuffer = stdoutBuffer.slice(nl + 1);
        if (!line) continue;
        const resolver = pending.shift();
        if (!resolver) {
          if (logLevel !== "silent") {
            log.warn(`clawguard-runtime: orphan broker line: ${line}`);
          }
          continue;
        }
        try {
          resolver.resolve(JSON.parse(line));
        } catch (e) {
          resolver.resolve({
            decision: "allow",
            block: false,
            reason: `clawguard-runtime: malformed broker response: ${e.message}`,
            finding_kinds: [],
          });
        }
      }
    });

    child.stderr.on("data", (chunk) => {
      stderrBuffer += chunk;
      if (logLevel === "debug") {
        log.debug(`clawguard-runtime[stderr]: ${chunk.trimEnd()}`);
      }
    });

    child.on("exit", (code) => {
      if (logLevel !== "silent") {
        log.warn(`clawguard-runtime: broker exited with code ${code}`);
      }
      broker = null;
      // Resolve any pending waiters with fail-open.
      while (pending.length) {
        const r = pending.shift();
        r.resolve({
          decision: "allow",
          block: false,
          reason: "clawguard-runtime: broker exited",
          finding_kinds: [],
        });
      }
    });

    child.on("error", (err) => {
      if (logLevel !== "silent") {
        log.error(`clawguard-runtime: broker spawn error: ${err.message}`);
      }
      broker = null;
    });

    return child;
  }

  function ensureBroker() {
    if (!broker) {
      broker = spawnBroker();
    }
    return broker;
  }

  function sendEvent(event) {
    return new Promise((resolve) => {
      const child = ensureBroker();
      if (!child || !child.stdin.writable) {
        resolve({
          decision: "allow",
          block: false,
          reason: "clawguard-runtime: broker not writable, fail-open",
          finding_kinds: [],
        });
        return;
      }
      const timer = setTimeout(() => {
        // Remove this resolver from the queue (it may have been satisfied
        // already; guard by marking `resolved`).
        if (!entry.resolved) {
          entry.resolved = true;
          resolve({
            decision: "allow",
            block: false,
            reason: `clawguard-runtime: broker timeout > ${HOOK_TIMEOUT_MS}ms, fail-open`,
            finding_kinds: [],
          });
        }
      }, HOOK_TIMEOUT_MS);

      const entry = {
        resolved: false,
        resolve: (r) => {
          if (entry.resolved) return;
          entry.resolved = true;
          clearTimeout(timer);
          resolve(r);
        },
      };
      pending.push(entry);
      try {
        child.stdin.write(JSON.stringify(event) + "\n");
      } catch (e) {
        entry.resolve({
          decision: "allow",
          block: false,
          reason: `clawguard-runtime: write error: ${e.message}`,
          finding_kinds: [],
        });
      }
    });
  }

  api.hooks.before_tool_call(async (event, ctx) => {
    if (bypassTools.has(event.toolName)) return undefined;
    const wireEvent = {
      phase: "before_tool_call",
      session_id: ctx?.sessionId || "",
      agent_id: ctx?.agentId || undefined,
      run_id: event.runId,
      tool_call_id: event.toolCallId,
      tool_name: event.toolName,
      params: event.params || {},
    };
    const verdict = await sendEvent(wireEvent);
    if (logLevel === "debug") {
      log.debug(`clawguard-runtime: pre ${event.toolName} → ${verdict.decision}`);
    }
    if (verdict.block) {
      return {
        block: true,
        blockReason:
          verdict.block_reason ||
          verdict.reason ||
          "clawguard blocked this tool call",
      };
    }
    return undefined;
  });

  api.hooks.after_tool_call(async (event, ctx) => {
    if (bypassTools.has(event.toolName)) return;
    const wireEvent = {
      phase: "after_tool_call",
      session_id: ctx?.sessionId || "",
      agent_id: ctx?.agentId || undefined,
      run_id: event.runId,
      tool_call_id: event.toolCallId,
      tool_name: event.toolName,
      params: event.params || {},
      result: typeof event.result === "string" ? event.result : undefined,
      error: event.error,
    };
    const verdict = await sendEvent(wireEvent);
    if (logLevel === "debug") {
      log.debug(`clawguard-runtime: post ${event.toolName} → ${verdict.decision}`);
    }
  });

  log.info(
    `clawguard-runtime: registered (bin=${clawguardBin}, manifest=${manifestPath || "<default>"}, bypass=${bypassTools.size})`
  );
}

module.exports = { register };
