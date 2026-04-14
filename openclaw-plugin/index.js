/**
 * ClawGuard OpenClaw Gateway Plugin
 *
 * Connects to the ClawGuard SSE server and forwards security alerts
 * to a configured messaging channel (Telegram, Discord, Slack, etc.)
 * via the OpenClaw gateway's channel infrastructure.
 *
 * Config in openclaw.json:
 *   plugins.entries.clawguard.config.host    — SSE host (auto-detected: 127.0.0.1 or host.docker.internal)
 *   plugins.entries.clawguard.config.port    — ClawGuard SSE port (default: 37776)
 *   plugins.entries.clawguard.config.channel — Channel type (telegram, discord, etc.)
 *   plugins.entries.clawguard.config.to      — Target chat/user/channel ID
 */

import { existsSync, readFileSync } from "node:fs";

const DEFAULT_PORT = 37776;
const RECONNECT_BASE_MS = 1000;
const RECONNECT_MAX_MS = 30000;

let feedEnabled = true;
let reconnectDelay = RECONNECT_BASE_MS;

export default {
  id: "clawguard",
  name: "ClawGuard Security Alerts",

  register(api) {
    const config = api.pluginConfig || {};
    const host = config.host || detectHost();
    const port = config.port || DEFAULT_PORT;
    const channel = config.channel;
    const to = config.to;
    const baseUrl = `http://${host}:${port}`;

    if (!channel || !to) {
      api.logger.info("[clawguard] channel and to are required in plugin config");
      return;
    }

    api.logger.info(`[clawguard] SSE target: ${baseUrl}, channel: ${channel}, to: ${to}`);

    // Background service: consume SSE stream from clawguard watch
    api.registerService({
      id: "clawguard-alert-feed",
      start: async () => {
        connectStream(api, baseUrl, channel, to);
      },
    });

    // Slash commands
    api.registerCommand({
      name: "clawguard_feed",
      description: "Toggle ClawGuard alert feed on/off",
      handler: async () => {
        feedEnabled = !feedEnabled;
        return {
          text: feedEnabled
            ? "ClawGuard alert feed resumed"
            : "ClawGuard alert feed paused",
        };
      },
    });

    api.registerCommand({
      name: "clawguard_status",
      description: "Show ClawGuard security status",
      handler: async () => {
        try {
          const res = await fetch(`${baseUrl}/status`);
          const data = await res.json();
          return { text: formatStatus(data) };
        } catch {
          return { text: "ClawGuard is not reachable. Is `clawguard watch` running?" };
        }
      },
    });

    api.registerCommand({
      name: "clawguard_alerts",
      description: "Show recent ClawGuard alerts",
      handler: async () => {
        try {
          const res = await fetch(`${baseUrl}/alerts?limit=10`);
          const data = await res.json();
          return { text: formatAlertList(data.alerts || []) };
        } catch {
          return { text: "ClawGuard is not reachable. Is `clawguard watch` running?" };
        }
      },
    });

    api.registerCommand({
      name: "clawguard_help",
      description: "Show all ClawGuard commands and usage",
      handler: async () => {
        return {
          text: [
            "\u{1F6E1}\uFE0F ClawGuard — Security Scanner for OpenClaw",
            "",
            "Telegram commands:",
            "  /clawguard_help     Show this help message",
            "  /clawguard_status   Show ClawGuard connection status",
            "  /clawguard_alerts   Show recent alerts (if available)",
            "  /clawguard_feed     Toggle the real-time alert feed on/off",
            "",
            "CLI commands (run on the host):",
            "  clawguard               First run: setup wizard + scan; after: status view",
            "  clawguard scan           Run a one-time security scan",
            "  clawguard watch          Start continuous monitoring (required for Telegram alerts)",
            "  clawguard audit          Show audit event log (config/skill/plugin changes)",
            "  clawguard status         Show persisted security status",
            "  clawguard alerts         Show alert history",
            "  clawguard baseline approve   Approve current state as drift baseline",
            "  clawguard notify         View/change notification settings",
            "",
            `Tip: Run \`clawguard watch\` with SSE enabled (port ${port}) to enable this Telegram integration.`,
          ].join("\n"),
        };
      },
    });
  },
};

// --- SSE Consumer ---

function connectStream(api, baseUrl, channel, to) {
  const url = `${baseUrl}/stream`;
  api.logger.info(`[clawguard] connecting to SSE stream at ${url}`);

  fetch(url, { headers: { Accept: "text/event-stream" } })
    .then((res) => {
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      api.logger.info("[clawguard] connected to SSE stream");
      reconnectDelay = RECONNECT_BASE_MS;
      return processStream(api, res.body, channel, to);
    })
    .catch((err) => {
      api.logger.info(`[clawguard] SSE connection error — ${err.message}`);
      scheduleReconnect(api, baseUrl, channel, to);
    });
}

async function processStream(api, body, channel, to) {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const events = parseSSEBuffer(buffer);
      buffer = events.remaining;

      for (const event of events.parsed) {
        if (!feedEnabled) continue;

        if (event.type === "alert") {
          const msg = formatAlert(event.data);
          sendToChannel(api, channel, to, msg);
        } else if (event.type === "digest") {
          const msg = formatDigest(event.data);
          sendToChannel(api, channel, to, msg);
        }
      }
    }
  } catch (err) {
    api.logger.info(`[clawguard] SSE stream read error — ${err.message}`);
  }

  scheduleReconnect(api, baseUrl, channel, to);
}

function scheduleReconnect(api, baseUrl, channel, to) {
  const delay = Math.min(reconnectDelay, RECONNECT_MAX_MS);
  api.logger.info(`[clawguard] reconnecting in ${Math.round(delay / 1000)}s`);
  setTimeout(() => connectStream(api, baseUrl, channel, to), delay);
  reconnectDelay = Math.min(reconnectDelay * 2, RECONNECT_MAX_MS);
}

// --- SSE Parsing ---

function parseSSEBuffer(buffer) {
  const parsed = [];
  const blocks = buffer.split("\n\n");
  const remaining = blocks.pop() || "";

  for (const block of blocks) {
    if (!block.trim()) continue;
    let eventType = "message";
    let data = "";

    for (const line of block.split("\n")) {
      if (line.startsWith("event: ")) {
        eventType = line.slice(7).trim();
      } else if (line.startsWith("data: ")) {
        data += line.slice(6);
      }
    }

    if (data) {
      try {
        parsed.push({ type: eventType, data: JSON.parse(data) });
      } catch {
        // Skip malformed JSON
      }
    }
  }

  return { parsed, remaining };
}

// --- Message Formatting ---

function formatAlert(data) {
  const severity = (data.severity || "unknown").toUpperCase();
  const path = data.path || "unknown";
  const explanation = data.explanation || "";
  const action = data.recommended_action || "";

  return [
    `\u{1F6E1}\uFE0F ClawGuard Alert [${severity}]`,
    `\u{1F4C1} ${path}`,
    `\u26A0\uFE0F ${explanation}`,
    action ? `\u{1F4A1} ${action}` : "",
  ]
    .filter(Boolean)
    .join("\n");
}

function formatDigest(data) {
  return [
    "\u{1F4CA} ClawGuard Daily Digest",
    `${data.alert_count || 0} new alerts in the last 24 hours`,
    data.summary || "",
    "Run /clawguard_alerts for details",
  ]
    .filter(Boolean)
    .join("\n");
}

function formatStatus(data) {
  return [
    "\u{1F6E1}\uFE0F ClawGuard Status",
    `Open alerts: ${data.open_alerts ?? "?"}`,
    `Baselines: ${data.baseline_count ?? "?"}`,
    `SSE clients: ${data.clients ?? "?"}`,
    `Feed: ${feedEnabled ? "on" : "off"}`,
  ].join("\n");
}

function formatAlertList(alerts) {
  if (!alerts.length) return "No recent alerts.";

  const lines = alerts.slice(0, 10).map((a) => {
    const sev = (a.severity || "?").toUpperCase();
    return `[${sev}] ${a.alert_id} — ${a.path}`;
  });

  return ["\u{1F6E1}\uFE0F Recent Alerts", ...lines].join("\n");
}

// --- Host Detection ---

/**
 * Auto-detect whether we are running inside a container.
 * If /.dockerenv exists or /proc/1/cgroup mentions docker/containerd,
 * use host.docker.internal so the plugin can reach the host SSE server.
 * Otherwise assume we are on the host and use 127.0.0.1.
 */
function detectHost() {
  try {
    if (existsSync("/.dockerenv")) return "host.docker.internal";
    if (existsSync("/proc/1/cgroup")) {
      const cgroup = readFileSync("/proc/1/cgroup", "utf8");
      if (/docker|containerd|kubepods/i.test(cgroup))
        return "host.docker.internal";
    }
  } catch {
    // read failed — assume host
  }
  return "127.0.0.1";
}

// --- Channel Send ---

const CHANNEL_SEND_MAP = {
  telegram: { namespace: "telegram", functionName: "sendMessageTelegram" },
  whatsapp: { namespace: "whatsapp", functionName: "sendMessageWhatsApp" },
  discord: { namespace: "discord", functionName: "sendMessageDiscord" },
  slack: { namespace: "slack", functionName: "sendMessageSlack" },
  signal: { namespace: "signal", functionName: "sendMessageSignal" },
};

function sendToChannel(api, channel, to, message) {
  const mapping = CHANNEL_SEND_MAP[channel];
  if (!mapping) {
    api.logger.info(`[clawguard] unsupported channel type: ${channel}`);
    return;
  }

  const channelApi = api.runtime?.channel?.[mapping.namespace];
  if (!channelApi) {
    api.logger.info(`[clawguard] channel "${channel}" not available in runtime`);
    return;
  }

  const senderFunction = channelApi[mapping.functionName];
  if (!senderFunction) {
    api.logger.info(`[clawguard] channel "${channel}" has no ${mapping.functionName} function`);
    return;
  }

  senderFunction(to, message).catch((error) => {
    const msg = error instanceof Error ? error.message : String(error);
    api.logger.info(`[clawguard] failed to send to ${channel}: ${msg}`);
  });
}
