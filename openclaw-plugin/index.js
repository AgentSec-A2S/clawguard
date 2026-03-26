/**
 * ClawGuard OpenClaw Gateway Plugin
 *
 * Connects to the ClawGuard SSE server and forwards security alerts
 * to a configured messaging channel (Telegram, Discord, Slack, etc.)
 * via the OpenClaw gateway's channel infrastructure.
 *
 * Config in openclaw.json:
 *   plugins.entries.clawguard.config.port    — ClawGuard SSE port (default: 37776)
 *   plugins.entries.clawguard.config.channel — Channel type (telegram, discord, etc.)
 *   plugins.entries.clawguard.config.to      — Target chat/user/channel ID
 */

const DEFAULT_PORT = 37776;
const RECONNECT_BASE_MS = 1000;
const RECONNECT_MAX_MS = 30000;
const HEARTBEAT_TIMEOUT_MS = 60000;

let feedEnabled = true;
let reconnectDelay = RECONNECT_BASE_MS;
let lastEventAt = Date.now();

export default {
  id: "clawguard",
  name: "ClawGuard Security Alerts",

  register(api) {
    const config = api.pluginConfig || {};
    const port = config.port || DEFAULT_PORT;
    const channel = config.channel;
    const to = config.to;
    const baseUrl = `http://127.0.0.1:${port}`;

    if (!channel || !to) {
      api.log?.("clawguard: channel and to are required in plugin config");
      return;
    }

    // Register background service for SSE consumption
    api.registerService?.("clawguard-feed", () => {
      connectStream(api, baseUrl, channel, to);
    });

    // Slash commands (read-only in V1)
    api.registerCommand?.("clawguard_feed", {
      description: "Toggle ClawGuard alert feed on/off",
      handler: async () => {
        feedEnabled = !feedEnabled;
        return feedEnabled
          ? "ClawGuard alert feed resumed"
          : "ClawGuard alert feed paused";
      },
    });

    api.registerCommand?.("clawguard_status", {
      description: "Show ClawGuard security status",
      handler: async () => {
        try {
          const res = await fetch(`${baseUrl}/status`);
          const data = await res.json();
          return formatStatus(data);
        } catch {
          return "ClawGuard is not reachable. Is `clawguard watch --sse-port` running?";
        }
      },
    });

    api.registerCommand?.("clawguard_alerts", {
      description: "Show recent ClawGuard alerts",
      handler: async () => {
        try {
          const res = await fetch(`${baseUrl}/alerts?limit=10`);
          const data = await res.json();
          return formatAlertList(data.alerts || []);
        } catch {
          return "ClawGuard is not reachable. Is `clawguard watch --sse-port` running?";
        }
      },
    });
  },
};

// --- SSE Consumer ---

function connectStream(api, baseUrl, channel, to) {
  const url = `${baseUrl}/stream`;
  api.log?.(`clawguard: connecting to SSE stream at ${url}`);

  // Use native fetch with ReadableStream for SSE
  fetch(url, { headers: { Accept: "text/event-stream" } })
    .then((res) => {
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      api.log?.("clawguard: connected to SSE stream");
      reconnectDelay = RECONNECT_BASE_MS;
      return processStream(api, res.body, channel, to);
    })
    .catch((err) => {
      api.log?.(`clawguard: SSE connection error — ${err.message}`);
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
        lastEventAt = Date.now();
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
    api.log?.(`clawguard: SSE stream read error — ${err.message}`);
  }

  scheduleReconnect(api, channel, to);
}

function scheduleReconnect(api, baseUrl, channel, to) {
  const delay = Math.min(reconnectDelay, RECONNECT_MAX_MS);
  api.log?.(
    `clawguard: reconnecting in ${Math.round(delay / 1000)}s`,
  );
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

// --- Channel Send ---

function sendToChannel(api, channel, to, message) {
  // Use OpenClaw's channel adapter to send messages
  // The exact API surface depends on the OpenClaw SDK version
  // This is the expected pattern based on claude-mem's implementation
  if (api.sendMessage) {
    api.sendMessage(channel, to, message);
  } else if (api.channels?.send) {
    api.channels.send(channel, to, message);
  } else {
    api.log?.(
      `clawguard: no channel send API available — message: ${message.slice(0, 100)}`,
    );
  }
}
