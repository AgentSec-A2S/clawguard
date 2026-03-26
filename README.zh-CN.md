# ClawGuard

> [为什么需要](#为什么需要-clawguard) | [当前能力](#当前能力) | [检查项](#现在会检查什么) | [工作方式](#工作方式) | [安装](#安装) | [使用](#首次运行与常用命令) | [通知](#通知) | [输出模型](#输出模型) | [范围与限制](#当前范围与限制) | [开发](#开发)

ClawGuard 是一个面向 OpenClaw 的宿主机侧完整性守护工具。

它要回答的问题很简单，也很实际：

`在真正信任这台机器上的 OpenClaw 之前，它当前的本地状态看起来还安全吗？`

ClawGuard 不是新的 runtime，不是沙箱，也不是通用型 EDR。它只聚焦在少量高信号问题上：

- 本地配置是否被放宽到危险状态
- 关键状态文件是否存在明显风险
- 扩展、技能、MCP、密钥等本地攻击面是否已经变得不安全

## 为什么需要 ClawGuard

OpenClaw 最敏感的安全面很多都不在“模型”里，而在宿主机本地：

- `~/.openclaw/openclaw.json`
- `~/.openclaw/exec-approvals.json`
- `~/.openclaw/.env`
- `~/.openclaw/agents/*/agent/auth-profiles.json`
- `~/.openclaw/skills/`
- 嵌在 OpenClaw 配置里的 MCP 启动器定义

运行时隔离可以降低爆炸半径，但它并不能告诉你：

- 这套本地配置是不是已经被削弱了
- 有没有出现危险漂移
- 有没有明显的高风险扩展面已经打开

ClawGuard 的目标不是“什么都做”，而是尽快给出一个可操作的判断：

- 第一次使用前：这套安装现在看起来是不是明显危险
- 改动之后：有没有重要状态发生了不该有的漂移
- 排障时：到底哪条证据最重要，严重度是什么，下一步该做什么

## 当前能力

- OpenClaw-first 的本地发现逻辑，支持常见状态目录布局，也覆盖 symlink 形式的 `~/.openclaw`
- 首次运行时自动发现 OpenClaw，完成最小化设置后立即执行扫描
- 面向终端的 findings-first 交互体验
- 人类可读输出和 `--json` 都来自同一套结构化 finding 模型
- OpenClaw 配置审计，覆盖：
  - 危险的 exec approval 配置
  - sandbox 关闭后仍走 host fallback 的情形
  - 危险的 sandbox network 模式
  - 暴露式 `gateway.bind`
  - `channels.*.dmPolicy="open"` 带来的外部直达风险
  - webhook token 缺失、插件 `allowPromptInjection=true` 等 hook / plugin 风险
  - 敏感本地文件权限过宽
- Tripwire 检测（V1 新增）：
  - 扫描 `exec-approvals.json` 中的 allowlist，标记预批准了灾难性命令的条目（`rm -rf /`、pipe-to-shell、反弹 shell、`mkfs`、`dd` 写块设备）
  - 支持全路径可执行文件识别（`/bin/rm`、`/usr/bin/env bash`）
  - 扩展 shell sink 检测：`sh`、`bash`、`zsh`、`dash`、`ksh`、`fish`
  - token-aware + quote-aware 命令匹配，防止引号内容触发误报
  - 审批策略漂移检测：`askFallback` 放松、危险可执行文件或解释器加入 allowlist
  - V1 为纯告警模式，不做实时命令拦截 — OpenClaw 的 exec-approval 系统是一个封闭的信任边界，没有稳定的外部拦截 API
- Skills 扫描，识别高风险 shell / network / install 行为
- MCP 扫描，识别可疑启动器、未固定版本依赖、过宽目录授权
- Secrets / env 扫描，识别硬编码 secret、token-like literal、PEM / SSH 私钥内容
- Advisory 匹配：当存在 OpenClaw 版本证据时，用本地 advisory feed 做版本区间匹配
  - 当前也支持一个受限 fallback，例如 `packages/core/package.json`
- SQLite 持久化（V1 新增）：
  - 扫描快照、当前 findings、基线、告警状态、通知回执
  - WAL 模式 + busy_timeout，损坏数据库自动重建
- Baseline 批准与漂移检测（V1 新增）：
  - `clawguard baseline approve` 记录当前文件哈希为批准状态
  - 文件变动时自动检测漂移并生成告警
- 前台 Watch 循环（V1 新增）：
  - 监听关键文件和 skill 目录的变化
  - 变更时重新扫描、记录快照、追加漂移告警
  - 桌面通知 + webhook 推送 + 每日摘要
- 持久化操作界面（V1 新增）：
  - `clawguard` / `clawguard status`：基于持久化状态的 status 视图
  - `clawguard alerts`：近期告警历史 + `clawguard alerts ignore <alert-id>` 确认告警
  - `clawguard trust openclaw-config` / `exec-approvals`：从基线恢复批准过的配置
- 内嵌 SSE 服务器（V1 新增）：
  - `--sse-port` 或 `[sse]` config 段启用，独立线程运行
  - Config 热更新：运行时修改 `config.toml` 的 `port` 或 `bind`，server 自动重启
  - 端点：`/stream`（SSE 事件流）、`/health`、`/status`、`/alerts`
  - 仅绑定 localhost，最多 16 个客户端，30 秒心跳
- OpenClaw gateway 插件（`openclaw-plugin/`）：
  - 连接 ClawGuard SSE 流，自动重连（exponential backoff）
  - 将告警和每日摘要转发到 Telegram/Discord/Slack 等已配置的 channel
  - Slash 命令：`/clawguard_feed`、`/clawguard_status`、`/clawguard_alerts`

## 现在会检查什么

ClawGuard 故意把 detector catalog 控制得很小，只保留高信号项。

- `OpenClaw config audit`
  - 检查本地 runtime posture 是否明显危险
  - tripwire 检测：标记 allowlist 中预批准灾难性命令的条目
  - 审批漂移检测：`askFallback` 放松、危险可执行文件/解释器进 allowlist
- `Skills scan`
  - 检查技能目录里是否存在值得人工复核的危险行为
- `MCP scan`
  - 检查 MCP 启动链是否有高风险安装与目录暴露模式
- `Secrets and env scan`
  - 检查是否直接落地了敏感密钥和私钥材料
- `Advisory matching`
  - 当能读到版本证据时，将本地版本与 advisory feed 做离线匹配
- `Baseline approval`
  - 将当前文件哈希证据记录为批准基线，用于漂移检测
- `Watch loop`
  - 监听关键文件和 skill 目录，变更时重新扫描、记录快照、追加漂移告警、推送通知

## 工作方式

从高层看，ClawGuard 的流水线是：

```text
preset
  -> discovery
  -> evidence collection
  -> source-context annotation
  -> detectors
  -> finding aggregation
  -> renderers
```

实际运行时大致分成六步：

1. `Discovery`
   按 OpenClaw 已知本地布局和固定锚点发现运行时。
2. `Setup`
   首次运行时写入 ClawGuard 自己的配置，并保持设置面尽量窄。
3. `Evidence collection`
   读取本地 OpenClaw 状态，例如配置、exec approvals、auth profiles、skills、`.env` 等。
4. `Detectors`
   用一组边界清晰的小检测器运行，而不是堆一个泛化规则大杂烩。
5. `Finding aggregation`
   把结果统一折叠进共享 finding 模型，带上严重度、证据、解释和建议动作。
6. `Rendering`
   将同一份结构化结果渲染成终端输出或机器可读 JSON。

## ClawGuard 不是什么

- 不是 OpenClaw 的替代 runtime
- 不是沙箱或网络策略引擎
- 不是通用宿主机监控产品
- 不是深度多智能体分析平台
- 不是自动修复系统

## 安装

### 快速安装（预编译二进制）

```bash
curl -fsSL https://raw.githubusercontent.com/AgentSec-A2S/clawguard/main/install.sh | sh
```

也可以从 [GitHub Releases](https://github.com/AgentSec-A2S/clawguard/releases) 页面下载指定版本。

### 从源码构建

```bash
cargo install --path .
```

本地开发：

```bash
cargo build --release
./target/release/clawguard --help
```

## 首次运行与常用命令

- `clawguard`
  - 首次运行时：发现 OpenClaw，进入向导，保存配置，立即执行扫描并展示 findings
  - 已配置后：人类输出打开持久化 status 视图；`clawguard --json` 仍保持扫描兼容
- `clawguard scan`
  - 直接运行扫描流程
- `clawguard status`
  - 显示持久化状态视图（开放告警、快照摘要、基线信息）
  - `clawguard status --json` 输出 status JSON 合约
- `clawguard alerts`
  - 显示近期持久化告警，最新在前
- `clawguard alerts ignore <alert-id>`
  - 确认一条告警（标记为 acknowledged，不从历史中删除）
- `clawguard baseline approve`
  - 将当前文件哈希证据记录为批准基线
- `clawguard trust openclaw-config`
  - 恢复上次 `baseline approve` 时捕获的 `openclaw.json` 内容
- `clawguard trust exec-approvals`
  - 恢复上次 `baseline approve` 时捕获的 `exec-approvals.json` 内容
- `clawguard watch`
  - 启动前台 watch 循环，监听文件变化，推送通知
  - `--iterations 1` 可用于冷启动路径的 smoke test，不会留下长驻进程
- `clawguard --json` 或 `clawguard scan --json`
  - 输出机器可读的 findings JSON
- `clawguard --no-interactive` 或 `clawguard scan --no-interactive`
  - 首次运行时接受默认设置，不进行交互
- 如果没有发现受支持 runtime
  - 终端输出和 `--json` 都会返回同一条结构化 Info finding，而不是”空成功”

常见示例：

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

## 通知

ClawGuard 有两条独立的通知路径，可以同时运行。两者都在 `clawguard watch` 期间触发——手动 `scan` 不发送通知。

```
watch loop 每轮迭代
  ├── 内置通知（config.toml 的 alert_strategy）
  │   ├── Desktop → macOS osascript / Linux notify-send
  │   ├── Webhook → HTTP POST 到配置的 URL
  │   └── LogOnly → 仅终端输出
  │
  └── SSE 流（可选，config.toml 的 [sse] 段）
      └── 实时事件 → OpenClaw 插件 → Telegram / Discord / Slack
```

### 内置通知

首次运行向导将通知路由保存到 `~/.clawguard/config.toml`。直接编辑即可后续修改：

```toml
alert_strategy = "Desktop"
webhook_url = "https://hooks.example.com/clawguard"
```

- `Desktop` — 本地会话支持时使用桌面通知，不支持时回退到日志输出
- `Webhook` — 需要 `webhook_url`，以 `http://` 或 `https://` 开头
- `LogOnly` — 所有通知仅输出到前台 `watch` 终端

每日摘要在首次 `watch` 评估时开始计时。ClawGuard 在该次初始化游标，不回溯旧告警。

### SSE 服务器（实时流式推送）

内嵌 SSE 服务器在独立线程上将告警和摘要事件推送给外部消费者。

在 `~/.clawguard/config.toml` 中启用：

```toml
[sse]
port = 37776
bind = "127.0.0.1"
```

或通过 CLI：`clawguard watch --sse-port 37776`

Config 热更新：运行时修改 `port` 或 `bind` 会自动重启服务器。

| 端点 | 说明 |
|------|------|
| `GET /stream` | SSE 事件流（`event: alert`、`event: digest`、`event: heartbeat`） |
| `GET /health` | 健康检查：`{"ok":true}` |
| `GET /status` | 当前状态：客户端数量、模式 |
| `GET /alerts?limit=10` | 近期告警 JSON 列表 |

用 curl 测试：

```bash
clawguard watch --sse-port 37776        # 终端 1
curl -N http://127.0.0.1:37776/stream   # 终端 2
```

### 通过 OpenClaw gateway 插件推送消息

`openclaw-plugin/` 目录包含一个插件，消费 SSE 流并通过 OpenClaw channel 转发到 Telegram/Discord/Slack 等平台。

在 `openclaw.json` 中配置：

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

消息频道中可用的 slash 命令：

| 命令 | 说明 | 状态 |
|------|------|------|
| `/clawguard_feed` | 开关告警推送 | V1 |
| `/clawguard_status` | 查看当前安全状态 | V1 |
| `/clawguard_alerts` | 查看最近 10 条告警 | V1 |
| `/clawguard_ignore <id>` | 在聊天中确认告警 | V1.5 |
| `/clawguard_trust <target>` | 在聊天中恢复批准配置 | V1.5 |
| `/clawguard_scan` | 触发即时重新扫描 | V1.5 |
| `/clawguard_config <key> <value>` | 远程更新 ClawGuard 配置 | V1.5 |

V1 命令为只读。V1.5 将增加操作性命令，通过认证的本地 API（`POST /command`，Unix socket + token）执行。

告警消息样式：

```
🛡️ ClawGuard Alert [HIGH]
📁 ~/.openclaw/exec-approvals.json
⚠️ Allowlist entry permits curl — dangerous executable
💡 Remove this allowlist entry or restrict it
```

## 输出模型

ClawGuard 是 findings-first 的。

每一条 finding 都尽量携带：

- 严重度
- detector / category
- runtime confidence
- 证据路径与可选行号
- 面向人的 plain-English explanation
- 推荐动作

终端 UI 和 `--json` 都来自同一份底层结构化结果，而不是从 prose 反向解析。

## 当前范围与限制

- 当前是 V1，仍然是 OpenClaw-first，不是多 runtime 产品
- V1 包含基线批准、前台 watch 循环、通知推送、status/alerts/trust 操作面、tripwire 检测
- 手动 `scan` 保持 findings-first 且无副作用；通知属于 `watch`
- `trust` 命令范围严格受限，只恢复 `baseline approve` 时捕获的 payload
- Tripwire 为纯告警模式，不做实时命令拦截（blocking 推迟至 V1.5+）
- ClawGuard 不会静默修改 OpenClaw 本地状态
- bundled advisory feed 目前仍然是保守策略，直到正式生产级 feed 就绪
- advisory 匹配依赖可读的 OpenClaw 版本证据
  - 当前支持 colocated `package.json` 或受限 fallback 如 `packages/core/package.json`
- `dmPolicy=open` 的严重度目前仅按全局 `tools.exec.host` 推断
  - 尚不支持 per-agent exec host override 反向关联到 channel 级 DM 暴露
- V0 风格退出码
  - 即使存在 finding，scan 命令也可能返回 `0`
  - 自动化集成应优先读取 `--json` 输出

## 开发

```bash
cargo test
cargo build --release
```
