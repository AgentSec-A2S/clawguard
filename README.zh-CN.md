# ClawGuard

**当前版本: v1.2.0-beta.4**（V1.3 Sprint 1 MCP 供应链加固已于 2026-04-21 发布）

> [为什么需要](#为什么需要-clawguard) | [当前能力](#当前能力) | [检查项](#现在会检查什么) | [工作方式](#工作方式) | [系统要求](#系统要求) | [安装](#安装) | [使用](#首次运行与常用命令) | [通知](#通知) | [输出模型](#输出模型) | [范围与限制](#当前范围与限制) | [开发](#开发)

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
- Skill TOFU（信任首次使用）溯源追踪：
  - 从 `.git/config` 和 `.git/HEAD` 提取 git 远程 URL 和 HEAD SHA（无子进程，支持 worktree 和 submodule 的 `gitdir:` 间接引用）
  - 边界保护：`.git` 路径解析不会逃逸出扫描根目录
  - 3 种溯源 finding：`skill-no-provenance`（Info）、`skill-unapproved-change`（Medium）、`skill-remote-redirect`（High）
  - 溯源检查同时在 `clawguard scan` 和 `clawguard watch` 管道中运行
  - `baseline approve` 在记录文件哈希的同时保存 git 溯源信息用于后续漂移对比
- **V1.3 Sprint 1（2026-04-21 发布）** — MCP 供应链加固 + 字节优先工件完整性：
  - `mcp-no-lockfile`（Medium, ASI06）— MCP server 通过 npx/pnpm dlx/yarn dlx/bunx 等启动器运行，但没有任何 lockfile（package-lock.json / pnpm-lock.yaml / yarn.lock / bun.lockb / bun.lock）来锁定版本。覆盖完整 JS 启动器矩阵以及 `sh -c` / `bash -c` 隧道调用
  - `mcp-server-name-typosquat`（High, ASI06）— 配置中的 MCP server 名字，在 NFKC + 小写 + 分隔符剥离归一化后，与内置白名单 `data/mcp_server_allowlist.txt`（30+ 条规范名）的 Damerau–Levenshtein 距离 ≤1（归一化长度 5–7）或 ≤2（长度 ≥8）。归一化长度 <5 的短名豁免，保持规则高置信
  - `mcp-command-changed`（High, ASI06）— 针对解析后的每服务器 `{command, args, url, cwd}` 元组做基线漂移，通过合成工件 `mcp-command://<config>#<source>::<name>` 发出，使某个 server 切换启动器或 cwd 能独立告警，与普通 config 漂移解耦
  - `file-type-mismatch`（High, ASI06）— 在 `skill/` 和 hook 目录做字节优先签名扫：任何声称是文本扩展名（或扩展名缺失的 hook）但前 16 字节命中原生可执行头（ELF / PE-MZ / Mach-O MH_MAGIC · MH_MAGIC_64 · MH_CIGAM · MH_CIGAM_64 / fat-universal FAT_MAGIC · FAT_CIGAM）都会被标记。二进制扩展名白名单（`.node`、`.wasm`、`.so`、`.dylib`、`.dll`、`.exe`、`.bin`、`.o`、`.a`）短路豁免，并强制执行扫描边界内的 symlink 逃逸防护
- 通过 `clawguard posture` 进行权限姿态评分：
  - 33 种具体 finding 类型的加权求和（每种类型独立权重 1–5）+ 严重度回退
  - 评分区间：Clean → Low → Moderate → Elevated → Critical
  - 与上次快照的趋势方向对比（improved / degraded / stable）
  - posture score 持久化到 SQLite；`--json` 输出支持 CI / 监控平台集成
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
- 配置驱动的扫描目录扩展：读取 `openclaw.json` 的 `skills.load.extraDirs` 和 `hooks.internal.load.extraDirs`，自动将这些目录纳入扫描范围
- `OPENCLAW_AGENT_DIR` 环境变量支持：若设置，ClawGuard 将额外扫描该目录下的 bootstrap 文件（在默认 `~/.openclaw/agents` 之外）
- OpenClaw gateway 插件（`openclaw-plugin/`）：
  - 连接 ClawGuard SSE 流，自动重连（exponential backoff）
  - 将告警和每日摘要转发到 Telegram/Discord/Slack 等已配置的 channel
  - Slash 命令：`/clawguard_help`、`/clawguard_feed`、`/clawguard_status`、`/clawguard_alerts`

## 现在会检查什么

ClawGuard 故意把 detector catalog 控制得很小，只保留高信号项。

- `OpenClaw config audit`
  - 检查本地 runtime posture 是否明显危险
  - tripwire 检测：标记 allowlist 中预批准灾难性命令的条目
  - 审批漂移检测：`askFallback` 放松、危险可执行文件/解释器进 allowlist
- `Skills scan`
  - 检查技能目录里是否存在值得人工复核的危险行为
- `MCP scan`
  - 检查 MCP 启动链是否有高风险安装与目录暴露模式（包括 `busybox`、`toybox` 等多功能合并二进制文件）
- `Secrets and env scan`
  - 检查是否直接落地了敏感密钥和私钥材料
- `设备认证和插件路径审计`
  - 标记 `dangerouslyDisableDeviceAuth=true`（Critical）
  - 标记从 `/tmp` 等不安全路径安装的 plugin（Medium）
  - 标记本地文件系统路径安装的 plugin（Info）
- `Hook 和 Webhook 安全`
  - 标记 `hooks.allowRequestSessionKey=true` — 外部 session 劫持风险（High）
  - 标记 `hooks.mappings[].allowUnsafeExternalContent=true` — webhook 提示注入（High）
  - 标记 `hooks.gmail.allowUnsafeExternalContent=true` — 邮件提示注入（High）
  - 标记 `hooks.mappings[].transform.module` 指向工作区外路径（Medium）
- `执行和沙箱姿态`
  - 标记 `tools.exec.host=node` — 无沙箱宿主机执行，支持全局和单 agent 级别检测（Medium）
  - 标记 `agents.defaults.sandbox.mode=off` 或单 agent 沙箱关闭（Medium）
  - 标记 `channels.*.accounts.*.dmPolicy=open` 嵌套账号级别（Medium）
  - 标记 `channels.*.groupPolicy=open` 和 `channels.*.accounts.*.groupPolicy=open` — 来自群组的不受信任消息可达 exec 路径（Medium）
  - 标记 `exec-approvals.json` 缺失 — 上游默认值已从 `security=deny` 改为 `security=full`，缺失文件意味着无需批准即可完整执行宿主机命令（Medium, ASI02）
- `ACP 插件姿态`
  - 标记 `plugins.entries.acpx.config.permissionMode=approve-all` — 自动批准所有工具调用，包括 exec、spawn、shell 和文件写入（High）
  - 跳过已禁用的插件，避免残留配置产生误报
- `Gateway 节点命令策略`
  - 标记 `gateway.nodes.allowCommands` 中的危险命令 — 允许通过配对节点进行敏感设备访问（High）
  - 危险集合：`camera.snap`、`camera.clip`、`screen.record`、`contacts.add`、`calendar.add`、`reminders.add`、`sms.send`、`sms.search`
  - 尊重 `gateway.nodes.denyCommands` — 被显式拒绝的命令不会被标记
- `工具配置文件升级`
  - 标记 per-agent `tools.profile` 覆盖全局 `minimal` 配置文件 — 授予超出预期基线的额外工具访问权限（Medium）
- `沙箱绑定挂载安全`
  - 标记符号链接绑定挂载源 — TOCTOU 风险，验证后目标可被替换（Medium）
  - 标记临时目录绑定挂载源（`/tmp`、`/var/tmp`）— 任何本地用户均可写入（Medium）
  - 标记 `dangerouslyAllowReservedContainerTargets=true` — 允许绑定到 /workspace 或 /agent（High）
  - 标记 `dangerouslyAllowExternalBindSources=true` — 允许从白名单根目录外部绑定（High）
  - 同时检查 `docker.binds` 和 `browser.binds`，支持默认配置和 per-agent 配置
  - 按 agent 解析有效沙箱范围（包括 `perSession` 标志）以避免误报
- `插件白名单/黑名单配置漂移`
  - 标记不在 `plugins.allow` 中的插件条目（当白名单已配置时）— 配置策略冲突（Medium）
  - 标记同时存在于 `plugins.deny` 中的插件条目 — 配置矛盾（Medium）
  - 跳过禁用的插件（`enabled: false`）和整个插件系统禁用的情况
  - 定性为配置漂移检测，而非活跃插件暴露 — 运行时优先级决定实际状态
- `OWASP ASI Top 10 映射`
  - 每个 finding 携带可选 `owasp_asi` 字段，映射到 OWASP Agentic Security Initiative Top 10 分类（ASI02–ASI10）
  - 在 `--json` 输出中渲染，支持合规和报告工作流
- `Hook 处理程序扫描`
  - 扫描托管 hooks（`~/.openclaw/hooks/`）和 `hooks.internal.load.extraDirs` 目录
  - 按上游加载顺序查找 handler：`handler.ts` → `handler.js` → `index.ts` → `index.js`
  - 哈希 `HOOK.md` 元数据用于基线漂移检测
  - 检测 shell 执行：`child_process`、`exec(`、`spawn(`、`execFile(`、`import("child_process")`、`process.binding()`（High）
  - 检测网络外泄：`fetch(`、`http.request`、`WebSocket`、`net.connect`、`dns.resolve`、`XMLHttpRequest`、`EventSource`（High）
  - 检测身份文件篡改：写入 SOUL.md、MEMORY.md、AGENTS.md、TOOLS.md、USER.md（Medium）
  - 检测配置篡改：写入 openclaw.json、exec-approvals.json（High）
  - 正确的块注释跟踪（多行 `/* ... */`）防止检测绕过
- `Bootstrap 文件完整性`
  - 扫描所有 agent 工作区（`~/.openclaw/agents/*/agent/`）中的 9 个 bootstrap 文件
  - 文件：AGENTS.md、SOUL.md、TOOLS.md、IDENTITY.md、USER.md、HEARTBEAT.md、BOOTSTRAP.md、MEMORY.md、memory.md
  - 检测编码载荷：base64 字符串 ≥100 字符，支持标准和 URL-safe 编码（High）
  - 检测 shell 注入：`$(...)` 命令替换、`${}` 变量展开（含 shell 上下文）、反引号替换（High）
  - 检测提示注入标记："ignore previous instructions"、"system override"、"forget everything" 等（Critical）
  - 检测混淆内容：每行 ≥10 个 hex（`\x`）或 unicode（`\u`）转义序列（Medium）
  - 工作区发现不会被父目录中的诱饵文件抑制
- `Skill TOFU 溯源`
  - 信任首次使用模型：首次 `baseline approve` 捕获 skill 文件哈希 + git 远程 URL + HEAD SHA 作为可信状态
  - 无基线的 skill：`skill-no-provenance`（Info, ASI06）— 仅提醒，用户批准前无需操作
  - skill 哈希变化但未 `baseline approve`：`skill-unapproved-change`（Medium, ASI06）— 可能的未授权修改
  - skill git 远程 URL 与批准基线不同：`skill-remote-redirect`（High, ASI06）— 供应链重定向，skill 来源切换到不同仓库
  - 溯源检查在 `clawguard scan` 和 `clawguard watch` 管道中自动运行
  - 不依赖子进程提取 git 元数据（直接解析 `.git/config` 和 `.git/HEAD`）
  - 支持 git worktree 和 submodule（通过 `.git` 文件 `gitdir:` 间接引用），并强制扫描边界检查
- `Advisory matching`
  - 当能读到版本证据时，将本地版本与 advisory feed 做离线匹配
- `Baseline approval`
  - 将当前文件哈希证据记录为批准基线，用于漂移检测
- `审计日志`
  - 被动采集 OpenClaw 的 `config-audit.jsonl`（配置写入事件，解析真实 ISO-8601 时间戳）
  - 基于文件级 SHA-256 哈希检测 skill 目录变更（捕获原地编辑）
  - 检测插件目录变更（安装/卸载事件）
  - 跨 agent 工作区的 bootstrap 文件变更追踪（SOUL.md、MEMORY.md、AGENTS.md 等的 SHA-256 快照对比）
  - 日志轮转安全：检测文件缩小并自动重置游标
  - `clawguard audit [--category X] [--since 1h] [--limit N] [--json]`
- `安全统计`
  - 聚合扫描历史、finding 趋势、告警处理率、基线数量和审计事件分类统计
  - 支持 `--since` 时间窗口过滤（1h、7d、30d）和 `--json` 机器可读输出
  - `clawguard stats [--since 7d] [--json]`
- `权限姿态评分`
  - 33 种具体 finding 类型各有独立权重（1–5），未映射类型按严重度回退（Critical=5、High=3、Medium=2、Low=1、Info=0）
  - 评分区间：Clean（0）、Low（1–10）、Moderate（11–25）、Elevated（26–50）、Critical（51+）
  - 与上次快照评分的趋势对比（improved / degraded / stable）
  - 每次快照的 posture score 持久化到 SQLite，支持历史趋势
  - `clawguard posture [--json]`
- `Watch loop`
  - 监听关键文件和 skill 目录，变更时重新扫描、记录快照、追加漂移告警、推送通知
  - 每次扫描周期后运行被动审计采集，持续捕获事件

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

## 系统要求

| 要求 | 详情 |
|------|------|
| **操作系统** | macOS（Intel / Apple Silicon）、Linux（x86_64 / ARM64） |
| **OpenClaw** | 建议 v2026.2.2 或更高版本，已在 v2026.3.x 上验证 |
| **运行时依赖** | 无外部依赖——单个静态二进制文件 |
| **源码构建** | Rust 1.75+ 和 Cargo |

ClawGuard 自动检测并扫描 OpenClaw 安装。其他 agent runtime（Claude Code、Codex）通过预设支持，但 OpenClaw 是主要目标。

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
- `clawguard notify`
  - 查看当前通知配置（策略、webhook、Telegram、SSE）
  - `clawguard notify --json` 输出通知配置 JSON
- `clawguard notify desktop`
  - 切换为桌面通知
- `clawguard notify webhook <url>`
  - 切换为 webhook 通知，自动验证 URL 格式
- `clawguard notify telegram [chat-id]`
  - 启用 SSE 服务器，配置通过 OpenClaw 插件的 Telegram 告警
  - 省略 chat-id 时自动从 OpenClaw 的 `channels.telegram` 配置中检测（`defaultTo`、`groups`、`direct`、`allowFrom`）
  - 检测到多个 ID 时显示编号列表供用户选择
  - 只检测到一个 ID 时自动选用
  - 无 OpenClaw 配置时回退到之前保存的值
  - 输出可直接粘贴到 `openclaw.json` 的插件配置片段
  - `--apply` 自动将插件配置写入 `openclaw.json`（写入前自动创建备份）
- `clawguard notify off`
  - 关闭所有通知（仅日志输出），并关闭 ClawGuard 自己的本地 SSE 配置
  - 不会停止运行在当前 ClawGuard 进程之外的外部 / plugin 托管 SSE 服务
- `clawguard watch`
  - 启动前台 watch 循环，持续监控检测到的 OpenClaw 运行时
  - **冷启动**：首次运行时执行完整扫描 — 发现运行时、运行所有检测器、基线漂移比对、快照 + findings 持久化到 SQLite
  - **事件循环**：使用 OS 文件系统通知（macOS/Linux 上的 `notify` crate）检测受监控文件变更；变更后重新扫描，2 秒防抖
  - **每次扫描周期**：重新发现运行时 → 运行所有检测器 → 与批准基线比对 → 持久化快照 → 为新漂移 findings 创建告警（对已有未解决告警去重）→ 从 OpenClaw 日志采集审计事件
  - **通知**：每次迭代后通过配置的路由（桌面/webhook/telegram）投递待处理告警，评估是否需要发送每日摘要
  - **SSE 广播**：使用 `--sse-port` 启动 SSE 服务器，向连接的客户端（如 OpenClaw gateway 插件）实时推送告警事件
  - `--iterations N` 运行 N 次后停止（0 = 一直运行，默认）
  - `--poll-interval-ms N` 设置迭代间隔（默认 1000ms）
  - `--sse-port N` 启用 SSE 服务器（0 = 禁用，默认）
  - `--iterations 1` 可用于冷启动路径的 smoke test，不会留下长驻进程
- `clawguard audit`
  - 查看近期审计事件（配置变更、skill/plugin 安装/卸载）
  - `--category config|hook|plugin|tool|skill` 按类别筛选
  - `--since 1h|24h|7d` 按时间范围筛选
  - `--limit N` 限制输出条数（默认 50）
  - `--json` 输出机器可读的顶层 JSON 数组（空结果时为 `[]`）
- `clawguard stats`
  - 显示聚合扫描与安全统计数据
  - `--since 1h|7d|30d` 按时间窗口过滤统计数据
  - `--json` 输出包含趋势数据的机器可读 JSON
- `clawguard posture`
  - 基于当前扫描 findings 计算加权权限暴露面评分
  - 评分区间：Clean（0）、Low（1–10）、Moderate（11–25）、Elevated（26–50）、Critical（51+）
  - 展示按 finding 类型分组的明细表（类型 × 数量 × 权重 = 小计）及与上次快照的趋势对比
  - `clawguard posture --json` 输出含评分、区间、明细数组和趋势的机器可读 JSON
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
clawguard notify
clawguard notify telegram                          # 自动检测 chat ID
clawguard notify telegram 123456789                # 手动指定 chat ID
clawguard notify telegram 123456789 --apply        # 自动写入 openclaw.json
clawguard notify webhook https://hooks.example.com/clawguard
clawguard notify off
clawguard watch --iterations 1
clawguard scan --json
clawguard status --json
clawguard posture
clawguard posture --json
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

内嵌、由 ClawGuard 自己拥有的 SSE 服务器会在独立线程上将告警和摘要事件推送给外部消费者。
如果配置的端口已被其他进程占用，`clawguard watch` 会继续运行，并报告一个“本地 SSE 退化”的 warning，而不会直接退出。
这个 SSE 服务器只属于当前的 `clawguard watch` 进程；外部或 plugin 托管的 SSE 基础设施是独立存在的。

在 `~/.clawguard/config.toml` 中启用：

```toml
[sse]
port = 37776
bind = "127.0.0.1"   # Docker 或远程访问时使用 "0.0.0.0"
```

在 Docker 容器中，ClawGuard 会自动检测 `/.dockerenv` 并建议使用 `host.docker.internal` 连接插件。

或通过 CLI：`clawguard watch --sse-port 37776`

Config 热更新：运行时修改 `port` 或 `bind` 会自动重启服务器。

| 端点 | 说明 |
|------|------|
| `GET /stream` | SSE 事件流（`event: alert`、`event: digest`、`event: heartbeat`） |
| `GET /health` | 健康检查：`{"ok":true}` |
| `GET /status` | 当前状态：客户端数量、模式 |
| `GET /alerts?limit=10` | 近期 `open` 告警 JSON 列表（默认视图） |
| `GET /alerts?status=all&limit=10` | 含 `open` / `acknowledged` / `resolved` 的近期告警历史 |

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
| `/clawguard_help` | 显示所有命令和使用指南 | V1 |
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
