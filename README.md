# Ovogo — 自主红队协调引擎

<div align="center">

**AI 驱动的渗透测试自主协调 Agent | Think-Act-Observe 引擎 | 多 Agent 编排 | 跨轮次记忆**

[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue.svg)](https://www.typescriptlang.org/)
[![OpenAI](https://img.shields.io/badge/OpenAI-Compatible-green.svg)](https://platform.openai.com/)
[![Claude](https://img.shields.io/badge/Claude-Supported-purple.svg)](https://www.anthropic.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> 用一句话启动: `ovogo "对 target.com 进行渗透测试"`

</div>

---

## 目录

- [项目简介](#项目简介)
- [核心架构](#核心架构)
  - [执行引擎](#执行引擎-think-act-observe)
  - [协调器模式](#协调器模式-coordinator)
  - [子 Agent 系统](#子-agent-系统)
  - [数据流](#数据流)
- [工具系统](#工具系统-20-tools)
- [记忆与上下文管理](#记忆与上下文管理)
- [安全基础设施](#安全基础设施)
- [高级功能](#高级功能)
- [快速开始](#快速开始)
- [项目结构](#项目结构)
- [设计决策](#设计决策)
- [技术栈](#技术栈)
- [安全声明](#安全声明)

---

## 项目简介

Ovogo 是一个**自主红队协调引擎**——它不是一堆散装的扫描脚本，而是一个具备完整推理能力的 AI Agent，能够：

1. **理解目标** — 接收渗透测试目标（URL / IP / 域名）
2. **制定计划** — 基于 MITRE ATT&CK 框架自动生成攻击链
3. **并行分发** — 同时派遣多个专业子 Agent 执行侦察、扫描、利用
4. **监控进度** — 定时读取子 Agent 输出，评估进展，调整策略
5. **联动利用** — 将一个 Agent 的发现传递给另一个 Agent 利用
6. **收集 Flag** — 自动搜索、提取目标 Flag
7. **生成报告** — 汇总所有发现，形成完整攻击链记录

**与传统红队框架的本质区别：**
- 传统框架 = 脚本编排（if-then 流程固定）
- Ovogo = AI 自主决策（LLM 每轮推理，动态调整策略）

---

## 核心架构

### 执行引擎：Think-Act-Observe

```
┌──────────────────────────────────────────────────────────────────┐
│                     RunTurn() 主循环                              │
│                                                                  │
│  ┌───────────┐    ┌──────────┐    ┌───────────┐    ┌──────────┐ │
│  │ Context   │ -> │ Streaming │ -> │  Tool     │ -> │ Loop /   │ │
│  │ Budget +  │    │ LLM Call  │    │ Batch     │    │ Return   │ │
│  │ Compact   │    │ (Think)   │    │ (Act/Obs) │    │          │ │
│  └───────────┘    └──────────┘    └───────────┘    └──────────┘ │
│       ↑                                                         │
│       │ 每 5 轮                                                  │
│  ┌────┴──────────┐                                             │
│  │ Critic 检查    │  15 项自动纠错清单                           │
│  └───────────────┘                                             │
│                                                                  │
│  并行调度: Promise.all (安全工具)  + 串行 (写操作)                │
│  软中断: ESC 暂停 → 用户介入 → 继续                              │
│  硬中断: Ctrl+C 取消                                              │
└──────────────────────────────────────────────────────────────────┘
```

每次 `runTurn()` 循环：
1. **上下文预算评估** — 检查 token 使用量，决定是否需要压缩
2. **自动压缩** — 超过 75% 时调用 LLM 摘要旧消息，保留最近 8 条原始消息
3. **Critic 注入** — 每 5 轮用 LLM 审查最近 24 条消息，发现失误立即纠正
4. **流式 API 调用** — 接收 LLM 的文本思考（Think）+ 工具调用（Act）
5. **工具批调度** — 读工具并行执行（Promise.all），写工具串行执行
6. **结果注入** — 工具结果作为 user 消息注入下一轮

### 协调器模式（Coordinator）

主 Agent 是**将军**，不是**士兵**。核心设计决策：

| 能力 | 主 Agent | 子 Agent |
|------|----------|----------|
| 扫描工具（nmap/nuclei） | 禁止 | 可用 |
| 利用工具（sqlmap/exploit） | 禁止 | 可用 |
| 交互工具（msfconsole/REPL） | 禁止 | 可用 |
| 读写文件 | 禁止 | 可用 |
| Bash 命令 | 只读白名单 | 全部 |
| 委派子 Agent | 可用 | 可用 |
| 读取结果 | 可用 | 可用 |
| WeaponRadar | 可用 | 可用 |

**白名单命令**：tail/head/cat/grep/ps/ls/stat/find/sort/uniq/diff/awk/sed -n/ss/netstat

**黑名单命令**：nmap/masscan/nuclei/ffuf/sqlmap/hydra/msfconsole/sliver/chisel/curl -o/wget/rm -rf/eval/pipe to shell

### 子 Agent 系统

25+ 种专业 Agent 类型，覆盖完整攻击链：

```
Phase 1 — 侦察 + 漏洞探测 (并行)
├── recon          侦察总管 (内部: dns-recon / port-scan / web-probe / osint)
└── vuln-scan      漏洞探测总管 (内部: web-vuln / service-vuln / auth-attack)

Phase 2 — 漏洞检索
└── weapon-match   POC 库语义检索 (22W Nuclei PoC, BGE-M3 向量搜索)

Phase 3 — 漏洞利用 + C2 (并行)
├── manual-exploit 手工利用 (curl/python 精准打击)
├── tool-exploit   工具利用 (MSF/sqlmap/searchsploit)
└── c2-deploy      C2 部署 (Metasploit/Sliver 监听 + payload)

Phase 4 — 靶机操作
├── target-recon   靶机信息收集 (本机 + 内网)
└── privesc        权限提升 (SUID/sudo/内核/计划任务)

Phase 5 — 内网横移
├── tunnel         内网穿透 (chisel socks5 代理)
├── internal-recon 内网资产发现 (proxychains + nmap)
└── lateral        横向移动 (MS17-010/PTH/凭证复用)

Phase 6 — Flag 收集
└── flag-hunter    全局 Flag 搜索收集

Phase 7 — 报告
└── report         渗透测试报告生成
```

每个子 Agent：
- 独立的 Engine 实例（隔离上下文）
- 专用系统 Prompt（红队角色设定 + 工具指引）
- 独立 tmux 面板输出（4 面板布局实时监控）
- 动态迭代次数（扫描型 Agent 自动 +100 轮缓冲）
- 后台任务 + 文件轮询（子 Agent 快速返回，扫描后台持续运行）

### 数据流

```
用户: "对 zhhovo.top 进行渗透测试"
  │
  ▼
┌─────────────────────────────────────────┐
│  主 Agent (Coordinator)                 │
│  ┌───────────────────────────────────┐  │
│  │ 分析目标 → 制定 Phase 1-7 计划    │  │
│  │ MultiAgent([recon, vuln-scan])   │  │
│  └───────────┬───────────────────────┘  │
│              │ 并行分发                  │
└──────────────┼──────────────────────────┘
               │
    ┌──────────┼──────────┐
    ▼          ▼          ▼
┌────────┐ ┌────────┐ ┌────────────┐
│ recon  │ │vuln-   │ │  session   │
│ agent  │ │scan    │ │  output    │
│        │ │agent   │ │  files     │
│ DNS    │ │nuclei  │ │ nmap.txt   │
│ nmap   │ │nikto   │ │ nuclei.txt │
│ httpx  │ │hydra   │ │ ffuf.json  │
└───┬────┘ └───┬────┘ └─────┬──────┘
    │          │            │
    ▼          ▼            ▼
┌─────────────────────────────────────────┐
│  主 Agent 读取结果 → 发现漏洞            │
│  Agent(weapon-match) → 匹配 POC        │
│  MultiAgent([manual, tool, c2]) → 利用 │
│  ... 循环直到 Flag 收集完成              │
└─────────────────────────────────────────┘
```

---

## 工具系统（20 Tools）

所有工具统一 `Tool` 接口：`execute(input, context) → Promise<ToolResult>`

### 执行类

| 工具 | 职责 | 关键特性 |
|------|------|----------|
| **Bash** | Shell 命令执行 | 进程组 kill（SIGTERM→SIGKILL）、后台模式（自动日志）、follow 模式（tmux 观战面板） |
| **ShellSession** | 持久反弹 Shell 管理 | listen/exec/kill，管理入站 TCP 连接 |
| **TmuxSession** | 本地交互进程管理 | new/send/capture/wait_for，管理 msfconsole/sqlmap/REPL |

### 文件类

| 工具 | 职责 |
|------|------|
| **Read** | 读取文件内容 |
| **Write** | 创建/写入文件 |
| **Edit** | 精确字符串替换 |
| **Glob** | glob 模式文件查找 |
| **Grep** | 正则内容搜索 |

### 情报类

| 工具 | 职责 |
|------|------|
| **WeaponRadar** | 22W Nuclei PoC 向量数据库语义检索（BGE-M3） |
| **WebSearch** | 网络搜索 |
| **WebFetch** | URL 内容获取 |
| **DocRead** | 文档读取解析 |

### 编排类

| 工具 | 职责 |
|------|------|
| **Agent** | 启动单个子 Agent |
| **MultiAgent** | 批量并发启动多个子 Agent |
| **DispatchAgent** | 异步分发任务（不阻塞当前推理） |
| **CheckDispatch** | 查询异步任务状态 |
| **GetDispatchResult** | 获取异步任务结果 |

### 管理类

| 工具 | 职责 |
|------|------|
| **FindingWrite** | 记录漏洞发现（持久到 `.ovogo/findings/`） |
| **FindingList** | 列出所有漏洞发现 |
| **TodoWrite** | 任务清单管理 |
| **C2** | C2 基础设施操作（Metasploit/Sliver） |

### 调度策略

- **并行批**：Read/Glob/Grep/WebFetch/WebSearch/Bash/Agent/MultiAgent/DispatchAgent/CheckDispatch/C2/ShellSession/TmuxSession — Promise.all 并发
- **串行批**：Write/Edit/FindingWrite — 顺序执行，避免竞态

---

## 记忆与上下文管理

### 三层记忆系统

```
┌────────────────────────────────────────────────────────┐
│  文件记忆 (MEMORY.md)                                   │
│  用户偏好 / 项目约定 / 反馈记录                          │
│  存储: ~/.ovogo/projects/{slug}/memory/                │
│  用途: 跨 session 的用户协作偏好                         │
├────────────────────────────────────────────────────────┤
│  语义记忆 (Semantic Memory)                              │
│  渗透知识持久化: CVE 利用结果 / 内网拓扑 / 凭证           │
│  存储: ~/.ovogo/projects/{slug}/memory/semantic.jsonl  │
│  检索: 标签 + 关键词，按置信度排序                        │
├────────────────────────────────────────────────────────┤
│  情景记忆 (Episodic Memory)                              │
│  行动轨迹: "我做了什么、成功/失败、花了多久"             │
│  存储: ~/.ovogo/projects/{slug}/memory/episodes.jsonl  │
│  用途: Critic 检查 / 上下文压缩时注入                    │
└────────────────────────────────────────────────────────┘
```

### 上下文预算管理

替代扁平的 "70% 警告 / 85% 压缩" 阈值，采用显式预算分配：

```
Max Tokens: 200,000
├── System Prompt:  5,000    (固定)
├── Memory:         8,000    (动态: 最近记忆)
├── History:       80,000    (可变: 最近消息)
├── Tool Results:  60,000    (可变: 最近工具结果)
└── Reserved:       8,192    (预留给 LLM 输出)
```

三种压缩策略：
- **proportional** (< 75%) — 按比例裁剪
- **priority** (75% - 90%) — 优先级裁剪：system > 最近历史 > 记忆 > 工具结果 > 旧历史
- **aggressive** (> 90%) — 仅保留 system + 最近 2 条消息

### Critic 自动纠错

每 5 轮执行一次 LLM 审查，15 项检查清单：
1. PoC 未执行
2. 工具未降级处理
3. 重要发现被遗忘
4. 任务偏离
5. 重复劳动
6. 交互式进程阻塞
7. 防御者思维（红队不应输出修复建议）
8. 提前终止扫描
9. 满足于信息泄露
10. poc_code 当 nuclei 模板
11. 绕过 MultiAgent 直接扫描
12. 发现漏洞不利用
13. 没有找 Flag
14. 主动杀掉后台扫描
15. 主 Agent 亲自执行

---

## 安全基础设施

### ShellSession — 反弹 Shell 持久管理

```
目标机 ──TCP──> 攻击机 (ShellSession listen)
                       │
                  exec("id")     → 执行命令
                  exec("cat /flag") → 读取 Flag
                  kill()         → 关闭连接
```

管理入站 TCP 连接，支持多 Shell 并发，命令执行超时控制。

### TmuxSession — 本地交互进程管理

```
msfconsole / sqlmap --wizard / Python REPL
       │
  TmuxSession:
  ├── new()     → 创建 tmux 会话启动进程
  ├── send()    → 发送按键
  ├── capture() → 捕获输出
  ├── wait_for()→ 等待特定模式出现
  ├── list()    → 列出会话
  └── kill()    → 终止会话
```

解决交互式工具直接 Bash 调用超时问题。

### C2 集成

- **Metasploit**：msfrpcd API 交互，listener 部署、payload 生成、session 管理
- **Sliver**：CLI 封装，implant 生成、beacon 交互
- **持久化**：C2 状态持久化（JSON），重启后恢复

---

## 高级功能

### Event Log — 不可变事件流

每 session 一个 `events.ndjson` 文件，记录完整审计轨迹：

```json
{"id":"evt_1713340000_1","timestamp":"2026-04-17T10:00:00Z","type":"tool_call","source":"Bash","detail":{"input":{"command":"nmap -sS target"}},"tags":["Bash"]}
{"id":"evt_1713340001_2","timestamp":"2026-04-17T10:00:01Z","type":"tool_result","source":"Bash","detail":{"content":"Starting Nmap...","isError":false},"tags":["Bash","success"]}
```

事件类型：`tool_call` / `tool_result` / `agent_spawn` / `agent_complete` / `dispatch_start` / `dispatch_complete` / `memory_write` / `memory_read` / `context_compact` / `critic_flag` / `user_input` / `user_interrupt`

### Dispatch — 异步 Agent 通信

```
主 Agent: DispatchAgent(agent_type="recon", prompt="扫描 target")
  → 立即返回 dispatch_id: disp_1713340000_1
  → 后台启动 recon agent
  → 完成后自动回调

主 Agent 继续推理 → CheckDispatch(disp_1713340000_1) → running
... 继续其他工作 ...
→ GetDispatchResult(disp_1713340000_1) → 完成结果
```

### Skill System — 阶段动态工具加载

按渗透阶段动态加载/卸载工具组：

```
Phase: recon      → recon skill (Bash + WebSearch + WebFetch + 文件操作)
Phase: vuln-scan  → vuln-scan skill (Bash + WeaponRadar + Finding + 文件操作)
Phase: exploit    → exploit skill (Bash + Shell + Tmux + C2 + 文件操作)
Phase: post-exp   → post-exploit skill (Bash + Shell + Tmux + 文件操作)
```

### Hook System — 工具调用钩子

```
PreToolCall  → 工具调用前触发 (env: OVOGO_TOOL_NAME, OVOGO_TOOL_INPUT)
PostToolCall → 工具调用后触发 (env: OVOGO_TOOL_NAME, OVOGO_TOOL_RESULT)
UserPromptSubmit → 用户输入提交前触发
```

配置：`.ovogo/settings.json` 中的 `hooks` 字段，支持多钩子。

### MCP 支持

Model Context Protocol 集成，可接入外部 MCP Server 扩展工具能力。

### ProgressTracker — 长任务进度追踪

Bash/MultiScan/WeaponRadar 等长任务的进度管理：start → update(%) → pause → resume → complete / fail。

### ToolCache — 工具结果缓存

SHA256 键值缓存，默认 24h TTL。跳过 WebFetch/WebSearch/WeaponRadar 等耗时查询的重复执行。

### Agent Worker — 独立子进程

`bin/agent-worker.ts` 独立进程，通过文件系统与主进程通信：
- 输入：context JSON 文件
- 输出：done JSON 文件 + session 目录文件
- 结构化提取：端口 / Web 服务 / 子域名 / IP / 漏洞

---

## 快速开始

### 一键安装

**Windows:**
```cmd
setup.bat
```

**macOS / Linux:**
```bash
chmod +x setup.sh && ./setup.sh
```

### 手动安装

```bash
git clone https://github.com/atreasureboy/ovogo.git
cd ovogo
npm install
npm run build
```

### 配置

```bash
# 设置 API 密钥 (必需)
export OPENAI_API_KEY=sk-xxx          # Linux/macOS
set OPENAI_API_KEY=sk-xxx             # Windows CMD
$env:OPENAI_API_KEY="sk-xxx"          # Windows PowerShell

# 可选配置
export OPENAI_BASE_URL=https://api.example.com  # 兼容端点
export OVOGO_MODEL=gpt-4o                       # 模型
export OVOGO_MAX_ITER=200                       # 最大轮数
export OVOGO_CWD=/path/to/project                # 工作目录
```

### 使用

```bash
# 交互模式 (REPL)
ovogo

# 直接任务
ovogo "对 zhhovo.top 进行渗透测试"

# 管道输入
echo "分析当前项目安全" | ovogo

# Plan 模式 (只读分析)
ovogo "/plan 分析目标 zhhovo.top 的攻击面"

# 参数控制
ovogo -m claude-sonnet-4-x --max-iter 300 --cwd /target/dir
```

### REPL 命令

| 命令 | 功能 |
|------|------|
| `/plan <task>` | Plan 模式运行（只读分析 + 确认执行） |
| `/skills` | 列出可用 skills |
| `/clear` | 清空对话历史 |
| `/history` | 显示消息数 |
| `/model` | 显示当前模型 |
| `/help` | 显示帮助 |
| `/exit` | 退出 |

交互控制：
- **ESC** — 暂停当前操作，注入用户建议
- **Ctrl+C** — 强制取消
- **Ctrl+D** — 退出

---

## 项目结构

```
ovogo/
├── bin/
│   ├── ovogogogo.ts          # 主入口 (REPL + Task + Plan 模式)
│   └── agent-worker.ts       # 子 Agent 独立进程
│
├── src/
│   ├── core/                 # 核心引擎
│   │   ├── engine.ts         # Think-Act-Observe 执行引擎 (流式 + 并行调度 + Critic)
│   │   ├── types.ts          # 核心类型定义
│   │   ├── compact.ts        # 上下文压缩 (LLM 摘要 + 百分比阈值)
│   │   ├── contextBudget.ts  # 上下文预算管理 (显式 token 分配)
│   │   ├── eventLog.ts       # 不可变事件流 (NDJSON 审计轨迹)
│   │   ├── dispatch.ts       # 异步 Agent 分发管理器
│   │   ├── semanticMemory.ts # 语义记忆 (跨 session 渗透知识)
│   │   ├── episodicMemory.ts # 情景记忆 (行动轨迹记录)
│   │   ├── skillRegistry.ts  # 技能注册表 (阶段动态加载)
│   │   ├── progressTracker.ts# 长任务进度追踪
│   │   ├── toolCache.ts      # 工具结果缓存 (SHA256 + TTL)
│   │   ├── priorityQueue.ts  # 优先级队列
│   │   ├── shell.ts          # Shell 抽象
│   │   └── graph/            # LangGraph 状态图 (遗留兼容)
│   │       ├── builder.ts
│   │       ├── types.ts
│   │       └── nodes/
│   │
│   ├── tools/                # 通用工具 (20 tools)
│   │   ├── agent.ts          # 子 Agent 派发 + Dispatch 工具
│   │   ├── multiAgent.ts     # 批量并发子 Agent
│   │   ├── bash.ts           # Shell 命令执行 (进程组 kill)
│   │   ├── shellSession.ts   # 反弹 Shell 持久管理
│   │   ├── tmuxSession.ts    # 本地交互进程管理
│   │   ├── weaponRadar.ts    # 22W PoC 向量数据库检索
│   │   ├── c2.ts             # C2 基础设施 (MSF/Sliver)
│   │   ├── finding.ts        # 漏洞档案管理
│   │   ├── multiScan.ts      # 批量并发扫描
│   │   ├── fileRead.ts       # 文件读取
│   │   ├── fileWrite.ts      # 文件写入
│   │   ├── fileEdit.ts       # 文件编辑
│   │   ├── glob.ts           # 文件查找
│   │   ├── grep.ts           # 内容搜索
│   │   ├── todo.ts           # 任务清单
│   │   ├── webFetch.ts       # URL 内容获取
│   │   ├── webSearch.ts      # 网络搜索
│   │   ├── docRead.ts        # 文档读取
│   │   └── index.ts          # 工具注册
│   │
│   ├── skills/               # 阶段技能模块
│   │   ├── recon.ts          # 侦察阶段工具
│   │   ├── vuln-scan.ts      # 漏洞扫描阶段工具
│   │   ├── exploit.ts        # 漏洞利用阶段工具
│   │   ├── post-exploit.ts   # 后渗透阶段工具
│   │   └── loader.ts         # 技能加载器
│   │
│   ├── prompts/              # Prompt 工程
│   │   ├── system.ts         # 系统 Prompt 组装 (12 sections)
│   │   ├── agentPrompts.ts   # 25+ Agent 类型专用 Prompt
│   │   └── tools.ts          # 工具描述 Prompt
│   │
│   ├── config/               # 配置系统
│   │   ├── settings.ts       # 设置加载 (项目级 + 用户级)
│   │   ├── hooks.ts          # Hook 执行器
│   │   └── ovogomd.ts        # OVOGO.md 指令加载
│   │
│   ├── memory/               # 文件记忆系统
│   │   └── index.ts          # MEMORY.md 索引 + 加载
│   │
│   ├── ui/                   # 终端 UI
│   │   ├── renderer.ts       # 终端渲染器 (文件回溯 + spinner)
│   │   ├── input.ts          # 输入处理 (ESC + Ctrl+C + Ctrl+D)
│   │   └── tmuxLayout.ts     # tmux 4 面板布局管理
│   │
│   ├── services/mcp/         # MCP 服务
│   │   ├── client.ts         # MCP 客户端
│   │   ├── loader.ts         # MCP 服务器加载
│   │   ├── mcpTool.ts        # MCP 工具适配
│   │   └── types.ts          # MCP 类型
│   │
│   ├── recon/                # 侦察 Agent 模块
│   ├── vuln-scan/            # 漏洞扫描 Agent 模块
│   ├── exploit/              # 漏洞利用 Agent 模块
│   ├── post-exploit/         # 后渗透 Agent 模块
│   ├── privesc/              # 提权 Agent 模块
│   ├── lateral/              # 横向移动 Agent 模块
│   ├── c2/                   # C2 Agent 模块
│   └── report/               # 报告 Agent 模块
│
├── sessions/                 # 运行时 session 输出 (git 忽略)
├── .ovogo/                   # 项目配置 + skills + findings
├── setup.bat                 # Windows 一键安装脚本
├── setup.sh                  # macOS/Linux 一键安装脚本
├── package.json
├── tsconfig.json
└── .gitignore
```

---

## 设计决策

### 为什么是协调器架构？

渗透测试是**长链路、多工具、长耗时**的任务。单一 Agent 直接执行所有工具会导致：
1. **上下文窗口爆炸** — 每个工具的结果都占 token
2. **专注力下降** — Agent 推理能力随上下文增大而衰减
3. **无法并行** — 串行执行浪费时间

**协调器方案**：主 Agent 只做决策和读结果，具体执行交给专业子 Agent，每个子 Agent 有隔离的上下文窗口。

### 为什么不固化流程？

传统红队框架（AutoRecon/Peirates/CrackMapExec）是 if-then 脚本，遇到非标准环境就挂。Ovogo 用 LLM 每轮推理动态决策：
- 发现新服务 → 立即匹配 POC
- 扫描超时 → 调整策略
- 工具缺失 → 安装或换方法
- 遇到防御 → 换攻击路径

### 为什么保留 LangGraph？

LangGraph 模块（`src/core/graph/`）是项目的初始架构实现，当前主执行路径使用自主实现的 Think-Act-Observe 引擎（`src/core/engine.ts`）。LangGraph 代码保留用于兼容和参考。

### 工具缓存策略

**不缓存**：Bash/ShellSession/TmuxSession/C2/Write/Edit/FindingWrite/Read/Glob/Grep — 这些要么有副作用，要么环境实时变化。
**缓存**：WebFetch/WebSearch/WeaponRadar — 网络请求和语义检索耗时高，结果相对稳定。

---

## 技术栈

| 类别 | 技术 |
|------|------|
| **语言** | TypeScript 5.7 (ES2022, NodeNext 模块) |
| **LLM** | OpenAI 兼容 API (Claude / GPT / 任意兼容端点) |
| **AI 框架** | OpenAI SDK, LangChain Core, LangGraph |
| **MCP** | @modelcontextprotocol/sdk |
| **工具集成** | nmap, nuclei, sqlmap, hydra, metasploit, sliver, chisel, subfinder, httpx, katana, ffuf, nikto |
| **进程管理** | tmux (子 Agent 面板 + 交互进程) |
| **PoC 数据库** | WeaponRadar (22W Nuclei PoC, BGE-M3 向量搜索, pgvector) |
| **类型系统** | Zod 3.24 |

---

## 安全声明

**本项目仅用于授权的安全测试、CTF 竞赛、安全研究和教育目的。**

使用者必须：
- 获得目标系统的书面授权
- 遵守当地法律法规
- 仅在授权范围内使用
- 不得用于未授权的渗透测试

---

<div align="center">

**Made with ❤️ for the Red Team Community**

[⭐ Star](https://github.com/atreasureboy/ovogo) | [🐛 Issues](https://github.com/atreasureboy/ovogo/issues) | [💡 Feature Request](https://github.com/atreasureboy/ovogo/issues)

</div>
