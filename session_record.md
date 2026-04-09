# OVOGOGOGO — 红队渗透自动化引擎

> 最后更新：2026-04-09
> 状态：生产可用，持续迭代中

---

## 一、项目定位

**ovogogogo** 是一个基于 OpenAI 兼容接口的红队渗透自动化引擎，渗透测试场景设计。

- **API 接口**：OpenAI 兼容格式（非 Anthropic SDK），支持任意兼容端点
- **运行环境**：64 核 Linux 云服务器，`/project/ovogogogo/`
- **授权测试范围**：`zhhovo.top`（测试靶场，完全白名单）
- **PoC_RAG 数据库** 22 万条 Nuclei PoC（pgvector + BGE-M3，`/data/poc_db/`）

---

## 二、核心架构

### 2.1 引擎层 (`src/core/`)

```
Think → Act → Observe 主循环（engine.ts）
  │
  ├── 并发调度（partitionToolCalls）
  │    ├── CONCURRENCY_SAFE_TOOLS → Promise.all 同时执行
  │    │   Bash / Agent / WeaponRadar / FindingList / MultiScan
  │    │   Read / Glob / Grep / WebFetch / WebSearch
  │    └── 其余工具（Write/Edit/FindingWrite）→ 串行
  │
  ├── 流式输出（OpenAI stream）
  ├── 自动 compact（超过 token 阈值时压缩历史）
  └── AbortController（Ctrl+C 取消当前轮次）
```

**关键配置：**
| 参数 | 值 | 说明 |
|------|----|------|
| `DEFAULT_TIMEOUT_MS` | 1,800,000 (30min) | Bash 默认超时 |
| `MAX_TIMEOUT_MS` | 14,400,000 (4h) | Bash 最大超时 |
| `maxIterations` | 200 | 主引擎最大轮次 |
| `MAX_TOOL_RESULT_LENGTH` | 20,000 | 工具输出截断长度 |

### 2.2 工具层 (`src/tools/`)

| 工具 | 类型 | 并发安全 | 说明 |
|------|------|---------|------|
| `Bash` | 执行 | ✅ | Shell 命令，30min 默认超时，支持 run_in_background |
| `Agent` | 子智能体 | ✅ | 专用红队 sub-agent，Promise.all 并行 |
| `WeaponRadar` | 武器库 | ✅ | 22W PoC 语义检索，支持 queries[] 批量 |
| `FindingWrite` | 漏洞记录 | ❌ | 写 `.ovogo/findings/*.json` |
| `FindingList` | 漏洞查询 | ✅ | 读 findings，支持过滤 |
| `MultiScan` | 并行扫描 | ✅ | Promise.all(wait) 或 nohup(detach) |
| `Read/Write/Edit` | 文件IO | ❌/✅ | Edit 串行，Read 并发 |
| `Glob/Grep` | 文件搜索 | ✅ | 并发安全 |
| `WebFetch/WebSearch` | 网络 | ✅ | OSINT/CVE 查询 |
| `TodoWrite` | 任务跟踪 | ❌ | 任务分解 |

### 2.3 多 Agent 架构（核心并发机制）

```
Orchestrator (1x, 主引擎, 200轮上限)
│
│  ◀── 同一响应中多个 Agent() 调用 = Promise.all 并行 ──▶
│
├─ Phase 1: RECON ── 3个Agent同时运行
│   ├─ dns-recon    (80轮)  subfinder/dnsx/amass
│   │                       → subs.txt / ips.txt / dns_records.txt
│   ├─ port-scan    (80轮)  nmap(两步,后台)/masscan/naabu
│   │                       → nmap_ports.txt / nmap_services.txt
│   └─ web-probe    (80轮)  httpx(-t 300 -timeout 10)/katana/gau
│                           → web_assets.txt / katana_urls.txt
│
├─ Phase 2: INTEL ── 2个Agent同时运行
│   ├─ weapon-match (60轮)  WeaponRadar批量查询
│   │                       → pocs/*.yaml（可直接用 nuclei 执行）
│   └─ osint        (60轮)  WebSearch/crt.sh/GitHub dork
│                           → osint_findings.txt
│
├─ Phase 3: SCAN ── 3个Agent同时运行
│   ├─ web-vuln    (120轮)  nuclei(-c 100 -bs 50 -rl 500)/ffuf(-t 200)
│   │                       → nuclei_web.txt / ffuf_dirs.json
│   ├─ service-vuln(100轮)  nuclei网络层/nmap-vuln/enum4linux
│   │                       → nuclei_network.txt / nmap_vuln.txt
│   └─ auth-attack (100轮)  hydra/kerbrute/默认凭证检测
│                           → hydra_results.txt / creds.txt
│
├─ Phase 4: EXPLOIT ── N个Agent同时运行（每高置信漏洞1个）
│   └─ poc-verify × N (60轮)  运行PoC + 截图/响应证据 + FindingWrite
│                              → evidence/CVE-XXXX_proof.txt
│
└─ Phase 5: REPORT ── 1个Agent
    └─ report (60轮)  FindingList + 汇总 → report.md
```

**并行原理：**
- `Agent` 工具在 `CONCURRENCY_SAFE_TOOLS` 中
- Orchestrator 在同一响应里调 3 个 `Agent(...)` → 引擎用 `Promise.all` 同时执行
- 64 核服务器轻松支持 50+ 并发 sub-agent

### 2.4 Prompt 层 (`src/prompts/`)

| 文件 | 作用 |
|------|------|
| `system.ts` | 主引擎 System Prompt（红队身份 + 工具规则 + 并发策略）|
| `agentPrompts.ts` | 10 种专用 Agent Prompt（dns-recon/port-scan 等）|
| `tools.ts` | 工具描述文本 |

---

## 三、工具并发配置（64核标准）

| 工具 | 关键参数 | 说明 |
|------|---------|------|
| nuclei | `-c 100 -bs 50 -rl 500` | 模板并发100/目标并发50/500RPS |
| ffuf | `-t 200` | 200线程 |
| httpx | `-t 300 -timeout 10` | 300线程/每请求10s超时 |
| subfinder | `-t 100` | 100线程 |
| dnsx | `-t 200` | 200线程 |
| naabu | `-rate 10000` | 1万包/秒 |
| nmap | `-T4 --min-rate 5000` | 高速，**全端口扫必须后台** |

---

## 四、武器库集成

### 4.1 数据库
- **位置**：PostgreSQL 127.0.0.1:5432，用户/密码：`msf/msf`，库名：`msf`
- **表**：`nuclei_exploits`（22万条，全部有 `full_poc_code`）
- **索引**：HNSW 向量索引（`poc_vector vector_cosine_ops`）
- **字段**：`id / module_name / full_poc_code / ai_analysis / cve_list / required_options / poc_vector`

### 4.2 查询接口
```bash
# 单查询（默认返回完整PoC代码）
python3 /data/poc_db/weapon_radar_query.py -q "Apache Shiro 反序列化" -n 3

# 批量查询（一次加载模型，处理多个查询）
python3 /data/poc_db/weapon_radar_query.py \
  --batch-json '[{"query":"WordPress RCE","top_k":3},{"query":"Log4j","top_k":3}]'

# 不要PoC代码（只看匹配结果）
python3 /data/poc_db/weapon_radar_query.py -q "SSRF" --no-code
```

### 4.3 WeaponRadar 工具用法
```
WeaponRadar({queries: ["Apache Log4j RCE", "Shiro 反序列化", "Jenkins RCE"]})
// 批量模式，模型只加载一次，PoC代码直接返回含nuclei执行命令
```

---

## 五、目录结构

```
/project/ovogogogo/
├── session_record.md          # 本文件（项目完整档案）
├── ovogo_progress.json        # 当前会话状态
├── resume.cfg                 # 恢复配置
├── package.json
├── tsconfig.json
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
│   │   ├── index.ts           # 工具注册表
│   │   ├── agent.ts           # AgentTool（10种专用类型，最高200轮）
│   │   ├── bash.ts            # BashTool（30min默认超时）
│   │   ├── weaponRadar.ts     # WeaponRadar（22W PoC，批量查询）
│   │   ├── multiScan.ts       # MultiScan（Promise.all / nohup两模式）
│   │   ├── finding.ts         # FindingWrite / FindingList
│   │   ├── fileRead.ts / fileWrite.ts / fileEdit.ts
│   │   ├── glob.ts / grep.ts
│   │   ├── todo.ts
│   │   └── webFetch.ts / webSearch.ts
│   │
│   ├── prompts/
│   │   ├── system.ts          # 主引擎 System Prompt
│   │   ├── agentPrompts.ts    # 10种红队Agent Prompt
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
│   └── skills/                # 45个工具技能文档
│       ├── nuclei.md          # nuclei专家（含-c 100 -bs 50 -rl 500）
│       ├── httpx.md           # httpx（-t 300 -timeout 10）
│       ├── subfinder.md       # subfinder（-t 100）
│       ├── ffuf.md            # ffuf（-t 200）
│       ├── dnsx.md            # dnsx（-t 200）
│       ├── katana.md          # katana（-d 2 -timeout 30）
│       ├── nmap.md / masscan.md / naabu.md
│       ├── sqlmap.md / hydra.md / wpscan.md
│       ├── enum4linux.md / kerbrute.md / netexec.md
│       └── ... (共45个)
│
├── sessions/                  # 渗透会话输出（每次自动创建）
│   └── session_TARGET_YYYYMMDD_HHMMSS/
│       ├── subs.txt           # 子域名列表
│       ├── ips.txt            # IP列表
│       ├── nmap_ports.txt     # 全端口扫描
│       ├── nmap_services.txt  # 服务版本
│       ├── web_assets.txt     # 存活Web资产
│       ├── nuclei_web.txt     # Web漏洞扫描结果
│       ├── pocs/              # 匹配到的PoC文件
│       ├── evidence/          # 漏洞证据
│       └── report.md          # 最终报告
│
└── /data/poc_db/              # 公司武器库（独立目录）
    ├── weapon_radar.py        # 核心引擎（BGE-M3向量+pgvector）
    └── weapon_radar_query.py  # JSON接口（供 WeaponRadar 工具调用）
```

---

## 六、Engagement 配置

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

## 七、已知问题 & 注意事项

| 问题 | 状态 | 解决方案 |
|------|------|---------|
| nmap -p- 超时 | ✅ 已修 | 必须用 `run_in_background: true` |
| httpx 挂死 | ✅ 已修 | 加 `-timeout 10` |
| nuclei 无模板报错 | ✅ 已修 | 必须加 `-t /root/nuclei-templates/` 或 `-id CVE` |
| WeaponRadar 双重加载 | ✅ 已修 | 用 `queries:[]` 批量，一次加载 |
| httpx vs Python httpx 冲突 | ✅ 已修 | 用绝对路径 `/root/go/bin/httpx` |
| nuclei 相对路径失败 | ✅ 已修 | 用 `-id CVE-xxx` 或绝对路径 |
| katana 超时 | ✅ 已修 | 强制 `-d 2 -timeout 30` |
| ffuf 字典路径错误 | ✅ 已修 | `/opt/wordlists/seclists/` |
| Agent max_iterations 太低 | ✅ 已修 | 各 Agent 80-120 轮 |

---

## 八、启动命令

```bash
cd /project/ovogogogo
node dist/bin/ovogogogo.js

# 或用 npm script
npm start

# 关键环境变量
OPENAI_BASE_URL=http://...   # 自定义 API 端点
OPENAI_API_KEY=xxx           # API 密钥
```

---

## 九、典型渗透流程（Orchestrator 标准操作）

```
用户: 对 zhhovo.top 进行全面渗透测试

Orchestrator:
  1. 读取 .ovogo/settings.json 确认 scope
  2. 创建 session dir: sessions/session_zhhovo.top_YYYYMMDD_HHMMSS/

  Phase 1 (一次性启动3个Agent):
    Agent(dns-recon, "subfinder+dnsx枚举zhhovo.top子域名", ...)
    Agent(port-scan, "nmap全端口扫描zhhovo.top", ...)
    Agent(web-probe, "httpx探测所有子域名Web服务", ...)
    → 等待全部完成（3个并行）

  Phase 2 (启动2个Agent):
    Agent(weapon-match, "根据发现的服务匹配PoC", ...)
    Agent(osint, "收集zhhovo.top相关公开情报", ...)
    → 等待全部完成

  Phase 3 (启动3个Agent):
    Agent(web-vuln, "nuclei扫描所有Web资产", ...)
    Agent(service-vuln, "扫描开放的非HTTP服务", ...)
    Agent(auth-attack, "测试发现的认证服务", ...)
    → 等待全部完成

  Phase 4 (每个高置信漏洞1个Agent):
    Agent(poc-verify, "验证CVE-2024-XXXX", ...)
    Agent(poc-verify, "验证CVE-2023-YYYY", ...)
    → 等待全部完成

  Phase 5:
    Agent(report, "生成完整渗透测试报告", ...)
```
