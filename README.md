# Ovogo — 自主红队协调引擎

<div align="center">

**AI 驱动的渗透测试自主协调 Agent | Think-Act-Observe 引擎 | 多 Agent 编排 | 防护感知利用 | 跨轮次记忆**

[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue.svg)](https://www.typescriptlang.org/)
[![OpenAI](https://img.shields.io/badge/OpenAI-Compatible-green.svg)](https://platform.openai.com/)
[![Claude](https://img.shields.io/badge/Claude-Supported-purple.svg)](https://www.anthropic.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> 用一句话启动: `ovogo "对 target.com 进行渗透测试"`

</div>

---

## 目录

- [项目简介](#项目简介)
- [完整架构全景图](#完整架构全景图)
- [核心模块详解](#核心模块详解)
  - [执行引擎：Think-Act-Observe](#执行引擎think-act-observe)
  - [状态机编排器](#状态机编排器)
  - [子 Agent 作战体系](#子-agent-作战体系)
  - [记忆与知识系统](#记忆与知识系统)
  - [工具系统（22 Tools）](#工具系统22-tools)
  - [安全基础设施](#安全基础设施)
  - [环境感知与绕过引擎](#环境感知与绕过引擎)
- [快速开始](#快速开始)
- [项目结构](#项目结构)
- [设计决策](#设计决策)
- [技术栈](#技术栈)
- [安全声明](#安全声明)

---

## 项目简介

Ovogo 是一个**自主红队协调引擎**——它不是一堆散装的扫描脚本，而是一个具备完整推理能力的 AI Agent，能够：

1. **理解目标** — 接收渗透测试目标（URL / IP / 域名）
2. **环境感知** — 自动检测 WAF/EDR/沙箱防护，生成结构化绕过建议
3. **制定计划** — 基于 MITRE ATT&CK 框架自动生成攻击链
4. **并行分发** — 同时派遣多个专业子 Agent 执行侦察、扫描、利用
5. **防护感知利用** — 集成 Havoc C2 / Sliver C2 / APT28 三大框架的 23 种绕过技术
6. **监控进度** — 定时读取子 Agent 输出，评估进展，调整策略
7. **联动利用** — 将一个 Agent 的发现传递给另一个 Agent 利用
8. **收集 Flag** — 自动搜索、提取目标 Flag
9. **生成报告** — 汇总所有发现，形成完整攻击链记录

**与传统红队框架的本质区别：**
- 传统框架 = 脚本编排（if-then 流程固定，遇防护即失效）
- Ovogo = AI 自主决策 + 防护感知（LLM 每轮推理，动态检测防护并选择绕过技术）

---

## 完整架构全景图

```
╔══════════════════════════════════════════════════════════════════════════════════════════════╗
║                              Ovogo — 自主红队协调引擎 架构全景                                ║
╠══════════════════════════════════════════════════════════════════════════════════════════════╣
║                                                                                              ║
║   用户输入: "对 zhhovo.top 进行渗透测试"                                                      ║
║        │                                                                                     ║
║        ▼                                                                                     ║
║  ┌─────────────────────────────────────────────────────────────────────────────────────┐    ║
║  │  bin/ovogogogo.ts  —  主入口 (REPL / 单次任务 / --orchestrator 状态机模式)          │    ║
║  │  ├── Skill 系统 (阶段动态工具加载)  │  Hook 系统 (Pre/Post 工具钩子)               │    ║
║  │  ├── MCP 服务 (外部工具扩展)      │  OVOGO.md (用户指令注入)                      │    ║
║  │  └── Memory 系统 (文件记忆加载)   │  KnowledgeBase (实战知识注入)                  │    ║
║  └─────────────────────────────────┬───────────────────────────────────────────────────┘    ║
║                                    │                                                         ║
║                    ┌───────────────┼───────────────┐                                         ║
║                    ▼               ▼               ▼                                         ║
║  ┌─────────────────────┐ ┌────────────────┐ ┌──────────────────────────────┐               ║
║  │  ExecutionEngine    │ │  Battle        │ │  Agent Worker (独立进程)     │               ║
║  │  (Think-Act-Observe)│ │  Orchestrator  │ │  ┌──────────────────────┐    │               ║
║  │                     │ │  (状态机)      │ │  │ 专用 Agent 实例      │    │               ║
║  │ ┌─────────────────┐ │ │              │ │  │ 独立 Engine + Prompt │    │               ║
║  │ │ Context Budget  │ │ │ PhaseMachine │ │  │ 文件系统通信         │    │               ║
║  │ │ + Auto-Compact  │ │ │ 7阶段状态机  │ │  │ 结构化结果提取       │    │               ║
║  │ ├─────────────────┤ │ ├──────────────┤ │  └──────────────────────┘    │               ║
║  │ │ Streaming LLM   │ │ │ TaskDAG      │ │  │  recon / vuln-scan /      │               ║
║  │ │ + Tool Stream   │ │ │ 依赖追踪     │ │  │  exploit / privesc /      │               ║
║  │ ├─────────────────┤ │ ├──────────────┤ │  │  lateral / flag-hunter    │               ║
║  │ │ Critic 审查     │ │ │ LLM          │ │  └──────────────────────────────┘               ║
║  │ │ (15项自动纠错)  │ │ │ Supervisor   │ │                                                 ║
║  │ ├─────────────────┤ │ │ RoE约束注入  │ │                                                 ║
║  │ │ 并行 Tool 调度  │ │ └──────┬───────┘ │                                                 ║
║  │ │ (Promise.all)   │ │        │       │ │                                                 ║
║  │ └────────┬────────┘ │        └───────┼─┘                                                 ║
║  └─────────┼──────────┘                │                                                   ║
║            │                           │                                                   ║
║  ┌─────────┴───────────────────────────┼──────────────────────────────────────┐           ║
║  │            工具层 (22 Tools)         │                                      │           ║
║  │  ┌──────────┬──────────┬────────────┼──────┬──────────┬──────────────┐     │           ║
║  │  │ Bash     │ Agent    │ MultiAgent │ 武器 │ Shell    │ TmuxSession  │     │           ║
║  │  │ 命令执行 │ 子Agent  │ 批量并发   │ 雷达 │ Session  │ 交互进程     │     │           ║
║  │  ├──────────┼──────────┼────────────┼──────┼──────────┼──────────────┤     │           ║
║  │  │ Read     │ Write    │ Edit       │ Glob │ Grep     │ TodoWrite    │     │           ║
║  │  │ 读文件   │ 写文件   │ 精确替换   │ 查找 │ 内容搜索 │ 任务清单     │     │           ║
║  │  ├──────────┼──────────┼────────────┼──────┼──────────┼──────────────┤     │           ║
║  │  │ Weapon   │ Web      │ Web        │ C2   │ Dispatch │ Finding      │     │           ║
║  │  │ Radar    │ Search   │ Fetch      │ 设施 │ Agent    │ Write/List   │     │           ║
║  │  │ 22W PoC  │ 网络搜索 │ URL获取    │ MSF  │ 异步任务 │ 漏洞管理     │     │           ║
║  │  ├──────────┼──────────┼────────────┼──────┼──────────┼──────────────┤     │           ║
║  │  │ MultiScan│ DocRead  │ EnvAnalyzer│技    │          │              │     │           ║
║  │  │ 并行扫描 │ 文档读取 │ 环境感知   │术生成│          │              │     │           ║
║  │  └──────────┴──────────┴────────────┴──────┴──────────┴──────────────┘     │           ║
║  └────────────────────────────────────────────────────────────────────────────┘           ║
║            │                                                                             ║
║  ┌─────────┴────────────────────────────────────────────────────────────────────┐       ║
║  │                        记忆 & 知识 & 安全基础设施                              │       ║
║  │  ┌──────────────┐ ┌───────────────┐ ┌──────────────┐ ┌──────────────────┐   │       ║
║  │  │ 语义记忆     │ │ 情景记忆      │ │ 实战知识库   │ │ EventLog         │   │       ║
║  │  │ SemanticMem  │ │ EpisodicMem   │ │ KnowledgeBase│ │ (不可变事件流)    │   │       ║
║  │  │ CVE/拓扑/凭证│ │ 行动轨迹      │ │ JSONL持久化  │ │ NDJSON审计轨迹    │   │       ║
║  │  ├──────────────┤ ├───────────────┤ ├──────────────┤ ├──────────────────┤   │       ║
║  │  │ 工具缓存     │ │ 进度追踪     │ │ Dispatch     │ │ 文件记忆         │   │       ║
║  │  │ ToolCache    │ │ Progress     │ │ 异步通信     │ │ MEMORY.md        │   │       ║
║  │  │ SHA256+TTL   │ │ 长任务管理   │ │ 任务队列     │ │ 跨session偏好    │   │       ║
║  │  └──────────────┘ └───────────────┘ └──────────────┘ └──────────────────┘   │       ║
║  └────────────────────────────────────────────────────────────────────────────┘       ║
║            │                                                                             ║
║  ┌─────────┴────────────────────────────────────────────────────────────────────────────┐ ║
║  │                    环境感知 & 绕过引擎 (EnvAnalyzer + TechniqueGenerator)               │ ║
║  │                                                                                      │ ║
║  │  ┌─────────────────────────┐    ┌──────────────────────────────────┐                │ ║
║  │  │  EnvAnalyzer            │ -> │  TechniqueGenerator (23 技术)    │                │ ║
║  │  │                         │    │                                  │                │ ║
║  │  │  WAF 检测 (wafw00f/curl)│    │  Havoc 系列 (6 技术):            │                │ ║
║  │  │  EDR 检测 (进程匹配)    │    │   AMSI/ETW绕过/间接syscall/      │                │ ║
║  │  │  沙箱检测 (VM特征)      │    │   睡眠混淆/栈伪造/Hash API       │                │ ║
║  │  │                         │    │                                  │                │ ║
║  │  │  输出: 防护类型+建议    │    │  Sliver 系列 (7 技术):           │                │ ║
║  │  │                         │    │   RefreshPE/SGN编码/流量多态/    │                │ ║
║  │  │                         │    │   PE元数据伪造/.NET双模式/       │                │ ║
║  │  │                         │    │   Go模板编译/操作模式            │                │ ║
║  │  │                         │    │                                  │                │ ║
║  │  │                         │    │  APT28 系列 (8 技术):            │                │ ║
║  │  │                         │    │   交替XOR/轮转XOR/PNG隐写/       │                │ ║
║  │  │                         │    │   RW→RX转换/APC注入/COM劫持/     │                │ ║
║  │  │                         │    │   Dead Drop/WebDAV UNC           │                │ ║
║  │  └─────────────────────────┘    └──────────────────────────────────┘                │ ║
║  └────────────────────────────────────────────────────────────────────────────────────┘ ║
║            │                                                                             ║
║  ┌─────────┴────────────────────────────────────────────────────────────────────────────┐ ║
║  │                              子 Agent 作战体系 (25+ 类型)                             │ ║
║  │                                                                                      │ ║
║  │   Phase 1: 侦察+探测          Phase 2: 漏洞检索      Phase 3: 漏洞利用+C2            │ ║
║  │  ┌──────────────────┐      ┌─────────────────┐    ┌────────────────────────────┐    │ ║
║  │  │ recon ─┬─ dns-recon     │ weapon-match     │    │ manual-exploit (curl/py)   │    │ ║
║  │  │        ├─ port-scan      │ 22W PoC语义检索  │    │ tool-exploit (MSF/sqlmap)  │    │ ║
║  │  │        ├─ web-probe      └─────────────────┘    │ c2-deploy (MSF/Sliver)     │    │ ║
║  │  │        └─ osint                                  └────────────┬───────────────┘    │ ║
║  │  ├──────────────────┤                                           │                    │ ║
║  │  │ vuln-scan ─┬─ web-vuln     Phase 4: 靶机操作       Phase 5: 内网横移              │ ║
║  │  │            ├─ service-vuln ┌──────────────┐    ┌────────────────────────────┐    │ ║
║  │  │            └─ auth-attack  │ target-recon  │    │ tunnel (chisel socks5)     │    │ ║
║  │  └──────────────────┘        │ privesc       │    │ internal-recon (proxy+nmap)│    │ ║
║  │                              └───────┬───────┘    │ lateral (PTH/MS17/Kerberos)│    │ ║
║  │                                      │            └────────────┬───────────────┘    │ ║
║  │                              Phase 6: Flag收集       Phase 7: 报告                  │ ║
║  │                              ┌──────────────┐    ┌────────────────────────────┐    │ ║
║  │                              │ flag-hunter   │    │ report (渗透测试报告)       │    │ ║
║  │                              │ 6层深度搜索   │    │ 攻击链记录 + 漏洞清单       │    │ ║
║  │                              └──────────────┘    └────────────────────────────┘    │ ║
║  └────────────────────────────────────────────────────────────────────────────────────┘ ║
║                                                                                          ║
║  输出: sessions/{target}_{timestamp}/ — 完整攻击记录 + 漏洞清单 + Flag + 报告             ║
╚══════════════════════════════════════════════════════════════════════════════════════════╝
```

---

## 核心模块详解

### 执行引擎：Think-Act-Observe

```
┌──────────────────────────────────────────────────────────────────┐
│                     RunTurn() 主循环                              │
│                                                                  │
│  ┌───────────┐    ┌──────────┐    ┌───────────┐    ┌──────────┐ │
│  │ Context   │ -> │ Streaming │ -> │  Tool     │ -> │ Loop /   │ │
│  │ Budget +  │    │ LLM Call  │    │  Batch    │    │ Return   │ │
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

### 状态机编排器

```
┌──────────────────────────────────────────────────────────────┐
│                    BattleOrchestrator                         │
│                                                              │
│  init → recon → vuln-scan → weapon-match → exploit           │
│         ↘          ↗          ↗         ↗                    │
│                          post-exploit → privesc → lateral    │
│                                            ↖        ↗        │
│                                              report → done   │
│                                                              │
│  PhaseMachine: 阶段状态追踪 + 允许转换约束                    │
│  TaskDAG:      任务依赖图 + 自动触发下游任务                   │
│  Supervisor:   LLM 决策引擎 (JSON 输出) + RoE 约束注入        │
│  Fallback:     规则降级决策 (LLM 失败时)                      │
│                                                              │
│ 启动: ovogogogo --orchestrator "对 target 进行渗透测试"       │
└──────────────────────────────────────────────────────────────┘
```

### 子 Agent 作战体系

```
┌─────────────────────────────────────────────────────────────────┐
│                    子 Agent 作战体系 (25+ 类型)                   │
│                                                                 │
│  Phase 1 — 侦察 + 漏洞探测 (并行开局)                            │
│  ├── recon          侦察总管 (内部: dns-recon / port-scan /     │
│  │                          web-probe / osint)                  │
│  └── vuln-scan      漏洞探测总管 (内部: web-vuln /              │
│                                   service-vuln / auth-attack)   │
│                                                                 │
│  Phase 2 — 漏洞检索                                             │
│  └── weapon-match   POC 库语义检索 (22W Nuclei PoC,             │
│                      BGE-M3 向量搜索)                            │
│                                                                 │
│  Phase 3 — 漏洞利用 + C2 (并行)                                  │
│  ├── manual-exploit  手工利用 (curl/python 精准打击 + 防护绕过)  │
│  ├── tool-exploit    工具利用 (MSF/sqlmap/searchsploit)          │
│  └── c2-deploy       C2 部署 (Metasploit/Sliver 监听 + payload)  │
│                                                                 │
│  Phase 4 — 靶机操作                                             │
│  ├── target-recon   靶机信息收集 (本机 + 内网)                   │
│  └── privesc        权限提升 (SUID/sudo/内核/计划任务/AMSI绕过)  │
│                                                                 │
│  Phase 5 — 内网横移                                             │
│  ├── tunnel         内网穿透 (chisel socks5 代理)                │
│  ├── internal-recon 内网资产发现 (proxychains + nmap)            │
│  └── lateral        横向移动 (MS17-010/PTH/凭证复用/AD攻击)      │
│                                                                 │
│  Phase 6 — Flag 收集                                            │
│  └── flag-hunter    全局 Flag 搜索收集 (6 层深度搜索)             │
│                                                                 │
│  Phase 7 — 报告                                                 │
│  └── report         渗透测试报告生成                              │
│                                                                 │
│  每个子 Agent: 独立 Engine | 专用 Prompt | tmux 面板 | 文件通信  │
└─────────────────────────────────────────────────────────────────┘
```

### 记忆与知识系统

```
┌─────────────────────────────────────────────────────────────────┐
│                     记忆 & 知识系统                              │
│                                                                 │
│  ┌───────────────────┐  ┌───────────────────┐                   │
│  │   语义记忆        │  │   情景记忆         │                   │
│  │   SemanticMemory  │  │   EpisodicMemory  │                   │
│  │                   │  │                   │                   │
│  │ 渗透知识持久化     │  │ 行动轨迹记录       │                   │
│  │ CVE利用/内网拓扑   │  │ "做了什么/成功失败" │                   │
│  │ 凭证/技术栈        │  │ Critic检查时注入   │                   │
│  │                   │  │                   │                   │
│  │ 存储: semantic.jsonl│ │ 存储: episodes.jsonl│                  │
│  └───────────────────┘  └───────────────────┘                   │
│                                                                 │
│  ┌───────────────────┐  ┌───────────────────┐                   │
│  │   实战知识库       │  │   文件记忆         │                   │
│  │   KnowledgeBase   │  │   MEMORY.md       │                   │
│  │                   │  │                   │                   │
│  │ 4类 JSONL 持久化   │  │ 用户协作偏好       │                   │
│  │ attack_patterns   │  │ 项目约定/反馈      │                   │
│  │ cve_notes         │  │ 跨 session 保留    │                   │
│  │ tool_combos       │  │                   │                   │
│  │ target_profiles   │  │ 存储: memory/     │                   │
│  │                   │  │                   │                   │
│  │ 规则提取(零LLM成本) │  │ 启动时自动加载     │                   │
│  │ 实时+Session结束   │  │                   │                   │
│  └───────────────────┘  └───────────────────┘                   │
│                                                                 │
│  攻击知识库 (AttackKnowledge) — 19 章节系统性方法论              │
│  ├── Web攻击向量 (API/认证/上传/SSRF/SSTI/反序列化)              │
│  ├── 框架漏洞 (Java/PHP/Python/Node.js/Go)                      │
│  ├── 云原生攻击 (Docker/K8s/CI-CD/AWS/Azure/GCP)                │
│  ├── 数据库攻击 (Redis/MongoDB/MySQL/PG/ES/RabbitMQ/Kafka)      │
│  ├── 内网&AD攻击 (Kerberos/NTLM/ADCS/BloodHound/横向)           │
│  ├── OAuth/SAML/SSO (授权码劫持/PKCE/断言注入)                  │
│  ├── AI/LLM应用攻击 (Prompt注入/RAG污染/工具滥用)                │
│  ├── 供应链&CI/CD (依赖污染/GitHub Actions/Jenkins)             │
│  ├── 攻击链配方 (10条完整攻击链公式)                             │
│  ├── EDR/AV 绕过技术 (AMSI/ETW/WAF/进程注入速查)                │
│  └── Sliver C2 技术 (RefreshPE/SGN/流量多态/PE伪造)             │
└─────────────────────────────────────────────────────────────────┘
```

### 工具系统（22 Tools）

所有工具统一 `Tool` 接口：`execute(input, context) → Promise<ToolResult>`

| 类别 | 工具 | 职责 |
|------|------|------|
| **执行** | Bash | Shell 命令（进程组 kill、后台模式、follow 模式） |
| | ShellSession | 持久反弹 Shell（listen/exec/kill） |
| | TmuxSession | 本地交互进程（msfconsole/sqlmap/REPL） |
| **文件** | Read / Write / Edit / Glob / Grep | 文件读写、查找、替换 |
| **情报** | WeaponRadar | 22W PoC 向量数据库语义检索（BGE-M3） |
| | WebSearch / WebFetch / DocRead | 网络搜索、URL 获取、文档读取 |
| **编排** | Agent / MultiAgent | 启动单个或多个子 Agent |
| | DispatchAgent / CheckDispatch / GetDispatchResult | 异步任务分发 |
| **管理** | FindingWrite / FindingList | 漏洞记录管理 |
| | TodoWrite | 任务清单 |
| | C2 | C2 基础设施（Metasploit/Sliver） |
| **扫描** | MultiScan | 并行扫描执行（等待/后台双模式） |
| **感知** | EnvAnalyzer | WAF/EDR/沙箱环境检测 + 绕过建议 |
| **绕过** | TechniqueGenerator | 23 种绕过技术生成（Havoc/Sliver/APT28） |

**调度策略**：
- **并行批**（Promise.all）：Read/Glob/Grep/WebFetch/WebSearch/Bash/Agent/MultiAgent/DispatchAgent/C2/ShellSession/TmuxSession/MultiScan/EnvAnalyzer/TechniqueGenerator
- **串行批**（竞态安全）：Write/Edit/FindingWrite

### 环境感知与绕过引擎

这是 Ovogo 区别于传统 AI 渗透工具的核心能力 —— 不再盲目生成 payload，而是先检测防护、再生成绕过方案。

```
┌─────────────────────────────────────────────────────────────────┐
│                  环境感知 & 绕过引擎                              │
│                                                                 │
│  Step 1: EnvAnalyzer 环境检测                                    │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                                                          │   │
│  │  WAF 检测 ──> wafw00f → 10种WAF特征匹配 → 置信度评分     │   │
│  │    ├── Cloudflare / 宝塔 / ModSecurity / AWS WAF         │   │
│  │    ├── Akamai / Imperva / Sucuri / 360 / 安全狗 / 长亭   │   │
│  │    └── 降级: curl 手动探针 + 状态码对比                   │   │
│  │                                                          │   │
│  │  EDR 检测 ──> ShellSession → tasklist 匹配已知EDR进程    │   │
│  │    ├── Windows Defender / CrowdStrike / SentinelOne      │   │
│  │    ├── Symantec / Carbon Black / FireEye / McAfee        │   │
│  │    └── Trend Micro / Kaspersky                            │   │
│  │                                                          │   │
│  │  沙箱检测 ──> CPU/内存/MAC/主机名 VM特征匹配              │   │
│  │                                                          │   │
│  │  输出: 防护类型 + 针对性绕过建议 → TechniqueGenerator     │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  Step 2: TechniqueGenerator 绕过生成 (23 技术)                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                                                          │   │
│  │  Havoc 系列 (6 技术):                                    │   │
│  │  ├── AMSI bypass  ──> 反射补丁/字符串混淆/环境变量/NGEN │   │
│  │  ├── ETW bypass   ──> 反射补丁/注册表禁用                │   │
│  │  ├── Havoc strategy ──> 编译器标志/间接syscall/         │   │
│  │  │                    硬件断点/睡眠混淆/栈伪造/Hash API  │   │
│  │  └── shellcode_encode / waf_evasion / obfuscated_ps      │   │
│  │                                                          │   │
│  │  Sliver 系列 (7 技术):                                   │   │
│  │  ├── RefreshPE      ──> DLL .text从磁盘重载去hook        │   │
│  │  ├── SGN encoding   ──> Shikata-Ga-Nai多态编码           │   │
│  │  ├── Traffic encoder──> 8种HTTP流量多态(Base32/58/64/   │   │
│  │  │                       Hex/English/PNG/Gzip/WASM)      │   │
│  │  ├── PE donor       ──> Rich Header/时间戳/签名克隆      │   │
│  │  ├── .NET dual      ──> 进程内CLR托管 vs fork-and-run    │   │
│  │  ├── Go template    ──> 条件编译/garble混淆              │   │
│  │  └── Sliver strategy ──> 操作模式综合                     │   │
│  │                                                          │   │
│  │  APT28 系列 (8 技术):                                    │   │
│  │  ├── String obfusc  ──> 交替字节XOR + Null填充           │   │
│  │  ├── Rotating XOR   ──> 76字节轮转XOR密钥                │   │
│  │  ├── PNG stego      ──> PNG隐写术 LSB提取shellcode       │   │
│  │  ├── RW→RX transition ──> 避免RWX检测的两阶段内存         │   │
│  │  ├── APC injection  ──> QueueUserAPC > CreateRemoteThread│   │
│  │  ├── COM hijack     ──> InprocServer32注册表劫持          │   │
│  │  ├── Dead Drop      ──> 合法云API作为C2(filen.io)        │   │
│  │  └── WebDAV UNC     ──> 无落地DLL内存加载                 │   │
│  │                                                          │   │
│  │  工作流: EnvAnalyzer → 检测防护 → TechniqueGenerator      │   │
│  │           → 选择绕过技术 → 生成payload → curl/Shell/C2投递│   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

**绕过工作流示例**：

```
目标: http://192.168.1.100

1. EnvAnalyzer({ target: "http://192.168.1.100", analyze_mode: "all" })
   → WAF: 宝塔 (confidence: 0.95)
   → EDR: Windows Defender (通过ShellSession检测)
   → 建议: 使用分块传输编码绕过WAF; 先执行AMSI bypass再运行PowerShell

2. TechniqueGenerator({ technique: "waf_evasion", payload: "' OR 1=1--",
    analysis_context: { waf: "宝塔" } })
   → 返回: Unicode编码 + SQL注释插入 + 分块传输 + 参数污染 四种方案

3. TechniqueGenerator({ technique: "amsi_bypass", payload: "payload",
    analysis_context: { edr: "Windows Defender" } })
   → 返回: 反射补丁 + 字符串混淆 + 排除路径 三种方案

4. 组合绕过payload → 通过curl/ShellSession/C2投递
```

### 安全基础设施

```
ShellSession (反弹 Shell 持久管理)          TmuxSession (本地交互进程)
┌─────────────────────────┐                ┌──────────────────────────┐
│  目标 ──TCP──> 攻击机    │                │  msfconsole / sqlmap     │
│     │                   │                │       │                  │
│  listen(port)           │                │  new()  → 创建 tmux 会话  │
│  exec(session, cmd)     │                │  send() → 发送按键        │
│  kill(session)          │                │  capture() → 捕获输出     │
│                         │                │  wait_for() → 等待模式    │
│  多 Shell 并发           │                │  list() / kill()          │
│  命令超时控制            │                │ 解决交互式工具超时问题    │
└─────────────────────────┘                └──────────────────────────┘

C2 集成 (Metasploit + Sliver)
├── Metasploit: msfrpcd API — listener 部署、payload 生成、session 管理
├── Sliver: CLI 封装 — implant 生成、beacon 交互
└── 持久化: C2 状态 JSON，重启后恢复

MultiScan (并行扫描执行器)
├── 等待模式 (detach: false) — Promise.all 并行，适合 <5min 短任务
│   └── subfinder / httpx / naabu / 快速 nmap → 自动超时 + 结果摘要
├── 后台模式 (detach: true) — nohup detached 进程，适合长任务
│   └── nmap -p- / nuclei 全模板 / hydra → 立即返回 PID + 输出路径
└── 统一输出: 状态图标 + 耗时 + 输出文件大小 + 末尾预览
```

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

# 状态机编排模式 (全自动攻击链)
ovogo --orchestrator "对 zhhovo.top 进行渗透测试"

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
│   ├── ovogogogo.ts          # 主入口 (REPL + Task + Plan + Orchestrator)
│   └── agent-worker.ts       # 子 Agent 独立进程
│
├── src/
│   ├── core/                 # 核心引擎
│   │   ├── engine.ts         # Think-Act-Observe 执行引擎 (流式 + 并行调度 + Critic)
│   │   ├── orchestrator.ts   # 状态机 + TaskDAG + LLM Supervisor
│   │   ├── types.ts          # 核心类型定义
│   │   ├── compact.ts        # 上下文压缩 (LLM 摘要 + 百分比阈值)
│   │   ├── contextBudget.ts  # 上下文预算管理 (显式 token 分配)
│   │   ├── eventLog.ts       # 不可变事件流 (NDJSON 审计轨迹)
│   │   ├── dispatch.ts       # 异步 Agent 分发管理器
│   │   ├── semanticMemory.ts # 语义记忆 (跨 session 渗透知识)
│   │   ├── episodicMemory.ts # 情景记忆 (行动轨迹记录)
│   │   ├── knowledgeBase.ts  # 实战知识库 (JSONL 持久化)
│   │   ├── knowledgeExtractor.ts # 规则知识提取器 (零LLM成本)
│   │   ├── skillRegistry.ts  # 技能注册表 (阶段动态加载)
│   │   ├── progressTracker.ts# 长任务进度追踪
│   │   ├── toolCache.ts      # 工具结果缓存 (SHA256 + TTL)
│   │   └── priorityQueue.ts  # 优先级队列
│   │
│   ├── tools/                # 通用工具 (22 tools)
│   │   ├── agent.ts          # 子 Agent 派发 + Dispatch 工具
│   │   ├── multiAgent.ts     # 批量并发子 Agent
│   │   ├── bash.ts           # Shell 命令执行 (进程组 kill)
│   │   ├── shellSession.ts   # 反弹 Shell 持久管理
│   │   ├── tmuxSession.ts    # 本地交互进程管理
│   │   ├── weaponRadar.ts    # 22W PoC 向量数据库检索
│   │   ├── multiScan.ts      # 并行扫描执行器 (等待/后台双模式)
│   │   ├── c2.ts             # C2 基础设施 (MSF/Sliver)
│   │   ├── finding.ts        # 漏洞档案管理
│   │   ├── envAnalyzer.ts    # 环境感知 (WAF/EDR/沙箱检测)
│   │   ├── techniqueGenerator.ts # 绕过引擎 (23种技术: Havoc/Sliver/APT28)
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
│   │   ├── system.ts         # 系统 Prompt 组装 (12+ sections)
│   │   ├── agentPrompts.ts   # 25+ Agent 类型专用 Prompt (含防护感知流程)
│   │   ├── attackKnowledge.ts # 19章攻击知识库 (含EDR绕过/Sliver技术)
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
│   └── services/mcp/         # MCP 服务
│       ├── client.ts         # MCP 客户端
│       ├── loader.ts         # MCP 服务器加载
│       ├── mcpTool.ts        # MCP 工具适配
│       └── types.ts          # MCP 类型
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
- **遇到防护 → EnvAnalyzer 检测 → TechniqueGenerator 生成绕过 → 换攻击路径**

### 为什么引入三大框架技术？

单纯靠 LLM "手写"绕过方案，质量不稳定且缺乏实战验证。Ovogo 从三个来源提取技术：

| 来源 | 提取内容 | 为什么选它 |
|------|---------|-----------|
| **Havoc C2** | 间接syscall/硬件断点AMSI bypass/睡眠混淆/栈伪造/Hash API | 编译时+运行时多层绕过，C源码级理解 |
| **Sliver C2** | RefreshPE/SGN多态编码/流量多态/PE元数据伪造/.NET双模式 | Go工程化能力，模块化扩展系统 |
| **APT28** | 交替XOR/PNG隐写/RW→RX/APC注入/COM劫持/Dead Drop/WebDAV | 国家级APT实战级免杀，多层加密链 |

### 状态机编排

主执行路径使用 `src/core/engine.ts` (Think-Act-Observe) + `src/core/orchestrator.ts` (PhaseMachine + TaskDAG + LLM Supervisor)，通过 `--orchestrator` 启用完整攻击链自动化。

### 工具缓存策略

**不缓存**：Bash/ShellSession/TmuxSession/C2/Write/Edit/FindingWrite/Read/Glob/Grep — 这些要么有副作用，要么环境实时变化。
**缓存**：WebFetch/WebSearch/WeaponRadar — 网络请求和语义检索耗时高，结果相对稳定。

---

## 技术栈

| 类别 | 技术 |
|------|------|
| **语言** | TypeScript 5.7 (ES2022, NodeNext 模块) |
| **LLM** | OpenAI 兼容 API (Claude / GPT / 任意兼容端点) |
| **AI 框架** | OpenAI SDK, LangChain Core |
| **MCP** | @modelcontextprotocol/sdk |
| **工具集成** | nmap, nuclei, sqlmap, hydra, metasploit, sliver, chisel, subfinder, httpx, katana, ffuf, nikto, wafw00f |
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
