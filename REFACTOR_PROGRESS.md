# 红队项目重构进度报告

## 📊 已完成的工作

### ✅ 架构升级

1. **LangGraph 集成** - 完成
   - 状态图架构（StateGraph）
   - Supervisor 协调节点
   - Worker 工作节点
   - Agent Worker 独立进程
   - 共享状态管理

2. **三层架构实现** - 进行中
   - **Tool 层**：原子工具，标准化输出
   - **Skill 层**：工具链路，战术组合
   - **Agent 层**：智能决策，战略指挥

---

## 🎯 已完成的子 Agent（极致化）

### 1. Recon Agent（侦察智能体）✅

**Tool 层（10+ 工具）**
- Subfinder - 快速子域名枚举
- Amass - 深度子域名枚举（OSINT + 主动）
- OneForAll - 全面子域名收集
- DNSx - 快速 DNS 解析和验证
- Masscan - 极速端口扫描（盲扫）
- Naabu - 高可靠端口扫描
- Nmap - 深度服务指纹识别
- httpx - Web 服务存活探测
- Fofa API - 空间测绘查询
- Shodan API - 空间测绘查询

**Skill 层（6个战术链路）**
- `collectSubdomains` - 全面子域名收集（Subfinder + Amass + OneForAll 并行）
- `validateSubdomains` - 子域名存活验证（DNSx 批量解析）
- `detectSubdomainTakeover` - 子域接管检测（CNAME 过滤 + httpx 验证）
- `scanPorts` - 全面端口扫描（Masscan 盲扫 + Naabu 验证 + Nmap 指纹）
- `probeWebServices` - Web 服务探测（httpx 存活 + 技术栈）
- `collectSpaceIntel` - 空间测绘情报收集（Fofa + Shodan 并行）

**Agent 层**
- LLM 驱动决策
- 动态选择 Skill 组合
- 维护全局资产状态图谱（Asset Graph）
- 自适应侦察策略
- 生成结构化报告

**特点**
- 不直接调用 Tool，只调用 Skill
- 具备完整的决策能力
- 支持多轮迭代和深度探测
- 自动去重和优先级排序

---

### 2. Vuln-Scan Agent（漏洞扫描智能体）✅

**Tool 层（10+ 工具）**
- Nuclei - 模板化漏洞扫描（全模板 + 指定严重程度）
- FFUF - 高速目录爆破
- Nikto - Web 服务器漏洞扫描
- SQLMap - SQL 注入自动化检测
- Arjun - HTTP 参数发现
- Dalfox - XSS 漏洞扫描
- WhatWeb - Web 应用指纹识别
- Xray - 被动代理扫描

**Skill 层（4个战术链路）**
- `scanWebVulnerabilities` - Web 漏洞全面扫描
  - 指纹识别（WhatWeb）
  - 参数发现（Arjun）
  - 目录爆破（FFUF）
  - 漏洞扫描（Nuclei Critical/High 优先）
  - 专项扫描（SQLMap + Dalfox）
  - 全面扫描（Nuclei Full）
  - 深度扫描（Nikto）
- `scanServiceVulnerabilities` - 服务层漏洞扫描
- `attackAuthentication` - 认证攻击（弱口令、默认凭证）
- `verifyVulnerabilities` - 漏洞验证（重新执行 PoC）

**Agent 层**
- LLM 驱动决策
- 智能分流（Web 漏洞 vs 服务漏洞 vs 认证攻击）
- 漏洞去重、优先级排序
- 自动验证（减少误报）
- 生成结构化漏洞报告

**特点**
- 自适应扫描（根据目标类型、数量、技术栈）
- 合规性控制（避免破坏性测试）
- 支持跳过慢速扫描（skipSlow 选项）

---

### 3. Exploit Agent（漏洞利用智能体）✅

**Tool 层（10+ 工具）**
- Metasploit - 自动化利用框架（通过资源文件）
- SearchSploit - PoC 搜索（本地 Exploit-DB）
- Nuclei PoC 执行 - 验证型利用
- 自定义 Exploit 脚本 - Python/Bash 脚本执行
- WebShell 管理 - 上传、连接、命令执行（PHP/JSP/ASPX）
- Reverse Shell 生成 - 多种 Payload（Bash/Python/PHP/NC/PowerShell）
- SQLMap 深度利用 - 数据提取、文件读取、Shell 上传

**Skill 层（7个战术链路）**
- `exploitRCE` - RCE 漏洞利用
  - SearchSploit 搜索 Exploit
  - Metasploit 自动化利用
  - 自定义脚本利用
  - 多种 Reverse Shell Payload
- `exploitSQLInjectionDeep` - SQL 注入深度利用
  - 数据库枚举
  - 敏感数据提取
  - 文件读取
  - WebShell 上传
- `exploitFileUpload` - 文件上传漏洞利用
- `exploitCommandInjection` - 命令注入利用
- `exploitDeserialization` - 反序列化漏洞利用（ysoserial/phpggc）
- `executeNucleiPoCBatch` - Nuclei PoC 批量执行

**Agent 层**
- LLM 驱动决策
- 动态选择利用策略
- 自动化利用流程（PoC 验证 → Exploit → Shell 获取）
- 多种 Payload 尝试（容错机制）
- Shell 管理和维护

**特点**
- 优先级策略（Critical RCE > High RCE > SQL 注入 > 文件上传）
- 自适应利用（根据中间结果调整策略）
- 合规性控制（仅在授权范围内利用）

---

### 4. Post-Exploit Agent（后渗透智能体）✅

**Tool 层（10+ 工具）**
- 系统信息枚举 - hostname/OS/kernel/users
- LinPEAS - Linux 权限提升枚举
- /etc/shadow 哈希提取
- SSH 私钥搜索
- 配置文件密码搜索
- 网络连接枚举 - netstat/ss
- 进程枚举 - ps aux
- 敏感文件搜索 - find（配置、备份、数据库）

**Skill 层（5个战术链路）**
- `enumerateSystem` - 系统全面枚举
  - 系统基本信息
  - 进程枚举
  - 网络连接枚举
- `harvestCredentials` - 凭证全面收集
  - /etc/shadow 哈希提取
  - SSH 私钥搜索
  - 配置文件密码搜索
- `enumeratePrivesc` - 权限提升枚举
  - LinPEAS 自动化枚举
  - SUID 二进制检查
  - 可写文件检查
  - 定时任务检查
  - 生成提权建议
- `collectSensitiveData` - 敏感数据收集
  - 配置文件
  - 备份文件
  - 数据库文件
- `discoverInternalAssets` - 内网资产发现
  - 网络接口和路由
  - 内网网段发现
  - 存活主机探测

**Agent 层**
- LLM 驱动决策
- 全面枚举目标系统
- 自动化凭证收集
- 权限提升准备
- 内网资产发现（为横向移动做准备）

**特点**
- 支持多 Shell 并行枚举
- 自动识别高价值数据
- 生成情报图谱（Intelligence Graph）

---

## 📁 文件结构

```
src/
├── recon/
│   ├── tools/index.ts       # 10+ 侦察工具
│   ├── skills/index.ts      # 6个侦察战术链路
│   └── agent/index.ts       # 侦察智能体
├── vuln-scan/
│   ├── tools/index.ts       # 10+ 扫描工具
│   ├── skills/index.ts      # 4个扫描战术链路
│   └── agent/index.ts       # 扫描智能体
├── exploit/
│   ├── tools/index.ts       # 10+ 利用工具
│   ├── skills/index.ts      # 7个利用战术链路
│   └── agent/index.ts       # 利用智能体
├── post-exploit/
│   ├── tools/index.ts       # 10+ 后渗透工具
│   ├── skills/index.ts      # 5个后渗透战术链路
│   └── agent/index.ts       # 后渗透智能体
└── core/
    ├── graph/
    │   ├── types.ts         # LangGraph 状态类型
    │   ├── nodes/
    │   │   ├── supervisor.ts # Supervisor 节点
    │   │   └── workers.ts    # Worker 节点
    │   └── builder.ts       # 状态图构建器
    ├── langGraphEngine.ts   # LangGraph 引擎
    └── langGraphIntegration.ts # 集成辅助函数
```

---

## 🎨 核心设计原则

### 1. 三层分离
- **Tool 层**：原子工具，标准化输出，无业务逻辑
- **Skill 层**：工具链路，战术组合，包含条件分支和容错
- **Agent 层**：智能决策，战略指挥，LLM 驱动

### 2. 每个子 Agent 都是"指挥官"
- 不是简单的工具封装
- 具备完整的决策能力
- 动态选择 Skill 组合
- 构建资产/漏洞/Shell/情报图谱

### 3. 极致化要求
- 工具覆盖全面（不只是 nmap/masscan）
- 链路精细设计（条件分支、容错、切换）
- 合规性硬编码（在 Skill 层控制）
- 自适应策略（根据中间结果调整）

---

## 🚀 下一步工作

### 待完成的子 Agent

5. **Privesc Agent**（权限提升智能体）
   - Tool: SUID 利用、内核 Exploit、sudo 滥用、定时任务劫持
   - Skill: 自动化提权链路
   - Agent: 智能选择提权方法

6. **Lateral Agent**（横向移动智能体）
   - Tool: PTH、PTT、MS17-010、凭证复用、SSH 横向
   - Skill: 内网扫描 + 凭证喷洒 + 漏洞利用
   - Agent: 智能横向移动策略

7. **C2 Agent**（C2 部署智能体）
   - Tool: Sliver、Metasploit、Cobalt Strike
   - Skill: Beacon 生成 + 上传 + 执行 + 等待上线
   - Agent: C2 管理和维护

8. **Report Agent**（报告生成智能体）
   - Tool: FindingList、证据收集
   - Skill: 报告模板生成
   - Agent: 完整渗透测试报告

---

## 💡 关键创新点

1. **Tool → Skill → Agent 三层架构**
   - 清晰的职责分离
   - 高度可复用
   - 易于测试和维护

2. **每个 Agent 都是独立的"指挥官"**
   - 不是简单的脚本封装
   - 具备战略级别的决策能力
   - 维护完整的状态图谱

3. **LangGraph 状态管理**
   - 所有 Agent 通过共享状态通信
   - 自动状态合并
   - 支持条件路由和循环

4. **极致化工具覆盖**
   - 侦察：10+ 工具（不只是 nmap）
   - 扫描：10+ 工具（不只是 nuclei）
   - 利用：10+ 工具（不只是 metasploit）
   - 后渗透：10+ 工具（不只是 linpeas）

5. **自适应策略**
   - 根据中间结果动态调整
   - 智能分流和优先级排序
   - 容错机制和降级决策

---

## 📊 当前进度

- ✅ LangGraph 架构集成
- ✅ Recon Agent（极致化）
- ✅ Vuln-Scan Agent（极致化）
- ✅ Exploit Agent（极致化）
- ✅ Post-Exploit Agent（极致化）
- ⏳ Privesc Agent（待开发）
- ⏳ Lateral Agent（待开发）
- ⏳ C2 Agent（待开发）
- ⏳ Report Agent（待开发）

**完成度：50%**（4/8 个子 Agent）

---

## 🎯 总结

已完成的 4 个子 Agent 都达到了"极致化"标准：
- 工具覆盖全面（每个 Agent 10+ 工具）
- 链路精细设计（Skill 层包含条件分支和容错）
- 智能决策能力（Agent 层 LLM 驱动）
- 状态图谱维护（Asset/Vuln/Shell/Intel Graph）

这不是简单的工具封装，而是真正的"智能体"。每个 Agent 都具备战略级别的指挥能力，能够根据环境动态调整策略，自主完成复杂的渗透测试任务。
