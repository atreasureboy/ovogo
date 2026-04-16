# Ovogo - Red Team Automation Framework

基于 LangGraph 的智能红队自动化框架，采用三层架构（Tool → Skill → Agent）实现全流程渗透测试自动化。

---

## 架构特点

- **三层架构**: Tool（原子操作）→ Skill（战术链）→ Agent（战略智能）
- **LLM 驱动**: 使用 Claude API 进行智能决策
- **状态管理**: LangGraph StateGraph 管理复杂状态流转
- **并行执行**: 支持技能链并行执行提升效率
- **多格式报告**: 自动生成 Markdown、HTML、JSON、PDF 报告

## 子智能体

### 1. Recon Agent (侦察)
- 主机发现、端口扫描、服务识别
- DNS 枚举、子域名发现
- Web 技术栈识别、目录爆破
- 10+ 工具，6 个技能链

### 2. VulnScan Agent (漏洞扫描)
- Nmap NSE 脚本扫描
- Nikto、SQLMap、XSStrike 专项扫描
- 漏洞数据库匹配、CVSS 评分
- 10+ 工具，6 个技能链

### 3. Exploit Agent (漏洞利用)
- Metasploit 自动化利用
- Web 漏洞利用（SQL 注入、XSS、RCE）
- 自定义 Exploit 执行
- 10+ 工具，6 个技能链

### 4. PostExploit Agent (后渗透)
- 系统信息收集、凭证窃取
- 持久化机制部署
- 数据窃取、日志清理
- 10+ 工具，6 个技能链

### 5. Privesc Agent (权限提升)
- Linux/Windows 提权向量枚举
- 内核漏洞利用、SUID/Sudo 滥用
- Docker 逃逸、计划任务劫持
- 10+ 工具，7 个技能链

### 6. Lateral Agent (横向移动)
- 内网主机发现、凭证收集
- SSH/SMB/WinRM/RDP 横向移动
- Kerberos 票据利用
- 10+ 工具，6 个技能链

### 7. C2 Agent (命令控制)
- Metasploit/Sliver/Cobalt Strike 部署
- 多平台 Payload 生成
- Session 管理、进程迁移
- 10+ 工具，6 个技能链

### 8. Report Agent (报告生成)
- 数据整合、风险评估
- 多格式报告生成
- 执行摘要、合规性分析
- 8+ 工具，4 个技能链

## 技术栈

- **语言**: TypeScript
- **AI 框架**: LangGraph
- **LLM**: Anthropic Claude (Sonnet 4)
- **工具集成**: Nmap, Metasploit, Nikto, SQLMap, LinPEAS, WinPEAS 等

## 安装

```bash
npm install
```

## 配置

创建 `.env` 文件：

```env
ANTHROPIC_API_KEY=your_api_key_here
```

## 使用

```bash
npm run build
npm start
```

## 项目结构

```
src/
├── core/              # 核心引擎和状态管理
├── recon/             # 侦察智能体
├── vuln-scan/         # 漏洞扫描智能体
├── exploit/           # 漏洞利用智能体
├── post-exploit/      # 后渗透智能体
├── privesc/           # 权限提升智能体
├── lateral/           # 横向移动智能体
├── c2/                # 命令控制智能体
└── report/            # 报告生成智能体
```

每个智能体包含：
- `tools/` - 原子操作工具
- `skills/` - 战术技能链
- `agent/` - 战略决策层

## 安全声明

本项目仅用于授权的安全测试和教育目的。使用者需遵守当地法律法规，未经授权的渗透测试是违法行为。

## License

MIT
