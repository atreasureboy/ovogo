/**
 * Recon Agent — 侦察智能体（指挥官级别）
 *
 * 职责：
 * 1. 理解自然语言任务，拆解为侦察子任务
 * 2. 动态选择 Skill 组合，构建侦察链路
 * 3. 维护全局资产状态图谱（Asset Graph）
 * 4. 根据中间结果调整策略（自适应侦察）
 * 5. 生成结构化侦察报告
 *
 * 特点：
 * - 不直接调用 Tool，只调用 Skill
 * - 具备完整的决策能力（LLM 驱动）
 * - 支持多轮迭代和深度探测
 */

import OpenAI from 'openai'
import { writeFileSync } from 'fs'
import { join } from 'path'
import {
  collectSubdomains,
  validateSubdomains,
  detectSubdomainTakeover,
  scanPorts,
  probeWebServices,
  collectSpaceIntel,
  type SkillResult,
  type SubdomainCollectionResult,
  type SubdomainValidationResult,
  type SubdomainTakeoverResult,
  type PortScanResult,
  type WebProbeSkillResult,
  type SpaceIntelResult,
} from '../skills/index.js'

// ── Agent 状态图谱 ────────────────────────────────────────────

export interface AssetGraph {
  // 域名资产
  rootDomain: string
  subdomains: Array<{
    subdomain: string
    ips: string[]
    cname?: string
    alive: boolean
    source: string
  }>

  // 网络资产
  ips: Array<{
    ip: string
    ports: Array<{
      port: number
      protocol: string
      service?: string
      version?: string
    }>
    country?: string
    org?: string
  }>

  // Web 资产
  webServices: Array<{
    url: string
    statusCode: number
    title?: string
    technologies: string[]
    server?: string
  }>

  // 漏洞线索
  vulnerabilities: Array<{
    type: string
    target: string
    severity: string
    evidence: string
  }>

  // 统计信息
  stats: {
    totalSubdomains: number
    aliveSubdomains: number
    totalIPs: number
    totalPorts: number
    totalWebServices: number
    totalVulnerabilities: number
  }
}

// ── Agent 决策输出 ────────────────────────────────────────────

export interface ReconDecision {
  action: 'collect_subdomains' | 'validate_subdomains' | 'detect_takeover' | 'scan_ports' | 'probe_web' | 'collect_intel' | 'finish'
  reasoning: string
  parameters?: Record<string, unknown>
}

// ── Agent 配置 ────────────────────────────────────────────────

export interface ReconAgentConfig {
  apiKey: string
  baseURL?: string
  model: string
  sessionDir: string
  target: string
  maxIterations?: number
  fofaConfig?: { apiKey: string; email: string }
  shodanConfig?: { apiKey: string }
}

// ── Agent 系统 Prompt ─────────────────────────────────────────

const RECON_AGENT_SYSTEM_PROMPT = `你是一个红队侦察智能体（Recon Agent），具备战略级别的侦察指挥能力。

## 核心职责
1. 全面收集目标资产（子域名、IP、端口、Web服务）
2. 构建完整的资产图谱（Asset Graph）
3. 发现潜在的攻击面和漏洞线索
4. 动态调整侦察策略（自适应）

## 可用的 Skill（战术链路）

### 1. collect_subdomains
- 功能：全面子域名收集
- 工具链：Subfinder + Amass + OneForAll（并行）
- 输出：去重后的子域名列表

### 2. validate_subdomains
- 功能：子域名存活验证
- 工具链：DNSx（批量解析 + CNAME 提取）
- 输出：存活子域名 + CNAME 记录

### 3. detect_takeover
- 功能：子域接管检测
- 工具链：CNAME 过滤 + httpx 验证 + 特征匹配
- 输出：可接管的子域名列表
- 合规性：仅被动检测，不尝试接管

### 4. scan_ports
- 功能：全面端口扫描
- 工具链：Masscan（盲扫） + Naabu（验证） + Nmap（指纹）
- 输出：开放端口 + 服务版本

### 5. probe_web
- 功能：Web 服务探测
- 工具链：httpx（存活 + 技术栈 + 服务器）
- 输出：Web 服务列表 + 技术栈统计

### 6. collect_intel
- 功能：空间测绘情报收集
- 工具链：Fofa API + Shodan API（并行）
- 输出：公开情报资产
- 合规性：仅查询公开数据，不主动扫描

## 决策规则

### 标准侦察流程
1. collect_subdomains → 收集子域名
2. validate_subdomains → 验证存活
3. detect_takeover → 检测子域接管（如果有 CNAME）
4. scan_ports → 扫描开放端口（对存活 IP）
5. probe_web → 探测 Web 服务（对 80/443/8080 等端口）
6. collect_intel → 补充空间测绘情报（可选）
7. finish → 生成报告

### 自适应策略
- 如果子域名数量 > 500，优先验证存活再扫描端口
- 如果发现大量 CNAME，立即执行子域接管检测
- 如果开放端口 < 10，跳过 Nmap 深度指纹
- 如果 Web 服务 > 100，分批探测

### 深度探测触发条件
- 发现敏感端口（22/3306/6379/27017）→ 记录到漏洞线索
- 发现管理后台（/admin, /login, /console）→ 记录到漏洞线索
- 发现过时技术栈（Apache 2.2, PHP 5.x）→ 记录到漏洞线索

## 输出格式（JSON）
{
  "action": "collect_subdomains",
  "reasoning": "开始侦察，首先收集子域名",
  "parameters": {}
}

## 关键原则
- 永远不要直接调用 Tool，只调用 Skill
- 每次决策都要基于当前的资产图谱状态
- 发现异常或高价值目标时，调整优先级
- 保持侦察的隐蔽性（不触发 WAF/IDS）`

// ── Recon Agent 实现 ─────────────────────────────────────────

export class ReconAgent {
  private config: ReconAgentConfig
  private client: OpenAI
  private assetGraph: AssetGraph
  private executionLog: Array<{
    iteration: number
    decision: ReconDecision
    skillResult: SkillResult<any>
    timestamp: number
  }>

  constructor(config: ReconAgentConfig) {
    this.config = config
    this.client = new OpenAI({
      apiKey: config.apiKey,
      baseURL: config.baseURL,
    })

    // 初始化资产图谱
    this.assetGraph = {
      rootDomain: config.target,
      subdomains: [],
      ips: [],
      webServices: [],
      vulnerabilities: [],
      stats: {
        totalSubdomains: 0,
        aliveSubdomains: 0,
        totalIPs: 0,
        totalPorts: 0,
        totalWebServices: 0,
        totalVulnerabilities: 0,
      },
    }

    this.executionLog = []
  }

  /**
   * 执行侦察任务
   */
  async execute(): Promise<AssetGraph> {
    const maxIterations = this.config.maxIterations || 20
    let iteration = 0

    console.log(`[Recon Agent] 开始侦察: ${this.config.target}`)
    console.log(`[Recon Agent] Session: ${this.config.sessionDir}`)

    while (iteration < maxIterations) {
      iteration++
      console.log(`\n[Recon Agent] 迭代 ${iteration}/${maxIterations}`)

      // 决策下一步行动
      const decision = await this.makeDecision()
      console.log(`[Recon Agent] 决策: ${decision.action}`)
      console.log(`[Recon Agent] 推理: ${decision.reasoning}`)

      // 执行完成
      if (decision.action === 'finish') {
        console.log(`[Recon Agent] 侦察完成`)
        break
      }

      // 执行 Skill
      const skillResult = await this.executeSkill(decision)
      console.log(`[Recon Agent] Skill 执行: ${skillResult.success ? '成功' : '失败'}`)
      console.log(`[Recon Agent] 耗时: ${(skillResult.duration / 1000).toFixed(1)}s`)

      // 更新资产图谱
      this.updateAssetGraph(decision.action, skillResult)

      // 记录执行日志
      this.executionLog.push({
        iteration,
        decision,
        skillResult,
        timestamp: Date.now(),
      })

      // 保存中间结果
      this.saveIntermediateResults()
    }

    // 生成最终报告
    this.generateReport()

    return this.assetGraph
  }

  /**
   * 决策下一步行动（LLM 驱动）
   */
  private async makeDecision(): Promise<ReconDecision> {
    // 构建状态摘要
    const stateSummary = this.buildStateSummary()

    // 构建执行历史
    const executionHistory = this.executionLog
      .slice(-5)
      .map(log => `[${log.decision.action}] ${log.decision.reasoning} → ${log.skillResult.success ? '成功' : '失败'}`)
      .join('\n')

    const userPrompt = `## 当前资产图谱状态
${stateSummary}

## 最近执行历史
${executionHistory || '（无）'}

## 任务
根据当前状态，决定下一步侦察行动。输出 JSON 格式的决策。`

    try {
      const response = await this.client.chat.completions.create({
        model: this.config.model,
        messages: [
          { role: 'system', content: RECON_AGENT_SYSTEM_PROMPT },
          { role: 'user', content: userPrompt },
        ],
        temperature: 0,
        max_tokens: 500,
        response_format: { type: 'json_object' },
      })

      const content = response.choices[0]?.message?.content?.trim() ?? '{}'
      const decision = JSON.parse(content) as ReconDecision

      return decision
    } catch (err) {
      // 降级决策
      return this.fallbackDecision()
    }
  }

  /**
   * 构建状态摘要
   */
  private buildStateSummary(): string {
    const { stats, subdomains, ips, webServices, vulnerabilities } = this.assetGraph

    const lines: string[] = []

    lines.push(`目标: ${this.config.target}`)
    lines.push(``)
    lines.push(`统计:`)
    lines.push(`  - 子域名: ${stats.totalSubdomains} 个（存活 ${stats.aliveSubdomains}）`)
    lines.push(`  - IP: ${stats.totalIPs} 个`)
    lines.push(`  - 开放端口: ${stats.totalPorts} 个`)
    lines.push(`  - Web 服务: ${stats.totalWebServices} 个`)
    lines.push(`  - 漏洞线索: ${stats.totalVulnerabilities} 个`)
    lines.push(``)

    if (subdomains.length > 0) {
      lines.push(`子域名样例（前5个）:`)
      for (const sub of subdomains.slice(0, 5)) {
        lines.push(`  - ${sub.subdomain} (${sub.alive ? '存活' : '死亡'})`)
      }
      lines.push(``)
    }

    if (ips.length > 0) {
      lines.push(`IP 样例（前5个）:`)
      for (const ip of ips.slice(0, 5)) {
        lines.push(`  - ${ip.ip} (${ip.ports.length} 个端口)`)
      }
      lines.push(``)
    }

    if (vulnerabilities.length > 0) {
      lines.push(`漏洞线索:`)
      for (const vuln of vulnerabilities.slice(0, 5)) {
        lines.push(`  - [${vuln.severity}] ${vuln.type} @ ${vuln.target}`)
      }
      lines.push(``)
    }

    return lines.join('\n')
  }

  /**
   * 降级决策（LLM 失败时）
   */
  private fallbackDecision(): ReconDecision {
    const { stats } = this.assetGraph

    // 简单的规则引擎
    if (stats.totalSubdomains === 0) {
      return {
        action: 'collect_subdomains',
        reasoning: '[降级决策] 尚未收集子域名',
      }
    }

    if (stats.aliveSubdomains === 0 && stats.totalSubdomains > 0) {
      return {
        action: 'validate_subdomains',
        reasoning: '[降级决策] 需要验证子域名存活',
      }
    }

    if (stats.totalPorts === 0 && stats.aliveSubdomains > 0) {
      return {
        action: 'scan_ports',
        reasoning: '[降级决策] 需要扫描端口',
      }
    }

    if (stats.totalWebServices === 0 && stats.totalPorts > 0) {
      return {
        action: 'probe_web',
        reasoning: '[降级决策] 需要探测 Web 服务',
      }
    }

    return {
      action: 'finish',
      reasoning: '[降级决策] 所有基础侦察已完成',
    }
  }

  /**
   * 执行 Skill
   */
  private async executeSkill(decision: ReconDecision): Promise<SkillResult<any>> {
    const { sessionDir } = this.config

    switch (decision.action) {
      case 'collect_subdomains':
        return await collectSubdomains(this.config.target, sessionDir)

      case 'validate_subdomains': {
        const subdomains = this.assetGraph.subdomains.map(s => s.subdomain)
        return await validateSubdomains(subdomains, sessionDir)
      }

      case 'detect_takeover': {
        const cnameRecords = this.assetGraph.subdomains
          .filter(s => s.cname)
          .map(s => ({ subdomain: s.subdomain, cname: s.cname! }))
        return await detectSubdomainTakeover(cnameRecords, sessionDir)
      }

      case 'scan_ports': {
        const targets = Array.from(new Set(this.assetGraph.subdomains.flatMap(s => s.ips)))
        return await scanPorts(targets, sessionDir)
      }

      case 'probe_web': {
        const targets = this.assetGraph.subdomains
          .filter(s => s.alive)
          .map(s => s.subdomain)
        return await probeWebServices(targets, sessionDir)
      }

      case 'collect_intel':
        return await collectSpaceIntel(
          this.config.target,
          this.config.fofaConfig,
          this.config.shodanConfig
        )

      default:
        return {
          success: false,
          data: null,
          steps: [],
          duration: 0,
          skill: 'unknown',
        }
    }
  }

  /**
   * 更新资产图谱
   */
  private updateAssetGraph(action: string, skillResult: SkillResult<any>): void {
    if (!skillResult.success) return

    switch (action) {
      case 'collect_subdomains': {
        const data = skillResult.data as SubdomainCollectionResult
        for (const sub of data.subdomains) {
          this.assetGraph.subdomains.push({
            subdomain: sub.subdomain,
            ips: [],
            alive: false,
            source: sub.source,
          })
        }
        this.assetGraph.stats.totalSubdomains = data.uniqueCount
        break
      }

      case 'validate_subdomains': {
        const data = skillResult.data as SubdomainValidationResult
        for (const dns of data.alive) {
          const existing = this.assetGraph.subdomains.find(s => s.subdomain === dns.subdomain)
          if (existing) {
            existing.ips = dns.ips
            existing.cname = dns.cname
            existing.alive = true
          }
        }
        this.assetGraph.stats.aliveSubdomains = data.alive.length
        break
      }

      case 'detect_takeover': {
        const data = skillResult.data as SubdomainTakeoverResult
        for (const vuln of data.vulnerable) {
          this.assetGraph.vulnerabilities.push({
            type: 'subdomain_takeover',
            target: vuln.subdomain,
            severity: 'high',
            evidence: vuln.evidence,
          })
        }
        this.assetGraph.stats.totalVulnerabilities += data.vulnerable.length
        break
      }

      case 'scan_ports': {
        const data = skillResult.data as PortScanResult
        for (const port of data.ports) {
          let ipEntry = this.assetGraph.ips.find(i => i.ip === port.ip)
          if (!ipEntry) {
            ipEntry = { ip: port.ip, ports: [] }
            this.assetGraph.ips.push(ipEntry)
          }
          ipEntry.ports.push({
            port: port.port,
            protocol: port.protocol,
            service: port.service,
            version: port.version,
          })
        }
        this.assetGraph.stats.totalIPs = data.uniqueIPs.length
        this.assetGraph.stats.totalPorts = data.openPortCount
        break
      }

      case 'probe_web': {
        const data = skillResult.data as WebProbeSkillResult
        for (const web of data.webServices) {
          this.assetGraph.webServices.push({
            url: web.url,
            statusCode: web.statusCode,
            title: web.title,
            technologies: web.technologies,
            server: web.server,
          })
        }
        this.assetGraph.stats.totalWebServices = data.aliveCount
        break
      }

      case 'collect_intel': {
        const data = skillResult.data as SpaceIntelResult
        for (const asset of data.assets) {
          let ipEntry = this.assetGraph.ips.find(i => i.ip === asset.ip)
          if (!ipEntry) {
            ipEntry = { ip: asset.ip, ports: [], country: asset.country, org: asset.org }
            this.assetGraph.ips.push(ipEntry)
          }
          ipEntry.ports.push({
            port: asset.port,
            protocol: asset.protocol,
            service: asset.service,
          })
        }
        break
      }
    }
  }

  /**
   * 保存中间结果
   */
  private saveIntermediateResults(): void {
    const outputFile = join(this.config.sessionDir, 'recon_asset_graph.json')
    writeFileSync(outputFile, JSON.stringify(this.assetGraph, null, 2), 'utf8')
  }

  /**
   * 生成最终报告
   */
  private generateReport(): void {
    const reportFile = join(this.config.sessionDir, 'recon_report.md')

    const lines: string[] = []

    lines.push(`# 侦察报告`)
    lines.push(``)
    lines.push(`目标: ${this.config.target}`)
    lines.push(`时间: ${new Date().toISOString()}`)
    lines.push(``)

    lines.push(`## 统计摘要`)
    lines.push(``)
    lines.push(`| 类型 | 数量 |`)
    lines.push(`|------|------|`)
    lines.push(`| 子域名 | ${this.assetGraph.stats.totalSubdomains} |`)
    lines.push(`| 存活子域名 | ${this.assetGraph.stats.aliveSubdomains} |`)
    lines.push(`| IP 地址 | ${this.assetGraph.stats.totalIPs} |`)
    lines.push(`| 开放端口 | ${this.assetGraph.stats.totalPorts} |`)
    lines.push(`| Web 服务 | ${this.assetGraph.stats.totalWebServices} |`)
    lines.push(`| 漏洞线索 | ${this.assetGraph.stats.totalVulnerabilities} |`)
    lines.push(``)

    if (this.assetGraph.vulnerabilities.length > 0) {
      lines.push(`## 漏洞线索`)
      lines.push(``)
      for (const vuln of this.assetGraph.vulnerabilities) {
        lines.push(`### [${vuln.severity.toUpperCase()}] ${vuln.type}`)
        lines.push(`- 目标: ${vuln.target}`)
        lines.push(`- 证据: ${vuln.evidence}`)
        lines.push(``)
      }
    }

    lines.push(`## 子域名列表`)
    lines.push(``)
    for (const sub of this.assetGraph.subdomains.filter(s => s.alive)) {
      lines.push(`- ${sub.subdomain} → ${sub.ips.join(', ')}`)
    }
    lines.push(``)

    lines.push(`## Web 服务列表`)
    lines.push(``)
    for (const web of this.assetGraph.webServices) {
      lines.push(`- ${web.url} [${web.statusCode}] ${web.title || ''}`)
      if (web.technologies.length > 0) {
        lines.push(`  - 技术栈: ${web.technologies.join(', ')}`)
      }
    }

    writeFileSync(reportFile, lines.join('\n'), 'utf8')
    console.log(`[Recon Agent] 报告已生成: ${reportFile}`)
  }
}
