/**
 * Vuln-Scan Agent — 漏洞扫描智能体（指挥官级别）
 *
 * 职责：
 * 1. 理解侦察阶段的资产图谱
 * 2. 动态选择扫描策略（根据目标类型、数量、技术栈）
 * 3. 智能分流（Web 漏洞 vs 服务漏洞 vs 认证攻击）
 * 4. 漏洞去重、优先级排序、自动验证
 * 5. 生成结构化漏洞报告
 *
 * 特点：
 * - 不直接调用 Tool，只调用 Skill
 * - 具备完整的决策能力（LLM 驱动）
 * - 支持自适应扫描（根据中间结果调整策略）
 * - 合规性控制（避免破坏性测试）
 */

import OpenAI from 'openai'
import { writeFileSync } from 'fs'
import { join } from 'path'
import {
  scanWebVulnerabilities,
  scanServiceVulnerabilities,
  attackAuthentication,
  verifyVulnerabilities,
  type SkillResult,
  type WebVulnScanResult,
  type ServiceVulnScanResult,
  type AuthAttackResult,
  type VulnVerificationResult,
} from '../skills/index.js'

// ── Agent 漏洞图谱 ────────────────────────────────────────────

export interface VulnerabilityGraph {
  // 漏洞列表
  vulnerabilities: Array<{
    id: string
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
    type: string
    target: string
    port?: number
    description: string
    evidence: string
    tool: string
    verified: boolean
    exploitable: boolean
    cve?: string
    timestamp: number
  }>

  // 隐藏路径
  hiddenPaths: Array<{
    url: string
    status: number
    length: number
  }>

  // 参数列表
  parameters: Array<{
    url: string
    parameter: string
    type: string
  }>

  // 凭证
  credentials: Array<{
    target: string
    service: string
    username: string
    password: string
    verified: boolean
  }>

  // 统计信息
  stats: {
    totalVulnerabilities: number
    critical: number
    high: number
    medium: number
    low: number
    info: number
    verified: number
    exploitable: number
  }
}

// ── Agent 决策输出 ────────────────────────────────────────────

export interface VulnScanDecision {
  action: 'scan_web' | 'scan_service' | 'attack_auth' | 'verify_vulns' | 'finish'
  reasoning: string
  parameters?: Record<string, unknown>
}

// ── Agent 配置 ────────────────────────────────────────────────

export interface VulnScanAgentConfig {
  apiKey: string
  baseURL?: string
  model: string
  sessionDir: string
  // 侦察阶段的输入
  assetGraph: {
    webServices: Array<{ url: string; technologies: string[] }>
    ips: Array<{ ip: string; ports: Array<{ port: number; service?: string }> }>
  }
  maxIterations?: number
  skipSlow?: boolean // 跳过慢速扫描
}

// ── Agent 系统 Prompt ─────────────────────────────────────────

const VULN_SCAN_AGENT_SYSTEM_PROMPT = `你是一个红队漏洞扫描智能体（Vuln-Scan Agent），具备战略级别的漏洞发现能力。

## 核心职责
1. 全面扫描目标漏洞（Web 漏洞、服务漏洞、认证漏洞）
2. 构建完整的漏洞图谱（Vulnerability Graph）
3. 优先发现高危可利用漏洞
4. 自动验证和去重

## 可用的 Skill（战术链路）

### 1. scan_web
- 功能：Web 漏洞全面扫描
- 工具链：WhatWeb（指纹） + Arjun（参数） + FFUF（目录） + Nuclei（漏洞） + SQLMap（SQL注入） + Dalfox（XSS） + Nikto（深度）
- 输出：Web 漏洞列表 + 隐藏路径 + 参数列表
- 适用：HTTP/HTTPS 服务

### 2. scan_service
- 功能：服务层漏洞扫描
- 工具链：Nuclei 网络模板 + Nmap 漏洞脚本
- 输出：服务漏洞列表
- 适用：非 HTTP 服务（SSH, MySQL, Redis, SMB 等）

### 3. attack_auth
- 功能：认证攻击（弱口令、默认凭证）
- 工具链：默认凭证测试 + 弱口令爆破（限制尝试）
- 输出：有效凭证列表
- 合规性：仅测试常见弱口令，不大规模爆破

### 4. verify_vulns
- 功能：漏洞验证
- 工具链：重新执行 PoC + 证据提取
- 输出：已验证漏洞 + 误报列表
- 合规性：仅验证，不实际利用

## 决策规则

### 标准扫描流程
1. scan_web → 扫描所有 Web 服务
2. scan_service → 扫描所有非 HTTP 服务
3. attack_auth → 测试认证漏洞（如果发现登录接口）
4. verify_vulns → 验证高危漏洞
5. finish → 生成报告

### 自适应策略
- 如果 Web 服务 > 50，分批扫描（每批 10 个）
- 如果发现 Critical 漏洞，立即验证
- 如果发现登录接口（/login, /admin），立即测试弱口令
- 如果发现敏感服务（Redis, MongoDB），优先扫描

### 优先级规则
- Critical 漏洞 > High 漏洞 > 认证漏洞 > Medium 漏洞
- RCE > SQL 注入 > 文件上传 > XSS > 信息泄露
- 已验证 > 未验证

## 输出格式（JSON）
{
  "action": "scan_web",
  "reasoning": "开始扫描，优先扫描 Web 服务",
  "parameters": { "targets": [...] }
}

## 关键原则
- 永远不要直接调用 Tool，只调用 Skill
- 每次决策都要基于当前的漏洞图谱状态
- 发现 Critical 漏洞立即验证
- 保持扫描的隐蔽性（避免触发 WAF/IDS）
- 合规性优先（不进行破坏性测试）`

// ── Vuln-Scan Agent 实现 ─────────────────────────────────────

export class VulnScanAgent {
  private config: VulnScanAgentConfig
  private client: OpenAI
  private vulnGraph: VulnerabilityGraph
  private executionLog: Array<{
    iteration: number
    decision: VulnScanDecision
    skillResult: SkillResult<any>
    timestamp: number
  }>

  constructor(config: VulnScanAgentConfig) {
    this.config = config
    this.client = new OpenAI({
      apiKey: config.apiKey,
      baseURL: config.baseURL,
    })

    // 初始化漏洞图谱
    this.vulnGraph = {
      vulnerabilities: [],
      hiddenPaths: [],
      parameters: [],
      credentials: [],
      stats: {
        totalVulnerabilities: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        verified: 0,
        exploitable: 0,
      },
    }

    this.executionLog = []
  }

  /**
   * 执行漏洞扫描任务
   */
  async execute(): Promise<VulnerabilityGraph> {
    const maxIterations = this.config.maxIterations || 15
    let iteration = 0

    console.log(`[Vuln-Scan Agent] 开始漏洞扫描`)
    console.log(`[Vuln-Scan Agent] Web 服务: ${this.config.assetGraph.webServices.length} 个`)
    console.log(`[Vuln-Scan Agent] IP 地址: ${this.config.assetGraph.ips.length} 个`)

    while (iteration < maxIterations) {
      iteration++
      console.log(`\n[Vuln-Scan Agent] 迭代 ${iteration}/${maxIterations}`)

      // 决策下一步行动
      const decision = await this.makeDecision()
      console.log(`[Vuln-Scan Agent] 决策: ${decision.action}`)
      console.log(`[Vuln-Scan Agent] 推理: ${decision.reasoning}`)

      // 执行完成
      if (decision.action === 'finish') {
        console.log(`[Vuln-Scan Agent] 扫描完成`)
        break
      }

      // 执行 Skill
      const skillResult = await this.executeSkill(decision)
      console.log(`[Vuln-Scan Agent] Skill 执行: ${skillResult.success ? '成功' : '失败'}`)
      console.log(`[Vuln-Scan Agent] 耗时: ${(skillResult.duration / 1000).toFixed(1)}s`)

      // 更新漏洞图谱
      this.updateVulnGraph(decision.action, skillResult)

      // 记录执行日志
      this.executionLog.push({
        iteration,
        decision,
        skillResult,
        timestamp: Date.now(),
      })

      // 保存中间结果
      this.saveIntermediateResults()

      // 如果发现 Critical 漏洞，立即验证
      if (this.vulnGraph.stats.critical > 0 && decision.action !== 'verify_vulns') {
        console.log(`[Vuln-Scan Agent] 发现 ${this.vulnGraph.stats.critical} 个 Critical 漏洞，准备验证`)
      }
    }

    // 生成最终报告
    this.generateReport()

    return this.vulnGraph
  }

  /**
   * 决策下一步行动（LLM 驱动）
   */
  private async makeDecision(): Promise<VulnScanDecision> {
    const stateSummary = this.buildStateSummary()
    const executionHistory = this.executionLog
      .slice(-5)
      .map(log => `[${log.decision.action}] ${log.decision.reasoning} → ${log.skillResult.success ? '成功' : '失败'}`)
      .join('\n')

    const userPrompt = `## 当前漏洞图谱状态
${stateSummary}

## 最近执行历史
${executionHistory || '（无）'}

## 任务
根据当前状态，决定下一步扫描行动。输出 JSON 格式的决策。`

    try {
      const response = await this.client.chat.completions.create({
        model: this.config.model,
        messages: [
          { role: 'system', content: VULN_SCAN_AGENT_SYSTEM_PROMPT },
          { role: 'user', content: userPrompt },
        ],
        temperature: 0,
        max_tokens: 500,
        response_format: { type: 'json_object' },
      })

      const content = response.choices[0]?.message?.content?.trim() ?? '{}'
      const decision = JSON.parse(content) as VulnScanDecision

      return decision
    } catch (err) {
      return this.fallbackDecision()
    }
  }

  /**
   * 构建状态摘要
   */
  private buildStateSummary(): string {
    const { stats, vulnerabilities, hiddenPaths, parameters, credentials } = this.vulnGraph
    const { webServices, ips } = this.config.assetGraph

    const lines: string[] = []

    lines.push(`输入资产:`)
    lines.push(`  - Web 服务: ${webServices.length} 个`)
    lines.push(`  - IP 地址: ${ips.length} 个`)
    lines.push(``)

    lines.push(`扫描进度:`)
    lines.push(`  - 漏洞: ${stats.totalVulnerabilities} 个`)
    lines.push(`    - Critical: ${stats.critical}`)
    lines.push(`    - High: ${stats.high}`)
    lines.push(`    - Medium: ${stats.medium}`)
    lines.push(`    - Low: ${stats.low}`)
    lines.push(`  - 已验证: ${stats.verified} 个`)
    lines.push(`  - 可利用: ${stats.exploitable} 个`)
    lines.push(`  - 隐藏路径: ${hiddenPaths.length} 个`)
    lines.push(`  - 参数: ${parameters.length} 个`)
    lines.push(`  - 凭证: ${credentials.length} 个`)
    lines.push(``)

    if (vulnerabilities.length > 0) {
      lines.push(`漏洞样例（前5个）:`)
      for (const vuln of vulnerabilities.slice(0, 5)) {
        lines.push(`  - [${vuln.severity.toUpperCase()}] ${vuln.type} @ ${vuln.target}`)
      }
      lines.push(``)
    }

    return lines.join('\n')
  }

  /**
   * 降级决策
   */
  private fallbackDecision(): VulnScanDecision {
    const { stats } = this.vulnGraph
    const { webServices, ips } = this.config.assetGraph

    // 简单的规则引擎
    if (stats.totalVulnerabilities === 0 && webServices.length > 0) {
      return {
        action: 'scan_web',
        reasoning: '[降级决策] 尚未扫描 Web 服务',
      }
    }

    if (stats.totalVulnerabilities > 0 && stats.verified === 0 && stats.critical > 0) {
      return {
        action: 'verify_vulns',
        reasoning: '[降级决策] 需要验证 Critical 漏洞',
      }
    }

    if (ips.length > 0 && stats.totalVulnerabilities < 10) {
      return {
        action: 'scan_service',
        reasoning: '[降级决策] 需要扫描服务层漏洞',
      }
    }

    return {
      action: 'finish',
      reasoning: '[降级决策] 所有扫描已完成',
    }
  }

  /**
   * 执行 Skill
   */
  private async executeSkill(decision: VulnScanDecision): Promise<SkillResult<any>> {
    const { sessionDir, assetGraph, skipSlow } = this.config

    switch (decision.action) {
      case 'scan_web': {
        const targets = assetGraph.webServices.map(w => w.url)
        return await scanWebVulnerabilities(targets, sessionDir, { skipSlow })
      }

      case 'scan_service': {
        const targets = assetGraph.ips.flatMap(ip =>
          ip.ports.map(p => ({
            ip: ip.ip,
            port: p.port,
            service: p.service || 'unknown',
          }))
        )
        return await scanServiceVulnerabilities(targets, sessionDir)
      }

      case 'attack_auth': {
        const targets = assetGraph.ips.flatMap(ip =>
          ip.ports
            .filter(p => ['ssh', 'mysql', 'redis', 'ftp', 'telnet'].includes(p.service || ''))
            .map(p => ({
              ip: ip.ip,
              port: p.port,
              service: p.service || 'unknown',
            }))
        )
        return await attackAuthentication(targets, sessionDir)
      }

      case 'verify_vulns': {
        const criticalVulns = this.vulnGraph.vulnerabilities
          .filter(v => v.severity === 'critical' && !v.verified)
          .map(v => ({
            type: v.type,
            target: v.target,
            templateID: v.tool === 'nuclei' ? v.id : undefined,
          }))
        return await verifyVulnerabilities(criticalVulns, sessionDir)
      }

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
   * 更新漏洞图谱
   */
  private updateVulnGraph(action: string, skillResult: SkillResult<any>): void {
    if (!skillResult.success) return

    switch (action) {
      case 'scan_web': {
        const data = skillResult.data as WebVulnScanResult
        for (const vuln of data.vulnerabilities) {
          this.vulnGraph.vulnerabilities.push({
            id: `${vuln.tool}-${Date.now()}-${Math.random()}`,
            severity: vuln.severity,
            type: vuln.type,
            target: vuln.target,
            description: vuln.description,
            evidence: vuln.evidence,
            tool: vuln.tool,
            verified: vuln.verified,
            exploitable: vuln.severity === 'critical' || vuln.severity === 'high',
            timestamp: Date.now(),
          })
        }
        this.vulnGraph.hiddenPaths.push(...data.hiddenPaths)
        this.vulnGraph.parameters.push(...data.parameters)
        this.updateStats()
        break
      }

      case 'scan_service': {
        const data = skillResult.data as ServiceVulnScanResult
        for (const vuln of data.vulnerabilities) {
          this.vulnGraph.vulnerabilities.push({
            id: `service-${Date.now()}-${Math.random()}`,
            severity: vuln.severity,
            type: vuln.type,
            target: vuln.target,
            port: vuln.port,
            description: vuln.description,
            evidence: vuln.evidence,
            tool: 'nuclei',
            verified: true,
            exploitable: vuln.severity === 'critical',
            cve: vuln.cve,
            timestamp: Date.now(),
          })
        }
        this.updateStats()
        break
      }

      case 'attack_auth': {
        const data = skillResult.data as AuthAttackResult
        this.vulnGraph.credentials.push(...data.credentials)
        break
      }

      case 'verify_vulns': {
        const data = skillResult.data as VulnVerificationResult
        for (const verified of data.verified) {
          const vuln = this.vulnGraph.vulnerabilities.find(
            v => v.target === verified.target && v.type === verified.vulnerability
          )
          if (vuln) {
            vuln.verified = true
            vuln.exploitable = verified.exploitable
            vuln.evidence = verified.proof
          }
        }
        this.updateStats()
        break
      }
    }
  }

  /**
   * 更新统计信息
   */
  private updateStats(): void {
    const { vulnerabilities } = this.vulnGraph

    this.vulnGraph.stats = {
      totalVulnerabilities: vulnerabilities.length,
      critical: vulnerabilities.filter(v => v.severity === 'critical').length,
      high: vulnerabilities.filter(v => v.severity === 'high').length,
      medium: vulnerabilities.filter(v => v.severity === 'medium').length,
      low: vulnerabilities.filter(v => v.severity === 'low').length,
      info: vulnerabilities.filter(v => v.severity === 'info').length,
      verified: vulnerabilities.filter(v => v.verified).length,
      exploitable: vulnerabilities.filter(v => v.exploitable).length,
    }
  }

  /**
   * 保存中间结果
   */
  private saveIntermediateResults(): void {
    const outputFile = join(this.config.sessionDir, 'vuln_graph.json')
    writeFileSync(outputFile, JSON.stringify(this.vulnGraph, null, 2), 'utf8')
  }

  /**
   * 生成最终报告
   */
  private generateReport(): void {
    const reportFile = join(this.config.sessionDir, 'vuln_report.md')

    const lines: string[] = []

    lines.push(`# 漏洞扫描报告`)
    lines.push(``)
    lines.push(`时间: ${new Date().toISOString()}`)
    lines.push(``)

    lines.push(`## 统计摘要`)
    lines.push(``)
    lines.push(`| 严重程度 | 数量 |`)
    lines.push(`|---------|------|`)
    lines.push(`| Critical | ${this.vulnGraph.stats.critical} |`)
    lines.push(`| High | ${this.vulnGraph.stats.high} |`)
    lines.push(`| Medium | ${this.vulnGraph.stats.medium} |`)
    lines.push(`| Low | ${this.vulnGraph.stats.low} |`)
    lines.push(`| Info | ${this.vulnGraph.stats.info} |`)
    lines.push(`| **总计** | **${this.vulnGraph.stats.totalVulnerabilities}** |`)
    lines.push(``)
    lines.push(`- 已验证: ${this.vulnGraph.stats.verified} 个`)
    lines.push(`- 可利用: ${this.vulnGraph.stats.exploitable} 个`)
    lines.push(``)

    // Critical 漏洞详情
    const criticalVulns = this.vulnGraph.vulnerabilities.filter(v => v.severity === 'critical')
    if (criticalVulns.length > 0) {
      lines.push(`## Critical 漏洞`)
      lines.push(``)
      for (const vuln of criticalVulns) {
        lines.push(`### ${vuln.type}`)
        lines.push(`- 目标: ${vuln.target}`)
        lines.push(`- 描述: ${vuln.description}`)
        lines.push(`- 证据: ${vuln.evidence}`)
        lines.push(`- 已验证: ${vuln.verified ? '是' : '否'}`)
        lines.push(`- 可利用: ${vuln.exploitable ? '是' : '否'}`)
        if (vuln.cve) lines.push(`- CVE: ${vuln.cve}`)
        lines.push(``)
      }
    }

    // High 漏洞详情
    const highVulns = this.vulnGraph.vulnerabilities.filter(v => v.severity === 'high')
    if (highVulns.length > 0) {
      lines.push(`## High 漏洞`)
      lines.push(``)
      for (const vuln of highVulns.slice(0, 10)) {
        lines.push(`### ${vuln.type}`)
        lines.push(`- 目标: ${vuln.target}`)
        lines.push(`- 描述: ${vuln.description}`)
        lines.push(``)
      }
    }

    writeFileSync(reportFile, lines.join('\n'), 'utf8')
    console.log(`[Vuln-Scan Agent] 报告已生成: ${reportFile}`)
  }
}
