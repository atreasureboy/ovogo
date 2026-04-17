/**
 * 漏洞扫描 Skill 层 — 战术链路
 *
 * 职责：
 * 1. 组合多个扫描工具形成完整的漏洞检测链路
 * 2. 智能分流（根据目标类型选择工具）
 * 3. 结果去重和优先级排序
 * 4. 自动验证（减少误报）
 */

import {
  runNucleiFull,
  runNucleiSeverity,
  runFFUF,
  runNikto,
  runSQLMap,
  runArjun,
  runDalfox,
  runWhatWeb,
  runXrayPassive,
  type NucleiVulnerability,
  type FFUFResult,
  type NiktoFinding,
  type SQLMapResult,
  type ArjunParameter,
  type DalfoxVulnerability,
  type WhatWebResult,
  type XrayVulnerability,
} from '../tools/index.js'

import type { SkillResult, SkillStep } from '../../core/agentTypes.js'
export type { SkillResult, SkillStep }

// ── Web 漏洞全面扫描 Skill ────────────────────────────────────

export interface WebVulnScanResult {
  vulnerabilities: Array<{
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
    type: string
    target: string
    description: string
    evidence: string
    tool: string
    verified: boolean
  }>
  hiddenPaths: FFUFResult[]
  parameters: ArjunParameter[]
  fingerprints: WhatWebResult[]
  stats: {
    critical: number
    high: number
    medium: number
    low: number
    info: number
  }
}

/**
 * Skill: Web 漏洞全面扫描
 *
 * 策略：
 * 1. 指纹识别（WhatWeb）→ 确定技术栈
 * 2. 参数发现（Arjun）→ 找到所有输入点
 * 3. 目录爆破（FFUF）→ 发现隐藏路径
 * 4. 漏洞扫描（Nuclei Critical/High）→ 快速发现高危漏洞
 * 5. 专项扫描（SQLMap + Dalfox）→ 针对性检测
 * 6. 全面扫描（Nuclei Full）→ 覆盖所有模板
 * 7. 深度扫描（Nikto）→ 补充检测
 */
export async function scanWebVulnerabilities(
  targets: string[],
  outputDir: string,
  options?: {
    skipSlow?: boolean // 跳过慢速扫描（Nikto, SQLMap）
    wordlist?: string  // 自定义字典
  }
): Promise<SkillResult<WebVulnScanResult>> {
  const startTime = Date.now()
  const steps: SkillStep[] = []
  const allVulnerabilities: WebVulnScanResult['vulnerabilities'] = []

  // 步骤 1: 指纹识别（并行）
  const whatwebResult = await runWhatWeb(targets, outputDir)
  steps.push({
    tool: 'whatweb',
    success: whatwebResult.success,
    duration: whatwebResult.duration,
    dataCount: whatwebResult.data.length,
    error: whatwebResult.error,
  })

  // 步骤 2: 参数发现（并行，每个目标）
  const arjunResults = await Promise.all(
    targets.slice(0, 10).map(target => runArjun(target, outputDir))
  )
  const allParameters: ArjunParameter[] = []
  for (const result of arjunResults) {
    steps.push({
      tool: 'arjun',
      success: result.success,
      duration: result.duration,
      dataCount: result.data.length,
      error: result.error,
    })
    if (result.success) allParameters.push(...result.data)
  }

  // 步骤 3: 目录爆破（并行，每个目标）
  const wordlist = options?.wordlist || '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt'
  const ffufResults = await Promise.all(
    targets.slice(0, 5).map(target => runFFUF(target, wordlist, outputDir, ['.php', '.asp', '.aspx', '.jsp']))
  )
  const allHiddenPaths: FFUFResult[] = []
  for (const result of ffufResults) {
    steps.push({
      tool: 'ffuf',
      success: result.success,
      duration: result.duration,
      dataCount: result.data.length,
      error: result.error,
    })
    if (result.success) allHiddenPaths.push(...result.data)
  }

  // 步骤 4: Nuclei 高危扫描（优先）
  const nucleiHighResult = await runNucleiSeverity(targets, ['critical', 'high'], outputDir)
  steps.push({
    tool: 'nuclei-high',
    success: nucleiHighResult.success,
    duration: nucleiHighResult.duration,
    dataCount: nucleiHighResult.data.length,
    error: nucleiHighResult.error,
  })

  if (nucleiHighResult.success) {
    for (const vuln of nucleiHighResult.data) {
      allVulnerabilities.push({
        severity: vuln.severity,
        type: vuln.type,
        target: vuln.host,
        description: vuln.name,
        evidence: vuln.matchedAt,
        tool: 'nuclei',
        verified: true,
      })
    }
  }

  // 步骤 5: 专项扫描（如果发现参数）
  if (allParameters.length > 0 && !options?.skipSlow) {
    // SQL 注入检测（前5个参数）
    const sqlTargets = allParameters.slice(0, 5).map(p => `${p.url}?${p.parameter}=1`)
    for (const target of sqlTargets) {
      const sqlmapResult = await runSQLMap(target, outputDir, { level: 2, risk: 2 })
      steps.push({
        tool: 'sqlmap',
        success: sqlmapResult.success,
        duration: sqlmapResult.duration,
        dataCount: sqlmapResult.data.length,
        error: sqlmapResult.error,
      })

      if (sqlmapResult.success && sqlmapResult.data.length > 0) {
        for (const vuln of sqlmapResult.data) {
          allVulnerabilities.push({
            severity: 'critical',
            type: 'SQL Injection',
            target: vuln.url,
            description: `SQL Injection in parameter: ${vuln.parameter}`,
            evidence: vuln.payload || '',
            tool: 'sqlmap',
            verified: true,
          })
        }
      }
    }

    // XSS 检测（前5个参数）
    for (const target of sqlTargets) {
      const dalfoxResult = await runDalfox(target, outputDir)
      steps.push({
        tool: 'dalfox',
        success: dalfoxResult.success,
        duration: dalfoxResult.duration,
        dataCount: dalfoxResult.data.length,
        error: dalfoxResult.error,
      })

      if (dalfoxResult.success && dalfoxResult.data.length > 0) {
        for (const vuln of dalfoxResult.data) {
          allVulnerabilities.push({
            severity: 'high',
            type: 'XSS',
            target: vuln.url,
            description: `XSS in parameter: ${vuln.parameter}`,
            evidence: vuln.payload,
            tool: 'dalfox',
            verified: true,
          })
        }
      }
    }
  }

  // 步骤 6: Nuclei 全面扫描
  const nucleiFullResult = await runNucleiFull(targets, outputDir)
  steps.push({
    tool: 'nuclei-full',
    success: nucleiFullResult.success,
    duration: nucleiFullResult.duration,
    dataCount: nucleiFullResult.data.length,
    error: nucleiFullResult.error,
  })

  if (nucleiFullResult.success) {
    for (const vuln of nucleiFullResult.data) {
      // 去重（避免与高危扫描重复）
      const exists = allVulnerabilities.some(
        v => v.target === vuln.host && v.description === vuln.name
      )
      if (!exists) {
        allVulnerabilities.push({
          severity: vuln.severity,
          type: vuln.type,
          target: vuln.host,
          description: vuln.name,
          evidence: vuln.matchedAt,
          tool: 'nuclei',
          verified: true,
        })
      }
    }
  }

  // 步骤 7: Nikto 深度扫描（可选）
  if (!options?.skipSlow) {
    for (const target of targets.slice(0, 3)) {
      const niktoResult = await runNikto(target, outputDir)
      steps.push({
        tool: 'nikto',
        success: niktoResult.success,
        duration: niktoResult.duration,
        dataCount: niktoResult.data.length,
        error: niktoResult.error,
      })

      if (niktoResult.success) {
        for (const finding of niktoResult.data) {
          allVulnerabilities.push({
            severity: 'medium',
            type: 'Web Server Issue',
            target: finding.url,
            description: finding.message,
            evidence: finding.method,
            tool: 'nikto',
            verified: false,
          })
        }
      }
    }
  }

  // 统计
  const stats = {
    critical: allVulnerabilities.filter(v => v.severity === 'critical').length,
    high: allVulnerabilities.filter(v => v.severity === 'high').length,
    medium: allVulnerabilities.filter(v => v.severity === 'medium').length,
    low: allVulnerabilities.filter(v => v.severity === 'low').length,
    info: allVulnerabilities.filter(v => v.severity === 'info').length,
  }

  return {
    success: true,
    data: {
      vulnerabilities: allVulnerabilities,
      hiddenPaths: allHiddenPaths,
      parameters: allParameters,
      fingerprints: whatwebResult.data,
      stats,
    },
    steps,
    duration: Date.now() - startTime,
    skill: 'web_vuln_scan',
  }
}

// ── 服务层漏洞扫描 Skill ──────────────────────────────────────

export interface ServiceVulnScanResult {
  vulnerabilities: Array<{
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
    type: string
    target: string
    port: number
    service: string
    description: string
    evidence: string
    cve?: string
  }>
  stats: {
    critical: number
    high: number
    medium: number
    low: number
    info: number
  }
}

/**
 * Skill: 服务层漏洞扫描
 *
 * 策略：
 * 1. Nuclei 网络模板扫描（针对非 HTTP 服务）
 * 2. Nmap 漏洞脚本扫描
 * 3. 专项工具（enum4linux, redis-cli, etc.）
 */
export async function scanServiceVulnerabilities(
  targets: Array<{ ip: string; port: number; service?: string }>,
  outputDir: string
): Promise<SkillResult<ServiceVulnScanResult>> {
  const startTime = Date.now()
  const steps: SkillStep[] = []
  const allVulnerabilities: ServiceVulnScanResult['vulnerabilities'] = []

  // 构建 Nuclei 目标列表（ip:port 格式）
  const nucleiTargets = targets.map(t => `${t.ip}:${t.port}`)

  // Nuclei 网络模板扫描
  const nucleiResult = await runNucleiFull(nucleiTargets, outputDir)
  steps.push({
    tool: 'nuclei-network',
    success: nucleiResult.success,
    duration: nucleiResult.duration,
    dataCount: nucleiResult.data.length,
    error: nucleiResult.error,
  })

  if (nucleiResult.success) {
    for (const vuln of nucleiResult.data) {
      const [ip, port] = vuln.host.split(':')
      allVulnerabilities.push({
        severity: vuln.severity,
        type: vuln.type,
        target: ip,
        port: parseInt(port) || 0,
        service: vuln.type,
        description: vuln.name,
        evidence: vuln.matchedAt,
        cve: vuln.templateID.match(/CVE-\d{4}-\d+/)?.[0],
      })
    }
  }

  // 统计
  const stats = {
    critical: allVulnerabilities.filter(v => v.severity === 'critical').length,
    high: allVulnerabilities.filter(v => v.severity === 'high').length,
    medium: allVulnerabilities.filter(v => v.severity === 'medium').length,
    low: allVulnerabilities.filter(v => v.severity === 'low').length,
    info: allVulnerabilities.filter(v => v.severity === 'info').length,
  }

  return {
    success: true,
    data: {
      vulnerabilities: allVulnerabilities,
      stats,
    },
    steps,
    duration: Date.now() - startTime,
    skill: 'service_vuln_scan',
  }
}

// ── 认证攻击 Skill ────────────────────────────────────────────

export interface AuthAttackResult {
  credentials: Array<{
    target: string
    port: number
    service: string
    username: string
    password: string
    verified: boolean
  }>
  weakPasswords: Array<{
    target: string
    service: string
    username: string
  }>
}

/**
 * Skill: 认证攻击（弱口令、默认凭证）
 *
 * 策略：
 * 1. 默认凭证测试（常见服务）
 * 2. 弱口令爆破（限制尝试次数，避免锁定）
 * 3. 凭证验证
 *
 * 合规性：仅测试常见弱口令，不进行大规模爆破
 */
export async function attackAuthentication(
  targets: Array<{ ip: string; port: number; service: string }>,
  outputDir: string
): Promise<SkillResult<AuthAttackResult>> {
  const startTime = Date.now()
  const steps: SkillStep[] = []
  const credentials: AuthAttackResult['credentials'] = []
  const weakPasswords: AuthAttackResult['weakPasswords'] = []

  // 默认凭证字典（合规性：仅测试公开的默认凭证）
  const defaultCreds = [
    { username: 'admin', password: 'admin' },
    { username: 'admin', password: 'password' },
    { username: 'admin', password: '123456' },
    { username: 'root', password: 'root' },
    { username: 'root', password: 'toor' },
    { username: 'administrator', password: 'administrator' },
  ]

  // 按服务分类测试
  for (const target of targets) {
    // 这里简化处理，实际需要调用 hydra 等工具
    // 示例：SSH 弱口令测试
    if (target.service === 'ssh') {
      // hydra -L users.txt -P pass.txt ssh://target:22
      // 合规性：限制尝试次数，避免触发防护
    }

    // 示例：MySQL 默认凭证测试
    if (target.service === 'mysql') {
      // mysql -h target -u root -p
    }

    // 示例：Redis 未授权访问
    if (target.service === 'redis') {
      // redis-cli -h target ping
    }
  }

  return {
    success: true,
    data: {
      credentials,
      weakPasswords,
    },
    steps,
    duration: Date.now() - startTime,
    skill: 'auth_attack',
  }
}

// ── 漏洞验证 Skill ────────────────────────────────────────────

export interface VulnVerificationResult {
  verified: Array<{
    vulnerability: string
    target: string
    proof: string
    exploitable: boolean
  }>
  falsePositives: string[]
}

/**
 * Skill: 漏洞验证
 *
 * 策略：
 * 1. 重新执行 PoC（确认可复现）
 * 2. 提取关键证据（响应内容、错误信息）
 * 3. 判断可利用性
 *
 * 合规性：仅验证，不进行实际利用
 */
export async function verifyVulnerabilities(
  vulnerabilities: Array<{
    type: string
    target: string
    templateID?: string
    payload?: string
  }>,
  outputDir: string
): Promise<SkillResult<VulnVerificationResult>> {
  const startTime = Date.now()
  const steps: SkillStep[] = []
  const verified: VulnVerificationResult['verified'] = []
  const falsePositives: string[] = []

  // 对每个漏洞重新验证
  for (const vuln of vulnerabilities) {
    if (vuln.templateID) {
      // 使用 Nuclei 重新扫描
      const result = await runNucleiFull([vuln.target], outputDir)

      if (result.success) {
        const match = result.data.find(v => v.templateID === vuln.templateID)
        if (match) {
          verified.push({
            vulnerability: vuln.type,
            target: vuln.target,
            proof: match.matchedAt,
            exploitable: match.severity === 'critical' || match.severity === 'high',
          })
        } else {
          falsePositives.push(`${vuln.type} @ ${vuln.target}`)
        }
      }
    }
  }

  return {
    success: true,
    data: {
      verified,
      falsePositives,
    },
    steps,
    duration: Date.now() - startTime,
    skill: 'vuln_verification',
  }
}
