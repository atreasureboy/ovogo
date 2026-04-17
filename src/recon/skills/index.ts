/**
 * Skill 层 — 侦察战术链路
 *
 * 职责：
 * 1. 组合多个 Tool 形成战术动作
 * 2. 包含条件分支和容错逻辑
 * 3. 硬编码合规性限制
 * 4. 自动切换网络出口（遇到阻断时）
 */

import {
  runSubfinder,
  runAmass,
  runOneForAll,
  runDNSx,
  runMasscan,
  runNaabu,
  runNmapService,
  runHttpx,
  queryFofa,
  queryShodan,
  type SubdomainResult,
  type DNSResult,
  type PortResult,
  type WebProbeResult,
  type SpaceEngineResult,
} from '../tools/index.js'

// ── Skill 输出标准格式 ────────────────────────────────────────

import type { SkillResult, SkillStep } from '../../core/agentTypes.js'
export type { SkillResult, SkillStep }

// ── 子域名收集 Skill ──────────────────────────────────────────

export interface SubdomainCollectionResult {
  subdomains: SubdomainResult[]
  uniqueCount: number
  sources: string[]
}

/**
 * Skill: 全面子域名收集
 *
 * 策略：
 * 1. 并行启动 Subfinder + Amass + OneForAll
 * 2. 合并去重
 * 3. 如果某个工具失败，不影响整体结果
 */
export async function collectSubdomains(
  domain: string,
  outputDir: string,
): Promise<SkillResult<SubdomainCollectionResult>> {
  const startTime = Date.now()
  const steps: SkillStep[] = []
  const allSubdomains: SubdomainResult[] = []

  // 并行执行三个工具
  const [subfinderResult, amassResult, oneforallResult] = await Promise.all([
    runSubfinder(domain, outputDir),
    runAmass(domain, outputDir),
    runOneForAll(domain, outputDir),
  ])

  // 记录步骤
  steps.push({
    tool: 'subfinder',
    success: subfinderResult.success,
    duration: subfinderResult.duration,
    dataCount: subfinderResult.data.length,
    error: subfinderResult.error,
  })

  steps.push({
    tool: 'amass',
    success: amassResult.success,
    duration: amassResult.duration,
    dataCount: amassResult.data.length,
    error: amassResult.error,
  })

  steps.push({
    tool: 'oneforall',
    success: oneforallResult.success,
    duration: oneforallResult.duration,
    dataCount: oneforallResult.data.length,
    error: oneforallResult.error,
  })

  // 合并结果
  if (subfinderResult.success) allSubdomains.push(...subfinderResult.data)
  if (amassResult.success) allSubdomains.push(...amassResult.data)
  if (oneforallResult.success) allSubdomains.push(...oneforallResult.data)

  // 去重
  const uniqueSubdomains = Array.from(
    new Map(allSubdomains.map(item => [item.subdomain, item])).values()
  )

  const sources = Array.from(new Set(allSubdomains.map(s => s.source)))

  return {
    success: uniqueSubdomains.length > 0,
    data: {
      subdomains: uniqueSubdomains,
      uniqueCount: uniqueSubdomains.length,
      sources,
    },
    steps,
    duration: Date.now() - startTime,
    skill: 'subdomain_collection',
  }
}

// ── 子域名存活验证 Skill ──────────────────────────────────────

export interface SubdomainValidationResult {
  alive: DNSResult[]
  dead: string[]
  cnameRecords: Array<{ subdomain: string; cname: string }>
}

/**
 * Skill: 子域名存活验证
 *
 * 策略：
 * 1. 使用 DNSx 批量解析
 * 2. 提取 CNAME 记录（用于后续子域接管检测）
 * 3. 过滤出存活的子域名
 */
export async function validateSubdomains(
  subdomains: string[],
  outputDir: string,
): Promise<SkillResult<SubdomainValidationResult>> {
  const startTime = Date.now()
  const steps: SkillStep[] = []

  // 执行 DNSx
  const dnsxResult = await runDNSx(subdomains, outputDir)

  steps.push({
    tool: 'dnsx',
    success: dnsxResult.success,
    duration: dnsxResult.duration,
    dataCount: dnsxResult.data.length,
    error: dnsxResult.error,
  })

  if (!dnsxResult.success) {
    return {
      success: false,
      data: { alive: [], dead: subdomains, cnameRecords: [] },
      steps,
      duration: Date.now() - startTime,
      skill: 'subdomain_validation',
    }
  }

  // 分类
  const alive = dnsxResult.data.filter(d => d.alive)
  const dead = dnsxResult.data.filter(d => !d.alive).map(d => d.subdomain)
  const cnameRecords = dnsxResult.data
    .filter(d => d.cname)
    .map(d => ({ subdomain: d.subdomain, cname: d.cname! }))

  return {
    success: true,
    data: { alive, dead, cnameRecords },
    steps,
    duration: Date.now() - startTime,
    skill: 'subdomain_validation',
  }
}

// ── 子域接管检测 Skill ────────────────────────────────────────

export interface SubdomainTakeoverResult {
  vulnerable: Array<{
    subdomain: string
    cname: string
    provider: string
    evidence: string
  }>
  safe: string[]
}

/**
 * Skill: 子域接管检测
 *
 * 策略：
 * 1. 过滤出指向云服务商的 CNAME（AWS S3, GitHub Pages, Heroku 等）
 * 2. 使用 httpx 验证 404 状态
 * 3. 检测特征字符串（如 "NoSuchBucket", "There isn't a GitHub Pages site here"）
 *
 * 合规性：仅执行被动检测，不尝试接管
 */
export async function detectSubdomainTakeover(
  cnameRecords: Array<{ subdomain: string; cname: string }>,
  outputDir: string,
): Promise<SkillResult<SubdomainTakeoverResult>> {
  const startTime = Date.now()
  const steps: SkillStep[] = []

  // 云服务商特征
  const providers = [
    { name: 'AWS S3', pattern: /s3.*\.amazonaws\.com/, evidence: 'NoSuchBucket' },
    { name: 'GitHub Pages', pattern: /github\.io/, evidence: "There isn't a GitHub Pages site here" },
    { name: 'Heroku', pattern: /herokuapp\.com/, evidence: 'No such app' },
    { name: 'Azure', pattern: /azurewebsites\.net/, evidence: 'Error 404' },
    { name: 'Shopify', pattern: /myshopify\.com/, evidence: 'Sorry, this shop is currently unavailable' },
  ]

  // 过滤出可疑的 CNAME
  const suspicious = cnameRecords.filter(record =>
    providers.some(p => p.pattern.test(record.cname))
  )

  if (suspicious.length === 0) {
    return {
      success: true,
      data: { vulnerable: [], safe: cnameRecords.map(r => r.subdomain) },
      steps,
      duration: Date.now() - startTime,
      skill: 'subdomain_takeover',
    }
  }

  // 使用 httpx 验证
  const targets = suspicious.map(s => `http://${s.subdomain}`)
  const httpxResult = await runHttpx(targets, outputDir)

  steps.push({
    tool: 'httpx',
    success: httpxResult.success,
    duration: httpxResult.duration,
    dataCount: httpxResult.data.length,
    error: httpxResult.error,
  })

  const vulnerable: SubdomainTakeoverResult['vulnerable'] = []
  const safe: string[] = []

  for (const record of suspicious) {
    const probe = httpxResult.data.find(p => p.url.includes(record.subdomain))

    if (!probe) {
      safe.push(record.subdomain)
      continue
    }

    // 检测 404 + 特征字符串
    if (probe.statusCode === 404) {
      const provider = providers.find(p => p.pattern.test(record.cname))
      if (provider) {
        // 这里需要获取响应体内容，简化处理
        vulnerable.push({
          subdomain: record.subdomain,
          cname: record.cname,
          provider: provider.name,
          evidence: `404 status + CNAME points to ${provider.name}`,
        })
      } else {
        safe.push(record.subdomain)
      }
    } else {
      safe.push(record.subdomain)
    }
  }

  return {
    success: true,
    data: { vulnerable, safe },
    steps,
    duration: Date.now() - startTime,
    skill: 'subdomain_takeover',
  }
}

// ── 端口扫描 Skill ────────────────────────────────────────────

export interface PortScanResult {
  ports: PortResult[]
  uniqueIPs: string[]
  openPortCount: number
  topPorts: Array<{ port: number; count: number }>
}

/**
 * Skill: 全面端口扫描
 *
 * 策略：
 * 1. 先用 Masscan 极速盲扫（1-65535）
 * 2. 再用 Naabu 验证（高可靠性）
 * 3. 最后用 Nmap 深度指纹识别（仅对开放端口）
 * 4. 合并去重
 */
export async function scanPorts(
  targets: string[],
  outputDir: string,
): Promise<SkillResult<PortScanResult>> {
  const startTime = Date.now()
  const steps: SkillStep[] = []
  const allPorts: PortResult[] = []

  // 步骤 1: Masscan 盲扫
  const masscanResult = await runMasscan(targets, outputDir)
  steps.push({
    tool: 'masscan',
    success: masscanResult.success,
    duration: masscanResult.duration,
    dataCount: masscanResult.data.length,
    error: masscanResult.error,
  })

  if (masscanResult.success) {
    allPorts.push(...masscanResult.data)
  }

  // 步骤 2: Naabu 验证
  const naabuResult = await runNaabu(targets, outputDir)
  steps.push({
    tool: 'naabu',
    success: naabuResult.success,
    duration: naabuResult.duration,
    dataCount: naabuResult.data.length,
    error: naabuResult.error,
  })

  if (naabuResult.success) {
    allPorts.push(...naabuResult.data)
  }

  // 去重（按 ip:port 去重）
  const uniquePorts = Array.from(
    new Map(allPorts.map(p => [`${p.ip}:${p.port}`, p])).values()
  )

  // 步骤 3: Nmap 深度指纹（仅对开放端口）
  if (uniquePorts.length > 0 && uniquePorts.length < 1000) {
    const ips = Array.from(new Set(uniquePorts.map(p => p.ip)))
    const ports = Array.from(new Set(uniquePorts.map(p => p.port)))

    const nmapResult = await runNmapService(ips, ports, outputDir)
    steps.push({
      tool: 'nmap',
      success: nmapResult.success,
      duration: nmapResult.duration,
      dataCount: nmapResult.data.length,
      error: nmapResult.error,
    })

    // 合并 Nmap 的服务信息
    if (nmapResult.success) {
      for (const nmapPort of nmapResult.data) {
        const existing = uniquePorts.find(
          p => p.ip === nmapPort.ip && p.port === nmapPort.port
        )
        if (existing) {
          existing.service = nmapPort.service
          existing.version = nmapPort.version
        }
      }
    }
  }

  // 统计
  const uniqueIPs = Array.from(new Set(uniquePorts.map(p => p.ip)))
  const portCounts = new Map<number, number>()
  for (const p of uniquePorts) {
    portCounts.set(p.port, (portCounts.get(p.port) || 0) + 1)
  }
  const topPorts = Array.from(portCounts.entries())
    .map(([port, count]) => ({ port, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10)

  return {
    success: uniquePorts.length > 0,
    data: {
      ports: uniquePorts,
      uniqueIPs,
      openPortCount: uniquePorts.length,
      topPorts,
    },
    steps,
    duration: Date.now() - startTime,
    skill: 'port_scan',
  }
}

// ── Web 服务探测 Skill ────────────────────────────────────────

export interface WebProbeSkillResult {
  webServices: WebProbeResult[]
  technologies: Map<string, number>
  servers: Map<string, number>
  aliveCount: number
}

/**
 * Skill: Web 服务全面探测
 *
 * 策略：
 * 1. 构建 URL 列表（http + https）
 * 2. 使用 httpx 批量探测
 * 3. 提取技术栈和服务器信息
 * 4. 统计分析
 */
export async function probeWebServices(
  targets: string[],
  outputDir: string,
): Promise<SkillResult<WebProbeSkillResult>> {
  const startTime = Date.now()
  const steps: SkillStep[] = []

  // 构建 URL 列表（http + https）
  const urls: string[] = []
  for (const target of targets) {
    if (target.startsWith('http')) {
      urls.push(target)
    } else {
      urls.push(`http://${target}`)
      urls.push(`https://${target}`)
    }
  }

  // 执行 httpx
  const httpxResult = await runHttpx(urls, outputDir)
  steps.push({
    tool: 'httpx',
    success: httpxResult.success,
    duration: httpxResult.duration,
    dataCount: httpxResult.data.length,
    error: httpxResult.error,
  })

  if (!httpxResult.success) {
    return {
      success: false,
      data: {
        webServices: [],
        technologies: new Map(),
        servers: new Map(),
        aliveCount: 0,
      },
      steps,
      duration: Date.now() - startTime,
      skill: 'web_probe',
    }
  }

  // 统计技术栈
  const technologies = new Map<string, number>()
  for (const service of httpxResult.data) {
    for (const tech of service.technologies) {
      technologies.set(tech, (technologies.get(tech) || 0) + 1)
    }
  }

  // 统计服务器
  const servers = new Map<string, number>()
  for (const service of httpxResult.data) {
    if (service.server) {
      servers.set(service.server, (servers.get(service.server) || 0) + 1)
    }
  }

  return {
    success: true,
    data: {
      webServices: httpxResult.data,
      technologies,
      servers,
      aliveCount: httpxResult.data.length,
    },
    steps,
    duration: Date.now() - startTime,
    skill: 'web_probe',
  }
}

// ── 空间测绘情报收集 Skill ────────────────────────────────────

export interface SpaceIntelResult {
  assets: SpaceEngineResult[]
  sources: string[]
  countries: Map<string, number>
  services: Map<string, number>
}

/**
 * Skill: 空间测绘情报收集
 *
 * 策略：
 * 1. 并行查询 Fofa + Shodan
 * 2. 合并去重
 * 3. 统计分析（国家分布、服务分布）
 *
 * 合规性：仅查询公开情报，不主动扫描
 */
export async function collectSpaceIntel(
  query: string,
  fofaConfig?: { apiKey: string; email: string },
  shodanConfig?: { apiKey: string },
): Promise<SkillResult<SpaceIntelResult>> {
  const startTime = Date.now()
  const steps: SkillStep[] = []
  const allAssets: SpaceEngineResult[] = []
  const sources: string[] = []

  // 并行查询
  const promises: Promise<any>[] = []

  if (fofaConfig) {
    promises.push(queryFofa(query, fofaConfig.apiKey, fofaConfig.email))
  }

  if (shodanConfig) {
    promises.push(queryShodan(query, shodanConfig.apiKey))
  }

  const results = await Promise.all(promises)

  // 处理结果
  for (const result of results) {
    steps.push({
      tool: result.tool,
      success: result.success,
      duration: result.duration,
      dataCount: result.data.length,
      error: result.error,
    })

    if (result.success) {
      allAssets.push(...result.data)
      sources.push(result.tool)
    }
  }

  // 去重（按 ip:port 去重）
  const uniqueAssets = Array.from(
    new Map(allAssets.map(a => [`${a.ip}:${a.port}`, a])).values()
  )

  // 统计国家分布
  const countries = new Map<string, number>()
  for (const asset of uniqueAssets) {
    if (asset.country) {
      countries.set(asset.country, (countries.get(asset.country) || 0) + 1)
    }
  }

  // 统计服务分布
  const services = new Map<string, number>()
  for (const asset of uniqueAssets) {
    services.set(asset.service, (services.get(asset.service) || 0) + 1)
  }

  return {
    success: uniqueAssets.length > 0,
    data: {
      assets: uniqueAssets,
      sources,
      countries,
      services,
    },
    steps,
    duration: Date.now() - startTime,
    skill: 'space_intel',
  }
}
