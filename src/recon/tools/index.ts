/**
 * Tool 层 — 原子工具定义
 *
 * 职责：
 * 1. 标准化所有工具的输出格式（统一JSON）
 * 2. 剥离终端字符、进度条、颜色代码
 * 3. 提供统一的错误处理
 * 4. 不包含任何业务逻辑
 */

import { exec } from 'child_process'
import { promisify } from 'util'
import { writeFileSync, readFileSync } from 'fs'
import { join } from 'path'

const execAsync = promisify(exec)

// ── 工具输出标准格式 ──────────────────────────────────────────

export interface ToolResult<T = unknown> {
  success: boolean
  data: T
  rawOutput?: string
  error?: string
  duration: number
  tool: string
}

// ── 子域名工具 ────────────────────────────────────────────────

export interface SubdomainResult {
  subdomain: string
  source: string
  timestamp: number
}

/**
 * Subfinder - 快速子域名枚举
 */
export async function runSubfinder(domain: string, outputDir: string): Promise<ToolResult<SubdomainResult[]>> {
  const startTime = Date.now()
  const outputFile = join(outputDir, 'subfinder.txt')

  try {
    const cmd = `subfinder -d ${domain} -all -recursive -o ${outputFile} -silent`
    const { stdout, stderr } = await execAsync(cmd, { timeout: 300000 })

    const subdomains = readFileSync(outputFile, 'utf8')
      .split('\n')
      .filter(line => line.trim())
      .map(subdomain => ({
        subdomain: subdomain.trim(),
        source: 'subfinder',
        timestamp: Date.now(),
      }))

    return {
      success: true,
      data: subdomains,
      rawOutput: stdout + stderr,
      duration: Date.now() - startTime,
      tool: 'subfinder',
    }
  } catch (err) {
    return {
      success: false,
      data: [],
      error: (err as Error).message,
      duration: Date.now() - startTime,
      tool: 'subfinder',
    }
  }
}

/**
 * Amass - 深度子域名枚举（OSINT + 主动）
 */
export async function runAmass(domain: string, outputDir: string): Promise<ToolResult<SubdomainResult[]>> {
  const startTime = Date.now()
  const outputFile = join(outputDir, 'amass.txt')

  try {
    const cmd = `amass enum -passive -d ${domain} -o ${outputFile}`
    const { stdout, stderr } = await execAsync(cmd, { timeout: 600000 })

    const subdomains = readFileSync(outputFile, 'utf8')
      .split('\n')
      .filter(line => line.trim())
      .map(subdomain => ({
        subdomain: subdomain.trim(),
        source: 'amass',
        timestamp: Date.now(),
      }))

    return {
      success: true,
      data: subdomains,
      rawOutput: stdout + stderr,
      duration: Date.now() - startTime,
      tool: 'amass',
    }
  } catch (err) {
    return {
      success: false,
      data: [],
      error: (err as Error).message,
      duration: Date.now() - startTime,
      tool: 'amass',
    }
  }
}

/**
 * OneForAll - 全面子域名收集
 */
export async function runOneForAll(domain: string, outputDir: string): Promise<ToolResult<SubdomainResult[]>> {
  const startTime = Date.now()
  const outputFile = join(outputDir, 'oneforall.json')

  try {
    const cmd = `python3 /opt/OneForAll/oneforall.py --target ${domain} run --format json --path ${outputFile}`
    const { stdout, stderr } = await execAsync(cmd, { timeout: 900000 })

    const results = JSON.parse(readFileSync(outputFile, 'utf8'))
    const subdomains = results.map((item: any) => ({
      subdomain: item.subdomain || item.host,
      source: 'oneforall',
      timestamp: Date.now(),
    }))

    return {
      success: true,
      data: subdomains,
      rawOutput: stdout + stderr,
      duration: Date.now() - startTime,
      tool: 'oneforall',
    }
  } catch (err) {
    return {
      success: false,
      data: [],
      error: (err as Error).message,
      duration: Date.now() - startTime,
      tool: 'oneforall',
    }
  }
}

// ── DNS 解析工具 ──────────────────────────────────────────────

export interface DNSResult {
  subdomain: string
  ips: string[]
  cname?: string
  alive: boolean
  timestamp: number
}

/**
 * DNSx - 快速DNS解析和验证
 */
export async function runDNSx(subdomains: string[], outputDir: string): Promise<ToolResult<DNSResult[]>> {
  const startTime = Date.now()
  const inputFile = join(outputDir, 'dnsx_input.txt')
  const outputFile = join(outputDir, 'dnsx.json')

  try {
    writeFileSync(inputFile, subdomains.join('\n'))

    const cmd = `dnsx -l ${inputFile} -json -o ${outputFile} -a -cname -resp -silent`
    const { stdout, stderr } = await execAsync(cmd, { timeout: 300000 })

    const lines = readFileSync(outputFile, 'utf8').split('\n').filter(l => l.trim())
    const results: DNSResult[] = lines.map(line => {
      const data = JSON.parse(line)
      return {
        subdomain: data.host,
        ips: data.a || [],
        cname: data.cname?.[0],
        alive: (data.a && data.a.length > 0) || false,
        timestamp: Date.now(),
      }
    })

    return {
      success: true,
      data: results,
      rawOutput: stdout + stderr,
      duration: Date.now() - startTime,
      tool: 'dnsx',
    }
  } catch (err) {
    return {
      success: false,
      data: [],
      error: (err as Error).message,
      duration: Date.now() - startTime,
      tool: 'dnsx',
    }
  }
}

// ── 端口扫描工具 ──────────────────────────────────────────────

export interface PortResult {
  ip: string
  port: number
  protocol: string
  state: string
  service?: string
  version?: string
  timestamp: number
}

/**
 * Masscan - 极速端口扫描（盲扫）
 */
export async function runMasscan(targets: string[], outputDir: string): Promise<ToolResult<PortResult[]>> {
  const startTime = Date.now()
  const inputFile = join(outputDir, 'masscan_targets.txt')
  const outputFile = join(outputDir, 'masscan.json')

  try {
    writeFileSync(inputFile, targets.join('\n'))

    const cmd = `masscan -iL ${inputFile} -p1-65535 --rate=10000 -oJ ${outputFile}`
    const { stdout, stderr } = await execAsync(cmd, { timeout: 600000 })

    const results = JSON.parse(readFileSync(outputFile, 'utf8'))
    const ports: PortResult[] = results
      .filter((item: any) => item.ports)
      .flatMap((item: any) =>
        item.ports.map((p: any) => ({
          ip: item.ip,
          port: p.port,
          protocol: p.proto,
          state: p.status,
          timestamp: Date.now(),
        }))
      )

    return {
      success: true,
      data: ports,
      rawOutput: stdout + stderr,
      duration: Date.now() - startTime,
      tool: 'masscan',
    }
  } catch (err) {
    return {
      success: false,
      data: [],
      error: (err as Error).message,
      duration: Date.now() - startTime,
      tool: 'masscan',
    }
  }
}

/**
 * Naabu - 高可靠端口扫描
 */
export async function runNaabu(targets: string[], outputDir: string): Promise<ToolResult<PortResult[]>> {
  const startTime = Date.now()
  const inputFile = join(outputDir, 'naabu_targets.txt')
  const outputFile = join(outputDir, 'naabu.json')

  try {
    writeFileSync(inputFile, targets.join('\n'))

    const cmd = `naabu -list ${inputFile} -json -o ${outputFile} -rate 10000 -c 100 -silent`
    const { stdout, stderr } = await execAsync(cmd, { timeout: 600000 })

    const lines = readFileSync(outputFile, 'utf8').split('\n').filter(l => l.trim())
    const ports: PortResult[] = lines.map(line => {
      const data = JSON.parse(line)
      return {
        ip: data.ip || data.host,
        port: data.port,
        protocol: 'tcp',
        state: 'open',
        timestamp: Date.now(),
      }
    })

    return {
      success: true,
      data: ports,
      rawOutput: stdout + stderr,
      duration: Date.now() - startTime,
      tool: 'naabu',
    }
  } catch (err) {
    return {
      success: false,
      data: [],
      error: (err as Error).message,
      duration: Date.now() - startTime,
      tool: 'naabu',
    }
  }
}

/**
 * Nmap - 深度服务指纹识别
 */
export async function runNmapService(targets: string[], ports: number[], outputDir: string): Promise<ToolResult<PortResult[]>> {
  const startTime = Date.now()
  const inputFile = join(outputDir, 'nmap_targets.txt')
  const outputFile = join(outputDir, 'nmap_service.xml')

  try {
    writeFileSync(inputFile, targets.join('\n'))
    const portList = ports.join(',')

    const cmd = `nmap -iL ${inputFile} -p ${portList} -sV -sC -T4 -oX ${outputFile} --min-rate 5000`
    const { stdout, stderr } = await execAsync(cmd, { timeout: 1800000 })

    // 解析 XML（简化版，实际需要用 xml2js）
    const xml = readFileSync(outputFile, 'utf8')
    const portMatches = xml.matchAll(/<port protocol="([^"]+)" portid="(\d+)">.*?<state state="([^"]+)".*?<service name="([^"]*)" product="([^"]*)" version="([^"]*)"/gs)

    const results: PortResult[] = []
    for (const match of portMatches) {
      results.push({
        ip: '', // 需要从XML中提取
        port: parseInt(match[2]),
        protocol: match[1],
        state: match[3],
        service: match[4],
        version: `${match[5]} ${match[6]}`.trim(),
        timestamp: Date.now(),
      })
    }

    return {
      success: true,
      data: results,
      rawOutput: stdout + stderr,
      duration: Date.now() - startTime,
      tool: 'nmap',
    }
  } catch (err) {
    return {
      success: false,
      data: [],
      error: (err as Error).message,
      duration: Date.now() - startTime,
      tool: 'nmap',
    }
  }
}

// ── Web 探测工具 ──────────────────────────────────────────────

export interface WebProbeResult {
  url: string
  statusCode: number
  title?: string
  contentLength: number
  technologies: string[]
  server?: string
  alive: boolean
  timestamp: number
}

/**
 * httpx - Web 服务存活探测
 */
export async function runHttpx(targets: string[], outputDir: string): Promise<ToolResult<WebProbeResult[]>> {
  const startTime = Date.now()
  const inputFile = join(outputDir, 'httpx_targets.txt')
  const outputFile = join(outputDir, 'httpx.json')

  try {
    writeFileSync(inputFile, targets.join('\n'))

    const cmd = `httpx -l ${inputFile} -json -o ${outputFile} -title -tech-detect -status-code -content-length -server -threads 300 -timeout 10 -silent`
    const { stdout, stderr } = await execAsync(cmd, { timeout: 600000 })

    const lines = readFileSync(outputFile, 'utf8').split('\n').filter(l => l.trim())
    const results: WebProbeResult[] = lines.map(line => {
      const data = JSON.parse(line)
      return {
        url: data.url,
        statusCode: data.status_code || data['status-code'],
        title: data.title,
        contentLength: data.content_length || data['content-length'] || 0,
        technologies: data.tech || data.technologies || [],
        server: data.server,
        alive: true,
        timestamp: Date.now(),
      }
    })

    return {
      success: true,
      data: results,
      rawOutput: stdout + stderr,
      duration: Date.now() - startTime,
      tool: 'httpx',
    }
  } catch (err) {
    return {
      success: false,
      data: [],
      error: (err as Error).message,
      duration: Date.now() - startTime,
      tool: 'httpx',
    }
  }
}

// ── 空间测绘工具 ──────────────────────────────────────────────

export interface SpaceEngineResult {
  ip: string
  port: number
  protocol: string
  service: string
  banner?: string
  country?: string
  city?: string
  org?: string
  timestamp: number
}

/**
 * Fofa API - 空间测绘查询
 */
export async function queryFofa(query: string, apiKey: string, email: string): Promise<ToolResult<SpaceEngineResult[]>> {
  const startTime = Date.now()

  try {
    const encodedQuery = Buffer.from(query).toString('base64')
    const url = `https://fofa.info/api/v1/search/all?email=${email}&key=${apiKey}&qbase64=${encodedQuery}&size=100`

    const response = await fetch(url)
    const data = await response.json() as any

    if (!data.results) {
      throw new Error('Fofa API returned no results')
    }

    const results: SpaceEngineResult[] = data.results.map((item: any[]) => ({
      ip: item[1],
      port: parseInt(item[2]) || 0,
      protocol: item[3] || 'tcp',
      service: item[4] || 'unknown',
      banner: item[5],
      country: item[6],
      city: item[7],
      org: item[8],
      timestamp: Date.now(),
    }))

    return {
      success: true,
      data: results,
      duration: Date.now() - startTime,
      tool: 'fofa',
    }
  } catch (err) {
    return {
      success: false,
      data: [],
      error: (err as Error).message,
      duration: Date.now() - startTime,
      tool: 'fofa',
    }
  }
}

/**
 * Shodan API - 空间测绘查询
 */
export async function queryShodan(query: string, apiKey: string): Promise<ToolResult<SpaceEngineResult[]>> {
  const startTime = Date.now()

  try {
    const url = `https://api.shodan.io/shodan/host/search?key=${apiKey}&query=${encodeURIComponent(query)}`

    const response = await fetch(url)
    const data = await response.json() as any

    if (!data.matches) {
      throw new Error('Shodan API returned no results')
    }

    const results: SpaceEngineResult[] = data.matches.map((item: any) => ({
      ip: item.ip_str,
      port: item.port,
      protocol: item.transport,
      service: item.product || item._shodan?.module || 'unknown',
      banner: item.data,
      country: item.location?.country_name,
      city: item.location?.city,
      org: item.org,
      timestamp: Date.now(),
    }))

    return {
      success: true,
      data: results,
      duration: Date.now() - startTime,
      tool: 'shodan',
    }
  } catch (err) {
    return {
      success: false,
      data: [],
      error: (err as Error).message,
      duration: Date.now() - startTime,
      tool: 'shodan',
    }
  }
}
