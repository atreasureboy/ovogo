/**
 * 漏洞扫描 Tool 层 — 原子工具定义
 *
 * 覆盖工具：
 * - Nuclei（模板化漏洞扫描）
 * - Xray（被动代理扫描）
 * - FFUF（目录爆破）
 * - Nikto（Web 漏洞扫描）
 * - SQLMap（SQL 注入）
 * - Wappalyzer（技术栈识别）
 * - WhatWeb（指纹识别）
 * - Arjun（参数发现）
 * - Dalfox（XSS 扫描）
 * - SSRF Hunter（SSRF 检测）
 */

import { exec } from 'child_process'
import { promisify } from 'util'
import { writeFileSync, readFileSync, existsSync } from 'fs'
import { join } from 'path'

const execAsync = promisify(exec)

import type { ToolResult } from '../../core/agentTypes.js'
export type { ToolResult }

// ── Nuclei 漏洞扫描 ───────────────────────────────────────────

export interface NucleiVulnerability {
  templateID: string
  name: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  type: string
  host: string
  matchedAt: string
  extractedResults?: string[]
  curlCommand?: string
  timestamp: number
}

/**
 * Nuclei - 模板化漏洞扫描（全模板）
 */
export async function runNucleiFull(targets: string[], outputDir: string): Promise<ToolResult<NucleiVulnerability[]>> {
  const startTime = Date.now()
  const inputFile = join(outputDir, 'nuclei_targets.txt')
  const outputFile = join(outputDir, 'nuclei_full.json')

  try {
    writeFileSync(inputFile, targets.join('\n'))

    const cmd = `nuclei -l ${inputFile} -json -o ${outputFile} -c 100 -bs 50 -rl 500 -timeout 10 -retries 2 -silent`
    const { stdout, stderr } = await execAsync(cmd, { timeout: 3600000 }) // 1小时超时

    const lines = readFileSync(outputFile, 'utf8').split('\n').filter(l => l.trim())
    const vulnerabilities: NucleiVulnerability[] = lines.map(line => {
      const data = JSON.parse(line)
      return {
        templateID: data['template-id'] || data.templateID,
        name: data.info?.name || data.name,
        severity: data.info?.severity || data.severity || 'info',
        type: data.type,
        host: data.host,
        matchedAt: data['matched-at'] || data.matchedAt,
        extractedResults: data['extracted-results'] || data.extractedResults,
        curlCommand: data['curl-command'] || data.curlCommand,
        timestamp: Date.now(),
      }
    })

    return {
      success: true,
      data: vulnerabilities,
      rawOutput: stdout + stderr,
      duration: Date.now() - startTime,
      tool: 'nuclei',
    }
  } catch (err) {
    return {
      success: false,
      data: [],
      error: (err as Error).message,
      duration: Date.now() - startTime,
      tool: 'nuclei',
    }
  }
}

/**
 * Nuclei - 指定严重程度扫描
 */
export async function runNucleiSeverity(
  targets: string[],
  severity: string[],
  outputDir: string
): Promise<ToolResult<NucleiVulnerability[]>> {
  const startTime = Date.now()
  const inputFile = join(outputDir, 'nuclei_targets.txt')
  const outputFile = join(outputDir, `nuclei_${severity.join('_')}.json`)

  try {
    writeFileSync(inputFile, targets.join('\n'))

    const severityFlag = severity.map(s => `-s ${s}`).join(' ')
    const cmd = `nuclei -l ${inputFile} ${severityFlag} -json -o ${outputFile} -c 100 -bs 50 -rl 500 -silent`
    const { stdout, stderr } = await execAsync(cmd, { timeout: 1800000 })

    const lines = readFileSync(outputFile, 'utf8').split('\n').filter(l => l.trim())
    const vulnerabilities: NucleiVulnerability[] = lines.map(line => {
      const data = JSON.parse(line)
      return {
        templateID: data['template-id'] || data.templateID,
        name: data.info?.name || data.name,
        severity: data.info?.severity || data.severity || 'info',
        type: data.type,
        host: data.host,
        matchedAt: data['matched-at'] || data.matchedAt,
        extractedResults: data['extracted-results'],
        curlCommand: data['curl-command'],
        timestamp: Date.now(),
      }
    })

    return {
      success: true,
      data: vulnerabilities,
      rawOutput: stdout + stderr,
      duration: Date.now() - startTime,
      tool: 'nuclei',
    }
  } catch (err) {
    return {
      success: false,
      data: [],
      error: (err as Error).message,
      duration: Date.now() - startTime,
      tool: 'nuclei',
    }
  }
}

// ── FFUF 目录爆破 ─────────────────────────────────────────────

export interface FFUFResult {
  url: string
  status: number
  length: number
  words: number
  lines: number
  redirectLocation?: string
  timestamp: number
}

/**
 * FFUF - 高速目录爆破
 */
export async function runFFUF(
  baseURL: string,
  wordlist: string,
  outputDir: string,
  extensions?: string[]
): Promise<ToolResult<FFUFResult[]>> {
  const startTime = Date.now()
  const outputFile = join(outputDir, 'ffuf.json')

  try {
    let cmd = `ffuf -u ${baseURL}/FUZZ -w ${wordlist} -json -o ${outputFile} -t 200 -timeout 10 -mc all -fc 404`

    if (extensions && extensions.length > 0) {
      cmd += ` -e ${extensions.join(',')}`
    }

    const { stdout, stderr } = await execAsync(cmd, { timeout: 1800000 })

    const data = JSON.parse(readFileSync(outputFile, 'utf8'))
    const results: FFUFResult[] = (data.results || []).map((item: any) => ({
      url: item.url,
      status: item.status,
      length: item.length,
      words: item.words,
      lines: item.lines,
      redirectLocation: item.redirectlocation,
      timestamp: Date.now(),
    }))

    return {
      success: true,
      data: results,
      rawOutput: stdout + stderr,
      duration: Date.now() - startTime,
      tool: 'ffuf',
    }
  } catch (err) {
    return {
      success: false,
      data: [],
      error: (err as Error).message,
      duration: Date.now() - startTime,
      tool: 'ffuf',
    }
  }
}

// ── Nikto Web 漏洞扫描 ────────────────────────────────────────

export interface NiktoFinding {
  id: string
  method: string
  url: string
  message: string
  osvdbId?: string
  timestamp: number
}

/**
 * Nikto - Web 服务器漏洞扫描
 */
export async function runNikto(target: string, outputDir: string): Promise<ToolResult<NiktoFinding[]>> {
  const startTime = Date.now()
  const outputFile = join(outputDir, 'nikto.json')

  try {
    const cmd = `nikto -h ${target} -Format json -output ${outputFile} -Tuning 123456789abc -timeout 10`
    const { stdout, stderr } = await execAsync(cmd, { timeout: 1800000 })

    const data = JSON.parse(readFileSync(outputFile, 'utf8'))
    const findings: NiktoFinding[] = (data.vulnerabilities || []).map((item: any) => ({
      id: item.id,
      method: item.method,
      url: item.url,
      message: item.msg,
      osvdbId: item.OSVDB,
      timestamp: Date.now(),
    }))

    return {
      success: true,
      data: findings,
      rawOutput: stdout + stderr,
      duration: Date.now() - startTime,
      tool: 'nikto',
    }
  } catch (err) {
    return {
      success: false,
      data: [],
      error: (err as Error).message,
      duration: Date.now() - startTime,
      tool: 'nikto',
    }
  }
}

// ── SQLMap SQL 注入检测 ───────────────────────────────────────

export interface SQLMapResult {
  url: string
  parameter: string
  injectable: boolean
  dbms?: string
  payload?: string
  data?: string[]
  timestamp: number
}

/**
 * SQLMap - SQL 注入自动化检测
 */
export async function runSQLMap(
  url: string,
  outputDir: string,
  options?: {
    data?: string
    cookie?: string
    level?: number
    risk?: number
  }
): Promise<ToolResult<SQLMapResult[]>> {
  const startTime = Date.now()
  const outputFile = join(outputDir, 'sqlmap.json')

  try {
    let cmd = `sqlmap -u "${url}" --batch --output-dir=${outputDir} --flush-session`

    if (options?.data) cmd += ` --data="${options.data}"`
    if (options?.cookie) cmd += ` --cookie="${options.cookie}"`
    if (options?.level) cmd += ` --level=${options.level}`
    if (options?.risk) cmd += ` --risk=${options.risk}`

    const { stdout, stderr } = await execAsync(cmd, { timeout: 1800000 })

    // SQLMap 输出解析（简化版）
    const injectable = stdout.includes('Parameter:') && stdout.includes('is vulnerable')

    const results: SQLMapResult[] = injectable ? [{
      url,
      parameter: 'detected',
      injectable: true,
      dbms: stdout.match(/back-end DBMS: ([^\n]+)/)?.[1],
      payload: stdout.match(/Payload: ([^\n]+)/)?.[1],
      timestamp: Date.now(),
    }] : []

    return {
      success: true,
      data: results,
      rawOutput: stdout + stderr,
      duration: Date.now() - startTime,
      tool: 'sqlmap',
    }
  } catch (err) {
    return {
      success: false,
      data: [],
      error: (err as Error).message,
      duration: Date.now() - startTime,
      tool: 'sqlmap',
    }
  }
}

// ── Arjun 参数发现 ────────────────────────────────────────────

export interface ArjunParameter {
  url: string
  method: string
  parameter: string
  type: 'GET' | 'POST' | 'JSON'
  timestamp: number
}

/**
 * Arjun - HTTP 参数发现
 */
export async function runArjun(url: string, outputDir: string): Promise<ToolResult<ArjunParameter[]>> {
  const startTime = Date.now()
  const outputFile = join(outputDir, 'arjun.json')

  try {
    const cmd = `arjun -u ${url} -oJ ${outputFile} -t 20 --stable`
    const { stdout, stderr } = await execAsync(cmd, { timeout: 600000 })

    const data = JSON.parse(readFileSync(outputFile, 'utf8'))
    const parameters: ArjunParameter[] = []

    for (const [url, params] of Object.entries(data)) {
      for (const param of params as any[]) {
        parameters.push({
          url,
          method: param.method || 'GET',
          parameter: param.name || param,
          type: param.type || 'GET',
          timestamp: Date.now(),
        })
      }
    }

    return {
      success: true,
      data: parameters,
      rawOutput: stdout + stderr,
      duration: Date.now() - startTime,
      tool: 'arjun',
    }
  } catch (err) {
    return {
      success: false,
      data: [],
      error: (err as Error).message,
      duration: Date.now() - startTime,
      tool: 'arjun',
    }
  }
}

// ── Dalfox XSS 扫描 ───────────────────────────────────────────

export interface DalfoxVulnerability {
  url: string
  parameter: string
  payload: string
  evidence: string
  poc: string
  timestamp: number
}

/**
 * Dalfox - XSS 漏洞扫描
 */
export async function runDalfox(url: string, outputDir: string): Promise<ToolResult<DalfoxVulnerability[]>> {
  const startTime = Date.now()
  const outputFile = join(outputDir, 'dalfox.json')

  try {
    const cmd = `dalfox url ${url} -o ${outputFile} --format json --silence --worker 100`
    const { stdout, stderr } = await execAsync(cmd, { timeout: 600000 })

    const lines = readFileSync(outputFile, 'utf8').split('\n').filter(l => l.trim())
    const vulnerabilities: DalfoxVulnerability[] = lines.map(line => {
      const data = JSON.parse(line)
      return {
        url: data.url,
        parameter: data.param,
        payload: data.payload,
        evidence: data.evidence,
        poc: data.poc,
        timestamp: Date.now(),
      }
    })

    return {
      success: true,
      data: vulnerabilities,
      rawOutput: stdout + stderr,
      duration: Date.now() - startTime,
      tool: 'dalfox',
    }
  } catch (err) {
    return {
      success: false,
      data: [],
      error: (err as Error).message,
      duration: Date.now() - startTime,
      tool: 'dalfox',
    }
  }
}

// ── WhatWeb 指纹识别 ──────────────────────────────────────────

export interface WhatWebResult {
  target: string
  httpStatus: number
  plugins: Record<string, any>
  timestamp: number
}

/**
 * WhatWeb - Web 应用指纹识别
 */
export async function runWhatWeb(targets: string[], outputDir: string): Promise<ToolResult<WhatWebResult[]>> {
  const startTime = Date.now()
  const inputFile = join(outputDir, 'whatweb_targets.txt')
  const outputFile = join(outputDir, 'whatweb.json')

  try {
    writeFileSync(inputFile, targets.join('\n'))

    const cmd = `whatweb -i ${inputFile} --log-json=${outputFile} -t 50 --max-threads=50`
    const { stdout, stderr } = await execAsync(cmd, { timeout: 600000 })

    const lines = readFileSync(outputFile, 'utf8').split('\n').filter(l => l.trim())
    const results: WhatWebResult[] = lines.map(line => {
      const data = JSON.parse(line)
      return {
        target: data.target,
        httpStatus: data.http_status,
        plugins: data.plugins,
        timestamp: Date.now(),
      }
    })

    return {
      success: true,
      data: results,
      rawOutput: stdout + stderr,
      duration: Date.now() - startTime,
      tool: 'whatweb',
    }
  } catch (err) {
    return {
      success: false,
      data: [],
      error: (err as Error).message,
      duration: Date.now() - startTime,
      tool: 'whatweb',
    }
  }
}

// ── Xray 被动扫描 ─────────────────────────────────────────────

export interface XrayVulnerability {
  createTime: number
  plugin: string
  target: {
    url: string
    params?: any[]
  }
  detail: {
    addr: string
    payload: string
    snapshot: string[]
  }
  timestamp: number
}

/**
 * Xray - 被动代理扫描
 * 需要先启动 Xray 代理，然后通过代理访问目标
 */
export async function runXrayPassive(
  proxyPort: number,
  outputDir: string,
  duration: number = 300000
): Promise<ToolResult<XrayVulnerability[]>> {
  const startTime = Date.now()
  const outputFile = join(outputDir, 'xray.json')

  try {
    // 启动 Xray 代理
    const cmd = `xray webscan --listen 127.0.0.1:${proxyPort} --json-output ${outputFile}`

    // 后台运行，等待指定时间
    const proc = execAsync(cmd, { timeout: duration })

    // 等待扫描时间
    await new Promise(resolve => setTimeout(resolve, duration))

    // 读取结果
    if (existsSync(outputFile)) {
      const lines = readFileSync(outputFile, 'utf8').split('\n').filter(l => l.trim())
      const vulnerabilities: XrayVulnerability[] = lines.map(line => {
        const data = JSON.parse(line)
        return {
          createTime: data.create_time,
          plugin: data.plugin,
          target: data.target,
          detail: data.detail,
          timestamp: Date.now(),
        }
      })

      return {
        success: true,
        data: vulnerabilities,
        duration: Date.now() - startTime,
        tool: 'xray',
      }
    }

    return {
      success: false,
      data: [],
      error: 'No output file generated',
      duration: Date.now() - startTime,
      tool: 'xray',
    }
  } catch (err) {
    return {
      success: false,
      data: [],
      error: (err as Error).message,
      duration: Date.now() - startTime,
      tool: 'xray',
    }
  }
}
