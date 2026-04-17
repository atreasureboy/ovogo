#!/usr/bin/env node
/**
 * Agent Worker — 独立的 agent 进程
 *
 * 在 tmux 中运行，从 context 文件读取输入，写结果到 done 文件。
 * 这样主进程和子 agent 通过文件系统通信，解耦执行。
 */

import { resolve, join } from 'path'
import { readFileSync, writeFileSync, existsSync, readdirSync } from 'fs'
import { ExecutionEngine } from '../src/core/engine.js'
import { Renderer } from '../src/ui/renderer.js'
import type { EngineConfig, OpenAIMessage } from '../src/core/types.js'
import { getRedTeamAgentPrompt, type RedTeamAgentType } from '../src/prompts/agentPrompts.js'
import type { AgentExecutionResult, Finding, Port, WebService, Credential, Shell } from '../src/core/agentResultTypes.js'

// ── 参数解析 ──────────────────────────────────────────────────

interface WorkerArgs {
  type: RedTeamAgentType
  sessionDir: string
  target?: string
  contextFile: string
}

function parseArgs(argv: string[]): WorkerArgs {
  const args = argv.slice(2)
  const parsed: Partial<WorkerArgs> = {}

  for (let i = 0; i < args.length; i++) {
    const arg = args[i]
    switch (arg) {
      case '--type':
        parsed.type = args[++i] as RedTeamAgentType
        break
      case '--session-dir':
        parsed.sessionDir = args[++i]
        break
      case '--target':
        parsed.target = args[++i]
        break
      case '--context':
        parsed.contextFile = args[++i]
        break
    }
  }

  if (!parsed.type || !parsed.sessionDir || !parsed.contextFile) {
    throw new Error('Missing required args: --type, --session-dir, --context')
  }

  return parsed as WorkerArgs
}

// ── 构建 Agent Prompt ─────────────────────────────────────────

function buildAgentPrompt(
  agentType: RedTeamAgentType,
  target: string | undefined,
  context: Record<string, unknown>,
): string {
  const lines: string[] = []

  lines.push(`[Agent Worker: ${agentType}]`)
  lines.push(``)

  if (target) {
    lines.push(`目标: ${target}`)
  }

  lines.push(`Session 目录: ${context.sessionDir}`)
  lines.push(``)

  lines.push(`[任务]`)
  lines.push(String(context.task ?? '执行渗透测试'))
  lines.push(``)

  // 根据 agent 类型添加特定上下文
  if (agentType === 'vuln-scan' || agentType === 'web-vuln' || agentType === 'service-vuln') {
    if (context.openPorts && Array.isArray(context.openPorts) && context.openPorts.length > 0) {
      lines.push(`[已发现端口]`)
      lines.push(context.openPorts.slice(0, 20).join(', '))
      lines.push(``)
    }
    if (context.webServices && Array.isArray(context.webServices) && context.webServices.length > 0) {
      lines.push(`[已发现 Web 服务]`)
      lines.push(context.webServices.slice(0, 10).join('\n'))
      lines.push(``)
    }
  }

  if (agentType === 'manual-exploit' || agentType === 'tool-exploit') {
    if (context.findings && Array.isArray(context.findings) && context.findings.length > 0) {
      lines.push(`[已发现漏洞]`)
      for (const f of context.findings.slice(0, 5)) {
        const finding = f as { severity: string; title: string; target: string }
        lines.push(`- [${finding.severity.toUpperCase()}] ${finding.title} @ ${finding.target}`)
      }
      lines.push(``)
    }
  }

  if (agentType === 'target-recon' || agentType === 'privesc') {
    if (context.shells && Array.isArray(context.shells) && context.shells.length > 0) {
      lines.push(`[可用 Shell]`)
      for (const s of context.shells) {
        const shell = s as { id: string; type: string; status: string }
        lines.push(`- ${shell.id} (${shell.type}, ${shell.status})`)
      }
      lines.push(``)
    }
  }

  lines.push(`[要求]`)
  lines.push(`1. 执行你的专项任务（${agentType}）`)
  lines.push(`2. 将所有输出文件写入 session 目录`)
  lines.push(`3. 完成后返回结构化摘要`)
  lines.push(``)

  return lines.join('\n')
}

// ── 提取结构化结果 ────────────────────────────────────────────

function extractStructuredResult(
  agentType: RedTeamAgentType,
  output: string,
  sessionDir: string,
): AgentExecutionResult {
  const result: AgentExecutionResult = {
    agentType,
    success: true,
    summary: output.slice(0, 500),
    outputFiles: [],
    findings: [],
    duration: 0,
  }

  // 扫描 session 目录，收集输出文件
  try {
    const files = readdirSync(sessionDir)
    result.outputFiles = files.filter((f) => f.endsWith('.txt') || f.endsWith('.json') || f.endsWith('.yaml'))
  } catch {
    // ignore
  }

  // 尝试从输出中提取结构化信息
  // 这里简化处理，实际可以更复杂

  // 提取端口 — 匹配 nmap/naabu 风格: "22/tcp  open  ssh"
  const portMatches = output.matchAll(/^(\d+)\/(tcp|udp)\s+(open|filtered|closed)/gm)
  const ports: Port[] = []
  const seenPorts = new Set<string>()
  for (const match of portMatches) {
    const key = `${match[1]}/${match[2]}`
    if (!seenPorts.has(key)) {
      seenPorts.add(key)
      ports.push({ port: parseInt(match[1], 10), protocol: match[2] })
    }
  }
  if (ports.length > 0) {
    result.openPorts = ports.slice(0, 100)
  }

  // 提取 URL — 只匹配明确的服务 URL
  const urlMatches = output.matchAll(/^(https?:\/\/[a-zA-Z0-9._-]+(?::\d+)?(?:\/[^\s,;|]*)?)$/gm)
  const urls: WebService[] = []
  const seenUrls = new Set<string>()
  for (const match of urlMatches) {
    if (!seenUrls.has(match[1])) {
      seenUrls.add(match[1])
      urls.push({ url: match[1], status: 200 })
    }
  }
  const urlLabelMatches = output.matchAll(/(?:URL|Target|Endpoint):\s*(https?:\/\/[^\s]+)/gi)
  for (const match of urlLabelMatches) {
    if (!seenUrls.has(match[1])) {
      seenUrls.add(match[1])
      urls.push({ url: match[1], status: 200 })
    }
  }
  if (urls.length > 0) {
    result.webServices = urls.slice(0, 50)
  }

  // 提取子域名 — 从结构化标签行中提取
  const subdomainMatches = output.matchAll(/(?:^Subdomain:\s*|^Host:\s*|^Domain:\s*)([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,})/gim)
  const subdomains = new Set<string>()
  for (const match of subdomainMatches) {
    subdomains.add(match[1].toLowerCase())
  }
  if (subdomains.size > 0) {
    result.subdomains = Array.from(subdomains).slice(0, 100)
  }

  // 提取 IP — 从 nmap/网络工具输出中提取
  const ipMatches = output.matchAll(/(?:Host:\s*|IP:\s*|Address:\s*|RHOSTS:\s*|^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b)/gm)
  const ips = new Set<string>()
  for (const match of ipMatches) {
    const ip = match[1] || match[0].replace(/^[^\d]*/, '')
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip) && ip !== '127.0.0.1') {
      ips.add(ip)
    }
  }
  if (ips.size > 0) {
    result.ips = Array.from(ips).slice(0, 50)
  }

  // 检查是否有错误标记
  if (output.includes('[ERROR]') || output.includes('failed') || output.includes('异常')) {
    result.success = false
  }

  return result
}

// ── 主函数 ────────────────────────────────────────────────────

async function main(): Promise<void> {
  try {
    const args = parseArgs(process.argv)
    const { type, sessionDir, target, contextFile } = args

    // 读取上下文
    if (!existsSync(contextFile)) {
      throw new Error(`Context file not found: ${contextFile}`)
    }
    const contextJson = readFileSync(contextFile, 'utf8')
    const context = JSON.parse(contextJson) as Record<string, unknown>

    // 获取 API 配置
    const apiKey = process.env.OPENAI_API_KEY
    if (!apiKey) {
      throw new Error('OPENAI_API_KEY not set')
    }
    const model = process.env.OVOGO_MODEL ?? 'gpt-4o'
    const baseURL = process.env.OPENAI_BASE_URL

    // 创建日志文件渲染器
    const logFile = join(sessionDir, `${type}_log.txt`)
    const renderer = Renderer.forFile(logFile)

    renderer.info(`[Agent Worker] Type: ${type}`)
    renderer.info(`[Agent Worker] Target: ${target ?? 'N/A'}`)
    renderer.info(`[Agent Worker] Session: ${sessionDir}`)

    // 构建 agent 配置
    const systemPrompt = getRedTeamAgentPrompt(type, sessionDir)
    const config: EngineConfig = {
      model,
      apiKey,
      baseURL,
      maxIterations: 120, // worker 默认 120 轮
      cwd: sessionDir,
      permissionMode: 'auto',
      systemPrompt,
      sessionDir,
      primaryTarget: target,
      coordinatorMode: false, // worker 是执行者，不是协调者
    }

    // 创建引擎
    const engine = new ExecutionEngine(config, renderer)

    // 构建 prompt
    const prompt = buildAgentPrompt(type, target, context)
    renderer.info(`[Agent Worker] Prompt:\n${prompt.slice(0, 300)}...`)

    // 执行任务
    const startTime = Date.now()
    const { result } = await engine.runTurn(prompt, [])
    const duration = Date.now() - startTime

    renderer.info(`[Agent Worker] Completed in ${(duration / 1000).toFixed(1)}s`)
    renderer.info(`[Agent Worker] Reason: ${result.reason}`)

    // 提取结构化结果
    const structuredResult = extractStructuredResult(type, result.output, sessionDir)
    structuredResult.duration = duration

    // 写入完成标记
    const doneFile = join(sessionDir, `${type}_done.json`)
    writeFileSync(doneFile, JSON.stringify(structuredResult, null, 2), 'utf8')

    renderer.success(`[Agent Worker] Result written to ${doneFile}`)

    process.exit(0)
  } catch (err: unknown) {
    const error = err as Error
    process.stderr.write(`[Agent Worker] Fatal: ${error.message}\n`)
    process.stderr.write(`${error.stack}\n`)
    process.exit(1)
  }
}

main()
