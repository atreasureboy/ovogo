/**
 * Worker Nodes — 子 agent 工作节点
 *
 * 职责：
 * 1. 从共享状态提取上下文
 * 2. 在 tmux 中启动独立的 agent 进程
 * 3. 等待 agent 完成并收集结果
 * 4. 更新共享状态
 */

import { exec as execCb } from 'child_process'
import { promisify } from 'util'
import { writeFileSync, readFileSync, existsSync, mkdirSync } from 'fs'
import { join } from 'path'
import type {
  GraphStateType,
  NodeUpdate,
  AgentExecutionResult,
  Finding,
  Port,
  WebService,
  Credential,
  Shell,
} from '../types.js'
import type { RedTeamAgentType } from '../../../prompts/agentPrompts.js'

const exec = promisify(execCb)

/** Shell-escape a single argument */
function shellEsc(s: string): string {
  return `'${s.replace(/'/g, "'\\''")}'`
}

/** Run a tmux sub-command */
async function tmux(args: string): Promise<string> {
  try {
    const { stdout, stderr } = await exec(`tmux ${args}`)
    return (stdout + stderr).trim()
  } catch (e: unknown) {
    const err = e as { stdout?: string; stderr?: string; message?: string }
    const out = ((err.stdout ?? '') + (err.stderr ?? '')).trim()
    throw new Error(out || err.message || String(e))
  }
}

/** Check if a tmux session exists */
async function sessionExists(name: string): Promise<boolean> {
  try {
    await exec(`tmux has-session -t ${shellEsc(name)} 2>/dev/null`)
    return true
  } catch {
    return false
  }
}

/** Wait for a file to exist (with timeout) */
async function waitForFile(filePath: string, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs
  const interval = 2000 // check every 2s

  while (Date.now() < deadline) {
    if (existsSync(filePath)) {
      return true
    }
    await new Promise((resolve) => setTimeout(resolve, interval))
  }

  return false
}

/**
 * 从共享状态提取 agent 需要的上下文
 */
function extractContextForAgent(agentType: RedTeamAgentType, state: GraphStateType): Record<string, unknown> {
  const {
    task,
    primaryTarget,
    sessionDir,
    currentPhase,
    phaseResults,
    findings,
    openPorts,
    webServices,
    credentials,
    shells,
    subdomains,
    ips,
  } = state

  // 基础上下文（所有 agent 都需要）
  const baseContext = {
    task,
    primaryTarget,
    sessionDir,
    currentPhase,
  }

  // 根据 agent 类型提供特定上下文
  switch (agentType) {
    case 'recon':
    case 'dns-recon':
    case 'port-scan':
    case 'web-probe':
    case 'osint':
      return {
        ...baseContext,
        // 侦察类 agent 不需要太多前置信息
      }

    case 'vuln-scan':
    case 'web-vuln':
    case 'service-vuln':
    case 'auth-attack':
      return {
        ...baseContext,
        // 漏洞扫描需要侦察结果
        openPorts: openPorts.map((p) => `${p.port}/${p.protocol}`),
        webServices: webServices.map((w) => w.url),
        subdomains: subdomains.slice(0, 50), // 限制数量
        ips: ips.slice(0, 20),
      }

    case 'weapon-match':
      return {
        ...baseContext,
        // PoC 匹配需要服务版本信息
        openPorts,
        webServices,
        techStack: webServices.flatMap((w) => w.tech ?? []),
      }

    case 'manual-exploit':
    case 'tool-exploit':
      return {
        ...baseContext,
        // 漏洞利用需要已发现的漏洞
        findings: findings.filter((f) => f.severity === 'critical' || f.severity === 'high'),
        openPorts,
        webServices,
      }

    case 'target-recon':
    case 'privesc':
      return {
        ...baseContext,
        // 后渗透需要 shell 信息
        shells,
        credentials,
      }

    case 'tunnel':
    case 'internal-recon':
    case 'lateral':
      return {
        ...baseContext,
        // 横向移动需要凭证和 shell
        shells,
        credentials,
        internalIps: ips.filter((ip) => ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.')),
      }

    case 'flag-hunter':
      return {
        ...baseContext,
        // Flag 收集需要所有 shell
        shells,
        webServices,
      }

    case 'report':
      return {
        ...baseContext,
        // 报告生成需要所有信息
        phaseResults,
        findings,
        openPorts,
        webServices,
        credentials,
        shells,
      }

    default:
      return baseContext
  }
}

/**
 * 在 tmux 中执行 agent
 */
async function executeAgentInTmux(params: {
  agentType: RedTeamAgentType
  sessionDir: string
  target?: string
  context: Record<string, unknown>
}): Promise<AgentExecutionResult> {
  const { agentType, sessionDir, target, context } = params
  const tmuxSessionName = `ovogo-${agentType}-${Date.now()}`

  const startTime = Date.now()

  try {
    // 1. 确保 session 目录存在
    mkdirSync(sessionDir, { recursive: true })

    // 2. 写入上下文到文件
    const contextFile = join(sessionDir, `${agentType}_context.json`)
    writeFileSync(contextFile, JSON.stringify(context, null, 2), 'utf8')

    // 3. 创建 tmux 会话
    if (await sessionExists(tmuxSessionName)) {
      await tmux(`kill-session -t ${shellEsc(tmuxSessionName)}`)
    }
    await tmux(`new-session -d -s ${shellEsc(tmuxSessionName)}`)

    // 4. 构建 agent 命令
    const agentCmd = [
      'node',
      'dist/bin/agent-worker.js',
      '--type',
      agentType,
      '--session-dir',
      sessionDir,
      '--context',
      contextFile,
    ]
    if (target) {
      agentCmd.push('--target', target)
    }

    // 5. 在 tmux 中启动 agent
    await tmux(`send-keys -t ${shellEsc(tmuxSessionName)} ${shellEsc(agentCmd.join(' '))} Enter`)

    // 6. 等待完成标记文件
    const doneFile = join(sessionDir, `${agentType}_done.json`)
    const timeout = 30 * 60 * 1000 // 30 分钟超时
    const completed = await waitForFile(doneFile, timeout)

    if (!completed) {
      // 超时 - 捕获当前输出
      const logFile = join(sessionDir, `${agentType}_log.txt`)
      let lastOutput = '(no output)'
      if (existsSync(logFile)) {
        lastOutput = readFileSync(logFile, 'utf8').slice(-2000)
      }

      throw new Error(`Agent ${agentType} timeout after ${timeout / 1000}s. Last output:\n${lastOutput}`)
    }

    // 7. 读取结果
    const resultJson = readFileSync(doneFile, 'utf8')
    const result = JSON.parse(resultJson) as AgentExecutionResult

    // 8. 清理 tmux 会话
    if (await sessionExists(tmuxSessionName)) {
      await tmux(`kill-session -t ${shellEsc(tmuxSessionName)}`)
    }

    return {
      ...result,
      duration: Date.now() - startTime,
    }
  } catch (err) {
    // 清理失败的会话
    if (await sessionExists(tmuxSessionName)) {
      await tmux(`kill-session -t ${shellEsc(tmuxSessionName)}`).catch(() => {})
    }

    return {
      agentType,
      success: false,
      summary: `Agent ${agentType} failed: ${(err as Error).message}`,
      outputFiles: [],
      findings: [],
      duration: Date.now() - startTime,
      error: (err as Error).message,
    }
  }
}

/**
 * 通用 Worker 节点工厂
 */
export function createWorkerNode(agentType: RedTeamAgentType) {
  return async (state: GraphStateType): Promise<NodeUpdate> => {
    const { sessionDir, primaryTarget, activeAgents } = state

    // 提取上下文
    const context = extractContextForAgent(agentType, state)

    // 执行 agent
    const result = await executeAgentInTmux({
      agentType,
      sessionDir,
      target: primaryTarget,
      context,
    })

    // 构建状态更新
    const update: NodeUpdate = {
      phaseResults: {
        [agentType]: {
          phase: state.currentPhase,
          agentType,
          success: result.success,
          summary: result.summary,
          outputFiles: result.outputFiles,
          findings: result.findings,
          timestamp: Date.now(),
          duration: result.duration,
        },
      },
      completedPhases: new Set([agentType]),
      messages: [
        {
          role: 'worker',
          content: result.summary,
          agentType,
          timestamp: Date.now(),
        },
      ],
    }

    // 移除自己从活跃列表
    const newActiveAgents = new Set(activeAgents)
    newActiveAgents.delete(agentType)
    update.activeAgents = newActiveAgents

    // 合并发现
    if (result.findings && result.findings.length > 0) {
      update.findings = result.findings
    }

    // 合并端口
    if (result.openPorts && result.openPorts.length > 0) {
      update.openPorts = result.openPorts
    }

    // 合并 Web 服务
    if (result.webServices && result.webServices.length > 0) {
      update.webServices = result.webServices
    }

    // 合并凭证
    if (result.credentials && result.credentials.length > 0) {
      update.credentials = result.credentials
    }

    // 合并 shell
    if (result.shells && result.shells.length > 0) {
      update.shells = result.shells
    }

    // 合并子域名
    if (result.subdomains && result.subdomains.length > 0) {
      update.subdomains = result.subdomains
    }

    // 合并 IP
    if (result.ips && result.ips.length > 0) {
      update.ips = result.ips
    }

    // 记录错误
    if (!result.success && result.error) {
      update.errors = [
        {
          agent: agentType,
          error: result.error,
          timestamp: Date.now(),
          recoverable: true,
        },
      ]
    }

    return update
  }
}

// ── 预定义的 Worker 节点 ──────────────────────────────────────

export const reconWorker = createWorkerNode('recon')
export const vulnScanWorker = createWorkerNode('vuln-scan')
export const weaponMatchWorker = createWorkerNode('weapon-match')
export const exploitWorker = createWorkerNode('manual-exploit')
export const postExploitWorker = createWorkerNode('target-recon')
export const privescWorker = createWorkerNode('privesc')
export const lateralWorker = createWorkerNode('lateral')
export const reportWorker = createWorkerNode('report')
