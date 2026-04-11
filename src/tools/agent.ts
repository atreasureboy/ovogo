/**
 * AgentTool — spawn a specialized sub-agent to handle a focused subtask.
 *
 * Red team agent types are mapped to purpose-built system prompts in
 * src/prompts/agentPrompts.ts.  Multiple Agent calls in one LLM response
 * execute in parallel (Agent is in CONCURRENCY_SAFE_TOOLS).
 */

import type { Tool, ToolContext, ToolDefinition, ToolResult } from '../core/types.js'
import type { EngineConfig } from '../core/types.js'
import { getAgentTypeSystemPrompt } from '../prompts/system.js'
import { getRedTeamAgentPrompt, type RedTeamAgentType } from '../prompts/agentPrompts.js'
import { Renderer } from '../ui/renderer.js'
import { tmuxLayout } from '../ui/tmuxLayout.js'

// Generic legacy types (kept for backward-compat)
type LegacyAgentType = 'general-purpose' | 'explore' | 'plan' | 'code-reviewer'

type AgentType = RedTeamAgentType | LegacyAgentType

const READ_ONLY_TYPES = new Set<AgentType>(['explore', 'plan', 'code-reviewer'])

const RED_TEAM_TYPES = new Set<AgentType>([
  // 侦察（并行）
  'recon', 'dns-recon', 'port-scan', 'web-probe', 'osint',
  // 漏洞检索
  'weapon-match',
  // 漏洞探测（开局就扫）
  'vuln-scan', 'web-vuln', 'service-vuln', 'auth-attack',
  // 漏洞利用（手动+工具，两个并行）
  'manual-exploit', 'tool-exploit',
  // C2（与漏洞利用同时）
  'c2-deploy',
  // 靶机（信息收集+提权）
  'target-recon', 'privesc',
  // 内网横移
  'tunnel', 'internal-recon', 'lateral',
  // Flag收集
  'flag-hunter',
  // 综合
  'report',
])

// Injected at startup — avoids circular imports
type ChildEngine = {
  runTurn: (msg: string, history: never[]) => Promise<{ result: { output: string; reason: string } }>
  abort: () => void
}
let _engineFactory: ((config: EngineConfig, renderer: unknown) => ChildEngine) | null = null
let _currentConfig: EngineConfig | null = null
let _currentRenderer: unknown = null

export function registerAgentFactory(
  factory: ((config: EngineConfig, renderer: unknown) => ChildEngine),
  config: EngineConfig,
  renderer: unknown,
): void {
  _engineFactory = factory
  _currentConfig = config
  _currentRenderer = renderer
}

/**
 * Shared runner used by both AgentTool and MultiAgentTool.
 * Returns a ToolResult with prefixed agent type.
 *
 * When running inside a tmux 4-pane layout, acquires a pane slot and creates
 * a file-backed renderer so the sub-agent's detailed output streams to its
 * dedicated pane.  The main renderer still shows high-level agentStart/Done markers.
 */
export async function runAgentTask(
  description: string,
  prompt: string,
  agentType: AgentType,
  maxIterations: number,
  context: ToolContext,
): Promise<ToolResult> {
  if (!_engineFactory || !_currentConfig || !_currentRenderer) {
    return { content: 'Error: AgentTool 未初始化', isError: true }
  }

  // Main renderer: shows high-level agentStart/Done markers on main pane
  const mainRenderer = _currentRenderer as {
    agentStart: (desc: string, type: string) => void
    agentDone:  (desc: string, success: boolean) => void
  }
  mainRenderer.agentStart(description, agentType)

  // Attempt to acquire a tmux pane slot for detailed output
  const agentLabel = `[${agentType}] ${description}`
  const paneSlot = tmuxLayout.acquireSlot(agentLabel)

  // Child renderer: file-backed if a pane slot is available, else share main renderer
  const childRenderer = paneSlot
    ? Renderer.forFile(paneSlot.logFile)
    : (_currentRenderer as Renderer)

  let systemPrompt: string
  if (RED_TEAM_TYPES.has(agentType)) {
    const basePrompt = getRedTeamAgentPrompt(agentType as RedTeamAgentType, context.cwd)
    const sessionDir = _currentConfig.sessionDir
    systemPrompt = sessionDir ? basePrompt + `\n\n当前 Session 目录: ${sessionDir}` : basePrompt
  } else {
    systemPrompt = getAgentTypeSystemPrompt(agentType as LegacyAgentType, context.cwd)
  }

  const childConfig: EngineConfig = {
    ..._currentConfig,
    maxIterations,
    cwd: context.cwd,
    hookRunner: undefined,
    planMode: READ_ONLY_TYPES.has(agentType),
    systemPrompt,
    // Sub-agents have no sessionDir so critic loop won't trigger in them
    sessionDir: undefined,
    // Sub-agents are executors, not coordinators — give them full tool access
    coordinatorMode: false,
  }

  const childEngine = _engineFactory(childConfig, childRenderer)

  // Propagate parent abort signal to child engine so Ctrl+C cancels sub-agents too
  if (context.signal) {
    if (context.signal.aborted) {
      mainRenderer.agentDone(description, false)
      if (paneSlot) tmuxLayout.releaseSlot(paneSlot.slot)
      return { content: `[${agentType}] 已取消（父任务中止）`, isError: true }
    }
    context.signal.addEventListener('abort', () => childEngine.abort(), { once: true })
  }

  try {
    const { result } = await childEngine.runTurn(prompt, [])
    mainRenderer.agentDone(description, result.reason !== 'error')

    if (paneSlot) tmuxLayout.releaseSlot(paneSlot.slot)

    if (!result.output) {
      return {
        content: `[${agentType}] "${description}" 完成（${result.reason}），无文本输出。`,
        isError: false,
      }
    }
    return {
      content: `[${agentType}] "${description}":\n\n${result.output}`,
      isError: false,
    }
  } catch (err: unknown) {
    mainRenderer.agentDone(description, false)
    if (paneSlot) tmuxLayout.releaseSlot(paneSlot.slot)
    return {
      content: `[${agentType}] "${description}" 异常: ${(err as Error).message}`,
      isError: true,
    }
  }
}

// Default max_iterations per agent type (agents are focused, need enough room)
export const DEFAULT_ITERATIONS: Record<string, number> = {
  // 侦察（并行）
  'recon':            80,
  'dns-recon':        80,
  'port-scan':        80,
  'web-probe':        80,
  'osint':            60,
  // 漏洞检索
  'weapon-match':     60,
  // 漏洞探测（开局就扫）
  'vuln-scan':       120,
  'web-vuln':        120,
  'service-vuln':    100,
  'auth-attack':     100,
  // 漏洞利用（手动+工具，两个并行）
  'manual-exploit':  100,
  'tool-exploit':    100,
  // C2（与漏洞利用同时）
  'c2-deploy':        80,
  // 靶机（信息收集+提权）
  'target-recon':     80,
  'privesc':         100,
  // 内网横移
  'tunnel':           80,
  'internal-recon':  100,
  'lateral':         120,
  // Flag收集
  'flag-hunter':      80,
  // 综合
  'report':           60,
  'general-purpose': 60,
  'explore':         40,
  'plan':            30,
  'code-reviewer':   30,
}

export class AgentTool implements Tool {
  name = 'Agent'

  definition: ToolDefinition = {
    type: 'function',
    function: {
      name: 'Agent',
      description: `启动专用 sub-agent 执行聚焦任务。多个 Agent 调用在同一响应中并发执行（Promise.all）。

## 红队 Agent 类型

### 一级 Agent（直接派给主agent）
| 类型 | 职责 | 场景 |
|------|------|------|
| recon | 侦察总管（内部再分 dns-recon/port-scan/web-probe/osint） | 开局 Phase 1 |
| vuln-scan | 漏洞探测总管（内部再分 web-vuln/service-vuln/auth-attack） | 开局 Phase 1 同时启动 |
| weapon-match | POC库检索（基于侦察结果匹配漏洞） | Phase 2 |
| manual-exploit | 手动漏洞利用（curl/python手工payload） | Phase 3 |
| tool-exploit | 工具漏洞利用（MSF/sqlmap/searchsploit） | Phase 3 |
| c2-deploy | C2部署（Metasploit/Sliver监听+payload生成） | Phase 3 同时启动 |
| target-recon | 靶机信息收集（本机+内网情报） | Phase 4 拿到shell后 |
| privesc | 权限提升（SUID/sudo/内核/计划任务） | Phase 4 |
| tunnel | 内网穿透（chisel socks5代理） | Phase 5 |
| internal-recon | 内网资产发现（proxychains+nmap/httpx） | Phase 5 |
| lateral | 横向移动（MS17-010/PTH/凭证复用） | Phase 5 |
| flag-hunter | 全面搜索并收集flag（ShellSession/C2/webshell） | 随时 |
| report | 生成最终渗透测试报告 | Phase 7 |

### 二级 Agent（由 recon/vuln-scan 内部调用，也可直接使用）
| 类型 | 职责 |
|------|------|
| dns-recon | 子域名/DNS枚举（subfinder/dnsx/amass） |
| port-scan | 端口/服务扫描（nmap两步/masscan） |
| web-probe | Web资产探测（httpx/katana/gau/指纹） |
| osint | OSINT情报（WebSearch/证书/GitHub dork） |
| web-vuln | Web漏洞扫描（nuclei HTTP/ffuf） |
| service-vuln | 服务层漏洞（nmap-vuln/enum4linux） |
| auth-attack | 认证攻击（hydra/kerbrute/默认凭证） |

### 通用类型
- general-purpose: 所有工具可用，复杂自定义任务

## 标准开局
  Agent(recon, ...) + Agent(vuln-scan, ...)   ← 同时发出，并发执行
  → 侦察和漏洞扫描同步进行，最大化时间利用

## 关键规则
- prompt 必须完全自包含（target、session_dir、具体任务、上游发现）
- 叶子 agent 不能再调用 Agent（只有 recon/vuln-scan 这类编排型 agent 可以）
- 每个 agent 写文件到 session_dir，结束时返回摘要`,
      parameters: {
        type: 'object',
        properties: {
          description: {
            type: 'string',
            description: '任务标签（显示在UI，如 "侦察 zhhovo.top"）',
          },
          prompt: {
            type: 'string',
            description: `完整任务指令，必须自包含，包含：
1. 目标（target URL/IP/域名）
2. session_dir（输出目录绝对路径）
3. 具体任务（做什么、输出什么文件）
4. 上下文（前一阶段的关键发现）

Sub-agent 没有父对话上下文，所有信息必须在 prompt 中提供。`,
          },
          subagent_type: {
            type: 'string',
            enum: [
              // 一级 agent（直接派给主agent）
              'recon', 'vuln-scan', 'weapon-match',
              'manual-exploit', 'tool-exploit', 'c2-deploy',
              'target-recon', 'privesc',
              'tunnel', 'internal-recon', 'lateral',
              'flag-hunter', 'report',
              // 二级 agent（也可直接使用）
              'dns-recon', 'port-scan', 'web-probe', 'osint',
              'web-vuln', 'service-vuln', 'auth-attack',
              // 通用
              'general-purpose', 'explore', 'plan', 'code-reviewer',
            ],
            description: 'Agent 类型（默认 general-purpose）',
          },
          max_iterations: {
            type: 'number',
            description: '最大执行轮数（各类型有合理默认值，可覆盖，最大 200）',
          },
        },
        required: ['description', 'prompt'],
      },
    },
  }

  async execute(input: Record<string, unknown>, context: ToolContext): Promise<ToolResult> {
    const description   = String(input.description ?? 'subtask')
    const prompt        = String(input.prompt ?? '')
    const agentType     = String(input.subagent_type ?? 'general-purpose') as AgentType
    const defaultIter   = DEFAULT_ITERATIONS[agentType] ?? 30
    const maxIterations = typeof input.max_iterations === 'number'
      ? Math.min(input.max_iterations, 200)
      : defaultIter

    if (!prompt.trim()) {
      return { content: 'Error: prompt 不能为空', isError: true }
    }

    if (!_engineFactory || !_currentConfig || !_currentRenderer) {
      return { content: 'Error: AgentTool 未初始化，请先调用 registerAgentFactory。', isError: true }
    }

    return runAgentTask(description, prompt, agentType, maxIterations, context)
  }
}
