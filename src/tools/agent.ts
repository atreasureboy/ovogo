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

// Generic legacy types (kept for backward-compat)
type LegacyAgentType = 'general-purpose' | 'explore' | 'plan' | 'code-reviewer'

type AgentType = RedTeamAgentType | LegacyAgentType

const READ_ONLY_TYPES = new Set<AgentType>(['explore', 'plan', 'code-reviewer'])

const RED_TEAM_TYPES = new Set<AgentType>([
  // 侦察
  'dns-recon', 'port-scan', 'web-probe', 'weapon-match', 'osint',
  // 扫描
  'web-vuln', 'service-vuln', 'auth-attack', 'poc-verify',
  // 利用
  'exploit', 'webshell',
  // 后渗透
  'post-exploit', 'privesc', 'c2-deploy',
  // 横移
  'tunnel', 'internal-recon', 'lateral',
  // 综合
  'report',
])

// Injected at startup — avoids circular imports
let _engineFactory: ((config: EngineConfig, renderer: unknown) => { runTurn: (msg: string, history: never[]) => Promise<{ result: { output: string; reason: string } }> }) | null = null
let _currentConfig: EngineConfig | null = null
let _currentRenderer: unknown = null

export function registerAgentFactory(
  factory: typeof _engineFactory,
  config: EngineConfig,
  renderer: unknown,
): void {
  _engineFactory = factory
  _currentConfig = config
  _currentRenderer = renderer
}

// Default max_iterations per agent type (agents are focused, need enough room)
const DEFAULT_ITERATIONS: Record<string, number> = {
  // 侦察
  'dns-recon':       80,
  'port-scan':       80,
  'web-probe':       80,
  'weapon-match':    60,
  'osint':           60,
  // 扫描
  'web-vuln':       120,
  'service-vuln':   100,
  'auth-attack':    100,
  'poc-verify':      60,
  // 利用
  'exploit':        100,   // 多轮尝试exploit + 验证shell
  'webshell':        80,   // 上传+验证+命令执行
  // 后渗透
  'post-exploit':    80,   // 信息收集+敏感文件搜索
  'privesc':        100,   // 检测+多种路径尝试
  'c2-deploy':       80,   // beacon生成+上传+执行+等待上线
  // 横移
  'tunnel':          80,   // proxy建立+验证
  'internal-recon': 100,   // 内网扫描（通过代理，较慢）
  'lateral':        120,   // 多目标横向移动
  // 综合
  'report':          60,
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
      description: `启动专用 sub-agent 并行执行聚焦任务。多个 Agent 调用在同一响应中会同时执行（Promise.all）。

## 红队专用 Agent 类型（推荐）

| 类型 | 职责 | 并行阶段 |
|------|------|---------|
| dns-recon | 子域名/DNS枚举（subfinder/dnsx/amass） | Phase 1 |
| port-scan | 端口/服务扫描（nmap两步/masscan/naabu） | Phase 1 |
| web-probe | Web资产探测（httpx/katana/gau/指纹） | Phase 1 |
| weapon-match | 武器库匹配（WeaponRadar批量检索） | Phase 2 |
| osint | OSINT情报收集（WebSearch/证书/GitHub） | Phase 2 |
| web-vuln | Web漏洞扫描（nuclei HTTP/nikto/ffuf） | Phase 3 |
| service-vuln | 服务层漏洞（nuclei网络层/nmap-vuln） | Phase 3 |
| auth-attack | 认证攻击（hydra/kerbrute/默认凭证） | Phase 3 |
| poc-verify | 验证具体漏洞PoC（每个高置信漏洞1个） | Phase 4 |
| exploit | 漏洞利用→拿shell（RCE/文件上传/SQLi） | Phase 4 |
| webshell | Webshell部署管理（PHP/JSP/ASPX） | Phase 4 |
| post-exploit | 后渗透信息收集（凭证/内网/持久化） | Phase 5 |
| privesc | 权限提升（SUID/sudo/内核/计划任务） | Phase 5 |
| c2-deploy | Sliver beacon部署（生成/上传/执行） | Phase 5 |
| tunnel | 内网穿透（chisel socks5代理） | Phase 6 |
| internal-recon | 内网资产发现（proxychains+nmap/httpx） | Phase 6 |
| lateral | 横向移动（MS17-010/PTH/凭证复用） | Phase 6 |
| report | 生成最终渗透测试报告 | Phase 7 |

## 通用类型
- general-purpose: 所有工具可用，复杂自定义任务
- explore: 只读调查（Read/Glob/Grep）
- plan: 分析+规划，不执行
- code-reviewer: 代码安全审计

## 并行执行示例
Phase 1 侦察（一次响应中同时调用3个）:
  Agent(dns-recon, ...) + Agent(port-scan, ...) + Agent(web-probe, ...)
  → 引擎用 Promise.all 同时运行，64核服务器完全支持

## 关键规则
- prompt 必须完全自包含（包含 target、session_dir、具体任务）
- sub-agent 不能再调用 Agent（禁止递归）
- 每个 agent 独立写文件到 session_dir，结束时返回摘要`,
      parameters: {
        type: 'object',
        properties: {
          description: {
            type: 'string',
            description: '子任务标签（显示在UI，如 "DNS侦察 zhhovo.top"）',
          },
          prompt: {
            type: 'string',
            description: `完整任务指令，必须自包含，包含：
1. 目标（target URL/IP/域名）
2. session_dir（输出目录绝对路径）
3. 具体任务（做什么、输出什么文件）
4. 上下文（前一阶段的关键发现，如开放端口、技术栈）

Sub-agent 没有父对话的上下文，所有信息必须在 prompt 中提供。`,
          },
          subagent_type: {
            type: 'string',
            enum: [
              'dns-recon', 'port-scan', 'web-probe',
              'weapon-match', 'osint',
              'web-vuln', 'service-vuln', 'auth-attack', 'poc-verify',
              'exploit', 'webshell',
              'post-exploit', 'privesc', 'c2-deploy',
              'tunnel', 'internal-recon', 'lateral',
              'report',
              'general-purpose', 'explore', 'plan', 'code-reviewer',
            ],
            description: 'Agent 类型（默认 general-purpose）',
          },
          max_iterations: {
            type: 'number',
            description: '最大执行轮数（每种类型有合理默认值，可覆盖，最大 100）',
          },
        },
        required: ['description', 'prompt'],
      },
    },
  }

  async execute(input: Record<string, unknown>, context: ToolContext): Promise<ToolResult> {
    const description    = String(input.description ?? 'subtask')
    const prompt         = String(input.prompt ?? '')
    const agentType      = String(input.subagent_type ?? 'general-purpose') as AgentType
    const defaultIter    = DEFAULT_ITERATIONS[agentType] ?? 30
    const maxIterations  = typeof input.max_iterations === 'number'
      ? Math.min(input.max_iterations, 200)
      : defaultIter

    if (!prompt.trim()) {
      return { content: 'Error: prompt 不能为空', isError: true }
    }

    const allValidTypes: AgentType[] = [
      'dns-recon', 'port-scan', 'web-probe',
      'weapon-match', 'osint',
      'web-vuln', 'service-vuln', 'auth-attack', 'poc-verify',
      'exploit', 'webshell',
      'post-exploit', 'privesc', 'c2-deploy',
      'tunnel', 'internal-recon', 'lateral',
      'report',
      'general-purpose', 'explore', 'plan', 'code-reviewer',
    ]
    if (!allValidTypes.includes(agentType)) {
      return {
        content: `Error: 未知 subagent_type "${agentType}"。可用类型：${allValidTypes.join(', ')}`,
        isError: true,
      }
    }

    if (!_engineFactory || !_currentConfig || !_currentRenderer) {
      return {
        content: 'Error: AgentTool 未初始化，请先调用 registerAgentFactory。',
        isError: true,
      }
    }

    const renderer = _currentRenderer as {
      agentStart: (desc: string, type: string) => void
      agentDone:  (desc: string, success: boolean) => void
    }
    renderer.agentStart(description, agentType)

    // Build specialized system prompt
    let systemPrompt: string
    if (RED_TEAM_TYPES.has(agentType)) {
      const basePrompt = getRedTeamAgentPrompt(agentType as RedTeamAgentType, context.cwd)
      // Inject session dir from config if available
      const sessionDir = _currentConfig.sessionDir
      systemPrompt = sessionDir
        ? basePrompt + `\n\n当前 Session 目录: ${sessionDir}`
        : basePrompt
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
    }

    const childEngine = _engineFactory(childConfig, _currentRenderer)

    try {
      const { result } = await childEngine.runTurn(prompt, [])
      renderer.agentDone(description, result.reason !== 'error')

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
      renderer.agentDone(description, false)
      return {
        content: `[${agentType}] "${description}" 异常: ${(err as Error).message}`,
        isError: true,
      }
    }
  }
}
