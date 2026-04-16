/**
 * Supervisor Node — 主协调节点
 *
 * 职责：
 * 1. 分析当前状态（已完成的阶段、发现的漏洞、活跃的 agent）
 * 2. 决定下一步行动（启动哪些 agent、等待、结束）
 * 3. 提供决策推理（便于调试和用户理解）
 */

import OpenAI from 'openai'
import type {
  GraphStateType,
  NodeUpdate,
  SupervisorDecision,
  RouteDecision,
} from '../types.js'

const SUPERVISOR_SYSTEM_PROMPT = `你是红队渗透测试的主协调 agent（Supervisor）。

## 职责
1. 分析当前渗透测试进度和成果
2. 决定下一步应该启动哪些子 agent
3. 确保攻击链的逻辑顺序和并行效率

## 标准攻击链阶段
1. **recon** — 侦察（子域名、端口、Web服务、OSINT）
2. **vuln-scan** — 漏洞扫描（Web漏洞、服务漏洞、认证攻击）
3. **weapon-match** — PoC匹配（从22万PoC库检索）
4. **exploit** — 漏洞利用（手动+工具，获取shell）
5. **post-exploit** — 后渗透（信息收集、凭证提取）
6. **privesc** — 权限提升（SUID、sudo、内核漏洞）
7. **lateral** — 横向移动（内网扫描、凭证复用、MS17-010）
8. **report** — 生成报告

## 决策规则
- **开局必须并行**：recon 和 vuln-scan 同时启动（最大化时间利用）
- **发现驱动**：根据已发现的端口/服务/漏洞决定下一步
- **优先拿shell**：发现高危漏洞立即启动 exploit
- **不要等待**：如果有可以并行的任务，立即启动
- **靶场目标**：最终目标是拿到 flag，不是写报告

## 可用的路由决策
- delegate_recon — 启动侦察
- delegate_vuln_scan — 启动漏洞扫描
- delegate_weapon_match — 启动PoC匹配
- delegate_exploit — 启动漏洞利用
- delegate_post_exploit — 启动后渗透
- delegate_privesc — 启动权限提升
- delegate_lateral — 启动横向移动
- delegate_report — 生成最终报告
- wait_for_agents — 等待当前活跃的agent完成
- finish — 任务完成

## 输出格式（JSON）
{
  "action": "delegate_recon",
  "reasoning": "开局阶段，启动侦察和漏洞扫描并行",
  "phase": "recon"
}

## 关键原则
- 永远不要串行等待可以并行的任务
- 发现Critical/High漏洞立即利用
- 拿到shell后立即后渗透+提权
- 不要在信息收集阶段停滞不前`

interface SupervisorContext {
  apiKey: string
  baseURL?: string
  model: string
}

let supervisorContext: SupervisorContext | null = null

export function initSupervisor(context: SupervisorContext): void {
  supervisorContext = context
}

/**
 * Supervisor 节点 — 决策下一步行动
 */
export async function supervisorNode(state: GraphStateType): Promise<NodeUpdate> {
  if (!supervisorContext) {
    throw new Error('Supervisor not initialized. Call initSupervisor() first.')
  }

  const {
    task,
    currentPhase,
    completedPhases,
    phaseResults,
    findings,
    openPorts,
    webServices,
    shells,
    credentials,
    activeAgents,
    messages,
    errors,
  } = state

  // 构建状态摘要
  const stateSummary = buildStateSummary({
    task,
    currentPhase,
    completedPhases,
    phaseResults,
    findings,
    openPorts,
    webServices,
    shells,
    credentials,
    activeAgents,
    errors,
  })

  // 调用 LLM 决策
  const decision = await callSupervisorLLM(stateSummary, messages.slice(-10))

  // 更新活跃 agent 列表
  const newActiveAgents = new Set(activeAgents)
  if (decision.action.startsWith('delegate_')) {
    const agentType = decision.action.replace('delegate_', '')
    newActiveAgents.add(agentType)
  }

  return {
    nextAction: decision.action,
    currentPhase: decision.phase ?? currentPhase,
    activeAgents: newActiveAgents,
    messages: [
      {
        role: 'supervisor',
        content: `[决策] ${decision.action}\n推理: ${decision.reasoning}`,
        timestamp: Date.now(),
      },
    ],
  }
}

/**
 * 构建状态摘要供 LLM 分析
 */
function buildStateSummary(params: {
  task: string
  currentPhase: string
  completedPhases: Set<string>
  phaseResults: Record<string, unknown>
  findings: unknown[]
  openPorts: unknown[]
  webServices: unknown[]
  shells: unknown[]
  credentials: unknown[]
  activeAgents: Set<string>
  errors: unknown[]
}): string {
  const {
    task,
    currentPhase,
    completedPhases,
    phaseResults,
    findings,
    openPorts,
    webServices,
    shells,
    credentials,
    activeAgents,
    errors,
  } = params

  const lines: string[] = []

  lines.push(`## 任务目标`)
  lines.push(task)
  lines.push(``)

  lines.push(`## 当前状态`)
  lines.push(`- 当前阶段: ${currentPhase}`)
  lines.push(`- 已完成阶段: ${[...completedPhases].join(', ') || '无'}`)
  lines.push(`- 活跃 agent: ${[...activeAgents].join(', ') || '无'}`)
  lines.push(``)

  lines.push(`## 已发现成果`)
  lines.push(`- 漏洞: ${findings.length} 个`)
  lines.push(`- 开放端口: ${openPorts.length} 个`)
  lines.push(`- Web服务: ${webServices.length} 个`)
  lines.push(`- Shell: ${shells.length} 个`)
  lines.push(`- 凭证: ${credentials.length} 个`)
  lines.push(``)

  if (findings.length > 0) {
    lines.push(`## 漏洞详情（前5个）`)
    const topFindings = findings.slice(0, 5) as Array<{ severity: string; title: string }>
    for (const f of topFindings) {
      lines.push(`- [${f.severity.toUpperCase()}] ${f.title}`)
    }
    lines.push(``)
  }

  if (Object.keys(phaseResults).length > 0) {
    lines.push(`## 阶段结果摘要`)
    for (const [phase, result] of Object.entries(phaseResults)) {
      const r = result as { success: boolean; summary: string }
      lines.push(`- ${phase}: ${r.success ? '✓' : '✗'} ${r.summary.slice(0, 100)}`)
    }
    lines.push(``)
  }

  if (errors.length > 0) {
    lines.push(`## 错误记录`)
    for (const err of errors.slice(-3)) {
      const e = err as { agent: string; error: string }
      lines.push(`- ${e.agent}: ${e.error}`)
    }
    lines.push(``)
  }

  lines.push(`## 决策要求`)
  lines.push(`根据以上状态，决定下一步行动。输出 JSON 格式的决策。`)

  return lines.join('\n')
}

/**
 * 调用 LLM 进行决策
 */
async function callSupervisorLLM(
  stateSummary: string,
  recentMessages: Array<{ role: string; content: string; agentType?: string }>,
): Promise<SupervisorDecision> {
  if (!supervisorContext) {
    throw new Error('Supervisor context not initialized')
  }

  const client = new OpenAI({
    apiKey: supervisorContext.apiKey,
    baseURL: supervisorContext.baseURL,
  })

  // 构建对话历史
  const conversationContext = recentMessages
    .map((m) => {
      const prefix = m.agentType ? `[${m.agentType}]` : `[${m.role}]`
      return `${prefix} ${m.content.slice(0, 200)}`
    })
    .join('\n')

  const userPrompt = `${stateSummary}

## 最近对话
${conversationContext}

请分析当前状态，决定下一步行动。输出 JSON 格式：
{
  "action": "delegate_xxx | wait_for_agents | finish",
  "reasoning": "决策推理",
  "phase": "当前阶段名称（可选）"
}`

  try {
    const response = await client.chat.completions.create({
      model: supervisorContext.model,
      messages: [
        { role: 'system', content: SUPERVISOR_SYSTEM_PROMPT },
        { role: 'user', content: userPrompt },
      ],
      temperature: 0,
      max_tokens: 500,
      response_format: { type: 'json_object' },
    })

    const content = response.choices[0]?.message?.content?.trim() ?? '{}'
    const decision = JSON.parse(content) as SupervisorDecision

    // 验证决策
    if (!decision.action || !decision.reasoning) {
      throw new Error('Invalid decision format')
    }

    return decision
  } catch (err) {
    // 降级策略：根据状态自动决策
    return fallbackDecision(stateSummary)
  }
}

/**
 * 降级决策逻辑（LLM 失败时）
 */
function fallbackDecision(stateSummary: string): SupervisorDecision {
  // 简单的规则引擎
  if (stateSummary.includes('已完成阶段: 无') || stateSummary.includes('当前阶段: init')) {
    return {
      action: 'delegate_recon',
      reasoning: '[降级决策] 开局阶段，启动侦察',
      phase: 'recon',
    }
  }

  if (stateSummary.includes('漏洞: 0 个') && stateSummary.includes('开放端口:')) {
    return {
      action: 'delegate_vuln_scan',
      reasoning: '[降级决策] 侦察完成，启动漏洞扫描',
      phase: 'vuln-scan',
    }
  }

  if (stateSummary.includes('[CRITICAL]') || stateSummary.includes('[HIGH]')) {
    return {
      action: 'delegate_exploit',
      reasoning: '[降级决策] 发现高危漏洞，启动利用',
      phase: 'exploit',
    }
  }

  if (stateSummary.includes('Shell: 1') || stateSummary.includes('Shell: 2')) {
    return {
      action: 'delegate_post_exploit',
      reasoning: '[降级决策] 已获得shell，启动后渗透',
      phase: 'post-exploit',
    }
  }

  return {
    action: 'finish',
    reasoning: '[降级决策] 无明确下一步，结束任务',
  }
}

/**
 * 路由函数 — 从状态中提取路由决策
 */
export function routeFromSupervisor(state: GraphStateType): RouteDecision {
  return state.nextAction as RouteDecision
}
