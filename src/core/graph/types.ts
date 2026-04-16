/**
 * LangGraph State Types — 共享状态定义
 *
 * 所有节点（supervisor + workers）通过这个共享状态通信。
 * 每个节点返回部分状态更新，LangGraph 自动合并。
 */

import { Annotation } from '@langchain/langgraph'

// ── 发现类型 ──────────────────────────────────────────────────

export interface Finding {
  id: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  title: string
  description: string
  target: string
  evidence: string
  cve?: string[]
  mitre_ttp?: string[]
  timestamp: number
}

export interface Port {
  port: number
  protocol: string
  service?: string
  version?: string
}

export interface WebService {
  url: string
  status: number
  title?: string
  tech?: string[]
  waf?: string
}

export interface Credential {
  type: 'password' | 'hash' | 'key' | 'token'
  username?: string
  value: string
  source: string
  target: string
}

export interface Shell {
  id: string
  type: 'reverse' | 'bind' | 'webshell' | 'c2'
  target: string
  port?: number
  status: 'active' | 'dead' | 'unknown'
  user?: string
  privilege?: string
  timestamp: number
}

// ── 消息类型 ──────────────────────────────────────────────────

export interface GraphMessage {
  role: 'supervisor' | 'worker' | 'user' | 'system'
  content: string
  agentType?: string
  timestamp: number
  metadata?: Record<string, unknown>
}

// ── 阶段结果 ──────────────────────────────────────────────────

export interface PhaseResult {
  phase: string
  agentType: string
  success: boolean
  summary: string
  outputFiles: string[]
  findings: Finding[]
  timestamp: number
  duration: number
}

// ── 错误记录 ──────────────────────────────────────────────────

export interface GraphError {
  agent: string
  error: string
  timestamp: number
  recoverable: boolean
}

// ── 主状态定义 ────────────────────────────────────────────────

/**
 * LangGraph 共享状态
 *
 * 使用 Annotation.Root 定义，支持自动合并策略：
 * - 数组字段：自动追加（concat）
 * - 对象字段：自动合并（merge）
 * - 基础类型：覆盖（replace）
 */
export const GraphState = Annotation.Root({
  // ── 任务信息 ────────────────────────────────────────────────
  task: Annotation<string>({
    reducer: (prev, next) => next ?? prev,
    default: () => '',
  }),

  primaryTarget: Annotation<string | undefined>({
    reducer: (prev, next) => next ?? prev,
    default: () => undefined,
  }),

  sessionDir: Annotation<string>({
    reducer: (prev, next) => next ?? prev,
    default: () => '',
  }),

  // ── 阶段控制 ────────────────────────────────────────────────
  currentPhase: Annotation<string>({
    reducer: (prev, next) => next ?? prev,
    default: () => 'init',
  }),

  phaseResults: Annotation<Record<string, PhaseResult>>({
    reducer: (prev, next) => ({ ...prev, ...next }),
    default: () => ({}),
  }),

  completedPhases: Annotation<Set<string>>({
    reducer: (prev, next) => new Set([...prev, ...next]),
    default: () => new Set(),
  }),

  // ── Agent 通信 ──────────────────────────────────────────────
  messages: Annotation<GraphMessage[]>({
    reducer: (prev, next) => [...prev, ...next],
    default: () => [],
  }),

  // ── 发现和成果 ──────────────────────────────────────────────
  findings: Annotation<Finding[]>({
    reducer: (prev, next) => [...prev, ...next],
    default: () => [],
  }),

  openPorts: Annotation<Port[]>({
    reducer: (prev, next) => [...prev, ...next],
    default: () => [],
  }),

  webServices: Annotation<WebService[]>({
    reducer: (prev, next) => [...prev, ...next],
    default: () => [],
  }),

  credentials: Annotation<Credential[]>({
    reducer: (prev, next) => [...prev, ...next],
    default: () => [],
  }),

  shells: Annotation<Shell[]>({
    reducer: (prev, next) => [...prev, ...next],
    default: () => [],
  }),

  subdomains: Annotation<string[]>({
    reducer: (prev, next) => [...new Set([...prev, ...next])],
    default: () => [],
  }),

  ips: Annotation<string[]>({
    reducer: (prev, next) => [...new Set([...prev, ...next])],
    default: () => [],
  }),

  // ── 控制流 ──────────────────────────────────────────────────
  nextAction: Annotation<string>({
    reducer: (prev, next) => next ?? prev,
    default: () => 'start',
  }),

  activeAgents: Annotation<Set<string>>({
    reducer: (prev, next) => new Set([...prev, ...next]),
    default: () => new Set(),
  }),

  waitingForAgents: Annotation<string[]>({
    reducer: (prev, next) => next ?? prev,
    default: () => [],
  }),

  // ── 错误处理 ────────────────────────────────────────────────
  errors: Annotation<GraphError[]>({
    reducer: (prev, next) => [...prev, ...next],
    default: () => [],
  }),

  // ── 用户交互 ────────────────────────────────────────────────
  userFeedback: Annotation<string | undefined>({
    reducer: (prev, next) => next ?? prev,
    default: () => undefined,
  }),

  pauseRequested: Annotation<boolean>({
    reducer: (prev, next) => next ?? prev,
    default: () => false,
  }),
})

export type GraphStateType = typeof GraphState.State

// ── 节点返回类型 ──────────────────────────────────────────────

/**
 * 节点函数返回部分状态更新
 * LangGraph 会自动合并到主状态
 */
export type NodeUpdate = Partial<GraphStateType>

// ── 路由决策类型 ──────────────────────────────────────────────

export type RouteDecision =
  | 'delegate_recon'
  | 'delegate_vuln_scan'
  | 'delegate_weapon_match'
  | 'delegate_exploit'
  | 'delegate_post_exploit'
  | 'delegate_privesc'
  | 'delegate_lateral'
  | 'delegate_report'
  | 'wait_for_agents'
  | 'user_input'
  | 'finish'
  | 'error'

// ── Supervisor 决策输出 ───────────────────────────────────────

export interface SupervisorDecision {
  action: RouteDecision
  reasoning: string
  phase?: string
  agentsToLaunch?: Array<{
    type: string
    priority: number
    context: Record<string, unknown>
  }>
}

// ── Agent 执行结果 ────────────────────────────────────────────

export interface AgentExecutionResult {
  agentType: string
  success: boolean
  summary: string
  outputFiles: string[]
  findings: Finding[]
  openPorts?: Port[]
  webServices?: WebService[]
  credentials?: Credential[]
  shells?: Shell[]
  subdomains?: string[]
  ips?: string[]
  duration: number
  error?: string
}
