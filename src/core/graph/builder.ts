/**
 * LangGraph Builder — 构建渗透测试状态图
 *
 * 图结构：
 *   START → supervisor → [条件路由] → worker nodes → supervisor → ... → END
 *
 * Supervisor 决定下一步启动哪个 worker，worker 完成后回到 supervisor。
 */

import { StateGraph, END } from '@langchain/langgraph'
import { GraphState, type GraphStateType, type RouteDecision } from './types.js'
import { supervisorNode, routeFromSupervisor } from './nodes/supervisor.js'
import {
  reconWorker,
  vulnScanWorker,
  weaponMatchWorker,
  exploitWorker,
  postExploitWorker,
  privescWorker,
  lateralWorker,
  reportWorker,
} from './nodes/workers.js'

/**
 * 构建完整的渗透测试状态图
 */
export function buildPentestGraph() {
  const graph = new StateGraph(GraphState)

  // ── 添加节点 ──────────────────────────────────────────────────

  // 主协调节点
  graph.addNode('supervisor', supervisorNode)

  // Worker 节点（各阶段子 agent）
  graph.addNode('recon', reconWorker)
  graph.addNode('vuln_scan', vulnScanWorker)
  graph.addNode('weapon_match', weaponMatchWorker)
  graph.addNode('exploit', exploitWorker)
  graph.addNode('post_exploit', postExploitWorker)
  graph.addNode('privesc', privescWorker)
  graph.addNode('lateral', lateralWorker)
  graph.addNode('report', reportWorker)

  // ── 设置入口 ──────────────────────────────────────────────────

  graph.addEdge('__start__', 'supervisor')

  // ── 条件路由：Supervisor → Workers ────────────────────────────

  graph.addConditionalEdges(
    'supervisor',
    routeFromSupervisor,
    {
      delegate_recon: 'recon',
      delegate_vuln_scan: 'vuln_scan',
      delegate_weapon_match: 'weapon_match',
      delegate_exploit: 'exploit',
      delegate_post_exploit: 'post_exploit',
      delegate_privesc: 'privesc',
      delegate_lateral: 'lateral',
      delegate_report: 'report',
      wait_for_agents: 'supervisor', // 循环等待
      finish: END,
      error: END,
    },
  )

  // ── Workers → Supervisor（完成后回到协调节点）─────────────────

  graph.addEdge('recon', 'supervisor')
  graph.addEdge('vuln_scan', 'supervisor')
  graph.addEdge('weapon_match', 'supervisor')
  graph.addEdge('exploit', 'supervisor')
  graph.addEdge('post_exploit', 'supervisor')
  graph.addEdge('privesc', 'supervisor')
  graph.addEdge('lateral', 'supervisor')

  // Report 完成后直接结束
  graph.addEdge('report', END)

  // ── 编译图 ────────────────────────────────────────────────────

  return graph.compile()
}

/**
 * 创建初始状态
 */
export function createInitialState(params: {
  task: string
  primaryTarget?: string
  sessionDir: string
}): GraphStateType {
  const { task, primaryTarget, sessionDir } = params

  return {
    // 任务信息
    task,
    primaryTarget,
    sessionDir,

    // 阶段控制
    currentPhase: 'init',
    phaseResults: {},
    completedPhases: new Set(),

    // Agent 通信
    messages: [
      {
        role: 'system',
        content: `任务启动: ${task}`,
        timestamp: Date.now(),
      },
    ],

    // 发现和成果
    findings: [],
    openPorts: [],
    webServices: [],
    credentials: [],
    shells: [],
    subdomains: [],
    ips: [],

    // 控制流
    nextAction: 'start',
    activeAgents: new Set(),
    waitingForAgents: [],

    // 错误处理
    errors: [],

    // 用户交互
    userFeedback: undefined,
    pauseRequested: false,
  }
}
