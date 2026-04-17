/**
 * LangGraph Builder — 构建渗透测试状态图
 *
 * 图结构：
 *   START → supervisor → [条件路由] → worker nodes → supervisor → ... → END
 *
 * Supervisor 决定下一步启动哪个 worker，worker 完成后回到 supervisor。
 */

import { StateGraph, END, START } from '@langchain/langgraph'
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
  return new StateGraph(GraphState)
    // ── 添加节点 ──────────────────────────────────────────────────
    .addNode('supervisor', supervisorNode)
    .addNode('recon', reconWorker)
    .addNode('vuln_scan', vulnScanWorker)
    .addNode('weapon_match', weaponMatchWorker)
    .addNode('exploit', exploitWorker)
    .addNode('post_exploit', postExploitWorker)
    .addNode('privesc', privescWorker)
    .addNode('lateral', lateralWorker)
    .addNode('report', reportWorker)
    // ── 设置入口 ──────────────────────────────────────────────────
    .addEdge(START, 'supervisor')
    // ── 条件路由：Supervisor → Workers ────────────────────────────
    .addConditionalEdges('supervisor', routeFromSupervisor, {
      delegate_recon: 'recon',
      delegate_vuln_scan: 'vuln_scan',
      delegate_weapon_match: 'weapon_match',
      delegate_exploit: 'exploit',
      delegate_post_exploit: 'post_exploit',
      delegate_privesc: 'privesc',
      delegate_lateral: 'lateral',
      delegate_report: 'report',
      wait_for_agents: 'supervisor',
      finish: END,
      error: END,
    })
    // ── Workers → Supervisor（完成后回到协调节点）─────────────────
    .addEdge('recon', 'supervisor')
    .addEdge('vuln_scan', 'supervisor')
    .addEdge('weapon_match', 'supervisor')
    .addEdge('exploit', 'supervisor')
    .addEdge('post_exploit', 'supervisor')
    .addEdge('privesc', 'supervisor')
    .addEdge('lateral', 'supervisor')
    // Report 完成后直接结束
    .addEdge('report', END)
    // ── 编译图 ────────────────────────────────────────────────────
    .compile()
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
