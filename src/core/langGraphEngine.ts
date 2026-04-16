/**
 * LangGraph Engine — 基于 LangGraph 的主引擎
 *
 * 替代原有的 ExecutionEngine，使用状态图管理整个渗透测试流程。
 */

import type { Renderer } from '../ui/renderer.js'
import { buildPentestGraph, createInitialState } from './graph/builder.js'
import { initSupervisor } from './graph/nodes/supervisor.js'
import type { GraphStateType } from './graph/types.js'

export interface LangGraphEngineConfig {
  model: string
  apiKey: string
  baseURL?: string
  sessionDir: string
  primaryTarget?: string
  cwd: string
}

export class LangGraphEngine {
  private config: LangGraphEngineConfig
  private renderer: Renderer
  private graph: ReturnType<typeof buildPentestGraph>

  constructor(config: LangGraphEngineConfig, renderer: Renderer) {
    this.config = config
    this.renderer = renderer

    // 初始化 supervisor
    initSupervisor({
      apiKey: config.apiKey,
      baseURL: config.baseURL,
      model: config.model,
    })

    // 构建图
    this.graph = buildPentestGraph()
  }

  /**
   * 执行任务
   */
  async runTask(task: string): Promise<void> {
    const { sessionDir, primaryTarget } = this.config

    this.renderer.info(`[LangGraph] 启动任务: ${task}`)
    this.renderer.info(`[LangGraph] Session: ${sessionDir}`)

    // 创建初始状态
    const initialState = createInitialState({
      task,
      primaryTarget,
      sessionDir,
    })

    try {
      // 流式执行图
      const stream = await this.graph.stream(initialState, {
        streamMode: 'values',
      })

      let lastState: GraphStateType | null = null

      for await (const state of stream) {
        lastState = state as GraphStateType
        this.renderStateUpdate(state as GraphStateType)
      }

      // 最终总结
      if (lastState) {
        this.renderFinalSummary(lastState)
      }

      this.renderer.success('[LangGraph] 任务完成')
    } catch (err: unknown) {
      const error = err as Error
      this.renderer.error(`[LangGraph] 执行失败: ${error.message}`)
      throw err
    }
  }

  /**
   * 渲染状态更新
   */
  private renderStateUpdate(state: GraphStateType): void {
    const { currentPhase, activeAgents, messages, findings, shells } = state

    // 显示最新消息
    const latestMessage = messages[messages.length - 1]
    if (latestMessage) {
      const prefix = latestMessage.agentType
        ? `[${latestMessage.agentType}]`
        : `[${latestMessage.role}]`

      if (latestMessage.role === 'supervisor') {
        this.renderer.info(`\n${prefix} ${latestMessage.content}`)
      } else if (latestMessage.role === 'worker') {
        this.renderer.success(`${prefix} ${latestMessage.content.slice(0, 200)}`)
      }
    }

    // 显示活跃 agent
    if (activeAgents.size > 0) {
      this.renderer.info(`  活跃 agent: ${[...activeAgents].join(', ')}`)
    }

    // 显示关键成果
    if (findings.length > 0) {
      const criticalFindings = findings.filter((f) => f.severity === 'critical')
      if (criticalFindings.length > 0) {
        this.renderer.warn(`  ⚠️  发现 ${criticalFindings.length} 个 CRITICAL 漏洞`)
      }
    }

    if (shells.length > 0) {
      const activeShells = shells.filter((s) => s.status === 'active')
      if (activeShells.length > 0) {
        this.renderer.success(`  🎯 获得 ${activeShells.length} 个活跃 shell`)
      }
    }
  }

  /**
   * 渲染最终总结
   */
  private renderFinalSummary(state: GraphStateType): void {
    const { completedPhases, findings, openPorts, webServices, shells, credentials } = state

    this.renderer.newline()
    this.renderer.info('═'.repeat(60))
    this.renderer.info('最终总结')
    this.renderer.info('═'.repeat(60))

    this.renderer.info(`已完成阶段: ${[...completedPhases].join(', ')}`)
    this.renderer.newline()

    this.renderer.info(`发现统计:`)
    this.renderer.info(`  - 漏洞: ${findings.length} 个`)
    this.renderer.info(`  - 开放端口: ${openPorts.length} 个`)
    this.renderer.info(`  - Web 服务: ${webServices.length} 个`)
    this.renderer.info(`  - Shell: ${shells.length} 个`)
    this.renderer.info(`  - 凭证: ${credentials.length} 个`)
    this.renderer.newline()

    // 按严重程度分类漏洞
    const bySeverity = {
      critical: findings.filter((f) => f.severity === 'critical').length,
      high: findings.filter((f) => f.severity === 'high').length,
      medium: findings.filter((f) => f.severity === 'medium').length,
      low: findings.filter((f) => f.severity === 'low').length,
      info: findings.filter((f) => f.severity === 'info').length,
    }

    if (findings.length > 0) {
      this.renderer.info(`漏洞分布:`)
      if (bySeverity.critical > 0) this.renderer.warn(`  - CRITICAL: ${bySeverity.critical}`)
      if (bySeverity.high > 0) this.renderer.warn(`  - HIGH: ${bySeverity.high}`)
      if (bySeverity.medium > 0) this.renderer.info(`  - MEDIUM: ${bySeverity.medium}`)
      if (bySeverity.low > 0) this.renderer.info(`  - LOW: ${bySeverity.low}`)
      if (bySeverity.info > 0) this.renderer.info(`  - INFO: ${bySeverity.info}`)
      this.renderer.newline()
    }

    // 显示活跃 shell
    const activeShells = shells.filter((s) => s.status === 'active')
    if (activeShells.length > 0) {
      this.renderer.success(`活跃 Shell:`)
      for (const shell of activeShells.slice(0, 5)) {
        this.renderer.success(`  - ${shell.id} (${shell.type}) @ ${shell.target}`)
      }
      this.renderer.newline()
    }

    this.renderer.info('═'.repeat(60))
  }

  /**
   * 获取当前模型
   */
  getModel(): string {
    return this.config.model
  }
}
