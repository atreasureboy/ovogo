/**
 * BattleOrchestrator — phase state machine + task DAG + LLM supervisor
 *
 * Manages the overall penetration testing engagement flow:
 * 1. Phase state machine — tracks current phase, allows LLM-guided transitions
 * 2. Task DAG — tracks dispatched agents, status, dependencies
 * 3. Supervisor — LLM decides what to dispatch next, respects RoE constraints
 *
 * Wraps the existing ExecutionEngine — does NOT replace it.
 * Calls engine.runTurn() for each agent dispatch, collects results into state.
 */

import type { Renderer } from '../ui/renderer.js'
import type { ExecutionEngine } from './engine.js'
import { AsyncTaskScheduler } from './taskScheduler.js'
import { OpenAICompatibleModelClient, type ModelClient } from './modelClient.js'
import { type Finding, parseFindingFromText, inferNextStep, shouldAutoProgress, buildChainContext } from './attackChain.js'

// ─── Phase definitions ──────────────────────────────────────────────────────

export type PhaseName =
  | 'init'
  | 'recon'
  | 'vuln-scan'
  | 'weapon-match'
  | 'exploit'
  | 'post-exploit'
  | 'privesc'
  | 'lateral'
  | 'report'
  | 'done'

export interface PhaseInfo {
  name: PhaseName
  description: string
  allowedNext: PhaseName[]  // LLM can transition to any of these
}

const PHASES: Record<PhaseName, PhaseInfo> = {
  'init':         { name: 'init',         description: '初始化',                  allowedNext: ['recon', 'vuln-scan', 'report'] },
  'recon':        { name: 'recon',        description: '侦察（子域名、端口、Web）', allowedNext: ['vuln-scan', 'weapon-match', 'exploit', 'done'] },
  'vuln-scan':    { name: 'vuln-scan',    description: '漏洞扫描',                allowedNext: ['weapon-match', 'exploit', 'recon', 'done'] },
  'weapon-match': { name: 'weapon-match', description: 'PoC 匹配',                allowedNext: ['exploit', 'vuln-scan', 'done'] },
  'exploit':      { name: 'exploit',      description: '漏洞利用（获取 shell）',   allowedNext: ['post-exploit', 'privesc', 'recon', 'done'] },
  'post-exploit': { name: 'post-exploit', description: '后渗透（信息收集）',       allowedNext: ['privesc', 'lateral', 'done'] },
  'privesc':      { name: 'privesc',      description: '权限提升',                allowedNext: ['lateral', 'post-exploit', 'done'] },
  'lateral':      { name: 'lateral',      description: '横向移动',                allowedNext: ['privesc', 'post-exploit', 'report', 'done'] },
  'report':       { name: 'report',       description: '生成报告',                allowedNext: ['done'] },
  'done':         { name: 'done',         description: '任务完成',                allowedNext: [] },
}

// ─── Task tracking ──────────────────────────────────────────────────────────

export type TaskStatus = 'pending' | 'dispatched' | 'running' | 'completed' | 'failed' | 'skipped'

export interface TaskNode {
  id: string
  type: string           // agent type or action name
  phase: PhaseName
  status: TaskStatus
  dependsOn: string[]    // task IDs that must complete before this can start
  prompt: string         // what the agent was asked to do
  result?: string        // summary of what was found
  findings: number       // count of findings produced
  startedAt?: number
  completedAt?: number
}

export class TaskDAG {
  private tasks = new Map<string, TaskNode>()

  /** Create a new task */
  add(task: Omit<TaskNode, 'id'> & { id?: string }): TaskNode {
    const id = task.id ?? `task_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`
    const node: TaskNode = { ...task, id, status: task.status ?? 'pending' }
    this.tasks.set(id, node)
    return node
  }

  /** Get task by ID */
  get(id: string): TaskNode | undefined {
    return this.tasks.get(id)
  }

  /** Update task status */
  update(id: string, updates: Partial<Pick<TaskNode, 'status' | 'result' | 'findings' | 'completedAt'>>): void {
    const task = this.tasks.get(id)
    if (task) Object.assign(task, updates)
  }

  /** Get all tasks in a phase */
  byPhase(phase: PhaseName): TaskNode[] {
    return [...this.tasks.values()].filter((t) => t.phase === phase)
  }

  /** Get all tasks with a status */
  byStatus(status: TaskStatus): TaskNode[] {
    return [...this.tasks.values()].filter((t) => t.status === status)
  }

  /** Check if all dependencies for a task are met */
  depsMet(task: TaskNode): boolean {
    return task.dependsOn.every((depId) => {
      const dep = this.tasks.get(depId)
      return dep && (dep.status === 'completed' || dep.status === 'skipped' || dep.status === 'failed')
    })
  }

  /** Get all tasks ready to run (pending + deps met) */
  getReady(): TaskNode[] {
    return [...this.tasks.values()].filter((t) => t.status === 'pending' && this.depsMet(t))
  }

  /** All tasks done? */
  isComplete(): boolean {
    return [...this.tasks.values()].every(
      (t) => ['completed', 'failed', 'skipped'].includes(t.status)
    )
  }

  /** Export for LLM context */
  toSummary(): string {
    const lines: string[] = []
    for (const task of this.tasks.values()) {
      const statusIcon = { pending: '⏳', dispatched: '📤', running: '🔄', completed: '✅', failed: '❌', skipped: '⏭️' }[task.status]
      lines.push(`${statusIcon} [${task.phase}] ${task.type}: ${task.result ?? task.prompt.slice(0, 80)} (发现: ${task.findings})`)
    }
    return lines.join('\n') || '(无任务)'
  }

  /** Full list */
  all(): TaskNode[] {
    return [...this.tasks.values()]
  }

  count(): number {
    return this.tasks.size
  }
}

// ─── Phase state machine ────────────────────────────────────────────────────

export class PhaseMachine {
  current: PhaseName = 'init'
  history: PhaseName[] = []
  findings: Finding[] = []
  ports: string[] = []
  services: string[] = []
  shellCount = 0
  credentialCount = 0

  /** Transition to a new phase */
  transition(to: PhaseName): boolean {
    const info = PHASES[this.current]
    if (!info || !info.allowedNext.includes(to)) return false
    this.history.push(this.current)
    this.current = to
    return true
  }

  /** Record a discovery — accepts either legacy (severity+title) or full Finding */
  recordFinding(severityOrFinding: string | Finding, titleArg?: string): void {
    if (typeof severityOrFinding === 'string') {
      // Legacy signature
      this.findings.push({
        severity: (severityOrFinding as 'critical' | 'high' | 'medium' | 'low' | 'info') ?? 'info',
        title: titleArg ?? '',
        phase: this.current,
        confidence: 50,
        vulnType: 'unknown',
        discoveredAt: Date.now(),
      })
    } else {
      this.findings.push(severityOrFinding)
    }
  }

  /** Record open ports/services */
  recordRecon(ports: string[], services: string[]): void {
    this.ports = [...new Set([...this.ports, ...ports])]
    this.services = [...new Set([...this.services, ...services])]
  }

  /** Record shell acquisition */
  recordShell(): void {
    this.shellCount++
  }

  /** Record credentials */
  recordCredentials(n: number): void {
    this.credentialCount += n
  }

  /** Get high-priority findings suitable for chain inference */
  getHighConfidenceFindings(): Finding[] {
    return this.findings.filter((f) => f.confidence >= 60)
  }

  /** Get a concise state summary for LLM */
  toSummary(): string {
    const criticalFindings = this.findings.filter((f) => f.severity === 'critical' || f.severity === 'high')
    return [
      `当前阶段: ${this.current} (${PHASES[this.current]?.description ?? ''})`,
      `已完成阶段: ${this.history.join(', ') || '无'}`,
      `发现: ${this.findings.length} 个漏洞 (${criticalFindings.length} 个高危以上, ${this.getHighConfidenceFindings().length} 个高置信度)`,
      `开放端口: ${this.ports.length} 个`,
      `Web 服务: ${this.services.length} 个`,
      `Shell: ${this.shellCount} 个`,
      `凭证: ${this.credentialCount} 个`,
      ...(criticalFindings.length > 0
        ? ['\n高危发现:']
        : []),
      ...criticalFindings.slice(-5).map((f) => `  [${f.severity.toUpperCase()}] ${f.title} (类型: ${f.vulnType}, 置信度: ${f.confidence}%)`),
    ].join('\n')
  }

  /** Get allowed next phases */
  allowedNext(): PhaseName[] {
    return PHASES[this.current]?.allowedNext ?? []
  }
}

// ─── Supervisor ─────────────────────────────────────────────────────────────

const SUPERVISOR_SYSTEM = `你是红队渗透测试的总指挥（Supervisor）。

## 职责
1. 分析当前渗透测试进度和成果
2. 决定下一步应该启动哪些子 agent
3. 确保攻击链的逻辑顺序和并行效率

## 标准攻击链阶段
1. recon — 侦察（子域名、端口、Web 服务、OSINT）
2. vuln-scan — 漏洞扫描（Web 漏洞、服务漏洞、认证攻击）
3. weapon-match — PoC 匹配（从内部 POC 库检索）
4. exploit — 漏洞利用（手动 + 工具，获取 shell）
5. post-exploit — 后渗透（信息收集、凭证提取）
6. privesc — 权限提升（SUID、sudo、内核漏洞）
7. lateral — 横向移动（内网扫描、凭证复用）
8. report — 生成报告

## 决策规则
- **开局必须并行**: recon 和 vuln-scan 同时启动
- **发现驱动**: 根据已发现的端口/服务/漏洞决定下一步
- **优先拿 shell**: 发现高危漏洞立即启动 exploit
- **不要等待**: 有可并行任务立即启动
- **靶场目标**: 最终目标是拿到 flag

## 可用的路由决策（next_phase 字段）
从 allowed_next 列表中选择一个阶段作为下一步。

## 输出格式（JSON）
{
  "reasoning": "决策推理（简要说明为什么做这个决定）",
  "next_phase": "下一个阶段名称",
  "dispatch": [
    {
      "agent_type": "agent 类型（如 recon, vuln-scan, manual-exploit 等）",
      "prompt": "给 agent 的具体任务描述（必须自包含目标、session_dir、具体任务）",
      "priority": "high|medium|low"
    }
  ]
}

dispatch 数组可以为空（等待当前 agent 完成）、也可以有多个（并行启动）。

## 关键原则
- 永远不要串行等待可以并行的任务
- 发现 Critical/High 漏洞立即利用
- 拿到 shell 后立即后渗透 + 提权
- 不要在信息收集阶段停滞不前`

interface EngagementContext {
  targets?: string[]
  outOfScope?: string[]
  phase?: string
  notes?: string
}

interface SupervisorDecision {
  reasoning: string
  next_phase: PhaseName
  dispatch: Array<{
    agent_type: string
    prompt: string
    priority: 'high' | 'medium' | 'low'
  }>
}

// ─── BattleOrchestrator ─────────────────────────────────────────────────────

export interface OrchestratorConfig {
  model: string
  apiKey: string
  baseURL?: string
  sessionDir: string
  primaryTarget?: string
  engagement?: EngagementContext
  cwd: string
}

export class BattleOrchestrator {
  private config: OrchestratorConfig
  private renderer: Renderer
  private engine: ExecutionEngine
  private phaseMachine = new PhaseMachine()
  private taskDAG = new TaskDAG()
  private scheduler: AsyncTaskScheduler
  private modelClient: ModelClient
  private maxCycles: number
  private cycleCount = 0

  constructor(config: OrchestratorConfig, renderer: Renderer, engine: ExecutionEngine, maxCycles = 50) {
    this.config = config
    this.renderer = renderer
    this.engine = engine
    this.maxCycles = maxCycles
    this.scheduler = new AsyncTaskScheduler(engine)
    this.modelClient = OpenAICompatibleModelClient.fromConfig({
      apiKey: config.apiKey,
      baseURL: config.baseURL,
    })
  }

  /** Run the full orchestrated engagement */
  async run(initialPrompt: string): Promise<void> {
    this.renderer.info(`[Orchestrator] 启动异步调度引擎 — 目标: ${this.config.primaryTarget ?? initialPrompt.slice(0, 60)}`)

    // Record initial task
    this.taskDAG.add({
      type: 'orchestrator',
      phase: 'init',
      status: 'completed',
      dependsOn: [],
      prompt: initialPrompt,
      result: '任务启动',
      findings: 0,
    })

    while (this.cycleCount < this.maxCycles) {
      this.cycleCount++
      this.renderer.info(`\n━━━ [周期 ${this.cycleCount}/${this.maxCycles}] ━━━`)

      // Step 1: Harvest completed tasks from previous cycle
      const completions = await this.scheduler.pollCompleted()
      for (const c of completions) {
        this.taskDAG.update(c.task.id, {
          status: c.success ? 'completed' : 'failed',
          result: c.output.slice(0, 500),
          findings: c.findings,
          completedAt: Date.now(),
        })
        this.extractFindings(c.task.id, c.output)
      }
      if (completions.length > 0) {
        this.renderer.info(`[Scheduler] ${completions.length} 个任务完成`)
        for (const c of completions) {
          const icon = c.success ? '✅' : '❌'
          this.renderer.info(`  ${icon} ${c.task.agentType}: ${c.output.slice(0, 100)}...`)
        }
      }

      // Step 2: Tick scheduler to launch eligible pending tasks
      if (!this.scheduler.isIdle) {
        const tick = await this.scheduler.tick()
        if (tick.launched > 0) {
          this.renderer.info(`[Scheduler] 启动 ${tick.launched} 个新任务`)
        }
      }

      // Step 3: Supervisor decides what to do next
      const decision = await this.supervisorDecide()

      if (decision) {
        this.renderer.info(`[Supervisor] ${decision.reasoning}`)
        this.renderer.info(`[Supervisor] 下一阶段: ${decision.next_phase} (${PHASES[decision.next_phase]?.description ?? ''})`)

        // Transition phase
        this.phaseMachine.transition(decision.next_phase)

        // Submit new dispatch requests to scheduler (non-blocking)
        if (decision.dispatch.length > 0) {
          const schedulerTasks = decision.dispatch.map((action) => {
            const taskId = `task_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`
            this.taskDAG.add({
              id: taskId,
              type: action.agent_type,
              phase: decision.next_phase,
              status: 'dispatched',
              dependsOn: [],
              prompt: action.prompt,
              findings: 0,
              startedAt: Date.now(),
            })
            return {
              id: taskId,
              agentType: action.agent_type,
              prompt: action.prompt,
              priority: action.priority,
              phase: decision.next_phase,
              dependsOn: [],
            }
          })

          this.scheduler.submit(schedulerTasks)

          // Tick to immediately launch eligible tasks
          const tick = await this.scheduler.tick()
          if (tick.launched > 0) {
            this.renderer.info(`[Scheduler] 启动 ${tick.launched} 个任务`)
          }
          for (const action of decision.dispatch) {
            this.renderer.info(`  [提交] ${action.agent_type} (${action.priority}): ${action.prompt.slice(0, 100)}...`)
          }
        }
      } else if (this.scheduler.isIdle) {
        this.renderer.info('[Orchestrator] 无更多行动，任务完成')
        this.phaseMachine.transition('done')
        break
      }

      // Step 4: Check if we should continue
      if (this.phaseMachine.current === 'done') {
        this.renderer.success('[Orchestrator] 任务完成')
        break
      }

      // If there are running tasks but no new dispatch, wait a bit
      if (!this.scheduler.isIdle && decision?.dispatch.length === 0) {
        this.renderer.info('[Scheduler] 等待后台任务完成...')
        // Brief pause to let background tasks progress
        await this.sleep(2000)
      }
    }

    this.renderFinalSummary()
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms))
  }

  /** LLM supervisor decides what to do next */
  private async supervisorDecide(): Promise<SupervisorDecision | null> {
    const stateSummary = this.phaseMachine.toSummary()
    const taskSummary = this.taskDAG.toSummary()
    const schedulerSummary = this.scheduler.toSummary()
    const allowedNext = this.phaseMachine.allowedNext()
    const roePrompt = this.buildRoEPrompt()
    const reconContext = this.buildReconContext()
    const chainContext = buildChainContext(this.phaseMachine.findings)

    const userPrompt = [
      `## 当前状态`,
      stateSummary,
      '',
      reconContext ? reconContext : '',
      chainContext ? chainContext : '',
      `## 调度器状态`,
      schedulerSummary,
      '',
      `## 任务执行记录`,
      taskSummary,
      '',
      `## 允许转换的下一阶段`,
      allowedNext.map((p) => `- ${p} (${PHASES[p]?.description ?? ''})`).join('\n'),
      '',
      roePrompt,
      '',
      `请决定下一步行动。输出 JSON 格式。`,
    ].filter(Boolean).join('\n')

    try {
      const content = await this.modelClient.completeText({
        model: this.config.model,
        messages: [
          { role: 'system', content: SUPERVISOR_SYSTEM },
          { role: 'user', content: userPrompt },
        ],
        temperature: 0,
        maxTokens: 1000,
        responseFormat: 'json_object',
      })

      if (!content) return this.autoProgressionDecision()

      const decision = JSON.parse(content) as SupervisorDecision

      // Validate and constrain
      if (!decision.next_phase || !allowedNext.includes(decision.next_phase)) {
        // Fallback: use current phase's first allowed next
        decision.next_phase = allowedNext[0] ?? 'done'
      }

      return decision
    } catch {
      return this.autoProgressionDecision() ?? this.fallbackDecision()
    }
  }

  /** Auto-progression decision based on attack-chain rules (no LLM call needed). */
  private autoProgressionDecision(): SupervisorDecision | null {
    const pm = this.phaseMachine
    const allowed = pm.allowedNext()

    // Find highest-confidence finding that should auto-progress
    const candidates = pm.findings
      .filter((f) => shouldAutoProgress(f))
      .sort((a, b) => b.confidence - a.confidence)

    for (const f of candidates) {
      const step = inferNextStep(f, this.config.primaryTarget ?? '目标')
      if (!step) continue
      if (!allowed.includes(step.phase)) continue
      return {
        reasoning: `[自动推进] 发现 ${f.vulnType} (${f.severity}, 置信度 ${f.confidence}%) → ${step.phase}`,
        next_phase: step.phase,
        dispatch: [{
          agent_type: step.agentType,
          prompt: step.prompt,
          priority: f.severity === 'critical' ? 'high' : 'medium',
        }],
      }
    }
    return null
  }

  /** Rule-based fallback decision */
  private fallbackDecision(): SupervisorDecision | null {
    const pm = this.phaseMachine
    const allowed = pm.allowedNext()

    if (pm.current === 'init') {
      return {
        reasoning: '[降级决策] 开局阶段',
        next_phase: 'recon',
        dispatch: [
          { agent_type: 'recon', prompt: `对 ${this.config.primaryTarget ?? '目标'} 进行全方位侦察（DNS/端口/Web/OSINT）`, priority: 'high' },
          { agent_type: 'vuln-scan', prompt: `对 ${this.config.primaryTarget ?? '目标'} 立即执行全量漏洞扫描`, priority: 'high' },
        ],
      }
    }

    if (pm.current === 'recon' && pm.ports.length > 0) {
      return {
        reasoning: '[降级决策] 侦察完成，启动漏洞扫描',
        next_phase: 'vuln-scan',
        dispatch: [
          { agent_type: 'vuln-scan', prompt: `基于已发现的 ${pm.ports.length} 个端口和 ${pm.services.length} 个服务，进行漏洞扫描`, priority: 'high' },
        ],
      }
    }

    if (pm.findings.some((f) => f.severity === 'critical' || f.severity === 'high')) {
      if (allowed.includes('exploit' as PhaseName)) {
        return {
          reasoning: '[降级决策] 发现高危漏洞，立即利用',
          next_phase: 'exploit',
          dispatch: [
            { agent_type: 'manual-exploit', prompt: `利用已发现的高危漏洞获取命令执行权限`, priority: 'high' },
          ],
        }
      }
    }

    if (pm.shellCount > 0 && allowed.includes('post-exploit' as PhaseName)) {
      return {
        reasoning: '[降级决策] 已获得 shell，启动后渗透',
        next_phase: 'post-exploit',
        dispatch: [
          { agent_type: 'target-recon', prompt: `在已控靶机上进行信息收集（本机 + 内网）`, priority: 'high' },
        ],
      }
    }

    // Default: move forward
    if (allowed.length > 0) {
      return {
        reasoning: '[降级决策] 推进到下一阶段',
        next_phase: allowed[0],
        dispatch: [],
      }
    }

    return null
  }

  /** Build RoE constraint prompt from engagement context */
  private buildRoEPrompt(): string {
    const e = this.config.engagement
    if (!e) return ''

    const lines: string[] = ['## 授权范围 (Rules of Engagement)']

    if (e.targets && e.targets.length > 0) {
      lines.push(`- **授权目标**: ${e.targets.join(', ')}`)
    }
    if (e.outOfScope && e.outOfScope.length > 0) {
      lines.push(`- **禁止触碰**: ${e.outOfScope.join(', ')}`)
    }
    if (e.phase) {
      lines.push(`- **当前阶段**: ${e.phase}`)
    }
    if (e.notes) {
      lines.push(`- **备注**: ${e.notes}`)
    }

    lines.push('')
    lines.push('严格遵守以上授权范围，不得对未授权目标执行任何操作。')

    return lines.join('\n')
  }

  /** Extract findings from agent output and update phase machine.
   *  Uses attackChain.parseFindingFromText to enrich each finding with vuln_type + confidence. */
  private extractFindings(taskId: string, output: string): void {
    const priorCount = this.phaseMachine.findings.length

    // Split output into lines and parse each [SEVERITY] marker as a potential finding
    const lines = output.split(/\r?\n/)
    for (const line of lines) {
      if (/\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]/i.test(line)) {
        const finding = parseFindingFromText(line, this.phaseMachine.current)
        if (finding) this.phaseMachine.recordFinding(finding)
      }
    }

    if (this.phaseMachine.findings.length > priorCount) {
      this.taskDAG.update(taskId, { findings: this.phaseMachine.findings.length - priorCount })

      // Auto-progression: any new high-confidence finding should escalate
      const newFindings = this.phaseMachine.findings.slice(priorCount)
      for (const f of newFindings) {
        if (shouldAutoProgress(f)) {
          this.renderer.info(
            `[AttackChain] 🔥 发现 ${f.vulnType} (置信度 ${f.confidence}%) — ` +
            `建议自动推进到 exploit 阶段`,
          )
        }
      }
    }

    // Shell detection
    if (/uid=\d+\(/.test(output) || /root@/.test(output)) {
      this.phaseMachine.recordShell()
    }

    // Port detection
    const portMatches = output.matchAll(/(\d+)\/(tcp|udp)\s+open/gi)
    for (const m of portMatches) {
      this.phaseMachine.recordRecon([`${m[1]}/${m[2]}`], [])
    }

    // Service detection (e.g. "22/tcp open ssh OpenSSH 7.4")
    const svcMatches = output.matchAll(/(\d+)\/(?:tcp|udp)\s+open\s+(\S+)(?:\s+(.+))?/gi)
    for (const m of svcMatches) {
      const svcName = m[3]?.split(/\s+/)[0] ?? m[2]
      if (svcName) this.phaseMachine.recordRecon([], [svcName])
    }
  }

  /** Build context to inject into vuln-scan / exploit prompts based on recon state */
  private buildReconContext(): string {
    const pm = this.phaseMachine
    if (pm.ports.length === 0 && pm.services.length === 0) return ''

    const lines: string[] = ['## 已知资产（从上一阶段结果注入）']
    if (pm.ports.length > 0) {
      lines.push(`- 开放端口: ${pm.ports.join(', ')}`)
    }
    if (pm.services.length > 0) {
      lines.push(`- 已识别服务: ${[...new Set(pm.services)].join(', ')}`)
    }
    if (pm.findings.length > 0) {
      lines.push(`- 已有发现: ${pm.findings.length} 个 (${pm.findings.filter((f) => f.severity === 'critical' || f.severity === 'high').length} 个高危以上)`)
      const lastCritical = pm.findings.filter((f) => f.severity === 'critical' || f.severity === 'high').slice(-3)
      for (const f of lastCritical) {
        lines.push(`  · [${f.severity.toUpperCase()}] ${f.title}${f.target ? ` @ ${f.target}` : ''}`)
      }
    }
    return lines.join('\n')
  }

  /** Render final summary */
  private renderFinalSummary(): void {
    const pm = this.phaseMachine
    this.renderer.info('')
    this.renderer.info('═'.repeat(60))
    this.renderer.info('最终总结')
    this.renderer.info('═'.repeat(60))
    this.renderer.info(``)
    this.renderer.info(`执行周期: ${this.cycleCount}`)
    this.renderer.info(`已完成阶段: ${pm.history.join(' → ')} → ${pm.current}`)
    this.renderer.info(`发现: ${pm.findings.length} 个漏洞, ${pm.shellCount} 个 shell, ${pm.credentialCount} 个凭证`)
    this.renderer.info(`任务: ${this.taskDAG.count()} 个, 执行记录:`)
    this.renderer.info(pm.toSummary())
    this.renderer.info('')
    this.renderer.info('═'.repeat(60))
  }
}
