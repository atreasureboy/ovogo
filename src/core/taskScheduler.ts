/**
 * AsyncTaskScheduler — orchestrator-level async task scheduling
 *
 * Solves two problems:
 * 1. **Time efficiency**: dispatchAgents() was sequentially awaiting each
 *    engine.runTurn(), so recon(10min) + vuln-scan(2h) = 2.5h serial.
 *    Now independent tasks launch as background Promises (not awaited).
 * 2. **Dependency/conflict management**: tasks with dependsOn wait for
 *    predecessors; tasks targeting the same resource don't overlap.
 *
 * Flow per orchestrator cycle:
 *   submit(tasks)  → queue pending
 *   tick()         → launch independent tasks as background Promises (don't await completion)
 *   pollCompleted() → harvest finished tasks for supervisor context
 */

import type { ExecutionEngine } from './engine.js'

// ─── Types ──────────────────────────────────────────────────────────────────

export interface SchedulerTask {
  id: string
  agentType: string
  prompt: string
  priority: 'high' | 'medium' | 'low'
  phase: string
  dependsOn: string[]     // task IDs that must complete before this can start
  targetResource?: string // extracted target IP/domain for conflict detection
}

export interface ScheduledResult {
  task: SchedulerTask
  output: string
  findings: number
  success: boolean
}

interface RunningEntry {
  task: SchedulerTask
  promise: Promise<{ task: SchedulerTask; result: { output: string; stopped: boolean; reason: string } }>
  startedAt: number
}

// ─── Timeout configuration ──────────────────────────────────────────────────

const DEFAULT_TASK_TIMEOUT_MS = 30 * 60 * 1000  // 30 minutes

const AGENT_TYPE_TIMEOUTS: Record<string, number> = {
  'manual-exploit': 45 * 60 * 1000,  // 45 min — complex exploit chains
  'tool-exploit':   45 * 60 * 1000,  // 45 min — msf/sliver can be slow
  'recon':          20 * 60 * 1000,  // 20 min — subdomain/port scans
  'vuln-scan':      60 * 60 * 1000,  // 60 min — nuclei full templates
  'lateral':        45 * 60 * 1000,  // 45 min — lateral movement chains
  'privesc':        30 * 60 * 1000,  // 30 min — privilege escalation
  'report':         15 * 60 * 1000,  // 15 min — report generation
}

function getTimeoutForAgentType(agentType: string): number {
  return AGENT_TYPE_TIMEOUTS[agentType] ?? DEFAULT_TASK_TIMEOUT_MS
}

// ─── Resource extraction ────────────────────────────────────────────────────

const IP_RE = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/
const URL_RE = /https?:\/\/([a-zA-Z0-9._:-]+)/
const DOMAIN_RE = /\b([a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+)\b/

function extractTargetResource(prompt: string): string | undefined {
  // Skip common placeholder tokens
  const skip = new Set(['target', 'TARGET', 'session', 'SESSION_DIR', 'session_dir'])
  let m = prompt.match(IP_RE)
  if (m && !skip.has(m[1])) return m[1]
  m = prompt.match(URL_RE)
  if (m && !skip.has(m[1])) return m[1]
  m = prompt.match(DOMAIN_RE)
  if (m && !skip.has(m[1])) return m[1]
  return undefined
}

// ─── AsyncTaskScheduler ─────────────────────────────────────────────────────

export class AsyncTaskScheduler {
  private engine: ExecutionEngine
  private pending: SchedulerTask[] = []
  private running = new Map<string, RunningEntry>()
  private completed: ScheduledResult[] = []
  private failed: SchedulerTask[] = []
  private completedIds = new Set<string>()
  private failedIds = new Set<string>()

  constructor(engine: ExecutionEngine) {
    this.engine = engine
  }

  /** Queue tasks for scheduling */
  submit(tasks: SchedulerTask[]): void {
    for (const task of tasks) {
      // Auto-extract target resource if not provided
      if (!task.targetResource) {
        task.targetResource = extractTargetResource(task.prompt)
      }
      this.pending.push(task)
    }
  }

  /**
   * One scheduling tick:
   * 1. Check which pending tasks have dependencies met + no resource conflict
   * 2. Launch eligible tasks as background Promises (do NOT await completion)
   * 3. Harvest any just-finished tasks into completed[]
   */
  async tick(): Promise<{ launched: number; completed: number }> {
    // First, harvest any just-finished tasks
    const harvested = await this.harvestCompleted()

    // Then launch eligible pending tasks
    let launched = 0
    const stillPending: SchedulerTask[] = []

    for (const task of this.pending) {
      if (this.canRun(task)) {
        this.launchTask(task)
        launched++
      } else {
        stillPending.push(task)
      }
    }

    this.pending = stillPending
    return { launched, completed: harvested }
  }

  /**
   * Poll for recently-completed tasks.
   * Returns tasks that finished since last call.
   */
  async pollCompleted(): Promise<ScheduledResult[]> {
    const harvested = await this.harvestCompleted()
    const results = this.completed.slice(-harvested)
    return results
  }

  /** Get currently running tasks */
  getRunning(): SchedulerTask[] {
    return [...this.running.values()].map((e) => e.task)
  }

  /** Get recently completed results */
  getCompleted(): ScheduledResult[] {
    return [...this.completed]
  }

  /** Get failed tasks */
  getFailed(): SchedulerTask[] {
    return [...this.failed]
  }

  /** Check if a task can run (deps met + no resource conflict) */
  private canRun(task: SchedulerTask): boolean {
    // Check dependencies
    const depsMet = task.dependsOn.every(
      (depId) => this.completedIds.has(depId) || this.failedIds.has(depId)
    )
    if (!depsMet) return false

    // Check resource conflict: same target already running
    if (task.targetResource) {
      for (const entry of this.running.values()) {
        if (entry.task.targetResource === task.targetResource) {
          // Same target — don't overlap unless same task type (concurrent scans ok)
          if (entry.task.agentType !== task.agentType) {
            return false
          }
        }
      }
    }

    return true
  }

  /** Launch a task as a background Promise with timeout */
  private launchTask(task: SchedulerTask): void {
    const timeoutMs = getTimeoutForAgentType(task.agentType)

    const taskPromise = this.engine.runTurn(
      this.buildTaskPrompt(task),
      [],
    ).then(({ result }) => ({ task, result }))

    const timeoutPromise = new Promise<{ task: SchedulerTask; result: { output: string; stopped: boolean; reason: string } }>((resolve) => {
      setTimeout(() => {
        resolve({
          task,
          result: {
            output: `[任务超时] ${task.agentType} 任务执行超过 ${timeoutMs / 60000} 分钟，自动标记为超时。任务可能仍在后台运行。`,
            stopped: true,
            reason: 'timeout',
          },
        })
      }, timeoutMs)
    })

    const promise = Promise.race([taskPromise, timeoutPromise])

    promise
      .then(({ task, result }) => {
        this.running.delete(task.id)
        this.completedIds.add(task.id)
        this.completed.push({
          task,
          output: result.output,
          findings: this.countFindings(result.output),
          success: !result.stopped || result.reason === 'stop_sequence',
        })
      })
      .catch((err) => {
        this.running.delete(task.id)
        this.failedIds.add(task.id)
        this.failed.push(task)
        // Record as completed with error info
        this.completed.push({
          task,
          output: `异常: ${(err as Error).message}`,
          findings: 0,
          success: false,
        })
      })

    this.running.set(task.id, {
      task,
      promise,
      startedAt: Date.now(),
    })
  }

  /** Harvest finished promises into completed[] */
  private async harvestCompleted(): Promise<number> {
    const beforeCount = this.completed.length
    const entries = [...this.running.values()]

    for (const entry of entries) {
      // Check if promise is settled by awaiting it with a timeout of 0
      // This is non-blocking: it only picks up already-resolved promises
      const settled = await this.isSettled(entry.promise)
      if (settled) {
        // The promise handler already moved it to completed/failed
        // (see launchTask .then/.catch above)
      }
    }

    return this.completed.length - beforeCount
  }

  /** Check if a promise has settled without blocking */
  private async isSettled(p: Promise<unknown>): Promise<boolean> {
    const flag = { done: false }
    const wrapped = p.then(
      () => { flag.done = true },
      () => { flag.done = true },
    )
    // Race with a zero-delay timeout — if promise is already resolved,
    // the microtask will have run and flag.done will be true
    await Promise.race([
      wrapped,
      new Promise<void>((resolve) => setImmediate(resolve)),
    ])
    return flag.done
  }

  /** Build the system prompt for a scheduled task */
  private buildTaskPrompt(task: SchedulerTask): string {
    const parts: string[] = [
      `你是 Ovogo 红队子 agent，专项类型: ${task.agentType}。`,
      ``,
      `## 任务`,
      task.prompt,
    ]
    return parts.join('\n')
  }

  /** Count findings in agent output */
  private countFindings(output: string): number {
    const matches = output.match(/\[(CRITICAL|HIGH|MEDIUM|LOW)\]\s+.+/gi)
    return matches?.length ?? 0
  }

  /** Human-readable summary for supervisor context */
  toSummary(): string {
    const lines: string[] = []

    if (this.running.size > 0) {
      lines.push('## 当前运行中的任务')
      for (const entry of this.running.values()) {
        const elapsed = Math.round((Date.now() - entry.startedAt) / 60000)
        const timeoutMin = Math.round(getTimeoutForAgentType(entry.task.agentType) / 60000)
        const resource = entry.task.targetResource ? ` → ${entry.task.targetResource}` : ''
        lines.push(`- [running] ${entry.task.agentType}: ${entry.task.prompt.slice(0, 80)}... (已运行 ${elapsed}min / 超时 ${timeoutMin}min${resource})`)
      }
    }

    if (this.completed.length > 0) {
      lines.push('## 本轮已完成的任务')
      for (const c of this.completed.slice(-10)) {
        lines.push(`- [completed] ${c.task.agentType}: ${c.output.slice(0, 120)}${c.output.length > 120 ? '...' : ''}`)
      }
    }

    if (this.pending.length > 0) {
      lines.push('## 排队等待启动的任务')
      for (const t of this.pending.slice(-10)) {
        const blocked = this.canRun(t) ? '等待资源' : `依赖: ${t.dependsOn.join(', ')}`
        lines.push(`- [pending] ${t.agentType}: ${t.prompt.slice(0, 80)}... (${blocked})`)
      }
    }

    if (lines.length === 0) return '(无调度任务)'
    return lines.join('\n')
  }

  /** Reset state for a new cycle */
  clearCompleted(): void {
    this.completed.length = 0
    this.failed.length = 0
    // Don't clear completedIds — needed for dependency tracking
  }

  /** Full reset */
  reset(): void {
    this.pending.length = 0
    this.running.clear()
    this.completed.length = 0
    this.failed.length = 0
    this.completedIds.clear()
    this.failedIds.clear()
  }

  /** Total tasks count (pending + running + completed) */
  get totalCount(): number {
    return this.pending.length + this.running.size + this.completed.length + this.failed.length
  }

  /** Are all tasks done? */
  get isIdle(): boolean {
    return this.pending.length === 0 && this.running.size === 0
  }
}
