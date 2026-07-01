import { redactText } from './redaction.js'

/**
 * DispatchManager — async agent dispatch with callback pattern
 *
 * Allows the main agent to dispatch tasks to sub-agents without blocking,
 * then check status and retrieve results later. Sub-agent completion
 * triggers a callback that injects the result into the next conversation turn.
 */

export type DispatchStatus = 'pending' | 'running' | 'completed' | 'failed'

export interface DispatchRecord {
  id: string
  agentType: string
  prompt: string
  status: DispatchStatus
  result?: string
  error?: string
  startedAt: string
  completedAt?: string
}

export type DispatchCallback = (record: DispatchRecord) => void

let _dispCounter = 0
function nextId(): string {
  _dispCounter++
  return `disp_${Date.now()}_${_dispCounter}`
}

export class DispatchManager {
  private dispatches = new Map<string, DispatchRecord>()
  private callbacks: DispatchCallback[] = []

  /** Create a new dispatch record */
  create(agentType: string, prompt: string): DispatchRecord {
    const id = nextId()
    const record: DispatchRecord = {
      id,
      agentType,
      prompt: redactText(prompt).slice(0, 500),
      status: 'pending',
      startedAt: new Date().toISOString(),
    }
    this.dispatches.set(id, record)
    return record
  }

  /** Update dispatch status */
  update(id: string, updates: Partial<Pick<DispatchRecord, 'status' | 'result' | 'error'>>): void {
    const record = this.dispatches.get(id)
    if (!record) return
    Object.assign(record, redactDispatchUpdates(updates))
    if (updates.status === 'completed' || updates.status === 'failed') {
      record.completedAt = new Date().toISOString()
      // Trigger callbacks
      for (const cb of this.callbacks) {
        try { cb({ ...record }) } catch { /* best-effort */ }
      }
    }
  }

  /** Get a dispatch record by ID */
  get(id: string): DispatchRecord | undefined {
    return this.dispatches.get(id)
  }

  /** List all dispatches, optionally filtered by status */
  list(status?: DispatchStatus): DispatchRecord[] {
    const all = Array.from(this.dispatches.values())
    if (status) return all.filter((d) => d.status === status)
    return all
  }

  /** Register a callback for dispatch completion */
  onCompletion(cb: DispatchCallback): void {
    this.callbacks.push(cb)
  }

  /** Get all completed dispatch results (for injection into next turn) */
  getCompletedSince(sinceIso?: string): DispatchRecord[] {
    const all = Array.from(this.dispatches.values())
    if (!sinceIso) return all.filter((d) => d.status === 'completed')
    return all.filter(
      (d) => d.status === 'completed' && d.completedAt && d.completedAt >= sinceIso,
    )
  }

  /** Count pending/running dispatches */
  activeCount(): number {
    return Array.from(this.dispatches.values()).filter(
      (d) => d.status === 'pending' || d.status === 'running',
    ).length
  }

  /** Clear completed dispatches to free memory */
  clearCompleted(): void {
    for (const [id, record] of this.dispatches) {
      if (record.status === 'completed' || record.status === 'failed') {
        this.dispatches.delete(id)
      }
    }
  }
}

function redactDispatchUpdates(
  updates: Partial<Pick<DispatchRecord, 'status' | 'result' | 'error'>>,
): Partial<Pick<DispatchRecord, 'status' | 'result' | 'error'>> {
  return {
    ...updates,
    result: typeof updates.result === 'string' ? redactText(updates.result) : updates.result,
    error: typeof updates.error === 'string' ? redactText(updates.error) : updates.error,
  }
}
