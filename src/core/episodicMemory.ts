/**
 * EpisodicMemory — action trajectory persistence
 *
 * Records "what I did, what happened, was it successful" for each tool call
 * and agent action. Lets the agent review its recent history of attempts
 * without re-reading the full conversation.
 *
 * Storage: ~/.ovogo/projects/{slug}/memory/episodes.jsonl
 */

import { appendFileSync, existsSync, readFileSync, mkdirSync } from 'fs'
import { join } from 'path'
import { redactRecord } from './redaction.js'

export interface EpisodicMemoryEntry {
  id: string
  turn: number
  toolName: string
  inputSummary: string   // truncated input
  resultSummary: string  // truncated result
  outcome: 'success' | 'failure' | 'partial'
  duration?: number      // ms
  timestamp: string      // ISO 8601
}

let _epCounter = 0
function nextId(): string {
  _epCounter++
  return `epi_${Date.now()}_${_epCounter}`
}

export class EpisodicMemory {
  private filePath: string

  constructor(projectDir: string) {
    const memDir = join(projectDir, 'memory')
    try { mkdirSync(memDir, { recursive: true }) } catch { /* best-effort */ }
    this.filePath = join(memDir, 'episodes.jsonl')
  }

  /** Append a new episode entry */
  write(entry: Omit<EpisodicMemoryEntry, 'id'>): EpisodicMemoryEntry {
    const full = redactRecord({ ...entry, id: nextId() }) as unknown as EpisodicMemoryEntry
    try {
      appendFileSync(this.filePath, JSON.stringify(full) + '\n', 'utf8')
    } catch { /* best-effort */ }
    return full
  }

  /** Read the most recent N episodes */
  recent(limit = 20): EpisodicMemoryEntry[] {
    const all = this.readAll()
    return all.slice(-limit)
  }

  /** Read all entries */
  readAll(): EpisodicMemoryEntry[] {
    if (!existsSync(this.filePath)) return []
    try {
      const lines = readFileSync(this.filePath, 'utf8').trim().split('\n').filter(Boolean)
      return lines.map((l) => JSON.parse(l) as EpisodicMemoryEntry)
    } catch {
      return []
    }
  }

  /** Search episodes by tool name */
  findByTool(toolName: string, limit = 10): EpisodicMemoryEntry[] {
    const all = this.readAll()
    return all.filter((e) => e.toolName === toolName).slice(-limit)
  }

  /** Count total entries */
  count(): number {
    return this.readAll().length
  }
}
