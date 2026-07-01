/**
 * SemanticMemory — cross-turn knowledge persistence for penetration testing
 *
 * Stores discovered facts (CVEs, credentials, network topology, exploit results)
 * as tagged entries in a JSONL file. Simple keyword/tag-based retrieval — no
 * embedding dependencies (can be added later as an optimization).
 *
 * Storage: ~/.ovogo/projects/{slug}/memory/semantic.jsonl
 */

import { appendFileSync, existsSync, readFileSync, mkdirSync } from 'fs'
import { join } from 'path'
import { redactRecord } from './redaction.js'

export interface SemanticMemoryEntry {
  id: string
  content: string
  tags: string[]
  source: string      // tool name or module that wrote this
  timestamp: string   // ISO 8601
  confidence: number  // 0–1, how confident we are this is correct
}

let _memCounter = 0
function nextId(): string {
  _memCounter++
  return `sem_${Date.now()}_${_memCounter}`
}

export class SemanticMemory {
  private filePath: string

  constructor(projectDir: string) {
    const memDir = join(projectDir, 'memory')
    try { mkdirSync(memDir, { recursive: true }) } catch { /* best-effort */ }
    this.filePath = join(memDir, 'semantic.jsonl')
  }

  /** Append a new memory entry */
  write(entry: Omit<SemanticMemoryEntry, 'id'>): SemanticMemoryEntry {
    const full = redactRecord({ ...entry, id: nextId() }) as unknown as SemanticMemoryEntry
    try {
      appendFileSync(this.filePath, JSON.stringify(full) + '\n', 'utf8')
    } catch { /* best-effort */ }
    return full
  }

  /** Read all entries */
  readAll(): SemanticMemoryEntry[] {
    if (!existsSync(this.filePath)) return []
    try {
      const lines = readFileSync(this.filePath, 'utf8').trim().split('\n').filter(Boolean)
      return lines.map((l) => JSON.parse(l) as SemanticMemoryEntry)
    } catch {
      return []
    }
  }

  /** Search by tags and/or keywords in content */
  search(options: { tags?: string[]; keywords?: string[]; limit?: number }): SemanticMemoryEntry[] {
    const all = this.readAll()
    let results = all

    if (options.tags && options.tags.length > 0) {
      results = results.filter((e) =>
        e.tags.some((t) => options.tags!.includes(t)),
      )
    }

    if (options.keywords && options.keywords.length > 0) {
      const lowerKeywords = options.keywords.map((k) => k.toLowerCase())
      results = results.filter((e) =>
        lowerKeywords.some((kw) => e.content.toLowerCase().includes(kw)),
      )
    }

    // Sort by confidence descending, then by timestamp descending
    results.sort((a, b) => {
      if (b.confidence !== a.confidence) return b.confidence - a.confidence
      return b.timestamp.localeCompare(a.timestamp)
    })

    const limit = options.limit ?? 20
    return results.slice(0, limit)
  }

  /** Get entries relevant to a specific target/host */
  searchByTarget(target: string, limit = 15): SemanticMemoryEntry[] {
    return this.search({
      keywords: [target],
      limit,
    })
  }

  /** Count total entries */
  count(): number {
    return this.readAll().length
  }
}
