/**
 * KnowledgeBase — cross-session growing attack knowledge
 *
 * Stores four types of knowledge as JSONL files:
 * - attack_patterns: successful attack chains (recon → vuln → exploit → shell)
 * - cve_notes: real-world CVE exploitation notes (what worked, what didn't)
 * - tool_combos: validated tool combinations (subfinder+httpx+nuclei → vulns)
 * - target_profiles: target type fingerprint + common weaknesses
 *
 * Dual directory: global (~/.ovogo/knowledge/) + project (~/.ovogo/projects/{slug}/knowledge/)
 * Writes go to project dir (if available), reads merge both.
 */

import { appendFileSync, existsSync, readFileSync, mkdirSync } from 'fs'
import { join } from 'path'
import { homedir } from 'os'

// ─── Entry types ──────────────────────────────────────────────────────────────

export type KnowledgeType = 'attack_patterns' | 'cve_notes' | 'tool_combos' | 'target_profiles'

export interface AttackPatternEntry {
  id: string
  title: string
  chain: string[]
  target_type: string
  techniques: string[]       // MITRE TTP IDs
  success_rate: number       // 0-1
  used_count: number
  last_used: string          // ISO or empty
  created_at: string
}

export interface CveNoteEntry {
  id: string
  cve: string
  service: string
  exploit_summary: string
  payload_type: string       // "curl" | "python" | "msf" | "other"
  success: boolean
  confidence: number         // 0-1
  notes: string
  created_at: string
}

export interface ToolComboEntry {
  id: string
  name: string
  tools: string[]
  command_template: string
  purpose: string
  used_count: number
  success_rate: number
  created_at: string
}

export interface TargetProfileEntry {
  id: string
  target_type: string
  indicators: string[]
  common_weaknesses: string[]
  successful_techniques: string[]
  created_at: string
}

export type KnowledgeEntry =
  | { type: 'attack_patterns'; data: AttackPatternEntry }
  | { type: 'cve_notes'; data: CveNoteEntry }
  | { type: 'tool_combos'; data: ToolComboEntry }
  | { type: 'target_profiles'; data: TargetProfileEntry }

const KNOWLEDGE_FILES: Record<KnowledgeType, string> = {
  attack_patterns: 'attack_patterns.jsonl',
  cve_notes: 'cve_notes.jsonl',
  tool_combos: 'tool_combos.jsonl',
  target_profiles: 'target_profiles.jsonl',
}

const GLOBAL_KNOWLEDGE_DIR = join(homedir(), '.ovogo', 'knowledge')

let _kbCounter = 0
function nextId(): string {
  _kbCounter++
  return `kb_${Date.now()}_${_kbCounter}`
}

// ─── KnowledgeBase ────────────────────────────────────────────────────────────

export class KnowledgeBase {
  private globalDir: string
  private projectDir?: string

  constructor(projectDir?: string) {
    this.globalDir = GLOBAL_KNOWLEDGE_DIR
    this.projectDir = projectDir
    try { mkdirSync(this.globalDir, { recursive: true }) } catch { /* best-effort */ }
    if (this.projectDir) {
      try { mkdirSync(this.projectDir, { recursive: true }) } catch { /* best-effort */ }
    }
  }

  /** Write an entry. Uses project dir if available, falls back to global */
  write(type: KnowledgeType, entry: Record<string, unknown>): void {
    const dir = this.projectDir ?? this.globalDir
    const filePath = join(dir, KNOWLEDGE_FILES[type])
    const fullEntry = { ...entry, id: (entry as any).id || nextId(), created_at: (entry as any).created_at || new Date().toISOString() }
    try {
      appendFileSync(filePath, JSON.stringify(fullEntry) + '\n', 'utf8')
    } catch { /* best-effort — knowledge write must never break the engine */ }
  }

  /** Read all entries of a type from both global and project dirs */
  readAll<T extends Record<string, unknown>>(type: KnowledgeType): T[] {
    const results: T[] = []
    const dirs = [this.globalDir]
    if (this.projectDir) dirs.push(this.projectDir)

    for (const dir of dirs) {
      const filePath = join(dir, KNOWLEDGE_FILES[type])
      if (!existsSync(filePath)) continue
      try {
        const lines = readFileSync(filePath, 'utf8').trim().split('\n').filter(Boolean)
        for (const line of lines) {
          try { results.push(JSON.parse(line) as T) } catch { /* skip malformed */ }
        }
      } catch { /* skip unreadable */ }
    }

    // Deduplicate by id (project entries override global)
    const seen = new Map<string, T>()
    for (const entry of results) {
      const id = (entry as any).id
      if (id) seen.set(id, entry)
    }
    return Array.from(seen.values())
  }

  /** Search entries by tags/keywords with confidence-based ranking */
  search(type: KnowledgeType, options: { tags?: string[]; keywords?: string[]; limit?: number }): KnowledgeEntry[] {
    const all = this.readAll(type) as Record<string, unknown>[]
    let results = all

    if (options.keywords && options.keywords.length > 0) {
      const kwLower = options.keywords.map((k) => k.toLowerCase())
      results = results.filter((e) => {
        const searchable = Object.values(e)
          .filter((v) => typeof v === 'string' || Array.isArray(v))
          .map((v) => Array.isArray(v) ? v.join(' ') : v as string)
          .join(' ')
          .toLowerCase()
        return kwLower.some((kw) => searchable.includes(kw))
      })
    }

    if (options.tags && options.tags.length > 0) {
      results = results.filter((e) => {
        const tags = (e.techniques as string[]) || (e.indicators as string[]) || []
        return options.tags!.some((t) => tags.includes(t))
      })
    }

    // Sort by success_rate/used_count descending, then by created_at descending
    results.sort((a, b) => {
      const rateA = (a.success_rate ?? a.confidence ?? 0) as number
      const rateB = (b.success_rate ?? b.confidence ?? 0) as number
      if (rateB !== rateA) return rateB - rateA
      return String(b.created_at || '').localeCompare(String(a.created_at || ''))
    })

    const limit = options.limit ?? 15
    return results.map((data) => ({ type, data } as unknown as KnowledgeEntry)).slice(0, limit)
  }

  /** Search all knowledge types for entries related to a specific target */
  searchByTarget(target: string, limit = 10): KnowledgeEntry[] {
    const allEntries: KnowledgeEntry[] = []
    const types: KnowledgeType[] = ['attack_patterns', 'cve_notes', 'tool_combos', 'target_profiles']

    for (const type of types) {
      const entries = this.search(type, { keywords: [target], limit })
      allEntries.push(...entries)
    }

    allEntries.sort((a, b) => {
      const countA = ((a.data as any).used_count ?? 0) as number
      const countB = ((b.data as any).used_count ?? 0) as number
      return countB - countA
    })

    return allEntries.slice(0, limit)
  }

  /** Get recommended attack patterns for a target type */
  recommend(targetType: string, limit = 5): AttackPatternEntry[] {
    const all = this.readAll('attack_patterns') as unknown as AttackPatternEntry[]
    const relevant = all.filter((e) =>
      e.target_type?.toLowerCase().includes(targetType.toLowerCase()) ||
      e.title?.toLowerCase().includes(targetType.toLowerCase())
    )
    relevant.sort((a, b) => {
      const scoreA = a.success_rate * 0.6 + Math.min(a.used_count / 10, 1) * 0.4
      const scoreB = b.success_rate * 0.6 + Math.min(b.used_count / 10, 1) * 0.4
      return scoreB - scoreA
    })
    return relevant.slice(0, limit)
  }

  /** Record that a knowledge entry was used (increment count, update success) */
  recordUsage(id: string, success: boolean, type?: KnowledgeType): void {
    // We don't modify in-place (JSONL append-only); instead, write an updated entry
    // The search will pick up the latest by dedup logic if we use the same id
    const types: KnowledgeType[] = type ? [type] : ['attack_patterns', 'cve_notes', 'tool_combos', 'target_profiles']

    for (const t of types) {
      const all = this.readAll(t) as Record<string, unknown>[]
      const entry = all.find((e) => (e as any).id === id)
      if (entry) {
        const updated = { ...entry }
        updated.used_count = ((updated.used_count ?? 0) as number) + 1
        updated.last_used = new Date().toISOString()
        if (updated.success_rate !== undefined) {
          const currentRate = updated.success_rate as number
          const count = updated.used_count as number
          updated.success_rate = (currentRate * (count - 1) + (success ? 1 : 0)) / count
        }
        this.write(t, updated)
        return
      }
    }
  }

  /** Format entries into a prompt section for injection */
  toPrompt(entries: KnowledgeEntry[]): string {
    if (entries.length === 0) return ''

    const sections: string[] = []

    // Group by type
    const byType = new Map<KnowledgeType, KnowledgeEntry[]>()
    for (const entry of entries) {
      const list = byType.get(entry.type) || []
      list.push(entry)
      byType.set(entry.type, list)
    }

    if (byType.has('attack_patterns')) {
      const items = byType.get('attack_patterns')!
      const lines = items.map((e) => {
        const d = e.data as AttackPatternEntry
        const chain = d.chain.join(' → ')
        return `- [${d.target_type}] ${d.title} (成功率: ${(d.success_rate * 100).toFixed(0)}%, 使用${d.used_count}次): ${chain}`
      })
      sections.push(`### 实战攻击模式 (Battle-Tested Attack Patterns)\n${lines.join('\n')}`)
    }

    if (byType.has('cve_notes')) {
      const items = byType.get('cve_notes')!
      const lines = items.map((e) => {
        const d = e.data as CveNoteEntry
        const status = d.success ? '成功' : '失败'
        return `- [${d.cve}] ${d.service} → ${d.exploit_summary} [${status}, 可信度: ${(d.confidence * 100).toFixed(0)}%]`
      })
      sections.push(`### CVE 实战笔记 (CVE Exploitation Notes)\n${lines.join('\n')}`)
    }

    if (byType.has('tool_combos')) {
      const items = byType.get('tool_combos')!
      const lines = items.map((e) => {
        const d = e.data as ToolComboEntry
        return `- ${d.name}: \`${d.command_template}\` — ${d.purpose} (成功率: ${(d.success_rate * 100).toFixed(0)}%, 使用${d.used_count}次)`
      })
      sections.push(`### 验证工具组合 (Validated Tool Combinations)\n${lines.join('\n')}`)
    }

    if (byType.has('target_profiles')) {
      const items = byType.get('target_profiles')!
      const lines = items.map((e) => {
        const d = e.data as TargetProfileEntry
        return `- **${d.target_type}**: 特征[${d.indicators.join(', ')}] | 弱点[${d.common_weaknesses.join(', ')}] | 有效技术[${d.successful_techniques.join(', ')}]`
      })
      sections.push(`### 目标画像 (Target Profiles)\n${lines.join('\n')}`)
    }

    return `# 实战知识库 (Battle Knowledge)\n\n以下是从以往渗透测试 session 中提取的实战经验，优先参考这些已验证的攻击路径。\n\n${sections.join('\n\n')}`
  }

  /** Get total entry count across all types */
  count(): number {
    let total = 0
    const types: KnowledgeType[] = ['attack_patterns', 'cve_notes', 'tool_combos', 'target_profiles']
    for (const type of types) {
      total += this.readAll(type).length
    }
    return total
  }

  /** Get stats per type */
  stats(): Record<KnowledgeType, number> {
    const result = {} as Record<KnowledgeType, number>
    const types: KnowledgeType[] = ['attack_patterns', 'cve_notes', 'tool_combos', 'target_profiles']
    for (const type of types) {
      result[type] = this.readAll(type).length
    }
    return result
  }
}
