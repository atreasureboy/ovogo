import { existsSync, readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { homedir } from 'node:os'
import { z } from 'zod'

const PermissionRuleSchema = z.string().min(1).max(500)

export const PermissionRulesSchema = z.object({
  allow: z.array(PermissionRuleSchema).optional(),
  deny: z.array(PermissionRuleSchema).optional(),
})

export type PermissionRules = z.infer<typeof PermissionRulesSchema>

export interface ParsedPermissionRule {
  toolName: string
  /** Glob pattern for the tool's input. Empty string means "match any input". */
  inputPattern: string
}

/**
 * Load permission rules from project `.ovogo/permissions.json` and global
 * `~/.ovogo/permissions.json`. Project rules override global rules with the
 * same tool name + pattern.
 */
export function loadPermissionRules(cwd: string): { rules: PermissionRules; diagnostics: string[] } {
  const globalPath = join(homedir(), '.ovogo', 'permissions.json')
  const projectPath = resolve(cwd, '.ovogo', 'permissions.json')
  const diagnostics: string[] = []
  let rules: PermissionRules = {}

  for (const path of [globalPath, projectPath]) {
    if (!existsSync(path)) continue
    try {
      const raw = JSON.parse(readFileSync(path, 'utf8'))
      const parsed = PermissionRulesSchema.safeParse(raw)
      if (!parsed.success) {
        diagnostics.push(`${path}: ${parsed.error.issues.map((i) => i.message).join('; ')}`)
        continue
      }
      rules = mergeRules(rules, parsed.data)
    } catch (err) {
      diagnostics.push(`${path}: ${(err as Error).message}`)
    }
  }
  return { rules, diagnostics }
}

function mergeRules(base: PermissionRules, overlay: PermissionRules): PermissionRules {
  return {
    allow: dedupe([...(base.allow ?? []), ...(overlay.allow ?? [])]),
    deny: dedupe([...(base.deny ?? []), ...(overlay.deny ?? [])]),
  }
}

function dedupe<T>(items: T[]): T[] {
  return Array.from(new Set(items))
}

const RULE_RE = /^([A-Za-z][A-Za-z0-9_]*)(?:\((.+)\))?$/

/**
 * Parse a rule string like `Bash(nmap:*)` or `Read(/shared/**)`.
 * Returns null if the rule is malformed.
 */
export function parsePermissionRule(rule: string): ParsedPermissionRule | null {
  const trimmed = rule.trim()
  const match = RULE_RE.exec(trimmed)
  if (!match) return null
  return {
    toolName: match[1],
    inputPattern: (match[2] ?? '').trim(),
  }
}

export interface RuleMatchContext {
  toolName: string
  input: Record<string, unknown>
  cwd: string
}

/**
 * Test whether a rule matches a tool call. The pattern is matched against a
 * tool-specific projection of the input:
 *   - Bash: the `command` string
 *   - Read/Write/Edit/DocRead: the `file_path` string
 *   - MultiScan: each `output_file` in `tasks`
 *   - other tools: empty (tool name match alone is enough)
 */
export function ruleMatches(rule: ParsedPermissionRule, ctx: RuleMatchContext): boolean {
  if (rule.toolName !== ctx.toolName) return false
  if (rule.inputPattern === '') return true

  const targets = extractMatchTargets(ctx.toolName, ctx.input)
  for (const target of targets) {
    if (matchGlob(rule.inputPattern, target)) return true
  }
  return false
}

function extractMatchTargets(toolName: string, input: Record<string, unknown>): string[] {
  if (toolName === 'Bash') {
    return typeof input.command === 'string' ? [input.command] : []
  }
  if (toolName === 'Read' || toolName === 'Write' || toolName === 'Edit' || toolName === 'DocRead') {
    return typeof input.file_path === 'string' ? [input.file_path] : []
  }
  if (toolName === 'MultiScan' && Array.isArray(input.tasks)) {
    return input.tasks
      .map((t) => (t && typeof t === 'object' && typeof (t as { output_file?: unknown }).output_file === 'string'
        ? (t as { output_file: string }).output_file
        : null))
      .filter((p): p is string => p !== null)
  }
  return []
}

/**
 * Glob-style match: `*` matches any chars except `/`+ `?`, `**` matches across `/`.
 * Implemented minimally so we don't pull in a full glob library at this layer.
 */
export function matchGlob(pattern: string, target: string): boolean {
  if (pattern === '*') return true
  // Translate to regex
  let re = '^'
  let i = 0
  while (i < pattern.length) {
    const c = pattern[i]
    if (c === '*') {
      if (pattern[i + 1] === '*') {
        re += '.*'
        i += 2
        if (pattern[i] === '/') i += 1
      } else {
        re += '[^/]*'
        i += 1
      }
    } else if (c === '?') {
      re += '[^/]'
      i += 1
    } else if ('.+^$|()[]{}\\'.includes(c)) {
      re += '\\' + c
      i += 1
    } else {
      re += c
      i += 1
    }
  }
  re += '$'
  return new RegExp(re).test(target)
}

/**
 * Evaluate rules: deny always wins. Returns null if no rule matched.
 */
export function evaluateRules(rules: PermissionRules, ctx: RuleMatchContext): 'allow' | 'deny' | null {
  const allowPatterns = (rules.allow ?? []).map(parsePermissionRule).filter((r): r is ParsedPermissionRule => r !== null)
  const denyPatterns = (rules.deny ?? []).map(parsePermissionRule).filter((r): r is ParsedPermissionRule => r !== null)

  for (const rule of denyPatterns) {
    if (ruleMatches(rule, ctx)) return 'deny'
  }
  for (const rule of allowPatterns) {
    if (ruleMatches(rule, ctx)) return 'allow'
  }
  return null
}