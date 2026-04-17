/**
 * Shared agent-level types used across all agent modules.
 * (recon, vuln-scan, exploit, post-exploit, privesc, lateral, c2, report)
 *
 * Previously each module defined its own copy — consolidated here to avoid drift.
 */

// ── Tool result ───────────────────────────────────────────────────────────────
// Flexible enough to cover both strict tool results (with duration/tool) and
// simplified skill/agent results (with message).
export interface ToolResult<T = unknown> {
  success: boolean
  data: T
  rawOutput?: string
  error?: string
  message?: string
  duration?: number
  tool?: string
}

// ── Skill result ──────────────────────────────────────────────────────────────
export interface SkillResult<T = unknown> {
  success: boolean
  data: T
  steps: SkillStep[]
  duration: number
  skill: string
  error?: string
}

export interface SkillStep {
  tool: string
  success: boolean
  duration?: number
  dataCount: number
  error?: string
}

// ── Shell command result (for executeCommand) ─────────────────────────────────
export interface ShellCommandResult {
  output: string
  success: boolean
  exitCode: number
}
