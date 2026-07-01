import { redactText } from './redaction.js'

/**
 * Shared types for agent execution results.
 * Used by bin/agent-worker.ts and the main engine.
 */

export interface Finding {
  title: string
  description: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  evidence?: string
  remediation?: string
}

export interface Port {
  port: number
  protocol: string
  service?: string
  version?: string
}

export interface WebService {
  url: string
  status: number
  title?: string
  tech?: string[]
}

export interface Credential {
  host: string
  username: string
  password: string
  source: string
}

export interface Shell {
  host: string
  user: string
  type: string
}

export interface AgentExecutionResult {
  agentType: string
  success: boolean
  summary: string
  outputFiles: string[]
  findings: Finding[]
  openPorts?: Port[]
  webServices?: WebService[]
  credentials?: Credential[]
  shells?: Shell[]
  subdomains?: string[]
  ips?: string[]
  duration: number
  error?: string
}

const RESULT_SENSITIVE_KEY_RE = /(api[_-]?key|authorization|cookie|password|passwd|private[_-]?key|secret|token)/i

/**
 * Redact an agent result before it is persisted or reintroduced to another
 * agent.  Unlike generic record redaction, this preserves the credentials
 * array shape while masking sensitive leaf values such as password/token.
 */
export function redactAgentExecutionResult(result: AgentExecutionResult): AgentExecutionResult {
  return redactResultValue(result) as AgentExecutionResult
}

function redactResultValue(value: unknown, key = ''): unknown {
  if (typeof value === 'string') {
    return RESULT_SENSITIVE_KEY_RE.test(key) ? '[REDACTED]' : redactText(value)
  }
  if (value === null || typeof value !== 'object') return value
  if (Array.isArray(value)) return value.map((item) => redactResultValue(item))

  const output: Record<string, unknown> = {}
  for (const [entryKey, entryValue] of Object.entries(value)) {
    output[entryKey] = redactResultValue(entryValue, entryKey)
  }
  return output
}
