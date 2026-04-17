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
