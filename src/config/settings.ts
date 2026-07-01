/**
 * Settings loader — reads .ovogo/settings.json from project and global dirs
 *
 * Config resolution order (later entries win):
 *   ~/.ovogo/settings.json   (global user defaults)
 *   .ovogo/settings.json     (project-specific, relative to cwd)
 *
 * Example settings.json:
 * {
 *   "hooks": {
 *     "PreToolCall": [
 *       { "matcher": "Bash", "command": "echo \"Running: $OVOGO_TOOL_INPUT\"" }
 *     ],
 *     "PostToolCall": [
 *       { "matcher": "Write,Edit", "command": "npx prettier --write \"$OVOGO_TOOL_NAME\" 2>/dev/null || true" }
 *     ],
 *     "UserPromptSubmit": [
 *       { "command": "logger -t ovogogogo \"prompt: $OVOGO_PROMPT\"" }
 *     ]
 *   }
 * }
 *
 * Hook env vars:
 *   PreToolCall:       OVOGO_TOOL_NAME, OVOGO_TOOL_INPUT (JSON)
 *   PostToolCall:      OVOGO_TOOL_NAME, OVOGO_TOOL_RESULT, OVOGO_TOOL_IS_ERROR
 *   UserPromptSubmit:  OVOGO_PROMPT
 */

import { readFileSync, existsSync } from 'fs'
import { resolve, join } from 'path'
import { homedir } from 'os'
import { z } from 'zod'

export interface HookEntry {
  /** Comma-separated tool names to match, or "*" / omit for all. Supports trailing "*" wildcard. */
  matcher?: string
  /** Shell command to execute. Runs with tool env vars set. */
  command: string
}

export interface HooksConfig {
  PreToolCall?: HookEntry[]
  PostToolCall?: HookEntry[]
  UserPromptSubmit?: HookEntry[]
}

/**
 * 渗透测试交战范围与上下文
 * 配置在 .ovogo/settings.json 的 "engagement" 字段
 */
export interface EngagementScope {
  /** 任务名称，如 "ZhhovoTop 外网渗透 2026-Q2" */
  name?: string
  /** 当前渗透阶段 */
  phase?: 'recon' | 'initial-access' | 'lateral-movement' | 'post-exploitation' | 'exfiltration'
  /** 授权目标列表（IP、CIDR、域名） */
  targets?: string[]
  /** 明确排除的目标（不得触碰） */
  out_of_scope?: string[]
  /** 任务开始日期 ISO 8601 */
  start_date?: string
  /** 任务截止日期 ISO 8601 */
  end_date?: string
  /** 额外备注（客户联系人、特殊要求等） */
  notes?: string
}

export interface OvogoSettings {
  hooks?: HooksConfig
  engagement?: EngagementScope
  runtime?: RuntimeSettings
  profile?: ProfileSettings
}

export interface RuntimeSettings {
  model?: string
  maxIterations?: number
  maxConcurrentToolCalls?: number
  permissionMode?: 'auto' | 'ask' | 'deny'
  readableRoots?: string[]
  writableRoots?: string[]
}

export interface ProfileSettings {
  /** `redteam` preserves legacy behavior; `generic` uses a domain-neutral prompt. */
  name?: 'redteam' | 'generic'
}

export interface SettingsDiagnostic {
  path: string
  level: 'warning' | 'error'
  message: string
}

const HookEntrySchema = z.object({
  matcher: z.string().optional(),
  command: z.string().min(1),
})

const HooksConfigSchema = z.object({
  PreToolCall: z.array(HookEntrySchema).optional(),
  PostToolCall: z.array(HookEntrySchema).optional(),
  UserPromptSubmit: z.array(HookEntrySchema).optional(),
}).partial()

const EngagementScopeSchema = z.object({
  name: z.string().optional(),
  phase: z.enum(['recon', 'initial-access', 'lateral-movement', 'post-exploitation', 'exfiltration']).optional(),
  targets: z.array(z.string()).optional(),
  out_of_scope: z.array(z.string()).optional(),
  start_date: z.string().optional(),
  end_date: z.string().optional(),
  notes: z.string().optional(),
}).partial()

const OvogoSettingsSchema = z.object({
  hooks: HooksConfigSchema.optional(),
  engagement: EngagementScopeSchema.optional(),
  runtime: z.object({
    model: z.string().min(1).optional(),
    maxIterations: z.number().int().positive().optional(),
    maxConcurrentToolCalls: z.number().int().positive().optional(),
    permissionMode: z.enum(['auto', 'ask', 'deny']).optional(),
    readableRoots: z.array(z.string()).optional(),
    writableRoots: z.array(z.string()).optional(),
  }).partial().optional(),
  profile: z.object({
    name: z.enum(['redteam', 'generic']).optional(),
  }).partial().optional(),
}).partial()

function formatZodIssues(error: z.ZodError): string {
  return error.issues
    .map((issue) => `${issue.path.join('.') || '<root>'}: ${issue.message}`)
    .join('; ')
}

function tryParse(path: string): { settings: OvogoSettings; diagnostics: SettingsDiagnostic[] } {
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf8')) as unknown
    const result = OvogoSettingsSchema.safeParse(parsed)
    if (!result.success) {
      return {
        settings: {},
        diagnostics: [{
          path,
          level: 'error',
          message: `Invalid settings schema: ${formatZodIssues(result.error)}`,
        }],
      }
    }
    return { settings: result.data, diagnostics: [] }
  } catch (err: unknown) {
    return {
      settings: {},
      diagnostics: [{
        path,
        level: 'error',
        message: `Unable to parse settings: ${(err as Error).message}`,
      }],
    }
  }
}

function mergeSettings(a: OvogoSettings, b: OvogoSettings): OvogoSettings {
  const mergedEngagement = b.engagement
    ? {
        ...(a.engagement ?? {}),
        ...b.engagement,
        targets: b.engagement.targets ?? a.engagement?.targets,
        out_of_scope: b.engagement.out_of_scope ?? a.engagement?.out_of_scope,
      }
    : a.engagement

  return {
    hooks: {
      PreToolCall: [...(a.hooks?.PreToolCall ?? []), ...(b.hooks?.PreToolCall ?? [])],
      PostToolCall: [...(a.hooks?.PostToolCall ?? []), ...(b.hooks?.PostToolCall ?? [])],
      UserPromptSubmit: [...(a.hooks?.UserPromptSubmit ?? []), ...(b.hooks?.UserPromptSubmit ?? [])],
    },
    engagement: mergedEngagement,
    runtime: {
      ...(a.runtime ?? {}),
      ...(b.runtime ?? {}),
    },
    profile: {
      ...(a.profile ?? {}),
      ...(b.profile ?? {}),
    },
  }
}

export function loadSettings(cwd: string): OvogoSettings {
  return loadSettingsWithDiagnostics(cwd).settings
}

export function loadSettingsWithDiagnostics(cwd: string): {
  settings: OvogoSettings
  diagnostics: SettingsDiagnostic[]
} {
  const globalPath = join(homedir(), '.ovogo', 'settings.json')
  const projectPath = resolve(cwd, '.ovogo', 'settings.json')

  let settings: OvogoSettings = {}
  const diagnostics: SettingsDiagnostic[] = []
  if (existsSync(globalPath)) {
    const loaded = tryParse(globalPath)
    settings = mergeSettings(settings, loaded.settings)
    diagnostics.push(...loaded.diagnostics)
  }
  if (existsSync(projectPath)) {
    const loaded = tryParse(projectPath)
    settings = mergeSettings(settings, loaded.settings)
    diagnostics.push(...loaded.diagnostics)
  }
  return { settings, diagnostics }
}
