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
}

function tryParse(path: string): OvogoSettings {
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as OvogoSettings
  } catch {
    return {}
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
  }
}

export function loadSettings(cwd: string): OvogoSettings {
  const globalPath = join(homedir(), '.ovogo', 'settings.json')
  const projectPath = resolve(cwd, '.ovogo', 'settings.json')

  let settings: OvogoSettings = {}
  if (existsSync(globalPath)) settings = mergeSettings(settings, tryParse(globalPath))
  if (existsSync(projectPath)) settings = mergeSettings(settings, tryParse(projectPath))
  return settings
}
