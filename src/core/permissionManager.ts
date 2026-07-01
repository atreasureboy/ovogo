import type { ToolRuntimeMetadata } from './types.js'
import { classifyBashCommand, extractBashReadTargets, extractBashWriteTargets } from './bashPolicy.js'
import { isAbsolute, relative, resolve } from 'path'
import { createInterface } from 'node:readline/promises'
import { stdin as defaultStdin, stdout as defaultStdout } from 'node:process'

export type PermissionMode = 'auto' | 'ask' | 'deny'

export interface ToolPermissionRequest {
  toolName: string
  input: Record<string, unknown>
  mode: PermissionMode
  runtime?: ToolRuntimeMetadata
  cwd: string
  sessionDir?: string
  readableRoots?: string[]
  writableRoots?: string[]
}

export interface ToolPermissionDecision {
  allowed: boolean
  reason?: string
  /** When true, the caller may prompt the user for approval and re-check. */
  requiresApproval?: boolean
}

/**
 * Async function that prompts the user to approve a tool call. Return `true`
 * to allow, `false` to deny. Throw to surface a system error.
 */
export type ApprovalPrompt = (request: ToolPermissionRequest) => Promise<boolean>

export interface ReadlinePromptOptions {
  stdin?: NodeJS.ReadableStream
  stdout?: NodeJS.WritableStream
}

/**
 * Default approval prompt using node:readline/promises. Falls back to deny
 * (returns `false`) when stdin is not a TTY — i.e. in CI or piped input.
 */
export function readlineApprovalPrompt(options: ReadlinePromptOptions = {}): ApprovalPrompt {
  const stdin = options.stdin ?? defaultStdin
  const stdout = options.stdout ?? defaultStdout
  return async (request) => {
    const isTTY = (stdin as { isTTY?: boolean }).isTTY === true
    if (!isTTY) return false
    const rl = createInterface({
      input: stdin as NodeJS.ReadableStream,
      output: stdout as NodeJS.WritableStream,
      terminal: true,
    })
    try {
      const summary = formatApprovalSummary(request)
      const answer = await rl.question(`Allow ${summary}? [y/N] `)
      return /^y(es)?$/i.test(answer.trim())
    } finally {
      rl.close()
    }
  }
}

function formatApprovalSummary(request: ToolPermissionRequest): string {
  if (request.toolName === 'Bash') {
    const cmd = String(request.input.command ?? '').slice(0, 80)
    return `Bash(${cmd})`
  }
  const inputSummary = JSON.stringify(request.input).slice(0, 80)
  return `${request.toolName}(${inputSummary})`
}

/**
 * Centralized permission preflight for tool calls.
 *
 * `checkTool` is synchronous and returns one of three states:
 *   - `{ allowed: true }` — proceed
 *   - `{ allowed: false, reason }` — deny with reason
 *   - `{ allowed: false, requiresApproval: true, reason }` — needs user prompt
 *
 * For `ask` mode, use `checkToolAsync` which awaits the configured approval
 * prompt before producing a final decision.
 */
export class PermissionManager {
  private approvalPrompt: ApprovalPrompt

  constructor(approvalPrompt: ApprovalPrompt = readlineApprovalPrompt()) {
    this.approvalPrompt = approvalPrompt
  }

  setApprovalPrompt(prompt: ApprovalPrompt): void {
    this.approvalPrompt = prompt
  }

  checkTool(request: ToolPermissionRequest): ToolPermissionDecision {
    const fileDecision = this.checkFilePathScope(request)
    if (!fileDecision.allowed) return fileDecision

    const bashPolicy = request.toolName === 'Bash'
      ? classifyBashInput(request.input)
      : null
    const readOnly = request.runtime?.readOnly === true || bashPolicy?.readOnly === true

    if (request.mode === 'auto' && bashPolicy?.capabilities.includes('dynamic_code')) {
      return {
        allowed: false,
        reason: `Bash command cannot be safely checked against workspace roots: ${bashPolicy.reason}.`,
      }
    }

    if (request.mode === 'deny' && !readOnly) {
      return {
        allowed: false,
        reason: bashPolicy?.reason
          ? `Permission mode "deny" allows only read-only Bash commands; ${bashPolicy.reason}.`
          : `Permission mode "deny" allows only read-only tools; ${request.toolName} is not marked read-only.`,
      }
    }

    if (request.mode === 'ask' && !readOnly) {
      return {
        allowed: false,
        requiresApproval: true,
        reason: bashPolicy?.reason
          ? `Permission mode "ask" requires approval for this Bash command (${bashPolicy.reason}).`
          : `Permission mode "ask" requires approval for ${request.toolName}.`,
      }
    }

    return { allowed: true }
  }

  async checkToolAsync(request: ToolPermissionRequest): Promise<ToolPermissionDecision> {
    const base = this.checkTool(request)
    if (base.allowed || !base.requiresApproval) return base

    const approved = await this.approvalPrompt(request)
    return approved
      ? { allowed: true }
      : { allowed: false, reason: 'User denied approval' }
  }

  private checkFilePathScope(request: ToolPermissionRequest): ToolPermissionDecision {
    if (request.toolName === 'Bash') {
      const command = request.input.command
      if (typeof command !== 'string') return { allowed: true }

      const readDecision = checkPathsWithinRoots(
        request.toolName,
        extractBashReadTargets(command),
        [request.cwd, request.sessionDir, ...(request.readableRoots ?? [])],
        request.cwd,
      )
      if (!readDecision.allowed) return readDecision

      return checkPathsWithinRoots(
        request.toolName,
        extractBashWriteTargets(command),
        [request.cwd, request.sessionDir, ...(request.writableRoots ?? [])],
        request.cwd,
      )
    }

    const filePaths = this.getFilePathsFromInput(request)
    if (filePaths.length === 0) return { allowed: true }

    const rootInputs = this.isWriteLikeTool(request.toolName)
      ? [request.cwd, request.sessionDir, ...(request.writableRoots ?? [])]
      : [request.cwd, request.sessionDir, ...(request.readableRoots ?? [])]

    return checkPathsWithinRoots(request.toolName, filePaths, rootInputs, request.cwd)
  }

  private getFilePathsFromInput(request: ToolPermissionRequest): string[] {
    if (['Read', 'DocRead', 'Write', 'Edit'].includes(request.toolName)) {
      const filePath = request.input.file_path
      return typeof filePath === 'string' && filePath.trim() ? [filePath] : []
    }

    if (request.toolName === 'MultiScan' && Array.isArray(request.input.tasks)) {
      return request.input.tasks
        .map((task) => {
          if (!task || typeof task !== 'object') return null
          const outputFile = (task as { output_file?: unknown }).output_file
          return typeof outputFile === 'string' && outputFile.trim() ? outputFile : null
        })
        .filter((path): path is string => path !== null)
    }

    return []
  }

  private isWriteLikeTool(toolName: string): boolean {
    return ['Write', 'Edit', 'MultiScan'].includes(toolName)
  }
}

function classifyBashInput(input: Record<string, unknown>) {
  const command = input.command
  return classifyBashCommand(typeof command === 'string' ? command : '')
}

function checkPathsWithinRoots(
  toolName: string,
  filePaths: string[],
  rootInputs: Array<string | undefined>,
  cwd: string,
): ToolPermissionDecision {
  if (filePaths.length === 0) return { allowed: true }

  const roots = rootInputs
    .filter((root): root is string => typeof root === 'string' && root.length > 0)
    .map((root) => resolve(root))

  for (const filePath of filePaths) {
    const targetPath = isAbsolute(filePath)
      ? resolve(filePath)
      : resolve(cwd, filePath)
    const allowed = roots.some((root) => isWithinPath(targetPath, root))
    if (!allowed) {
      return {
        allowed: false,
        reason: `${toolName} target is outside workspace roots: ${targetPath}`,
      }
    }
  }

  return { allowed: true }
}

function isWithinPath(targetPath: string, rootPath: string): boolean {
  const rel = relative(rootPath, targetPath)
  return rel === '' || (!!rel && !rel.startsWith('..') && !isAbsolute(rel))
}
