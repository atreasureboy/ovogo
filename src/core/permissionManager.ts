import type { ToolRuntimeMetadata } from './types.js'
import { classifyBashCommand, extractBashReadTargets, extractBashWriteTargets } from './bashPolicy.js'
import { isAbsolute, relative, resolve } from 'path'

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
}

/**
 * Centralized permission preflight for tool calls.
 *
 * This is intentionally small: it creates one runtime gate that can later grow
 * into interactive approval, persistent allow/deny rules, and workspace ACLs.
 */
export class PermissionManager {
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
        reason: bashPolicy?.reason
          ? `Permission mode "ask" requires approval for this Bash command (${bashPolicy.reason}), but interactive approval is not implemented yet.`
          : `Permission mode "ask" requires approval for ${request.toolName}, but interactive approval is not implemented yet.`,
      }
    }

    return { allowed: true }
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
