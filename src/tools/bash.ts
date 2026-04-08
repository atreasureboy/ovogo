/**
 * BashTool — shell command execution
 *
 * Distilled from Claude Code source:
 * src/tools/BashTool/BashTool.tsx
 * src/utils/Shell.js
 *
 * Core capability: execute shell commands with timeout, capture stdout+stderr,
 * handle background execution.
 */

import { exec as execCb } from 'child_process'
import { promisify } from 'util'
import type { Tool, ToolContext, ToolDefinition, ToolResult } from '../core/types.js'
import { BASH_DESCRIPTION } from '../prompts/tools.js'

const execAsync = promisify(execCb)

const MAX_OUTPUT_LENGTH = 30_000 // characters — truncate very long outputs
const DEFAULT_TIMEOUT_MS = 120_000 // 2 minutes

export interface BashInput {
  command: string
  timeout?: number
  run_in_background?: boolean
  description?: string
}

function truncateOutput(output: string, maxLen: number): string {
  if (output.length <= maxLen) return output
  const half = Math.floor(maxLen / 2)
  const head = output.slice(0, half)
  const tail = output.slice(output.length - half)
  return `${head}\n\n[... ${output.length - maxLen} characters truncated ...]\n\n${tail}`
}

export class BashTool implements Tool {
  name = 'Bash'

  definition: ToolDefinition = {
    type: 'function',
    function: {
      name: 'Bash',
      description: BASH_DESCRIPTION,
      parameters: {
        type: 'object',
        properties: {
          command: {
            type: 'string',
            description: 'The bash command to execute',
          },
          timeout: {
            type: 'number',
            description: 'Timeout in milliseconds (default: 120000, max: 600000)',
          },
          run_in_background: {
            type: 'boolean',
            description: 'Run command in background and return immediately',
          },
          description: {
            type: 'string',
            description: 'Brief description of what this command does (shown to user)',
          },
        },
        required: ['command'],
      },
    },
  }

  async execute(input: Record<string, unknown>, context: ToolContext): Promise<ToolResult> {
    const { command, timeout, run_in_background, description } = input as unknown as BashInput

    if (!command || typeof command !== 'string') {
      return { content: 'Error: command is required and must be a string', isError: true }
    }

    const timeoutMs = Math.min(
      typeof timeout === 'number' ? timeout : DEFAULT_TIMEOUT_MS,
      600_000,
    )

    if (run_in_background) {
      // Spawn detached, don't wait
      const { spawn } = await import('child_process')
      const child = spawn('bash', ['-c', command], {
        detached: true,
        stdio: 'ignore',
        cwd: context.cwd,
        env: process.env,
      })
      child.unref()
      return {
        content: `Command started in background (PID: ${child.pid})`,
        isError: false,
      }
    }

    try {
      const { stdout, stderr } = await execAsync(command, {
        cwd: context.cwd,
        timeout: timeoutMs,
        maxBuffer: 50 * 1024 * 1024, // 50MB
        env: { ...process.env, TERM: 'dumb' },
        shell: '/bin/bash',
      })

      const combined = [stdout, stderr].filter(Boolean).join('\n').trimEnd()
      const output = truncateOutput(combined, MAX_OUTPUT_LENGTH)
      return { content: output || '(no output)', isError: false }
    } catch (err: unknown) {
      const error = err as NodeJS.ErrnoException & {
        stdout?: string
        stderr?: string
        code?: number
        killed?: boolean
        signal?: string
      }

      if (error.killed || error.signal === 'SIGTERM') {
        const msg = `Command timed out after ${timeoutMs / 1000}s: ${command}`
        return { content: msg, isError: true }
      }

      // Non-zero exit code — capture stdout+stderr for debugging
      const stdout = error.stdout ?? ''
      const stderr = error.stderr ?? ''
      const combined = [stdout, stderr].filter(Boolean).join('\n').trimEnd()
      const output = truncateOutput(combined, MAX_OUTPUT_LENGTH)
      const exitCode = error.code ?? 1

      const result = `Exit code: ${exitCode}\n${output}`.trimEnd()
      // Non-zero exit is NOT necessarily a fatal error — return as content
      // so the LLM can decide whether to retry/fix
      return { content: result, isError: false }
    }
  }
}
