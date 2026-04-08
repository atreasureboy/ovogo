/**
 * BashTool — shell command execution with proper abort support
 *
 * Reference: Claude Code src/tools/BashTool/BashTool.tsx, src/utils/Shell.js
 *
 * Key change vs the previous promisified exec() approach:
 * We use exec() in callback form so we hold a reference to the ChildProcess.
 * When context.signal fires (Ctrl+C), we kill the entire process group
 * (SIGTERM → SIGKILL after 5 s) — matching Claude Code's abort behaviour.
 */

import { exec } from 'child_process'
import type { Tool, ToolContext, ToolDefinition, ToolResult } from '../core/types.js'
import { BASH_DESCRIPTION } from '../prompts/tools.js'

const MAX_OUTPUT_LENGTH = 30_000
const DEFAULT_TIMEOUT_MS = 120_000

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
    const { command, timeout, run_in_background } = input as unknown as BashInput

    if (!command || typeof command !== 'string') {
      return { content: 'Error: command is required and must be a string', isError: true }
    }

    const timeoutMs = Math.min(
      typeof timeout === 'number' ? timeout : DEFAULT_TIMEOUT_MS,
      600_000,
    )

    // ── Background mode (fire-and-forget) ───────────────────────
    if (run_in_background) {
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

    // ── Foreground mode with abort support ──────────────────────
    // Use exec() callback form so we can kill the child on abort.
    // Reference: Claude Code Shell.js kill-by-process-group approach.
    return new Promise<ToolResult>((resolve) => {
      let settled = false

      const child = exec(
        command,
        {
          cwd: context.cwd,
          timeout: timeoutMs,
          maxBuffer: 50 * 1024 * 1024,
          env: { ...process.env, TERM: 'dumb' },
          shell: '/bin/bash',
        },
        (err, stdout, stderr) => {
          // Remove the abort listener to prevent it firing after process ends
          if (context.signal) {
            context.signal.removeEventListener('abort', onAbort)
          }

          if (settled) return
          settled = true

          // Check if we were cancelled
          if (context.signal?.aborted) {
            resolve({ content: 'Command cancelled.', isError: true })
            return
          }

          if (!err) {
            const combined = [stdout, stderr].filter(Boolean).join('\n').trimEnd()
            resolve({ content: truncateOutput(combined, MAX_OUTPUT_LENGTH) || '(no output)', isError: false })
            return
          }

          const nodeErr = err as NodeJS.ErrnoException & {
            killed?: boolean
            signal?: string
            stdout?: string
            stderr?: string
            code?: number
          }

          if (nodeErr.killed || nodeErr.signal === 'SIGTERM') {
            resolve({ content: `Command timed out after ${timeoutMs / 1000}s`, isError: true })
            return
          }

          // Non-zero exit — provide stdout+stderr so the LLM can diagnose
          const out = [nodeErr.stdout ?? stdout, nodeErr.stderr ?? stderr].filter(Boolean).join('\n').trimEnd()
          const exitCode = nodeErr.code ?? 1
          resolve({
            content: truncateOutput(`Exit code: ${exitCode}\n${out}`, MAX_OUTPUT_LENGTH).trimEnd(),
            isError: false,  // non-zero exit is not necessarily fatal
          })
        },
      )

      // ── Abort handler — kill entire process group ────────────
      // Reference: Claude Code Shell.js process.kill(-pid, 'SIGTERM')
      const onAbort = () => {
        if (settled) return
        settled = true

        const pid = child.pid
        if (pid !== undefined) {
          // Kill the process group (includes any subshells spawned by the command)
          try { process.kill(-pid, 'SIGTERM') } catch {
            try { child.kill('SIGTERM') } catch { /* ignore */ }
          }
          // SIGKILL fallback after 5 s for stubborn processes
          setTimeout(() => {
            try { process.kill(-pid, 'SIGKILL') } catch {
              try { child.kill('SIGKILL') } catch { /* ignore */ }
            }
          }, 5_000)
        }

        resolve({ content: 'Command cancelled.', isError: true })
      }

      if (context.signal) {
        if (context.signal.aborted) {
          onAbort()
        } else {
          context.signal.addEventListener('abort', onAbort, { once: true })
        }
      }
    })
  }
}
