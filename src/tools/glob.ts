/**
 * GlobTool — find files by pattern
 * Reference: src/tools/GlobTool/
 */

import { glob } from 'glob'
import { stat } from 'fs/promises'
import type { Tool, ToolContext, ToolDefinition, ToolResult } from '../core/types.js'
import { GLOB_DESCRIPTION } from '../prompts/tools.js'

export interface GlobInput {
  pattern: string
  path?: string
}

export class GlobTool implements Tool {
  name = 'Glob'

  definition: ToolDefinition = {
    type: 'function',
    function: {
      name: 'Glob',
      description: GLOB_DESCRIPTION,
      parameters: {
        type: 'object',
        properties: {
          pattern: {
            type: 'string',
            description: 'Glob pattern (e.g. "**/*.ts", "src/**/*.{js,ts}")',
          },
          path: {
            type: 'string',
            description: 'Directory to search in (defaults to cwd)',
          },
        },
        required: ['pattern'],
      },
    },
  }

  async execute(input: Record<string, unknown>, context: ToolContext): Promise<ToolResult> {
    const { pattern, path: searchPath } = input as unknown as GlobInput

    if (!pattern || typeof pattern !== 'string') {
      return { content: 'Error: pattern is required', isError: true }
    }

    const cwd = searchPath ?? context.cwd

    try {
      const files = await glob(pattern, {
        cwd,
        absolute: true,
        nodir: true,
        dot: false,
        ignore: ['**/node_modules/**', '**/.git/**', '**/dist/**'],
      })

      if (files.length === 0) {
        return { content: `No files found matching: ${pattern} in ${cwd}`, isError: false }
      }

      // Sort by modification time (newest first) — mirrors Claude Code behavior
      const withMtime = await Promise.all(
        files.map(async (f) => {
          try {
            const s = await stat(f)
            return { path: f, mtime: s.mtimeMs }
          } catch {
            return { path: f, mtime: 0 }
          }
        }),
      )

      withMtime.sort((a, b) => b.mtime - a.mtime)

      const sorted = withMtime.map((f) => f.path)
      return {
        content: sorted.join('\n'),
        isError: false,
      }
    } catch (err: unknown) {
      const error = err as Error
      return { content: `Glob error: ${error.message}`, isError: true }
    }
  }
}
