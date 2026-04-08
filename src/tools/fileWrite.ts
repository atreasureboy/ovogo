/**
 * FileWriteTool — write/create files
 * Reference: src/tools/FileWriteTool/
 */

import { writeFile, mkdir } from 'fs/promises'
import { dirname } from 'path'
import type { Tool, ToolContext, ToolDefinition, ToolResult } from '../core/types.js'
import { WRITE_FILE_DESCRIPTION } from '../prompts/tools.js'

export interface WriteFileInput {
  file_path: string
  content: string
}

export class FileWriteTool implements Tool {
  name = 'Write'

  definition: ToolDefinition = {
    type: 'function',
    function: {
      name: 'Write',
      description: WRITE_FILE_DESCRIPTION,
      parameters: {
        type: 'object',
        properties: {
          file_path: {
            type: 'string',
            description: 'Absolute path to write to',
          },
          content: {
            type: 'string',
            description: 'Content to write',
          },
        },
        required: ['file_path', 'content'],
      },
    },
  }

  async execute(input: Record<string, unknown>, _context: ToolContext): Promise<ToolResult> {
    const { file_path, content } = input as unknown as WriteFileInput

    if (!file_path || typeof file_path !== 'string') {
      return { content: 'Error: file_path is required', isError: true }
    }
    if (typeof content !== 'string') {
      return { content: 'Error: content must be a string', isError: true }
    }

    try {
      // Ensure parent directory exists
      await mkdir(dirname(file_path), { recursive: true })
      await writeFile(file_path, content, 'utf8')

      const lines = content.split('\n').length
      return {
        content: `File written: ${file_path} (${lines} lines, ${content.length} bytes)`,
        isError: false,
      }
    } catch (err: unknown) {
      const error = err as NodeJS.ErrnoException
      return { content: `Error writing file: ${error.message}`, isError: true }
    }
  }
}
