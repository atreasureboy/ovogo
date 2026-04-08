/**
 * McpTool — wraps a single MCP server tool as a Tool interface
 *
 * Each tool exposed by an MCP server becomes an instance of McpTool.
 * The tool name is prefixed with the server name to avoid collisions:
 *   e.g. "filesystem__read_file", "git__log"
 */

import type { Client } from '@modelcontextprotocol/sdk/client/index.js'
import type { Tool, ToolContext, ToolDefinition, ToolResult } from '../../core/types.js'
import { callMcpTool } from './client.js'
import type { McpServerTool } from './types.js'

/**
 * Sanitize a tool name for use as an OpenAI function name.
 * OpenAI requires: ^[a-zA-Z0-9_-]{1,64}$
 */
export function mcpToolId(serverName: string, toolName: string): string {
  const raw = `${serverName}__${toolName}`
  return raw.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 64)
}

export class McpTool implements Tool {
  name: string
  definition: ToolDefinition
  private client: Client
  private rawToolName: string

  constructor(meta: McpServerTool, client: Client) {
    this.rawToolName = meta.toolName
    this.client = client
    this.name = mcpToolId(meta.serverName, meta.toolName)

    // Build description with server attribution
    const description =
      `[MCP: ${meta.serverName}] ${meta.description}`.slice(0, 1024)

    this.definition = {
      type: 'function',
      function: {
        name: this.name,
        description,
        parameters: {
          type: 'object',
          properties: (meta.inputSchema as { properties?: Record<string, unknown> }).properties ?? {},
          required: (meta.inputSchema as { required?: string[] }).required,
        },
      },
    }
  }

  async execute(input: Record<string, unknown>, _context: ToolContext): Promise<ToolResult> {
    return callMcpTool(this.client, this.rawToolName, input)
  }
}
