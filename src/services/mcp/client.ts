/**
 * MCP Client — connects to a single MCP server via stdio transport
 *
 * Reference: src/services/mcp/client.ts (StdioClientTransport usage)
 *
 * Protocol: JSON-RPC 2.0 over stdin/stdout of a child process.
 * The child process is the MCP server (e.g. a filesystem server, git server, etc.)
 */

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'
import type { McpServerConfig, McpServerTool } from './types.js'

const CONNECTION_TIMEOUT_MS = 15_000

export interface ConnectedMcpClient {
  name: string
  client: Client
  tools: McpServerTool[]
  disconnect: () => Promise<void>
}

/**
 * Connect to a single MCP server and retrieve its tool list.
 */
export async function connectMcpServer(
  config: McpServerConfig,
): Promise<ConnectedMcpClient> {
  const transport = new StdioClientTransport({
    command: config.command,
    args: config.args ?? [],
    env: {
      ...process.env,
      ...(config.env ?? {}),
    } as Record<string, string>,
  })

  const client = new Client(
    { name: 'ovogogogo', version: '0.2.0' },
    { capabilities: {} },
  )

  // Connect with timeout
  await Promise.race([
    client.connect(transport),
    new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error(`MCP server "${config.name}" connection timed out`)), CONNECTION_TIMEOUT_MS),
    ),
  ])

  // Retrieve available tools
  const toolsResult = await client.listTools()

  const tools: McpServerTool[] = (toolsResult.tools ?? []).map((t) => ({
    serverName: config.name,
    toolName: t.name,
    description: t.description ?? `Tool from MCP server: ${config.name}`,
    inputSchema: (t.inputSchema as Record<string, unknown>) ?? { type: 'object', properties: {} },
  }))

  return {
    name: config.name,
    client,
    tools,
    disconnect: () => client.close(),
  }
}

/**
 * Call a tool on a connected MCP server and return the text result.
 */
export async function callMcpTool(
  client: Client,
  toolName: string,
  args: Record<string, unknown>,
): Promise<{ content: string; isError: boolean }> {
  try {
    const result = await client.callTool({ name: toolName, arguments: args })

    // Extract text content from response
    const content = result.content ?? []
    const textParts: string[] = []

    for (const block of content as Array<{ type: string; text?: string; data?: string; mimeType?: string }>) {
      if (block.type === 'text' && block.text) {
        textParts.push(block.text)
      } else if (block.type === 'image') {
        textParts.push(`[image: ${block.mimeType ?? 'unknown'}, base64 data omitted]`)
      } else if (block.type === 'resource') {
        textParts.push(`[resource: ${JSON.stringify(block)}]`)
      }
    }

    const isError = Boolean(result.isError)
    return {
      content: textParts.join('\n') || '(no content returned)',
      isError,
    }
  } catch (err: unknown) {
    return {
      content: `MCP tool call failed: ${(err as Error).message}`,
      isError: true,
    }
  }
}
