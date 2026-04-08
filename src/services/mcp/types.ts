/**
 * MCP service types
 */

export interface McpServerConfig {
  /** Display name for the server */
  name: string
  /** Command to launch (e.g. "npx", "python") */
  command: string
  /** Args to command (e.g. ["-y", "@modelcontextprotocol/server-filesystem", "/"]) */
  args?: string[]
  /** Additional env vars for the server process */
  env?: Record<string, string>
}

export interface McpConfig {
  servers: McpServerConfig[]
}

export interface McpConnection {
  name: string
  client: import('@modelcontextprotocol/sdk/client/index.js').Client
  tools: McpServerTool[]
}

export interface McpServerTool {
  serverName: string
  toolName: string
  description: string
  inputSchema: Record<string, unknown>
}
