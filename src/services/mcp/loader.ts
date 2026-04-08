/**
 * MCP Loader — read config, connect servers, return Tool instances
 *
 * Config file locations (first found wins):
 *   1. OVOGO_MCP_CONFIG env var (path to JSON file)
 *   2. ~/.ovogo/mcp.json
 *   3. {cwd}/.ovogo/mcp.json
 *
 * Config format:
 * {
 *   "servers": [
 *     {
 *       "name": "filesystem",
 *       "command": "npx",
 *       "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"],
 *       "env": {}
 *     },
 *     {
 *       "name": "git",
 *       "command": "uvx",
 *       "args": ["mcp-server-git", "--repository", "/repo"]
 *     }
 *   ]
 * }
 */

import { readFileSync, existsSync } from 'fs'
import { homedir } from 'os'
import { resolve, join } from 'path'
import type { Tool } from '../../core/types.js'
import { connectMcpServer, type ConnectedMcpClient } from './client.js'
import { McpTool } from './mcpTool.js'
import type { McpConfig } from './types.js'

function findConfigFile(cwd: string): string | null {
  const candidates = [
    process.env.OVOGO_MCP_CONFIG,
    join(homedir(), '.ovogo', 'mcp.json'),
    join(cwd, '.ovogo', 'mcp.json'),
  ].filter(Boolean) as string[]

  for (const path of candidates) {
    if (existsSync(path)) return path
  }
  return null
}

function loadConfig(cwd: string): McpConfig | null {
  const configPath = findConfigFile(cwd)
  if (!configPath) return null

  try {
    const raw = readFileSync(configPath, 'utf8')
    const parsed = JSON.parse(raw) as McpConfig
    if (!Array.isArray(parsed.servers)) {
      throw new Error('config.servers must be an array')
    }
    return parsed
  } catch (err) {
    process.stderr.write(`[mcp] Failed to parse config: ${(err as Error).message}\n`)
    return null
  }
}

export interface McpLoadResult {
  tools: Tool[]
  connections: ConnectedMcpClient[]
  errors: Array<{ server: string; error: string }>
}

/**
 * Load MCP servers from config and return Tool instances.
 * Servers that fail to connect are skipped (non-fatal).
 */
export async function loadMcpTools(cwd: string): Promise<McpLoadResult> {
  const config = loadConfig(cwd)
  if (!config || config.servers.length === 0) {
    return { tools: [], connections: [], errors: [] }
  }

  const tools: Tool[] = []
  const connections: ConnectedMcpClient[] = []
  const errors: Array<{ server: string; error: string }> = []

  // Connect all servers concurrently
  await Promise.all(
    config.servers.map(async (serverConfig) => {
      try {
        process.stderr.write(`[mcp] Connecting to "${serverConfig.name}"...\n`)
        const conn = await connectMcpServer(serverConfig)
        connections.push(conn)

        // Wrap each server tool as a Tool instance
        for (const meta of conn.tools) {
          tools.push(new McpTool(meta, conn.client))
        }

        process.stderr.write(
          `[mcp] "${serverConfig.name}" connected — ${conn.tools.length} tool(s): ${conn.tools.map(t => t.toolName).join(', ')}\n`,
        )
      } catch (err) {
        const msg = (err as Error).message
        errors.push({ server: serverConfig.name, error: msg })
        process.stderr.write(`[mcp] Failed to connect "${serverConfig.name}": ${msg}\n`)
      }
    }),
  )

  return { tools, connections, errors }
}

/**
 * Gracefully disconnect all MCP connections.
 */
export async function disconnectAll(connections: ConnectedMcpClient[]): Promise<void> {
  await Promise.all(connections.map((c) => c.disconnect().catch(() => {})))
}
