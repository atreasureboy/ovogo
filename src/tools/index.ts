/**
 * Tool registry — all available tools for ovogogogo
 */

import type { Tool } from '../core/types.js'
import { BashTool } from './bash.js'
import { FileReadTool } from './fileRead.js'
import { FileWriteTool } from './fileWrite.js'
import { FileEditTool } from './fileEdit.js'
import { GlobTool } from './glob.js'
import { GrepTool } from './grep.js'
import { TodoWriteTool } from './todo.js'
import { WebFetchTool } from './webFetch.js'
import { WebSearchTool } from './webSearch.js'
import { AgentTool } from './agent.js'
import { FindingWriteTool, FindingListTool } from './finding.js'
import { WeaponRadarTool } from './weaponRadar.js'
import { MultiScanTool } from './multiScan.js'
import { MultiAgentTool } from './multiAgent.js'
import { ShellSessionTool } from './shellSession.js'
import { TmuxSessionTool } from './tmuxSession.js'
import { C2Tool } from './c2.js'
import { DocReadTool } from './docRead.js'

export function createTools(extraTools: Tool[] = []): Tool[] {
  return [
    new BashTool(),
    new FileReadTool(),
    new FileWriteTool(),
    new FileEditTool(),
    new GlobTool(),
    new GrepTool(),
    new TodoWriteTool(),
    new WebFetchTool(),
    new WebSearchTool(),
    new AgentTool(),
    new MultiAgentTool(),
    new ShellSessionTool(),
    new TmuxSessionTool(),
    new FindingWriteTool(),
    new FindingListTool(),
    new WeaponRadarTool(),
    new MultiScanTool(),
    new C2Tool(),
    new DocReadTool(),
    ...extraTools,
  ]
}

export function getToolDefinitions(tools: Tool[]) {
  return tools.map((t) => t.definition)
}

export function findTool(tools: Tool[], name: string): Tool | undefined {
  return tools.find((t) => t.name === name)
}

export {
  DocReadTool,
  BashTool,
  FileReadTool,
  FileWriteTool,
  FileEditTool,
  GlobTool,
  GrepTool,
  TodoWriteTool,
  WebFetchTool,
  WebSearchTool,
  FindingWriteTool,
  FindingListTool,
  WeaponRadarTool,
  MultiScanTool,
  MultiAgentTool,
  ShellSessionTool,
  TmuxSessionTool,
  C2Tool,
}
