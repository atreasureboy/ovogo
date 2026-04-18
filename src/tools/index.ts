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
import { AgentTool, DispatchAgentTool, CheckDispatchTool, GetDispatchResultTool } from './agent.js'
import { FindingWriteTool, FindingListTool } from './finding.js'
import { WeaponRadarTool } from './weaponRadar.js'
import { MultiScanTool } from './multiScan.js'
import { MultiAgentTool } from './multiAgent.js'
import { ShellSessionTool } from './shellSession.js'
import { TmuxSessionTool } from './tmuxSession.js'
import { C2Tool } from './c2.js'
import { DocReadTool } from './docRead.js'
import { KnowledgeQueryTool } from './knowledgeQuery.js'
import { BypassDetectorTool } from './bypassDetector.js'
import { PayloadFactoryTool } from './payloadFactory.js'
import { EnvAnalyzerTool } from './envAnalyzer.js'
import { TechniqueGeneratorTool } from './techniqueGenerator.js'
import type { KnowledgeBase } from '../core/knowledgeBase.js'

export function createTools(extraTools: Tool[] = [], knowledgeBase?: KnowledgeBase): Tool[] {
  const tools: Tool[] = [
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
    new DispatchAgentTool(),
    new CheckDispatchTool(),
    new GetDispatchResultTool(),
    new ShellSessionTool(),
    new TmuxSessionTool(),
    new FindingWriteTool(),
    new FindingListTool(),
    new WeaponRadarTool(),
    new MultiScanTool(),
    new C2Tool(),
    new DocReadTool(),
    // Legacy names (backward compat)
    new BypassDetectorTool(),
    new PayloadFactoryTool(),
    // New neutral-named tools (preferred)
    new EnvAnalyzerTool(),
    new TechniqueGeneratorTool(),
    ...extraTools,
  ]

  if (knowledgeBase) {
    tools.push(new KnowledgeQueryTool(knowledgeBase))
  }

  return tools
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
  BypassDetectorTool,
  PayloadFactoryTool,
  EnvAnalyzerTool,
  TechniqueGeneratorTool,
}
