/**
 * Tool registry — all available tools for ovogogogo
 */

import type { Tool, ToolRuntimeMetadata } from '../core/types.js'
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
import { EnvAnalyzerTool } from './envAnalyzer.js'
import { TechniqueGeneratorTool } from './techniqueGenerator.js'
import { PayloadGeneratorTool } from './payloadGenerator.js'
import type { KnowledgeBase } from '../core/knowledgeBase.js'

const READ_ONLY_TOOLS = new Set([
  'Read', 'Glob', 'Grep', 'WebFetch', 'WebSearch', 'FindingList',
  'WeaponRadar', 'DocRead', 'EnvAnalyzer', 'TechniqueGenerator', 'PayloadGenerator',
  'KnowledgeQuery', 'CheckDispatch', 'GetDispatchResult',
])

const CONCURRENCY_SAFE_TOOLS = new Set([
  'Read', 'Glob', 'Grep', 'WebFetch', 'WebSearch',
  'WeaponRadar', 'FindingList', 'MultiScan',
  'Bash', 'Agent', 'MultiAgent',
  'DispatchAgent', 'CheckDispatch', 'GetDispatchResult',
  'C2', 'ShellSession', 'TmuxSession',
  'EnvAnalyzer', 'TechniqueGenerator', 'PayloadGenerator', 'DocRead', 'KnowledgeQuery',
])

const CACHEABLE_TOOLS = new Set([
  'WebFetch', 'WebSearch', 'WeaponRadar', 'DocRead', 'EnvAnalyzer', 'TechniqueGenerator', 'PayloadGenerator', 'KnowledgeQuery',
])

const LONG_RUNNING_TOOLS = new Set([
  'Bash', 'MultiScan', 'WeaponRadar', 'WebSearch', 'C2',
])

function defaultRuntimeForTool(name: string): ToolRuntimeMetadata {
  return {
    readOnly: READ_ONLY_TOOLS.has(name),
    concurrencySafe: CONCURRENCY_SAFE_TOOLS.has(name),
    cacheable: CACHEABLE_TOOLS.has(name),
    cacheTtlMs: ['WebFetch', 'WebSearch'].includes(name) ? 60 * 60 * 1000 : undefined,
    longRunning: LONG_RUNNING_TOOLS.has(name),
  }
}

function withDefaultRuntime(tool: Tool): Tool {
  tool.runtime = {
    ...defaultRuntimeForTool(tool.name),
    ...(tool.runtime ?? {}),
  }
  return tool
}

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
    new EnvAnalyzerTool(),
    new TechniqueGeneratorTool(),
    new PayloadGeneratorTool(),
    ...extraTools,
  ]

  if (knowledgeBase) {
    tools.push(new KnowledgeQueryTool(knowledgeBase))
  }

  return tools.map(withDefaultRuntime)
}

export function getToolDefinitions(tools: Tool[]) {
  return tools.map((t) => t.definition)
}

export function findTool(tools: Tool[], name: string): Tool | undefined {
  return tools.find((t) => t.name === name)
}

export function getToolRuntime(tools: Tool[], name: string): ToolRuntimeMetadata {
  return findTool(tools, name)?.runtime ?? defaultRuntimeForTool(name)
}

export function isPlanModeTool(tools: Tool[], name: string): boolean {
  return getToolRuntime(tools, name).readOnly === true
}

export function isConcurrencySafeTool(tools: Tool[], name: string): boolean {
  return getToolRuntime(tools, name).concurrencySafe === true
}

export function isCacheableTool(tools: Tool[], name: string): boolean {
  return getToolRuntime(tools, name).cacheable === true
}

export function isLongRunningTool(tools: Tool[], name: string): boolean {
  return getToolRuntime(tools, name).longRunning === true
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
  EnvAnalyzerTool,
  TechniqueGeneratorTool,
  PayloadGeneratorTool,
}
