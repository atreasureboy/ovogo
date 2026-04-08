// Core types for ovogogogo execution engine

export interface Message {
  role: 'system' | 'user' | 'assistant' | 'tool'
  content: string | ContentBlock[]
  tool_call_id?: string
  name?: string
}

export type ContentBlock =
  | TextBlock
  | ToolUseBlock
  | ToolResultBlock

export interface TextBlock {
  type: 'text'
  text: string
}

export interface ToolUseBlock {
  type: 'tool_use'
  id: string
  name: string
  input: Record<string, unknown>
}

export interface ToolResultBlock {
  type: 'tool_result'
  tool_use_id: string
  content: string
  is_error?: boolean
}

// OpenAI-compatible tool call format
export interface ToolCall {
  id: string
  type: 'function'
  function: {
    name: string
    arguments: string
  }
}

export interface OpenAIMessage {
  role: 'system' | 'user' | 'assistant' | 'tool'
  content: string | null
  tool_calls?: ToolCall[]
  tool_call_id?: string
  name?: string
}

export interface ToolDefinition {
  type: 'function'
  function: {
    name: string
    description: string
    parameters: {
      type: 'object'
      properties: Record<string, unknown>
      required?: string[]
    }
  }
}

export interface ToolResult {
  content: string
  isError: boolean
}

export interface Tool {
  name: string
  definition: ToolDefinition
  execute(input: Record<string, unknown>, context: ToolContext): Promise<ToolResult>
}

export interface ToolContext {
  cwd: string
  permissionMode: 'auto' | 'ask' | 'deny'
  /** AbortSignal — tools should honour this to support Ctrl+C cancellation */
  signal?: AbortSignal
}

/**
 * Interface for hook runners — decouples engine from config layer.
 * Hooks are best-effort: implementations must never throw.
 */
export interface IHookRunner {
  runPreToolCall(toolName: string, input: Record<string, unknown>): void
  runPostToolCall(toolName: string, result: string, isError: boolean): void
  runUserPromptSubmit(prompt: string): void
}

export interface EngineConfig {
  model: string
  baseURL?: string
  apiKey: string
  maxIterations: number
  cwd: string
  permissionMode: 'auto' | 'ask' | 'deny'
  systemPrompt?: string
  /** Extra tools to inject (e.g. MCP tools) */
  extraTools?: Tool[]
  /**
   * Plan mode: restrict tools to read-only (Read, Glob, Grep, WebFetch, WebSearch).
   * The agent analyzes and plans but cannot write, edit, or execute.
   */
  planMode?: boolean
  /** Hook runner for PreToolCall / PostToolCall / UserPromptSubmit events */
  hookRunner?: IHookRunner
}

export interface TurnResult {
  stopped: boolean
  reason: 'max_iterations' | 'stop_sequence' | 'tool_end' | 'error'
  output: string
}
