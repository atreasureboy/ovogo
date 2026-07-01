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

export interface ToolRuntimeMetadata {
  /** Tool can be exposed in plan mode because it should not mutate local state. */
  readOnly?: boolean
  /** Tool calls with no ordering dependency may run concurrently in one model turn. */
  concurrencySafe?: boolean
  /** Tool result can be reused for identical inputs. */
  cacheable?: boolean
  /** Optional TTL for cached successful results. */
  cacheTtlMs?: number
  /** Tool is expected to benefit from progress tracking. */
  longRunning?: boolean
}

export interface Tool {
  name: string
  definition: ToolDefinition
  runtime?: ToolRuntimeMetadata
  execute(input: Record<string, unknown>, context: ToolContext): Promise<ToolResult>
}

export interface ToolContext {
  cwd: string
  permissionMode: 'auto' | 'ask' | 'deny'
  /** AbortSignal — tools should honour this to support Ctrl+C cancellation */
  signal?: AbortSignal
  /** Progress update function for long-running tools */
  updateProgress?: (progress: number, recoveryData?: Record<string, unknown>) => void
  /**
   * API config forwarded from engine — allows tools that need LLM calls
   * (e.g. image analysis via vision API) to reuse the same endpoint + key.
   */
  apiConfig?: { apiKey: string; baseURL?: string; model: string }
  /** Unified model adapter for tools that need auxiliary LLM calls. */
  modelClient?: import('./modelClient.js').ModelClient
  /**
   * Session output directory — for tools that need to write to the engagement
   * session directory (e.g. FindingWrite for anchor updates).
   */
  sessionDir?: string
  /** Event log for audit trail — best-effort, never throws */
  eventLog?: import('./eventLog.js').EventLog
  /** Semantic memory — cross-turn knowledge persistence */
  semanticMemory?: import('./semanticMemory.js').SemanticMemory
  /** Episodic memory — action trajectory persistence */
  episodicMemory?: import('./episodicMemory.js').EpisodicMemory
  /** Knowledge base — growing attack knowledge */
  knowledgeBase?: import('./knowledgeBase.js').KnowledgeBase
  /** Additional roots tools may read from. cwd and sessionDir are always included. */
  readableRoots?: string[]
  /** Additional roots mutating file tools may write to. cwd and sessionDir are always included. */
  writableRoots?: string[]
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
  /** Session output directory — injected into sub-agent prompts */
  sessionDir?: string
  /** Primary engagement target (usually the first configured target) */
  primaryTarget?: string
  /** All in-scope targets from engagement config */
  engagementTargets?: string[]
  /** Out-of-scope targets from engagement config */
  outOfScopeTargets?: string[]
  /** Current engagement phase */
  engagementPhase?: string
  /** Progress tracker for long-running tools */
  progressTracker?: import('./progressTracker.js').ProgressTracker
  /** Cache for tool execution results */
  toolCache?: import('./toolCache.js').ToolCache
  /**
   * Coordinator mode: main agent acts as orchestrator only.
   * Scanning/exploitation tools are blocked — must delegate to sub-agents.
   * Only applies to the main agent (sessionDir is set), not sub-agents.
   */
  coordinatorMode?: boolean
  /**
   * Maximum context window in tokens for the selected model.
   * Defaults to 200_000 (claude-sonnet-4-x).  Used to compute percentage-based
   * compact/warn thresholds instead of a flat token count.
   */
  maxContextTokens?: number
  /** Dispatch manager for async agent communication */
  dispatchManager?: import('./dispatch.js').DispatchManager
  /**
   * Upper bound for one parallel-safe tool batch. Prevents unbounded fan-out
   * when a model emits many concurrency-safe tool calls in one response.
   */
  maxConcurrentToolCalls?: number
  /** Event log for audit trail */
  eventLog?: import('./eventLog.js').EventLog
  /** Context budget manager for explicit token allocation */
  contextBudget?: import('./contextBudget.js').ContextBudgetManager
  /** Semantic memory — cross-turn knowledge persistence */
  semanticMemory?: import('./semanticMemory.js').SemanticMemory
  /** Episodic memory — action trajectory persistence */
  episodicMemory?: import('./episodicMemory.js').EpisodicMemory
  /** Knowledge base — growing attack knowledge */
  knowledgeBase?: import('./knowledgeBase.js').KnowledgeBase
  /** Additional roots for read tools. cwd and sessionDir are always included. */
  readableRoots?: string[]
  /** Additional roots for write/edit/output tools. cwd and sessionDir are always included. */
  writableRoots?: string[]
  /** Persistent permission rules from .ovogo/permissions.json (deny wins). */
  permissionRules?: import('../config/permissionRules.js').PermissionRules
}

export interface TurnResult {
  stopped: boolean
  /**
   * stop_sequence  — LLM returned finish_reason=stop with no tool calls
   * max_iterations — hit maxIterations ceiling
   * error          — hard abort (Ctrl+C × 2) or unrecoverable API error
   * interrupted    — soft pause requested (Ctrl+C × 1), partial history preserved
   */
  reason: 'max_iterations' | 'stop_sequence' | 'tool_end' | 'error' | 'interrupted'
  output: string
}
