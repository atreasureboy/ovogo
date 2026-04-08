/**
 * Think-Act-Observe Engine — with streaming output
 *
 * Distilled from:
 * - src/QueryEngine.ts         (top-level orchestration)
 * - src/query.ts               (API call + tool execution loop)
 * - src/services/tools/toolOrchestration.ts  (parallel vs serial batching)
 *
 * Key improvements over naïve implementation:
 *
 * 1. Parallel tool execution (reference: toolOrchestration.ts)
 *    Read-only tools (Read/Glob/Grep/WebFetch/WebSearch) are batched and run
 *    with Promise.all.  Write/exec tools run serially.
 *
 * 2. AbortController per turn (reference: abortController.ts)
 *    engine.abort() cancels the current turn at any point — including inside
 *    long-running Bash commands and network fetches.
 *
 * 3. Plan mode — only read-only tools are exposed/executed.
 *
 * 4. Hook callbacks around every tool call.
 */

import OpenAI from 'openai'
import type {
  EngineConfig,
  OpenAIMessage,
  Tool,
  ToolContext,
  ToolResult,
  TurnResult,
} from './types.js'
import { createTools, findTool, getToolDefinitions } from '../tools/index.js'
import { getPlanModePrefix } from '../prompts/system.js'
import type { Renderer } from '../ui/renderer.js'
import { maybeCompact, estimateTokens, COMPACT_THRESHOLD_TOKENS } from './compact.js'

const MAX_TOOL_RESULT_LENGTH = 20_000

function truncateToolResult(result: string): string {
  if (result.length <= MAX_TOOL_RESULT_LENGTH) return result
  const half = MAX_TOOL_RESULT_LENGTH / 2
  return (
    result.slice(0, half) +
    `\n\n[... ${result.length - MAX_TOOL_RESULT_LENGTH} chars truncated ...]\n\n` +
    result.slice(result.length - half)
  )
}

// Accumulated tool call during streaming
interface StreamingToolCall {
  index: number
  id: string
  name: string
  arguments: string
}

// Parsed tool call ready for execution
interface ParsedToolCall {
  tc: StreamingToolCall
  input: Record<string, unknown>
}

// Tool batch for parallel vs serial scheduling
interface ToolBatch {
  safe: boolean
  calls: ParsedToolCall[]
}

/** Plan mode — tools allowed in read-only analysis */
const PLAN_MODE_TOOLS = new Set(['Read', 'Glob', 'Grep', 'WebFetch', 'WebSearch'])

/**
 * Concurrency-safe tools: pure reads with no side-effects.
 * These can run in parallel within a single LLM response.
 * Reference: Claude Code isConcurrencySafe flag on each tool.
 */
const CONCURRENCY_SAFE_TOOLS = new Set(['Read', 'Glob', 'Grep', 'WebFetch', 'WebSearch'])

/**
 * Partition tool calls into batches for scheduling:
 * - Consecutive safe (read-only) tools → one batch, run with Promise.all
 * - Any unsafe (write/exec) tool → its own serial batch
 * Reference: Claude Code toolOrchestration.ts partitionToolCalls()
 */
function partitionToolCalls(calls: ParsedToolCall[]): ToolBatch[] {
  const batches: ToolBatch[] = []

  for (const call of calls) {
    const safe = CONCURRENCY_SAFE_TOOLS.has(call.tc.name)
    const last = batches[batches.length - 1]

    if (last && last.safe && safe) {
      last.calls.push(call)   // extend existing safe batch
    } else {
      batches.push({ safe, calls: [call] })  // new batch
    }
  }

  return batches
}

export class ExecutionEngine {
  private client: OpenAI
  private tools: Tool[]
  private config: EngineConfig
  private renderer: Renderer
  /** Abort controller for the current turn — null when idle */
  private currentTurnAbortController: AbortController | null = null

  constructor(config: EngineConfig, renderer: Renderer) {
    this.config = config
    this.renderer = renderer
    this.client = new OpenAI({
      apiKey: config.apiKey,
      baseURL: config.baseURL,
    })
    this.tools = createTools(config.extraTools ?? [])
  }

  /**
   * Cancel the currently running turn.
   * Propagates to all in-flight tool executions via ToolContext.signal.
   */
  abort(): void {
    this.currentTurnAbortController?.abort('user_cancelled')
  }

  /**
   * Execute a single user turn with streaming output.
   * Full Think → Act → Observe loop.
   */
  async runTurn(
    userMessage: string,
    history: OpenAIMessage[],
  ): Promise<{ result: TurnResult; newHistory: OpenAIMessage[] }> {
    const planMode = this.config.planMode ?? false

    // Build system prompt: optional plan-mode prefix + pre-assembled prompt
    const baseSystemPrompt = this.config.systemPrompt ?? ''
    const systemPrompt = planMode
      ? getPlanModePrefix() + baseSystemPrompt
      : baseSystemPrompt

    // Per-turn AbortController — cancelled by engine.abort() or SIGINT
    const turnAbortController = new AbortController()
    this.currentTurnAbortController = turnAbortController

    const toolContext: ToolContext = {
      cwd: this.config.cwd,
      permissionMode: this.config.permissionMode,
      signal: turnAbortController.signal,
    }

    const messages: OpenAIMessage[] = [
      ...history,
      { role: 'user', content: userMessage },
    ]

    // In plan mode, only expose read-only tools
    const allToolDefs = getToolDefinitions(this.tools)
    const toolDefs = planMode
      ? allToolDefs.filter((t) => PLAN_MODE_TOOLS.has(t.function.name))
      : allToolDefs

    let iterations = 0
    let finalOutput = ''

    try {
      while (iterations < this.config.maxIterations) {
        // Check for cancellation at the top of each loop
        if (turnAbortController.signal.aborted) {
          return {
            result: { stopped: true, reason: 'error', output: finalOutput },
            newHistory: messages,
          }
        }

        iterations++

        // ── Auto-compact when context grows too large ────────────
        const estimatedTokens = estimateTokens(messages)
        if (estimatedTokens > COMPACT_THRESHOLD_TOKENS) {
          this.renderer.compactStart(estimatedTokens)
          const compactResult = await maybeCompact(this.client, this.config.model, messages)
          if (compactResult.compacted) {
            messages.length = 0
            messages.push(...compactResult.messages)
            this.renderer.compactDone(compactResult.originalTokens, compactResult.summaryTokens)
          }
        }

        // ── Streaming API call ───────────────────────────────────
        this.renderer.startSpinner()

        let stream: AsyncIterable<OpenAI.Chat.ChatCompletionChunk>
        try {
          stream = await this.client.chat.completions.create(
            {
              model: this.config.model,
              messages: [
                { role: 'system', content: systemPrompt },
                ...(messages as OpenAI.Chat.ChatCompletionMessageParam[]),
              ],
              tools: toolDefs as OpenAI.Chat.ChatCompletionTool[],
              tool_choice: 'auto',
              temperature: 0,
              max_tokens: 8192,
              stream: true,
            },
            // Pass abort signal to the HTTP request
            { signal: turnAbortController.signal },
          )
        } catch (err: unknown) {
          this.renderer.stopSpinner()
          const error = err as Error
          if (error.name === 'AbortError' || turnAbortController.signal.aborted) {
            return {
              result: { stopped: true, reason: 'error', output: finalOutput },
              newHistory: messages,
            }
          }
          this.renderer.error(`API error: ${error.message}`)
          return {
            result: { stopped: true, reason: 'error', output: error.message },
            newHistory: messages,
          }
        }

        // ── Consume stream ───────────────────────────────────────
        let assistantText = ''
        let finishReason: string | null = null
        const toolCallsMap = new Map<number, StreamingToolCall>()
        let firstToken = true

        try {
          for await (const chunk of stream) {
            if (turnAbortController.signal.aborted) break

            const delta = chunk.choices[0]?.delta
            if (!delta) continue

            if (delta.content) {
              if (firstToken) {
                this.renderer.stopSpinner()
                this.renderer.beginAssistantText()
                firstToken = false
              }
              this.renderer.streamToken(delta.content)
              assistantText += delta.content
            }

            if (delta.tool_calls) {
              for (const tc of delta.tool_calls) {
                const idx = tc.index
                if (!toolCallsMap.has(idx)) {
                  toolCallsMap.set(idx, { index: idx, id: '', name: '', arguments: '' })
                }
                const acc = toolCallsMap.get(idx)!
                if (tc.id) acc.id = tc.id
                if (tc.function?.name) acc.name += tc.function.name
                if (tc.function?.arguments) acc.arguments += tc.function.arguments
              }
            }

            if (chunk.choices[0]?.finish_reason) {
              finishReason = chunk.choices[0].finish_reason
            }
          }
        } catch (err: unknown) {
          this.renderer.stopSpinner()
          const error = err as Error
          if (error.name === 'AbortError' || turnAbortController.signal.aborted) {
            return {
              result: { stopped: true, reason: 'error', output: finalOutput },
              newHistory: messages,
            }
          }
          this.renderer.error(`Stream error: ${error.message}`)
          return {
            result: { stopped: true, reason: 'error', output: error.message },
            newHistory: messages,
          }
        }

        this.renderer.stopSpinner()

        if (assistantText) {
          this.renderer.endAssistantText()
          finalOutput = assistantText
        }

        const rawToolCalls = Array.from(toolCallsMap.values()).sort((a, b) => a.index - b.index)

        const assistantMsg: OpenAIMessage = {
          role: 'assistant',
          content: assistantText || null,
          tool_calls: rawToolCalls.length > 0
            ? rawToolCalls.map((tc) => ({
                id: tc.id,
                type: 'function' as const,
                function: { name: tc.name, arguments: tc.arguments },
              }))
            : undefined,
        }
        messages.push(assistantMsg)

        if (finishReason === 'stop' || rawToolCalls.length === 0) {
          return {
            result: { stopped: true, reason: 'stop_sequence', output: finalOutput },
            newHistory: messages,
          }
        }

        // ── Parse inputs ─────────────────────────────────────────
        const parsedCalls: ParsedToolCall[] = rawToolCalls.map((tc) => {
          let input: Record<string, unknown>
          try {
            input = JSON.parse(tc.arguments || '{}') as Record<string, unknown>
          } catch {
            input = {}
          }
          return { tc, input }
        })

        // ── Schedule: parallel (safe) vs serial (unsafe) ─────────
        // Reference: Claude Code toolOrchestration.ts
        const batches = partitionToolCalls(parsedCalls)

        for (const batch of batches) {
          if (turnAbortController.signal.aborted) break

          if (batch.safe && batch.calls.length > 1) {
            // ── Parallel batch ───────────────────────────────────
            // Show all tool starts up front
            for (const { tc, input } of batch.calls) {
              this.renderer.toolStart(tc.name, input)
              this.config.hookRunner?.runPreToolCall(tc.name, input)
            }

            // Execute concurrently
            const results = await Promise.all(
              batch.calls.map(({ tc, input }) =>
                this.executeToolCall(tc.name, input, toolContext, planMode),
              ),
            )

            // Collect results in original order
            for (let i = 0; i < batch.calls.length; i++) {
              const { tc } = batch.calls[i]
              const result = results[i]
              this.config.hookRunner?.runPostToolCall(tc.name, result.content, result.isError)
              this.renderer.toolResult(tc.name, result.content, result.isError)
              messages.push({
                role: 'tool',
                tool_call_id: tc.id,
                content: truncateToolResult(result.content),
                name: tc.name,
              })
            }
          } else {
            // ── Serial batch ─────────────────────────────────────
            for (const { tc, input } of batch.calls) {
              if (turnAbortController.signal.aborted) break

              this.renderer.toolStart(tc.name, input)
              this.config.hookRunner?.runPreToolCall(tc.name, input)

              const result = await this.executeToolCall(tc.name, input, toolContext, planMode)

              this.config.hookRunner?.runPostToolCall(tc.name, result.content, result.isError)
              this.renderer.toolResult(tc.name, result.content, result.isError)

              messages.push({
                role: 'tool',
                tool_call_id: tc.id,
                content: truncateToolResult(result.content),
                name: tc.name,
              })
            }
          }
        }
      }
    } finally {
      this.currentTurnAbortController = null
    }

    this.renderer.warn(`Max iterations (${this.config.maxIterations}) reached`)
    return {
      result: { stopped: true, reason: 'max_iterations', output: finalOutput },
      newHistory: messages,
    }
  }

  private async executeToolCall(
    toolName: string,
    input: Record<string, unknown>,
    context: ToolContext,
    planMode = false,
  ): Promise<ToolResult> {
    // In plan mode, block write tools (defence in depth — tool defs already filtered)
    if (planMode && !PLAN_MODE_TOOLS.has(toolName)) {
      return {
        content: `Tool "${toolName}" is not available in plan mode. Only read-only tools are allowed. Output your plan as text.`,
        isError: true,
      }
    }

    const tool = findTool(this.tools, toolName)
    if (!tool) {
      return { content: `Unknown tool: ${toolName}`, isError: true }
    }
    try {
      return await tool.execute(input, context)
    } catch (err: unknown) {
      return {
        content: `Tool ${toolName} threw exception: ${(err as Error).message}`,
        isError: true,
      }
    }
  }

  getModel(): string {
    return this.config.model
  }
}
