/**
 * Think-Act-Observe Engine — with streaming output
 *
 * Distilled from:
 * - src/QueryEngine.ts  (top-level orchestration)
 * - src/query.ts        (API call + tool execution loop)
 *
 * Streaming: tokens are rendered in real-time as they arrive.
 * Tool calls accumulate during stream, then execute after stream ends.
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
import { getSystemPrompt } from '../prompts/system.js'
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

export class ExecutionEngine {
  private client: OpenAI
  private tools: Tool[]
  private config: EngineConfig
  private renderer: Renderer

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
   * Execute a single user turn with streaming output.
   * Full Think → Act → Observe loop.
   */
  async runTurn(
    userMessage: string,
    history: OpenAIMessage[],
  ): Promise<{ result: TurnResult; newHistory: OpenAIMessage[] }> {
    const systemPrompt = this.config.systemPrompt ?? getSystemPrompt(this.config.cwd)
    const toolContext: ToolContext = {
      cwd: this.config.cwd,
      permissionMode: this.config.permissionMode,
    }

    const messages: OpenAIMessage[] = [
      ...history,
      { role: 'user', content: userMessage },
    ]

    const toolDefs = getToolDefinitions(this.tools)
    let iterations = 0
    let finalOutput = ''

    while (iterations < this.config.maxIterations) {
      iterations++

      // ── Auto-compact when context grows too large ──────────
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

      // ── Streaming API call ──────────────────────────────────
      this.renderer.startSpinner()

      let stream: AsyncIterable<OpenAI.Chat.ChatCompletionChunk>
      try {
        stream = await this.client.chat.completions.create({
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
        })
      } catch (err: unknown) {
        this.renderer.stopSpinner()
        const error = err as Error
        this.renderer.error(`API error: ${error.message}`)
        return {
          result: { stopped: true, reason: 'error', output: error.message },
          newHistory: messages,
        }
      }

      // ── Consume stream ──────────────────────────────────────
      let assistantText = ''
      let finishReason: string | null = null
      const toolCallsMap = new Map<number, StreamingToolCall>()
      let firstToken = true

      try {
        for await (const chunk of stream) {
          const delta = chunk.choices[0]?.delta

          if (!delta) continue

          // Text token
          if (delta.content) {
            if (firstToken) {
              this.renderer.stopSpinner()
              this.renderer.beginAssistantText()
              firstToken = false
            }
            this.renderer.streamToken(delta.content)
            assistantText += delta.content
          }

          // Tool call delta
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
        this.renderer.error(`Stream error: ${error.message}`)
        return {
          result: { stopped: true, reason: 'error', output: error.message },
          newHistory: messages,
        }
      }

      // Ensure spinner stopped
      this.renderer.stopSpinner()

      if (assistantText) {
        this.renderer.endAssistantText()
        finalOutput = assistantText
      }

      const toolCalls = Array.from(toolCallsMap.values()).sort((a, b) => a.index - b.index)

      // Build assistant message for history
      const assistantMsg: OpenAIMessage = {
        role: 'assistant',
        content: assistantText || null,
        tool_calls: toolCalls.length > 0
          ? toolCalls.map(tc => ({
              id: tc.id,
              type: 'function' as const,
              function: { name: tc.name, arguments: tc.arguments },
            }))
          : undefined,
      }
      messages.push(assistantMsg)

      // Stop if no tool calls
      if (finishReason === 'stop' || toolCalls.length === 0) {
        return {
          result: { stopped: true, reason: 'stop_sequence', output: finalOutput },
          newHistory: messages,
        }
      }

      // ── Execute tool calls ──────────────────────────────────
      for (const tc of toolCalls) {
        let input: Record<string, unknown>
        try {
          input = JSON.parse(tc.arguments || '{}') as Record<string, unknown>
        } catch {
          input = {}
        }

        this.renderer.toolStart(tc.name, input)
        const result = await this.executeToolCall(tc.name, input, toolContext)
        this.renderer.toolResult(tc.name, result.content, result.isError)

        messages.push({
          role: 'tool',
          tool_call_id: tc.id,
          content: truncateToolResult(result.content),
          name: tc.name,
        })
      }

      // Loop — model processes results
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
  ): Promise<ToolResult> {
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
