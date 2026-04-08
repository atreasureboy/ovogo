/**
 * AgentTool — spawn a sub-agent to handle a focused subtask
 *
 * Distilled from Claude Code source:
 * - src/tools/AgentTool/runAgent.ts   (sub-engine execution)
 * - src/tools/AgentTool/prompt.ts     (description and when-to-use)
 *
 * Design:
 * - Parent engine calls AgentTool with {description, prompt}
 * - AgentTool creates a fresh child ExecutionEngine
 * - Child has independent conversation history (clean context)
 * - Child shares the same renderer (with visual nesting via indent)
 * - Child's result is returned as a string to the parent
 *
 * Why sub-agents?
 * - Complex tasks: parent decomposes, sub-agents execute pieces in sequence
 * - Clean context: each sub-agent gets a focused prompt, no noise from parent history
 * - Recursion guard: sub-agents cannot spawn further sub-agents (depth=1 limit)
 */

import type { Tool, ToolContext, ToolDefinition, ToolResult } from '../core/types.js'
import type { EngineConfig } from '../core/types.js'

// Injected at startup — avoids circular imports
let _engineFactory: ((config: EngineConfig, renderer: unknown) => { runTurn: (msg: string, history: never[]) => Promise<{ result: { output: string; reason: string } }> }) | null = null
let _currentConfig: EngineConfig | null = null
let _currentRenderer: unknown = null

export function registerAgentFactory(
  factory: typeof _engineFactory,
  config: EngineConfig,
  renderer: unknown,
): void {
  _engineFactory = factory
  _currentConfig = config
  _currentRenderer = renderer
}

export class AgentTool implements Tool {
  name = 'Agent'

  definition: ToolDefinition = {
    type: 'function',
    function: {
      name: 'Agent',
      description: `Launch a focused sub-agent to handle a specific subtask.

Use this when:
- A task has a self-contained subtask that would clutter the main conversation
- You need to explore/investigate something without polluting the main context
- A subtask requires many tool calls but produces a single final answer

The sub-agent gets a fresh conversation context with only the prompt you provide.
It has access to all the same tools (Bash, Read, Write, Edit, Glob, Grep, etc.)
but CANNOT spawn further sub-agents.

The sub-agent runs to completion and returns its final output as a string.

IMPORTANT: Only use this for genuinely self-contained subtasks. Don't use it
just to parallelize work — use multiple tool calls in a single response for that.`,
      parameters: {
        type: 'object',
        properties: {
          description: {
            type: 'string',
            description: 'Brief label for this sub-task (shown in UI, e.g. "Fix auth module")',
          },
          prompt: {
            type: 'string',
            description: `The complete task prompt for the sub-agent. Must be fully self-contained — the sub-agent has NO access to the parent conversation history. Include all context needed: file paths, current state, what to do, what to return.`,
          },
          max_iterations: {
            type: 'number',
            description: 'Max think-act cycles for the sub-agent (default: 15)',
          },
        },
        required: ['description', 'prompt'],
      },
    },
  }

  async execute(input: Record<string, unknown>, context: ToolContext): Promise<ToolResult> {
    const description = String(input.description ?? 'subtask')
    const prompt = String(input.prompt ?? '')
    const maxIterations = typeof input.max_iterations === 'number'
      ? Math.min(input.max_iterations, 30)
      : 15

    if (!prompt.trim()) {
      return { content: 'Error: prompt is required and must not be empty', isError: true }
    }

    if (!_engineFactory || !_currentConfig || !_currentRenderer) {
      return {
        content: 'Error: AgentTool not initialized. Call registerAgentFactory first.',
        isError: true,
      }
    }

    // Visual: show sub-agent header
    const renderer = _currentRenderer as {
      agentStart: (desc: string) => void
      agentDone: (desc: string, success: boolean) => void
    }
    renderer.agentStart(description)

    // Create child engine with reduced max iterations + same config
    const childConfig: EngineConfig = {
      ..._currentConfig,
      maxIterations,
      cwd: context.cwd,
      // Mark as sub-agent so it won't spawn further agents
      systemPrompt: buildSubAgentSystemPrompt(context.cwd),
    }

    const childEngine = _engineFactory(childConfig, _currentRenderer)

    try {
      const { result } = await childEngine.runTurn(prompt, [])
      renderer.agentDone(description, result.reason !== 'error')

      if (!result.output) {
        return {
          content: `Sub-agent "${description}" completed (${result.reason}) but produced no text output.`,
          isError: false,
        }
      }

      return {
        content: `Sub-agent "${description}" result:\n\n${result.output}`,
        isError: false,
      }
    } catch (err: unknown) {
      renderer.agentDone(description, false)
      return {
        content: `Sub-agent "${description}" failed: ${(err as Error).message}`,
        isError: true,
      }
    }
  }
}

function buildSubAgentSystemPrompt(cwd: string): string {
  return `You are a focused sub-agent with a specific subtask to complete.

Working directory: ${cwd}

Rules:
- Complete ONLY the task in the user message — do not expand scope
- You cannot spawn further sub-agents (Agent tool is disabled for you)
- After completing the task, provide a clear, complete summary of what you did and the result
- If you cannot complete the task, explain exactly why and what you tried

You have access to: Bash, Read, Write, Edit, Glob, Grep, TodoWrite, WebFetch, WebSearch.`
}
