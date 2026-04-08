/**
 * AgentTool — spawn a specialized sub-agent to handle a focused subtask
 */

import type { Tool, ToolContext, ToolDefinition, ToolResult } from '../core/types.js'
import type { EngineConfig } from '../core/types.js'
import { getAgentTypeSystemPrompt } from '../prompts/system.js'

export type AgentType = 'general-purpose' | 'explore' | 'plan' | 'code-reviewer'

const READ_ONLY_TYPES = new Set<AgentType>(['explore', 'plan', 'code-reviewer'])

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
      description: `Launch a specialized sub-agent to handle a focused subtask.

Sub-agent types:
- "general-purpose" (default): All tools available. Use for complex subtasks that need to read and write.
- "explore": Read-only (Read, Glob, Grep, WebFetch, WebSearch). Fast codebase investigation without side effects.
- "plan": Read-only + produces a numbered step-by-step plan. Use before making complex changes.
- "code-reviewer": Read-only + code quality focus. Reports issues by severity without making changes.

Use sub-agents when:
- A subtask is self-contained and would clutter the main conversation
- You need to investigate something without polluting the main context
- A subtask requires many tool calls but produces a single final answer

The sub-agent gets a fresh conversation context with only the prompt you provide.
It runs to completion and returns its output as a string.

IMPORTANT: Sub-agents cannot spawn further sub-agents.`,
      parameters: {
        type: 'object',
        properties: {
          description: {
            type: 'string',
            description: 'Brief label for this sub-task (shown in UI, e.g. "Explore auth module")',
          },
          prompt: {
            type: 'string',
            description: `Complete task prompt for the sub-agent. Must be fully self-contained — the sub-agent has NO access to the parent conversation. Include all context: file paths, current state, what to do, what to return.`,
          },
          subagent_type: {
            type: 'string',
            enum: ['general-purpose', 'explore', 'plan', 'code-reviewer'],
            description: 'Type of sub-agent (default: "general-purpose"). Use "explore" for read-only investigation, "plan" for planning, "code-reviewer" for code review.',
          },
          max_iterations: {
            type: 'number',
            description: 'Max think-act cycles for the sub-agent (default: 15, max: 30)',
          },
        },
        required: ['description', 'prompt'],
      },
    },
  }

  async execute(input: Record<string, unknown>, context: ToolContext): Promise<ToolResult> {
    const description = String(input.description ?? 'subtask')
    const prompt = String(input.prompt ?? '')
    const agentType = (String(input.subagent_type ?? 'general-purpose')) as AgentType
    const maxIterations = typeof input.max_iterations === 'number'
      ? Math.min(input.max_iterations, 30)
      : 15

    if (!prompt.trim()) {
      return { content: 'Error: prompt is required and must not be empty', isError: true }
    }

    const validTypes: AgentType[] = ['general-purpose', 'explore', 'plan', 'code-reviewer']
    if (!validTypes.includes(agentType)) {
      return {
        content: `Error: unknown subagent_type "${agentType}". Use one of: ${validTypes.join(', ')}`,
        isError: true,
      }
    }

    if (!_engineFactory || !_currentConfig || !_currentRenderer) {
      return {
        content: 'Error: AgentTool not initialized. Call registerAgentFactory first.',
        isError: true,
      }
    }

    const renderer = _currentRenderer as {
      agentStart: (desc: string, type: string) => void
      agentDone: (desc: string, success: boolean) => void
    }
    renderer.agentStart(description, agentType)

    // Build child config based on agent type
    const childConfig: EngineConfig = {
      ..._currentConfig,
      maxIterations,
      cwd: context.cwd,
      // No hooks in sub-agents (avoid recursive hook execution)
      hookRunner: undefined,
      // Read-only types get planMode=true (engine filters write tools)
      planMode: READ_ONLY_TYPES.has(agentType),
      // Type-specific system prompt
      systemPrompt: getAgentTypeSystemPrompt(agentType, context.cwd),
    }

    const childEngine = _engineFactory(childConfig, _currentRenderer)

    try {
      const { result } = await childEngine.runTurn(prompt, [])
      renderer.agentDone(description, result.reason !== 'error')

      if (!result.output) {
        return {
          content: `Sub-agent "${description}" (${agentType}) completed (${result.reason}) but produced no text output.`,
          isError: false,
        }
      }

      return {
        content: `Sub-agent "${description}" (${agentType}) result:\n\n${result.output}`,
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
