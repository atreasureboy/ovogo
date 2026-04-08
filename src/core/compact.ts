/**
 * Conversation Compact — auto-summarize when context grows too large
 *
 * Distilled from Claude Code source:
 * - src/services/compact/autoCompact.ts  (threshold logic)
 * - src/services/compact/prompt.ts       (DETAILED_ANALYSIS_INSTRUCTION + NO_TOOLS_PREAMBLE)
 * - src/services/compact/compact.ts      (compactConversation)
 *
 * Strategy:
 *   1. Estimate token count of current conversation (~4 chars/token)
 *   2. When it exceeds COMPACT_THRESHOLD_TOKENS, call the LLM to summarize
 *   3. Replace old messages with a single system-style summary message
 *   4. Keep last N recent messages verbatim (fresh context)
 */

import OpenAI from 'openai'
import type { OpenAIMessage } from './types.js'

// Rough chars-per-token estimate (conservative — better to compact early)
const CHARS_PER_TOKEN = 3.5

// Trigger compact when estimated tokens exceed this (model max is usually 128k–200k)
export const COMPACT_THRESHOLD_TOKENS = 80_000

// Keep this many recent messages verbatim after compaction
const KEEP_RECENT_MESSAGES = 8

// Reserve tokens for the summary output itself
const SUMMARY_OUTPUT_RESERVE = 4_000

/**
 * Rough token count estimate from message array.
 * Counts all content strings + JSON overhead.
 */
export function estimateTokens(messages: OpenAIMessage[]): number {
  let chars = 0
  for (const msg of messages) {
    if (typeof msg.content === 'string') {
      chars += msg.content.length
    } else if (msg.content === null) {
      chars += 4
    }
    if (msg.tool_calls) {
      chars += JSON.stringify(msg.tool_calls).length
    }
    if (msg.name) chars += msg.name.length
    chars += 20 // message envelope overhead
  }
  return Math.ceil(chars / CHARS_PER_TOKEN)
}

export function shouldCompact(messages: OpenAIMessage[], threshold = COMPACT_THRESHOLD_TOKENS): boolean {
  return estimateTokens(messages) > threshold
}

// ── Compact prompt (from Claude Code source) ──────────────────────────────────

const NO_TOOLS_PREAMBLE = `CRITICAL: Respond with TEXT ONLY. Do NOT call any tools.
Do NOT use any tools. Your entire response must be a plain text summary.
Tool calls will be IGNORED — you have one turn to produce text.

`

const SUMMARY_SYSTEM_PROMPT = `${NO_TOOLS_PREAMBLE}You are summarizing a conversation between a user and an AI coding assistant.

Your summary will replace the full conversation history. The assistant must be able to continue the conversation from your summary with complete context.

Before writing the summary, analyze the conversation in <analysis> tags:
1. Go through each message chronologically
2. Identify: user requests, decisions made, files modified, commands run, errors encountered and fixed
3. Note any explicit user feedback or corrections
4. Identify what is still in progress or incomplete

Then write the summary in <summary> tags with these sections:

## Task Overview
What the user asked for and the overall goal.

## Work Completed
- Files created/modified (with paths and key changes)
- Commands run and their outcomes
- Problems solved and how

## Current State
What has been done, what is working, what is still pending.

## Key Context
Important decisions, patterns, constraints, or user preferences to remember.
Include relevant code snippets, function signatures, or file contents that are critical for continuing.

## Next Steps
What needs to be done next (if anything is incomplete).`

/**
 * Extract content between tags, stripping the analysis scratchpad.
 */
function extractSummary(text: string): string {
  // Try to get <summary>...</summary>
  const summaryMatch = text.match(/<summary>([\s\S]*?)<\/summary>/i)
  if (summaryMatch?.[1]) {
    return summaryMatch[1].trim()
  }

  // Fall back: strip <analysis> block and return the rest
  return text
    .replace(/<analysis>[\s\S]*?<\/analysis>/i, '')
    .trim()
}

/**
 * Serialize messages to text for the summarization prompt.
 */
function serializeMessages(messages: OpenAIMessage[]): string {
  const parts: string[] = []
  for (const msg of messages) {
    const role = msg.role.toUpperCase()
    if (typeof msg.content === 'string' && msg.content) {
      parts.push(`[${role}]: ${msg.content}`)
    } else if (msg.content === null && msg.tool_calls?.length) {
      const calls = msg.tool_calls
        .map(tc => `  → ${tc.function.name}(${tc.function.arguments.slice(0, 200)})`)
        .join('\n')
      parts.push(`[ASSISTANT tool calls]:\n${calls}`)
    }
    if (msg.role === 'tool' && typeof msg.content === 'string') {
      const preview = msg.content.slice(0, 500)
      const truncated = msg.content.length > 500 ? ' ...[truncated]' : ''
      parts.push(`[TOOL RESULT: ${msg.name ?? '?'}]: ${preview}${truncated}`)
    }
  }
  return parts.join('\n\n')
}

export interface CompactResult {
  compacted: boolean
  messages: OpenAIMessage[]
  summaryTokens: number
  originalTokens: number
}

/**
 * Compact the conversation if it exceeds the token threshold.
 * Returns new (smaller) messages array.
 */
export async function maybeCompact(
  client: OpenAI,
  model: string,
  messages: OpenAIMessage[],
  threshold = COMPACT_THRESHOLD_TOKENS,
): Promise<CompactResult> {
  const originalTokens = estimateTokens(messages)

  if (originalTokens <= threshold) {
    return { compacted: false, messages, summaryTokens: 0, originalTokens }
  }

  // Keep the most recent messages verbatim — they're the freshest context
  const recentMessages = messages.slice(-KEEP_RECENT_MESSAGES)
  const olderMessages = messages.slice(0, -KEEP_RECENT_MESSAGES)

  if (olderMessages.length === 0) {
    // Nothing to compact — can't help
    return { compacted: false, messages, summaryTokens: 0, originalTokens }
  }

  // Build the summarization request
  const conversationText = serializeMessages(olderMessages)
  const userPrompt = `Please summarize the following conversation:\n\n${conversationText}`

  let summaryText: string
  try {
    const response = await client.chat.completions.create({
      model,
      messages: [
        { role: 'system', content: SUMMARY_SYSTEM_PROMPT },
        { role: 'user', content: userPrompt },
      ],
      temperature: 0,
      max_tokens: SUMMARY_OUTPUT_RESERVE,
      // No tools — we explicitly don't want tool calls here
    })
    summaryText = response.choices[0]?.message?.content ?? ''
  } catch (err) {
    // If summarization fails, return original messages unchanged
    return { compacted: false, messages, summaryTokens: 0, originalTokens }
  }

  const summary = extractSummary(summaryText)
  if (!summary) {
    return { compacted: false, messages, summaryTokens: 0, originalTokens }
  }

  // Build compacted history: summary message + recent verbatim messages
  const summaryMessage: OpenAIMessage = {
    role: 'user',
    content: `[CONVERSATION SUMMARY — previous context compacted]\n\n${summary}`,
  }

  const syntheticAssistantAck: OpenAIMessage = {
    role: 'assistant',
    content: `I've reviewed the conversation summary and have the context needed to continue.`,
  }

  const compactedMessages: OpenAIMessage[] = [
    summaryMessage,
    syntheticAssistantAck,
    ...recentMessages,
  ]

  const summaryTokens = estimateTokens(compactedMessages)

  return {
    compacted: true,
    messages: compactedMessages,
    summaryTokens,
    originalTokens,
  }
}
