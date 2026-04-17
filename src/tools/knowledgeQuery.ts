/**
 * KnowledgeQuery tool — allows the agent to actively query the knowledge base
 */

import type { Tool, ToolContext, ToolDefinition, ToolResult } from '../core/types.js'
import { KnowledgeBase, type KnowledgeType } from '../core/knowledgeBase.js'

export const KNOWLEDGE_QUERY_DEFINITION: ToolDefinition = {
  type: 'function',
  function: {
    name: 'KnowledgeQuery',
    description: 'Query the battle knowledge base for attack patterns, CVE notes, tool combos, or target profiles. Use this to find proven attack strategies before planning your approach.',
    parameters: {
      type: 'object',
      properties: {
        type: {
          type: 'string',
          enum: ['attack_patterns', 'cve_notes', 'tool_combos', 'target_profiles', 'all'],
          description: 'Knowledge type to query. "all" searches everything.',
        },
        query: {
          type: 'string',
          description: 'Search query — target name, technology, CVE, or keyword.',
        },
        limit: {
          type: 'number',
          description: 'Maximum results to return. Default: 10.',
        },
      },
      required: ['type', 'query'],
    },
  },
}

export class KnowledgeQueryTool implements Tool {
  name = 'KnowledgeQuery'
  definition = KNOWLEDGE_QUERY_DEFINITION

  constructor(private kb: KnowledgeBase) {}

  async execute(input: Record<string, unknown>, _context: ToolContext): Promise<ToolResult> {
    const type = String(input.type || 'all') as KnowledgeType | 'all'
    const query = String(input.query || '')
    const limit = Number(input.limit) || 10

    if (!query) {
      return { content: 'Error: query parameter is required', isError: true }
    }

    const results: string[] = []

    const types: KnowledgeType[] = type === 'all'
      ? ['attack_patterns', 'cve_notes', 'tool_combos', 'target_profiles']
      : [type]

    for (const t of types) {
      const entries = this.kb.search(t, { keywords: [query], limit })
      if (entries.length > 0) {
        results.push(`## ${t}\n${this.kb.toPrompt(entries)}`)
      }
    }

    if (results.length === 0) {
      return { content: `No knowledge found matching query: "${query}". The knowledge base is still growing — keep running sessions to build it up.`, isError: false }
    }

    return { content: results.join('\n\n'), isError: false }
  }
}
