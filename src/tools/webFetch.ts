/**
 * WebFetch — fetch URL and extract readable text
 * Reference: src/tools/WebFetchTool/
 *
 * Uses Node's built-in fetch (Node 18+).
 * Strips HTML tags to return clean text for LLM consumption.
 */

import type { Tool, ToolContext, ToolDefinition, ToolResult } from '../core/types.js'

const MAX_CONTENT_LENGTH = 50_000 // characters returned to LLM
const FETCH_TIMEOUT_MS = 30_000

export interface WebFetchInput {
  url: string
  max_length?: number
  start_index?: number
}

/**
 * Minimal HTML → plain text extraction.
 * Removes scripts/styles/tags, collapses whitespace.
 */
function htmlToText(html: string): string {
  return html
    // Remove script and style blocks entirely
    .replace(/<script[\s\S]*?<\/script>/gi, '')
    .replace(/<style[\s\S]*?<\/style>/gi, '')
    // Convert common block elements to newlines
    .replace(/<\/?(p|div|section|article|header|footer|h[1-6]|li|tr|br)[^>]*>/gi, '\n')
    // Remove all remaining tags
    .replace(/<[^>]+>/g, '')
    // Decode common HTML entities
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&nbsp;/g, ' ')
    // Collapse whitespace
    .replace(/[ \t]+/g, ' ')
    .replace(/\n{3,}/g, '\n\n')
    .trim()
}

export class WebFetchTool implements Tool {
  name = 'WebFetch'

  definition: ToolDefinition = {
    type: 'function',
    function: {
      name: 'WebFetch',
      description: `Fetch a URL and return its content as plain text.

Use this to:
- Read documentation pages
- Fetch API responses
- Check package READMEs or changelogs
- Read web resources referenced in the task

HTML is automatically stripped to extract readable text.
Large pages are truncated — use start_index to paginate.`,
      parameters: {
        type: 'object',
        properties: {
          url: {
            type: 'string',
            description: 'The URL to fetch (must start with http:// or https://)',
          },
          max_length: {
            type: 'number',
            description: `Maximum characters to return (default: ${MAX_CONTENT_LENGTH})`,
          },
          start_index: {
            type: 'number',
            description: 'Character offset to start from (for pagination, default: 0)',
          },
        },
        required: ['url'],
      },
    },
  }

  async execute(input: Record<string, unknown>, _context: ToolContext): Promise<ToolResult> {
    const { url, max_length, start_index } = input as unknown as WebFetchInput

    if (!url || typeof url !== 'string') {
      return { content: 'Error: url is required', isError: true }
    }

    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      return { content: 'Error: URL must start with http:// or https://', isError: true }
    }

    const maxLen = typeof max_length === 'number' ? Math.min(max_length, MAX_CONTENT_LENGTH) : MAX_CONTENT_LENGTH
    const startIdx = typeof start_index === 'number' ? start_index : 0

    try {
      const controller = new AbortController()
      const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS)

      const response = await fetch(url, {
        signal: controller.signal,
        headers: {
          'User-Agent': 'ovogogogo/0.1.0 (autonomous code execution engine)',
          'Accept': 'text/html,application/xhtml+xml,text/plain,*/*',
        },
        redirect: 'follow',
      })

      clearTimeout(timer)

      if (!response.ok) {
        return {
          content: `HTTP ${response.status} ${response.statusText} for ${url}`,
          isError: true,
        }
      }

      const contentType = response.headers.get('content-type') ?? ''
      const rawBody = await response.text()

      let text: string
      if (contentType.includes('text/html')) {
        text = htmlToText(rawBody)
      } else {
        // JSON, plain text, etc — return as-is
        text = rawBody.trim()
      }

      const totalLen = text.length
      const slice = text.slice(startIdx, startIdx + maxLen)

      const header = `URL: ${url}\nContent-Type: ${contentType}\nLength: ${totalLen} chars\n`
      const pagination =
        startIdx + maxLen < totalLen
          ? `\n\n[Showing chars ${startIdx}–${startIdx + maxLen} of ${totalLen}. Use start_index=${startIdx + maxLen} for next page.]`
          : ''

      return {
        content: header + '\n' + slice + pagination,
        isError: false,
      }
    } catch (err: unknown) {
      const error = err as Error
      if (error.name === 'AbortError') {
        return { content: `Request timed out after ${FETCH_TIMEOUT_MS / 1000}s: ${url}`, isError: true }
      }
      return { content: `Fetch error: ${error.message}`, isError: true }
    }
  }
}
