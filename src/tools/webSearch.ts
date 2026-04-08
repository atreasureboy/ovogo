/**
 * WebSearch — search the web and return results
 * Reference: src/tools/WebSearchTool/
 *
 * Backends (in priority order):
 *   1. OVOGO_SEARCH_API_KEY + OVOGO_SEARCH_ENGINE_ID → Google Custom Search JSON API
 *   2. SERPAPI_KEY → SerpAPI (google results)
 *   3. Fallback → DuckDuckGo Instant Answer API (no key needed, limited)
 *
 * Set env vars to unlock fuller results.
 */

import type { Tool, ToolContext, ToolDefinition, ToolResult } from '../core/types.js'

const SEARCH_TIMEOUT_MS = 15_000

export interface WebSearchInput {
  query: string
  num_results?: number
}

interface SearchResult {
  title: string
  url: string
  snippet: string
}

// ─── Backend: DuckDuckGo Instant Answer (no key) ────────────

async function duckduckgoSearch(query: string, numResults: number): Promise<SearchResult[]> {
  const url = `https://api.duckduckgo.com/?q=${encodeURIComponent(query)}&format=json&no_html=1&skip_disambig=1`

  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), SEARCH_TIMEOUT_MS)

  try {
    const resp = await fetch(url, {
      signal: controller.signal,
      headers: { 'User-Agent': 'ovogogogo/0.1.0' },
    })
    clearTimeout(timer)

    if (!resp.ok) return []

    const data = await resp.json() as {
      AbstractText?: string
      AbstractURL?: string
      AbstractSource?: string
      RelatedTopics?: Array<{ Text?: string; FirstURL?: string }>
    }

    const results: SearchResult[] = []

    // Abstract (main answer)
    if (data.AbstractText && data.AbstractURL) {
      results.push({
        title: data.AbstractSource ?? 'Answer',
        url: data.AbstractURL,
        snippet: data.AbstractText,
      })
    }

    // Related topics
    for (const topic of data.RelatedTopics ?? []) {
      if (topic.Text && topic.FirstURL) {
        results.push({
          title: topic.Text.split(' - ')[0] ?? topic.Text,
          url: topic.FirstURL,
          snippet: topic.Text,
        })
        if (results.length >= numResults) break
      }
    }

    return results
  } catch {
    clearTimeout(timer)
    return []
  }
}

// ─── Backend: Google Custom Search JSON API ──────────────────

async function googleSearch(
  query: string,
  numResults: number,
  apiKey: string,
  engineId: string,
): Promise<SearchResult[]> {
  const url =
    `https://www.googleapis.com/customsearch/v1?key=${apiKey}` +
    `&cx=${engineId}&q=${encodeURIComponent(query)}&num=${Math.min(numResults, 10)}`

  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), SEARCH_TIMEOUT_MS)

  try {
    const resp = await fetch(url, { signal: controller.signal })
    clearTimeout(timer)
    if (!resp.ok) return []

    const data = await resp.json() as {
      items?: Array<{ title: string; link: string; snippet: string }>
    }

    return (data.items ?? []).map(item => ({
      title: item.title,
      url: item.link,
      snippet: item.snippet,
    }))
  } catch {
    clearTimeout(timer)
    return []
  }
}

// ─── Backend: SerpAPI ────────────────────────────────────────

async function serpApiSearch(
  query: string,
  numResults: number,
  apiKey: string,
): Promise<SearchResult[]> {
  const url =
    `https://serpapi.com/search.json?api_key=${apiKey}` +
    `&q=${encodeURIComponent(query)}&num=${Math.min(numResults, 10)}&engine=google`

  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), SEARCH_TIMEOUT_MS)

  try {
    const resp = await fetch(url, { signal: controller.signal })
    clearTimeout(timer)
    if (!resp.ok) return []

    const data = await resp.json() as {
      organic_results?: Array<{ title: string; link: string; snippet: string }>
    }

    return (data.organic_results ?? []).map(r => ({
      title: r.title,
      url: r.link,
      snippet: r.snippet,
    }))
  } catch {
    clearTimeout(timer)
    return []
  }
}

// ─────────────────────────────────────────────────────────────

function formatResults(results: SearchResult[], query: string, backend: string): string {
  if (results.length === 0) {
    return `No results found for: ${query}\n\nTip: Set OVOGO_SEARCH_API_KEY + OVOGO_SEARCH_ENGINE_ID (Google) or SERPAPI_KEY for better results.`
  }

  const lines = [`Search: ${query}  [via ${backend}]`, '']
  results.forEach((r, i) => {
    lines.push(`${i + 1}. ${r.title}`)
    lines.push(`   ${r.url}`)
    lines.push(`   ${r.snippet}`)
    lines.push('')
  })
  return lines.join('\n')
}

export class WebSearchTool implements Tool {
  name = 'WebSearch'

  definition: ToolDefinition = {
    type: 'function',
    function: {
      name: 'WebSearch',
      description: `Search the web and return results with titles, URLs, and snippets.

Use this to:
- Look up documentation, APIs, error messages
- Find recent information (post training cutoff)
- Verify package names, versions, or compatibility

Results include URLs you can then fetch with WebFetch for full content.

Backends (set env vars for better results):
- OVOGO_SEARCH_API_KEY + OVOGO_SEARCH_ENGINE_ID → Google Custom Search
- SERPAPI_KEY → SerpAPI
- Fallback: DuckDuckGo Instant Answer (no key needed, limited)`,
      parameters: {
        type: 'object',
        properties: {
          query: {
            type: 'string',
            description: 'Search query',
          },
          num_results: {
            type: 'number',
            description: 'Number of results to return (default: 5, max: 10)',
          },
        },
        required: ['query'],
      },
    },
  }

  async execute(input: Record<string, unknown>, _context: ToolContext): Promise<ToolResult> {
    const { query, num_results } = input as unknown as WebSearchInput

    if (!query || typeof query !== 'string') {
      return { content: 'Error: query is required', isError: true }
    }

    const numResults = Math.min(typeof num_results === 'number' ? num_results : 5, 10)

    // Try backends in priority order
    const googleKey = process.env.OVOGO_SEARCH_API_KEY
    const googleEngineId = process.env.OVOGO_SEARCH_ENGINE_ID
    const serpKey = process.env.SERPAPI_KEY

    let results: SearchResult[] = []
    let backend = 'DuckDuckGo'

    if (googleKey && googleEngineId) {
      results = await googleSearch(query, numResults, googleKey, googleEngineId)
      backend = 'Google Custom Search'
    } else if (serpKey) {
      results = await serpApiSearch(query, numResults, serpKey)
      backend = 'SerpAPI'
    }

    // Fallback to DDG if primary returned nothing
    if (results.length === 0) {
      results = await duckduckgoSearch(query, numResults)
      backend = 'DuckDuckGo'
    }

    return {
      content: formatResults(results, query, backend),
      isError: false,
    }
  }
}
