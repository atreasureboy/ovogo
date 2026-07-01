/**
 * WeaponRadar — 武器库语义检索工具
 *
 * 通过 HTTP 调用 WeaponRadar API 服务（/project/poc_db/server.py），
 * 对 22W Nuclei PoC 数据库进行自然语言向量检索（BGE-M3 + pgvector）。
 *
 * API 地址通过环境变量 WEAPON_RADAR_URL 配置，默认 http://127.0.0.1:8765
 */

import type { Tool, ToolContext, ToolDefinition, ToolResult } from '../core/types.js'

function getApiBase(): string {
  return (process.env.WEAPON_RADAR_URL ?? 'http://127.0.0.1:8765').replace(/\/$/, '')
}

const TIMEOUT_MS = 180_000   // 3 分钟：首次请求需等模型加载

interface RadarResult {
  rank:              number
  id:                number
  module_name:       string
  attack_logic:      string
  opsec_risk?:       number
  cve_list?:         string[]
  required_options?: Record<string, string>
  auto_parameters?:  Record<string, string>
  score:             number
  score_pct:         number
  poc_code?:         string
}

interface RadarOutput {
  query:     string
  results:   RadarResult[]
  total:     number
  encode_ms: number
  search_ms: number
  error?:    string
}

// ── Client-side filtering ──────────────────────────────────────────────────

export interface FilterOpts {
  minScore?: number
  maxOpsec?: number
  cveFilter?: string[]
  excludeKeywords?: string[]
  topN?: number
}

export interface FilterStats {
  before: number
  after: number
  droppedMinScore: number
  droppedOpsec: number
  droppedCve: number
  droppedKeyword: number
  truncatedToTopN: number
}

export function applyFilters(results: RadarResult[], opts: FilterOpts): { results: RadarResult[]; stats: FilterStats } {
  const stats: FilterStats = {
    before: results.length,
    after: 0,
    droppedMinScore: 0,
    droppedOpsec: 0,
    droppedCve: 0,
    droppedKeyword: 0,
    truncatedToTopN: 0,
  }
  let filtered = results

  if (opts.minScore !== undefined && opts.minScore > 0) {
    const before = filtered.length
    filtered = filtered.filter((r) => r.score_pct >= opts.minScore!)
    stats.droppedMinScore = before - filtered.length
  }

  if (opts.maxOpsec !== undefined && opts.maxOpsec < 5) {
    const before = filtered.length
    filtered = filtered.filter((r) => r.opsec_risk === undefined || r.opsec_risk <= opts.maxOpsec!)
    stats.droppedOpsec = before - filtered.length
  }

  if (opts.cveFilter && opts.cveFilter.length > 0) {
    const wanted = new Set(opts.cveFilter.map((c) => c.toUpperCase()))
    const before = filtered.length
    filtered = filtered.filter((r) => (r.cve_list ?? []).some((c) => wanted.has(c.toUpperCase())))
    stats.droppedCve = before - filtered.length
  }

  if (opts.excludeKeywords && opts.excludeKeywords.length > 0) {
    const lower = opts.excludeKeywords.map((k) => k.toLowerCase())
    const before = filtered.length
    filtered = filtered.filter((r) => {
      const hay = `${r.module_name} ${r.attack_logic ?? ''}`.toLowerCase()
      return !lower.some((kw) => hay.includes(kw))
    })
    stats.droppedKeyword = before - filtered.length
  }

  // Sort by score desc before topN (defensive — API usually returns ranked, but enforce)
  filtered = [...filtered].sort((a, b) => b.score_pct - a.score_pct)

  if (opts.topN !== undefined && opts.topN > 0 && filtered.length > opts.topN) {
    stats.truncatedToTopN = filtered.length - opts.topN
    filtered = filtered.slice(0, opts.topN)
  }

  stats.after = filtered.length
  return { results: filtered, stats }
}

export function formatFilterSummary(stats: FilterStats, opts: FilterOpts): string {
  const parts: string[] = []
  if (opts.minScore !== undefined) parts.push(`min_score≥${opts.minScore}`)
  if (opts.maxOpsec !== undefined) parts.push(`opsec≤${opts.maxOpsec}`)
  if (opts.cveFilter?.length) parts.push(`cve∈{${opts.cveFilter.join(',')}}`)
  if (opts.excludeKeywords?.length) parts.push(`exclude={${opts.excludeKeywords.join(',')}}`)
  if (opts.topN !== undefined) parts.push(`topN=${opts.topN}`)
  const filtStr = parts.length > 0 ? ` [过滤: ${parts.join(' | ')}]` : ''
  return `${stats.before}→${stats.after} 条 (score-:${stats.droppedMinScore} opsec-:${stats.droppedOpsec} cve-:${stats.droppedCve} kw-:${stats.droppedKeyword} topN-:${stats.truncatedToTopN})${filtStr}`
}

function formatSummaryResults(output: RadarOutput, stats: FilterStats, opts: FilterOpts): string {
  const lines: string[] = [
    `武器库检索 — 查询: "${output.query}"`,
    `返回 ${output.total} 条 | 编码 ${output.encode_ms}ms | 检索 ${output.search_ms}ms`,
    `过滤后${formatFilterSummary(stats, opts)}`,
    '─'.repeat(72),
  ]
  for (const r of output.results) {
    const scoreBar = r.score_pct >= 80 ? '★★★' : r.score_pct >= 60 ? '★★☆' : '★☆☆'
    const cves = r.cve_list?.length ? ` [${r.cve_list.join(',')}]` : ''
    const risk = r.opsec_risk !== undefined ? ` opsec:${r.opsec_risk}/5` : ''
    lines.push(`#${r.rank} [${r.score_pct}%]${scoreBar}${risk}${cves} ${r.module_name}`)
  }
  if (output.results.length === 0) {
    lines.push('(过滤后无匹配结果)')
  }
  return lines.join('\n')
}

function formatSingleResult(output: RadarOutput, stats?: FilterStats, opts?: FilterOpts): string {
  const lines: string[] = [
    `武器库检索 — 查询: "${output.query}"`,
    `返回 ${output.total} 条 | 编码 ${output.encode_ms}ms | 检索 ${output.search_ms}ms`,
    ...(stats && opts ? [`过滤后${formatFilterSummary(stats, opts)}`] : []),
    '─'.repeat(72),
  ]

  for (const r of output.results) {
    const scoreBar = r.score_pct >= 80 ? '★★★' : r.score_pct >= 60 ? '★★☆' : '★☆☆'
    const riskStr  = r.opsec_risk !== undefined ? ` | 噪音风险:${r.opsec_risk}/5` : ''
    lines.push(`#${r.rank}  [${r.score_pct}%] ${scoreBar}  ${r.module_name}  (ID: ${r.id})${riskStr}`)

    if (r.cve_list && r.cve_list.length > 0) {
      lines.push(`    CVE: ${r.cve_list.join(', ')}`)
    }
    if (r.attack_logic) {
      lines.push(`    攻击逻辑: ${r.attack_logic}`)
    }
    if (r.auto_parameters && Object.keys(r.auto_parameters).length > 0) {
      lines.push(`    参数说明: ${JSON.stringify(r.auto_parameters)}`)
    }

    if (r.poc_code) {
      // ⚠️ poc_code 是漏洞原理参考，不是 nuclei 模板。
      // 从 attack_logic 中提取关键信息，给出 curl/Python 验证建议。
      lines.push(`    ▶ PoC 原理参考（需改写为手动 exploit）:`)
      lines.push(`      ${r.poc_code.slice(0, 300)}${r.poc_code.length > 300 ? '...' : ''}`)
      if (r.cve_list && r.cve_list.length > 0) {
        lines.push(`      快速验证: nuclei -u TARGET -id ${r.cve_list[0]} -silent`)
      }
      lines.push(`      利用步骤: 1) 从 poc_code 提取 endpoint+payload → 2) curl 验证 → 3) 利用`)
    }
    lines.push('')
  }

  if (output.results.length === 0 && stats) {
    lines.push(`(过滤后无匹配结果 — 原始 ${stats.before} 条全部被过滤掉)`)
  }

  return lines.join('\n').trimEnd()
}

function formatBatchResults(outputs: RadarOutput[], opts: FilterOpts, fmt: 'detailed' | 'summary'): string {
  return outputs.map((output, i) => {
    if (output.error) {
      return `[${i + 1}] 查询 "${output.query}" 失败: ${output.error}`
    }
    const { results: filtered, stats } = applyFilters(output.results ?? [], opts)
    const out = { ...output, results: filtered }
    if (filtered.length === 0) {
      return `[${i + 1}] 查询 "${output.query}"${formatFilterSummary(stats, opts)}: 无匹配结果`
    }
    return fmt === 'summary' ? formatSummaryResults(out, stats, opts) : formatSingleResult(out, stats, opts)
  }).join('\n\n' + '═'.repeat(72) + '\n\n')
}

async function fetchWithTimeout(url: string, body: unknown, signal?: AbortSignal): Promise<RadarOutput | RadarOutput[]> {
  const ac = new AbortController()
  const timer = setTimeout(() => ac.abort(), TIMEOUT_MS)

  // 如果外部取消也触发 abort
  signal?.addEventListener('abort', () => ac.abort(), { once: true })

  try {
    const resp = await fetch(url, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(body),
      signal:  ac.signal,
    })
    if (!resp.ok) {
      const text = await resp.text().catch(() => '')
      throw new Error(`HTTP ${resp.status}: ${text}`)
    }
    return await resp.json() as RadarOutput | RadarOutput[]
  } finally {
    clearTimeout(timer)
  }
}

export class WeaponRadarTool implements Tool {
  name = 'WeaponRadar'

  definition: ToolDefinition = {
    type: 'function',
    function: {
      name: 'WeaponRadar',
      description: `检索公司内部 22W Nuclei PoC 武器数据库，使用自然语言描述攻击意图，返回最匹配的漏洞武器。

使用 BGE-M3 向量语义搜索，可以用中文或英文描述：
- 攻击目标特征："Apache Log4j RCE"、"WordPress 插件漏洞"
- 攻击类型："SSRF via URL 参数"、"SQL 注入 登录绕过"
- 服务+版本："Shiro 反序列化"、"Tomcat 文件上传"
- 已发现的服务："目标跑了 Jenkins 2.3，找 RCE"

返回结果包含：攻击逻辑分析、完整可执行 PoC YAML、nuclei 执行命令（可直接复制运行）。

## 客户端过滤（命中即丢弃，不再返回）
- min_score: 最低相似度（0-100），低于此值的结果丢弃
- max_opsec: 最高噪音风险（0-5），超过此值的高噪音 PoC 丢弃（适合静默渗透）
- cve_filter: 只保留指定 CVE 列表（如 ["CVE-2021-44228","CVE-2017-9805"]）
- exclude_keywords: 排除名称/描述含这些关键字的结果（如 ["Windows","Microsoft"] 只看 Linux）
- top_n: 过滤后最多保留 N 条（按 score 降序）
- output_format: "detailed"（默认，含 PoC 代码） | "summary"（仅一行简介，适合大量候选快速浏览）

批量查询优化：如需同时检索多个目标/漏洞，使用 queries[] 参数，比多次调用快很多。`,
      parameters: {
        type: 'object',
        properties: {
          query: {
            type: 'string',
            description: '单个查询：自然语言攻击意图描述，支持中英文。例如："Apache Struts2 RCE"、"Shiro 反序列化认证绕过"',
          },
          queries: {
            type: 'array',
            items: { type: 'string' },
            description: '批量查询（推荐）：多个查询组成的数组。例如：["Apache Log4j RCE", "WordPress 文件上传", "Spring Boot Actuator"]',
          },
          top_k: {
            type: 'number',
            description: '每个查询返回结果数量，默认 3，最多 10。',
          },
          hide_code: {
            type: 'boolean',
            description: '设为 true 时不返回 PoC YAML 代码（默认 false，即默认返回完整可执行 PoC）。',
          },
          min_score: {
            type: 'number',
            description: '最低相似度阈值 0-100，过滤掉 score_pct 低于此值的结果',
          },
          max_opsec: {
            type: 'number',
            description: '最高噪音风险 0-5，过滤掉 opsec_risk 超过此值的高噪音 PoC（适合静默渗透）',
          },
          cve_filter: {
            type: 'array',
            items: { type: 'string' },
            description: '只保留指定 CVE 列表（如 ["CVE-2021-44228","CVE-2017-9805"]）',
          },
          exclude_keywords: {
            type: 'array',
            items: { type: 'string' },
            description: '排除名称/描述含这些关键字的结果（如 ["Windows","Microsoft"] 只看 Linux）',
          },
          top_n: {
            type: 'number',
            description: '过滤后最多保留 N 条（按 score 降序截断）',
          },
          output_format: {
            type: 'string',
            enum: ['detailed', 'summary'],
            description: '"detailed"=含 PoC 代码（默认），"summary"=每条一行简介（适合大量候选快速浏览）',
          },
        },
        required: [],
      },
    },
  }

  async execute(input: Record<string, unknown>, context: ToolContext): Promise<ToolResult> {
    const query    = input.query as string | undefined
    const queries  = input.queries as string[] | undefined
    const topK     = Math.min(Math.max(Number(input.top_k ?? 3), 1), 10)
    const hideCode = Boolean(input.hide_code ?? false)
    const base     = getApiBase()
    const fmt      = (input.output_format === 'summary' ? 'summary' : 'detailed') as 'detailed' | 'summary'
    const filterOpts: FilterOpts = {
      minScore: input.min_score !== undefined ? Number(input.min_score) : undefined,
      maxOpsec: input.max_opsec !== undefined ? Number(input.max_opsec) : undefined,
      cveFilter: Array.isArray(input.cve_filter) ? (input.cve_filter as string[]) : undefined,
      excludeKeywords: Array.isArray(input.exclude_keywords) ? (input.exclude_keywords as string[]) : undefined,
      topN: input.top_n !== undefined ? Number(input.top_n) : undefined,
    }

    try {
      // 批量模式
      if (queries && queries.length > 0) {
        const resp = await fetchWithTimeout(
          `${base}/batch`,
          {
            queries: queries.map(q => ({ query: q.trim(), top_k: topK })),
            no_code: hideCode,
          },
          context.signal,
        ) as unknown as { results: RadarOutput[] }

        return { content: formatBatchResults(resp.results, filterOpts, fmt), isError: false }
      }

      // 单查询模式
      if (!query?.trim()) {
        return { content: 'Error: 必须提供 query 或 queries 参数', isError: true }
      }

      const resp = await fetchWithTimeout(
        `${base}/query`,
        { query: query.trim(), top_k: topK, no_code: hideCode },
        context.signal,
      ) as RadarOutput

      if (resp.error) {
        return { content: `WeaponRadar 错误: ${resp.error}`, isError: true }
      }
      if (!resp.results || resp.results.length === 0) {
        return { content: `武器库中未找到匹配 "${query}" 的 PoC，尝试换用不同关键词。`, isError: false }
      }

      const { results: filtered, stats } = applyFilters(resp.results, filterOpts)
      if (filtered.length === 0) {
        return {
          content: `武器库中匹配 "${query}" 的 ${resp.results.length} 条全部被客户端过滤掉 — ${formatFilterSummary(stats, filterOpts)}`,
          isError: false,
        }
      }
      const out = { ...resp, results: filtered }
      return {
        content: fmt === 'summary' ? formatSummaryResults(out, stats, filterOpts) : formatSingleResult(out, stats, filterOpts),
        isError: false,
      }

    } catch (err: unknown) {
      const e = err as Error
      if (e.name === 'AbortError') {
        return { content: 'WeaponRadar: 已取消', isError: true }
      }
      if (e.message?.includes('fetch failed') || e.message?.includes('ECONNREFUSED')) {
        return {
          content: `WeaponRadar: 无法连接 API 服务 ${base}\n请确认 weapon-radar 服务正在运行：systemctl status weapon-radar`,
          isError: true,
        }
      }
      return { content: `WeaponRadar 请求失败: ${e.message}`, isError: true }
    }
  }
}
