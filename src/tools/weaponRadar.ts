/**
 * WeaponRadar — 武器库语义检索工具
 *
 * 调用 /data/poc_db/weapon_radar_query.py，对公司 22W Nuclei PoC 数据库
 * 进行自然语言向量检索（BGE-M3 + pgvector），返回最匹配的漏洞武器。
 *
 * 支持批量查询：queries[] 参数可传入多个查询，模型只加载一次（避免 2×60s 开销）。
 *
 * 注意：首次调用需加载 BGE-M3 模型，约 30-60 秒；后续调用因 OS 缓存
 * 会快很多。超时设为 180s 以覆盖最慢情况。
 */

import { exec } from 'child_process'
import type { Tool, ToolContext, ToolDefinition, ToolResult } from '../core/types.js'

const RADAR_SCRIPT = '/data/poc_db/weapon_radar_query.py'
const TIMEOUT_MS   = 180_000   // 3 分钟：首次加载 BGE-M3 可能需要 60s+

interface RadarResult {
  rank:             number
  id:               number
  module_name:      string
  attack_logic:     string
  opsec_risk?:      number
  cve_list?:        string[]
  required_options?: Record<string, string>
  auto_parameters?: Record<string, string>
  score:            number
  score_pct:        number
  poc_code?:        string
}

interface RadarOutput {
  query:     string
  results:   RadarResult[]
  total:     number
  encode_ms: number
  search_ms: number
  error?:    string
}

interface BatchOutput {
  batch: (RadarOutput & { error?: string })[]
}

function formatSingleResult(output: RadarOutput): string {
  const lines: string[] = [
    `武器库检索 — 查询: "${output.query}"`,
    `返回 ${output.total} 条 | 编码 ${output.encode_ms}ms | 检索 ${output.search_ms}ms`,
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

    // PoC 代码 + 可执行命令
    if (r.poc_code) {
      // 写到临时文件的建议路径
      const safeName = r.module_name.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 60)
      const tmpPath = `/tmp/poc_${safeName}.yaml`
      lines.push(`    ▶ 执行方式:`)
      lines.push(`      cat > ${tmpPath} << 'NUCLEI_EOF'`)
      lines.push(r.poc_code)
      lines.push(`NUCLEI_EOF`)
      lines.push(`      /root/go/bin/nuclei -u TARGET -t ${tmpPath} -silent`)
      if (r.cve_list && r.cve_list.length > 0) {
        lines.push(`      # 或用 -id: /root/go/bin/nuclei -u TARGET -id ${r.cve_list[0]}`)
      }
    }
    lines.push('')
  }

  return lines.join('\n').trimEnd()
}

function formatBatchResults(batch: BatchOutput): string {
  return batch.batch.map((output, i) => {
    if (output.error) {
      return `[${i + 1}] 查询 "${output.query}" 失败: ${output.error}`
    }
    if (!output.results || output.results.length === 0) {
      return `[${i + 1}] 查询 "${output.query}": 未找到匹配 PoC`
    }
    return formatSingleResult(output)
  }).join('\n\n' + '═'.repeat(72) + '\n\n')
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

⚠️ 首次调用需加载语义模型（约 30-60 秒），请耐心等待。

批量查询优化：如需同时检索多个目标/漏洞，使用 queries[] 参数，模型只加载一次，比多次调用快 3-5 倍。`,
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
            description: '批量查询（推荐）：多个查询组成的数组，模型只加载一次。例如：["Apache Log4j RCE", "WordPress 文件上传", "Spring Boot Actuator"]',
          },
          top_k: {
            type: 'number',
            description: '每个查询返回结果数量，默认 3，最多 10。发现目标服务时建议用 5，针对性查找用 3。',
          },
          hide_code: {
            type: 'boolean',
            description: '设为 true 时不返回 PoC YAML 代码（默认 false，即默认返回完整可执行 PoC）。',
          },
        },
        required: [],
      },
    },
  }

  async execute(input: Record<string, unknown>, context: ToolContext): Promise<ToolResult> {
    const query     = input.query as string | undefined
    const queries   = input.queries as string[] | undefined
    const topK      = Math.min(Math.max(Number(input.top_k ?? 3), 1), 10)
    const hideCode  = Boolean(input.hide_code ?? false)

    // 批量模式：queries[] 优先
    if (queries && queries.length > 0) {
      const batchItems = queries.map(q => ({ query: q.trim(), top_k: topK }))
      const batchJson = JSON.stringify(batchItems).replace(/'/g, "'\\''")
      const cmd = [
        `python3 ${RADAR_SCRIPT}`,
        `--batch-json '${batchJson}'`,
        hideCode ? '--no-code' : '',
      ].filter(Boolean).join(' ')

      return this._runCmd(cmd, context, `批量(${queries.length}个查询)`)
    }

    // 单查询模式
    if (!query || !query.trim()) {
      return { content: 'Error: 必须提供 query 或 queries 参数', isError: true }
    }

    const escapedQuery = query.replace(/'/g, "'\\''")
    const cmd = [
      `python3 ${RADAR_SCRIPT}`,
      `-q '${escapedQuery}'`,
      `-n ${topK}`,
      hideCode ? '--no-code' : '',
    ].filter(Boolean).join(' ')

    return this._runCmd(cmd, context, query)
  }

  private _runCmd(cmd: string, context: ToolContext, label: string): Promise<ToolResult> {
    return new Promise<ToolResult>((resolve) => {
      let settled = false

      const child = exec(cmd, {
        timeout: TIMEOUT_MS,
        maxBuffer: 10 * 1024 * 1024,   // 10MB：PoC 代码可能很长
        cwd: context.cwd,
        env: { ...process.env },
      }, (err, stdout, stderr) => {
        if (context.signal) context.signal.removeEventListener('abort', onAbort)
        if (settled) return
        settled = true

        if (context.signal?.aborted) {
          resolve({ content: 'WeaponRadar: 已取消', isError: true })
          return
        }

        if (err) {
          const nodeErr = err as NodeJS.ErrnoException & { killed?: boolean }
          if (nodeErr.killed) {
            resolve({ content: `WeaponRadar: 超时（>${TIMEOUT_MS / 1000}s），模型加载过慢或数据库无响应`, isError: true })
            return
          }
          const raw = stdout.trim() || stderr.trim()
          try {
            const parsed = JSON.parse(raw) as RadarOutput
            if (parsed.error) {
              resolve({ content: `WeaponRadar 错误: ${parsed.error}`, isError: true })
              return
            }
          } catch { /* 非 JSON，直接输出 */ }
          resolve({
            content: `WeaponRadar 执行失败 (exit ${(err as NodeJS.ErrnoException).code ?? 1}):\n${raw}`,
            isError: true,
          })
          return
        }

        // 成功 — 解析 JSON 并格式化
        const raw = stdout.trim()
        let parsed: RadarOutput | BatchOutput
        try {
          parsed = JSON.parse(raw) as RadarOutput | BatchOutput
        } catch {
          resolve({ content: raw || '(无输出)', isError: false })
          return
        }

        // 批量模式响应
        if ('batch' in parsed) {
          resolve({ content: formatBatchResults(parsed as BatchOutput), isError: false })
          return
        }

        const single = parsed as RadarOutput
        if (single.error) {
          resolve({ content: `WeaponRadar 错误: ${single.error}`, isError: true })
          return
        }

        if (!single.results || single.results.length === 0) {
          resolve({ content: `武器库中未找到匹配 "${label}" 的 PoC，尝试换用不同关键词。`, isError: false })
          return
        }

        resolve({ content: formatSingleResult(single), isError: false })
      })

      const onAbort = () => {
        if (settled) return
        settled = true
        const pid = child.pid
        if (pid !== undefined) {
          try { process.kill(-pid, 'SIGTERM') } catch {
            try { child.kill('SIGTERM') } catch { /* ignore */ }
          }
        }
        resolve({ content: 'WeaponRadar: 已取消', isError: true })
      }

      if (context.signal) {
        if (context.signal.aborted) {
          onAbort()
        } else {
          context.signal.addEventListener('abort', onAbort, { once: true })
        }
      }
    })
  }
}
