/**
 * MultiAgent — 单次工具调用并行启动多个专用子 Agent
 *
 * 解决 LLM 逐个调用 Agent 导致串行等待的问题。
 * 类似 MultiScan 之于 Bash，MultiAgent 把所有 agent 放进一次工具调用，
 * 引擎用 Promise.all 同时运行它们。
 *
 * 用法示例（Phase 1 侦察+漏洞探测并行）：
 *   MultiAgent({
 *     agents: [
 *       { subagent_type: "recon",     description: "侦察 TARGET",     prompt: "..." },
 *       { subagent_type: "vuln-scan", description: "漏洞探测 TARGET", prompt: "..." },
 *     ]
 *   })
 */

import type { Tool, ToolContext, ToolDefinition, ToolResult } from '../core/types.js'
import { DEFAULT_ITERATIONS, runAgentTask } from './agent.js'
import type { RedTeamAgentType } from '../prompts/agentPrompts.js'

type AgentType = RedTeamAgentType | 'general-purpose' | 'explore' | 'plan' | 'code-reviewer'

interface AgentSpec {
  subagent_type?: string
  description: string
  prompt: string
  max_iterations?: number
}

export class MultiAgentTool implements Tool {
  name = 'MultiAgent'

  definition: ToolDefinition = {
    type: 'function',
    function: {
      name: 'MultiAgent',
      description: `单次工具调用同时启动多个 Agent，全部并行运行（Promise.all）。

这是解决渗透测试多阶段并行的正确方式。与逐个调用 Agent 相比：
- 逐个调用 Agent：每个 agent 串行等待前一个完成 ← 慢，浪费时间
- MultiAgent 一次调用：所有 agent 同时运行，互不等待 ← 快，正确

## 推荐使用场景

**Phase 1 侦察+漏洞探测（2并行，开局必用）**
MultiAgent([recon, vuln-scan])
  → recon 内部再分派: dns-recon / port-scan / web-probe / osint
  → vuln-scan 内部再分派: web-vuln / service-vuln / auth-attack

**Phase 3 漏洞利用+C2（3并行）**
MultiAgent([manual-exploit, tool-exploit, c2-deploy])

**Phase 4 靶机操作（2并行）**
MultiAgent([target-recon, privesc])

**Phase 5 内网横移（3并行）**
MultiAgent([tunnel, internal-recon, lateral])

## 每个 agent 的 prompt 必须完全自包含（包含 target、session_dir、前阶段上下文）`,
      parameters: {
        type: 'object',
        properties: {
          agents: {
            type: 'array',
            description: '要并行运行的 agent 列表',
            items: {
              type: 'object',
              properties: {
                subagent_type: {
                  type: 'string',
                  enum: [
                    // 一级 agent（直接派给主agent）
                    'recon', 'vuln-scan', 'weapon-match',
                    'manual-exploit', 'tool-exploit', 'c2-deploy',
                    'target-recon', 'privesc',
                    'tunnel', 'internal-recon', 'lateral',
                    'flag-hunter', 'report',
                    // 二级 agent（也可直接使用）
                    'dns-recon', 'port-scan', 'web-probe', 'osint',
                    'web-vuln', 'service-vuln', 'auth-attack',
                    // 通用
                    'general-purpose', 'explore', 'plan', 'code-reviewer',
                  ],
                  description: 'Agent 类型（协调者模式下禁止 general-purpose/explore/plan/code-reviewer）',
                },
                description: {
                  type: 'string',
                  description: 'Agent 标签，显示在 UI（如 "DNS侦察 example.com"）',
                },
                prompt: {
                  type: 'string',
                  description: '完整任务指令，必须包含 target、session_dir、具体任务、前阶段上下文',
                },
                max_iterations: {
                  type: 'number',
                  description: '最大执行轮数（可选，默认由 agent 类型决定）',
                },
              },
              required: ['description', 'prompt'],
            },
            minItems: 2,
          },
        },
        required: ['agents'],
      },
    },
  }

  async execute(input: Record<string, unknown>, context: ToolContext): Promise<ToolResult> {
    const specs = input.agents as AgentSpec[] | undefined
    if (!specs || specs.length === 0) {
      return { content: 'Error: agents 数组不能为空', isError: true }
    }
    if (specs.length === 1) {
      return { content: 'Warning: MultiAgent 只收到 1 个 agent，建议直接用 Agent 工具', isError: false }
    }

    for (let i = 0; i < specs.length; i++) {
      const spec = specs[i]
      if (!spec.description || !spec.description.trim()) {
        return { content: `Error: agents[${i}].description 不能为空`, isError: true }
      }
      if (!spec.prompt || !spec.prompt.trim()) {
        return { content: `Error: agents[${i}].prompt 不能为空`, isError: true }
      }
    }

    // Run all agents in parallel
    const results = await Promise.all(
      specs.map((spec) => {
        const agentType = (spec.subagent_type ?? 'general-purpose') as AgentType
        const defaultIter = (DEFAULT_ITERATIONS as Record<string, number>)[agentType] ?? 60
        const maxIterations = typeof spec.max_iterations === 'number'
          ? Math.min(spec.max_iterations, 200)
          : defaultIter

        return runAgentTask(
          spec.description,
          spec.prompt,
          agentType,
          maxIterations,
          context,
        )
      }),
    )

    // Combine results
    const lines: string[] = [`MultiAgent: ${specs.length} agents 并行完成\n`]
    let anyError = false

    for (let i = 0; i < specs.length; i++) {
      const spec = specs[i]
      const result = results[i]
      if (result.isError) anyError = true
      lines.push(`${'═'.repeat(60)}`)
      lines.push(`[${spec.subagent_type ?? 'general-purpose'}] ${spec.description}`)
      lines.push(result.content)
    }

    return { content: lines.join('\n'), isError: anyError }
  }
}
