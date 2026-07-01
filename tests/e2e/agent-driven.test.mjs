/**
 * Agent-driven kill chain test — REAL LLM (DeepSeek) drives the real agent
 * (ExecutionEngine + AgentTool sub-agents) against the local Flask target.
 *
 * This proves the FULL think-act-observe loop works end-to-end, not just
 * that individual tools can be called in sequence.
 *
 * Opt-in: requires DEEPSEEK_API_KEY (or OPENAI_API_KEY for OpenAI-compatible)
 *         env var. Skipped if missing.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { startTarget } from './spawn-target.mjs'
import { ExecutionEngine } from '../../dist/src/core/engine.js'
import { Renderer } from '../../dist/src/ui/renderer.js'
import { AgentTool, registerAgentFactory } from '../../dist/src/tools/agent.js'
import { DispatchManager } from '../../dist/src/core/dispatch.js'
import { EventLog } from '../../dist/src/core/eventLog.js'
import { mkdirSync } from 'fs'
import { join } from 'path'
import { tmpdir } from 'os'

const apiKey = process.env.DEEPSEEK_API_KEY || process.env.OPENAI_API_KEY
const baseURL = process.env.DEEPSEEK_API_KEY
  ? (process.env.DEEPSEEK_BASE_URL || 'https://api.deepseek.com')
  : process.env.OPENAI_BASE_URL
const model = process.env.DEEPSEEK_API_KEY
  ? (process.env.DEEPSEEK_MODEL || 'deepseek-chat')
  : (process.env.OVOGO_MODEL || 'gpt-4o-mini')

if (!apiKey) {
  test('agent-driven kill chain (SKIPPED — no DEEPSEEK_API_KEY)', { skip: true }, () => {})
} else {
  test('agent-driven kill chain: real LLM attacks real target', async (t) => {
    const { baseUrl, flag, stop } = await startTarget()
    t.after(() => stop())

    // ── Set up engine + sub-agent factory ─────────────────────────────────
    const sessionDir = join(tmpdir(), `ovogo_e2e_${Date.now()}`)
    mkdirSync(sessionDir, { recursive: true })
    const eventLog = new EventLog(sessionDir)
    const dispatchManager = new DispatchManager()

    const config = {
      apiKey,
      baseURL,
      model,
      cwd: process.cwd(),
      permissionMode: 'auto',
      maxIterations: 30,
      sessionDir,
      coordinatorMode: false,        // sub-agent must have full tool access
      eventLog,
      dispatchManager,
      systemPrompt: `You are a red-team pentest sub-agent. Use Bash + PayloadGenerator + TechniqueGenerator to attack the target and extract the flag.

Rules:
- Use curl via Bash to probe the target.
- Use PayloadGenerator(category='sqli', database='sqlite', context='union') to get a real SQLi payload.
- Once you find SQLi, run a UNION SELECT payload to extract the flag column from the users table.
- Print the flag clearly in your final output so the caller can grep it.

Do NOT generate fake flags. Do NOT claim success without showing the actual flag string in your output.`,
    }

    const renderer = new Renderer()
    const engine = new ExecutionEngine(config, renderer)

    registerAgentFactory(
      (childConfig, childRenderer) => new ExecutionEngine(childConfig, childRenderer),
      config,
      renderer,
    )

    // ── Direct attack: call Bash via engine.runTurn (NO coordinator mode) ─
    // The engine prompt is "you have full tool access, attack this URL"
    const task = `目标: ${baseUrl}
任务: 1) curl 探活; 2) 用 PayloadGenerator 生成 SQLite SQLi payload; 3) UNION SELECT 提取 users 表 flag 列; 4) 把 flag 字符串打印在最终输出里。
预期 flag 格式: ${flag}
务必在最后一行清晰打印 "FLAG: <actual_flag_value>"。`

    console.log(`\n[LLM] ${model} @ ${baseURL}`)
    console.log(`[LLM] target: ${baseUrl}`)
    console.log(`[LLM] task: ${task.slice(0, 100)}...\n`)

    const { result, newHistory } = await engine.runTurn(task, [])

    console.log(`\n[LLM] stop reason: ${result.reason}, output length: ${result.output.length}`)
    console.log(`[LLM] last 500 chars of output:\n${result.output.slice(-500)}\n`)

    // ── Assertions ────────────────────────────────────────────────────────
    assert.equal(result.reason, 'stop_sequence', `engine should finish naturally, got ${result.reason}`)
    assert.ok(result.output.length > 50, 'engine should produce real output')

    // The flag MUST appear in the conversation somewhere — not just in tool results,
    // because the agent needs to echo it in its final text response.
    const allContent = newHistory
      .map((m) => (typeof m.content === 'string' ? m.content : '') + (m.tool_calls ? JSON.stringify(m.tool_calls) : ''))
      .join('\n')
    assert.ok(
      allContent.includes(flag),
      `Flag "${flag}" should appear somewhere in the LLM conversation. Final output:\n${result.output}\n\nFull history tool/text:\n${allContent.slice(-2000)}`,
    )
  })
}