/**
 * Think-Act-Observe Engine — with streaming output
 *
 * Key improvements over naïve implementation:
 *
 * 1. Parallel tool execution
 *    Read-only tools (Read/Glob/Grep/WebFetch/WebSearch) are batched and run
 *    with Promise.all.  Write/exec tools run serially.
 *
 * 2. AbortController per turn
 *    engine.abort() cancels the current turn at any point — including inside
 *    long-running Bash commands and network fetches.
 *
 * 3. Plan mode — only read-only tools are exposed/executed.
 *
 * 4. Hook callbacks around every tool call.
 *
 * 5. Critic loop — every CRITIC_INTERVAL iterations a lightweight LLM call
 *    reviews recent context for common failure modes and injects corrections
 *    as a user message before the next main LLM call.
 */

import OpenAI from 'openai'
import type {
  EngineConfig,
  OpenAIMessage,
  Tool,
  ToolContext,
  ToolResult,
  TurnResult,
} from './types.js'
import { createTools, findTool, getToolDefinitions } from '../tools/index.js'
import { getPlanModePrefix } from '../prompts/system.js'
import type { Renderer } from '../ui/renderer.js'
import { maybeCompact, calculateContextState, MODEL_MAX_CONTEXT_TOKENS } from './compact.js'
import { PriorityQueue, ToolTask } from './priorityQueue.js'
import { ProgressTracker } from './progressTracker.js'
import { ToolCache } from './toolCache.js'

const MAX_TOOL_RESULT_LENGTH = 20_000

// ── Critic configuration ─────────────────────────────────────────────────────
/** Run critic every N iterations (only when there are enough messages to review) */
const CRITIC_INTERVAL = 5
/** Don't bother before this many iterations */
const CRITIC_MIN_ITERATIONS = 4
/** How many recent messages to feed the critic */
const CRITIC_CONTEXT_MESSAGES = 24
/** Max tokens the critic can produce */
const CRITIC_MAX_TOKENS = 400

const CRITIC_SYSTEM_PROMPT = `你是一个渗透测试会话的批判性监督 agent。
你只阅读操作历史，不执行操作。你的职责是发现以下常见失误并给出简短纠正：

1. **PoC 未执行** — WeaponRadar 返回了 poc_code，但随后没有把 PoC 写入文件并用 nuclei 执行
2. **工具降级** — 遇到 "command not found" / 模板找不到 / 工具缺失，直接改用手动 curl/wget 测试，而非先安装工具
3. **重要发现被遗忘** — 之前扫描/发现的端口、服务版本、凭证、漏洞没有被后续步骤跟进利用
4. **任务偏离** — 偏离了最初的目标，陷入无关或低价值操作
5. **重复劳动** — 正在重复已经完成过的操作（相同命令、相同扫描）
6. **交互式进程阻塞** — 使用 msfconsole / nc shell / python REPL 等交互式进程但未用 TmuxSession，导致 Bash 调用超时
7. **防御者思维** — 输出了"建议的修复措施"/"建议修复"/"修复建议"/"应该修复"等内容，或建议目标方打补丁/加固配置，这是红队工具，只攻不守
8. **提前终止扫描** — 后台扫描（nuclei/nmap/hydra）仍在 ps aux 中运行，却宣称"扫描完成"或进行最终总结，应继续等待并读取扫描结果
9. **满足于信息泄露** — 发现目录列表/配置文件等低风险信息后就停止推进，未尝试利用这些信息进一步拿 shell（如从配置文件提取凭证、寻找可写路径、上传 webshell）
10. **poc_code 当 nuclei 模板** — 把 WeaponRadar 返回的 poc_code 写成 .yaml 文件然后 nuclei -t 执行，这几乎必然失败（格式不兼容）；正确做法是从 poc_code 提取 endpoint+payload，改写为 curl/python 手动测试
11. **绕过 MultiAgent 直接扫描** — 主 agent 用 Bash / MultiScan 直接运行 nmap / nuclei / hydra / httpx 等扫描工具，而不是调用 MultiAgent 分发给专用子 agent；主 agent 是协调者，扫描应由子 agent（dns-recon / port-scan / web-vuln 等）执行
12. **发现漏洞不利用** — 确认漏洞存在（RCE/SQLi/文件上传）后只是 FindingWrite 就停止，没有继续利用执行命令、上传 webshell、读取 flag；靶场任务要求拿到 flag，不是写报告
13. **没有找 flag** — 已经拿到命令执行权限（RCE/shell/webshell），但没有执行 find / -name flag* 或 cat /flag 等命令去寻找 flag 内容
14. **主动杀掉后台扫描** — 执行了 killall nuclei / killall nmap / kill -9 <pid> 等命令强制终止了正在运行的后台扫描进程（nuclei/nmap/hydra/ffuf/masscan），随后重新启动扫描或继续任务；应当让原有扫描进程跑完并读取其结果，而不是杀掉重来；这一行为等同于自毁进度
15. **主agent亲自执行** — 主agent直接调用Bash/MultiScan/ShellSession/TmuxSession/Write/Edit等执行类工具，而不是通过Agent/MultiAgent委派子agent；主agent是协调者，必须委派子agent执行所有具体操作

输出规则：
- 发现问题：用 "⚠️ [问题] {描述}" + "↳ [纠正] {具体应执行什么}" 格式，最多 3 条
- 没有问题：只输出 "OK"
- 不解释你的角色，不废话，直接结论`

function formatMessagesForCritic(messages: OpenAIMessage[]): string {
  return messages
    .map((m) => {
      if (m.role === 'assistant') {
        const toolCalls = (m as { tool_calls?: Array<{ function: { name: string; arguments: string } }> }).tool_calls
        if (toolCalls && toolCalls.length > 0) {
          const calls = toolCalls
            .map((tc) => {
              let args: Record<string, unknown>
              try { args = JSON.parse(tc.function.arguments) } catch { args = {} }
              // Truncate large fields (e.g. poc_code in WeaponRadar results)
              const truncated = Object.fromEntries(
                Object.entries(args).map(([k, v]) => [
                  k,
                  typeof v === 'string' && v.length > 300 ? v.slice(0, 300) + '…' : v,
                ]),
              )
              return `  [TOOL_CALL] ${tc.function.name}(${JSON.stringify(truncated)})`
            })
            .join('\n')
          const text = typeof m.content === 'string' && m.content ? `  ${m.content}\n` : ''
          return `[ASSISTANT]\n${text}${calls}`
        }
        return `[ASSISTANT] ${m.content ?? ''}`
      }
      if (m.role === 'tool') {
        const content = typeof m.content === 'string' ? m.content.slice(0, 800) : ''
        const name = (m as { name?: string }).name ?? 'tool'
        return `[TOOL_RESULT:${name}] ${content}${content.length >= 800 ? '…' : ''}`
      }
      if (m.role === 'user') {
        const content = typeof m.content === 'string' ? m.content.slice(0, 400) : ''
        return `[USER] ${content}`
      }
      return ''
    })
    .filter(Boolean)
    .join('\n')
}

function truncateToolResult(result: string): string {
  if (result.length <= MAX_TOOL_RESULT_LENGTH) return result
  const half = MAX_TOOL_RESULT_LENGTH / 2
  return (
    result.slice(0, half) +
    `\n\n[... ${result.length - MAX_TOOL_RESULT_LENGTH} chars truncated ...]\n\n` +
    result.slice(result.length - half)
  )
}

// Accumulated tool call during streaming
interface StreamingToolCall {
  index: number
  id: string
  name: string
  arguments: string
}

// Parsed tool call ready for execution
interface ParsedToolCall {
  tc: StreamingToolCall
  input: Record<string, unknown>
}

// Tool batch for parallel vs serial scheduling
interface ToolBatch {
  safe: boolean
  calls: ParsedToolCall[]
}

/** Plan mode — tools allowed in read-only analysis */
const PLAN_MODE_TOOLS = new Set(['Read', 'Glob', 'Grep', 'WebFetch', 'WebSearch'])

/**
 * Coordinator mode — tools the main agent is allowed to use directly.
 * Everything else must be delegated to sub-agents via Agent/MultiAgent.
 *
 * Rationale: the main agent should be an orchestrator, not an executor.
 * Scanning, exploitation, and post-exploitation are sub-agent work.
 * The main agent reads results, makes decisions, and dispatches tasks.
 */
const COORDINATOR_ALLOWED_TOOLS = new Set([
  // Delegation (core orchestrator tools)
  'Agent', 'MultiAgent',
  // Intelligence / lookup (fast, no side effects)
  'WeaponRadar', 'WebSearch', 'WebFetch',
  // Reading sub-agent outputs and documents
  'Read', 'Glob', 'Grep', 'DocRead',
  // Progress tracking
  'FindingWrite', 'FindingList', 'TodoWrite',
  // C2 coordination (get_ip, list_sessions, list_listeners — read-only actions)
  'C2',
])

/**
 * In coordinator mode, these agent types should be launched in parallel via MultiAgent
 * unless there is an explicit serial dependency reason.
 */
const PARALLEL_FIRST_AGENT_TYPES = new Set([
  'recon', 'vuln-scan',
  'manual-exploit', 'tool-exploit', 'c2-deploy',
  'target-recon', 'privesc',
  'tunnel', 'internal-recon', 'lateral',
])

/** Coordinator must not delegate core work to generic helper agents. */
const FORBIDDEN_COORDINATOR_AGENT_TYPES = new Set([
  'general-purpose', 'explore', 'plan', 'code-reviewer',
])

/**
 * Concurrency-safe tools: run in parallel within a single LLM response.
 *
 * Rule: if the LLM emits multiple tool calls in one response, it intends them
 * to be independent — execute them all concurrently (Promise.all).
 *
 * Bash is included: the 64-core server has no issue with 50 concurrent shells.
 * Dependent commands should be chained inside a single Bash call (&&/;), not
 * split across separate Bash calls.
 *
 * Serial exceptions (own batch): Write, Edit, FindingWrite — these mutate shared
 * state and ordering may matter across calls.
 */
const CONCURRENCY_SAFE_TOOLS = new Set([
  'Read', 'Glob', 'Grep', 'WebFetch', 'WebSearch',
  'WeaponRadar', 'FindingList', 'MultiScan',
  'Bash',        // parallel — dependent ops should be chained with && in one call
  'Agent',       // parallel — multiple sub-agents run simultaneously via Promise.all
  'MultiAgent',  // parallel — internally uses Promise.all; safe to batch with others
  'C2',          // parallel — deploy_listener / get_ip / list_sessions are safe
  'ShellSession', // parallel — listen / list / exec on different sessions
  'TmuxSession',  // parallel — new / list / capture on different sessions
])

/**
 * Tools whose results must never be cached.
 * - State-mutating tools: always re-execute
 * - Read/Glob/Grep: in a live pen-test environment files change after every Bash
 *   write — a 5-minute stale read would silently return old content and confuse
 *   the agent. Cache only truly static, expensive lookups (Web fetch, WeaponRadar).
 */
const NO_CACHE_TOOLS = new Set([
  'Bash', 'ShellSession', 'TmuxSession', 'C2',
  'Write', 'Edit', 'FileEdit', 'FindingWrite',
  'Read', 'Glob', 'Grep',   // filesystem changes mid-session — never stale-serve
])

/**
 * Partition tool calls into batches for scheduling:
 * - All tools in CONCURRENCY_SAFE_TOOLS → merged into one parallel batch (Promise.all)
 * - Write / Edit / FindingWrite and other stateful tools → own serial batch
 */
function partitionToolCalls(calls: ParsedToolCall[]): ToolBatch[] {
  const batches: ToolBatch[] = []

  for (const call of calls) {
    const safe = CONCURRENCY_SAFE_TOOLS.has(call.tc.name)
    const last = batches[batches.length - 1]

    if (last && last.safe && safe) {
      last.calls.push(call)   // extend existing parallel batch
    } else {
      batches.push({ safe, calls: [call] })  // new batch
    }
  }

  return batches
}

export class ExecutionEngine {
  private client: OpenAI
  private tools: Tool[]
  private config: EngineConfig
  private renderer: Renderer
  /** Abort controller for the current turn — null when idle */
  private currentTurnAbortController: AbortController | null = null
  /** Soft-interrupt flag: pause after current tool finishes, preserve history */
  private softAbortRequested = false
  /** Priority queue for tool execution */
  private priorityQueue: PriorityQueue
  /** Progress tracker for long-running tools */
  private progressTracker: ProgressTracker
  /** Cache for tool execution results */
  private toolCache: ToolCache

  constructor(config: EngineConfig, renderer: Renderer) {
    this.config = config
    this.renderer = renderer
    this.client = new OpenAI({
      apiKey: config.apiKey,
      baseURL: config.baseURL,
    })
    this.tools = createTools(config.extraTools ?? [])
    this.priorityQueue = config.priorityQueue || new PriorityQueue()
    this.progressTracker = config.progressTracker || new ProgressTracker()
    this.toolCache = config.toolCache || new ToolCache()
  }

  /**
   * Hard cancel — immediately aborts in-flight API calls and tool executions.
   * Propagates via AbortSignal into Bash (kills process group) and WebFetch.
   */
  abort(): void {
    this.currentTurnAbortController?.abort('user_cancelled')
  }

  /**
   * Soft interrupt — sets a flag the main loop checks at the START of each
   * iteration (after current tool finishes).  Causes runTurn() to return
   * with reason='interrupted' while preserving the full conversation history,
   * allowing the caller to inject a user message and resume.
   */
  softAbort(): void {
    this.softAbortRequested = true
  }

  /**
   * Run a lightweight critic check over recent conversation history.
   * Returns a correction string to inject, or null if everything looks fine.
   * Errors are swallowed — critic failures must never break the main loop.
   */
  private async runCriticCheck(messages: OpenAIMessage[]): Promise<string | null> {
    const recent = messages.slice(-CRITIC_CONTEXT_MESSAGES)
    if (recent.length < 4) return null

    try {
      const response = await this.client.chat.completions.create({
        model: this.config.model,
        messages: [
          { role: 'system', content: CRITIC_SYSTEM_PROMPT },
          {
            role: 'user',
            content: `以下是最近的操作历史，请检查是否存在失误：\n\n${formatMessagesForCritic(recent)}`,
          },
        ],
        temperature: 0,
        max_tokens: CRITIC_MAX_TOKENS,
      })

      const output = response.choices[0]?.message?.content?.trim() ?? ''
      if (!output || /^ok$/i.test(output)) return null
      return output
    } catch {
      return null
    }
  }

  /**
   * Execute a single user turn with streaming output.
   * Full Think → Act → Observe loop.
   */
  async runTurn(
    userMessage: string,
    history: OpenAIMessage[],
  ): Promise<{ result: TurnResult; newHistory: OpenAIMessage[] }> {
    const planMode = this.config.planMode ?? false

    // Build system prompt: optional plan-mode prefix + pre-assembled prompt
    const baseSystemPrompt = this.config.systemPrompt ?? ''
    const systemPrompt = planMode
      ? getPlanModePrefix() + baseSystemPrompt
      : baseSystemPrompt

    // Per-turn AbortController — cancelled by engine.abort() or SIGINT
    const turnAbortController = new AbortController()
    this.currentTurnAbortController = turnAbortController

    const toolContext: ToolContext = {
      cwd: this.config.cwd,
      permissionMode: this.config.permissionMode,
      signal: turnAbortController.signal,
      // Forward API config so vision/doc tools can make their own LLM calls
      apiConfig: {
        apiKey: this.config.apiKey,
        baseURL: this.config.baseURL,
        model: this.config.model,
      },
    }

    const messages: OpenAIMessage[] = [
      ...history,
      { role: 'user', content: userMessage },
    ]

    // In plan mode, only expose read-only tools
    // In coordinator mode, only expose orchestrator tools
    const allToolDefs = getToolDefinitions(this.tools)
    const coordinatorMode = (this.config.coordinatorMode ?? false) && !!this.config.sessionDir
    let toolDefs = allToolDefs
    if (planMode) {
      toolDefs = allToolDefs.filter((t) => PLAN_MODE_TOOLS.has(t.function.name))
    } else if (coordinatorMode) {
      toolDefs = allToolDefs.filter((t) => COORDINATOR_ALLOWED_TOOLS.has(t.function.name))
    }

    let iterations = 0
    let finalOutput = ''

    try {
      while (iterations < this.config.maxIterations) {
        // Check for cancellation at the top of each loop
        if (turnAbortController.signal.aborted) {
          return {
            result: { stopped: true, reason: 'error', output: finalOutput },
            newHistory: messages,
          }
        }

        iterations++

        // ── Soft-interrupt check — pause after current tool, preserve history ─
        if (this.softAbortRequested) {
          this.softAbortRequested = false
          return {
            result: { stopped: true, reason: 'interrupted', output: finalOutput },
            newHistory: messages,
          }
        }

        // ── Context stats + auto-compact ────────────────────────
        // Use percentage-based thresholds (ref: calculateTokenWarningState in
        // reference implementation).  Mirrors 70% warn / 85% compact pattern.
        const maxCtxTokens = this.config.maxContextTokens ?? MODEL_MAX_CONTEXT_TOKENS
        const ctxState = calculateContextState(messages, maxCtxTokens)

        // Show context stats every 5 iterations (main agent only, not sub-agents)
        if (this.config.sessionDir && iterations % 5 === 0) {
          this.renderer.contextStats(ctxState.currentTokens, ctxState.maxTokens, ctxState.pct)
        }

        if (ctxState.shouldCompact) {
          this.renderer.compactStart(ctxState.currentTokens)
          const compactResult = await maybeCompact(this.client, this.config.model, messages)
          if (compactResult.compacted) {
            messages.length = 0
            messages.push(...compactResult.messages)
            this.renderer.compactDone(compactResult.originalTokens, compactResult.summaryTokens)
          }
        } else if (ctxState.shouldWarn) {
          this.renderer.contextWarning(ctxState.currentTokens, ctxState.maxTokens, ctxState.pct)
        }

        // ── Critic injection — every CRITIC_INTERVAL iterations ──
        // Only for the main agent (not sub-agents) to avoid recursive critic calls.
        // Sub-agents have shorter maxIterations and no sessionDir typically.
        if (
          iterations >= CRITIC_MIN_ITERATIONS &&
          iterations % CRITIC_INTERVAL === 0 &&
          !planMode &&
          this.config.sessionDir  // only main agent has sessionDir
        ) {
          const criticism = await this.runCriticCheck(messages)
          if (criticism) {
            this.renderer.warn(`[批判检查] ${criticism.split('\n')[0]}`)
            messages.push({
              role: 'user',
              content: `[🔍 自动纠错检查]\n${criticism}\n\n请根据以上纠错提示立即调整行动。`,
            })
          }
        }

        // ── Streaming API call ───────────────────────────────────
        this.renderer.startSpinner()

        let stream: AsyncIterable<OpenAI.Chat.ChatCompletionChunk>
        try {
          stream = await this.client.chat.completions.create(
            {
              model: this.config.model,
              messages: [
                { role: 'system', content: systemPrompt },
                ...(messages as OpenAI.Chat.ChatCompletionMessageParam[]),
              ],
              tools: toolDefs as OpenAI.Chat.ChatCompletionTool[],
              tool_choice: 'auto',
              temperature: 0,
              max_tokens: 8192,
              stream: true,
            },
            // Pass abort signal to the HTTP request
            { signal: turnAbortController.signal },
          )
        } catch (err: unknown) {
          this.renderer.stopSpinner()
          const error = err as Error
          if (error.name === 'AbortError' || turnAbortController.signal.aborted) {
            return {
              result: { stopped: true, reason: 'error', output: finalOutput },
              newHistory: messages,
            }
          }
          this.renderer.error(`API error: ${error.message}`)
          return {
            result: { stopped: true, reason: 'error', output: error.message },
            newHistory: messages,
          }
        }

        // ── Consume stream ───────────────────────────────────────
        let assistantText = ''
        let finishReason: string | null = null
        const toolCallsMap = new Map<number, StreamingToolCall>()
        let firstToken = true

        try {
          for await (const chunk of stream) {
            if (turnAbortController.signal.aborted) break

            const delta = chunk.choices[0]?.delta
            if (!delta) continue

            if (delta.content) {
              if (firstToken) {
                this.renderer.stopSpinner()
                this.renderer.beginAssistantText()
                firstToken = false
              }
              this.renderer.streamToken(delta.content)
              assistantText += delta.content
            }

            if (delta.tool_calls) {
              for (const tc of delta.tool_calls) {
                const idx = tc.index
                if (!toolCallsMap.has(idx)) {
                  toolCallsMap.set(idx, { index: idx, id: '', name: '', arguments: '' })
                }
                const acc = toolCallsMap.get(idx)!
                if (tc.id) acc.id = tc.id
                if (tc.function?.name) acc.name += tc.function.name
                if (tc.function?.arguments) acc.arguments += tc.function.arguments
              }
            }

            if (chunk.choices[0]?.finish_reason) {
              finishReason = chunk.choices[0].finish_reason
            }
          }
        } catch (err: unknown) {
          this.renderer.stopSpinner()
          const error = err as Error
          if (error.name === 'AbortError' || turnAbortController.signal.aborted) {
            return {
              result: { stopped: true, reason: 'error', output: finalOutput },
              newHistory: messages,
            }
          }
          this.renderer.error(`Stream error: ${error.message}`)
          return {
            result: { stopped: true, reason: 'error', output: error.message },
            newHistory: messages,
          }
        }

        this.renderer.stopSpinner()

        if (assistantText) {
          this.renderer.endAssistantText()
          finalOutput = assistantText
        }

        const rawToolCalls = Array.from(toolCallsMap.values()).sort((a, b) => a.index - b.index)

        const assistantMsg: OpenAIMessage = {
          role: 'assistant',
          content: assistantText || null,
          tool_calls: rawToolCalls.length > 0
            ? rawToolCalls.map((tc) => ({
                id: tc.id,
                type: 'function' as const,
                function: { name: tc.name, arguments: tc.arguments },
              }))
            : undefined,
        }
        messages.push(assistantMsg)

        if (finishReason === 'stop' || rawToolCalls.length === 0) {
          return {
            result: { stopped: true, reason: 'stop_sequence', output: finalOutput },
            newHistory: messages,
          }
        }

        // ── Parse inputs ─────────────────────────────────────────
        const parsedCalls: ParsedToolCall[] = rawToolCalls.map((tc) => {
          let input: Record<string, unknown>
          try {
            input = JSON.parse(tc.arguments || '{}') as Record<string, unknown>
          } catch {
            input = {}
          }
          return { tc, input }
        })

        // ── Schedule: parallel (safe) vs serial (unsafe) ─────────
        const batches = partitionToolCalls(parsedCalls)

        for (const batch of batches) {
          if (turnAbortController.signal.aborted) break

          if (batch.safe && batch.calls.length > 1) {
            // ── Parallel batch ───────────────────────────────────
            // Show all tool starts up front
            for (const { tc, input } of batch.calls) {
              this.renderer.toolStart(tc.name, input)
              this.config.hookRunner?.runPreToolCall(tc.name, input)
            }

            // Execute concurrently
            const results = await Promise.all(
              batch.calls.map(({ tc, input }) =>
                this.executeToolCall(tc.name, input, toolContext, planMode),
              ),
            )

            // Collect results in original order
            for (let i = 0; i < batch.calls.length; i++) {
              const { tc } = batch.calls[i]
              const result = results[i]
              this.config.hookRunner?.runPostToolCall(tc.name, result.content, result.isError)
              this.renderer.toolResult(tc.name, result.content, result.isError)
              messages.push({
                role: 'tool',
                tool_call_id: tc.id,
                content: truncateToolResult(result.content),
                name: tc.name,
              })
            }
          } else {
            // ── Serial batch ─────────────────────────────────────
            for (const { tc, input } of batch.calls) {
              if (turnAbortController.signal.aborted) break

              this.renderer.toolStart(tc.name, input)
              this.config.hookRunner?.runPreToolCall(tc.name, input)

              const result = await this.executeToolCall(tc.name, input, toolContext, planMode)

              this.config.hookRunner?.runPostToolCall(tc.name, result.content, result.isError)
              this.renderer.toolResult(tc.name, result.content, result.isError)

              messages.push({
                role: 'tool',
                tool_call_id: tc.id,
                content: truncateToolResult(result.content),
                name: tc.name,
              })

              // ── Soft-interrupt check after each serial tool ──────
              // Checked here (not just at iteration start) so ESC takes
              // effect after the current tool, not after the full batch.
              if (this.softAbortRequested) {
                this.softAbortRequested = false
                return {
                  result: { stopped: true, reason: 'interrupted', output: finalOutput },
                  newHistory: messages,
                }
              }
            }
          }

          // ── Soft-interrupt check after each batch (parallel too) ─
          if (this.softAbortRequested) {
            this.softAbortRequested = false
            return {
              result: { stopped: true, reason: 'interrupted', output: finalOutput },
              newHistory: messages,
            }
          }
        }
      }
    } finally {
      this.currentTurnAbortController = null
    }

    this.renderer.warn(`Max iterations (${this.config.maxIterations}) reached`)
    return {
      result: { stopped: true, reason: 'max_iterations', output: finalOutput },
      newHistory: messages,
    }
  }

  private async executeToolCall(
    toolName: string,
    input: Record<string, unknown>,
    context: ToolContext,
    planMode = false,
  ): Promise<ToolResult> {
    // In plan mode, block write tools (defence in depth — tool defs already filtered)
    if (planMode && !PLAN_MODE_TOOLS.has(toolName)) {
      return {
        content: `Tool "${toolName}" is not available in plan mode. Only read-only tools are allowed. Output your plan as text.`,
        isError: true,
      }
    }

    // In coordinator mode, block execution tools (defence in depth — tool defs already filtered)
    const coordinatorMode = (this.config.coordinatorMode ?? false) && !!this.config.sessionDir
    if (coordinatorMode && !COORDINATOR_ALLOWED_TOOLS.has(toolName)) {
      const agentSuggestion = this.getCoordinatorSuggestion(toolName, input)
      return {
        content: `⛔ 协调者模式：主 agent 不能直接使用 ${toolName}。${agentSuggestion}`,
        isError: true,
      }
    }
    if (coordinatorMode) {
      const violation = this.getCoordinatorDelegationViolation(toolName, input)
      if (violation) {
        return {
          content: `⛔ 协调者委派策略：${violation}`,
          isError: true,
        }
      }
    }

    // Check cache first (skip for non-cacheable tools)
    if (!NO_CACHE_TOOLS.has(toolName)) {
      const cachedResult = this.toolCache.get(toolName, input)
      if (cachedResult) {
        this.renderer.info(`[Cache hit] ${toolName}`)
        return cachedResult
      }
    }

    const tool = findTool(this.tools, toolName)
    if (!tool) {
      return { content: `Unknown tool: ${toolName}`, isError: true }
    }

    // Generate task ID for progress tracking
    const taskId = `task_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
    // Declared outside try so catch block can reference it
    const isLongRunningTool = ['Bash', 'MultiScan', 'WeaponRadar', 'WebSearch', 'C2'].includes(toolName)

    try {
      if (isLongRunningTool) {
        this.progressTracker.start(taskId, toolName, input)
        this.renderer.info(`[Progress] Starting ${toolName} task ${taskId}`)
      }

      // Create a progress update function
      const updateProgress = (progress: number, recoveryData?: Record<string, unknown>) => {
        if (isLongRunningTool) {
          this.progressTracker.update(taskId, progress, recoveryData)
          this.renderer.info(`[Progress] ${toolName}: ${progress}%`)
        }
      }

      // Add progress update to context
      const enhancedContext: ToolContext & { updateProgress?: (progress: number, recoveryData?: Record<string, unknown>) => void } = {
        ...context,
        updateProgress
      }

      // Execute the tool
      const result = await tool.execute(input, enhancedContext)

      // Complete progress tracking
      if (isLongRunningTool) {
        this.progressTracker.complete(taskId, result.content)
        this.renderer.info(`[Progress] ${toolName} completed`)
      }

      // Cache the result (only for cacheable, successful, non-error results)
      if (!result.isError && !NO_CACHE_TOOLS.has(toolName)) {
        const ttl = ['WebFetch', 'WebSearch'].includes(toolName)
          ? 60 * 60 * 1000  // 1 hour for expensive web lookups
          : undefined
        this.toolCache.set(toolName, input, result, ttl)
      }

      return result
    } catch (err: unknown) {
      // Handle error in progress tracking — use the same isLongRunningTool flag
      if (isLongRunningTool) {
        this.progressTracker.fail(taskId, (err as Error).message)
        this.renderer.error(`[Progress] ${toolName} failed: ${(err as Error).message}`)
      }

      return {
        content: `Tool ${toolName} threw exception: ${(err as Error).message}`,
        isError: true,
      }
    }
  }

  getModel(): string {
    return this.config.model
  }

  /**
   * When coordinator mode blocks a tool, suggest the correct sub-agent delegation.
   */
  private getCoordinatorSuggestion(toolName: string, input: Record<string, unknown>): string {
    const TOOL_TO_AGENT: Record<string, { type: string; reason: string }> = {
      'Bash': {
        type: '根据命令内容选择子agent类型',
        reason: 'Bash命令是子agent的工作。扫描用recon/vuln-scan，利用用manual-exploit/tool-exploit，靶机用target-recon',
      },
      'MultiScan': {
        type: 'vuln-scan → web-vuln / service-vuln',
        reason: 'MultiScan只是并行Bash，没有LLM推理。用MultiAgent启动vuln-scan子agent',
      },
      'ShellSession': {
        type: 'manual-exploit / target-recon / privesc',
        reason: '反弹shell交互是子agent的工作',
      },
      'TmuxSession': {
        type: 'tool-exploit / c2-deploy',
        reason: 'msfconsole/sliver交互是子agent的工作',
      },
      'Write': {
        type: 'manual-exploit / report',
        reason: '文件写入是子agent的工作',
      },
      'Edit': {
        type: 'manual-exploit',
        reason: '文件编辑是子agent的工作',
      },
    }

    const suggestion = TOOL_TO_AGENT[toolName]
    if (!suggestion) {
      return `请通过 Agent 或 MultiAgent 委派子agent执行。`
    }

    if (toolName === 'Bash') {
      const cmd = String(input.command ?? '').toLowerCase()
      if (cmd.includes('nmap') || cmd.includes('masscan') || cmd.includes('naabu')) {
        return `请用 MultiAgent 启动 recon 子agent:\n  MultiAgent({ agents: [{ subagent_type: "recon", description: "侦察", prompt: "对 TARGET 进行端口扫描" }] })`
      }
      if (cmd.includes('nuclei') || cmd.includes('nikto') || cmd.includes('ffuf')) {
        return `请用 MultiAgent 启动 vuln-scan 子agent:\n  MultiAgent({ agents: [{ subagent_type: "vuln-scan", description: "漏洞扫描", prompt: "对 TARGET 进行漏洞扫描" }] })`
      }
      if (cmd.includes('sqlmap')) {
        return `请用 MultiAgent 启动 manual-exploit 和 tool-exploit 子agent:\n  MultiAgent({ agents: [{ subagent_type: "manual-exploit", ... }, { subagent_type: "tool-exploit", ... }] })`
      }
      if (cmd.includes('hydra') || cmd.includes('kerbrute')) {
        return `请用 MultiAgent 启动 vuln-scan 子agent:\n  MultiAgent({ agents: [{ subagent_type: "vuln-scan", description: "认证攻击", prompt: "对 TARGET 进行弱口令测试" }] })`
      }
      if (cmd.includes('subfinder') || cmd.includes('dnsx') || cmd.includes('amass')) {
        return `请用 MultiAgent 启动 recon 子agent:\n  MultiAgent({ agents: [{ subagent_type: "recon", description: "DNS侦察", prompt: "对 TARGET 进行DNS子域名枚举" }] })`
      }
      if (cmd.includes('httpx') || cmd.includes('katana')) {
        return `请用 MultiAgent 启动 recon 子agent:\n  MultiAgent({ agents: [{ subagent_type: "recon", description: "Web探测", prompt: "对 TARGET 进行Web服务探测" }] })`
      }
      if (cmd.includes('chisel') || cmd.includes('stowaway') || cmd.includes('proxychains')) {
        return `请用 Agent 启动 tunnel 子agent:\n  Agent({ subagent_type: "tunnel", description: "内网穿透", prompt: "建立内网穿透代理" })`
      }
      if (cmd.includes('linpeas') || cmd.includes('winpeas')) {
        return `请用 Agent 启动 privesc 子agent:\n  Agent({ subagent_type: "privesc", description: "权限提升", prompt: "在靶机上进行提权" })`
      }
      if (cmd.includes('find') && cmd.includes('flag')) {
        return `请用 Agent 启动 flag-hunter 子agent:\n  Agent({ subagent_type: "flag-hunter", description: "Flag收集", prompt: "搜索并收集flag" })`
      }
      if (cmd.includes('tail') || cmd.includes('cat') || cmd.includes('head')) {
        return `读取文件请用 Read 工具:\n  Read({ file_path: "SESSION_DIR/xxx.txt" })`
      }
    }

    return `${suggestion.reason}。请用 MultiAgent/Agent 启动 ${suggestion.type} 子agent。`
  }

  /**
   * Additional delegation policy in coordinator mode.
   * Goal: force the main agent to orchestrate specialized parallel workers,
   * not funnel work into one generic sub-agent.
   */
  private getCoordinatorDelegationViolation(
    toolName: string,
    input: Record<string, unknown>,
  ): string | null {
    if (toolName === 'Agent') {
      const agentType = String(input.subagent_type ?? 'general-purpose')
      const serialReason = String(input.serial_reason ?? '').trim()

      if (FORBIDDEN_COORDINATOR_AGENT_TYPES.has(agentType)) {
        return `主agent禁止委派 ${agentType} 这类泛化子agent。请使用专用红队子agent（如 recon / vuln-scan / manual-exploit / lateral / flag-hunter）。`
      }

      if (PARALLEL_FIRST_AGENT_TYPES.has(agentType) && serialReason.length < 8) {
        return `阶段型任务 ${agentType} 默认必须并行编排。请改为 MultiAgent 一次启动多个子agent；若确有强依赖需串行，请在 Agent 调用中提供 serial_reason 说明依赖原因。`
      }
    }

    if (toolName === 'MultiAgent') {
      const specs = input.agents
      if (!Array.isArray(specs) || specs.length === 0) return null

      for (const raw of specs) {
        if (!raw || typeof raw !== 'object') continue
        const spec = raw as Record<string, unknown>
        const agentType = String(spec.subagent_type ?? 'general-purpose')
        if (FORBIDDEN_COORDINATOR_AGENT_TYPES.has(agentType)) {
          return `MultiAgent 中禁止包含 ${agentType}。请改为专用红队子agent类型。`
        }
      }
    }

    return null
  }
}
