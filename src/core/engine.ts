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

import type {
  EngineConfig,
  OpenAIMessage,
  Tool,
  ToolContext,
  ToolResult,
  TurnResult,
} from './types.js'
import {
  createTools,
  findTool,
  getToolDefinitions,
  isCacheableTool,
  isConcurrencySafeTool,
  isLongRunningTool,
  isPlanModeTool,
} from '../tools/index.js'
import { getPlanModePrefix } from '../prompts/system.js'
import type { Renderer } from '../ui/renderer.js'
import { maybeCompact, calculateContextState, MODEL_MAX_CONTEXT_TOKENS } from './compact.js'
import { ProgressTracker } from './progressTracker.js'
import { ToolCache } from './toolCache.js'
import type { EventLogEntry } from './eventLog.js'
import { ContextBudgetManager, CompressionStrategy } from './contextBudget.js'
import { KnowledgeExtractor } from './knowledgeExtractor.js'
import { PermissionManager } from './permissionManager.js'
import { OpenAICompatibleModelClient, type ChatStreamChunk, type ModelClient } from './modelClient.js'
import { partitionToolCalls } from './toolScheduler.js'
import { ArtifactStore } from './artifactStore.js'

const MAX_TOOL_RESULT_LENGTH = 20_000
const DEFAULT_MAX_CONCURRENT_TOOL_CALLS = 8

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
  // Async dispatch
  'DispatchAgent', 'CheckDispatch', 'GetDispatchResult',
  // Intelligence / lookup (fast, no side effects)
  'WeaponRadar', 'WebSearch', 'WebFetch',
  // Reading sub-agent outputs and documents
  'Read', 'Glob', 'Grep', 'DocRead',
  // Progress tracking
  'FindingWrite', 'FindingList', 'TodoWrite',
  // C2 coordination (get_ip, list_sessions, list_listeners — read-only actions)
  'C2',
  // Bash — read-only commands only (whitelist enforced at execution time)
  'Bash',
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
 * Coordinator mode — Bash read-only command whitelist.
 * The main agent needs these to monitor sub-agent progress via file inspection
 * without being able to launch scans or exploits directly.
 */
const COORDINATOR_BASH_WHITELIST = [
  // File reading / inspection
  /^tail\b/, /^head\b/, /^cat\b/, /^wc\b/, /^less\b/, /^more\b/, /^bat\b/,
  // Search
  /^grep\b/, /^egrep\b/, /^fgrep\b/, /^zgrep\b/,
  // Listing / filesystem
  /^ls\b/, /^stat\b/, /^file\b/, /^du\b/, /^df\b/, /^find\b/, /^tree\b/,
  // Process monitoring
  /^ps\b/, /^top\b/, /^htop\b/, /^uptime\b/, /^free\b/,
  // Identity / system info
  /^whoami\b/, /^id\b/, /^hostname\b/, /^uname\b/, /^who\b/, /^w\b/,
  // Safe output
  /^echo\b/, /^printf\b/,
  // Log / session monitoring
  /^sed\s+.*-n\b/,  // sed -n is safe (no -i)
  /^awk\b/,
  // Sorting / filtering
  /^sort\b/, /^uniq\b/, /^diff\b/, /^cmp\b/,
  // Network info (read-only)
  /^ss\b/, /^netstat\b/, /^ip\s+(addr|route|link|neigh)\b/,
  // But block dangerous network commands
]

/** Regexes for commands the coordinator must NEVER run via Bash. */
const COORDINATOR_BASH_BLACKLIST = [
  /nmap\b/, /masscan\b/, /naabu\b/,        // port scanning
  /nuclei\b/, /nikto\b/, /ffuf\b/,          // vuln scanning
  /sqlmap\b/, /hydra\b/, /kerbrute\b/,      // exploitation / brute-force
  /msfconsole\b/, /msfvenom\b/, /metasploit\b/,  // C2
  /sliver\b/, /cobalt.*strike\b/,           // C2
  /chisel\b/, /stowaway\b/, /proxychains\b/, /socat\b/, // tunneling
  /curl.*(-o\s|-O\b|--output\b)/,           // curl downloading files
  /wget\b/, /fetch\b/,                      // downloading
  /chmod\b.*\+x/, /chown\b/,                // permission changes
  /apt\s+install\b/, /apt-get\s+install\b/, // package installation
  /go\s+install\b/,                         // Go tool installation
  /pip\s+install\b/, /pip3\s+install\b/,   // Python package installation
  /rm\b.*(-rf|-fr)/,                        // destructive deletion
  /find\b.*(-exec\b.*-c\s|delete\b)/,       // find destructive operations
  /\|\s*(bash|sh|zsh)\b/,                   // pipe to shell
  /\beval\b/, /source\s/, /\. /,            // code evaluation
]

export class ExecutionEngine {
  private modelClient: ModelClient
  private tools: Tool[]
  private config: EngineConfig
  private renderer: Renderer
  /** Abort controller for the current turn — null when idle */
  private currentTurnAbortController: AbortController | null = null
  /** Soft-interrupt flag: pause after current tool finishes, preserve history */
  private softAbortRequested = false
  /** Progress tracker for long-running tools */
  private progressTracker: ProgressTracker
  /** Cache for tool execution results */
  private toolCache: ToolCache
  /** Event log — may be undefined if not configured */
  private eventLog: EngineConfig['eventLog']
  /** Context budget manager — may be undefined if not configured */
  private contextBudget: EngineConfig['contextBudget']
  /** Knowledge extractor — may be undefined if not configured */
  private knowledgeExtractor: KnowledgeExtractor | null = null
  private permissionManager = new PermissionManager()
  private artifactStore: ArtifactStore | null = null

  constructor(config: EngineConfig, renderer: Renderer) {
    this.config = config
    this.renderer = renderer
    this.modelClient = OpenAICompatibleModelClient.fromConfig({
      apiKey: config.apiKey,
      baseURL: config.baseURL,
    })
    this.tools = createTools(config.extraTools ?? [], config.knowledgeBase)
    this.progressTracker = config.progressTracker || new ProgressTracker()
    this.toolCache = config.toolCache || new ToolCache()
    this.eventLog = config.eventLog
    this.contextBudget = config.contextBudget
    this.artifactStore = config.sessionDir ? new ArtifactStore(config.sessionDir) : null

    // Initialize knowledge extractor if knowledge base is configured
    if (config.knowledgeBase) {
      this.knowledgeExtractor = new KnowledgeExtractor(config.knowledgeBase)
    }
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
      const output = await this.modelClient.completeText({
        model: this.config.model,
        messages: [
          { role: 'system', content: CRITIC_SYSTEM_PROMPT },
          {
            role: 'user',
            content: `以下是最近的操作历史，请检查是否存在失误：\n\n${formatMessagesForCritic(recent)}`,
          },
        ],
        temperature: 0,
        maxTokens: CRITIC_MAX_TOKENS,
      })

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
    const runId = `run_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`

    // Reset knowledge extractor state at the start of each new user turn
    this.knowledgeExtractor?.reset()

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
      modelClient: this.modelClient,
      // Inject sessionDir for tools that need anchor updates
      sessionDir: this.config.sessionDir,
      // Inject new systems into tool context
      eventLog: this.eventLog,
      semanticMemory: this.config.semanticMemory,
      episodicMemory: this.config.episodicMemory,
      readableRoots: this.config.readableRoots,
      writableRoots: this.config.writableRoots,
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
      toolDefs = allToolDefs.filter((t) => isPlanModeTool(this.tools, t.function.name))
    } else if (coordinatorMode) {
      toolDefs = allToolDefs.filter((t) => COORDINATOR_ALLOWED_TOOLS.has(t.function.name))
    }

    let iterations = 0
    let finalOutput = ''
    const finish = (result: TurnResult): { result: TurnResult; newHistory: OpenAIMessage[] } => {
      this.eventLog?.append('run_complete', 'engine', {
        runId,
        reason: result.reason,
        iterations,
        messageCount: messages.length,
        outputLength: result.output.length,
      }, ['run', result.reason])
      return { result, newHistory: messages }
    }

    this.eventLog?.append('run_start', 'engine', {
      runId,
      model: this.config.model,
      planMode,
      coordinatorMode,
      historyMessages: history.length,
      exposedTools: toolDefs.length,
    }, ['run'])

    try {
      while (iterations < this.config.maxIterations) {
        // Check for cancellation at the top of each loop
        if (turnAbortController.signal.aborted) {
          return finish({ stopped: true, reason: 'error', output: finalOutput })
        }

        iterations++
        const turnId = `${runId}_turn_${iterations}`
        this.eventLog?.append('turn_start', 'engine', {
          runId,
          turnId,
          iteration: iterations,
          messageCount: messages.length,
        }, ['turn'])

        // ── Soft-interrupt check — pause after current tool, preserve history ─
        if (this.softAbortRequested) {
          this.softAbortRequested = false
          return finish({ stopped: true, reason: 'interrupted', output: finalOutput })
        }

        // ── Context stats + auto-compact ────────────────────────
        const maxCtxTokens = this.config.maxContextTokens ?? MODEL_MAX_CONTEXT_TOKENS

        // Use ContextBudgetManager if available, else fall back to percentage-based thresholds
        const baseCtxState = calculateContextState(messages, maxCtxTokens)
        let ctxState: ReturnType<typeof calculateContextState> & { strategy?: CompressionStrategy }
        if (this.contextBudget) {
          const budgetState = this.contextBudget.evaluate(baseCtxState.currentTokens)
          ctxState = {
            ...baseCtxState,
            strategy: budgetState.strategy,
            shouldCompact: budgetState.shouldCompact,
            shouldWarn: budgetState.shouldWarn,
          }
        } else {
          ctxState = baseCtxState as ReturnType<typeof calculateContextState> & { strategy?: CompressionStrategy }
        }

        // Show context stats every 5 iterations (main agent only, not sub-agents)
        if (this.config.sessionDir && iterations % 5 === 0) {
          this.renderer.contextStats(ctxState.currentTokens, ctxState.maxTokens, ctxState.pct)
        }

        if (ctxState.shouldCompact) {
          this.renderer.compactStart(ctxState.currentTokens)
          this.eventLog?.append('context_compact', 'engine', {
            strategy: ctxState.strategy,
            tokens_before: ctxState.currentTokens,
            pct: ctxState.pct,
          })
          const compactResult = await maybeCompact(this.modelClient, this.config.model, messages, undefined, this.config.sessionDir)
          if (compactResult.compacted) {
            messages.length = 0
            messages.push(...compactResult.messages)
            this.renderer.compactDone(compactResult.originalTokens, compactResult.summaryTokens)
            this.eventLog?.append('context_compact', 'engine', {
              tokens_after: compactResult.summaryTokens,
              reduction: compactResult.originalTokens - compactResult.summaryTokens,
            })
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
            this.eventLog?.append('critic_flag', 'critic', {
              criticism: criticism.slice(0, 500),
              iteration: iterations,
            })
            messages.push({
              role: 'user',
              content: `[🔍 自动纠错检查]\n${criticism}\n\n请根据以上纠错提示立即调整行动。`,
            })
          }
        }

        // ── Streaming API call ───────────────────────────────────
        this.renderer.startSpinner()
        this.eventLog?.append('model_request', 'model', {
          runId,
          turnId,
          model: this.config.model,
          messageCount: messages.length + 1, // includes system prompt
          toolCount: toolDefs.length,
        }, ['model'])

        let stream: AsyncIterable<ChatStreamChunk>
        try {
          stream = await this.modelClient.streamChat({
            model: this.config.model,
            systemPrompt,
            messages,
            tools: toolDefs,
            signal: turnAbortController.signal,
            temperature: 0,
            maxTokens: 8192,
          })
        } catch (err: unknown) {
          this.renderer.stopSpinner()
          const error = err as Error
          if (error.name === 'AbortError' || turnAbortController.signal.aborted) {
            return finish({ stopped: true, reason: 'error', output: finalOutput })
          }
          this.renderer.error(`API error: ${error.message}`)
          return finish({ stopped: true, reason: 'error', output: error.message })
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
            return finish({ stopped: true, reason: 'error', output: finalOutput })
          }
          this.renderer.error(`Stream error: ${error.message}`)
          return finish({ stopped: true, reason: 'error', output: error.message })
        }

        this.renderer.stopSpinner()

        if (assistantText) {
          this.renderer.endAssistantText()
          finalOutput = assistantText
        }

        const rawToolCalls = Array.from(toolCallsMap.values()).sort((a, b) => a.index - b.index)
        this.eventLog?.append('model_response', 'model', {
          runId,
          turnId,
          finishReason,
          textLength: assistantText.length,
          toolCallCount: rawToolCalls.length,
          toolNames: rawToolCalls.map((tc) => tc.name),
        }, ['model', rawToolCalls.length > 0 ? 'tool_calls' : 'text'])

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
          this.extractSessionKnowledge()
          return finish({ stopped: true, reason: 'stop_sequence', output: finalOutput })
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
        const maxParallelBatchSize = Math.max(
          1,
          Math.floor(this.config.maxConcurrentToolCalls ?? DEFAULT_MAX_CONCURRENT_TOOL_CALLS),
        )
        const batches = partitionToolCalls(
          parsedCalls,
          (name) => isConcurrencySafeTool(this.tools, name),
          { maxParallelBatchSize },
        )

        for (const batch of batches) {
          if (turnAbortController.signal.aborted) break

          if (batch.safe && batch.calls.length > 1) {
            // ── Parallel batch ───────────────────────────────────
            // Show all tool starts up front
            for (const { tc, input } of batch.calls) {
              this.renderer.toolStart(tc.name, input)
              this.config.hookRunner?.runPreToolCall(tc.name, input)
              this.eventLog?.append('tool_call', tc.name, { input }, [tc.name])
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
              this.eventLog?.append('tool_result', tc.name, { content: result.content.slice(0, 500), isError: result.isError }, [tc.name, result.isError ? 'error' : 'success'])
              messages.push({
                role: 'tool',
                tool_call_id: tc.id,
                content: this.prepareToolResultContent(tc.name, result.content),
                name: tc.name,
              })
            }
          } else {
            // ── Serial batch ─────────────────────────────────────
            for (const { tc, input } of batch.calls) {
              if (turnAbortController.signal.aborted) break

              this.renderer.toolStart(tc.name, input)
              this.config.hookRunner?.runPreToolCall(tc.name, input)
              this.eventLog?.append('tool_call', tc.name, { input }, [tc.name])

              const result = await this.executeToolCall(tc.name, input, toolContext, planMode)

              this.config.hookRunner?.runPostToolCall(tc.name, result.content, result.isError)
              this.renderer.toolResult(tc.name, result.content, result.isError)
              this.eventLog?.append('tool_result', tc.name, { content: result.content.slice(0, 500), isError: result.isError }, [tc.name, result.isError ? 'error' : 'success'])

              messages.push({
                role: 'tool',
                tool_call_id: tc.id,
                content: this.prepareToolResultContent(tc.name, result.content),
                name: tc.name,
              })

              // ── Soft-interrupt check after each serial tool ──────
              // Checked here (not just at iteration start) so ESC takes
              // effect after the current tool, not after the full batch.
              if (this.softAbortRequested) {
                this.softAbortRequested = false
                return finish({ stopped: true, reason: 'interrupted', output: finalOutput })
              }
            }
          }

          // ── Soft-interrupt check after each batch (parallel too) ─
          if (this.softAbortRequested) {
            this.softAbortRequested = false
            return finish({ stopped: true, reason: 'interrupted', output: finalOutput })
          }
        }
      }
    } finally {
      this.currentTurnAbortController = null
    }

    this.renderer.warn(`Max iterations (${this.config.maxIterations}) reached`)
    this.extractSessionKnowledge()
    return finish({ stopped: true, reason: 'max_iterations', output: finalOutput })
  }

  /** Session-end knowledge extraction (best-effort, never throws) */
  private extractSessionKnowledge(): void {
    if (!this.knowledgeExtractor || !this.eventLog) return
    try {
      const events = this.eventLog.readAll()
      this.knowledgeExtractor.extractFromSession(events)
    } catch { /* best-effort — knowledge extraction must never break the engine */ }
  }

  private prepareToolResultContent(toolName: string, content: string): string {
    if (content.length <= MAX_TOOL_RESULT_LENGTH) return content

    const artifact = this.artifactStore?.writeText(`tool_${toolName}`, content)
    if (artifact) {
      this.eventLog?.append('artifact_write', 'artifact_store', {
        toolName,
        path: artifact.path,
        bytes: artifact.bytes,
        sha256: artifact.sha256,
        createdAt: artifact.createdAt,
        prefix: artifact.prefix,
        reason: 'tool_result_too_large',
      }, ['artifact', toolName])
      return [
        `[Full tool output stored at: ${artifact.path}]`,
        `[Bytes: ${artifact.bytes}]`,
        `[SHA256: ${artifact.sha256}]`,
        '',
        truncateToolResult(content),
      ].join('\n')
    }

    return truncateToolResult(content)
  }

  private async executeToolCall(
    toolName: string,
    input: Record<string, unknown>,
    context: ToolContext,
    planMode = false,
  ): Promise<ToolResult> {
    // In plan mode, block write tools (defence in depth — tool defs already filtered)
    if (planMode && !isPlanModeTool(this.tools, toolName)) {
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
    // In coordinator mode, Bash is restricted to read-only commands
    if (coordinatorMode && toolName === 'Bash') {
      const cmd = String(input.command ?? '')
      const bashCheck = this.checkCoordinatorBash(cmd)
      if (!bashCheck.allowed) {
        return {
          content: `⛔ 协调者模式：Bash 命令 "${cmd}" 被拦截。\n原因: ${bashCheck.reason}\n主 agent 只能使用只读命令（tail/head/cat/wc/grep/ps/ls/stat/find等）查看子 agent 进度。`,
          isError: true,
        }
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
    if (isCacheableTool(this.tools, toolName)) {
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
    const permission = this.permissionManager.checkTool({
      toolName,
      input,
      mode: this.config.permissionMode,
      runtime: tool.runtime,
      cwd: context.cwd,
      sessionDir: context.sessionDir,
      readableRoots: context.readableRoots,
      writableRoots: context.writableRoots,
    })
    if (!permission.allowed) {
      this.eventLog?.append('permission_denied', 'permissions', {
        toolName,
        reason: permission.reason,
        mode: this.config.permissionMode,
      }, ['permission', toolName])
      return { content: `Permission denied: ${permission.reason}`, isError: true }
    }

    // Generate task ID for progress tracking
    const taskId = `task_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
    // Declared outside try so catch block can reference it
    const longRunning = isLongRunningTool(this.tools, toolName)

    try {
      if (longRunning) {
        this.progressTracker.start(taskId, toolName, input)
        this.renderer.info(`[Progress] Starting ${toolName} task ${taskId}`)
      }

      // Create a progress update function
      const updateProgress = (progress: number, recoveryData?: Record<string, unknown>) => {
        if (longRunning) {
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
      if (longRunning) {
        this.progressTracker.complete(taskId, result.content)
        this.renderer.info(`[Progress] ${toolName} completed`)
      }

      // Cache the result (only for cacheable, successful, non-error results)
      if (!result.isError && isCacheableTool(this.tools, toolName)) {
        const ttl = findTool(this.tools, toolName)?.runtime?.cacheTtlMs
        this.toolCache.set(toolName, input, result, ttl)
      }

      // Write episodic memory entry
      const epiMem = this.config.episodicMemory
      if (epiMem) {
        epiMem.write({
          turn: 0,
          toolName,
          inputSummary: JSON.stringify(input).slice(0, 200),
          resultSummary: result.content.slice(0, 300),
          outcome: result.isError ? 'failure' : 'success',
          timestamp: new Date().toISOString(),
        })
      }

      // Real-time knowledge extraction
      if (!result.isError && this.knowledgeExtractor) {
        this.knowledgeExtractor.extractFromToolResult(toolName, input, result.content)
      }

      return result
    } catch (err: unknown) {
      // Handle error in progress tracking using the same runtime metadata.
      if (longRunning) {
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
    if (toolName === 'Bash') {
      const cmd = String(input.command ?? '').toLowerCase()
      if (cmd.includes('nmap') || cmd.includes('masscan') || cmd.includes('naabu')) {
        return `扫描命令应由子agent执行。请用 MultiAgent 启动 recon 子agent:\n  MultiAgent({ agents: [{ subagent_type: "recon", description: "侦察", prompt: "对 TARGET 进行端口扫描" }] })`
      }
      if (cmd.includes('nuclei') || cmd.includes('nikto') || cmd.includes('ffuf')) {
        return `扫描命令应由子agent执行。请用 MultiAgent 启动 vuln-scan 子agent:\n  MultiAgent({ agents: [{ subagent_type: "vuln-scan", description: "漏洞扫描", prompt: "对 TARGET 进行漏洞扫描" }] })`
      }
      if (cmd.includes('sqlmap')) {
        return `利用命令应由子agent执行。请用 MultiAgent 启动 manual-exploit 和 tool-exploit 子agent:\n  MultiAgent({ agents: [{ subagent_type: "manual-exploit", ... }, { subagent_type: "tool-exploit", ... }] })`
      }
      if (cmd.includes('hydra') || cmd.includes('kerbrute')) {
        return `爆破命令应由子agent执行。请用 MultiAgent 启动 vuln-scan 子agent:\n  MultiAgent({ agents: [{ subagent_type: "vuln-scan", description: "认证攻击", prompt: "对 TARGET 进行弱口令测试" }] })`
      }
      if (cmd.includes('subfinder') || cmd.includes('dnsx') || cmd.includes('amass')) {
        return `侦察命令应由子agent执行。请用 MultiAgent 启动 recon 子agent:\n  MultiAgent({ agents: [{ subagent_type: "recon", description: "DNS侦察", prompt: "对 TARGET 进行DNS子域名枚举" }] })`
      }
      if (cmd.includes('httpx') || cmd.includes('katana')) {
        return `探测命令应由子agent执行。请用 MultiAgent 启动 recon 子agent:\n  MultiAgent({ agents: [{ subagent_type: "recon", description: "Web探测", prompt: "对 TARGET 进行Web服务探测" }] })`
      }
      if (cmd.includes('chisel') || cmd.includes('stowaway') || cmd.includes('proxychains')) {
        return `穿透命令应由子agent执行。请用 Agent 启动 tunnel 子agent:\n  Agent({ subagent_type: "tunnel", description: "内网穿透", prompt: "建立内网穿透代理" })`
      }
      if (cmd.includes('linpeas') || cmd.includes('winpeas')) {
        return `提权命令应由子agent执行。请用 Agent 启动 privesc 子agent:\n  Agent({ subagent_type: "privesc", description: "权限提升", prompt: "在靶机上进行提权" })`
      }
      if (cmd.includes('find') && cmd.includes('flag')) {
        return `Flag搜索应由子agent执行。请用 Agent 启动 flag-hunter 子agent:\n  Agent({ subagent_type: "flag-hunter", description: "Flag收集", prompt: "搜索并收集flag" })`
      }
      return `只读命令（tail/cat/grep/ps/wc等）可直接使用。扫描/利用命令应通过 Agent 或 MultiAgent 委派子agent执行。`
    }

    if (!suggestion) {
      return `请通过 Agent 或 MultiAgent 委派子agent执行。`
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

  /**
   * Check whether a Bash command is allowed in coordinator mode.
   * Uses whitelist (allowed patterns) + blacklist (blocked patterns).
   */
  private checkCoordinatorBash(cmd: string): { allowed: boolean; reason: string } {
    const trimmed = cmd.trim()
    if (!trimmed) return { allowed: false, reason: '空命令' }

    // First check blacklist — if any blacklisted pattern matches, block
    for (const re of COORDINATOR_BASH_BLACKLIST) {
      if (re.test(trimmed.toLowerCase())) {
        return { allowed: false, reason: `该命令匹配黑名单：${re.source}，属于扫描/利用/安装类操作，应委派子 agent` }
      }
    }

    // Then check whitelist — if any whitelisted pattern matches, allow
    for (const re of COORDINATOR_BASH_WHITELIST) {
      if (re.test(trimmed.toLowerCase())) {
        return { allowed: true, reason: '' }
      }
    }

    return { allowed: false, reason: '该命令不在协调者只读命令白名单中' }
  }
}
