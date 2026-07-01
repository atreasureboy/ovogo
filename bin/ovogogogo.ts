#!/usr/bin/env node
/**
 * ovogogogo — Autonomous Code Execution Engine
 *
 * ovogogogo-style interactive CLI. No React, no Ink — pure terminal.
 *
 * Usage:
 *   ovogogogo                              # interactive REPL
 *   ovogogogo "fix the type errors"        # single task
 *   echo "task" | ovogogogo               # pipe input
 *   ovogogogo -m gpt-4o --max-iter 20     # with options
 *
 * Environment:
 *   OPENAI_API_KEY     (required)
 *   OPENAI_BASE_URL    (optional, for compatible endpoints)
 *   OVOGO_MODEL        (default: gpt-4o)
 *   OVOGO_MAX_ITER     (default: 30)
 *   OVOGO_CWD          (default: process.cwd())
 *
 * Config:
 *   .ovogo/settings.json  — hooks and other settings (project-level)
 *   ~/.ovogo/settings.json — user-level defaults
 *
 * Skills:
 *   .ovogo/skills/*.md    — project-specific slash commands
 *   ~/.ovogo/skills/*.md  — global user slash commands
 */

import { resolve, join } from 'path'
import { existsSync, mkdirSync, statSync, writeFileSync } from 'fs'
import { ExecutionEngine } from '../src/core/engine.js'
import { Renderer } from '../src/ui/renderer.js'
import { InputHandler, readStdin } from '../src/ui/input.js'
import type { EngineConfig, OpenAIMessage } from '../src/core/types.js'
import { registerAgentFactory, setDispatchManager } from '../src/tools/agent.js'
import { DispatchManager } from '../src/core/dispatch.js'
import { loadMcpTools, disconnectAll } from '../src/services/mcp/loader.js'
import type { ConnectedMcpClient } from '../src/services/mcp/client.js'
import { loadSettingsWithDiagnostics } from '../src/config/settings.js'
import { HookRunner, NoopHookRunner } from '../src/config/hooks.js'
import { loadSkills, expandSkillPrompt } from '../src/skills/loader.js'
import type { Skill } from '../src/skills/loader.js'
import { loadOvogoMd } from '../src/config/ovogomd.js'
import { getMemoryDir, buildMemorySystemSection, getMemoryStats } from '../src/memory/index.js'
import { buildFullSystemPrompt } from '../src/prompts/system.js'
import { ProgressTracker } from '../src/core/progressTracker.js'
import { ToolCache } from '../src/core/toolCache.js'
import { EventLog } from '../src/core/eventLog.js'
import { ArtifactStore } from '../src/core/artifactStore.js'
import { SemanticMemory } from '../src/core/semanticMemory.js'
import { EpisodicMemory } from '../src/core/episodicMemory.js'
import { ContextBudgetManager } from '../src/core/contextBudget.js'
import { KnowledgeBase } from '../src/core/knowledgeBase.js'
import { BattleOrchestrator } from '../src/core/orchestrator.js'
import { tmuxLayout } from '../src/ui/tmuxLayout.js'
import { redactText } from '../src/core/redaction.js'

const VERSION = '0.1.0'
const DEFAULT_MAX_CONCURRENT_TOOL_CALLS = 8
const MAX_CONCURRENT_TOOL_CALLS_LIMIT = 64

// ─────────────────────────────────────────────────────────────
// Arg parsing
// ─────────────────────────────────────────────────────────────

interface Args {
  task?: string
  model: string
  modelProvided: boolean
  maxIter: number
  maxIterProvided: boolean
  permissionMode: 'auto' | 'ask' | 'deny'
  permissionModeProvided: boolean
  cwd: string
  help: boolean
  version: boolean
  orchestrator: boolean
  doctor: boolean
  eventsDir?: string
  artifactsDir?: string
  eventType?: string
  eventSource?: string
  eventTags?: string[]
  eventSince?: string
  eventLimit?: number
  artifactLimit?: number
  json: boolean
  strict: boolean
}

const MAX_RECENT_HISTORY_MESSAGES = 120
const MAX_PINNED_USER_MESSAGES = 12

function trimHistoryForNextTurn(messages: OpenAIMessage[]): OpenAIMessage[] {
  if (messages.length <= MAX_RECENT_HISTORY_MESSAGES) return [...messages]

  const keepIndexes = new Set<number>()
  const recentStart = Math.max(0, messages.length - MAX_RECENT_HISTORY_MESSAGES)

  for (let i = recentStart; i < messages.length; i++) {
    keepIndexes.add(i)
  }

  const pinnedUserIndexes = messages
    .map((msg, idx) => ({ msg, idx }))
    .filter(({ msg }) => {
      if (msg.role !== 'user' || typeof msg.content !== 'string') return false
      // Skip synthetic compaction summaries; keep real user instructions.
      return !msg.content.startsWith('[CONVERSATION SUMMARY')
    })
    .slice(-MAX_PINNED_USER_MESSAGES)
    .map(({ idx }) => idx)

  for (const idx of pinnedUserIndexes) {
    keepIndexes.add(idx)
  }

  return Array.from(keepIndexes)
    .sort((a, b) => a - b)
    .map((idx) => messages[idx])
}

function parseArgs(argv: string[]): Args {
  const args = argv.slice(2)
  let task: string | undefined
  let model = process.env.OVOGO_MODEL ?? 'gpt-4o'
  let maxIter = parsePositiveInt(process.env.OVOGO_MAX_ITER, 200)
  const envPermissionMode = process.env.OVOGO_PERMISSION_MODE
  let permissionMode: 'auto' | 'ask' | 'deny' =
    envPermissionMode === 'ask' || envPermissionMode === 'deny' ? envPermissionMode : 'auto'
  let cwd = process.env.OVOGO_CWD ?? process.cwd()
  let help = false
  let version = false
  let orchestrator = false
  let doctor = false
  let eventsDir: string | undefined
  let artifactsDir: string | undefined
  let eventType: string | undefined
  let eventSource: string | undefined
  const eventTags: string[] = []
  let eventSince: string | undefined
  let eventLimit: number | undefined
  let artifactLimit: number | undefined
  let json = false
  let strict = false
  let modelProvided = false
  let maxIterProvided = false
  let permissionModeProvided = false

  for (let i = 0; i < args.length; i++) {
    const arg = args[i]
    switch (arg) {
      case '--help': case '-h': help = true; break
      case '--version': case '-v': case '-V': version = true; break
      case '--orchestrator': orchestrator = true; break
      case '--doctor': doctor = true; break
      case '--json': json = true; break
      case '--strict': strict = true; break
      case '--events': eventsDir = args[++i]; break
      case '--artifacts': artifactsDir = args[++i]; break
      case '--event-type': eventType = args[++i]; break
      case '--event-source': eventSource = args[++i]; break
      case '--event-tag': {
        const value = args[++i]
        if (value) eventTags.push(...value.split(',').map((tag) => tag.trim()).filter(Boolean))
        break
      }
      case '--event-since': eventSince = args[++i]; break
      case '--event-limit': eventLimit = parsePositiveInt(args[++i], eventLimit ?? 20); break
      case '--artifact-limit': artifactLimit = parsePositiveInt(args[++i], artifactLimit ?? 20); break
      case '--model': case '-m': model = args[++i] ?? model; modelProvided = true; break
      case '--max-iter': maxIter = parsePositiveInt(args[++i], maxIter); maxIterProvided = true; break
      case '--permission-mode': {
        const value = args[++i]
        if (value === 'auto' || value === 'ask' || value === 'deny') {
          permissionMode = value
          permissionModeProvided = true
        }
        break
      }
      case '--cwd': cwd = args[++i] ?? cwd; break
      default:
        if (!arg.startsWith('-')) task = task ? task + ' ' + arg : arg
    }
  }
  return {
    task,
    model,
    modelProvided,
    maxIter,
    maxIterProvided,
    permissionMode,
    permissionModeProvided,
    cwd,
    help,
    version,
    orchestrator,
    doctor,
    eventsDir,
    artifactsDir,
    eventType,
    eventSource,
    eventTags,
    eventSince,
    eventLimit,
    artifactLimit,
    json,
    strict,
  }
}

function parsePositiveInt(value: string | undefined, fallback: number): number {
  if (value === undefined) return fallback
  const parsed = Number.parseInt(value, 10)
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback
}

function resolveMaxConcurrentToolCalls(settingsValue?: number, envValue?: string): number {
  const fallback = settingsValue ?? DEFAULT_MAX_CONCURRENT_TOOL_CALLS
  const raw = envValue !== undefined ? parsePositiveInt(envValue, fallback) : fallback
  return Math.max(1, Math.min(Math.floor(raw), MAX_CONCURRENT_TOOL_CALLS_LIMIT))
}

// ─────────────────────────────────────────────────────────────
// Help text
// ─────────────────────────────────────────────────────────────

function printHelp(skills: Map<string, Skill>): void {
  const r = new Renderer()
  r.banner(VERSION, 'gpt-4o')
  process.stdout.write(`USAGE
  ovogogogo [options] [task]

OPTIONS
  -m, --model <model>    LLM model  (env: OVOGO_MODEL, default: gpt-4o)
  --max-iter <n>         Think-Act-Observe max cycles  (env: OVOGO_MAX_ITER, default: 200)
  --permission-mode <m>   Tool permission mode: auto | ask | deny  (env: OVOGO_PERMISSION_MODE, default: auto)
  --cwd <path>           Working directory  (env: OVOGO_CWD, default: cwd)
  --orchestrator         State machine mode — LLM supervisor dispatches agents across pentest phases
  --doctor               Run local config/environment diagnostics without requiring an API key
  --events <sessionDir>  Summarize a session events.ndjson without requiring an API key
  --artifacts <sessionDir> Summarize a session artifacts/manifest.ndjson without requiring an API key
  --event-type <type>    With --events, include recent events of this type
  --event-source <src>   With --events, include recent events from this source
  --event-tag <tag>      With --events, include recent events with this tag (repeatable or comma-separated)
  --event-since <time>   With --events, include events at or after this ISO timestamp
  --event-limit <n>      With --events, include recent matching events (default with filters: 20)
  --artifact-limit <n>   With --artifacts, include recent artifacts (default: 20)
  --json                 Emit machine-readable JSON for compatible diagnostics commands
  --strict               For diagnostics, return non-zero when integrity warnings are present
  -v, --version          Print version and exit
  -h, --help             Show this help

ENVIRONMENT
  OPENAI_API_KEY         Required — OpenAI API key
  OPENAI_BASE_URL        Optional — compatible endpoint URL
  OVOGO_MAX_CONCURRENT_TOOL_CALLS  Max safe tool calls per parallel batch (clamped 1..64, default: 8)

TOOLS
  Bash          Execute shell commands and pentest tools
  Read          Read file contents
  Write         Write/create files
  Edit          Precise string replacement in files
  Glob          Find files by glob pattern
  Grep          Search file contents with regex
  TodoWrite     Task checklist management
  WebFetch      Fetch URL content as plain text
  WebSearch     Search the web
  Agent         Spawn a sub-agent (explore/plan/code-reviewer/general-purpose)
  FindingWrite  Record a vulnerability finding (persisted to .ovogo/findings/)
  FindingList   List all findings with optional filters
  WeaponRadar   Semantic search over 22W internal Nuclei PoC database (BGE-M3)

REPL COMMANDS
  /plan <task>   Run task in plan mode (read-only analysis + confirm before execute)
  /skills        List available skills
  /<skill> [args] Run a built-in or custom skill
  /clear         Clear conversation history
  /history       Show message count
  /model         Show current model
  /cwd           Show working directory
  /help          Show this help
  /exit          Exit ovogogogo

SKILLS (${skills.size} available)
${[...skills.values()].map(s => `  /${s.name.padEnd(14)} ${s.description}`).join('\n')}

HOOKS (configure in .ovogo/settings.json)
  PreToolCall      Runs before each tool call  (env: OVOGO_TOOL_NAME, OVOGO_TOOL_INPUT)
  PostToolCall     Runs after each tool call   (env: OVOGO_TOOL_NAME, OVOGO_TOOL_RESULT, OVOGO_TOOL_IS_ERROR)
  UserPromptSubmit Runs when user submits input (env: OVOGO_PROMPT)

EXAMPLES
  ovogogogo
  ovogogogo "fix the TypeScript errors in src/"
  ovogogogo -m gpt-4o --cwd /my/project "write unit tests"
  echo "install and test" | ovogogogo
`)
}

function runDoctor(cwd: string, skills: Map<string, Skill>, json = false, strict = false): number {
  const { settings, diagnostics } = loadSettingsWithDiagnostics(cwd)
  const hasApiKey = Boolean(process.env.OPENAI_API_KEY)
  const hasSettingsErrors = diagnostics.some((diagnostic) => diagnostic.level === 'error')
  const readableRoots = normalizeRuntimeRoots(cwd, settings.runtime?.readableRoots)
  const writableRoots = normalizeRuntimeRoots(cwd, settings.runtime?.writableRoots)
  const rootDiagnostics = [
    ...diagnoseRuntimeRoots('runtime.readableRoots', readableRoots),
    ...diagnoseRuntimeRoots('runtime.writableRoots', writableRoots),
  ]
  const profileName = settings.profile?.name ?? 'redteam'
  const summary = {
    cwd,
    openaiApiKey: hasApiKey ? 'set' : 'missing',
    settingsStatus: hasSettingsErrors ? 'error' : 'ok',
    skillsIndexed: skills.size,
    profile: {
      name: profileName,
      behavior: profileName === 'generic' ? 'domain-neutral coding agent' : 'legacy redteam prompt',
    },
    runtime: {
      model: settings.runtime?.model ?? process.env.OVOGO_MODEL ?? 'gpt-4o',
      maxIterations: settings.runtime?.maxIterations ?? process.env.OVOGO_MAX_ITER ?? '200',
      maxConcurrentToolCalls: resolveMaxConcurrentToolCalls(
        settings.runtime?.maxConcurrentToolCalls,
        process.env.OVOGO_MAX_CONCURRENT_TOOL_CALLS,
      ),
      permissionMode: settings.runtime?.permissionMode ?? process.env.OVOGO_PERMISSION_MODE ?? 'auto',
    },
    workspace: {
      root: cwd,
      extraRoots: 'sessionDir is added at runtime',
      readableRoots,
      writableRoots,
    },
    diagnostics,
    rootDiagnostics,
  }

  if (json) {
    process.stdout.write(JSON.stringify(summary, null, 2) + '\n')
    return doctorExitCode(hasSettingsErrors, rootDiagnostics.length, strict)
  }

  process.stdout.write(`Ovogo Doctor\n`)
  process.stdout.write(`- cwd: ${summary.cwd}\n`)
  process.stdout.write(`- OPENAI_API_KEY: ${summary.openaiApiKey}\n`)
  process.stdout.write(`- settings: ${summary.settingsStatus}\n`)
  process.stdout.write(`- skills indexed: ${summary.skillsIndexed}\n`)
  process.stdout.write(`- profile.name: ${summary.profile.name}\n`)
  process.stdout.write(`- profile.behavior: ${summary.profile.behavior}\n`)
  process.stdout.write(`- runtime.model: ${summary.runtime.model}\n`)
  process.stdout.write(`- runtime.maxIterations: ${summary.runtime.maxIterations}\n`)
  process.stdout.write(`- runtime.maxConcurrentToolCalls: ${summary.runtime.maxConcurrentToolCalls}\n`)
  process.stdout.write(`- runtime.permissionMode: ${summary.runtime.permissionMode}\n`)
  process.stdout.write(`- workspace.root: ${summary.workspace.root}\n`)
  process.stdout.write(`- workspace.extraRoots: ${summary.workspace.extraRoots}\n`)
  process.stdout.write(`- workspace.readableRoots: ${summary.workspace.readableRoots.join(', ') || '(none)'}\n`)
  process.stdout.write(`- workspace.writableRoots: ${summary.workspace.writableRoots.join(', ') || '(none)'}\n`)

  for (const diagnostic of diagnostics) {
    process.stdout.write(`- ${diagnostic.level}: ${diagnostic.path}: ${diagnostic.message}\n`)
  }
  for (const diagnostic of rootDiagnostics) {
    process.stdout.write(`- warning: ${diagnostic}\n`)
  }

  return doctorExitCode(hasSettingsErrors, rootDiagnostics.length, strict)
}

function doctorExitCode(hasSettingsErrors: boolean, rootDiagnosticCount: number, strict: boolean): number {
  if (hasSettingsErrors) return 1
  if (strict && rootDiagnosticCount > 0) return 2
  return 0
}

function normalizeRuntimeRoots(cwd: string, roots: string[] | undefined): string[] {
  return (roots ?? []).map((root) => resolve(cwd, root))
}

function diagnoseRuntimeRoots(label: string, roots: string[]): string[] {
  return roots.flatMap((root, index) => {
    if (!existsSync(root)) return [`${label}[${index}] does not exist: ${root}`]
    try {
      if (!statSync(root).isDirectory()) return [`${label}[${index}] is not a directory: ${root}`]
    } catch (err: unknown) {
      return [`${label}[${index}] cannot be inspected: ${(err as Error).message}`]
    }
    return []
  })
}

function runEventsSummary(
  sessionDir: string,
  json = false,
  strict = false,
  options: {
    eventType?: string
    eventSource?: string
    eventTags?: string[]
    eventSince?: string
    eventLimit?: number
  } = {},
): number {
  const eventLog = new EventLog(resolve(sessionDir))
  const stats = eventLog.stats()
  const hasEventFilter = Boolean(options.eventType || options.eventSource || options.eventSince || options.eventTags?.length)
  const shouldIncludeEvents = hasEventFilter || options.eventLimit !== undefined
  const eventLimit = options.eventLimit ?? (hasEventFilter ? 20 : 0)
  const recentEvents = shouldIncludeEvents
    ? eventLog.query({
        type: options.eventType as any,
        source: options.eventSource,
        tags: options.eventTags,
        since: options.eventSince,
        limit: eventLimit,
      })
    : []
  const summary = {
    sessionDir: resolve(sessionDir),
    eventsFile: eventLog.getFilePath(),
    filters: {
      eventType: options.eventType,
      eventSource: options.eventSource,
      eventTags: options.eventTags,
      eventSince: options.eventSince,
      eventLimit: shouldIncludeEvents ? eventLimit : undefined,
    },
    recentEvents,
    ...stats,
  }

  if (json) {
    process.stdout.write(JSON.stringify(summary, null, 2) + '\n')
    return strict && summary.invalidLines > 0 ? 2 : 0
  }

  process.stdout.write(`Ovogo Events\n`)
  process.stdout.write(`- sessionDir: ${summary.sessionDir}\n`)
  process.stdout.write(`- eventsFile: ${summary.eventsFile}\n`)
  process.stdout.write(`- total: ${summary.total}\n`)
  process.stdout.write(`- invalidLines: ${summary.invalidLines}\n`)
  process.stdout.write(`- firstTimestamp: ${summary.firstTimestamp ?? '(none)'}\n`)
  process.stdout.write(`- lastTimestamp: ${summary.lastTimestamp ?? '(none)'}\n`)
  if (shouldIncludeEvents) {
    const filters = [
      summary.filters.eventType ? `type=${summary.filters.eventType}` : undefined,
      summary.filters.eventSource ? `source=${summary.filters.eventSource}` : undefined,
      summary.filters.eventTags?.length ? `tags=${summary.filters.eventTags.join(',')}` : undefined,
      summary.filters.eventSince ? `since=${summary.filters.eventSince}` : undefined,
      `limit=${eventLimit}`,
    ].filter(Boolean).join(' ')
    process.stdout.write(`- filters: ${filters}\n`)
    process.stdout.write(`- recentEvents (${summary.recentEvents.length}):\n`)
    for (const event of summary.recentEvents) {
      process.stdout.write(`  - ${event.timestamp} ${event.type} ${event.source} ${event.id}\n`)
    }
  }
  process.stdout.write(`- byType:\n`)
  for (const [type, count] of Object.entries(summary.byType).sort()) {
    process.stdout.write(`  - ${type}: ${count}\n`)
  }
  process.stdout.write(`- bySource:\n`)
  for (const [source, count] of Object.entries(summary.bySource).sort()) {
    process.stdout.write(`  - ${source}: ${count}\n`)
  }

  return strict && summary.invalidLines > 0 ? 2 : 0
}

function runArtifactsSummary(
  sessionDir: string,
  json = false,
  strict = false,
  options: { artifactLimit?: number } = {},
): number {
  const store = new ArtifactStore(resolve(sessionDir))
  const diagnostics = store.readManifestWithDiagnostics()
  const artifactLimit = options.artifactLimit ?? 20
  const recentArtifacts = diagnostics.entries.slice(-artifactLimit)
  const totalBytes = diagnostics.entries.reduce((sum, artifact) => sum + artifact.bytes, 0)
  const summary = {
    sessionDir: resolve(sessionDir),
    manifestFile: store.getManifestPath(),
    total: diagnostics.entries.length,
    invalidLines: diagnostics.invalidLines,
    totalBytes,
    artifactLimit,
    recentArtifacts,
  }

  if (json) {
    process.stdout.write(JSON.stringify(summary, null, 2) + '\n')
    return strict && summary.invalidLines > 0 ? 2 : 0
  }

  process.stdout.write(`Ovogo Artifacts\n`)
  process.stdout.write(`- sessionDir: ${summary.sessionDir}\n`)
  process.stdout.write(`- manifestFile: ${summary.manifestFile}\n`)
  process.stdout.write(`- total: ${summary.total}\n`)
  process.stdout.write(`- invalidLines: ${summary.invalidLines}\n`)
  process.stdout.write(`- totalBytes: ${summary.totalBytes}\n`)
  process.stdout.write(`- recentArtifacts (${summary.recentArtifacts.length}):\n`)
  for (const artifact of summary.recentArtifacts) {
    process.stdout.write(`  - ${artifact.createdAt} ${artifact.bytes}B ${artifact.sha256} ${artifact.path}\n`)
  }

  return strict && summary.invalidLines > 0 ? 2 : 0
}

// ─────────────────────────────────────────────────────────────
// Session directory — 按目标+时间戳隔离扫描输出
// ─────────────────────────────────────────────────────────────

function createSessionDir(cwd: string, primaryTarget?: string): string {
  const targetSlug = (primaryTarget ?? 'session')
    .replace(/^https?:\/\//, '')
    .replace(/[^a-zA-Z0-9._-]/g, '_')
    .replace(/_+/g, '_')
    .slice(0, 64)

  const ts = new Date()
    .toISOString()
    .replace('T', '_')
    .replace(/:/g, '')
    .slice(0, 15)   // YYYYMMDD_HHMMSS

  const dirName = `${targetSlug}_${ts}`
  const sessionDir = join(cwd, 'sessions', dirName)
  mkdirSync(sessionDir, { recursive: true })
  return sessionDir
}

// ─────────────────────────────────────────────────────────────
// Progress log (断点续传)
// ─────────────────────────────────────────────────────────────

function updateProgressLog(cwd: string, step: string, nextAction: string): void {
  try {
    const log = {
      current_step: step,
      next_action: redactText(nextAction),
      timestamp: new Date().toISOString(),
      cwd,
    }
    writeFileSync(
      resolve(cwd, 'ovogo_progress.json'),
      JSON.stringify(log, null, 2),
      'utf8',
    )
  } catch {
    // best-effort
  }
}

// ─────────────────────────────────────────────────────────────
// Plan mode handler
// ─────────────────────────────────────────────────────────────

async function runPlanMode(
  task: string,
  engine: ExecutionEngine,
  planConfig: EngineConfig,
  renderer: Renderer,
  input: InputHandler,
  history: OpenAIMessage[],
  cwd: string,
): Promise<void> {
  renderer.planModeStart()
  renderer.humanPrompt(`[PLAN] ${task}`)
  updateProgressLog(cwd, 'planning', task.slice(0, 100))

  // Run with read-only plan engine (copy of history so it stays pristine)
  const planEngine = new ExecutionEngine(planConfig, renderer)
  try {
    await planEngine.runTurn(task, [...history])
  } catch (err: unknown) {
    renderer.error(`Plan error: ${(err as Error).message}`)
    return
  }

  // Ask for confirmation
  renderer.planConfirmPrompt()
  const { text: answer, eof } = await input.readLine('')
  if (eof) return

  const confirmed = answer.trim().toLowerCase()
  if (confirmed === 'y' || confirmed === 'yes') {
    renderer.info('Executing plan...')
    renderer.humanPrompt(task)
    updateProgressLog(cwd, 'running', task.slice(0, 100))

    const startMs = Date.now()
    try {
      const { result, newHistory } = await engine.runTurn(task, history)
      history.length = 0
      history.push(...trimHistoryForNextTurn(newHistory))
      const elapsed = ((Date.now() - startMs) / 1000).toFixed(1)
      renderer.info(`Done in ${elapsed}s · ${result.reason}`)
    } catch (err: unknown) {
      renderer.error(`Execution error: ${(err as Error).message}`)
    }
    updateProgressLog(cwd, 'idle', 'waiting for next task')
  } else {
    renderer.info('Plan cancelled.')
    updateProgressLog(cwd, 'idle', 'waiting for next task')
  }
}

// ─────────────────────────────────────────────────────────────
// Built-in REPL commands
// ─────────────────────────────────────────────────────────────

async function handleBuiltin(
  cmd: string,
  history: OpenAIMessage[],
  engine: ExecutionEngine,
  renderer: Renderer,
  cwd: string,
  skills: Map<string, Skill>,
): Promise<boolean | 'exit' | { skill: Skill; args: string }> {
  const parts = cmd.split(/\s+/)
  const command = parts[0]
  const rest = parts.slice(1).join(' ')

  switch (command) {
    case '/exit':
    case '/quit':
      renderer.info('Goodbye.')
      return 'exit'

    case '/clear':
      history.length = 0
      renderer.success('History cleared.')
      return true

    case '/history':
      renderer.info(`Session: ${history.length} messages in history`)
      return true

    case '/model':
      renderer.info(`Model: ${engine.getModel()}`)
      return true

    case '/cwd':
      renderer.info(`Working directory: ${cwd}`)
      return true

    case '/skills': {
      renderer.newline()
      if (skills.size === 0) {
        renderer.info('No skills available.')
        return true
      }
      const bySource = new Map<string, Skill[]>()
      for (const s of skills.values()) {
        const list = bySource.get(s.source) ?? []
        list.push(s)
        bySource.set(s.source, list)
      }
      for (const [source, list] of bySource) {
        process.stdout.write(`  \x1b[2m── ${source} ──\x1b[0m\n`)
        for (const s of list) {
          process.stdout.write(`  \x1b[36m/${s.name.padEnd(16)}\x1b[0m \x1b[2m${s.description}\x1b[0m\n`)
        }
      }
      renderer.newline()
      return true
    }

    case '/help': {
      renderer.newline()
      const COMMANDS = {
        '/plan <task>': 'Plan mode — analyze then confirm before execute',
        '/skills':      'List available skills',
        '/<skill>':     'Run a skill (e.g. /commit, /review)',
        '/clear':       'Clear conversation history',
        '/history':     'Show message count in session',
        '/model':       'Show current model',
        '/cwd':         'Show working directory',
        '/help':        'Show this help',
        '/exit':        'Exit ovogogogo',
      }
      for (const [c, desc] of Object.entries(COMMANDS)) {
        process.stdout.write(`  \x1b[36m${c.padEnd(20)}\x1b[0m ${desc}\n`)
      }
      renderer.newline()
      return true
    }

    default: {
      // Check if command matches a loaded skill
      const skillName = command.slice(1) // strip leading /
      const skill = skills.get(skillName)
      if (skill) {
        return { skill, args: rest }
      }
      renderer.warn(`Unknown command: ${command}. Type /help for available commands.`)
      return true
    }
  }
}

// ─────────────────────────────────────────────────────────────
// REPL — interactive conversation loop
// ─────────────────────────────────────────────────────────────

async function runRepl(
  engine: ExecutionEngine,
  planConfig: EngineConfig,
  renderer: Renderer,
  cwd: string,
  skills: Map<string, Skill>,
  hookRunner: { runUserPromptSubmit: (p: string) => void },
): Promise<void> {
  const input = new InputHandler()
  const history: OpenAIMessage[] = []

  renderer.info(`Type your task and press Enter · /plan /skills /help /exit`)
  renderer.info(`ESC to pause/inject · Ctrl+D to exit`)

  let running = false
  // Whether we are currently awaiting the user's interrupt-prompt input
  // (prevents a second ESC from re-triggering softAbort while reading feedback)
  let awaitingInput = false

  // ── ESC key: soft pause ───────────────────────────────────────
  // readline in terminal mode calls readline.emitKeypressEvents(stdin) internally,
  // so stdin already emits 'keypress' events by the time we get here.
  // Debounce: only one soft abort per 800ms to prevent rapid repeated triggers.
  let lastEscMs = 0
  process.stdin.on('keypress', (_str: unknown, key: { name?: string }) => {
    if (key?.name === 'escape' && running && !awaitingInput) {
      const now = Date.now()
      if (now - lastEscMs < 800) return
      lastEscMs = now
      engine.softAbort()
      renderer.stopSpinner()
      process.stdout.write('\n')
      renderer.warn('⚡ 正在暂停... 当前工具完成后停止，请稍候')
    }
  })

  // ── Ctrl+C: hard kill (no two-stage logic) ───────────────────
  process.on('SIGINT', () => {
    if (running) {
      engine.abort()
      renderer.stopSpinner()
      renderer.warn('已取消。')
      running = false
    } else {
      // 不在运行中：第二次 Ctrl+C = 真正退出（cleanup 由 process.on('exit') 处理）
      renderer.newline()
      renderer.info('Goodbye.')
      process.exit(0)
    }
  })

  /**
   * Run one task (or task continuation) through the engine.
   * Handles the soft-interrupt resume loop internally.
   */
  async function runTask(prompt: string, taskHistory: OpenAIMessage[], startMs: number): Promise<void> {
    running = true

    let currentPrompt   = prompt
    let currentHistory  = taskHistory

    try {
      while (true) {

        const { result, newHistory } = await engine.runTurn(currentPrompt, currentHistory)

        // Update shared history with latest turn
        history.length = 0
        history.push(...trimHistoryForNextTurn(newHistory))
        currentHistory = [...history]

        if (result.reason === 'interrupted') {
          // ── Soft interrupt: ask user for guidance, then resume ──
          renderer.writeInterruptPrompt()
          awaitingInput = true
          const { text: feedback, eof } = await input.readLine('')
          awaitingInput = false

          if (eof) {
            // Ctrl+D during interrupt prompt = hard exit
            break
          }

          const trimmedFeedback = feedback.trim()
          if (trimmedFeedback) {
            renderer.interruptInjected(trimmedFeedback)
            currentPrompt = `[用户中途介入]\n${trimmedFeedback}\n\n请根据以上建议继续执行任务。`
          } else {
            // Empty Enter = resume silently
            currentPrompt = '[继续] 请继续自主推进任务，无需等待进一步指示。'
          }
          // Continue the while loop → runTurn again with new message
          continue
        }

        // Normal finish (stop / max_iterations / error)
        const elapsed = ((Date.now() - startMs) / 1000).toFixed(1)
        renderer.info(`Done in ${elapsed}s · ${result.reason}`)
        break
      }
    } catch (err: unknown) {
      const error = err as Error
      if (error.name !== 'AbortError') {
        renderer.error(`Error: ${error.message}`)
      }
    } finally {
      running = false
    }
  }

  while (true) {
    renderer.writePrompt()
    const { text, eof } = await input.readLine('')

    if (eof) {
      renderer.newline()
      renderer.info('Goodbye.')
      input.close()
      break
    }

    const trimmed = text.trim()
    if (!trimmed) continue

    // ── /plan command ─────────────────────────────────────────
    if (trimmed.startsWith('/plan')) {
      const planTask = trimmed.slice(5).trim()
      if (!planTask) {
        renderer.warn('Usage: /plan <task description>')
        continue
      }
      hookRunner.runUserPromptSubmit(trimmed)
      await runPlanMode(planTask, engine, planConfig, renderer, input, history, cwd)
      continue
    }

    // ── Other /commands ───────────────────────────────────────
    if (trimmed.startsWith('/')) {
      const result = await handleBuiltin(trimmed, history, engine, renderer, cwd, skills)

      if (result === 'exit') {
        input.close()
        break
      }

      // Skill matched — result is {skill, args}
      if (typeof result === 'object') {
        const { skill, args } = result
        const expandedPrompt = expandSkillPrompt(skill, args)
        renderer.info(`Running skill: /${skill.name}${args ? ' ' + args : ''}`)
        hookRunner.runUserPromptSubmit(trimmed)
        renderer.humanPrompt(expandedPrompt.split('\n')[0] + (expandedPrompt.includes('\n') ? ' …' : ''))
        updateProgressLog(cwd, 'running', `/${skill.name}`)

        await runTask(expandedPrompt, [...history], Date.now())
        updateProgressLog(cwd, 'idle', 'waiting for next task')
        continue
      }

      continue
    }

    // ── Regular task ──────────────────────────────────────────
    renderer.humanPrompt(trimmed)
    hookRunner.runUserPromptSubmit(trimmed)
    updateProgressLog(cwd, 'running', trimmed.slice(0, 100))

    await runTask(trimmed, [...history], Date.now())
    updateProgressLog(cwd, 'idle', 'waiting for next task')
  }

  process.exit(0)
}

// ─────────────────────────────────────────────────────────────
// Single-shot task
// ─────────────────────────────────────────────────────────────

async function runTask(
  engine: ExecutionEngine,
  renderer: Renderer,
  task: string,
  cwd: string,
): Promise<void> {
  renderer.humanPrompt(task)
  updateProgressLog(cwd, 'running', task.slice(0, 100))

  const startMs = Date.now()
  const { result } = await engine.runTurn(task, [])
  const elapsed = ((Date.now() - startMs) / 1000).toFixed(1)

  renderer.info(`Done in ${elapsed}s · ${result.reason}`)
  updateProgressLog(cwd, 'complete', 'done')
}

// ─────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const {
    task,
    model: parsedModel,
    modelProvided,
    maxIter: parsedMaxIter,
    maxIterProvided,
    permissionMode: parsedPermissionMode,
    permissionModeProvided,
    cwd: rawCwd,
    help,
    version,
    orchestrator: useOrchestrator,
    doctor,
    eventsDir,
    artifactsDir,
    eventType,
    eventSource,
    eventTags,
    eventSince,
    eventLimit,
    artifactLimit,
    json,
    strict,
  } = parseArgs(process.argv)
  const cwd = resolve(rawCwd)

  // Load skills early so --help can list them
  const skills = loadSkills(cwd)

  if (version) {
    process.stdout.write(`${VERSION} (ovogogogo)\n`)
    process.exit(0)
  }

  if (help) {
    printHelp(skills)
    process.exit(0)
  }

  if (doctor) {
    process.exit(runDoctor(cwd, skills, json, strict))
  }

  if (eventsDir) {
    process.exit(runEventsSummary(eventsDir, json, strict, {
      eventType,
      eventSource,
      eventTags,
      eventSince,
      eventLimit,
    }))
  }

  if (artifactsDir) {
    process.exit(runArtifactsSummary(artifactsDir, json, strict, { artifactLimit }))
  }

  const apiKey = process.env.OPENAI_API_KEY
  if (!apiKey) {
    process.stderr.write(
      '\x1b[31mError:\x1b[0m OPENAI_API_KEY is not set.\n' +
        'Export it with: export OPENAI_API_KEY=sk-...\n',
    )
    process.exit(1)
  }

  const renderer = new Renderer()

  // Load settings + hooks
  const { settings, diagnostics: settingsDiagnostics } = loadSettingsWithDiagnostics(cwd)
  const model = modelProvided || process.env.OVOGO_MODEL
    ? parsedModel
    : settings.runtime?.model ?? parsedModel
  const maxIter = maxIterProvided || process.env.OVOGO_MAX_ITER
    ? parsedMaxIter
    : settings.runtime?.maxIterations ?? parsedMaxIter
  const maxConcurrentToolCalls = resolveMaxConcurrentToolCalls(
    settings.runtime?.maxConcurrentToolCalls,
    process.env.OVOGO_MAX_CONCURRENT_TOOL_CALLS,
  )
  const permissionMode = permissionModeProvided || process.env.OVOGO_PERMISSION_MODE
    ? parsedPermissionMode
    : settings.runtime?.permissionMode ?? parsedPermissionMode

  renderer.banner(VERSION, model)
  renderer.info(`cwd: ${cwd}`)
  renderer.info(`Runtime: maxIter=${maxIter}, maxConcurrentToolCalls=${maxConcurrentToolCalls}, permissionMode=${permissionMode}`)
  for (const diagnostic of settingsDiagnostics) {
    renderer.warn(`Settings ${diagnostic.level}: ${diagnostic.path} — ${diagnostic.message}`)
  }
  const hookRunner = settings.hooks
    ? new HookRunner(settings.hooks)
    : new NoopHookRunner()

  const hasHooks = Boolean(
    settings.hooks?.PreToolCall?.length ||
    settings.hooks?.PostToolCall?.length ||
    settings.hooks?.UserPromptSubmit?.length,
  )
  if (hasHooks) {
    const count =
      (settings.hooks?.PreToolCall?.length ?? 0) +
      (settings.hooks?.PostToolCall?.length ?? 0) +
      (settings.hooks?.UserPromptSubmit?.length ?? 0)
    renderer.info(`Hooks: ${count} hook(s) loaded from .ovogo/settings.json`)
  }

  // Show loaded skills (project/global only, not builtins)
  const customSkills = [...skills.values()].filter((s) => s.source !== 'builtin')
  if (customSkills.length > 0) {
    renderer.info(`Skills: ${customSkills.length} custom skill(s) loaded — type /skills to list`)
  }

  // Load OVOGO.md files (project + user instructions)
  const ovogoMdFiles = await loadOvogoMd(cwd)
  if (ovogoMdFiles.length > 0) {
    const labels = ovogoMdFiles.map((f) => f.type).join(', ')
    renderer.info(`OVOGO.md: ${ovogoMdFiles.length} file(s) loaded (${labels})`)
  }

  // Initialize memory system
  const memoryDir = getMemoryDir(cwd)
  const memStats = getMemoryStats(memoryDir)
  if (memStats.hasIndex) {
    renderer.info(`Memory: ${memStats.entryCount} entr${memStats.entryCount !== 1 ? 'ies' : 'y'} — ${memoryDir}`)
  } else {
    renderer.info(`Memory: initialized — ${memoryDir}`)
  }

  // Show engagement scope if configured
  const engagement = settings.engagement
  if (engagement) {
    renderer.info(`Engagement: ${engagement.name ?? '未命名'} · 阶段: ${engagement.phase ?? '未设置'}`)
    if (engagement.targets && engagement.targets.length > 0) {
      renderer.info(`Targets: ${engagement.targets.join(', ')}`)
    }
  }

  // Initialize knowledge base (global + project-level)
  const projectSlug = cwd.replace(/[^a-zA-Z0-9]/g, '_').slice(0, 32)
  const projectKnowledgeDir = join(process.env.HOME ?? '', '.ovogo', 'projects', projectSlug, 'knowledge')
  const knowledgeBase = new KnowledgeBase(projectKnowledgeDir)
  const kbStats = knowledgeBase.stats()
  const kbTotal = Object.values(kbStats).reduce((a, b) => a + b, 0)
  if (kbTotal > 0) {
    renderer.info(`Knowledge Base: ${kbTotal} entries (${kbStats.attack_patterns} attack, ${kbStats.cve_notes} CVE, ${kbStats.tool_combos} combos, ${kbStats.target_profiles} profiles)`)
  } else {
    renderer.info(`Knowledge Base: empty — will grow from sessions`)
  }

  // Query relevant knowledge for system prompt injection
  let knowledgePrompt = ''
  if (kbTotal > 0) {
    const targetForQuery = engagement?.targets?.[0] ?? ''
    const entries = targetForQuery
      ? knowledgeBase.searchByTarget(targetForQuery, 15)
      : knowledgeBase.recommend('', 10).map((e) => ({ type: 'attack_patterns' as const, data: e }))
    if (entries.length > 0) {
      knowledgePrompt = knowledgeBase.toPrompt(entries)
      renderer.info(`Knowledge: ${entries.length} entries injected into system prompt`)
    }
  }

  // Create per-session output directory
  const primaryTarget = engagement?.targets?.[0]
  const sessionDir = createSessionDir(cwd, primaryTarget)
  renderer.info(`Session dir: ${sessionDir}`)

  // Initialize sub-agent tmux monitor (creates background tmux session for agent windows)
  const agentLogDir = join(sessionDir, 'agent-logs')
  const layoutReady = tmuxLayout.init(agentLogDir)
  if (layoutReady) {
    renderer.info(`Agent 监控: ${tmuxLayout.sessionHint()}`)
  }

  // Build the full system prompt once (OVOGO.md + memory + engagement + sessionDir + knowledge)
  const memorySection = buildMemorySystemSection(memoryDir)
  const profileName = settings.profile?.name ?? 'redteam'
  renderer.info(`Profile: ${profileName}`)
  const systemPrompt = buildFullSystemPrompt(cwd, ovogoMdFiles, memorySection, engagement, sessionDir, knowledgePrompt, profileName)

  // Load MCP servers (non-fatal if config missing)
  let mcpConnections: ConnectedMcpClient[] = []
  const { tools: mcpTools, connections, errors: mcpErrors } = await loadMcpTools(cwd)
  mcpConnections = connections

  if (mcpTools.length > 0) {
    renderer.info(`MCP: ${mcpTools.length} tool(s) loaded from ${connections.length} server(s)`)
  }
  for (const e of mcpErrors) {
    renderer.warn(`MCP: "${e.server}" failed — ${e.error}`)
  }

  // Initialize optimization components
  const progressTracker = new ProgressTracker()
  const toolCache = new ToolCache()

  // ── New systems: Event Log, Memory, Context Budget, Dispatch ──
  const eventLog = new EventLog(sessionDir)
  renderer.info(`EventLog: ${eventLog.getFilePath()}`)

  // Remove duplicate projectSlug — already declared above
  const semanticMemory = new SemanticMemory(join(process.env.HOME ?? '', '.ovogo', 'projects', projectSlug))
  const episodicMemory = new EpisodicMemory(join(process.env.HOME ?? '', '.ovogo', 'projects', projectSlug))

  const maxCtxTokens = 200_000 // claude-sonnet-4-x default
  const contextBudget = new ContextBudgetManager({
    maxTokens: maxCtxTokens,
    systemPrompt: 5_000,
    memory: 8_000,
    history: 80_000,
    toolResults: 60_000,
    reserved: 8_192,
  })

  const dispatchManager = new DispatchManager()
  setDispatchManager(dispatchManager)

  // Register dispatch completion callback — inject completed results into next turn
  dispatchManager.onCompletion((record) => {
    renderer.info(`[Dispatch] ${record.id} (${record.agentType}) → ${record.status}`)
  })

  const config: EngineConfig = {
    model,
    apiKey,
    baseURL: process.env.OPENAI_BASE_URL,
    maxIterations: maxIter,
    cwd,
    permissionMode,
    extraTools: mcpTools,
    hookRunner,
    systemPrompt,
    sessionDir,   // injected into sub-agent prompts via registerAgentFactory
    primaryTarget,
    engagementTargets: engagement?.targets,
    outOfScopeTargets: engagement?.out_of_scope,
    engagementPhase: engagement?.phase,
    progressTracker,
    toolCache,
    coordinatorMode: true,
    maxConcurrentToolCalls,
    maxContextTokens: maxCtxTokens,
    eventLog,
    contextBudget,
    dispatchManager,
    semanticMemory,
    episodicMemory,
    knowledgeBase: kbTotal > 0 ? knowledgeBase : undefined,
    readableRoots: normalizeRuntimeRoots(cwd, settings.runtime?.readableRoots),
    writableRoots: normalizeRuntimeRoots(cwd, settings.runtime?.writableRoots),
  }

  // Plan-mode config: same system prompt + planMode=true (engine filters write tools)
  const planConfig: EngineConfig = {
    ...config,
    planMode: true,
  }

  const engine = new ExecutionEngine(config, renderer)

  // Register agent factory so AgentTool can spawn child engines
  registerAgentFactory(
    (childConfig, childRenderer) => new ExecutionEngine(childConfig as EngineConfig, childRenderer as Renderer),
    config,
    renderer,
  )

  // Cleanup MCP connections + tmux session on exit
  let cleanedUp = false
  const cleanup = () => {
    if (cleanedUp) return
    cleanedUp = true
    tmuxLayout.destroy()
    disconnectAll(mcpConnections).catch(() => {})
  }
  process.on('exit', cleanup)
  process.on('SIGTERM', () => { cleanup(); process.exit(0) })
  process.on('SIGHUP',  () => { cleanup(); process.exit(0) })

  // ── Orchestrator mode: state machine supervisor ──────────────
  if (useOrchestrator) {
    const primaryTarget = engagement?.targets?.[0] ?? ''
    const orchestratorInstance = new BattleOrchestrator(
      {
        model,
        apiKey,
        baseURL: process.env.OPENAI_BASE_URL,
        sessionDir,
        primaryTarget: primaryTarget || undefined,
        engagement,
        cwd,
      },
      renderer,
      engine,
      maxIter,
    )

    const initialTask = task ?? '对目标进行完整渗透测试'
    await orchestratorInstance.run(initialTask)
    return
  }

  // Pipe input?
  if (!process.stdin.isTTY) {
    const piped = await readStdin()
    if (piped) {
      hookRunner.runUserPromptSubmit(piped)
      await runTask(engine, renderer, piped, cwd)
      return
    }
  }

  // Single task from args?
  if (task) {
    hookRunner.runUserPromptSubmit(task)
    await runTask(engine, renderer, task, cwd)
    return
  }

  // Interactive REPL
  await runRepl(engine, planConfig, renderer, cwd, skills, hookRunner)
}

main().catch((err: unknown) => {
  process.stderr.write(`\x1b[31mFatal:\x1b[0m ${(err as Error).message}\n`)
  process.exit(1)
})
