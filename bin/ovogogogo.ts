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
import { writeFileSync, mkdirSync } from 'fs'
import { ExecutionEngine } from '../src/core/engine.js'
import { Renderer } from '../src/ui/renderer.js'
import { InputHandler, readStdin } from '../src/ui/input.js'
import type { EngineConfig, OpenAIMessage } from '../src/core/types.js'
import { registerAgentFactory } from '../src/tools/agent.js'
import { loadMcpTools, disconnectAll } from '../src/services/mcp/loader.js'
import type { ConnectedMcpClient } from '../src/services/mcp/client.js'
import { loadSettings } from '../src/config/settings.js'
import { HookRunner, NoopHookRunner } from '../src/config/hooks.js'
import { loadSkills, expandSkillPrompt } from '../src/skills/loader.js'
import type { Skill } from '../src/skills/loader.js'
import { loadOvogoMd } from '../src/config/ovogomd.js'
import { getMemoryDir, buildMemorySystemSection, getMemoryStats } from '../src/memory/index.js'
import { buildFullSystemPrompt } from '../src/prompts/system.js'

const VERSION = '0.1.0'

// ─────────────────────────────────────────────────────────────
// Arg parsing
// ─────────────────────────────────────────────────────────────

interface Args {
  task?: string
  model: string
  maxIter: number
  cwd: string
  help: boolean
  version: boolean
}

function parseArgs(argv: string[]): Args {
  const args = argv.slice(2)
  let task: string | undefined
  let model = process.env.OVOGO_MODEL ?? 'gpt-4o'
  let maxIter = parseInt(process.env.OVOGO_MAX_ITER ?? '200', 10)
  let cwd = process.env.OVOGO_CWD ?? process.cwd()
  let help = false
  let version = false

  for (let i = 0; i < args.length; i++) {
    const arg = args[i]
    switch (arg) {
      case '--help': case '-h': help = true; break
      case '--version': case '-v': case '-V': version = true; break
      case '--model': case '-m': model = args[++i] ?? model; break
      case '--max-iter': maxIter = parseInt(args[++i] ?? '30', 10); break
      case '--cwd': cwd = args[++i] ?? cwd; break
      default:
        if (!arg.startsWith('-')) task = task ? task + ' ' + arg : arg
    }
  }
  return { task, model, maxIter, cwd, help, version }
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
  --cwd <path>           Working directory  (env: OVOGO_CWD, default: cwd)
  -v, --version          Print version and exit
  -h, --help             Show this help

ENVIRONMENT
  OPENAI_API_KEY         Required — OpenAI API key
  OPENAI_BASE_URL        Optional — compatible endpoint URL

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
      next_action: nextAction,
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
      history.push(...newHistory.slice(-40))
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
): Promise<boolean | 'exit'> {
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
        return { skill, args: rest } as unknown as boolean // signal to caller
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
  renderer.info(`Ctrl+C to cancel · Ctrl+D to exit`)

  let running = false

  // Ctrl+C: if a turn is running, tell the engine to abort it.
  // engine.abort() propagates via AbortSignal into Bash (kills process group)
  // and WebFetch (cancels the HTTP request)
  process.on('SIGINT', () => {
    if (running) {
      engine.abort()
      renderer.stopSpinner()
      renderer.warn('Cancelled.')
      running = false
      renderer.writePrompt()
    } else {
      renderer.newline()
      renderer.info('Press Ctrl+D or type /exit to quit.')
      renderer.writePrompt()
    }
  })

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

    // ── /plan command — needs full REPL context ──────────────
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

    // ── Other /commands ──────────────────────────────────────
    if (trimmed.startsWith('/')) {
      const result = await handleBuiltin(trimmed, history, engine, renderer, cwd, skills)

      if (result === 'exit') {
        input.close()
        break
      }

      // Skill matched — result is {skill, args}
      if (result !== true && result !== false && typeof result === 'object') {
        const { skill, args } = result as unknown as { skill: Skill; args: string }
        const expandedPrompt = expandSkillPrompt(skill, args)
        renderer.info(`Running skill: /${skill.name}${args ? ' ' + args : ''}`)
        hookRunner.runUserPromptSubmit(trimmed)
        renderer.humanPrompt(expandedPrompt.split('\n')[0] + (expandedPrompt.includes('\n') ? ' …' : ''))
        updateProgressLog(cwd, 'running', `/${skill.name}`)

        running = true
        const startMs = Date.now()
        try {
          const { result: r, newHistory } = await engine.runTurn(expandedPrompt, history)
          history.length = 0
          history.push(...newHistory.slice(-40))
          const elapsed = ((Date.now() - startMs) / 1000).toFixed(1)
          renderer.info(`Done in ${elapsed}s · ${r.reason}`)
        } catch (err: unknown) {
          renderer.error(`Error: ${(err as Error).message}`)
        } finally {
          running = false
        }
        updateProgressLog(cwd, 'idle', 'waiting for next task')
        continue
      }

      continue
    }

    // ── Regular task ──────────────────────────────────────────
    renderer.humanPrompt(trimmed)

    // UserPromptSubmit hook
    hookRunner.runUserPromptSubmit(trimmed)

    updateProgressLog(cwd, 'running', trimmed.slice(0, 100))

    running = true
    const startMs = Date.now()

    try {
      const { result, newHistory } = await engine.runTurn(trimmed, history)

      history.length = 0
      history.push(...newHistory.slice(-40))

      const elapsed = ((Date.now() - startMs) / 1000).toFixed(1)
      renderer.info(`Done in ${elapsed}s · ${result.reason}`)
    } catch (err: unknown) {
      const error = err as Error
      if (error.name !== 'AbortError') {
        renderer.error(`Error: ${error.message}`)
      }
    } finally {
      running = false
    }

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
  const { task, model, maxIter, cwd: rawCwd, help, version } = parseArgs(process.argv)
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

  const apiKey = process.env.OPENAI_API_KEY
  if (!apiKey) {
    process.stderr.write(
      '\x1b[31mError:\x1b[0m OPENAI_API_KEY is not set.\n' +
        'Export it with: export OPENAI_API_KEY=sk-...\n',
    )
    process.exit(1)
  }

  const renderer = new Renderer()
  renderer.banner(VERSION, model)
  renderer.info(`cwd: ${cwd}`)

  // Load settings + hooks
  const settings = loadSettings(cwd)
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

  // Create per-session output directory
  const primaryTarget = engagement?.targets?.[0]
  const sessionDir = createSessionDir(cwd, primaryTarget)
  renderer.info(`Session dir: ${sessionDir}`)

  // Build the full system prompt once (OVOGO.md + memory + engagement + sessionDir injected)
  const memorySection = buildMemorySystemSection(memoryDir)
  const systemPrompt = buildFullSystemPrompt(cwd, ovogoMdFiles, memorySection, engagement, sessionDir)

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

  const config: EngineConfig = {
    model,
    apiKey,
    baseURL: process.env.OPENAI_BASE_URL,
    maxIterations: maxIter,
    cwd,
    permissionMode: 'auto',
    extraTools: mcpTools,
    hookRunner,
    systemPrompt,
    sessionDir,   // injected into sub-agent prompts via registerAgentFactory
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

  // Cleanup MCP connections on exit
  const cleanup = () => disconnectAll(mcpConnections).catch(() => {})
  process.on('exit', cleanup)
  process.on('SIGTERM', () => { cleanup(); process.exit(0) })

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
