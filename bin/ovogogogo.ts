#!/usr/bin/env node
/**
 * ovogogogo — Autonomous Code Execution Engine
 *
 * Claude Code-style interactive CLI. No React, no Ink — pure terminal.
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
 */

import { resolve } from 'path'
import { writeFileSync } from 'fs'
import { ExecutionEngine } from '../src/core/engine.js'
import { Renderer } from '../src/ui/renderer.js'
import { InputHandler, readStdin } from '../src/ui/input.js'
import type { EngineConfig, OpenAIMessage } from '../src/core/types.js'
import { registerAgentFactory } from '../src/tools/agent.js'
import { loadMcpTools, disconnectAll } from '../src/services/mcp/loader.js'
import type { ConnectedMcpClient } from '../src/services/mcp/client.js'

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
  let maxIter = parseInt(process.env.OVOGO_MAX_ITER ?? '30', 10)
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

function printHelp(): void {
  const r = new Renderer()
  r.banner(VERSION, 'gpt-4o')
  process.stdout.write(`USAGE
  ovogogogo [options] [task]

OPTIONS
  -m, --model <model>    LLM model  (env: OVOGO_MODEL, default: gpt-4o)
  --max-iter <n>         Think-Act-Observe max cycles  (env: OVOGO_MAX_ITER, default: 30)
  --cwd <path>           Working directory  (env: OVOGO_CWD, default: cwd)
  -v, --version          Print version and exit
  -h, --help             Show this help

ENVIRONMENT
  OPENAI_API_KEY         Required — OpenAI API key
  OPENAI_BASE_URL        Optional — compatible endpoint URL

TOOLS
  Bash       Execute shell commands
  Read       Read file contents
  Write      Write/create files
  Edit       Precise string replacement in files
  Glob       Find files by glob pattern
  Grep       Search file contents with regex
  TodoWrite  Task checklist management
  WebFetch   Fetch URL content as plain text
  WebSearch  Search the web (set OVOGO_SEARCH_API_KEY or SERPAPI_KEY for better results)

EXAMPLES
  ovogogogo
  ovogogogo "fix the TypeScript errors in src/"
  ovogogogo -m gpt-4o --cwd /my/project "write unit tests"
  echo "install and test" | ovogogogo
`)
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
// REPL — interactive conversation loop
// ─────────────────────────────────────────────────────────────

const BUILTIN_COMMANDS: Record<string, string> = {
  '/clear': 'Clear conversation history',
  '/history': 'Show message count in current session',
  '/model': 'Show current model',
  '/cwd': 'Show current working directory',
  '/help': 'Show available commands',
  '/exit': 'Exit ovogogogo',
}

async function runRepl(
  engine: ExecutionEngine,
  renderer: Renderer,
  cwd: string,
): Promise<void> {
  const input = new InputHandler()
  const history: OpenAIMessage[] = []

  renderer.info(`Type your task and press Enter. ${Object.keys(BUILTIN_COMMANDS).join(' | ')}`)
  renderer.info(`Ctrl+C to cancel a running task · Ctrl+D to exit`)

  let running = false // true while engine is processing

  // Ctrl+C handling — cancel current turn if running
  let abortController = new AbortController()
  process.on('SIGINT', () => {
    if (running) {
      renderer.stopSpinner()
      renderer.warn('Cancelled.')
      abortController.abort()
      abortController = new AbortController()
      running = false
      // Re-draw prompt
      renderer.writePrompt()
    } else {
      renderer.newline()
      renderer.info('Press Ctrl+D or type /exit to quit.')
      renderer.writePrompt()
    }
  })

  // Main REPL loop
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

    // Built-in commands
    if (trimmed.startsWith('/')) {
      const handled = await handleBuiltin(trimmed, history, engine, renderer, cwd)
      if (handled === 'exit') {
        input.close()
        break
      }
      if (handled) continue
    }

    // Display user message
    renderer.humanPrompt(trimmed)
    updateProgressLog(cwd, 'running', trimmed.slice(0, 100))

    // Run the engine
    running = true
    const startMs = Date.now()

    try {
      const { result, newHistory } = await engine.runTurn(trimmed, history)

      // Update rolling history (keep last 40 messages to avoid context explosion)
      history.length = 0
      const keep = newHistory.slice(-40)
      history.push(...keep)

      const elapsed = ((Date.now() - startMs) / 1000).toFixed(1)
      renderer.info(`Done in ${elapsed}s · ${result.reason}`)
    } catch (err: unknown) {
      const error = err as Error
      if (error.name === 'AbortError') {
        // Already handled by SIGINT
      } else {
        renderer.error(`Error: ${error.message}`)
      }
    } finally {
      running = false
    }

    updateProgressLog(cwd, 'idle', 'waiting for next task')
  }

  process.exit(0)
}

async function handleBuiltin(
  cmd: string,
  history: OpenAIMessage[],
  engine: ExecutionEngine,
  renderer: Renderer,
  cwd: string,
): Promise<boolean | 'exit'> {
  const parts = cmd.split(/\s+/)
  const command = parts[0]

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

    case '/help':
      renderer.newline()
      for (const [cmd, desc] of Object.entries(BUILTIN_COMMANDS)) {
        process.stdout.write(`  \x1b[36m${cmd.padEnd(12)}\x1b[0m ${desc}\n`)
      }
      renderer.newline()
      return true

    default:
      renderer.warn(`Unknown command: ${command}. Type /help for available commands.`)
      return true
  }
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

  if (version) {
    process.stdout.write(`${VERSION} (ovogogogo)\n`)
    process.exit(0)
  }

  if (help) {
    printHelp()
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

  const cwd = resolve(rawCwd)
  const renderer = new Renderer()

  renderer.banner(VERSION, model)
  renderer.info(`cwd: ${cwd}`)

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
      await runTask(engine, renderer, piped, cwd)
      return
    }
  }

  // Single task from args?
  if (task) {
    await runTask(engine, renderer, task, cwd)
    return
  }

  // Interactive REPL
  await runRepl(engine, renderer, cwd)
}

main().catch((err: unknown) => {
  process.stderr.write(`\x1b[31mFatal:\x1b[0m ${(err as Error).message}\n`)
  process.exit(1)
})
