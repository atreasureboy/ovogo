/**
 * Terminal UI Renderer — modern terminal aesthetic
 *
 * Visual design:
 * - Gradient OVOGO ASCII art banner
 * - Colored left-border stripes per section type
 * - Box-framed tool call display
 * - Consistent icon system for status messages
 * - Styled REPL prompt with phase indicator
 * - Braille spinner with rotating verbs
 * - Per-tool color coding
 *
 * Supports writing to a custom stream (e.g. a file WriteStream for sub-agent panes).
 * Use Renderer.forFile(path) to create a file-backed renderer.
 */

import { createWriteStream } from 'fs'
import type { WriteStream } from 'fs'
import { redactText } from '../core/redaction.js'

// ─────────────────────────────────────────────────────────────
// ANSI helpers
// ─────────────────────────────────────────────────────────────

const ESC = '\x1b['
const RESET = '\x1b[0m'
const BOLD = '\x1b[1m'
const DIM = '\x1b[2m'
const ITALIC = '\x1b[3m'

// Foreground colors
const FG = {
  black: `${ESC}30m`,
  red: `${ESC}31m`,
  green: `${ESC}32m`,
  yellow: `${ESC}33m`,
  blue: `${ESC}34m`,
  magenta: `${ESC}35m`,
  cyan: `${ESC}36m`,
  white: `${ESC}37m`,
  brightBlack: `${ESC}90m`,
  brightRed: `${ESC}91m`,
  brightGreen: `${ESC}92m`,
  brightYellow: `${ESC}93m`,
  brightBlue: `${ESC}94m`,
  brightMagenta: `${ESC}95m`,
  brightCyan: `${ESC}96m`,
  brightWhite: `${ESC}97m`,
}

// Background colors
const BG = {
  blue: `${ESC}44m`,
  magenta: `${ESC}45m`,
  brightBlack: `${ESC}100m`,
  brightRed: `${ESC}101m`,
  brightGreen: `${ESC}102m`,
  brightYellow: `${ESC}103m`,
  brightBlue: `${ESC}104m`,
  brightMagenta: `${ESC}105m`,
  brightCyan: `${ESC}106m`,
}

// Cursor
const CURSOR = {
  up: (n: number) => `${ESC}${n}A`,
  down: (n: number) => `${ESC}${n}B`,
  col: (n: number) => `${ESC}${n}G`,
  save: `${ESC}s`,
  restore: `${ESC}u`,
  hide: `${ESC}?25l`,
  show: `${ESC}?25h`,
  clearLine: `${ESC}2K`,
  clearToEnd: `${ESC}0K`,
}

function stripAnsi(value: string): string {
  return value.replace(/\x1b\[[0-9;?]*[ -/]*[@-~]/g, '')
}

// ─────────────────────────────────────────────────────────────
// OVOGO ASCII art logo — gradient-ready lines
// ─────────────────────────────────────────────────────────────

const LOGO_LINES = [
  ' ██████╗ ██╗   ██╗ ██████╗  ██████╗  ██████╗ ',
  '██╔═══██╗██║   ██║██╔═══██╗██╔════╝ ██╔═══██╗',
  '██║   ██║╚██╗ ██╔╝██║   ██║██║  ███╗██║   ██║',
  '╚██████╔╝ ╚████╔╝ ╚██████╔╝╚██████╔╝╚██████╔╝',
  ' ╚═════╝   ╚═══╝   ╚═════╝  ╚═════╝  ╚═════╝ ',
]

// Gradient colors for logo (magenta → cyan → green)
const LOGO_GRADIENT = [
  FG.brightMagenta,
  FG.magenta,
  FG.brightBlue,
  FG.brightCyan,
  FG.brightGreen,
]

// ─────────────────────────────────────────────────────────────
// Spinner frames (Braille Unicode)
// ─────────────────────────────────────────────────────────────

const SPINNER_FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']

export const SPINNER_VERBS = [
  'Analyzing',   'Architecting',  'Computing',   'Crafting',
  'Decoding',    'Deliberating',  'Engineering', 'Executing',
  'Exploring',   'Generating',    'Hacking',     'Inferring',
  'Mapping',     'Orchestrating', 'Pondering',   'Probing',
  'Reasoning',   'Ruminating',    'Scanning',    'Synthesizing',
  'Thinking',    'Vibing',        'Wrangling',
]

// ─────────────────────────────────────────────────────────────
// Word wrap utility
// ─────────────────────────────────────────────────────────────

export function wrapText(text: string, width: number, indent = ''): string {
  if (!text) return ''
  const lines: string[] = []
  const paragraphs = text.split('\n')
  for (const paragraph of paragraphs) {
    if (!paragraph.trim()) {
      lines.push('')
      continue
    }
    const words = paragraph.split(' ')
    let line = indent
    for (const word of words) {
      if (line.length + word.length + 1 > width && line.trim()) {
        lines.push(line.trimEnd())
        line = indent + word + ' '
      } else {
        line += word + ' '
      }
    }
    if (line.trim()) lines.push(line.trimEnd())
  }
  return lines.join('\n')
}

// ─────────────────────────────────────────────────────────────
// Stripe helpers — colored left-border per section type
// ─────────────────────────────────────────────────────────────

const STRIPE = {
  user:     `${FG.brightBlue}│${RESET}`,
  assistant:`${FG.brightCyan}│${RESET}`,
  tool:     `${FG.brightYellow}┃${RESET}`,
  result:   `${FG.brightGreen}│${RESET}`,
  error:    `${FG.brightRed}│${RESET}`,
  agent:    `${FG.brightMagenta}│${RESET}`,
  compact:  `${FG.yellow}│${RESET}`,
  info:     `${FG.brightBlack}│${RESET}`,
  dispatch: `${FG.cyan}│${RESET}`,
}

// ─────────────────────────────────────────────────────────────
// Renderer class
// ─────────────────────────────────────────────────────────────

export class Renderer {
  private spinnerInterval: NodeJS.Timeout | null = null
  private spinnerFrame = 0
  private spinnerVerbIndex = 0
  private spinnerVerbRotateCounter = 0
  private lastSpinnerLineLen = 0
  private termWidth: number
  private _assistantLineStarted = false

  /** Instance-level write function */
  private write: (s: string) => void
  /** Whether the output stream is a real TTY */
  private isTTY: boolean

  constructor(options?: { stream?: NodeJS.WritableStream; redactOutput?: boolean }) {
    const stream = options?.stream ?? process.stdout
    this.write = (s: string) => {
      stream.write(options?.redactOutput ? redactText(stripAnsi(s)) : s)
    }
    this.isTTY = (stream as NodeJS.WriteStream).isTTY === true
    this.termWidth = this.isTTY ? ((stream as NodeJS.WriteStream).columns ?? 80) : 80
    if (this.isTTY) {
      (stream as NodeJS.WriteStream).on?.('resize', () => {
        this.termWidth = (stream as NodeJS.WriteStream).columns ?? 80
      })
    }
  }

  static forFile(filePath: string): Renderer {
    const fileStream = createWriteStream(filePath, { flags: 'a' }) as unknown as NodeJS.WritableStream
    return new Renderer({ stream: fileStream, redactOutput: true })
  }

  // ── Utility ──────────────────────────────────────────────────

  private fullWidth(char: string, padding = 4): string {
    const inner = Math.max(0, this.termWidth - padding)
    return char.repeat(inner)
  }

  private thinBar(): string {
    const inner = Math.min(this.termWidth - 6, 72)
    return `${FG.brightBlack}─${'─'.repeat(inner)}─${RESET}`
  }

  private doubleBar(): string {
    const inner = Math.min(this.termWidth - 6, 72)
    return `${FG.brightBlack}═${'═'.repeat(inner)}═${RESET}`
  }

  // ── Banner — gradient ASCII art + info panel ─────────────────

  banner(version: string, model: string): void {
    this.write('\n')

    // Gradient logo lines
    for (let i = 0; i < LOGO_LINES.length; i++) {
      const color = LOGO_GRADIENT[i % LOGO_GRADIENT.length]
      this.write(`  ${BOLD}${color}${LOGO_LINES[i]}${RESET}\n`)
    }

    this.write('\n')

    // Top decorative line
    const bar = this.doubleBar()
    this.write(`  ${bar}\n`)

    // Info row
    const info = [
      `${DIM}version${RESET} ${BOLD}${FG.brightWhite}${version}${RESET}`,
      `${DIM}model${RESET}   ${BOLD}${FG.brightCyan}${model}${RESET}`,
      `${DIM}engine${RESET}  ${BOLD}${FG.brightGreen}Think-Act-Observe${RESET}`,
      `${DIM}mode${RESET}    ${BOLD}${FG.brightYellow}Coordinator${RESET}`,
    ]
    this.write(`  ${info.join('  ')}\n`)
    this.write(`  ${bar}\n`)

    // Tagline
    this.write(
      `  ${DIM}AI-Powered Red Team Coordination Engine — ` +
      `${FG.brightMagenta}autonomous penetration testing${RESET}${DIM}${RESET}\n`,
    )
    this.write('\n')
  }

  // ── Section separator ────────────────────────────────────────

  separator(): void {
    const inner = Math.min(this.termWidth - 8, 68)
    const left = `${FG.brightBlack}◇${RESET}`
    const right = `${FG.brightBlack}◇${RESET}`
    const mid = `${DIM}${'·'.repeat(inner)}${RESET}`
    this.write(`\n  ${left}${mid}${right}\n`)
  }

  // ── Human message — framed box ──────────────────────────────

  humanPrompt(text: string): void {
    const innerWidth = Math.min(this.termWidth - 8, 72)
    const topBar = `${FG.brightBlue}╭${'─'.repeat(innerWidth)}╮${RESET}`
    const botBar = `${FG.brightBlue}╰${'─'.repeat(innerWidth)}╯${RESET}`

    this.write('\n')
    this.write(`  ${topBar}\n`)

    const lines = text.split('\n')
    for (const line of lines) {
      const content = `${BOLD}${FG.brightWhite}${line}${RESET}`
      this.write(`  ${FG.brightBlue}│${RESET} ${FG.brightBlue}❯${RESET} ${content}\n`)
    }

    this.write(`  ${botBar}\n`)
  }

  // ── Assistant text output ───────────────────────────────────

  assistantText(text: string): void {
    const width = Math.min(this.termWidth - 8, 96)
    const lines = wrapText(text, width).split('\n')
    this.write('\n')
    for (const line of lines) {
      this.write(`  ${STRIPE.assistant} ${line}\n`)
    }
  }

  // ── Streaming text output ───────────────────────────────────

  private streamingActive = false

  beginAssistantText(): void {
    this.streamingActive = true
    this._assistantLineStarted = false
    this.write('\n')
  }

  streamToken(token: string): void {
    if (!this.streamingActive) {
      this.beginAssistantText()
    }
    if (!this._assistantLineStarted) {
      this.write(`  ${STRIPE.assistant} `)
      this._assistantLineStarted = true
    }
    const indented = token.replace(/\n/g, `\n  ${STRIPE.assistant} `)
    this.write(indented)
  }

  endAssistantText(): void {
    if (this.streamingActive) {
      this.write('\n')
      this.streamingActive = false
      this._assistantLineStarted = false
    }
  }

  // ── Tool call display ───────────────────────────────────────

  toolStart(toolName: string, input: Record<string, unknown>): void {
    const preview = this.formatToolPreview(toolName, input)
    const nameColor = this.toolColor(toolName)
    const icon = this.toolIcon(toolName)

    this.write(
      `\n  ${STRIPE.tool}  ${icon} ${BOLD}${nameColor}${toolName}${RESET}` +
        `  ${FG.brightBlack}${preview}${RESET}\n`,
    )
  }

  toolResult(toolName: string, result: string, isError: boolean): void {
    const stripe = isError ? STRIPE.error : STRIPE.result
    const icon = isError ? `${FG.brightRed}✗${RESET}` : `${FG.brightGreen}✓${RESET}`
    const maxPreview = 300
    const truncated =
      result.length > maxPreview
        ? result.slice(0, maxPreview) + `\n… (${result.length - maxPreview} more chars)`
        : result

    if (isError) {
      this.write(`  ${stripe}  ${icon}  ${FG.brightRed}${truncated}${RESET}\n`)
      return
    }

    const lines = truncated.split('\n')
    const shown = lines.slice(0, 8)
    const hidden = lines.length - shown.length

    for (const line of shown) {
      this.write(`  ${stripe}  ${DIM}${line}${RESET}\n`)
    }
    if (hidden > 0) {
      this.write(`  ${stripe}  ${DIM}… ${hidden} more line${hidden !== 1 ? 's' : ''}${RESET}\n`)
    }
  }

  private toolColor(name: string): string {
    const colors: Record<string, string> = {
      Bash:              FG.brightYellow,
      Read:              FG.brightCyan,
      Write:             FG.brightGreen,
      Edit:              FG.brightBlue,
      Glob:              FG.brightMagenta,
      Grep:              FG.brightMagenta,
      WebFetch:          FG.cyan,
      WebSearch:         FG.cyan,
      TodoWrite:         FG.brightGreen,
      Agent:             FG.brightMagenta,
      MultiAgent:        FG.brightMagenta,
      DispatchAgent:     FG.cyan,
      CheckDispatch:     FG.cyan,
      GetDispatchResult: FG.cyan,
      FindingWrite:      FG.brightGreen,
      FindingList:       FG.brightGreen,
      WeaponRadar:       FG.brightYellow,
      C2:                FG.brightRed,
      ShellSession:      FG.brightRed,
      TmuxSession:       FG.brightRed,
    }
    return colors[name] ?? FG.white
  }

  private toolIcon(name: string): string {
    const icons: Record<string, string> = {
      Bash:              `${FG.brightYellow}⌘${RESET}`,
      Read:              `${FG.brightCyan}◈${RESET}`,
      Write:             `${FG.brightGreen}◈${RESET}`,
      Edit:              `${FG.brightBlue}◈${RESET}`,
      Glob:              `${FG.brightMagenta}◇${RESET}`,
      Grep:              `${FG.brightMagenta}◇${RESET}`,
      WebFetch:          `${FG.cyan}◎${RESET}`,
      WebSearch:         `${FG.cyan}◎${RESET}`,
      TodoWrite:         `${FG.brightGreen}☐${RESET}`,
      Agent:             `${FG.brightMagenta}⎇${RESET}`,
      MultiAgent:        `${FG.brightMagenta}⎈${RESET}`,
      DispatchAgent:     `${FG.cyan}⇢${RESET}`,
      CheckDispatch:     `${FG.cyan}⇠${RESET}`,
      GetDispatchResult: `${FG.cyan}⇤${RESET}`,
      FindingWrite:      `${FG.brightGreen}⚑${RESET}`,
      FindingList:       `${FG.brightGreen}⚑${RESET}`,
      WeaponRadar:       `${FG.brightYellow}⚔${RESET}`,
      C2:                `${FG.brightRed}⚡${RESET}`,
      ShellSession:      `${FG.brightRed}⌁${RESET}`,
      TmuxSession:       `${FG.brightRed}⌁${RESET}`,
    }
    return icons[name] ?? `${FG.white}·${RESET}`
  }

  private formatToolPreview(toolName: string, input: Record<string, unknown>): string {
    switch (toolName) {
      case 'Bash': {
        const cmd = String(input.command ?? '').trim()
        return cmd.length > 80 ? cmd.slice(0, 77) + '…' : cmd
      }
      case 'Read': {
        const fp = String(input.file_path ?? '')
        const offset = input.offset ? ` +${input.offset}` : ''
        return fp + offset
      }
      case 'Write': {
        const fp = String(input.file_path ?? '')
        const content = String(input.content ?? '')
        const lines = content.split('\n').length
        return `${fp}  (${lines} lines)`
      }
      case 'Edit': {
        const fp = String(input.file_path ?? '')
        const old = String(input.old_string ?? '').split('\n')[0]?.slice(0, 40) ?? ''
        return `${fp}  "${old}…"`
      }
      case 'Glob': {
        const pattern = String(input.pattern ?? '')
        const path = input.path ? ` in ${input.path}` : ''
        return `${pattern}${path}`
      }
      case 'Grep': {
        const pattern = String(input.pattern ?? '')
        const glob = input.glob ? ` [${input.glob}]` : ''
        return `/${pattern}/${glob}`
      }
      case 'Agent': {
        const type = input.subagent_type ? String(input.subagent_type) : ''
        const desc = input.description ? String(input.description) : ''
        return type ? `[${type}] ${desc}` : desc
      }
      case 'MultiAgent': {
        const agents = input.agents
        if (Array.isArray(agents)) {
          const types = agents
            .filter((a: any) => a && typeof a === 'object')
            .map((a: any) => a.subagent_type ?? 'unknown')
            .join(', ')
          return `×${agents.length} agents: ${types}`
        }
        return ''
      }
      case 'WeaponRadar': {
        const q = input.query ?? input.queries
        if (Array.isArray(q)) return `${q.length} queries`
        if (q) return `"${String(q).slice(0, 50)}"`
        return ''
      }
      default:
        return JSON.stringify(input).slice(0, 80)
    }
  }

  // ── Spinner ──────────────────────────────────────────────────

  startSpinner(initialVerb?: string): void {
    if (!this.isTTY) return
    if (this.spinnerInterval) this.stopSpinner()

    this.spinnerVerbIndex = Math.floor(Math.random() * SPINNER_VERBS.length)
    this.spinnerVerbRotateCounter = 0
    if (initialVerb) {
      const idx = SPINNER_VERBS.findIndex((v) =>
        v.toLowerCase().startsWith(initialVerb.toLowerCase()),
      )
      if (idx !== -1) this.spinnerVerbIndex = idx
    }

    this.write(CURSOR.hide)
    this.renderSpinner()

    this.spinnerInterval = setInterval(() => {
      this.spinnerFrame = (this.spinnerFrame + 1) % SPINNER_FRAMES.length
      this.spinnerVerbRotateCounter++
      if (this.spinnerVerbRotateCounter >= 24) {
        this.spinnerVerbRotateCounter = 0
        this.spinnerVerbIndex = (this.spinnerVerbIndex + 1) % SPINNER_VERBS.length
      }
      this.renderSpinner()
    }, 50)
  }

  private renderSpinner(): void {
    if (!this.isTTY) return
    const frame = SPINNER_FRAMES[this.spinnerFrame]
    const verb = SPINNER_VERBS[this.spinnerVerbIndex]
    const line =
      `  ${FG.brightMagenta}${BOLD}${frame}${RESET} ` +
      `${FG.brightBlack}${verb}${RESET}${FG.brightBlack}…${RESET}`
    this.write(CURSOR.col(1) + CURSOR.clearToEnd + line)
    this.lastSpinnerLineLen = line.replace(/\x1b\[[^m]*m/g, '').length
  }

  stopSpinner(): void {
    if (!this.spinnerInterval) return
    clearInterval(this.spinnerInterval)
    this.spinnerInterval = null
    if (this.isTTY) {
      this.write(CURSOR.col(1) + CURSOR.clearLine + CURSOR.show)
    }
    this.lastSpinnerLineLen = 0
  }

  // ── Status / info messages ──────────────────────────────────

  info(msg: string): void {
    this.write(`  ${FG.brightBlack}·${RESET}  ${DIM}${msg}${RESET}\n`)
  }

  success(msg: string): void {
    this.write(`  ${FG.brightGreen}✓${RESET} ${FG.brightGreen}${msg}${RESET}\n`)
  }

  error(msg: string): void {
    this.write(`  ${FG.brightRed}✗${RESET} ${FG.brightRed}${msg}${RESET}\n`)
  }

  warn(msg: string): void {
    this.write(`  ${FG.brightYellow}⚠${RESET} ${FG.brightYellow}${msg}${RESET}\n`)
  }

  // ── Sub-agent display ───────────────────────────────────────

  agentStart(description: string, agentType = 'general-purpose'): void {
    const typeLabel = agentType !== 'general-purpose'
      ? `  ${DIM}[${FG.brightMagenta}${agentType}${RESET}${DIM}]${RESET}`
      : ''
    this.write(`\n  ${STRIPE.agent}  ${BOLD}${FG.brightMagenta}⎇${RESET}${BOLD}${FG.brightMagenta} Agent${RESET}${typeLabel}  ${DIM}${description}${RESET}\n`)
  }

  agentDone(description: string, success: boolean): void {
    const icon = success ? `${FG.brightGreen}✓${RESET}` : `${FG.brightRed}✗${RESET}`
    this.write(`  ${STRIPE.agent}  ${icon} ${DIM}Agent "${description}" done${RESET}\n`)
  }

  agentSummary(agentType: string, description: string, summary: string): void {
    const header = `  ${STRIPE.agent}  ${BOLD}${FG.brightMagenta}[${agentType}]${RESET} ${DIM}${description}${RESET}\n`
    const body = summary
      .split('\n')
      .map(line => `  ${STRIPE.agent}    ${DIM}${line}${RESET}`)
      .join('\n')
    this.write(`${header}${body}\n`)
  }

  agentHeartbeat(agentType: string, description: string, elapsedSec: number): void {
    const mins = Math.floor(elapsedSec / 60)
    const secs = elapsedSec % 60
    const elapsed = mins > 0 ? `${mins}m${secs}s` : `${secs}s`
    this.write(
      `  ${STRIPE.agent}  ${FG.yellow}⏳${RESET} ${DIM}[${agentType}] ${description} — 运行中 ${elapsed}…${RESET}\n`
    )
  }

  // ── Plan mode banner ────────────────────────────────────────

  planModeStart(): void {
    const bar = this.thinBar()
    this.write(`\n  ${bar}\n`)
    this.write(
      `  ${FG.brightBlue}◇${RESET}  ${BOLD}${FG.brightCyan}✦ PLAN MODE${RESET}  ${DIM}(read-only analysis)${RESET}\n`
    )
    this.write(`  ${bar}\n`)
  }

  planConfirmPrompt(): void {
    this.write(`\n  ${FG.brightYellow}?${RESET} Proceed with execution? ${DIM}[y/N]${RESET} `)
  }

  // ── Compact notifications ───────────────────────────────────

  compactStart(tokenCount: number): void {
    this.write(
      `\n  ${STRIPE.compact}  ${FG.yellow}⟳${RESET}` +
        `  ${DIM}Context ~${Math.round(tokenCount / 1000)}k tokens — compacting…${RESET}\n`,
    )
  }

  compactDone(originalTokens: number, summaryTokens: number): void {
    const saved = Math.round((1 - summaryTokens / originalTokens) * 100)
    this.write(
      `  ${STRIPE.compact}  ${FG.brightGreen}✓${RESET}` +
        `  ${DIM}~${Math.round(originalTokens / 1000)}k → ~${Math.round(summaryTokens / 1000)}k tokens (${saved}% saved)${RESET}\n`,
    )
  }

  // ── Context stats ───────────────────────────────────────────

  contextWarning(tokens: number, maxTokens: number, pct: number): void {
    const pctStr = Math.round(pct * 100)
    this.write(
      `\n  ${STRIPE.compact}  ${FG.brightYellow}⚠${RESET}` +
        `  ${DIM}上下文 ${pctStr}% · ~${Math.round(tokens / 1000)}k / ${Math.round(maxTokens / 1000)}k tokens — 接近压缩阈值${RESET}\n`,
    )
  }

  contextStats(tokens: number, maxTokens: number, pct: number): void {
    const pctInt = Math.round(pct * 100)
    const filled = Math.round(pct * 16)
    const bar = '█'.repeat(filled) + '░'.repeat(16 - filled)
    const color = pct >= 0.85 ? FG.red : pct >= 0.70 ? FG.yellow : FG.brightBlack
    this.write(
      `  ${DIM}ctx [${color}${bar}${RESET}${DIM}] ${pctInt}% · ~${Math.round(tokens / 1000)}k/${Math.round(maxTokens / 1000)}k${RESET}\n`,
    )
  }

  // ── Turn stats ──────────────────────────────────────────────

  turnStats(iterations: number, model: string): void {
    this.write(`\n  ${DIM}↻ ${iterations} turn${iterations !== 1 ? 's' : ''} · ${model}${RESET}\n`)
  }

  // ── Dispatch display ────────────────────────────────────────

  dispatchStarted(id: string, agentType: string, description: string): void {
    this.write(
      `\n  ${STRIPE.dispatch}  ${FG.cyan}⇢${RESET} ${BOLD}${FG.brightCyan}Dispatch${RESET}` +
        `  ${DIM}[${agentType}]${RESET} ${FG.brightWhite}${description}${RESET}` +
        `  ${DIM}id: ${id}${RESET}\n`,
    )
  }

  dispatchCompleted(id: string, success: boolean): void {
    const icon = success ? `${FG.brightGreen}✓${RESET}` : `${FG.brightRed}✗${RESET}`
    this.write(`  ${STRIPE.dispatch}  ${icon} ${DIM}Dispatch ${id} ${success ? 'completed' : 'failed'}${RESET}\n`)
  }

  // ── Input prompt ────────────────────────────────────────────

  writePrompt(): void {
    this.write(`\n${FG.brightBlue}◇${RESET} ${BOLD}${FG.brightWhite}ovogo${RESET}${DIM} › ${RESET}`)
  }

  writeInterruptPrompt(): void {
    const bar = this.fullWidth('─')
    this.write(
      `\n\x07` +
      `  ${FG.brightYellow}╭${bar}╮${RESET}\n` +
      `  ${FG.brightYellow}│${RESET}  ${FG.brightYellow}${BOLD}⚡ 任务已暂停${RESET}  ${DIM}输入建议后按 Enter 注入并继续${RESET}  ${FG.brightYellow}│${RESET}\n` +
      `  ${FG.brightYellow}│${RESET}  ${DIM}直接按 Enter = 静默恢复  |  Ctrl+D = 终止${RESET}  ${FG.brightYellow}│${RESET}\n` +
      `  ${FG.brightYellow}╰${bar}╯${RESET}\n` +
      `${FG.brightYellow}◇${RESET} `,
    )
  }

  interruptInjected(msg: string): void {
    this.write(
      `\n  ${FG.brightYellow}⚡${RESET} ${DIM}已注入:${RESET} ${FG.brightWhite}${msg.slice(0, 120)}${msg.length > 120 ? '…' : ''}${RESET}\n`,
    )
  }

  newline(): void {
    this.write('\n')
  }
}
