/**
 * Terminal UI Renderer — pure process.stdout.write, zero UI frameworks
 *
 * Visual design:
 * - OVOGO ASCII art banner at startup
 * - Colored left-border stripes per section type
 * - Gradient-style separators
 * - ✻ spinner with rotating verbs during thinking
 * - Tool call boxes with per-tool color coding
 */

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

// Background colors (subtle tints for stripe accents)
const BG = {
  blue: `${ESC}44m`,
  magenta: `${ESC}45m`,
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

const w = (s: string) => process.stdout.write(s)
const isTTY = process.stdout.isTTY

// ─────────────────────────────────────────────────────────────
// OVOGO ASCII art logo (block font)
// ─────────────────────────────────────────────────────────────

const LOGO_LINES = [
  ' ██████╗ ██╗   ██╗ ██████╗  ██████╗  ██████╗ ',
  '██╔═══██╗██║   ██║██╔═══██╗██╔════╝ ██╔═══██╗',
  '██║   ██║╚██╗ ██╔╝██║   ██║██║  ███╗██║   ██║',
  '╚██████╔╝ ╚████╔╝ ╚██████╔╝╚██████╔╝╚██████╔╝',
  ' ╚═════╝   ╚═══╝   ╚═════╝  ╚═════╝  ╚═════╝ ',
]

// ─────────────────────────────────────────────────────────────
// Spinner frames (Braille Unicode)
// ─────────────────────────────────────────────────────────────

const SPINNER_FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']

// Verbs for spinner animation
export const SPINNER_VERBS = [
  'Accomplishing',
  'Architecting',
  'Baking',
  'Calculating',
  'Cerebrating',
  'Cogitating',
  'Composing',
  'Computing',
  'Concocting',
  'Considering',
  'Crafting',
  'Crunching',
  'Crystallizing',
  'Deliberating',
  'Determining',
  'Distilling',
  'Elaborating',
  'Engineering',
  'Examining',
  'Executing',
  'Exploring',
  'Figuring',
  'Generating',
  'Hatching',
  'Implementing',
  'Inferring',
  'Initializing',
  'Innovating',
  'Mulling',
  'Noodling',
  'Orchestrating',
  'Pondering',
  'Processing',
  'Reasoning',
  'Ruminating',
  'Sautéing',
  'Scheming',
  'Solving',
  'Synthesizing',
  'Thinking',
  'Transmuting',
  'Vibing',
  'Wrangling',
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

// Heavy vertical bar for emphasis sections
const STRIPE = {
  user: `${FG.brightBlue}│${RESET}`,
  assistant: `${FG.brightCyan}│${RESET}`,
  tool: `${FG.brightYellow}┃${RESET}`,
  result: `${FG.brightGreen}│${RESET}`,
  error: `${FG.brightRed}│${RESET}`,
  agent: `${FG.brightMagenta}│${RESET}`,
  compact: `${FG.yellow}│${RESET}`,
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

  constructor() {
    this.termWidth = isTTY ? (process.stdout.columns ?? 80) : 80
    if (isTTY) {
      process.stdout.on('resize', () => {
        this.termWidth = process.stdout.columns ?? 80
      })
    }
  }

  // ── Banner ───────────────────────────────────────────────────

  banner(version: string, model: string): void {
    const barWidth = Math.min(this.termWidth - 4, 48)
    const bar = `${FG.brightBlack}${'━'.repeat(barWidth)}${RESET}`

    w('\n')
    for (const line of LOGO_LINES) {
      w(`  ${FG.brightMagenta}${BOLD}${line}${RESET}\n`)
    }
    w('\n')
    w(`  ${bar}\n`)
    w(
      `  ${DIM}version${RESET} ${FG.brightWhite}${version}${RESET}` +
        `   ${DIM}model${RESET} ${FG.brightCyan}${model}${RESET}\n`,
    )
    w(`  ${bar}\n`)
    w('\n')
  }

  // ── Section separator — gradient style ───────────────────────

  separator(): void {
    const innerWidth = Math.min(this.termWidth - 10, 68)
    const mid = `${DIM}${'─'.repeat(innerWidth)}${RESET}`
    const cap = `${FG.brightBlack}▒${RESET}`
    w(`\n  ${cap}${mid}${cap}\n`)
  }

  // ── Human message — blue framed box with stripe ──────────────

  humanPrompt(text: string): void {
    const innerWidth = Math.min(this.termWidth - 8, 72)
    const topBar = `${FG.brightBlue}╭${'─'.repeat(innerWidth)}╮${RESET}`
    const botBar = `${FG.brightBlue}╰${'─'.repeat(innerWidth)}╯${RESET}`

    w('\n')
    w(`  ${topBar}\n`)

    const lines = text.split('\n')
    for (const line of lines) {
      const content = `${FG.brightBlue}❯${RESET} ${BOLD}${FG.brightWhite}${line}${RESET}`
      w(`  ${FG.brightBlue}│${RESET} ${content}\n`)
    }

    w(`  ${botBar}\n`)
  }

  // ── Assistant text output (non-streaming) ────────────────────

  assistantText(text: string): void {
    const width = Math.min(this.termWidth - 8, 96)
    const lines = wrapText(text, width).split('\n')
    w('\n')
    for (const line of lines) {
      w(`  ${STRIPE.assistant} ${line}\n`)
    }
  }

  // ── Streaming text output ────────────────────────────────────

  private streamingActive = false

  beginAssistantText(): void {
    this.streamingActive = true
    this._assistantLineStarted = false
    w('\n')
  }

  streamToken(token: string): void {
    if (!this.streamingActive) {
      this.beginAssistantText()
    }
    if (!this._assistantLineStarted) {
      w(`  ${STRIPE.assistant} `)
      this._assistantLineStarted = true
    }
    // After each newline, re-emit the left stripe prefix
    const indented = token.replace(/\n/g, `\n  ${STRIPE.assistant} `)
    w(indented)
  }

  endAssistantText(): void {
    if (this.streamingActive) {
      w('\n')
      this.streamingActive = false
      this._assistantLineStarted = false
    }
  }

  // ── Tool call display ─────────────────────────────────────────
  // Yellow stripe for tool invocations, per-tool color for name

  toolStart(toolName: string, input: Record<string, unknown>): void {
    const preview = this.formatToolPreview(toolName, input)
    const nameColor = this.toolColor(toolName)
    w(
      `\n  ${STRIPE.tool}  ${BOLD}${nameColor}${toolName}${RESET}` +
        `  ${FG.brightBlack}${preview}${RESET}\n`,
    )
  }

  toolResult(toolName: string, result: string, isError: boolean): void {
    const stripe = isError ? STRIPE.error : STRIPE.result
    const maxPreview = 300
    const truncated =
      result.length > maxPreview
        ? result.slice(0, maxPreview) + `\n… (${result.length - maxPreview} more chars)`
        : result

    if (isError) {
      w(`  ${stripe}  ${FG.brightRed}${truncated}${RESET}\n`)
      return
    }

    const lines = truncated.split('\n')
    const shown = lines.slice(0, 8)
    const hidden = lines.length - shown.length

    for (const line of shown) {
      w(`  ${stripe}  ${DIM}${line}${RESET}\n`)
    }
    if (hidden > 0) {
      w(`  ${stripe}  ${DIM}… ${hidden} more line${hidden !== 1 ? 's' : ''}${RESET}\n`)
    }
  }

  private toolColor(name: string): string {
    const colors: Record<string, string> = {
      Bash: FG.brightYellow,
      Read: FG.brightCyan,
      Write: FG.brightGreen,
      Edit: FG.brightBlue,
      Glob: FG.brightMagenta,
      Grep: FG.brightMagenta,
      WebFetch: FG.cyan,
      WebSearch: FG.cyan,
      TodoWrite: FG.brightGreen,
      Agent: FG.brightMagenta,
    }
    return colors[name] ?? FG.white
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
      default:
        return JSON.stringify(input).slice(0, 80)
    }
  }

  // ── Spinner ───────────────────────────────────────────────────

  startSpinner(initialVerb?: string): void {
    if (!isTTY) return
    if (this.spinnerInterval) this.stopSpinner()

    this.spinnerVerbIndex = Math.floor(Math.random() * SPINNER_VERBS.length)
    this.spinnerVerbRotateCounter = 0
    if (initialVerb) {
      const idx = SPINNER_VERBS.findIndex((v) =>
        v.toLowerCase().startsWith(initialVerb.toLowerCase()),
      )
      if (idx !== -1) this.spinnerVerbIndex = idx
    }

    w(CURSOR.hide)
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
    if (!isTTY) return
    const frame = SPINNER_FRAMES[this.spinnerFrame]
    const verb = SPINNER_VERBS[this.spinnerVerbIndex]
    const line =
      `  ${FG.brightMagenta}${frame}${RESET} ` +
      `${FG.brightBlack}${verb}${RESET}${FG.brightBlack}…${RESET}`
    w(CURSOR.col(1) + CURSOR.clearToEnd + line)
    this.lastSpinnerLineLen = line.replace(/\x1b\[[^m]*m/g, '').length
  }

  stopSpinner(): void {
    if (!this.spinnerInterval) return
    clearInterval(this.spinnerInterval)
    this.spinnerInterval = null
    if (isTTY) {
      w(CURSOR.col(1) + CURSOR.clearLine + CURSOR.show)
    }
    this.lastSpinnerLineLen = 0
  }

  // ── Status / info messages ────────────────────────────────────

  info(msg: string): void {
    w(`  ${DIM}${msg}${RESET}\n`)
  }

  success(msg: string): void {
    w(`  ${FG.brightGreen}✓${RESET} ${msg}\n`)
  }

  error(msg: string): void {
    w(`  ${FG.brightRed}✗${RESET} ${FG.red}${msg}${RESET}\n`)
  }

  warn(msg: string): void {
    w(`  ${FG.yellow}⚠${RESET} ${FG.yellow}${msg}${RESET}\n`)
  }

  // ── Sub-agent display ─────────────────────────────────────────

  agentStart(description: string, agentType = 'general-purpose'): void {
    const typeLabel = agentType !== 'general-purpose' ? `  ${FG.brightBlack}[${agentType}]${RESET}` : ''
    w(`\n  ${STRIPE.agent}  ${BOLD}${FG.brightMagenta}⎇ Agent${RESET}${typeLabel}  ${DIM}${description}${RESET}\n`)
  }

  agentDone(description: string, success: boolean): void {
    const icon = success ? `${FG.brightGreen}✓${RESET}` : `${FG.brightRed}✗${RESET}`
    w(`  ${STRIPE.agent}  ${icon} ${DIM}Agent "${description}" done${RESET}\n`)
  }

  /** Show plan mode banner before a plan run */
  planModeStart(): void {
    w(
      `\n  ${FG.brightBlue}┌${'─'.repeat(50)}┐${RESET}\n` +
      `  ${FG.brightBlue}│${RESET}  ${BOLD}${FG.brightCyan}✦ PLAN MODE${RESET}  ${DIM}(read-only analysis)${RESET}` +
      `${' '.repeat(17)}${FG.brightBlue}│${RESET}\n` +
      `  ${FG.brightBlue}└${'─'.repeat(50)}┘${RESET}\n`,
    )
  }

  /** Ask the user to confirm plan execution, returns the raw line */
  planConfirmPrompt(): void {
    w(`\n  ${FG.brightYellow}?${RESET} Proceed with execution? ${DIM}[y/N]${RESET} `)
  }

  // ── Compact notifications ─────────────────────────────────────

  compactStart(tokenCount: number): void {
    w(
      `\n  ${STRIPE.compact}  ${FG.yellow}⟳${RESET}` +
        `  ${DIM}Context ~${Math.round(tokenCount / 1000)}k tokens — compacting…${RESET}\n`,
    )
  }

  compactDone(originalTokens: number, summaryTokens: number): void {
    const saved = Math.round((1 - summaryTokens / originalTokens) * 100)
    w(
      `  ${STRIPE.compact}  ${FG.brightGreen}✓${RESET}` +
        `  ${DIM}~${Math.round(originalTokens / 1000)}k → ~${Math.round(summaryTokens / 1000)}k tokens (${saved}% saved)${RESET}\n`,
    )
  }

  // ── Turn stats ────────────────────────────────────────────────

  turnStats(iterations: number, model: string): void {
    w(`\n  ${DIM}↩ ${iterations} turn${iterations !== 1 ? 's' : ''} · ${model}${RESET}\n`)
  }

  // ── Input prompt ──────────────────────────────────────────────

  writePrompt(): void {
    w(`\n${FG.brightBlue}❯${RESET} `)
  }

  writeInterruptPrompt(): void {
    // \x07 = BEL — terminal bell to alert user
    w(
      `\x07\n` +
      `${FG.brightYellow}${'─'.repeat(60)}${RESET}\n` +
      `${FG.brightYellow}  ⚡ 任务已暂停${RESET}  ${BOLD}输入建议后按 Enter 注入并继续${RESET}\n` +
      `${DIM}  直接按 Enter = 静默恢复  |  Ctrl+D = 终止${RESET}\n` +
      `${FG.brightYellow}${'─'.repeat(60)}${RESET}\n` +
      `${FG.brightYellow}▶${RESET} `,
    )
  }

  interruptInjected(msg: string): void {
    w(
      `\n  ${FG.brightYellow}⚡${RESET} ${DIM}已注入:${RESET} ${FG.brightWhite}${msg.slice(0, 120)}${msg.length > 120 ? '…' : ''}${RESET}\n`,
    )
  }

  newline(): void {
    w('\n')
  }
}
