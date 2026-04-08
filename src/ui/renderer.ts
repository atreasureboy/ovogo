/**
 * Terminal UI Renderer — pure process.stdout.write, zero UI frameworks
 *
 * Mimics Claude Code's visual style:
 * - ✻ spinner with rotating verbs during thinking
 * - ⎿ tool call display with tool name + args
 * - Colored output via ANSI escape codes
 * - Status line at bottom
 * - Input prompt with ❯ glyph
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
// Spinner frames (Claude Code style: ✦ variants)
// ─────────────────────────────────────────────────────────────

const SPINNER_FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']

// Verbs extracted from Claude Code constants/spinnerVerbs.ts
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
// Renderer class
// ─────────────────────────────────────────────────────────────

export class Renderer {
  private spinnerInterval: NodeJS.Timeout | null = null
  private spinnerFrame = 0
  private spinnerVerbIndex = 0
  private spinnerVerbRotateCounter = 0
  private lastSpinnerLineLen = 0
  private termWidth: number

  constructor() {
    this.termWidth = isTTY ? (process.stdout.columns ?? 80) : 80
    if (isTTY) {
      process.stdout.on('resize', () => {
        this.termWidth = process.stdout.columns ?? 80
      })
    }
  }

  // ── Banner ───────────────────────────────────────────────

  banner(version: string, model: string): void {
    w('\n')
    w(`  ${FG.brightMagenta}✻${RESET} ${BOLD}ovogogogo${RESET} ${DIM}v${version}${RESET}\n`)
    w(`  ${DIM}Model: ${model}${RESET}\n`)
    w('\n')
  }

  // ── Section separator ────────────────────────────────────

  separator(): void {
    const line = '─'.repeat(Math.min(this.termWidth - 2, 78))
    w(`\n${DIM}${line}${RESET}\n`)
  }

  // ── Human message prompt display ─────────────────────────

  humanPrompt(text: string): void {
    this.separator()
    w(`${FG.brightBlue}❯${RESET} ${text}\n`)
    this.separator()
  }

  // ── Assistant text output (non-streaming) ───────────────

  assistantText(text: string): void {
    const width = Math.min(this.termWidth - 4, 100)
    const wrapped = wrapText(text, width, '  ')
    w(`\n${wrapped}\n`)
  }

  // ── Streaming text output ────────────────────────────────

  private streamingActive = false

  beginAssistantText(): void {
    this.streamingActive = true
    w('\n  ') // indent first line
  }

  streamToken(token: string): void {
    if (!this.streamingActive) {
      this.beginAssistantText()
    }
    // Handle newlines: add indent after each newline
    const indented = token.replace(/\n/g, '\n  ')
    w(indented)
  }

  endAssistantText(): void {
    if (this.streamingActive) {
      w('\n')
      this.streamingActive = false
    }
  }

  // ── Tool call display ────────────────────────────────────
  // Mimics Claude Code's ⎿ run ... format

  toolStart(toolName: string, input: Record<string, unknown>): void {
    const preview = this.formatToolPreview(toolName, input)
    w(`\n  ${FG.brightBlack}⎿${RESET}  ${BOLD}${this.toolColor(toolName)}${toolName}${RESET}  ${DIM}${preview}${RESET}\n`)
  }

  toolResult(toolName: string, result: string, isError: boolean): void {
    const maxPreview = 300
    const preview = result.length > maxPreview
      ? result.slice(0, maxPreview) + `\n  ${DIM}... (${result.length - maxPreview} more chars)${RESET}`
      : result

    if (isError) {
      w(`     ${FG.red}✗${RESET} ${FG.red}${preview}${RESET}\n`)
    } else {
      // Show first few lines of output
      const lines = preview.split('\n')
      const shown = lines.slice(0, 8)
      const hidden = lines.length - shown.length
      for (const line of shown) {
        w(`     ${DIM}${line}${RESET}\n`)
      }
      if (hidden > 0) {
        w(`     ${DIM}... ${hidden} more lines${RESET}\n`)
      }
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
    }
    return colors[name] ?? FG.white
  }

  private formatToolPreview(toolName: string, input: Record<string, unknown>): string {
    switch (toolName) {
      case 'Bash': {
        const cmd = String(input.command ?? '').trim()
        return cmd.length > 80 ? cmd.slice(0, 77) + '...' : cmd
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
        return `${fp} (${lines} lines)`
      }
      case 'Edit': {
        const fp = String(input.file_path ?? '')
        const old = String(input.old_string ?? '').split('\n')[0]?.slice(0, 40) ?? ''
        return `${fp}: "${old}…"`
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

  // ── Spinner ──────────────────────────────────────────────

  startSpinner(initialVerb?: string): void {
    if (!isTTY) return
    if (this.spinnerInterval) this.stopSpinner()

    this.spinnerVerbIndex = Math.floor(Math.random() * SPINNER_VERBS.length)
    this.spinnerVerbRotateCounter = 0
    if (initialVerb) {
      // Find verb or use random
      const idx = SPINNER_VERBS.findIndex(v => v.toLowerCase().startsWith(initialVerb.toLowerCase()))
      if (idx !== -1) this.spinnerVerbIndex = idx
    }

    w(CURSOR.hide)
    this.renderSpinner()

    this.spinnerInterval = setInterval(() => {
      this.spinnerFrame = (this.spinnerFrame + 1) % SPINNER_FRAMES.length
      this.spinnerVerbRotateCounter++
      // Rotate verb every ~24 frames (~1.2s at 50ms interval)
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
    const elapsed = '' // could add elapsed time
    const line = `  ${FG.brightMagenta}${frame}${RESET} ${FG.brightBlack}${verb}…${RESET}${elapsed}`

    // Clear previous line and write new spinner
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

  // ── Status / info messages ───────────────────────────────

  info(msg: string): void {
    w(`  ${DIM}${msg}${RESET}\n`)
  }

  success(msg: string): void {
    w(`  ${FG.brightGreen}✓${RESET} ${msg}\n`)
  }

  error(msg: string): void {
    w(`  ${FG.red}✗${RESET} ${FG.red}${msg}${RESET}\n`)
  }

  warn(msg: string): void {
    w(`  ${FG.yellow}⚠${RESET} ${FG.yellow}${msg}${RESET}\n`)
  }

  // ── Turn stats ───────────────────────────────────────────

  // ── Sub-agent display ────────────────────────────────────

  agentStart(description: string): void {
    w(`\n  ${FG.brightMagenta}⎇${RESET}  ${BOLD}Agent${RESET}  ${DIM}${description}${RESET}\n`)
  }

  agentDone(description: string, success: boolean): void {
    const icon = success ? `${FG.brightGreen}✓${RESET}` : `${FG.red}✗${RESET}`
    w(`     ${icon} ${DIM}Agent "${description}" done${RESET}\n`)
  }

  // ── Compact notifications ─────────────────────────────────

  compactStart(tokenCount: number): void {
    w(`\n  ${FG.yellow}⟳${RESET} ${DIM}Context growing large (~${Math.round(tokenCount / 1000)}k tokens) — compacting conversation…${RESET}\n`)
  }

  compactDone(originalTokens: number, summaryTokens: number): void {
    const saved = Math.round((1 - summaryTokens / originalTokens) * 100)
    w(`  ${FG.brightGreen}✓${RESET} ${DIM}Compacted: ~${Math.round(originalTokens / 1000)}k → ~${Math.round(summaryTokens / 1000)}k tokens (${saved}% saved)${RESET}\n`)
  }

  // ── Turn stats ───────────────────────────────────────────

  turnStats(iterations: number, model: string): void {
    w(`\n  ${DIM}↩ ${iterations} turn${iterations !== 1 ? 's' : ''} · ${model}${RESET}\n`)
  }

  // ── Input prompt ─────────────────────────────────────────

  writePrompt(): void {
    w(`\n${FG.brightBlue}❯${RESET} `)
  }

  newline(): void {
    w('\n')
  }
}
