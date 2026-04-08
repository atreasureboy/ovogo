/**
 * Interactive input handler — raw readline with history support
 *
 * Provides Claude Code-style input:
 * - ❯ prompt glyph
 * - Arrow key history navigation
 * - Ctrl+C to cancel / Ctrl+D to exit
 * - Multi-line paste support
 */

import { createInterface, type Interface } from 'readline'

export interface InputResult {
  text: string
  eof: boolean
}

export class InputHandler {
  private rl: Interface
  private history: string[] = []

  constructor() {
    this.rl = createInterface({
      input: process.stdin,
      output: process.stdout,
      terminal: process.stdout.isTTY,
      historySize: 100,
    })

    // Expose internal history array so we can pre-populate
    // readline stores history in reverse order internally
  }

  async readLine(promptText: string): Promise<InputResult> {
    return new Promise((resolve) => {
      // Handle Ctrl+D (EOF)
      this.rl.once('close', () => {
        resolve({ text: '', eof: true })
      })

      this.rl.question(promptText, (answer) => {
        if (answer.trim()) {
          this.history.unshift(answer)
        }
        resolve({ text: answer, eof: false })
      })
    })
  }

  close(): void {
    this.rl.close()
  }

  getHistory(): string[] {
    return [...this.history]
  }
}

/**
 * Read a single line from stdin (for pipe/non-TTY usage)
 */
export async function readStdin(): Promise<string> {
  if (process.stdin.isTTY) return ''
  return new Promise((resolve) => {
    const chunks: Buffer[] = []
    process.stdin.on('data', (chunk: Buffer) => chunks.push(chunk))
    process.stdin.on('end', () => resolve(Buffer.concat(chunks).toString('utf8').trim()))
    process.stdin.on('error', () => resolve(''))
    setTimeout(() => resolve(chunks.map(c => c.toString()).join('').trim()), 3000)
  })
}
