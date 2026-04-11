/**
 * TmuxLayout — Sub-agent tmux window manager
 *
 * 架构：
 *   - 主 agent 在普通终端运行（不进 tmux）
 *   - 每个子 agent 获得一个独立的 tmux 窗口（window），在里面展示执行过程
 *   - 用户可以新开终端执行 `tmux a -t <session>` 查看所有子 agent
 *   - 各窗口实时 tail -f 子 agent 的日志文件，颜色/格式完整保留
 *
 * 布局示意（tmux 会话内）：
 *   [0: OVOGO-Status] [1: dns-recon] [2: port-scan] [3: web-vuln] ...
 *
 * 降级：tmux 不可用或初始化失败时，子 agent 输出回落到主 stdout renderer
 */

import { execSync, spawnSync } from 'child_process'
import { mkdirSync, writeFileSync } from 'fs'
import { join } from 'path'

// ─────────────────────────────────────────────────────────────
// Shell single-quote escape
// ─────────────────────────────────────────────────────────────
function sq(s: string): string {
  return `'${s.replace(/'/g, "'\\''")}'`
}

// ─────────────────────────────────────────────────────────────
// 将 agent label 转为合法的 tmux 窗口名（≤20 chars, 无特殊符号）
// ─────────────────────────────────────────────────────────────
function toWindowName(label: string): string {
  return label
    .replace(/^\[([^\]]+)\]\s*/, '$1-')   // [dns-recon] xxx → dns-recon-xxx
    .replace(/[^a-zA-Z0-9_\-]/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/, '')
    .slice(0, 20)
}

// ─────────────────────────────────────────────────────────────
// TmuxLayout
// ─────────────────────────────────────────────────────────────

interface AgentWindow {
  slot: number
  logFile: string
  windowName: string
  agentLabel: string
}

export class TmuxLayout {
  private sessionName = ''
  private logDir = ''
  private initialized = false
  private slotCounter = 0
  private activeWindows: AgentWindow[] = []

  /**
   * 初始化：在后台创建一个独立的 tmux session，用于承载所有子 agent 窗口。
   * 主进程不需要在 tmux 里。
   *
   * @param logDir 子 agent 日志目录
   * @returns true = 成功，false = tmux 不可用或初始化失败
   */
  init(logDir: string): boolean {
    if (this.initialized) return true

    // 检查 tmux 是否可用
    const check = spawnSync('tmux', ['-V'], { stdio: 'pipe' })
    if (check.status !== 0) return false

    try {
      mkdirSync(logDir, { recursive: true })
    } catch {
      return false
    }

    this.logDir = logDir
    this.sessionName = `ovogo-${Date.now()}`

    try {
      // 创建后台 tmux session（不 attach，不影响主终端）
      execSync(
        `tmux new-session -d -s ${sq(this.sessionName)} -x 200 -y 50`,
        { stdio: 'pipe' },
      )

      // 重命名第一个窗口为状态总览
      execSync(`tmux rename-window -t ${sq(this.sessionName + ':0')} 'OVOGO-Status'`)

      // 在状态窗口写欢迎信息
      const welcome = [
        'clear',
        `echo "\\033[1m\\033[95m${'═'.repeat(60)}\\033[0m"`,
        `echo "\\033[1m\\033[95m  OVOGO — Sub-Agent Monitor\\033[0m"`,
        `echo "\\033[2m  子 agent 窗口将在这里自动出现（Ctrl+B + 数字 切换）\\033[0m"`,
        `echo "\\033[1m\\033[95m${'═'.repeat(60)}\\033[0m"`,
      ].join(' && ')
      execSync(`tmux send-keys -t ${sq(this.sessionName + ':0')} ${JSON.stringify(welcome)} Enter`)

      this.initialized = true
      return true

    } catch {
      this.sessionName = ''
      return false
    }
  }

  /**
   * 为新子 agent 创建一个 tmux 窗口，返回日志文件路径。
   * 如果 tmux 不可用则返回 null（降级到主 renderer）。
   */
  acquireSlot(agentLabel: string): { slot: number; logFile: string } | null {
    if (!this.initialized) return null

    const slot = this.slotCounter++
    const logFile = join(this.logDir, `agent-${slot}.log`)
    const windowName = toWindowName(agentLabel) || `agent-${slot}`

    // 写入 agent 启动 banner 到日志文件
    const startBanner =
      `\x1b[1m\x1b[95m${'═'.repeat(58)}\x1b[0m\n` +
      `\x1b[1m\x1b[95m  ⎇  ${agentLabel}\x1b[0m\n` +
      `\x1b[2m     Started: ${new Date().toLocaleTimeString()}\x1b[0m\n` +
      `\x1b[1m\x1b[95m${'═'.repeat(58)}\x1b[0m\n`
    try {
      writeFileSync(logFile, startBanner)
    } catch { /* best-effort */ }

    try {
      // 在 tmux session 里新建一个窗口
      execSync(
        `tmux new-window -t ${sq(this.sessionName)} -n ${sq(windowName)}`,
        { stdio: 'pipe' },
      )

      // 窗口内运行 tail -f 实时显示 agent 输出
      const tailCmd = `tail -f ${sq(logFile)}`
      execSync(
        `tmux send-keys -t ${sq(this.sessionName + ':' + windowName)} ${JSON.stringify(tailCmd)} Enter`,
        { stdio: 'pipe' },
      )

    } catch {
      // 窗口创建失败，仍然返回 logFile 供 Renderer.forFile 使用
    }

    this.activeWindows.push({ slot, logFile, windowName, agentLabel })
    return { slot, logFile }
  }

  /**
   * 子 agent 完成后标记窗口为 done（在日志结尾写入 footer，更新窗口名）。
   */
  releaseSlot(slot: number): void {
    const win = this.activeWindows.find(w => w.slot === slot)
    if (!win) return

    // 写入完成 footer
    const footer =
      `\n\x1b[2m${'─'.repeat(58)}\x1b[0m\n` +
      `\x1b[32m  ✓ "${win.agentLabel}" 完成\x1b[0m\n` +
      `\x1b[2m  ${new Date().toLocaleTimeString()}\x1b[0m\n` +
      `\x1b[2m${'─'.repeat(58)}\x1b[0m\n`
    try { writeFileSync(win.logFile, footer, { flag: 'a' }) } catch { /* best-effort */ }

    // 重命名窗口加 ✓ 标记
    try {
      const doneWindowName = `✓-${win.windowName}`.slice(0, 20)
      execSync(
        `tmux rename-window -t ${sq(this.sessionName + ':' + win.windowName)} ${sq(doneWindowName)}`,
        { stdio: 'pipe' },
      )
    } catch { /* best-effort */ }

    this.activeWindows = this.activeWindows.filter(w => w.slot !== slot)
  }

  /**
   * 返回给用户看的提示：如何 attach 到子 agent 监控 session。
   */
  sessionHint(): string {
    if (!this.initialized) return ''
    return `tmux a -t ${this.sessionName}  (Ctrl+B + 数字 切换子 agent 窗口)`
  }

  isReady(): boolean {
    return this.initialized
  }

  /**
   * 清理：杀掉整个 tmux 会话（主进程退出时调用）。
   * 这会终止所有子 agent 窗口内的 tail -f 进程。
   * Best-effort — 失败不抛。
   */
  destroy(): void {
    if (!this.initialized || !this.sessionName) return
    try {
      execSync(`tmux kill-session -t ${sq(this.sessionName)}`, { stdio: 'pipe' })
    } catch { /* best-effort */ }
    this.initialized = false
    this.sessionName = ''
    this.activeWindows = []
  }
}

/** Singleton */
export const tmuxLayout = new TmuxLayout()
