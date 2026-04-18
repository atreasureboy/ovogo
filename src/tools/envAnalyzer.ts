/**
 * EnvAnalyzerTool — environment analysis for authorized security assessments
 *
 * Probes target for WAF/EDR/sandbox protections and returns structured
 * reports with evasion recommendations. Used in CTF/authorized penetration
 * testing to understand the defensive posture of the target environment.
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
    product: 'FireEye/Mandiant',
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

interface EnvAnalyzerInput {
  target: string
  analyze_mode: 'waf' | 'edr' | 'sandbox' | 'all'
  port?: number
  shell_session_id?: string
}

export class EnvAnalyzerTool implements Tool {
  name = 'EnvAnalyzer'

  definition: ToolDefinition = {
    type: 'function',
    function: {
      name: 'EnvAnalyzer',
      description: `Analyze target environment for WAF/EDR/sandbox protections in authorized security assessments.

## Modes
- analyze_mode: 'waf' = WAF only, 'edr' = EDR only, 'sandbox' = sandbox only, 'all' = full scan
- target: target URL (e.g., http://1.2.3.4 or http://example.com)
- port: optional port (default 80/443)
- shell_session_id: if you already have shell access, pass session_id for remote EDR/sandbox analysis`,
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Target URL (e.g., http://1.2.3.4)' },
          analyze_mode: { type: 'string', enum: ['waf', 'edr', 'sandbox', 'all'], description: 'Analysis mode' },
          port: { type: 'number', description: 'Target port (default parsed from URL)' },
          shell_session_id: { type: 'string', description: 'Existing shell session ID for remote EDR/sandbox analysis' },
        },
        required: ['target', 'analyze_mode'],
      },
    },
  }

  async execute(input: Record<string, unknown>, context: ToolContext): Promise<ToolResult> {
    const { target, analyze_mode, port, shell_session_id } = input as unknown as EnvAnalyzerInput

    const results: string[] = []
    const recommendations: string[] = []

    try {
      if (analyze_mode === 'waf' || analyze_mode === 'all') {
        const wafResult = await this.detectWAF(target, port)
        results.push(wafResult.report)
        if (wafResult.detected) {
          recommendations.push(...wafResult.recommendations)
        }
      }

      if ((analyze_mode === 'edr' || analyze_mode === 'all') && shell_session_id) {
        const edrResult = await this.detectEDR(shell_session_id, context)
        results.push(edrResult.report)
        if (edrResult.detected) {
          recommendations.push(...edrResult.recommendations)
        }
      }

      if ((analyze_mode === 'sandbox' || analyze_mode === 'all') && shell_session_id) {
        const sandboxResult = await this.detectSandbox(shell_session_id, context)
        results.push(sandboxResult.report)
        if (sandboxResult.detected) {
          recommendations.push(...sandboxResult.recommendations)
        }
      }
    } catch (err) {
      results.push(`[Analysis Exception] ${(err as Error).message}`)
      results.push('Falling back to default evasion strategy (base64 encoding + chunked transfer).')
    }

    if (results.length === 0) {
      return {
        content: `[EnvAnalyzer] No analysis executed.\nReason: analyze_mode="${analyze_mode}" but no shell_session_id (EDR/sandbox analysis requires shell access).\nWAF analysis attempted but target may be unreachable.\n\nRecommend default evasion strategy.`,
        isError: false,
      }
    }

    const output = [
      '[EnvAnalyzer] Environment Analysis Report',
      '═'.repeat(50),
      ...results,
      '',
      '── Recommendations ──',
      recommendations.length > 0 ? recommendations.map((r, i) => `${i + 1}. ${r}`).join('\n') : 'No special protections detected. Standard techniques should work.',
      '',
      'TechniqueGenerator Usage:',
      `  TechniqueGenerator({ technique: "corresponding technique", payload: "original payload", analysis_context: { waf: "detected WAF", edr: "detected EDR" } })`,
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
        recommendations.push(`WAF "${wafName}" confirmed. Use TechniqueGenerator({ technique: "waf_evasion" }) to generate evasion payloads`)
        recommendations.push('Chunked transfer encoding: Transfer-Encoding: chunked')
        recommendations.push('HTTP parameter pollution: same parameter sent multiple times')
        return { detected: true, report: `[WAF] Detected: ${wafName}\nMethod: wafw00f`, recommendations }
      }
    } catch { /* wafw00f not available */ }

    // Manual curl probes
    const probes = [
      { url: `${target}/?id=1' OR '1'='1`, headers: '' },
      { url: `${target}/../../../etc/passwd`, headers: '' },
      { url: target, headers: '-H "User-Agent: \' OR 1=1--"' },
      { url: target, headers: '-H "X-Forwarded-For: 127.0.0.1"' },
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

    // Check for generic blocking patterns
    let genericBlockDetected = false
    try {
      const { stdout: normalStatus } = await exec(`curl -sS -m 8 -o /dev/null -w "%{http_code}" "${target}" 2>/dev/null || echo "000"`)
      const { stdout: blockStatus } = await exec(`curl -sS -m 8 -o /dev/null -w "%{http_code}" "${target}/?id=1'+OR+1%3D1--" 2>/dev/null || echo "000"`)
      if (normalStatus !== blockStatus && (blockStatus === '403' || blockStatus === '406' || blockStatus === '503' || blockStatus === '429')) {
        genericBlockDetected = true
      }
    } catch { /* ignore */ }

    if (detectedWAF) {
      recommendations.push(`WAF "${detectedWAF}" confirmed (confidence: ${detectedConfidence})`)
      recommendations.push(`Use TechniqueGenerator({ technique: "waf_evasion", analysis_context: { waf: "${detectedWAF}" } })`)
      recommendations.push('Recommended: chunked transfer encoding / HTTP parameter pollution / Unicode encoding / SQL comment insertion')
      return {
        detected: true,
        report: `[WAF] Detected: ${detectedWAF} (confidence: ${(detectedConfidence * 100).toFixed(0)}%)\nMethod: manual HTTP probes`,
        recommendations,
      }
    }

    if (genericBlockDetected) {
      recommendations.push('Possible WAF/IP restriction detected (403 on malicious probes, normal on clean requests)')
      recommendations.push('Use TechniqueGenerator({ technique: "waf_evasion" }) to generate evasion payloads')
      recommendations.push('Reduce request rate, use random User-Agent, add legitimate headers')
      return {
        detected: true,
        report: '[WAF] Suspected WAF/IP restriction (generic blocking pattern)\nMethod: status code comparison',
        recommendations,
      }
    }

    return { detected: false, report: '[WAF] No WAF protections detected', recommendations: [] }
  }

  // ── EDR Detection (requires shell access) ──────────────────────────────

  private async detectEDR(shellSessionId: string, context: ToolContext): Promise<{ detected: boolean; report: string; recommendations: string[] }> {
    const detected: string[] = []
    const recommendations: string[] = []

    try {
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
          recommendations.push(`${edr.product} confirmed. AMSI bypass should be performed before any PowerShell execution`)
          recommendations.push(`Use TechniqueGenerator({ technique: "amsi_bypass", platform: "windows", analysis_context: { edr: "${edr.product}" } })`)
          recommendations.push('Avoid disk writes — use in-memory execution or fileless techniques')
          if (edr.product === 'Windows Defender') {
            recommendations.push('Defender: consider adding exclusion path via Add-MpPreference -ExclusionPath')
          }
        }
      }
    } catch { /* not Windows or no shell */ }

    if (detected.length > 0) {
      return {
        detected: true,
        report: `[EDR] Detected: ${detected.join(', ')}\nMethod: process list matching`,
        recommendations,
      }
    }

    return {
      detected: false,
      report: `[EDR] Unable to remotely detect EDR (no shell access). After obtaining shell, run:\ntasklist | findstr /I "CSFalcon Sentinel MsMpEng ccSvc RepMgr avp"\nsc query | findstr /I "WinDefend CrowdStrike Sentinel Trend"\ndriverquery | findstr /I "WdFilter CsDeviceControl SRTSP"`,
      recommendations: ['For Windows targets, assume EDR presence by default. Prepare AMSI bypass proactively.'],
    }
  }

  // ── Sandbox Detection (requires shell access) ──────────────────────────

  private async detectSandbox(shellSessionId: string, context: ToolContext): Promise<{ detected: boolean; report: string; recommendations: string[] }> {
    const indicators: string[] = []
    const recommendations: string[] = []

    try {
      const { stdout: cpuInfo } = await exec(`nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo 2>/dev/null || echo "unknown"`)
      const cpuCount = parseInt(cpuInfo.trim()) || 99
      if (cpuCount <= 2) {
        indicators.push(`CPU cores: ${cpuCount} (≤2 may indicate sandbox/VM)`)
      }

      const { stdout: memInfo } = await exec(`free -m 2>/dev/null | grep Mem | awk '{print $2}' || echo "unknown"`)
      const memMb = parseInt(memInfo.trim()) || 99999
      if (memMb < 2048) {
        indicators.push(`Memory: ${memMb}MB (<2GB may indicate sandbox/VM)`)
      }

      const { stdout: hostname } = await exec(`hostname 2>/dev/null || echo ""`)
      for (const su of SANDBOX_USERNAMES) {
        if (hostname.toLowerCase().includes(su)) {
          indicators.push(`Hostname contains "${su}", possible sandbox environment`)
          break
        }
      }

      const { stdout: macInfo } = await exec(`ip link show 2>/dev/null | grep ether | head -3 || ifconfig 2>/dev/null | grep ether | head -3 || true`)
      for (const prefix of VM_MAC_PREFIXES) {
        if (macInfo.toLowerCase().includes(prefix.toLowerCase())) {
          indicators.push(`MAC address prefix ${prefix}, possible virtual machine`)
          break
        }
      }
    } catch { /* not accessible */ }

    if (indicators.length > 0) {
      recommendations.push('Sandbox/VM indicators detected. Consider delayed execution or legitimate process injection techniques')
      recommendations.push('Avoid obvious malicious behavior patterns (rapid port scanning,大量 network connections)')
      return {
        detected: true,
        report: `[Sandbox] Detected indicators:\n${indicators.map((i) => `  - ${i}`).join('\n')}`,
        recommendations,
      }
    }

    return { detected: false, report: '[Sandbox] No sandbox indicators detected', recommendations: [] }
  }
}
