/**
 * KnowledgeExtractor — rule-based knowledge extraction from agent sessions
 *
 * Extracts attack patterns, CVE notes, tool combos, and target profiles from:
 * 1. Real-time: each successful tool execution (extractFromToolResult)
 * 2. Session-end: full event log analysis (extractFromSession)
 *
 * Rule-based extraction — zero LLM cost, instant.
 */

import type { KnowledgeBase, CveNoteEntry, ToolComboEntry, AttackPatternEntry, TargetProfileEntry } from './knowledgeBase.js'
import type { EventLogEntry } from './eventLog.js'

// Known CVE regex patterns in tool input/output
const CVE_REGEX = /CVE-\d{4}-\d{4,}/gi
const KNOWN_CVE_SERVICES: Record<string, string[]> = {
  'CVE-2021-44228': ['Log4Shell', 'Java'],
  'CVE-2022-22965': ['Spring4Shell', 'Spring'],
  'CVE-2021-41773': ['Apache', 'Path Traversal'],
  'CVE-2019-0193': ['Apache Solr', 'DataImportHandler'],
  'CVE-2019-17558': ['Apache Solr', 'Velocity'],
  'CVE-2022-26134': ['Confluence', 'OGNL'],
  'CVE-2024-23897': ['Jenkins', 'Groovy'],
  'CVE-2021-25646': ['Apache Druid', 'RCE'],
  'CVE-2017-5638': ['Apache Struts2', 'OGNL'],
}

// Known exploit command patterns
const EXPLOIT_PATTERNS = [
  { name: 'bash反弹', regex: /bash\s+-[ci].*\/dev\/tcp\//i, type: 'curl' },
  { name: 'nc反弹', regex: /\bnc\b.*-e\s+\/bin\/(ba)?sh/i, type: 'curl' },
  { name: 'python反弹', regex: /python.*socket.*connect/i, type: 'python' },
  { name: 'sqlmap os-shell', regex: /sqlmap.*--os-shell/i, type: 'python' },
  { name: 'msf exploit', regex: /msfconsole.*exploit/i, type: 'msf' },
  { name: 'redis RCE', regex: /redis-cli.*config\s+set\s+dir/i, type: 'curl' },
  { name: 'ThinkPHP RCE', regex: /think\\app\/invokefunction/i, type: 'curl' },
  { name: 'Shiro RCE', regex: /rememberMe=.*ysoserial/i, type: 'python' },
  { name: 'Fastjson RCE', regex: /@type.*JdbcRowSetImpl/i, type: 'curl' },
]

// Tool chain patterns — sequences that form effective combos
const KNOWN_TOOL_CHAINS: Record<string, string[]> = {
  'Web资产发现': ['subfinder', 'httpx', 'katana'],
  '漏洞扫描': ['nmap', 'nuclei', 'ffuf'],
  '认证攻击': ['nuclei', 'hydra'],
  '内网侦察': ['nmap', 'enum4linux', 'crackmapexec'],
  '容器逃逸': ['docker', 'curl', 'chisel'],
}

// Shell acquisition indicators
const SHELL_INDICATORS = [
  /uid=\d+\(/,                  // Linux: uid=0(root)
  /Linux\s+\S+\s+\d+\.\d+\.\d+/, // Linux kernel info after 'uname -a'
  /Microsoft Windows/,           // Windows target
  /NT\s+AUTHORITY/,              // Windows SYSTEM
  /root@/,                       // root shell prompt
  /meterpreter>/,                // Metasploit session
]

export class KnowledgeExtractor {
  private kb: KnowledgeBase
  private toolCallSequence: Array<{ tool: string; input: string; result: string; timestamp: string }> = []
  private attackChainSteps: string[] = []
  private detectedTargetType: string = 'unknown'
  private detectedCves: Set<string> = new Set()
  private shellAcquired = false

  constructor(kb: KnowledgeBase) {
    this.kb = kb
  }

  /**
   * Real-time extraction — called after each successful tool execution.
   * Detects CVE exploitation, shell acquisition, and tool chain building.
   */
  extractFromToolResult(toolName: string, input: Record<string, unknown>, result: string): void {
    const cmd = String(input.command || '')
    const combinedText = `${cmd} ${result}`.slice(0, 5000) // limit analysis size

    // Track tool sequence for combo detection
    this.toolCallSequence.push({
      tool: toolName,
      input: cmd,
      result: result.slice(0, 500),
      timestamp: new Date().toISOString(),
    })
    // Keep only last 50 tool calls
    if (this.toolCallSequence.length > 50) {
      this.toolCallSequence = this.toolCallSequence.slice(-50)
    }

    // Extract CVE references
    const cves = combinedText.match(CVE_REGEX)
    if (cves) {
      for (const cve of cves) {
        this.detectedCves.add(cve.toUpperCase())
      }
    }

    // Detect target type from tool results
    this._detectTargetType(combinedText)

    // Detect shell acquisition
    if (!this.shellAcquired && this._checkShellAcquired(result)) {
      this.shellAcquired = true
      this.attackChainSteps.push('获取shell')
    }

    // Check for successful exploit execution
    this._extractCveNoteIfExploit(cmd, result, combinedText)

    // Track attack chain steps
    this._trackAttackStep(toolName, cmd, result)
  }

  /**
   * Session-end extraction — called when a session completes.
   * Extracts attack patterns, tool combos, target profiles from full session data.
   */
  extractFromSession(): void {
    // Extract attack patterns from the tool call sequence
    if (this.attackChainSteps.length >= 3) {
      this._extractAttackPattern()
    }

    // Extract tool combos from tool call sequence
    if (this.toolCallSequence.length > 0) {
      this._extractToolCombos()
    }

    // Extract target profile
    if (this.detectedTargetType !== 'unknown') {
      this._extractTargetProfile()
    }
  }

  /**
   * Extract attack chains from EventLog entries.
   * Analyzes the full event sequence to identify successful attack paths.
   */
  extractAttackChains(events: EventLogEntry[]): void {
    // Find successful exploit sequences in event log
    const toolCalls = events.filter((e) => e.type === 'tool_call')
    const toolResults = events.filter((e) => e.type === 'tool_result' && !e.detail?.isError)

    if (toolResults.length < 2) return

    // Look for recon → scan → exploit → shell patterns
    const phases = this._classifyEventPhases(toolCalls, toolResults)
    if (phases.recon.length > 0 && phases.exploit.length > 0) {
      const chain: string[] = []
      if (phases.recon.length > 0) chain.push('侦察发现资产')
      if (phases.scan.length > 0) chain.push('漏洞扫描发现弱点')
      if (phases.exploit.length > 0) chain.push('漏洞利用成功')
      if (this.shellAcquired) chain.push('获取shell')

      if (chain.length >= 2) {
        this.kb.write('attack_patterns', {
          title: `自动化攻击链: ${chain.join(' → ')}`,
          chain,
          target_type: this.detectedTargetType,
          techniques: this._extractTechniques(events),
          success_rate: 0.8, // Initial confidence from successful chain
          used_count: 1,
          last_used: new Date().toISOString(),
        })
      }
    }
  }

  /**
   * Extract CVE notes from Finding entries.
   */
  extractCveNotes(findings: Array<{ title: string; description: string; severity: string }>): void {
    for (const finding of findings) {
      const cves = finding.title.match(CVE_REGEX) || finding.description.match(CVE_REGEX)
      if (!cves) continue

      for (const cve of cves) {
        const cveUpper = cve.toUpperCase()
        const serviceInfo = KNOWN_CVE_SERVICES[cveUpper] || ['Unknown']

        this.kb.write('cve_notes', {
          cve: cveUpper,
          service: serviceInfo[0],
          exploit_summary: finding.title,
          payload_type: this._detectPayloadType(finding.description),
          success: finding.severity === 'critical' || finding.severity === 'high',
          confidence: finding.severity === 'critical' ? 0.95 : finding.severity === 'high' ? 0.8 : 0.6,
          notes: finding.description.slice(0, 500),
        })
      }
    }
  }

  /**
   * Extract tool combos from tool call sequence.
   */
  extractToolCombos(events: EventLogEntry[]): void {
    const toolNames = events
      .filter((e) => e.type === 'tool_call')
      .map((e) => e.source)

    // Check against known combo patterns
    for (const [name, tools] of Object.entries(KNOWN_TOOL_CHAINS)) {
      const present = tools.filter((t) =>
        toolNames.some((tn) => tn.toLowerCase().includes(t.toLowerCase()))
      )

      if (present.length >= Math.ceil(tools.length * 0.6)) {
        // At least 60% of the combo tools were used → valid combo
        this.kb.write('tool_combos', {
          name,
          tools: present,
          command_template: present.join(' → '),
          purpose: `${name} — 在本次session中验证有效`,
          used_count: 1,
          success_rate: 0.75,
        })
      }
    }
  }

  /**
   * Extract target profile from session data.
   */
  extractTargetProfile(events: EventLogEntry[]): void {
    if (this.detectedTargetType === 'unknown') return

    const weaknesses = this._extractWeaknesses(events)
    const techniques = this._extractTechniques(events)

    if (weaknesses.length > 0 || techniques.length > 0) {
      this.kb.write('target_profiles', {
        target_type: this.detectedTargetType,
        indicators: this._extractIndicators(events),
        common_weaknesses: weaknesses,
        successful_techniques: techniques,
      })
    }
  }

  // ─── Private helpers ──────────────────────────────────────────────────────

  private _checkShellAcquired(result: string): boolean {
    return SHELL_INDICATORS.some((re) => re.test(result))
  }

  private _detectTargetType(text: string): void {
    if (text === this.detectedTargetType) return

    const typePatterns: Record<string, RegExp[]> = {
      'Spring Boot': [/actuator/, /\/env/, /heapdump/, /spring\.cloud/],
      'ThinkPHP': [/think\\app/, /invokefunction/, /thinkphp/i],
      'Apache Solr': [/solr/, /solr\/select/],
      'WordPress': [/wp-content/, /wp-admin/, /wordpress/i],
      'Java Web': [/\.jsp/, /tomcat/, /weblogic/, /jboss/],
      'PHP': [/\.php/, /phpinfo/, /eval\(/],
      'Node.js': [/node_modules/, /express/, /next\.js/],
      'Python': [/flask/, /django/, /python/, /\.py/],
      'Redis': [/redis-cli/, /6379/],
      'Docker': [/docker\.sock/, /\/var\/run\/docker/],
      'Kubernetes': [/kubernetes/, /kubectl/, /pods/, /\/api\/v1\//],
      'Windows AD': [/domain\.controller/, /kerberos/, /445/, /smb/],
    }

    for (const [type, patterns] of Object.entries(typePatterns)) {
      if (patterns.some((p) => p.test(text))) {
        this.detectedTargetType = type
        break
      }
    }
  }

  private _extractCveNoteIfExploit(cmd: string, result: string, combined: string): void {
    // Check if this looks like a successful exploit
    if (!this._checkShellAcquired(result) && !SHELL_INDICATORS.some((re) => re.test(cmd))) {
      return // Not a clear exploit success
    }

    const cves = combined.match(CVE_REGEX)
    if (!cves || cves.length === 0) return

    for (const cve of cves) {
      const cveUpper = cve.toUpperCase()
      const serviceInfo = KNOWN_CVE_SERVICES[cveUpper] || ['Unknown']
      const exploitType = this._detectPayloadType(combined)

      this.kb.write('cve_notes', {
        cve: cveUpper,
        service: serviceInfo[0],
        exploit_summary: `成功利用 ${cveUpper} 获取命令执行`,
        payload_type: exploitType,
        success: true,
        confidence: 0.9,
        notes: `命令: ${cmd.slice(0, 200)}`,
      })
    }
  }

  private _detectPayloadType(text: string): string {
    for (const p of EXPLOIT_PATTERNS) {
      if (p.regex.test(text)) return p.type
    }
    if (text.includes('curl')) return 'curl'
    if (text.includes('python')) return 'python'
    if (text.includes('msf') || text.includes('metasploit')) return 'msf'
    return 'other'
  }

  private _trackAttackStep(toolName: string, cmd: string, result: string): void {
    // Map tool usage to attack chain phases
    if (/subfinder|amass|dnsx/.test(cmd)) {
      if (!this.attackChainSteps.includes('DNS子域名枚举')) {
        this.attackChainSteps.push('DNS子域名枚举')
      }
    }
    if (/nmap|masscan|naabu/.test(cmd)) {
      if (!this.attackChainSteps.includes('端口扫描')) {
        this.attackChainSteps.push('端口扫描')
      }
    }
    if (/httpx|wafw00f/.test(cmd)) {
      if (!this.attackChainSteps.includes('Web指纹识别')) {
        this.attackChainSteps.push('Web指纹识别')
      }
    }
    if (/nuclei|nikto/.test(cmd)) {
      if (!this.attackChainSteps.includes('漏洞扫描')) {
        this.attackChainSteps.push('漏洞扫描')
      }
    }
    if (/ffuf|dirsearch|gobuster/.test(cmd)) {
      if (!this.attackChainSteps.includes('目录枚举')) {
        this.attackChainSteps.push('目录枚举')
      }
    }
    if (/hydra|kerbrute/.test(cmd)) {
      if (!this.attackChainSteps.includes('暴力破解')) {
        this.attackChainSteps.push('暴力破解')
      }
    }
    if (/curl.*system|curl.*\/etc\/passwd|curl.*id['"`]/.test(cmd)) {
      if (!this.attackChainSteps.includes('漏洞利用')) {
        this.attackChainSteps.push('漏洞利用')
      }
    }
  }

  private _extractAttackPattern(): void {
    if (this.attackChainSteps.length < 2) return

    this.kb.write('attack_patterns', {
      title: `攻击链: ${this.attackChainSteps.join(' → ')}`,
      chain: [...this.attackChainSteps],
      target_type: this.detectedTargetType,
      techniques: this._extractTechniquesFromSteps(this.attackChainSteps),
      success_rate: this.shellAcquired ? 0.85 : 0.5,
      used_count: 1,
      last_used: new Date().toISOString(),
    })
  }

  private _extractToolCombos(): void {
    // Find contiguous sequences of tool calls that form combos
    const tools = this.toolCallSequence.map((t) => t.tool)
    const uniqueTools = [...new Set(tools)].filter((t) => t !== 'Bash' && t !== 'Read')

    if (uniqueTools.length >= 2) {
      this.kb.write('tool_combos', {
        name: `Session工具组合: ${uniqueTools.join('+')}`,
        tools: uniqueTools.slice(0, 8),
        command_template: uniqueTools.slice(0, 4).join(' → '),
        purpose: `本次session验证的组合: ${uniqueTools.join(', ')}`,
        used_count: 1,
        success_rate: this.shellAcquired ? 0.8 : 0.5,
      })
    }
  }

  private _extractTargetProfile(): void {
    // Already handled by extractTargetProfile(events) — skip duplicate
  }

  private _extractTechniques(events: EventLogEntry[]): string[] {
    // Map observed actions to MITRE ATT&CK TTPs
    const ttps = new Set<string>()
    for (const event of events) {
      const detail = JSON.stringify(event.detail)
      if (/nmap|port/.test(detail)) ttps.add('T1046') // Network Service Scanning
      if (/nuclei|vuln/.test(detail)) ttps.add('T1595') // Active Scanning
      if (/hydra|password/.test(detail)) ttps.add('T1110') // Brute Force
      if (/curl.*exploit|python.*reverse/.test(detail)) ttps.add('T1190') // Exploit Public App
      if (/uid=0|root/.test(detail)) ttps.add('T1068') // Privilege Escalation
      if (/find.*flag/.test(detail)) ttps.add('T1005') // Data from Local System
    }
    return Array.from(ttps)
  }

  private _extractTechniquesFromSteps(steps: string[]): string[] {
    const ttps = new Set<string>()
    for (const step of steps) {
      if (step.includes('DNS') || step.includes('子域名')) ttps.add('T1592')
      if (step.includes('端口')) ttps.add('T1046')
      if (step.includes('指纹')) ttps.add('T1592')
      if (step.includes('漏洞扫描')) ttps.add('T1595')
      if (step.includes('目录')) ttps.add('T1083')
      if (step.includes('暴力')) ttps.add('T1110')
      if (step.includes('利用')) ttps.add('T1190')
      if (step.includes('shell')) ttps.add('T1059')
    }
    return Array.from(ttps)
  }

  private _extractWeaknesses(events: EventLogEntry[]): string[] {
    const weaknesses = new Set<string>()
    for (const event of events) {
      const detail = JSON.stringify(event.detail)
      if (/default.*(login|credential|password)/i.test(detail)) weaknesses.add('默认凭证')
      if (/unauthorized|unauthenticated/i.test(detail)) weaknesses.add('未授权访问')
      if (/information.?disclosure|info.?leak/i.test(detail)) weaknesses.add('信息泄露')
      if (/rce|remote.*code.*execution/i.test(detail)) weaknesses.add('远程代码执行')
      if (/sql.?injection/i.test(detail)) weaknesses.add('SQL注入')
      if (/xss|cross.*site.*scripting/i.test(detail)) weaknesses.add('XSS')
      if (/file.?upload/i.test(detail)) weaknesses.add('文件上传')
      if (/path.?traversal|directory.?traversal/i.test(detail)) weaknesses.add('路径遍历')
    }
    return Array.from(weaknesses)
  }

  private _extractIndicators(events: EventLogEntry[]): string[] {
    const indicators = new Set<string>()
    for (const event of events) {
      const src = event.source.toLowerCase()
      if (src.includes('httpx')) indicators.add('Web服务存活')
      if (src.includes('nmap')) indicators.add('端口开放')
      if (src.includes('nuclei')) indicators.add('存在CVE漏洞')
      if (src.includes('subfinder')) indicators.add('子域名枚举')
      if (src.includes('ffuf')) indicators.add('隐藏路径发现')
    }
    return Array.from(indicators)
  }

  private _classifyEventPhases(
    toolCalls: EventLogEntry[],
    toolResults: EventLogEntry[],
  ): { recon: EventLogEntry[]; scan: EventLogEntry[]; exploit: EventLogEntry[] } {
    const recon: EventLogEntry[] = []
    const scan: EventLogEntry[] = []
    const exploit: EventLogEntry[] = []

    for (const event of toolCalls) {
      const src = event.source.toLowerCase()
      const detail = JSON.stringify(event.detail).toLowerCase()
      if (/subfinder|dnsx|amass|httpx|wafw00f/.test(src) || /subdomain|dns|web.*probe/.test(detail)) {
        recon.push(event)
      } else if (/nmap|nuclei|nikto|ffuf|masscan|naabu/.test(src) || /scan|enum|probe/.test(detail)) {
        scan.push(event)
      } else if (/curl.*system|python.*exploit|msf|sqlmap|hydra/.test(detail)) {
        exploit.push(event)
      }
    }

    return { recon, scan, exploit }
  }
}
