/**
 * Attack Chain Inference — maps vulnerability findings to next-phase actions.
 *
 * Used by BattleOrchestrator to:
 * 1. Auto-suggest next phase when high-confidence finding surfaces
 * 2. Inject attack chain context into dispatched agent prompts
 * 3. Recommend follow-up vuln_type to look for after exploitation succeeds
 *
 * Why a separate module: keeps orchestration logic decoupled from the actual
 * attack mapping data, so the mapping can grow independently and be unit-tested
 * without spinning up the full orchestrator.
 */

import type { PhaseName } from './orchestrator.js'

// ── Vulnerability taxonomy ────────────────────────────────────────────────

export type VulnType =
  | 'sqli' | 'nosqli' | 'rce' | 'lfi' | 'rfi' | 'path-traversal'
  | 'ssrf' | 'ssti' | 'xxe' | 'xss' | 'cmdi'
  | 'deserialization' | 'crlf' | 'smuggle'
  | 'auth-bypass' | 'idor' | 'weak-credentials'
  | 'sensitive-data' | 'info-leak'
  | 'misconfig'
  | 'unknown'

// ── Extended Finding ──────────────────────────────────────────────────────

export interface Finding {
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  title: string
  phase: string
  /** 0-100 — how confident we are this is real & exploitable */
  confidence: number
  /** What kind of bug — drives attack chain inference */
  vulnType: VulnType
  /** Where on the target — endpoint / URL / param / service */
  target?: string
  /** Raw evidence (curl command, payload, response excerpt) */
  evidence?: string
  /** When did we discover this (epoch ms) */
  discoveredAt: number
}

// ── Attack Chain Step ─────────────────────────────────────────────────────

export interface AttackChainStep {
  /** Suggested next phase to dispatch to */
  phase: PhaseName
  /** Agent type name to dispatch (matches BattleOrchestrator's expected types) */
  agentType: string
  /** Self-contained prompt with target + context + concrete task */
  prompt: string
  /** Confidence this step will succeed (0-100), based on input finding confidence */
  expectedConfidence: number
  /** If this exploit succeeds, what vuln_type should we look for next */
  followups: VulnType[]
}

// ── Chain mapping table ──────────────────────────────────────────────────

interface ChainRule {
  exploitablePhase: PhaseName
  agentType: string
  promptTemplate: (f: Finding, target: string) => string
  followups: VulnType[]
  /** Threshold for "auto-suggest exploit now" (default 70) */
  autoThreshold: number
}

const CHAIN: Record<VulnType, ChainRule | undefined> = {
  'sqli': {
    exploitablePhase: 'exploit',
    agentType: 'sqli-exploit',
    promptTemplate: (f, t) =>
      `利用 SQL 注入获取数据或 RCE。\n目标: ${t}\n漏洞参数: ${f.target ?? '待定'}\n` +
      `证据: ${f.evidence ?? '(需自行探测)'}\n` +
      `任务: 1) 验证注入 → 2) 提取 schema+credentials → 3) 尝试 INTO OUTFILE 写 shell 或调用 xp_cmdshell`,
    followups: ['rce', 'sensitive-data', 'weak-credentials'],
    autoThreshold: 70,
  },
  'nosqli': {
    exploitablePhase: 'exploit',
    agentType: 'nosqli-exploit',
    promptTemplate: (f, t) =>
      `利用 NoSQL 注入获取数据或 RCE。\n目标: ${t}\n漏洞参数: ${f.target ?? '待定'}\n` +
      `任务: 1) $where JS injection 探测 → 2) 数据提取 → 3) 升级到 RCE`,
    followups: ['rce', 'sensitive-data', 'auth-bypass'],
    autoThreshold: 70,
  },
  'rce': {
    exploitablePhase: 'exploit',
    agentType: 'manual-exploit',
    promptTemplate: (f, t) =>
      `RCE 漏洞已确认，立即获取 shell。\n目标: ${t}\n漏洞参数: ${f.target ?? '待定'}\n` +
      `证据: ${f.evidence ?? ''}\n` +
      `任务: 用 PayloadGenerator 生成对应 payload，立即反弹 shell 或写 webshell`,
    followups: ['weak-credentials', 'sensitive-data', 'auth-bypass'],
    autoThreshold: 50,  // RCE is critical — exploit on lower confidence
  },
  'lfi': {
    exploitablePhase: 'exploit',
    agentType: 'lfi-exploit',
    promptTemplate: (f, t) =>
      `LFI 漏洞已确认，升级到 RCE。\n目标: ${t}\n漏洞参数: ${f.target ?? '待定'}\n` +
      `任务: 1) php://filter 读源码 → 2) log poisoning 或 pearcmd.php → 3) 获取 webshell`,
    followups: ['rce', 'sensitive-data'],
    autoThreshold: 70,
  },
  'rfi': {
    exploitablePhase: 'exploit',
    agentType: 'rfi-exploit',
    promptTemplate: (f, t) =>
      `RFI 漏洞已确认，直接执行 payload。\n目标: ${t}\n漏洞参数: ${f.target ?? '待定'}\n` +
      `任务: 部署并触发远程 payload 获取 shell`,
    followups: ['rce', 'auth-bypass', 'sensitive-data'],
    autoThreshold: 60,
  },
  'path-traversal': {
    exploitablePhase: 'exploit',
    agentType: 'path-traversal-exploit',
    promptTemplate: (f, t) =>
      `路径穿越已确认，读取敏感文件。\n目标: ${t}\n漏洞参数: ${f.target ?? '待定'}\n` +
      `任务: 1) /etc/passwd + /etc/shadow → 2) SSH keys → 3) 应用配置（数据库密码）`,
    followups: ['rce', 'sensitive-data', 'weak-credentials'],
    autoThreshold: 65,
  },
  'ssrf': {
    exploitablePhase: 'exploit',
    agentType: 'ssrf-exploit',
    promptTemplate: (f, t) =>
      `SSRF 漏洞已确认，扫描内网。\n目标: ${t}\n漏洞参数: ${f.target ?? '待定'}\n` +
      `任务: 1) 内网端口扫描（172.16/24, 10.0/24, 192.168/24） → 2) 探测云元数据 169.254.169.254 → 3) 协议级攻击（gopher://, dict://）`,
    followups: ['rce', 'sensitive-data', 'auth-bypass'],
    autoThreshold: 70,
  },
  'ssti': {
    exploitablePhase: 'exploit',
    agentType: 'ssti-exploit',
    promptTemplate: (f, t) =>
      `SSTI 漏洞已确认，获取 RCE。\n目标: ${t}\n漏洞参数: ${f.target ?? '待定'}\n` +
      `任务: 1) 识别模板引擎 → 2) 用 PayloadGenerator 生成引擎专属 payload → 3) 反弹 shell`,
    followups: ['rce', 'auth-bypass'],
    autoThreshold: 75,
  },
  'xxe': {
    exploitablePhase: 'exploit',
    agentType: 'xxe-exploit',
    promptTemplate: (f, t) =>
      `XXE 漏洞已确认，读取文件或 RCE。\n目标: ${t}\n漏洞参数: ${f.target ?? '待定'}\n` +
      `任务: 1) file:// 读文件 → 2) PHP expect:// RCE → 3) OOB 数据外带`,
    followups: ['rce', 'sensitive-data', 'lfi'],
    autoThreshold: 65,
  },
  'xss': {
    exploitablePhase: 'weapon-match',  // XSS alone doesn't grant shell — search for cookie-steal/CSRF chains
    agentType: 'xss-weaponize',
    promptTemplate: (f, t) =>
      `XSS 漏洞已确认，武器化利用。\n目标: ${t}\n漏洞参数: ${f.target ?? '待定'}\n` +
      `任务: 1) 窃取 admin cookie → 2) 提权到 admin → 3) 找 admin 后台 RCE`,
    followups: ['auth-bypass', 'idor', 'sensitive-data'],
    autoThreshold: 80,  // XSS often needs user interaction — higher threshold
  },
  'cmdi': {
    exploitablePhase: 'exploit',
    agentType: 'cmdi-exploit',
    promptTemplate: (f, t) =>
      `命令注入已确认，立即反弹 shell。\n目标: ${t}\n漏洞参数: ${f.target ?? '待定'}\n` +
      `任务: PayloadGenerator 生成 cmdi payload 直接利用`,
    followups: ['rce', 'auth-bypass', 'sensitive-data'],
    autoThreshold: 60,
  },
  'deserialization': {
    exploitablePhase: 'exploit',
    agentType: 'deserialization-exploit',
    promptTemplate: (f, t) =>
      `反序列化漏洞已确认，利用 gadget chain 获取 RCE。\n目标: ${t}\n漏洞参数: ${f.target ?? '待定'}\n` +
      `任务: 1) 识别 engine（Java/PHP/.NET/Python） → 2) PayloadGenerator 生成 gadget 链 → 3) 投递 payload`,
    followups: ['rce', 'auth-bypass', 'sensitive-data'],
    autoThreshold: 80,  // Need precise gadget match
  },
  'crlf': {
    exploitablePhase: 'exploit',
    agentType: 'crlf-exploit',
    promptTemplate: (f, t) =>
      `CRLF 注入已确认，武器化。\n目标: ${t}\n漏洞参数: ${f.target ?? '待定'}\n` +
      `任务: 1) Set-Cookie 注入劫持会话 → 2) XSS via response splitting → 3) 缓存投毒`,
    followups: ['xss', 'auth-bypass'],
    autoThreshold: 75,
  },
  'smuggle': {
    exploitablePhase: 'exploit',
    agentType: 'smuggle-exploit',
    promptTemplate: (f, t) =>
      `HTTP Request Smuggling 已确认。\n目标: ${t}\n` +
      `任务: 1) 识别 CL.TE / TE.CL / H2 变种 → 2) 投递走私请求劫持其他用户请求 → 3) 升级到内部 RCE`,
    followups: ['rce', 'auth-bypass', 'sensitive-data'],
    autoThreshold: 85,
  },
  'auth-bypass': {
    exploitablePhase: 'exploit',
    agentType: 'auth-bypass-exploit',
    promptTemplate: (f, t) =>
      `认证绕过已确认，进入应用。\n目标: ${t}\n漏洞参数: ${f.target ?? '待定'}\n` +
      `任务: 1) 进入后台 → 2) 提权到 admin → 3) 找 admin 后台的 RCE/文件上传`,
    followups: ['rce', 'idor', 'sensitive-data'],
    autoThreshold: 70,
  },
  'idor': {
    exploitablePhase: 'exploit',
    agentType: 'idor-exploit',
    promptTemplate: (f, t) =>
      `IDOR 已确认，提取数据。\n目标: ${t}\n漏洞参数: ${f.target ?? '待定'}\n` +
      `任务: 1) 提取全用户数据 → 2) 找 admin 用户 → 3) 提权/越权`,
    followups: ['auth-bypass', 'sensitive-data'],
    autoThreshold: 60,
  },
  'weak-credentials': {
    exploitablePhase: 'exploit',
    agentType: 'credential-stuffing',
    promptTemplate: (f, t) =>
      `弱口令已确认，登录并提权。\n目标: ${t}\n` +
      `任务: 1) 登录目标服务 → 2) 查找后台 RCE → 3) 获取系统 shell`,
    followups: ['rce', 'auth-bypass', 'sensitive-data'],
    autoThreshold: 50,
  },
  'sensitive-data': {
    exploitablePhase: 'weapon-match',
    agentType: 'sensitive-data-analyzer',
    promptTemplate: (f, t) =>
      `敏感数据已泄露。\n目标: ${t}\n` +
      `任务: 1) 评估影响（credentials/PII/keys） → 2) 用泄露的 credentials 横向移动 → 3) 提取完整数据`,
    followups: ['auth-bypass', 'weak-credentials'],
    autoThreshold: 60,
  },
  'info-leak': {
    exploitablePhase: 'weapon-match',
    agentType: 'info-leak-analyzer',
    promptTemplate: (f, t) =>
      `信息泄露已发现。\n目标: ${t}\n` +
      `任务: 1) 评估可利用性（版本/路径/源码/keys） → 2) 针对泄露内容检索 WeaponRadar → 3) 升级利用`,
    followups: ['rce', 'weak-credentials', 'auth-bypass'],
    autoThreshold: 50,
  },
  'misconfig': {
    exploitablePhase: 'weapon-match',
    agentType: 'misconfig-analyzer',
    promptTemplate: (f, t) =>
      `配置错误已发现。\n目标: ${t}\n` +
      `任务: 1) 评估影响（CORS/directory listing/debug/admin exposed） → 2) 直接利用`,
    followups: ['rce', 'sensitive-data', 'auth-bypass'],
    autoThreshold: 55,
  },
  'unknown': undefined,
}

// ── Public API ────────────────────────────────────────────────────────────

/** Map vuln_type → attack chain step (or null if unknown). */
export function inferNextStep(finding: Finding, target: string): AttackChainStep | null {
  const rule = CHAIN[finding.vulnType]
  if (!rule) return null
  return {
    phase: rule.exploitablePhase,
    agentType: rule.agentType,
    prompt: rule.promptTemplate(finding, target),
    expectedConfidence: finding.confidence,
    followups: rule.followups,
  }
}

/** Should this finding auto-trigger exploit dispatch (vs waiting for supervisor)? */
export function shouldAutoProgress(finding: Finding): boolean {
  const rule = CHAIN[finding.vulnType]
  if (!rule) return false
  return (
    (finding.severity === 'critical' || finding.severity === 'high') &&
    finding.confidence >= rule.autoThreshold
  )
}

/** Build attack-chain context for injection into agent prompts. */
export function buildChainContext(findings: Finding[]): string {
  if (findings.length === 0) return ''
  const lines: string[] = ['## 已发现漏洞 → 推荐攻击链']
  for (const f of findings) {
    const step = inferNextStep(f, '(本任务目标)')
    const auto = shouldAutoProgress(f)
    if (!step) {
      lines.push(`- [${f.severity.toUpperCase()}] ${f.title} (类型: ${f.vulnType}) → 待人工评估`)
      continue
    }
    const autoTag = auto ? '🔥 [自动推进]' : '⏸ [需确认]'
    lines.push(
      `- ${autoTag} [${f.severity.toUpperCase()}] ${f.title}` +
      ` (类型: ${f.vulnType}, 置信度: ${f.confidence}%)` +
      `\n   → 下一阶段: ${step.phase} / agent: ${step.agentType}` +
      `\n   → 后续可查: ${step.followups.join(', ')}`,
    )
  }
  return lines.join('\n')
}

/** Extract a Finding from agent output (regex-based, mirrors orchestrator.extractFindings). */
export function parseFindingFromText(text: string, currentPhase: string): Finding | null {
  const match = text.match(/\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]\s+(.+)/i)
  if (!match) return null
  const sevRaw = match[1].toLowerCase()
  const sev = (sevRaw === 'critical' || sevRaw === 'high' || sevRaw === 'medium' || sevRaw === 'low' || sevRaw === 'info') ? sevRaw : 'info'
  const title = match[2].trim().slice(0, 200)

  // Try to detect vuln_type from title keywords (order matters — more specific first)
  const titleLower = title.toLowerCase()
  let vulnType: VulnType = 'unknown'
  let confidence = 50
  if (/nosql|mongodb|couchdb|cassandra/i.test(title)) { vulnType = 'nosqli'; confidence = 80 }
  else if (/sql\s*inj|sqli|union\s+select/i.test(title)) { vulnType = 'sqli'; confidence = 80 }
  else if (/command\s+inject|\bcmdi\b|os\s+command/i.test(title)) { vulnType = 'cmdi'; confidence = 90 }
  else if (/rce|remote\s+code/i.test(title)) { vulnType = 'rce'; confidence = 90 }
  else if (/lfi|local\s+file|file\s+inclusion/i.test(title)) { vulnType = 'lfi'; confidence = 80 }
  else if (/rfi|remote\s+file\s+inclusion/i.test(title)) { vulnType = 'rfi'; confidence = 85 }
  else if (/path\s+traversal|directory\s+traversal|\.\.\//i.test(title)) { vulnType = 'path-traversal'; confidence = 75 }
  else if (/ssrf|server.?side\s+request/i.test(title)) { vulnType = 'ssrf'; confidence = 80 }
  else if (/ssti|template\s+inject/i.test(title)) { vulnType = 'ssti'; confidence = 85 }
  else if (/xxe|xml\s+external/i.test(title)) { vulnType = 'xxe'; confidence = 85 }
  else if (/xss|cross.?site\s+script/i.test(title)) { vulnType = 'xss'; confidence = 70 }
  else if (/deserial|ysoserial|unserialize/i.test(title)) { vulnType = 'deserialization'; confidence = 85 }
  else if (/crlf|response\s+split/i.test(title)) { vulnType = 'crlf'; confidence = 80 }
  else if (/smuggl/i.test(title)) { vulnType = 'smuggle'; confidence = 90 }
  else if (/auth.?bypass|login\s+bypass/i.test(title)) { vulnType = 'auth-bypass'; confidence = 75 }
  else if (/idor|insecure\s+direct/i.test(title)) { vulnType = 'idor'; confidence = 70 }
  else if (/weak\s+(?:pass|cred|secret)|default\s+cred/i.test(title)) { vulnType = 'weak-credentials'; confidence = 80 }
  else if (/sensitive\s+data|hardcod|api\s+key|secret\s+key/i.test(title)) { vulnType = 'sensitive-data'; confidence = 75 }
  else if (/info\s+disclos|info\s+leak|stack\s+trace|version\s+disclos/i.test(title)) { vulnType = 'info-leak'; confidence = 50 }
  else if (/misconfig|cors|directory\s+listing|debug\s+mode/i.test(title)) { vulnType = 'misconfig'; confidence = 60 }

  // Bump confidence for severity
  if (sev === 'critical') confidence = Math.max(confidence, 90)
  else if (sev === 'high') confidence = Math.max(confidence, 75)

  return {
    severity: sev,
    title,
    phase: currentPhase,
    confidence,
    vulnType,
    discoveredAt: Date.now(),
  }
}

/** Get all known vuln types (for testing / UI). */
export function knownVulnTypes(): VulnType[] {
  return Object.keys(CHAIN).filter((k) => CHAIN[k as VulnType] !== undefined) as VulnType[]
}