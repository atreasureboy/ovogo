import test from 'node:test'
import assert from 'node:assert/strict'
import {
  inferNextStep,
  shouldAutoProgress,
  buildChainContext,
  parseFindingFromText,
  knownVulnTypes,
} from '../dist/src/core/attackChain.js'

const target = 'http://target.example.com'

// ── inferNextStep ──────────────────────────────────────────────────────────

test('inferNextStep maps sqli → exploit agent', () => {
  const f = { severity: 'high', title: 'SQL injection', phase: 'vuln-scan', confidence: 80, vulnType: 'sqli', target: 'http://t/?id=', discoveredAt: 0 }
  const step = inferNextStep(f, target)
  assert.equal(step.phase, 'exploit')
  assert.equal(step.agentType, 'sqli-exploit')
  assert.match(step.prompt, /SQL/)
  assert.ok(step.followups.includes('rce'))
})

test('inferNextStep maps rce → exploit with RCE-specific agent', () => {
  const f = { severity: 'critical', title: 'RCE', phase: 'vuln-scan', confidence: 90, vulnType: 'rce', discoveredAt: 0 }
  const step = inferNextStep(f, target)
  assert.equal(step.phase, 'exploit')
  assert.equal(step.agentType, 'manual-exploit')
})

test('inferNextStep maps xss → weapon-match (not exploit)', () => {
  const f = { severity: 'high', title: 'XSS', phase: 'vuln-scan', confidence: 80, vulnType: 'xss', discoveredAt: 0 }
  const step = inferNextStep(f, target)
  assert.equal(step.phase, 'weapon-match')
  assert.equal(step.agentType, 'xss-weaponize')
})

test('inferNextStep returns null for unknown vuln_type', () => {
  const f = { severity: 'low', title: 'mystery', phase: 'vuln-scan', confidence: 50, vulnType: 'unknown', discoveredAt: 0 }
  assert.equal(inferNextStep(f, target), null)
})

test('inferNextStep prompt embeds target and finding location', () => {
  const f = { severity: 'high', title: 'LFI', phase: 'vuln-scan', confidence: 75, vulnType: 'lfi', target: '/var/www/html/index.php?file=', evidence: 'curl -F file=@/etc/passwd', discoveredAt: 0 }
  const step = inferNextStep(f, target)
  assert.match(step.prompt, /var\/www\/html/)
  assert.match(step.prompt, /LFI/)
  assert.match(step.prompt, /http:\/\/target\.example\.com/)
})

// ── shouldAutoProgress ─────────────────────────────────────────────────────

test('shouldAutoProgress: high-confidence RCE auto-progresses (threshold 50)', () => {
  const f = { severity: 'critical', title: 'RCE', phase: 'vuln-scan', confidence: 60, vulnType: 'rce', discoveredAt: 0 }
  assert.equal(shouldAutoProgress(f), true)
})

test('shouldAutoProgress: medium-severity XSS below 80% does NOT auto-progress', () => {
  const f = { severity: 'medium', title: 'XSS', phase: 'vuln-scan', confidence: 75, vulnType: 'xss', discoveredAt: 0 }
  assert.equal(shouldAutoProgress(f), false)
})

test('shouldAutoProgress: low-severity finding never auto-progresses', () => {
  const f = { severity: 'low', title: 'info leak', phase: 'vuln-scan', confidence: 90, vulnType: 'info-leak', discoveredAt: 0 }
  assert.equal(shouldAutoProgress(f), false)
})

test('shouldAutoProgress: high-severity SQLi at 70% auto-progresses', () => {
  const f = { severity: 'high', title: 'SQLi', phase: 'vuln-scan', confidence: 70, vulnType: 'sqli', discoveredAt: 0 }
  assert.equal(shouldAutoProgress(f), true)
})

test('shouldAutoProgress: smuggled HTTP smuggling needs 85%+', () => {
  const f1 = { severity: 'critical', title: 'HTTP smuggling', phase: 'vuln-scan', confidence: 80, vulnType: 'smuggle', discoveredAt: 0 }
  const f2 = { severity: 'critical', title: 'HTTP smuggling', phase: 'vuln-scan', confidence: 90, vulnType: 'smuggle', discoveredAt: 0 }
  assert.equal(shouldAutoProgress(f1), false)
  assert.equal(shouldAutoProgress(f2), true)
})

// ── buildChainContext ──────────────────────────────────────────────────────

test('buildChainContext returns empty string when no findings', () => {
  assert.equal(buildChainContext([]), '')
})

test('buildChainContext marks auto-progressing findings with fire emoji', () => {
  const f1 = { severity: 'critical', title: 'RCE in /admin', phase: 'vuln-scan', confidence: 90, vulnType: 'rce', discoveredAt: 0 }
  const f2 = { severity: 'low', title: 'XSS', phase: 'vuln-scan', confidence: 50, vulnType: 'xss', discoveredAt: 0 }
  const ctx = buildChainContext([f1, f2])
  assert.match(ctx, /🔥.*RCE/s)
  assert.match(ctx, /⏸.*XSS/s)
})

test('buildChainContext includes followups recommendations', () => {
  const f = { severity: 'high', title: 'SSRF', phase: 'vuln-scan', confidence: 80, vulnType: 'ssrf', discoveredAt: 0 }
  const ctx = buildChainContext([f])
  assert.match(ctx, /后续可查: rce, sensitive-data, auth-bypass/)
})

// ── parseFindingFromText ───────────────────────────────────────────────────

test('parseFindingFromText extracts severity and title', () => {
  const f = parseFindingFromText('[CRITICAL] SQL injection in /api/users?id=', 'vuln-scan')
  assert.ok(f)
  assert.equal(f.severity, 'critical')
  assert.match(f.title, /SQL injection/)
})

test('parseFindingFromText detects vuln_type from title keywords', () => {
  const cases = [
    { title: 'SQL injection via id param', expected: 'sqli' },
    { title: 'NoSQL injection in MongoDB endpoint', expected: 'nosqli' },
    { title: 'Remote code execution via upload', expected: 'rce' },
    { title: 'Local file inclusion in /file=', expected: 'lfi' },
    { title: 'SSRF via url parameter', expected: 'ssrf' },
    { title: 'SSTI in Jinja2 template', expected: 'ssti' },
    { title: 'XXE in XML parser', expected: 'xxe' },
    { title: 'Reflected XSS in search', expected: 'xss' },
    { title: 'Command injection via ping', expected: 'cmdi' },
    { title: 'Deserialization via ysoserial', expected: 'deserialization' },
    { title: 'CRLF injection in header', expected: 'crlf' },
    { title: 'HTTP smuggling via TE.CL', expected: 'smuggle' },
    { title: 'Auth bypass via JWT none alg', expected: 'auth-bypass' },
    { title: 'IDOR in /api/users/123', expected: 'idor' },
    { title: 'Weak password admin:admin', expected: 'weak-credentials' },
    { title: 'Sensitive data in /backup.zip', expected: 'sensitive-data' },
    { title: 'Information disclosure via stack trace', expected: 'info-leak' },
    { title: 'CORS misconfiguration allows *', expected: 'misconfig' },
  ]
  for (const c of cases) {
    const f = parseFindingFromText(`[HIGH] ${c.title}`, 'vuln-scan')
    assert.ok(f, `should parse: ${c.title}`)
    assert.equal(f.vulnType, c.expected, `${c.title} should map to ${c.expected}`)
  }
})

test('parseFindingFromText confidence bumps for critical severity', () => {
  const low = parseFindingFromText('[LOW] SQL injection somewhere', 'vuln-scan')
  const crit = parseFindingFromText('[CRITICAL] SQL injection somewhere', 'vuln-scan')
  assert.ok(crit.confidence >= 90, `critical confidence ${crit.confidence} should be >= 90`)
  assert.ok(crit.confidence > low.confidence)
})

test('parseFindingFromText returns null for non-finding text', () => {
  assert.equal(parseFindingFromText('just some normal output', 'vuln-scan'), null)
})

// ── knownVulnTypes ─────────────────────────────────────────────────────────

test('knownVulnTypes covers the standard taxonomy', () => {
  const types = knownVulnTypes()
  for (const expected of ['sqli', 'rce', 'lfi', 'ssrf', 'ssti', 'xxe', 'xss', 'cmdi', 'deserialization', 'auth-bypass', 'idor', 'weak-credentials']) {
    assert.ok(types.includes(expected), `${expected} should be in known types`)
  }
  assert.ok(!types.includes('unknown'), 'unknown should NOT be returned')
})