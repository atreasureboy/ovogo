import test from 'node:test'
import assert from 'node:assert/strict'

import {
  parsePermissionRule,
  matchGlob,
  ruleMatches,
  evaluateRules,
  loadPermissionRules,
} from '../dist/src/config/permissionRules.js'
import { PermissionManager } from '../dist/src/core/permissionManager.js'

test('parsePermissionRule handles bare tool names', () => {
  const rule = parsePermissionRule('Bash')
  assert.deepEqual(rule, { toolName: 'Bash', inputPattern: '' })
})

test('parsePermissionRule handles tool(pattern) syntax', () => {
  const rule = parsePermissionRule('Bash(nmap*)')
  assert.deepEqual(rule, { toolName: 'Bash', inputPattern: 'nmap*' })
})

test('parsePermissionRule returns null on malformed input', () => {
  assert.equal(parsePermissionRule('1Invalid(abc)'), null)
  assert.equal(parsePermissionRule('Bash()'), null)
  assert.equal(parsePermissionRule(''), null)
})

test('matchGlob handles single star', () => {
  assert.equal(matchGlob('*', 'anything'), true)
  assert.equal(matchGlob('nmap*', 'nmap -sV target'), true)
  assert.equal(matchGlob('nmap*', 'sqlmap --url=x'), false)
})

test('matchGlob handles double star for path matching', () => {
  assert.equal(matchGlob('/shared/**', '/shared/docs/a.md'), true)
  assert.equal(matchGlob('/shared/**', '/shared/docs/sub/b.md'), true)
  assert.equal(matchGlob('/shared/**', '/etc/passwd'), false)
})

test('matchGlob handles question mark', () => {
  assert.equal(matchGlob('file?.txt', 'file1.txt'), true)
  assert.equal(matchGlob('file?.txt', 'file12.txt'), false)
})

test('matchGlob handles substring patterns with surrounding stars', () => {
  assert.equal(matchGlob('**passwd**', 'cat /etc/passwd'), true)
  assert.equal(matchGlob('**passwd**', 'cat /etc/shadow'), false)
})

test('ruleMatches matches Bash command prefix', () => {
  const rule = parsePermissionRule('Bash(nmap*)')
  assert.equal(ruleMatches(rule, { toolName: 'Bash', input: { command: 'nmap -sV 10.0.0.1' }, cwd: '/w' }), true)
  assert.equal(ruleMatches(rule, { toolName: 'Bash', input: { command: 'sqlmap --url=x' }, cwd: '/w' }), false)
  assert.equal(ruleMatches(rule, { toolName: 'Read', input: { file_path: '/w/x' }, cwd: '/w' }), false)
})

test('ruleMatches matches Read file_path glob', () => {
  const rule = parsePermissionRule('Read(/shared/docs/**)')
  assert.equal(ruleMatches(rule, { toolName: 'Read', input: { file_path: '/shared/docs/a.md' }, cwd: '/w' }), true)
  assert.equal(ruleMatches(rule, { toolName: 'Read', input: { file_path: '/etc/passwd' }, cwd: '/w' }), false)
})

test('evaluateRules denies when deny rule matches', () => {
  const result = evaluateRules(
    { deny: ['Bash(**rm -rf**)'] },
    { toolName: 'Bash', input: { command: 'rm -rf /tmp/x' }, cwd: '/w' },
  )
  assert.equal(result, 'deny')
})

test('evaluateRules allows when allow rule matches', () => {
  const result = evaluateRules(
    { allow: ['Bash(nmap*)'] },
    { toolName: 'Bash', input: { command: 'nmap -sV x' }, cwd: '/w' },
  )
  assert.equal(result, 'allow')
})

test('evaluateRules returns null when no rule matches', () => {
  const result = evaluateRules(
    { allow: ['Bash(nmap*)'], deny: ['Bash(**rm -rf**)'] },
    { toolName: 'Bash', input: { command: 'ls -la' }, cwd: '/w' },
  )
  assert.equal(result, null)
})

test('evaluateRules deny wins over allow', () => {
  const result = evaluateRules(
    { allow: ['Bash(curl*)'], deny: ['Bash(curl**/etc/**)'] },
    { toolName: 'Bash', input: { command: 'curl http://x/etc/passwd' }, cwd: '/w' },
  )
  assert.equal(result, 'deny')
})

test('PermissionManager honors allow rules even in deny mode', () => {
  const mgr = new PermissionManager(undefined, { allow: ['Read'] })
  const decision = mgr.checkTool({
    toolName: 'Read',
    input: { file_path: '/etc/passwd' },
    mode: 'deny',
    cwd: '/w',
  })
  assert.equal(decision.allowed, true)
})

test('PermissionManager honors deny rules even in auto mode', () => {
  const mgr = new PermissionManager(undefined, { deny: ['Bash(**rm -rf**)'] })
  const decision = mgr.checkTool({
    toolName: 'Bash',
    input: { command: 'rm -rf /tmp/important' },
    mode: 'auto',
    cwd: '/workspace',
  })
  assert.equal(decision.allowed, false)
  assert.match(decision.reason ?? '', /permissions\.json/)
})

test('PermissionManager setRules updates rules at runtime', () => {
  const mgr = new PermissionManager()
  assert.equal(
    mgr.checkTool({ toolName: 'Bash', input: { command: 'ls /workspace' }, mode: 'auto', cwd: '/workspace' }).allowed,
    true,
  )
  mgr.setRules({ deny: ['Bash(**passwd**)'] })
  const decision = mgr.checkTool({
    toolName: 'Bash',
    input: { command: 'cat /etc/passwd' },
    mode: 'auto',
    cwd: '/workspace',
  })
  assert.equal(decision.allowed, false)
  assert.match(decision.reason ?? '', /permissions\.json/)
})

test('loadPermissionRules returns empty when no files exist', () => {
  const { rules, diagnostics } = loadPermissionRules('/nonexistent/path/that/does/not/exist')
  assert.deepEqual(rules, {})
  assert.deepEqual(diagnostics, [])
})