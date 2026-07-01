import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

import { FindingListTool, FindingWriteTool } from '../dist/src/tools/finding.js'

function context(cwd, sessionDir = cwd) {
  return { cwd, sessionDir, permissionMode: 'auto' }
}

test('FindingWrite rejects path-like ids before writing files', async () => {
  const cwd = mkdtempSync(join(tmpdir(), 'ovogo-finding-id-'))
  const tool = new FindingWriteTool()

  const result = await tool.execute({
    id: '../escape',
    title: 'bad id',
    type: 'info-disclosure',
    target: 'example.test',
    severity: 'info',
    phase: 'other',
    description: 'path traversal attempt',
    status: 'open',
  }, context(cwd))

  assert.equal(result.isError, true)
  assert.match(result.content, /finding id/)
  assert.equal(existsSync(join(cwd, '.ovogo', 'escape.json')), false)
})

test('FindingWrite redacts persisted findings, anchors, and tool response', async () => {
  const cwd = mkdtempSync(join(tmpdir(), 'ovogo-finding-redact-'))
  const sessionDir = mkdtempSync(join(tmpdir(), 'ovogo-finding-session-'))
  const tool = new FindingWriteTool()

  const result = await tool.execute({
    id: 'weak-cred-1',
    title: 'password: titlesecret flag',
    type: 'weak-cred',
    target: 'https://example.test/?token=targetsecret',
    severity: 'critical',
    phase: 'initial-access',
    description: 'Authorization: Bearer abcdefghijklmnop',
    poc: 'client_secret: pocsecret',
    status: 'confirmed',
  }, context(cwd, sessionDir))

  assert.equal(result.isError, false)
  assert.doesNotMatch(result.content, /titlesecret|targetsecret/)

  const findingRaw = readFileSync(join(cwd, '.ovogo', 'findings', 'weak-cred-1.json'), 'utf8')
  const anchorsRaw = readFileSync(join(sessionDir, '.anchors.json'), 'utf8')
  const combined = findingRaw + anchorsRaw + result.content

  assert.doesNotMatch(combined, /titlesecret|targetsecret|abcdefghijklmnop|pocsecret/)
  assert.match(findingRaw, /password: \[REDACTED\]/)
  assert.match(findingRaw, /Bearer \[REDACTED\]/)
  assert.match(findingRaw, /client_secret: \[REDACTED\]/)
  assert.match(anchorsRaw, /password: \[REDACTED\]/)
})

test('FindingList redacts legacy plaintext finding files before returning context', async () => {
  const cwd = mkdtempSync(join(tmpdir(), 'ovogo-finding-list-'))
  const findingsDir = join(cwd, '.ovogo', 'findings')
  mkdirSync(findingsDir, { recursive: true })
  writeFileSync(join(findingsDir, 'legacy.json'), JSON.stringify({
    id: 'legacy',
    title: 'password: legacytitlesecret',
    type: 'weak-cred',
    target: 'https://example.test/?access_token=legacytargetsecret',
    severity: 'critical',
    phase: 'initial-access',
    description: 'Authorization: Bearer legacyauthsecret123',
    status: 'confirmed',
    timestamp: new Date().toISOString(),
  }, null, 2), 'utf8')

  const result = await new FindingListTool().execute({}, context(cwd))

  assert.equal(result.isError, false)
  assert.doesNotMatch(result.content, /legacytitlesecret|legacytargetsecret|legacyauthsecret123/)
  assert.match(result.content, /password: \[REDACTED\]/)
  assert.match(result.content, /access_token=\[REDACTED\]/)
})
