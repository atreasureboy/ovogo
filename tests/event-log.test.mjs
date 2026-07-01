import test from 'node:test'
import assert from 'node:assert/strict'
import { appendFileSync, mkdtempSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

import { EventLog } from '../dist/src/core/eventLog.js'

test('EventLog.readAll preserves valid entries when one NDJSON line is corrupt', () => {
  const sessionDir = mkdtempSync(join(tmpdir(), 'ovogo-events-'))
  const log = new EventLog(sessionDir)
  log.append('run_start', 'test', { n: 1 })
  appendFileSync(log.getFilePath(), '{not-json}\n', 'utf8')
  log.append('run_complete', 'test', { n: 2 })

  const events = log.readAll()

  assert.equal(events.length, 2)
  assert.deepEqual(events.map((event) => event.type), ['run_start', 'run_complete'])
  assert.equal(log.readWithDiagnostics().invalidLines, 1)
})


test('EventLog.stats summarizes events by type and source', () => {
  const sessionDir = mkdtempSync(join(tmpdir(), 'ovogo-events-stats-'))
  const log = new EventLog(sessionDir)
  log.append('tool_call', 'Read', {})
  log.append('tool_result', 'Read', {})
  log.append('tool_call', 'Write', {})

  const stats = log.stats()

  assert.equal(stats.total, 3)
  assert.equal(stats.invalidLines, 0)
  assert.match(stats.firstTimestamp ?? '', /^\d{4}-\d{2}-\d{2}T/)
  assert.match(stats.lastTimestamp ?? '', /^\d{4}-\d{2}-\d{2}T/)
  assert.equal(stats.byType.tool_call, 2)
  assert.equal(stats.byType.tool_result, 1)
  assert.equal(stats.bySource.Read, 2)
  assert.equal(stats.bySource.Write, 1)
})

test('EventLog.stats reports corrupt NDJSON lines', () => {
  const sessionDir = mkdtempSync(join(tmpdir(), 'ovogo-events-corrupt-stats-'))
  const log = new EventLog(sessionDir)
  log.append('tool_call', 'Read', {})
  appendFileSync(log.getFilePath(), 'not-json\n', 'utf8')

  const stats = log.stats()

  assert.equal(stats.total, 1)
  assert.equal(stats.invalidLines, 1)
})

test('EventLog.query filters by source, tags, and timestamp', () => {
  const sessionDir = mkdtempSync(join(tmpdir(), 'ovogo-events-query-'))
  const log = new EventLog(sessionDir)
  appendFileSync(log.getFilePath(), [
    JSON.stringify({
      id: 'evt_old',
      timestamp: '2026-06-30T00:00:00.000Z',
      type: 'tool_call',
      source: 'Read',
      detail: {},
      tags: ['fs'],
    }),
    JSON.stringify({
      id: 'evt_new',
      timestamp: '2026-06-30T01:00:00.000Z',
      type: 'permission_denied',
      source: 'permissions',
      detail: {},
      tags: ['security', 'Bash'],
    }),
  ].join('\n') + '\n', 'utf8')

  const events = log.query({
    source: 'permissions',
    tags: ['Bash'],
    since: '2026-06-30T00:30:00.000Z',
    limit: 10,
  })

  assert.equal(events.length, 1)
  assert.equal(events[0].id, 'evt_new')
})

test('EventLog.append redacts common secrets before writing', () => {
  const sessionDir = mkdtempSync(join(tmpdir(), 'ovogo-events-redact-'))
  const log = new EventLog(sessionDir)
  const returned = log.append('tool_call', 'Bash', {
    apiKey: 'sk-testsecret1234567890',
    input: {
      password: 'p@ssw0rd',
      command: 'curl -H "Authorization: Bearer abcdefghijklmnop" "https://example.test/?token=plainsecret&access_token=accesssecret&refresh_token=refreshsecret&client_secret=clientsecret"',
      pem: '-----BEGIN PRIVATE KEY-----\nabc123secret\n-----END PRIVATE KEY-----',
      jwt: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnopqrstuvwxyz',
      nested: [{ cookie: 'sessionid=secret' }],
    },
  })

  const [event] = log.readAll()
  const serialized = JSON.stringify(event)

  assert.equal(returned.detail.apiKey, '[REDACTED]')
  assert.equal(event.detail.apiKey, '[REDACTED]')
  assert.equal(event.detail.input.password, '[REDACTED]')
  assert.equal(event.detail.input.nested[0].cookie, '[REDACTED]')
  assert.doesNotMatch(serialized, /sk-testsecret/)
  assert.doesNotMatch(serialized, /p@ssw0rd/)
  assert.doesNotMatch(serialized, /abcdefghijklmnop/)
  assert.doesNotMatch(serialized, /plainsecret/)
  assert.doesNotMatch(serialized, /accesssecret/)
  assert.doesNotMatch(serialized, /refreshsecret/)
  assert.doesNotMatch(serialized, /clientsecret/)
  assert.doesNotMatch(serialized, /abc123secret/)
  assert.doesNotMatch(serialized, /abcdefghijklmnopqrstuvwxyz/)
  assert.match(serialized, /Bearer \[REDACTED\]/)
  assert.match(serialized, /token=\[REDACTED\]/)
  assert.match(serialized, /access_token=\[REDACTED\]/)
  assert.match(serialized, /refresh_token=\[REDACTED\]/)
  assert.match(serialized, /client_secret=\[REDACTED\]/)
})

test('EventLog.append tolerates circular detail objects', () => {
  const sessionDir = mkdtempSync(join(tmpdir(), 'ovogo-events-circular-'))
  const log = new EventLog(sessionDir)
  const detail = { name: 'root' }
  detail.self = detail

  const event = log.append('tool_result', 'test', detail)

  assert.equal(event.detail.self, '[Circular]')
  assert.equal(log.readAll()[0].detail.self, '[Circular]')
})

test('EventLog.readAll redacts legacy plaintext entries on replay', () => {
  const sessionDir = mkdtempSync(join(tmpdir(), 'ovogo-events-legacy-redact-'))
  const log = new EventLog(sessionDir)
  appendFileSync(log.getFilePath(), JSON.stringify({
    id: 'evt_legacy',
    timestamp: new Date().toISOString(),
    type: 'tool_result',
    source: 'Bash',
    detail: { output: 'Authorization: Basic legacybasicsecret' },
  }) + '\n', 'utf8')

  const [event] = log.readAll()
  const serialized = JSON.stringify(event)

  assert.doesNotMatch(serialized, /legacybasicsecret/)
  assert.match(serialized, /Basic \[REDACTED\]/)
})
