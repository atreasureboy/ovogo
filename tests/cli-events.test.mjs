import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, appendFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { spawnSync } from 'node:child_process'

test('CLI --events summarizes a session event log without OPENAI_API_KEY', (t) => {
  const sessionDir = mkdtempSync(join(tmpdir(), 'ovogo-events-cli-'))
  appendFileSync(join(sessionDir, 'events.ndjson'), JSON.stringify({
    id: 'evt_1',
    timestamp: new Date().toISOString(),
    type: 'tool_call',
    source: 'Read',
    detail: {},
  }) + '\n', 'utf8')

  const env = { ...process.env }
  delete env.OPENAI_API_KEY
  const result = spawnSync(process.execPath, ['dist/bin/ovogogogo.js', '--events', sessionDir], {
    cwd: process.cwd(),
    env,
    encoding: 'utf8',
  })

  if (result.error) {
    t.skip(`child process unavailable in this environment: ${result.error.message}`)
    return
  }

  assert.equal(result.status, 0)
  assert.match(result.stdout, /Ovogo Events/)
  assert.match(result.stdout, /total: 1/)
  assert.match(result.stdout, /invalidLines: 0/)
  assert.match(result.stdout, /firstTimestamp:/)
  assert.match(result.stdout, /tool_call: 1/)
  assert.match(result.stdout, /Read: 1/)
})

test('CLI --events --json emits machine-readable summary', (t) => {
  const sessionDir = mkdtempSync(join(tmpdir(), 'ovogo-events-json-cli-'))
  appendFileSync(join(sessionDir, 'events.ndjson'), JSON.stringify({
    id: 'evt_1',
    timestamp: new Date().toISOString(),
    type: 'permission_denied',
    source: 'permissions',
    detail: { toolName: 'Bash' },
  }) + '\n', 'utf8')

  const env = { ...process.env }
  delete env.OPENAI_API_KEY
  const result = spawnSync(process.execPath, ['dist/bin/ovogogogo.js', '--events', sessionDir, '--json'], {
    cwd: process.cwd(),
    env,
    encoding: 'utf8',
  })

  if (result.error) {
    t.skip(`child process unavailable in this environment: ${result.error.message}`)
    return
  }

  assert.equal(result.status, 0)
  const summary = JSON.parse(result.stdout)
  assert.equal(summary.sessionDir, sessionDir)
  assert.match(summary.eventsFile, /events\.ndjson$/)
  assert.equal(summary.total, 1)
  assert.equal(summary.invalidLines, 0)
  assert.match(summary.firstTimestamp, /^\d{4}-\d{2}-\d{2}T/)
  assert.match(summary.lastTimestamp, /^\d{4}-\d{2}-\d{2}T/)
  assert.equal(summary.byType.permission_denied, 1)
  assert.equal(summary.bySource.permissions, 1)
})

test('CLI --events --strict returns non-zero for corrupt event logs', (t) => {
  const sessionDir = mkdtempSync(join(tmpdir(), 'ovogo-events-strict-cli-'))
  appendFileSync(join(sessionDir, 'events.ndjson'), JSON.stringify({
    id: 'evt_1',
    timestamp: new Date().toISOString(),
    type: 'tool_call',
    source: 'Read',
    detail: {},
  }) + '\nnot-json\n', 'utf8')

  const env = { ...process.env }
  delete env.OPENAI_API_KEY
  const result = spawnSync(process.execPath, ['dist/bin/ovogogogo.js', '--events', sessionDir, '--strict', '--json'], {
    cwd: process.cwd(),
    env,
    encoding: 'utf8',
  })

  if (result.error) {
    t.skip(`child process unavailable in this environment: ${result.error.message}`)
    return
  }

  assert.equal(result.status, 2)
  const summary = JSON.parse(result.stdout)
  assert.equal(summary.total, 1)
  assert.equal(summary.invalidLines, 1)
})

test('CLI --events can include filtered recent events with legacy redaction', (t) => {
  const sessionDir = mkdtempSync(join(tmpdir(), 'ovogo-events-filter-cli-'))
  appendFileSync(join(sessionDir, 'events.ndjson'), [
    JSON.stringify({
      id: 'evt_1',
      timestamp: new Date().toISOString(),
      type: 'tool_call',
      source: 'Read',
      detail: { file_path: 'README.md' },
    }),
    JSON.stringify({
      id: 'evt_2',
      timestamp: new Date().toISOString(),
      type: 'permission_denied',
      source: 'permissions',
      detail: { reason: 'Authorization: Bearer filtersecret12345' },
    }),
  ].join('\n') + '\n', 'utf8')

  const env = { ...process.env }
  delete env.OPENAI_API_KEY
  const result = spawnSync(process.execPath, [
    'dist/bin/ovogogogo.js',
    '--events', sessionDir,
    '--event-type', 'permission_denied',
    '--event-limit', '1',
    '--json',
  ], {
    cwd: process.cwd(),
    env,
    encoding: 'utf8',
  })

  if (result.error) {
    t.skip(`child process unavailable in this environment: ${result.error.message}`)
    return
  }

  assert.equal(result.status, 0)
  const summary = JSON.parse(result.stdout)
  assert.equal(summary.total, 2)
  assert.equal(summary.filters.eventType, 'permission_denied')
  assert.equal(summary.filters.eventLimit, 1)
  assert.equal(summary.recentEvents.length, 1)
  assert.equal(summary.recentEvents[0].type, 'permission_denied')
  assert.doesNotMatch(JSON.stringify(summary), /filtersecret12345/)
  assert.match(JSON.stringify(summary), /Bearer \[REDACTED\]/)
})

test('CLI --events filters recent events by source, tag, and timestamp', (t) => {
  const sessionDir = mkdtempSync(join(tmpdir(), 'ovogo-events-source-tag-cli-'))
  appendFileSync(join(sessionDir, 'events.ndjson'), [
    JSON.stringify({
      id: 'evt_1',
      timestamp: '2026-06-30T00:00:00.000Z',
      type: 'tool_call',
      source: 'Read',
      detail: {},
      tags: ['fs'],
    }),
    JSON.stringify({
      id: 'evt_2',
      timestamp: '2026-06-30T01:00:00.000Z',
      type: 'permission_denied',
      source: 'permissions',
      detail: { toolName: 'Bash' },
      tags: ['permission', 'Bash'],
    }),
    JSON.stringify({
      id: 'evt_3',
      timestamp: '2026-06-30T02:00:00.000Z',
      type: 'permission_denied',
      source: 'permissions',
      detail: { toolName: 'Write' },
      tags: ['permission', 'Write'],
    }),
  ].join('\n') + '\n', 'utf8')

  const env = { ...process.env }
  delete env.OPENAI_API_KEY
  const result = spawnSync(process.execPath, [
    'dist/bin/ovogogogo.js',
    '--events', sessionDir,
    '--event-source', 'permissions',
    '--event-tag', 'Bash',
    '--event-since', '2026-06-30T00:30:00.000Z',
    '--json',
  ], {
    cwd: process.cwd(),
    env,
    encoding: 'utf8',
  })

  if (result.error) {
    t.skip(`child process unavailable in this environment: ${result.error.message}`)
    return
  }

  assert.equal(result.status, 0)
  const summary = JSON.parse(result.stdout)
  assert.equal(summary.filters.eventSource, 'permissions')
  assert.deepEqual(summary.filters.eventTags, ['Bash'])
  assert.equal(summary.filters.eventSince, '2026-06-30T00:30:00.000Z')
  assert.equal(summary.recentEvents.length, 1)
  assert.equal(summary.recentEvents[0].id, 'evt_2')
})
