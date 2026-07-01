import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

import { appendAgentEvent } from '../dist/src/tools/agent.js'

test('appendAgentEvent redacts secrets in sub-agent audit log', () => {
  const sessionDir = mkdtempSync(join(tmpdir(), 'ovogo-agent-events-'))
  appendAgentEvent(
    { sessionDir },
    {
      event: 'delegation.start',
      prompt_preview: 'Use Authorization: Bearer abcdefghijklmnop and token=plainsecret',
      apiKey: 'sk-testsecret1234567890',
    },
  )

  const raw = readFileSync(join(sessionDir, 'agent_events.ndjson'), 'utf8')
  const event = JSON.parse(raw.trim())

  assert.equal(event.apiKey, '[REDACTED]')
  assert.doesNotMatch(raw, /abcdefghijklmnop/)
  assert.doesNotMatch(raw, /plainsecret/)
  assert.doesNotMatch(raw, /sk-testsecret/)
  assert.match(raw, /Bearer \[REDACTED\]/)
  assert.match(raw, /token=\[REDACTED\]/)
})

test('appendAgentEvent is a no-op without sessionDir', () => {
  assert.doesNotThrow(() => appendAgentEvent({}, { event: 'noop' }))
})
