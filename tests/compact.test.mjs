import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

import { maybeCompact } from '../dist/src/core/compact.js'

test('maybeCompact uses ModelClient.completeText and preserves recent messages', async () => {
  const calls = []
  const modelClient = {
    streamChat: async () => { throw new Error('not used') },
    completeText: async (request) => {
      calls.push(request)
      return '<analysis>scratch</analysis><summary>Useful compacted context.</summary>'
    },
  }
  const messages = [
    ...Array.from({ length: 9 }, (_, idx) => ({
      role: idx % 2 === 0 ? 'user' : 'assistant',
      content: `old-${idx} ${'x'.repeat(200)}`,
    })),
    { role: 'user', content: 'recent question' },
  ]

  const result = await maybeCompact(modelClient, 'unit-model', messages, 10)

  assert.equal(result.compacted, true)
  assert.equal(calls.length, 1)
  assert.equal(calls[0].model, 'unit-model')
  assert.equal(calls[0].maxTokens > 0, true)
  assert.match(String(result.messages[0].content), /Useful compacted context/)
  assert.equal(result.messages.at(-1).content, 'recent question')
})

test('maybeCompact leaves messages unchanged below threshold', async () => {
  let called = false
  const modelClient = {
    streamChat: async () => { throw new Error('not used') },
    completeText: async () => { called = true; return 'summary' },
  }
  const messages = [{ role: 'user', content: 'short' }]

  const result = await maybeCompact(modelClient, 'unit-model', messages, 10_000)

  assert.equal(result.compacted, false)
  assert.equal(result.messages, messages)
  assert.equal(called, false)
})

test('maybeCompact redacts legacy anchors before injecting compacted context', async () => {
  const sessionDir = mkdtempSync(join(tmpdir(), 'ovogo-compact-anchors-'))
  writeFileSync(join(sessionDir, '.anchors.json'), JSON.stringify({
    creds: [{
      target: 'https://example.test/?token=anchortargetsecret',
      username: 'admin',
      credential: 'password: anchorcredentialsecret',
      type: 'weak-cred',
    }],
    flags: [{
      content: 'client_secret: flagsecret',
      target: 'example.test',
      path: '/flag',
    }],
  }), 'utf8')
  const modelClient = {
    streamChat: async () => { throw new Error('not used') },
    completeText: async () => '<summary>Compacted.</summary>',
  }
  const messages = [
    ...Array.from({ length: 9 }, (_, idx) => ({ role: 'user', content: `old-${idx} ${'x'.repeat(200)}` })),
    { role: 'assistant', content: 'recent' },
  ]

  const result = await maybeCompact(modelClient, 'unit-model', messages, 10, sessionDir)
  const summary = String(result.messages[0].content)

  assert.equal(result.compacted, true)
  assert.doesNotMatch(summary, /anchortargetsecret|anchorcredentialsecret|flagsecret/)
  assert.match(summary, /token=\[REDACTED\]/)
  assert.match(summary, /admin:\[REDACTED\]/)
  assert.match(summary, /client_secret: \[REDACTED\]/)
})
