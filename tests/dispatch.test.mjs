import test from 'node:test'
import assert from 'node:assert/strict'

import { DispatchManager } from '../dist/src/core/dispatch.js'

test('DispatchManager redacts prompts, results, errors, and callback records', () => {
  const manager = new DispatchManager()
  const callbacks = []
  manager.onCompletion((record) => callbacks.push(record))

  const record = manager.create('worker', 'use password: dispatchsecret and token=querysecret')
  assert.doesNotMatch(record.prompt, /dispatchsecret/)
  assert.doesNotMatch(record.prompt, /querysecret/)
  assert.match(record.prompt, /password: \[REDACTED\]/)
  assert.match(record.prompt, /token=\[REDACTED\]/)

  manager.update(record.id, {
    status: 'completed',
    result: 'finished with Authorization: Bearer abcdefghijklmnop',
    error: 'ignored client_secret: callbacksecret',
  })

  const completed = manager.get(record.id)
  assert.equal(completed.status, 'completed')
  assert.doesNotMatch(completed.result, /abcdefghijklmnop/)
  assert.doesNotMatch(completed.error, /callbacksecret/)
  assert.match(completed.result, /Bearer \[REDACTED\]/)
  assert.match(completed.error, /client_secret: \[REDACTED\]/)

  assert.equal(callbacks.length, 1)
  assert.doesNotMatch(callbacks[0].result, /abcdefghijklmnop/)
  assert.doesNotMatch(callbacks[0].error, /callbacksecret/)
})
