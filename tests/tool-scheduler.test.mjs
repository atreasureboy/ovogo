import test from 'node:test'
import assert from 'node:assert/strict'

import { partitionToolCalls } from '../dist/src/core/toolScheduler.js'

const call = (name) => ({ tc: { name } })

test('partitionToolCalls groups adjacent concurrency-safe calls', () => {
  const batches = partitionToolCalls(
    [call('Read'), call('Grep'), call('Write'), call('Glob'), call('WebFetch')],
    (name) => ['Read', 'Grep', 'Glob', 'WebFetch'].includes(name),
  )

  assert.deepEqual(batches.map((batch) => ({ safe: batch.safe, names: batch.calls.map((c) => c.tc.name) })), [
    { safe: true, names: ['Read', 'Grep'] },
    { safe: false, names: ['Write'] },
    { safe: true, names: ['Glob', 'WebFetch'] },
  ])
})

test('partitionToolCalls preserves serial ordering for unsafe calls', () => {
  const batches = partitionToolCalls(
    [call('Write'), call('Edit'), call('FindingWrite')],
    () => false,
  )

  assert.deepEqual(batches.map((batch) => batch.calls.map((c) => c.tc.name)), [
    ['Write'],
    ['Edit'],
    ['FindingWrite'],
  ])
})

test('partitionToolCalls caps adjacent concurrency-safe batches', () => {
  const batches = partitionToolCalls(
    [call('Read'), call('Grep'), call('Glob'), call('WebFetch'), call('Read')],
    () => true,
    { maxParallelBatchSize: 2 },
  )

  assert.deepEqual(batches.map((batch) => ({ safe: batch.safe, names: batch.calls.map((c) => c.tc.name) })), [
    { safe: true, names: ['Read', 'Grep'] },
    { safe: true, names: ['Glob', 'WebFetch'] },
    { safe: true, names: ['Read'] },
  ])
})
