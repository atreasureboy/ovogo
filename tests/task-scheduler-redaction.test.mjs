import test from 'node:test'
import assert from 'node:assert/strict'

import { AsyncTaskScheduler } from '../dist/src/core/taskScheduler.js'

const flush = () => new Promise((resolve) => setImmediate(resolve))

test('AsyncTaskScheduler redacts stored prompts and completed outputs', async () => {
  const engine = {
    async runTurn() {
      return {
        result: {
          output: 'done with password: outputsecret and Authorization: Bearer abcdefghijklmnop',
          stopped: false,
          reason: 'stop_sequence',
        },
      }
    },
  }
  const scheduler = new AsyncTaskScheduler(engine)

  scheduler.submit([{
    id: 'task-1',
    agentType: 'worker',
    prompt: 'scan example.com with access_token=inputsecret',
    priority: 'high',
    phase: 'test',
    dependsOn: [],
  }])

  const pendingSummary = scheduler.toSummary()
  assert.match(pendingSummary, /example\.com/)
  assert.doesNotMatch(pendingSummary, /inputsecret/)
  assert.match(pendingSummary, /access_token=\[REDACTED\]/)

  await scheduler.tick()
  await flush()
  await scheduler.pollCompleted()

  const completed = scheduler.getCompleted()[0]
  assert.equal(completed.task.targetResource, 'example.com')
  assert.doesNotMatch(completed.output, /outputsecret/)
  assert.doesNotMatch(completed.output, /abcdefghijklmnop/)
  assert.match(completed.output, /password: \[REDACTED\]/)
  assert.match(completed.output, /Bearer \[REDACTED\]/)

  const completedSummary = scheduler.toSummary()
  assert.doesNotMatch(completedSummary, /outputsecret/)
  assert.doesNotMatch(completedSummary, /abcdefghijklmnop/)
})
