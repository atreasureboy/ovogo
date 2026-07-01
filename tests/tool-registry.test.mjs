/**
 * Tool registry contract test — every tool returned from createTools must
 * have an executable `.execute` method (regression guard against the
 * withDefaultRuntime spread bug that stripped class-instance methods).
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { createTools, findTool } from '../dist/src/tools/index.js'

const TOOL_NAMES = [
  'Bash', 'Read', 'Write', 'Edit', 'Glob', 'Grep', 'TodoWrite',
  'WebFetch', 'WebSearch', 'Agent', 'MultiAgent', 'DispatchAgent',
  'CheckDispatch', 'GetDispatchResult', 'ShellSession', 'TmuxSession',
  'FindingWrite', 'FindingList', 'WeaponRadar', 'MultiScan',
  'C2', 'DocRead', 'EnvAnalyzer', 'TechniqueGenerator', 'PayloadGenerator',
]

test('createTools returns every tool with a working .execute', () => {
  const tools = createTools()
  const missing = []
  for (const name of TOOL_NAMES) {
    const t = findTool(tools, name)
    if (!t) { missing.push(`${name}: not registered`); continue }
    if (typeof t.execute !== 'function') {
      missing.push(`${name}: execute is ${typeof t.execute}`)
    }
    if (!t.definition || t.definition.type !== 'function') {
      missing.push(`${name}: bad definition`)
    }
    if (!t.runtime) {
      missing.push(`${name}: no runtime metadata`)
    }
  }
  assert.deepEqual(missing, [], `tool registry defects: ${missing.join('; ')}`)
})

test('withDefaultRuntime preserves identity and adds runtime', () => {
  const tools = createTools()
  const bash = findTool(tools, 'Bash')
  // same instance still has .execute after map → no spread clone
  assert.equal(typeof bash.execute, 'function')
  assert.equal(bash.runtime.readOnly, false, 'Bash is not read-only')
  assert.equal(bash.runtime.longRunning, true, 'Bash is long-running')
  assert.equal(bash.runtime.concurrencySafe, true, 'Bash is concurrency-safe')
})

test('createTools with knowledgeBase adds KnowledgeQuery', () => {
  // Fake minimal KB to satisfy constructor
  const fakeKB = { query: async () => [], size: () => 0 }
  const tools = createTools([], fakeKB)
  const kq = findTool(tools, 'KnowledgeQuery')
  assert.ok(kq, 'KnowledgeQuery should be registered when KB provided')
  assert.equal(typeof kq.execute, 'function')
})