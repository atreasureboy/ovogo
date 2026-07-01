import test from 'node:test'
import assert from 'node:assert/strict'

import {
  createTools,
  isCacheableTool,
  isConcurrencySafeTool,
  isPlanModeTool,
} from '../dist/src/tools/index.js'

test('tool runtime metadata drives plan mode exposure', () => {
  const tools = createTools()

  assert.equal(isPlanModeTool(tools, 'Read'), true)
  assert.equal(isPlanModeTool(tools, 'WebSearch'), true)
  assert.equal(isPlanModeTool(tools, 'Write'), false)
  assert.equal(isPlanModeTool(tools, 'Edit'), false)
})

test('tool runtime metadata does not cache agent execution results', () => {
  const tools = createTools()

  assert.equal(isCacheableTool(tools, 'WebFetch'), true)
  assert.equal(isCacheableTool(tools, 'WeaponRadar'), true)
  assert.equal(isCacheableTool(tools, 'Agent'), false)
  assert.equal(isCacheableTool(tools, 'MultiAgent'), false)
  assert.equal(isCacheableTool(tools, 'MultiScan'), false)
})

test('tool runtime metadata identifies safe parallel batches', () => {
  const tools = createTools()

  assert.equal(isConcurrencySafeTool(tools, 'Read'), true)
  assert.equal(isConcurrencySafeTool(tools, 'Bash'), true)
  assert.equal(isConcurrencySafeTool(tools, 'Write'), false)
  assert.equal(isConcurrencySafeTool(tools, 'FindingWrite'), false)
})


test('extra tool runtime metadata overrides defaults', () => {
  const customTool = {
    name: 'CustomMutableLookup',
    runtime: { readOnly: false, concurrencySafe: false, cacheable: true, cacheTtlMs: 42 },
    definition: {
      type: 'function',
      function: {
        name: 'CustomMutableLookup',
        description: 'custom',
        parameters: { type: 'object', properties: {} },
      },
    },
    execute: async () => ({ content: 'ok', isError: false }),
  }

  const tools = createTools([customTool])

  assert.equal(isPlanModeTool(tools, 'CustomMutableLookup'), false)
  assert.equal(isConcurrencySafeTool(tools, 'CustomMutableLookup'), false)
  assert.equal(isCacheableTool(tools, 'CustomMutableLookup'), true)
  assert.equal(tools.find((tool) => tool.name === 'CustomMutableLookup')?.runtime?.cacheTtlMs, 42)
})
