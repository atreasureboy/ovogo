import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

import { loadSettings, loadSettingsWithDiagnostics } from '../dist/src/config/settings.js'

function makeProject(settingsText) {
  const cwd = mkdtempSync(join(tmpdir(), 'ovogo-settings-'))
  const dir = join(cwd, '.ovogo')
  mkdirSync(dir, { recursive: true })
  writeFileSync(join(dir, 'settings.json'), settingsText, 'utf8')
  return cwd
}

test('loadSettingsWithDiagnostics reports invalid project settings schema', () => {
  const cwd = makeProject(JSON.stringify({ hooks: { PreToolCall: [{ command: '' }] } }))
  const result = loadSettingsWithDiagnostics(cwd)

  assert.equal(result.settings.hooks?.PreToolCall?.length ?? 0, 0)
  assert.ok(result.diagnostics.some((diagnostic) =>
    diagnostic.path.endsWith('.ovogo/settings.json') &&
    diagnostic.level === 'error' &&
    diagnostic.message.includes('Invalid settings schema'),
  ))
})

test('loadSettings preserves compatibility API for valid project settings', () => {
  const cwd = makeProject(JSON.stringify({
    engagement: {
      name: 'Unit Test Engagement',
      phase: 'recon',
      targets: ['example.test'],
    },
  }))
  const settings = loadSettings(cwd)

  assert.equal(settings.engagement?.name, 'Unit Test Engagement')
  assert.equal(settings.engagement?.phase, 'recon')
  assert.deepEqual(settings.engagement?.targets, ['example.test'])
})


test('loadSettings accepts generic runtime settings', () => {
  const cwd = makeProject(JSON.stringify({
    runtime: {
      model: 'unit-model',
      maxIterations: 7,
      maxConcurrentToolCalls: 3,
      permissionMode: 'deny',
      readableRoots: ['/shared/read'],
      writableRoots: ['/shared/write'],
    },
  }))
  const result = loadSettingsWithDiagnostics(cwd)

  assert.equal(result.settings.runtime?.model, 'unit-model')
  assert.equal(result.settings.runtime?.maxIterations, 7)
  assert.equal(result.settings.runtime?.maxConcurrentToolCalls, 3)
  assert.equal(result.settings.runtime?.permissionMode, 'deny')
  assert.deepEqual(result.settings.runtime?.readableRoots, ['/shared/read'])
  assert.deepEqual(result.settings.runtime?.writableRoots, ['/shared/write'])
})


test('loadSettings accepts profile selection', () => {
  const cwd = makeProject(JSON.stringify({ profile: { name: 'generic' } }))
  const result = loadSettingsWithDiagnostics(cwd)

  assert.equal(result.settings.profile?.name, 'generic')
  assert.equal(result.diagnostics.some((diagnostic) => diagnostic.level === 'error'), false)
})
