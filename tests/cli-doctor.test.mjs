import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { spawnSync } from 'node:child_process'

test('CLI --doctor runs without OPENAI_API_KEY', (t) => {
  const cwd = mkdtempSync(join(tmpdir(), 'ovogo-doctor-'))
  const env = { ...process.env }
  delete env.OPENAI_API_KEY

  const result = spawnSync(process.execPath, ['dist/bin/ovogogogo.js', '--doctor', '--cwd', cwd], {
    cwd: process.cwd(),
    env,
    encoding: 'utf8',
  })

  if (result.error) {
    t.skip(`child process unavailable in this environment: ${result.error.message}`)
    return
  }

  assert.equal(result.status, 0)
  assert.match(result.stdout, /Ovogo Doctor/)
  assert.match(result.stdout, /OPENAI_API_KEY: missing/)
  assert.match(result.stdout, /profile.name: redteam/)
  assert.match(result.stdout, /workspace.root:/)
})

test('CLI --doctor resolves runtime roots and warns about missing roots', (t) => {
  const cwd = mkdtempSync(join(tmpdir(), 'ovogo-doctor-roots-'))
  mkdirSync(join(cwd, '.ovogo'), { recursive: true })
  mkdirSync(join(cwd, 'readable'), { recursive: true })
  writeFileSync(join(cwd, '.ovogo', 'settings.json'), JSON.stringify({
    runtime: {
      readableRoots: ['readable'],
      writableRoots: ['missing-writable'],
    },
  }), 'utf8')

  const env = { ...process.env }
  delete env.OPENAI_API_KEY
  const result = spawnSync(process.execPath, ['dist/bin/ovogogogo.js', '--doctor', '--cwd', cwd], {
    cwd: process.cwd(),
    env,
    encoding: 'utf8',
  })

  if (result.error) {
    t.skip(`child process unavailable in this environment: ${result.error.message}`)
    return
  }

  assert.equal(result.status, 0)
  assert.match(result.stdout, new RegExp(`workspace\\.readableRoots: ${join(cwd, 'readable')}`))
  assert.match(result.stdout, /warning: runtime\.writableRoots\[0\] does not exist:/)
})

test('CLI --doctor --json emits machine-readable diagnostics', (t) => {
  const cwd = mkdtempSync(join(tmpdir(), 'ovogo-doctor-json-'))
  mkdirSync(join(cwd, '.ovogo'), { recursive: true })
  mkdirSync(join(cwd, 'readable'), { recursive: true })
  writeFileSync(join(cwd, '.ovogo', 'settings.json'), JSON.stringify({
    profile: { name: 'generic' },
    runtime: {
      maxConcurrentToolCalls: 5,
      permissionMode: 'deny',
      readableRoots: ['readable'],
      writableRoots: ['missing'],
    },
  }), 'utf8')

  const env = { ...process.env }
  delete env.OPENAI_API_KEY
  const result = spawnSync(process.execPath, ['dist/bin/ovogogogo.js', '--doctor', '--json', '--cwd', cwd], {
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
  assert.equal(summary.cwd, cwd)
  assert.equal(summary.openaiApiKey, 'missing')
  assert.equal(summary.settingsStatus, 'ok')
  assert.equal(summary.profile.name, 'generic')
  assert.equal(summary.runtime.maxConcurrentToolCalls, 5)
  assert.equal(summary.runtime.permissionMode, 'deny')
  assert.deepEqual(summary.workspace.readableRoots, [join(cwd, 'readable')])
  assert.equal(summary.rootDiagnostics.length, 1)
  assert.match(summary.rootDiagnostics[0], /runtime\.writableRoots\[0\] does not exist:/)
})

test('CLI --doctor clamps runtime maxConcurrentToolCalls env override', (t) => {
  const cwd = mkdtempSync(join(tmpdir(), 'ovogo-doctor-concurrency-'))
  mkdirSync(join(cwd, '.ovogo'), { recursive: true })
  writeFileSync(join(cwd, '.ovogo', 'settings.json'), JSON.stringify({
    runtime: { maxConcurrentToolCalls: 500 },
  }), 'utf8')

  const env = {
    ...process.env,
    OVOGO_MAX_CONCURRENT_TOOL_CALLS: '999',
  }
  delete env.OPENAI_API_KEY
  const result = spawnSync(process.execPath, ['dist/bin/ovogogogo.js', '--doctor', '--json', '--cwd', cwd], {
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
  assert.equal(summary.runtime.maxConcurrentToolCalls, 64)
})

test('CLI --doctor --strict returns non-zero for root diagnostics', (t) => {
  const cwd = mkdtempSync(join(tmpdir(), 'ovogo-doctor-strict-'))
  mkdirSync(join(cwd, '.ovogo'), { recursive: true })
  writeFileSync(join(cwd, '.ovogo', 'settings.json'), JSON.stringify({
    runtime: { writableRoots: ['missing'] },
  }), 'utf8')

  const env = { ...process.env }
  delete env.OPENAI_API_KEY
  const result = spawnSync(process.execPath, ['dist/bin/ovogogogo.js', '--doctor', '--strict', '--json', '--cwd', cwd], {
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
  assert.equal(summary.settingsStatus, 'ok')
  assert.equal(summary.rootDiagnostics.length, 1)
})
