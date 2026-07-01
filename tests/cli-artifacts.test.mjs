import test from 'node:test'
import assert from 'node:assert/strict'
import { appendFileSync, mkdirSync, mkdtempSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { spawnSync } from 'node:child_process'

test('CLI --artifacts summarizes artifact manifest without OPENAI_API_KEY', (t) => {
  const sessionDir = mkdtempSync(join(tmpdir(), 'ovogo-artifacts-cli-'))
  const artifactDir = join(sessionDir, 'artifacts')
  mkdirSync(artifactDir, { recursive: true })
  appendFileSync(join(artifactDir, 'manifest.ndjson'), [
    JSON.stringify({
      path: join(artifactDir, 'one.txt'),
      bytes: 3,
      sha256: 'hash-one',
      createdAt: '2026-06-30T00:00:00.000Z',
      prefix: 'tool_Read',
    }),
    JSON.stringify({
      path: join(artifactDir, 'two.txt'),
      bytes: 4,
      sha256: 'hash-two',
      createdAt: '2026-06-30T01:00:00.000Z',
      prefix: 'api_key=legacysecret12345',
    }),
  ].join('\n') + '\n', 'utf8')

  const env = { ...process.env }
  delete env.OPENAI_API_KEY
  const result = spawnSync(process.execPath, [
    'dist/bin/ovogogogo.js',
    '--artifacts', sessionDir,
    '--artifact-limit', '1',
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
  assert.equal(summary.sessionDir, sessionDir)
  assert.match(summary.manifestFile, /artifacts\/manifest\.ndjson$/)
  assert.equal(summary.total, 2)
  assert.equal(summary.invalidLines, 0)
  assert.equal(summary.totalBytes, 7)
  assert.equal(summary.recentArtifacts.length, 1)
  assert.equal(summary.recentArtifacts[0].sha256, 'hash-two')
  assert.equal(summary.recentArtifacts[0].prefix, 'api_key=[REDACTED]')
  assert.doesNotMatch(JSON.stringify(summary), /legacysecret12345/)
})

test('CLI --artifacts --strict returns non-zero for corrupt manifest lines', (t) => {
  const sessionDir = mkdtempSync(join(tmpdir(), 'ovogo-artifacts-strict-cli-'))
  const artifactDir = join(sessionDir, 'artifacts')
  mkdirSync(artifactDir, { recursive: true })
  appendFileSync(join(artifactDir, 'manifest.ndjson'), [
    JSON.stringify({
      path: join(artifactDir, 'one.txt'),
      bytes: 3,
      sha256: 'hash-one',
      createdAt: '2026-06-30T00:00:00.000Z',
      prefix: 'tool_Read',
    }),
    'not-json',
  ].join('\n') + '\n', 'utf8')

  const env = { ...process.env }
  delete env.OPENAI_API_KEY
  const result = spawnSync(process.execPath, [
    'dist/bin/ovogogogo.js',
    '--artifacts', sessionDir,
    '--strict',
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

  assert.equal(result.status, 2)
  const summary = JSON.parse(result.stdout)
  assert.equal(summary.total, 1)
  assert.equal(summary.invalidLines, 1)
})
