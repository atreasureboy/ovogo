import test from 'node:test'
import assert from 'node:assert/strict'
import { appendFileSync, existsSync, mkdtempSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { createHash } from 'node:crypto'

import { ArtifactStore } from '../dist/src/core/artifactStore.js'

test('ArtifactStore writes text artifacts under session artifacts directory', () => {
  const sessionDir = mkdtempSync(join(tmpdir(), 'ovogo-artifacts-'))
  const store = new ArtifactStore(sessionDir)
  const record = store.writeText('tool:Read', 'hello artifact')

  assert.ok(record)
  assert.equal(record.bytes, Buffer.byteLength('hello artifact', 'utf8'))
  assert.equal(record.sha256, createHash('sha256').update('hello artifact').digest('hex'))
  assert.match(record.createdAt, /^\d{4}-\d{2}-\d{2}T/)
  assert.equal(record.prefix, 'tool_Read')
  assert.equal(existsSync(record.path), true)
  assert.match(record.path, /artifacts\/\d+_\d+_tool_Read\.txt$/)
  assert.equal(readFileSync(record.path, 'utf8'), 'hello artifact')

  const manifest = readFileSync(store.getManifestPath(), 'utf8').trim().split('\n').map(JSON.parse)
  assert.equal(manifest.length, 1)
  assert.deepEqual(manifest[0], record)
})

test('ArtifactStore redacts common inline secrets before writing artifacts', () => {
  const sessionDir = mkdtempSync(join(tmpdir(), 'ovogo-artifacts-redact-'))
  const store = new ArtifactStore(sessionDir)
  const content = [
    'Authorization: Bearer abcdefghijklmnop',
    'OPENAI_API_KEY=sk-testsecret1234567890',
    'access_token=accesssecret',
    'jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnopqrstuvwxyz',
    '-----BEGIN PRIVATE KEY-----',
    'abc123secret',
    '-----END PRIVATE KEY-----',
  ].join('\n')
  const record = store.writeText('tool:Bash', content)

  assert.ok(record)
  const stored = readFileSync(record.path, 'utf8')
  assert.equal(record.bytes, Buffer.byteLength(stored, 'utf8'))
  assert.equal(record.sha256, createHash('sha256').update(stored).digest('hex'))
  assert.doesNotMatch(stored, /abcdefghijklmnop/)
  assert.doesNotMatch(stored, /sk-testsecret/)
  assert.doesNotMatch(stored, /accesssecret/)
  assert.doesNotMatch(stored, /abc123secret/)
  assert.doesNotMatch(stored, /abcdefghijklmnopqrstuvwxyz/)
  assert.match(stored, /Bearer \[REDACTED\]/)
  assert.match(stored, /OPENAI_API_KEY=\[REDACTED\]/)
  assert.match(stored, /access_token=\[REDACTED\]/)
})

test('ArtifactStore avoids same-prefix filename collisions in one process', () => {
  const sessionDir = mkdtempSync(join(tmpdir(), 'ovogo-artifacts-unique-'))
  const store = new ArtifactStore(sessionDir)
  const first = store.writeText('tool:Read', 'first')
  const second = store.writeText('tool:Read', 'second')

  assert.ok(first)
  assert.ok(second)
  assert.notEqual(first.path, second.path)
  assert.equal(readFileSync(first.path, 'utf8'), 'first')
  assert.equal(readFileSync(second.path, 'utf8'), 'second')

  const manifest = readFileSync(store.getManifestPath(), 'utf8').trim().split('\n').map(JSON.parse)
  assert.equal(manifest.length, 2)
  assert.equal(manifest[0].path, first.path)
  assert.equal(manifest[1].path, second.path)
  assert.equal(manifest[0].sha256, first.sha256)
  assert.equal(manifest[1].sha256, second.sha256)
})

test('ArtifactStore redacts secret-like prefixes before filenames and manifest records', () => {
  const sessionDir = mkdtempSync(join(tmpdir(), 'ovogo-artifacts-prefix-'))
  const store = new ArtifactStore(sessionDir)
  const record = store.writeText('api_key=sk-secretvalue12345', 'plain')

  assert.ok(record)
  assert.doesNotMatch(record.path, /sk-secretvalue/)
  assert.doesNotMatch(record.prefix, /sk-secretvalue/)

  const manifest = readFileSync(store.getManifestPath(), 'utf8')
  assert.doesNotMatch(manifest, /sk-secretvalue/)
  assert.match(manifest, /REDACTED/)
})

test('ArtifactStore reads manifest with diagnostics and legacy redaction', () => {
  const sessionDir = mkdtempSync(join(tmpdir(), 'ovogo-artifacts-manifest-'))
  const store = new ArtifactStore(sessionDir)
  const current = store.writeText('tool:Read', 'current')
  appendFileSync(store.getManifestPath(), 'not-json\n', 'utf8')
  appendFileSync(store.getManifestPath(), JSON.stringify({
    path: '/tmp/legacy.txt',
    bytes: 12,
    sha256: 'legacyhash',
    createdAt: '2026-06-30T00:00:00.000Z',
    prefix: 'api_key=legacysecret12345',
  }) + '\n', 'utf8')

  const diagnostics = store.readManifestWithDiagnostics()

  assert.ok(current)
  assert.equal(diagnostics.invalidLines, 1)
  assert.equal(diagnostics.entries.length, 2)
  assert.equal(diagnostics.entries[0].path, current.path)
  assert.equal(diagnostics.entries[1].prefix, 'api_key=[REDACTED]')
  assert.doesNotMatch(JSON.stringify(diagnostics.entries), /legacysecret12345/)
  assert.deepEqual(store.readManifest(), diagnostics.entries)
})
