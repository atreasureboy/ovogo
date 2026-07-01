import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

import { SemanticMemory } from '../dist/src/core/semanticMemory.js'
import { EpisodicMemory } from '../dist/src/core/episodicMemory.js'
import { KnowledgeBase } from '../dist/src/core/knowledgeBase.js'

test('SemanticMemory and EpisodicMemory redact persisted entries', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ovogo-memory-redaction-'))
  const semantic = new SemanticMemory(dir)
  const episodic = new EpisodicMemory(dir)

  const semanticEntry = semantic.write({
    content: 'credential found: password: semanticsecret',
    tags: ['credential'],
    source: 'Authorization: Bearer abcdefghijklmnop',
    timestamp: new Date().toISOString(),
    confidence: 0.9,
  })
  const episodeEntry = episodic.write({
    turn: 1,
    toolName: 'Bash',
    inputSummary: 'curl https://example.test/?token=episodicsecret',
    resultSummary: 'client_secret: resultsecret',
    outcome: 'success',
    timestamp: new Date().toISOString(),
  })

  const rawSemantic = readFileSync(join(dir, 'memory', 'semantic.jsonl'), 'utf8')
  const rawEpisodic = readFileSync(join(dir, 'memory', 'episodes.jsonl'), 'utf8')
  const combined = rawSemantic + rawEpisodic

  assert.doesNotMatch(combined, /semanticsecret|abcdefghijklmnop|episodicsecret|resultsecret/)
  assert.match(semanticEntry.content, /password: \[REDACTED\]/)
  assert.match(semanticEntry.source, /Bearer \[REDACTED\]/)
  assert.match(episodeEntry.inputSummary, /token=\[REDACTED\]/)
  assert.match(episodeEntry.resultSummary, /client_secret: \[REDACTED\]/)
})

test('KnowledgeBase redacts entries before JSONL persistence', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ovogo-knowledge-redaction-'))
  const kb = new KnowledgeBase(dir)

  kb.write('cve_notes', {
    id: 'kb-redaction-test',
    cve: 'CVE-2099-0001',
    service: 'demo',
    exploit_summary: 'Authorization: Bearer knowledgebearersecret',
    payload_type: 'curl',
    success: true,
    confidence: 0.8,
    notes: 'api_key: knowledgesecret',
  })

  const raw = readFileSync(join(dir, 'cve_notes.jsonl'), 'utf8')
  assert.doesNotMatch(raw, /knowledgebearersecret|knowledgesecret/)
  assert.match(raw, /Bearer \[REDACTED\]/)
  assert.match(raw, /api_key: \[REDACTED\]/)
})
