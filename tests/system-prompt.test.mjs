import test from 'node:test'
import assert from 'node:assert/strict'

import { getSystemPrompt } from '../dist/src/prompts/system.js'

test('generic profile uses domain-neutral system prompt', () => {
  const prompt = getSystemPrompt('/workspace/project', undefined, '/workspace/project/sessions/1', 'generic')

  assert.match(prompt, /domain-neutral autonomous coding agent/)
  assert.match(prompt, /Working directory: \/workspace\/project/)
  assert.doesNotMatch(prompt, /红队作战/)
  assert.doesNotMatch(prompt, /MITRE ATT&CK/)
})

test('redteam profile preserves legacy prompt by default', () => {
  const prompt = getSystemPrompt('/workspace/project')

  assert.match(prompt, /红队作战/)
})
