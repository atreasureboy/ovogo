import test from 'node:test'
import assert from 'node:assert/strict'

import { redactRecord, redactText } from '../dist/src/core/redaction.js'

test('redactText masks common inline secret formats', () => {
  const input = [
    'Authorization: Bearer abcdefghijklmnop',
    'Authorization: Basic dXNlcjpwYXNz',
    'Set-Cookie: sessionid=cookiesecret; HttpOnly',
    'Cookie: csrftoken=csrfcookiesecret; theme=light',
    'https://user:urlpasssecret@example.test/path',
    'OPENAI_API_KEY=sk-testsecret1234567890',
    'AWS_SECRET_ACCESS_KEY="awssecretaccesskey"',
    'PRIVATE_KEY=inlineprivatekeysecret',
    'access_token=accesssecret',
    'password: colonsecret',
    'client_secret: clientcolonsecret',
    '"password":"jsonsecret"',
    "'api_key': 'singlequotedsecret'",
    '-----BEGIN PRIVATE KEY-----',
    'abc123secret',
    '-----END PRIVATE KEY-----',
  ].join('\n')
  const redacted = redactText(input)

  assert.doesNotMatch(redacted, /abcdefghijklmnop/)
  assert.doesNotMatch(redacted, /dXNlcjpwYXNz/)
  assert.doesNotMatch(redacted, /cookiesecret/)
  assert.doesNotMatch(redacted, /csrfcookiesecret/)
  assert.doesNotMatch(redacted, /urlpasssecret/)
  assert.doesNotMatch(redacted, /sk-testsecret/)
  assert.doesNotMatch(redacted, /awssecretaccesskey/)
  assert.doesNotMatch(redacted, /inlineprivatekeysecret/)
  assert.doesNotMatch(redacted, /accesssecret/)
  assert.doesNotMatch(redacted, /colonsecret/)
  assert.doesNotMatch(redacted, /clientcolonsecret/)
  assert.doesNotMatch(redacted, /jsonsecret/)
  assert.doesNotMatch(redacted, /singlequotedsecret/)
  assert.doesNotMatch(redacted, /abc123secret/)
  assert.match(redacted, /Bearer \[REDACTED\]/)
  assert.match(redacted, /Basic \[REDACTED\]/)
  assert.match(redacted, /Set-Cookie: \[REDACTED\]/)
  assert.match(redacted, /Cookie: \[REDACTED\]/)
  assert.match(redacted, /https:\/\/user:\[REDACTED\]@example\.test/)
  assert.match(redacted, /OPENAI_API_KEY=\[REDACTED\]/)
  assert.match(redacted, /AWS_SECRET_ACCESS_KEY=\[REDACTED\]/)
  assert.match(redacted, /PRIVATE_KEY=\[REDACTED\]/)
  assert.match(redacted, /password: \[REDACTED\]/)
  assert.match(redacted, /client_secret: \[REDACTED\]/)
  assert.match(redacted, /"password":"\[REDACTED\]"/)
  assert.match(redacted, /'api_key': '\[REDACTED\]'/)
})

test('redactRecord masks sensitive keys and circular references', () => {
  const input = {
    apiKey: 'sk-testsecret1234567890',
    nested: { token: 'plainsecret', value: 'safe' },
  }
  input.self = input

  const redacted = redactRecord(input)

  assert.equal(redacted.apiKey, '[REDACTED]')
  assert.equal(redacted.nested.token, '[REDACTED]')
  assert.equal(redacted.nested.value, 'safe')
  assert.equal(redacted.self, '[Circular]')
})

test('redactRecord preserves non-secret token telemetry keys', () => {
  const redacted = redactRecord({
    tokenCount: 123,
    tokens_before: 456,
    maxTokens: 789,
    credentialCount: 2,
    apiKey: 'sk-testsecret1234567890',
    clientSecret: 'client-secret-value',
  })

  assert.equal(redacted.tokenCount, 123)
  assert.equal(redacted.tokens_before, 456)
  assert.equal(redacted.maxTokens, 789)
  assert.equal(redacted.credentialCount, 2)
  assert.equal(redacted.apiKey, '[REDACTED]')
  assert.equal(redacted.clientSecret, '[REDACTED]')
})
