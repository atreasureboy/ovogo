import test from 'node:test'
import assert from 'node:assert/strict'

import { redactAgentExecutionResult } from '../dist/src/core/agentResultTypes.js'

test('redactAgentExecutionResult preserves shape while masking sensitive leaves', () => {
  const result = redactAgentExecutionResult({
    agentType: 'worker',
    success: true,
    summary: 'found Authorization: Bearer abcdefghijklmnop and token=querysecret',
    outputFiles: ['report-token=filesecret.txt'],
    findings: [{
      title: 'finding',
      description: 'password: findingsecret',
      severity: 'high',
      evidence: 'client_secret: evidencesecret',
    }],
    webServices: [{ url: 'https://example.com/callback?access_token=urlsecret', status: 200 }],
    credentials: [{ host: 'example.com', username: 'admin', password: 'credentialsecret', source: 'dump' }],
    duration: 42,
    error: 'api_key: errorsecret',
  })

  assert.equal(result.agentType, 'worker')
  assert.equal(result.duration, 42)
  assert.equal(result.credentials?.[0]?.username, 'admin')
  assert.equal(result.credentials?.[0]?.password, '[REDACTED]')
  assert.doesNotMatch(JSON.stringify(result), /abcdefghijklmnop|querysecret|filesecret|findingsecret|evidencesecret|urlsecret|credentialsecret|errorsecret/)
  assert.match(result.summary, /Bearer \[REDACTED\]/)
  assert.match(result.findings[0].description, /password: \[REDACTED\]/)
  assert.match(result.webServices?.[0]?.url ?? '', /access_token=\[REDACTED\]/)
  assert.match(result.error ?? '', /api_key: \[REDACTED\]/)
})
