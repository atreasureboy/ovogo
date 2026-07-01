import test from 'node:test'
import assert from 'node:assert/strict'
import { Writable } from 'node:stream'

import { Renderer } from '../dist/src/ui/renderer.js'

function captureStream() {
  let output = ''
  const stream = new Writable({
    write(chunk, _encoding, callback) {
      output += chunk.toString()
      callback()
    },
  })
  return { stream, output: () => output }
}

test('Renderer redacts file-style output when redaction is enabled', () => {
  const capture = captureStream()
  const renderer = new Renderer({ stream: capture.stream, redactOutput: true })

  renderer.info('password: rendersecret')
  renderer.toolResult('Bash', 'Authorization: Bearer abcdefghijklmnop', false)
  renderer.streamToken('client_secret: streamsecret')
  renderer.endAssistantText()

  const output = capture.output()
  assert.doesNotMatch(output, /rendersecret|abcdefghijklmnop|streamsecret/)
  assert.match(output, /password: \[REDACTED\]/)
  assert.match(output, /Bearer \[REDACTED\]/)
  assert.match(output, /client_secret: \[REDACTED\]/)
})
