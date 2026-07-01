import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

import { DocReadTool } from '../dist/src/tools/docRead.js'

test('DocRead image analysis uses ToolContext modelClient', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'ovogo-docread-'))
  const imagePath = join(dir, 'sample.png')
  writeFileSync(imagePath, Buffer.from([0x89, 0x50, 0x4e, 0x47]))

  const requests = []
  const tool = new DocReadTool()
  const result = await tool.execute(
    { file_path: imagePath, prompt: 'read text' },
    {
      cwd: dir,
      permissionMode: 'auto',
      apiConfig: { apiKey: 'unused', model: 'vision-model' },
      modelClient: {
        streamChat: async () => { throw new Error('unexpected streamChat') },
        completeText: async (request) => {
          requests.push(request)
          return 'detected text'
        },
      },
    },
  )

  assert.equal(result.isError, false)
  assert.match(result.content, /detected text/)
  assert.equal(requests.length, 1)
  assert.equal(requests[0].model, 'vision-model')
  assert.equal(requests[0].maxTokens, 4096)
  assert.deepEqual(requests[0].messages[0].content[0], { type: 'text', text: 'read text' })
  assert.match(requests[0].messages[0].content[1].image_url.url, /^data:image\/png;base64,/)
})

test('DocRead image analysis reports missing modelClient', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'ovogo-docread-missing-client-'))
  const imagePath = join(dir, 'sample.png')
  writeFileSync(imagePath, Buffer.from([0x89, 0x50, 0x4e, 0x47]))

  const tool = new DocReadTool()
  const result = await tool.execute(
    { file_path: imagePath },
    {
      cwd: dir,
      permissionMode: 'auto',
      apiConfig: { apiKey: 'unused', model: 'vision-model' },
    },
  )

  assert.equal(result.isError, true)
  assert.match(result.content, /requires modelClient/)
})
