import test from 'node:test'
import assert from 'node:assert/strict'

import { OpenAICompatibleModelClient } from '../dist/src/core/modelClient.js'

test('OpenAICompatibleModelClient.completeText maps request and trims output', async () => {
  const calls = []
  const fakeOpenAI = {
    chat: {
      completions: {
        create: async (...args) => {
          calls.push(args)
          return { choices: [{ message: { content: '  done  ' } }] }
        },
      },
    },
  }
  const client = new OpenAICompatibleModelClient(fakeOpenAI)

  const result = await client.completeText({
    model: 'unit-model',
    messages: [{ role: 'user', content: 'hello' }],
    temperature: 0.2,
    maxTokens: 123,
    responseFormat: 'json_object',
  })

  assert.equal(result, 'done')
  assert.equal(calls.length, 1)
  assert.equal(calls[0][0].model, 'unit-model')
  assert.equal(calls[0][0].max_tokens, 123)
  assert.equal(calls[0][0].temperature, 0.2)
  assert.deepEqual(calls[0][0].response_format, { type: 'json_object' })
})

test('OpenAICompatibleModelClient.completeText forwards multimodal content', async () => {
  const calls = []
  const fakeOpenAI = {
    chat: {
      completions: {
        create: async (...args) => {
          calls.push(args)
          return { choices: [{ message: { content: 'vision result' } }] }
        },
      },
    },
  }
  const client = new OpenAICompatibleModelClient(fakeOpenAI)

  const content = [
    { type: 'text', text: 'describe' },
    { type: 'image_url', image_url: { url: 'data:image/png;base64,abc', detail: 'high' } },
  ]
  const result = await client.completeText({
    model: 'vision-model',
    messages: [{ role: 'user', content }],
  })

  assert.equal(result, 'vision result')
  assert.deepEqual(calls[0][0].messages[0].content, content)
})

test('OpenAICompatibleModelClient.streamChat enables tool streaming', async () => {
  const calls = []
  const fakeStream = { [Symbol.asyncIterator]: async function* () {} }
  const fakeOpenAI = {
    chat: {
      completions: {
        create: async (...args) => {
          calls.push(args)
          return fakeStream
        },
      },
    },
  }
  const client = new OpenAICompatibleModelClient(fakeOpenAI)

  const result = await client.streamChat({
    model: 'unit-model',
    systemPrompt: 'system',
    messages: [{ role: 'user', content: 'hello' }],
    tools: [],
  })

  assert.equal(result, fakeStream)
  assert.equal(calls[0][0].stream, true)
  assert.equal(calls[0][0].tool_choice, 'auto')
  assert.deepEqual(calls[0][0].messages[0], { role: 'system', content: 'system' })
})
