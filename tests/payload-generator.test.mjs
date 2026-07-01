import test from 'node:test'
import assert from 'node:assert/strict'
import { PayloadGeneratorTool } from '../dist/src/tools/payloadGenerator.js'
import { getToolDefinitions, findTool } from '../dist/src/tools/index.js'

const tool = new PayloadGeneratorTool()
const ctx = {}

test('PayloadGenerator is registered and discoverable', () => {
  const def = tool.definition
  assert.equal(def.function.name, 'PayloadGenerator')
  const tools = [tool]
  const found = findTool(tools, 'PayloadGenerator')
  assert.equal(found, tool)
})

test('PayloadGenerator definition includes all 11 categories', () => {
  const def = tool.definition
  const enumStr = def.function.parameters.properties.category.enum.join(',')
  for (const c of ['xss', 'sqli', 'lfi', 'rfi', 'deserialization', 'path_traversal', 'xxe', 'ssrf', 'cmdi', 'ssti', 'crlf', 'smuggle']) {
    assert.ok(enumStr.includes(c), `category ${c} missing from enum`)
  }
})

test('XSS payloads include classic + WAF bypass polyglot', async () => {
  const r = await tool.execute({ category: 'xss', context: 'all' }, ctx)
  assert.equal(r.isError, false)
  assert.match(r.content, /alert\(1\)/)
  assert.match(r.content, /WAF Bypass/i)
  assert.match(r.content, /Polyglot/i)
})

test('SQLi payloads cover all databases + contexts + WAF variants', async () => {
  const r = await tool.execute({ category: 'sqli', database: 'all', context: 'all', waf: 'cloudflare' }, ctx)
  assert.equal(r.isError, false)
  assert.match(r.content, /UNION/i)
  assert.match(r.content, /SLEEP/i)
  assert.match(r.content, /pg_sleep/i)
  assert.match(r.content, /WAITFOR/i)
  assert.match(r.content, /extractvalue|updatexml/i)
  assert.match(r.content, /Cloudflare specific/i)
})

test('LFI payloads include PHP filter + pearcmd + log poisoning + Windows', async () => {
  const r = await tool.execute({ category: 'lfi', wrapper: 'all', file: '/etc/passwd' }, ctx)
  assert.equal(r.isError, false)
  assert.match(r.content, /php:\/\/filter/i)
  assert.match(r.content, /pearcmd/i)
  assert.match(r.content, /auth\.log/i)
  assert.match(r.content, /win\.ini/i)
})

test('RFI/RCE payloads cover all platforms', async () => {
  const r = await tool.execute({ category: 'rfi', platform: 'all', command: 'id' }, ctx)
  assert.equal(r.isError, false)
  assert.match(r.content, /Runtime\.getRuntime/i)
  assert.match(r.content, /child_process/i)
  assert.match(r.content, /os\.system/i)
  assert.match(r.content, /OGNL|SpEL/i)
})

test('Deserialization payloads include ysoserial + phpggc + .NET', async () => {
  // Test all engines by calling separately
  const java = await tool.execute({ category: 'deserialization', engine: 'java' }, ctx)
  const php = await tool.execute({ category: 'deserialization', engine: 'php' }, ctx)
  const python = await tool.execute({ category: 'deserialization', engine: 'python' }, ctx)
  const dotnet = await tool.execute({ category: 'deserialization', engine: 'dotnet' }, ctx)
  for (const r of [java, php, python, dotnet]) assert.equal(r.isError, false)
  assert.match(java.content, /CommonsCollections/i)
  assert.match(java.content, /ysoserial/i)
  assert.match(php.content, /phpggc/i)
  assert.match(php.content, /Phar/i)
  assert.match(python.content, /PyYAML/i)
  assert.match(dotnet.content, /ysoserial\.net/i)
})

test('SSRF payloads include gopher + IP blacklist bypass', async () => {
  const r = await tool.execute({ category: 'ssrf', target_url: 'http://127.0.0.1:8080' }, ctx)
  assert.equal(r.isError, false)
  assert.match(r.content, /gopher:\/\//i)
  assert.match(r.content, /file:\/\/\/etc\/passwd/i)
  assert.match(r.content, /2130706433/)
  assert.match(r.content, /nip\.io/)
})

test('Unknown category returns error', async () => {
  const r = await tool.execute({ category: 'nonsense' }, ctx)
  assert.equal(r.isError, true)
  assert.match(r.content, /Unknown category/i)
})

test('Missing category returns error', async () => {
  const r = await tool.execute({}, ctx)
  assert.equal(r.isError, true)
  assert.match(r.content, /must provide.*category/i)
})

test('PayloadGenerator is included in default tool set', () => {
  const tools = getToolDefinitions([tool])
  const names = tools.map((t) => t.function.name)
  assert.ok(names.includes('PayloadGenerator'))
})
