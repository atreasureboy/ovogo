import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

import { expandSkillPrompt, isValidSkillName, loadSkills } from '../dist/src/skills/loader.js'

test('file-backed skills keep metadata in index and load prompt on invocation', () => {
  const cwd = mkdtempSync(join(tmpdir(), 'ovogo-skill-'))
  const skillDir = join(cwd, '.ovogo', 'skills')
  mkdirSync(skillDir, { recursive: true })
  writeFileSync(join(skillDir, 'demo.md'), `---\nname: demo\ndescription: Demo skill\n---\nHello $ARGS`, 'utf8')

  const skills = loadSkills(cwd)
  const skill = skills.get('demo')

  assert.ok(skill)
  assert.equal(skill.description, 'Demo skill')
  assert.equal(skill.prompt, undefined)
  assert.match(skill.filePath ?? '', /demo\.md$/)
  assert.equal(expandSkillPrompt(skill, 'world'), 'Hello world')
})

test('skill loader rejects unsafe slash-command names', () => {
  const cwd = mkdtempSync(join(tmpdir(), 'ovogo-skill-unsafe-'))
  const skillDir = join(cwd, '.ovogo', 'skills')
  mkdirSync(skillDir, { recursive: true })
  writeFileSync(join(skillDir, 'safe-name.md'), `---\nname: safe-name\ndescription: Safe\n---\nOK`, 'utf8')
  writeFileSync(join(skillDir, 'bad space.md'), `---\nname: "bad space"\ndescription: Bad\n---\nNO`, 'utf8')
  writeFileSync(join(skillDir, 'slash.md'), `---\nname: "/exit"\ndescription: Bad\n---\nNO`, 'utf8')

  const skills = loadSkills(cwd)

  assert.equal(isValidSkillName('safe-name_1'), true)
  assert.equal(isValidSkillName('bad space'), false)
  assert.equal(isValidSkillName('/exit'), false)
  assert.ok(skills.get('safe-name'))
  assert.equal(skills.has('bad space'), false)
  assert.equal(skills.has('/exit'), false)
})

test('file-backed skill prompts are truncated to protect context budget', () => {
  const cwd = mkdtempSync(join(tmpdir(), 'ovogo-skill-large-'))
  const skillDir = join(cwd, '.ovogo', 'skills')
  mkdirSync(skillDir, { recursive: true })
  writeFileSync(join(skillDir, 'huge.md'), `---\nname: huge\ndescription: Huge\n---\n${'A'.repeat(90_000)}$ARGS`, 'utf8')

  const skill = loadSkills(cwd).get('huge')
  assert.ok(skill)

  const expanded = expandSkillPrompt(skill, 'tail-args')

  assert.equal(expanded.includes('tail-args'), false)
  assert.match(expanded, /Skill prompt truncated: \d+ characters omitted/)
  assert.ok(expanded.length < 81_000)
})
