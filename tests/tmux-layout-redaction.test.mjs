import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

import { TmuxLayout } from '../dist/src/ui/tmuxLayout.js'

test('TmuxLayout redacts direct banner and footer log writes', () => {
  const logDir = mkdtempSync(join(tmpdir(), 'ovogo-tmux-redact-'))
  const layout = new TmuxLayout()
  layout.initialized = true
  layout.logDir = logDir
  layout.sessionName = 'ovogo-test-redaction'

  const slot = layout.acquireSlot('[worker] password: tmuxsecret')
  assert.ok(slot)
  layout.releaseSlot(slot.slot)

  const raw = readFileSync(slot.logFile, 'utf8')
  assert.doesNotMatch(raw, /tmuxsecret/)
  assert.doesNotMatch(raw, /\x1b\[/)
  assert.match(raw, /password: \[REDACTED\]/)
})
