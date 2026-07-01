/**
 * E2E target spawner — starts a vulnerable Flask app on a random free port,
 * returns the base URL + PID, and provides a cleanup function.
 *
 * Usage:
 *   const { baseUrl, pid, stop } = await startTarget()
 *   try {
 *     // ... run tests against baseUrl ...
 *   } finally {
 *     await stop()
 *   }
 */
import { spawn } from 'child_process'
import { randomBytes } from 'crypto'
import { resolve } from 'path'
import { setTimeout as sleep } from 'timers/promises'

const TARGET_PATH = resolve(import.meta.dirname, 'target', 'app.py')

export async function startTarget({ flag } = {}) {
  // Try a random port range — pick 0 to let OS assign a free port
  const port = 10000 + Math.floor(Math.random() * 50000)
  const flagValue = flag ?? `flag{ovogo_e2e_${randomBytes(4).toString('hex')}}`

  const proc = spawn('python3', ['-u', TARGET_PATH, String(port)], {
    env: { ...process.env, E2E_FLAG: flagValue, PYTHONUNBUFFERED: '1' },
    stdio: ['ignore', 'pipe', 'pipe'],
  })

  const baseUrl = `http://127.0.0.1:${port}`

  // Poll for HTTP readiness — more reliable than stdout matching because Python may buffer
  const deadline = Date.now() + 10000
  let ready = false
  let lastErr = null
  while (Date.now() < deadline) {
    try {
      const resp = await fetch(`${baseUrl}/`, { signal: AbortSignal.timeout(1000) })
      if (resp.ok) { ready = true; break }
      lastErr = `HTTP ${resp.status}`
    } catch (e) {
      lastErr = e.message
    }
    await sleep(100)
  }

  if (!ready) {
    proc.kill('SIGKILL')
    throw new Error(`Target failed to become ready within 10s: ${lastErr}`)
  }

  let stopped = false
  const stop = async () => {
    if (stopped) return
    stopped = true
    proc.kill('SIGTERM')
    // Give it a moment to die gracefully
    await sleep(200)
    if (!proc.killed) proc.kill('SIGKILL')
  }

  return { baseUrl, port, pid: proc.pid, flag: flagValue, stop }
}