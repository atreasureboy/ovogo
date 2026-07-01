# Adding a Tool to Ovogo

This guide walks through creating a new tool and registering it with the engine. The example below adds a fictional `NetworkPing` tool.

## Tool anatomy

Every tool implements the `Tool` interface from `src/core/types.ts`:

```typescript
export interface Tool {
  name: string
  definition: ToolDefinition
  runtime?: ToolRuntimeMetadata
  execute(input: Record<string, unknown>, context: ToolContext): Promise<ToolResult>
}
```

- `name` — must be unique across all registered tools (used by the LLM).
- `definition` — OpenAI-compatible function spec; the LLM uses this to know when to call the tool.
- `runtime` — declarative metadata that drives plan-mode filtering, parallel batching, and caching. **Always set this.**
- `execute` — the implementation; receives parsed args and a `ToolContext`.

## Step 1 — Create the tool file

Create `src/tools/networkPing.ts`:

```typescript
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import type { Tool, ToolContext, ToolDefinition, ToolResult } from '../core/types.js'

const execFileP = promisify(execFile)
const MAX_OUTPUT_LENGTH = 4_000

export class NetworkPingTool implements Tool {
  name = 'NetworkPing'

  definition: ToolDefinition = {
    type: 'function',
    function: {
      name: 'NetworkPing',
      description: 'Send ICMP echo requests to a host. Returns round-trip stats.',
      parameters: {
        type: 'object',
        properties: {
          host: { type: 'string', description: 'Hostname or IP to ping' },
          count: { type: 'integer', description: 'Number of probes (default 4)' },
        },
        required: ['host'],
      },
    },
  }

  runtime = {
    // Treat as read-only so `permissionMode: deny` allows it and it can run
    // in plan mode.
    readOnly: true,
    // Safe to run in parallel with other concurrency-safe tools.
    concurrencySafe: true,
    // Cached briefly — ping results rarely change inside a session.
    cacheable: true,
    cacheTtlMs: 60_000,
    // Not long-running (4 default probes < 5s).
    longRunning: false,
  } as const

  async execute(input: Record<string, unknown>, context: ToolContext): Promise<ToolResult> {
    const host = String(input.host ?? '').trim()
    const count = Math.min(Math.max(Number(input.count ?? 4), 1), 20)

    if (!host) {
      return { content: 'Error: host is required', isError: true }
    }

    try {
      const { stdout, stderr } = await execFileP('ping', ['-c', String(count), host], {
        timeout: 30_000,
        signal: context.signal,
      })
      return { content: stdout || stderr, isError: false }
    } catch (err) {
      return { content: `ping failed: ${(err as Error).message}`, isError: true }
    }
  }
}
```

### Key conventions

- **Always honor `context.signal`** for abort support (Ctrl+C, engine timeout).
- **Truncate long output** to avoid blowing the LLM context budget. ~30 KB is a safe ceiling.
- **Return `{ content, isError }`** — never throw from `execute` unless it's truly catastrophic.
- **Validate inputs at the top** of `execute` — return `{ isError: true }` on bad input.

## Step 2 — Register the tool

Edit `src/tools/index.ts`:

```typescript
import { NetworkPingTool } from './networkPing.js'

// Inside createTools():
const tools: Tool[] = [
  // ... existing tools ...
  new NetworkPingTool(),  // ← add here
  ...extraTools,
]

// Also add to the bottom re-exports:
export { NetworkPingTool }
```

Order doesn't matter functionally, but keep new tools grouped logically (network probes near `webFetch`, file ops near `bash`, etc.).

## Step 3 — Add the tool description to the system prompt

The system prompt in `src/prompts/system.ts` lists tools the LLM sees. If your tool is a core capability, add a one-liner to the TOOLS section. Otherwise the model can still discover it from `definition.description`.

## Step 4 — Permissions (optional)

If your tool reads files, extends `Write/Edit/MultiScan` patterns, or runs Bash, you may need to wire it into `PermissionManager.getFilePathsFromInput` in `src/core/permissionManager.ts`.

For self-contained tools like `NetworkPing` that don't touch the filesystem or shell, no permission wiring is needed.

## Step 5 — Tests

Add `tests/network-ping.test.mjs`:

```javascript
import test from 'node:test'
import assert from 'node:assert/strict'
import { NetworkPingTool } from '../dist/src/tools/networkPing.js'

test('NetworkPing rejects missing host', async () => {
  const tool = new NetworkPingTool()
  const result = await tool.execute({}, { cwd: '/tmp', permissionMode: 'auto' })
  assert.equal(result.isError, true)
  assert.match(result.content, /host is required/)
})

test('NetworkPing runtime metadata is correct', () => {
  const tool = new NetworkPingTool()
  assert.equal(tool.runtime?.readOnly, true)
  assert.equal(tool.runtime?.concurrencySafe, true)
  assert.equal(tool.runtime?.cacheable, true)
})
```

## Step 6 — Build & test

```bash
npm run build
npm test
```

Both must pass before committing.

## Runtime metadata quick reference

| Flag | Effect when `true` |
|---|---|
| `readOnly` | Tool exposed in plan mode; allowed under `permissionMode: deny` |
| `concurrencySafe` | Tool runs in parallel batches via `Promise.all` |
| `cacheable` | Identical (name, input) results reused from `ToolCache` |
| `cacheTtlMs` | TTL for cached results (default: tool-specific) |
| `longRunning` | UI shows `ProgressTracker` updates; prompts engine to consider background mode |

Defaults: `readOnly=false`, `concurrencySafe=false`, `cacheable=false`, `longRunning=false`. **Always set these explicitly** — the engine doesn't infer them.

## Where to look for examples

- `src/tools/bash.ts` — long-running, abort handling, output truncation
- `src/tools/fileRead.ts` — file scope permissions
- `src/tools/webFetch.ts` — uses `context.modelClient` for image analysis
- `src/tools/multiScan.ts` — fan-out, background mode
- `src/tools/envAnalyzer.ts` — read-only with multiple internal probes