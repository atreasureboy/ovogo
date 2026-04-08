/**
 * Memory system — persistent cross-session memory for ovogogogo
 *
 * Reference: Claude Code src/memdir/, src/utils/paths.ts
 *
 * Storage layout:
 *   ~/.ovogo/projects/{project-slug}/memory/
 *     MEMORY.md            ← index file (loaded into every system prompt)
 *     user_role.md         ← individual memory files (written by the agent)
 *     feedback_testing.md
 *     ...
 *
 * The project slug is derived from the git root path (or cwd if not a repo).
 * Example: /home/user/my-project → home-user-my-project
 *
 * How it works:
 * 1. At startup, MEMORY.md is loaded and injected into the system prompt
 * 2. The agent is instructed HOW to write memories (format, when, types)
 * 3. When the agent writes a memory, it uses the Write tool directly:
 *    - Creates/updates the individual .md file in memoryDir
 *    - Adds a pointer line to MEMORY.md
 * No special tool needed — the agent uses Write like it writes any other file.
 *
 * Memory file frontmatter format:
 *   ---
 *   name: Short title
 *   description: One-line description (used for relevance matching)
 *   type: user | feedback | project | reference
 *   ---
 *
 * MEMORY.md limits (matching Claude Code):
 *   - 200 lines max (rest truncated and not loaded)
 *   - 25 000 bytes max
 */

import { readFileSync, existsSync, mkdirSync } from 'fs'
import { join, parse } from 'path'
import { homedir } from 'os'
import { execSync } from 'child_process'

const MEMORY_INDEX_FILE = 'MEMORY.md'
const MAX_INDEX_LINES = 200
const MAX_INDEX_BYTES = 25_000

// ─────────────────────────────────────────────────────────────
// Path resolution
// ─────────────────────────────────────────────────────────────

function getGitRoot(cwd: string): string {
  try {
    return execSync('git rev-parse --show-toplevel', {
      cwd,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim()
  } catch {
    return cwd
  }
}

/** Turn an absolute path into a flat slug for directory naming */
function slugifyPath(p: string): string {
  return p
    .replace(/^\//, '')          // strip leading /
    .replace(/\//g, '-')         // / → -
    .replace(/[^a-zA-Z0-9\-_.]/g, '_')  // sanitize special chars
    .slice(0, 128)               // max length
}

/** Return the memory directory for the current project (creates it if absent) */
export function getMemoryDir(cwd: string): string {
  const gitRoot = getGitRoot(cwd)
  const slug = slugifyPath(gitRoot)
  const dir = join(homedir(), '.ovogo', 'projects', slug, 'memory')
  mkdirSync(dir, { recursive: true })
  return dir
}

// ─────────────────────────────────────────────────────────────
// Index loading
// ─────────────────────────────────────────────────────────────

interface IndexResult {
  content: string
  lineCount: number
  wasTruncated: boolean
}

function loadMemoryIndex(memoryDir: string): IndexResult {
  const indexPath = join(memoryDir, MEMORY_INDEX_FILE)
  if (!existsSync(indexPath)) {
    return { content: '', lineCount: 0, wasTruncated: false }
  }

  try {
    const raw = readFileSync(indexPath, 'utf8')
    const lines = raw.split('\n')
    let truncated = raw
    let wasTruncated = false

    if (lines.length > MAX_INDEX_LINES) {
      truncated = lines.slice(0, MAX_INDEX_LINES).join('\n')
      wasTruncated = true
    }

    if (Buffer.byteLength(truncated, 'utf8') > MAX_INDEX_BYTES) {
      const buf = Buffer.from(truncated, 'utf8').slice(0, MAX_INDEX_BYTES)
      const str = buf.toString('utf8')
      const lastNl = str.lastIndexOf('\n')
      truncated = lastNl > 0 ? str.slice(0, lastNl) : str
      wasTruncated = true
    }

    return { content: truncated.trim(), lineCount: lines.length, wasTruncated }
  } catch {
    return { content: '', lineCount: 0, wasTruncated: false }
  }
}

// ─────────────────────────────────────────────────────────────
// System prompt assembly
// ─────────────────────────────────────────────────────────────

export function buildMemorySystemSection(memoryDir: string): string {
  const { content, lineCount, wasTruncated } = loadMemoryIndex(memoryDir)

  const indexSection = content
    ? `## Current MEMORY.md\n\n${content}${wasTruncated ? `\n\n> ⚠ MEMORY.md has ${lineCount} lines — only first ${MAX_INDEX_LINES} shown. Keep index concise.` : ''}`
    : `## Current MEMORY.md\n\n(empty — no memories saved yet)`

  const instructions = `## Memory Instructions

You have a persistent, file-based memory system at: \`${memoryDir}\`

This directory persists between conversations. Read from it to recall past context; write to it to save important facts for future sessions.

### When to save a memory
- **User** — roles, preferences, working style, knowledge level
- **Feedback** — corrections or confirmations of your approach (what to do / avoid)
- **Project** — ongoing goals, decisions, deadlines, stakeholders
- **Reference** — pointers to external resources (dashboards, issue trackers, docs)

Do NOT save: code patterns derivable from reading the codebase, git history, or anything already in CLAUDE.md.

### How to save (2 steps)

**Step 1 — Write the memory file** using the Write tool:
\`\`\`
path: ${memoryDir}/example_memory.md
content:
---
name: Short descriptive title
description: One-line description (used to decide relevance in future sessions)
type: user | feedback | project | reference
---

Memory content here. For feedback/project types, include:
**Why:** reason the user gave
**How to apply:** when this should change your behavior
\`\`\`

**Step 2 — Add a pointer in MEMORY.md** (append one line):
\`\`\`
- [Short title](example_memory.md) — one-line hook under ~150 chars
\`\`\`

### Rules
- Each memory lives in its own file — never put content directly in MEMORY.md
- MEMORY.md is an index only; lines 201+ are truncated and never read
- Check for existing memories before creating duplicates (use Read + Glob)
- Update stale memories rather than creating new ones
- If the user says "remember X", save it immediately`

  return `# Persistent Memory\n\n${indexSection}\n\n${instructions}`
}

// ─────────────────────────────────────────────────────────────
// Diagnostics (for startup banner)
// ─────────────────────────────────────────────────────────────

export interface MemoryStats {
  memoryDir: string
  entryCount: number
  hasIndex: boolean
}

export function getMemoryStats(memoryDir: string): MemoryStats {
  const indexPath = join(memoryDir, MEMORY_INDEX_FILE)
  if (!existsSync(indexPath)) {
    return { memoryDir, entryCount: 0, hasIndex: false }
  }

  try {
    const content = readFileSync(indexPath, 'utf8')
    // Count lines that look like memory entries: "- [..."
    const entryCount = content.split('\n').filter((l) => /^- \[/.test(l)).length
    return { memoryDir, entryCount, hasIndex: true }
  } catch {
    return { memoryDir, entryCount: 0, hasIndex: true }
  }
}
