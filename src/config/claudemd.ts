/**
 * CLAUDE.md loader — project instruction files injected into the system prompt
 *
 * Resolution order (reference: Claude Code src/utils/claudemd.ts):
 *   1. ~/.ovogo/CLAUDE.md              — user-level global instructions
 *   2. Walk from git-root → cwd:
 *      - {dir}/CLAUDE.md              — project instructions (checked in)
 *      - {dir}/.ovogo/CLAUDE.md       — project-private instructions (gitignored)
 *
 * Limits (matching Claude Code):
 *   - Max 200 lines per file (rest truncated)
 *   - Max 25 000 bytes per file (rest truncated)
 *
 * The loaded content is formatted and prepended to the system prompt so the
 * agent is aware of project-specific conventions, constraints, and commands.
 */

import { readFileSync, existsSync } from 'fs'
import { join, dirname, parse } from 'path'
import { homedir } from 'os'
import { execSync } from 'child_process'

export interface ClaudeMdFile {
  path: string
  content: string
  type: 'user' | 'project' | 'project-private'
}

const MAX_LINES = 200
const MAX_BYTES = 25_000

function readAndTruncate(filePath: string): string | null {
  try {
    const raw = readFileSync(filePath, 'utf8')
    let truncated = raw

    const lines = truncated.split('\n')
    if (lines.length > MAX_LINES) {
      truncated = lines.slice(0, MAX_LINES).join('\n')
      truncated += `\n\n[... truncated at ${MAX_LINES} lines ...]`
    }

    if (Buffer.byteLength(truncated, 'utf8') > MAX_BYTES) {
      // Byte-truncate at last newline boundary
      const buf = Buffer.from(truncated, 'utf8').slice(0, MAX_BYTES)
      const str = buf.toString('utf8')
      const lastNl = str.lastIndexOf('\n')
      truncated = (lastNl > 0 ? str.slice(0, lastNl) : str) + '\n\n[... truncated at 25 000 bytes ...]'
    }

    return truncated.trim() || null
  } catch {
    return null
  }
}

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

/** Collect directories from cwd up to (and including) gitRoot */
function dirsUpToRoot(cwd: string, gitRoot: string): string[] {
  const dirs: string[] = []
  let current = cwd
  const { root } = parse(cwd)

  while (true) {
    dirs.push(current)
    if (current === gitRoot) break
    const parent = dirname(current)
    if (parent === current || parent === root) break // filesystem root
    current = parent
  }

  // We want outermost (gitRoot) first so later entries override
  return dirs.reverse()
}

export async function loadClaudeMd(cwd: string): Promise<ClaudeMdFile[]> {
  const files: ClaudeMdFile[] = []

  // 1. User-level: ~/.ovogo/CLAUDE.md
  const userPath = join(homedir(), '.ovogo', 'CLAUDE.md')
  const userContent = readAndTruncate(userPath)
  if (userContent) {
    files.push({ path: userPath, content: userContent, type: 'user' })
  }

  // 2. Walk from git root → cwd
  const gitRoot = getGitRoot(cwd)
  const dirs = dirsUpToRoot(cwd, gitRoot)

  for (const dir of dirs) {
    // Project instructions (checked into codebase)
    const projectPath = join(dir, 'CLAUDE.md')
    if (existsSync(projectPath) && projectPath !== userPath) {
      const content = readAndTruncate(projectPath)
      if (content) files.push({ path: projectPath, content, type: 'project' })
    }

    // Project-private instructions (.ovogo/CLAUDE.md — add to .gitignore)
    const privatePath = join(dir, '.ovogo', 'CLAUDE.md')
    if (existsSync(privatePath)) {
      const content = readAndTruncate(privatePath)
      if (content) files.push({ path: privatePath, content, type: 'project-private' })
    }
  }

  return files
}

export function formatClaudeMdForPrompt(files: ClaudeMdFile[]): string {
  if (files.length === 0) return ''

  const sections = files.map((f) => {
    const typeLabel =
      f.type === 'user'
        ? "(your personal global instructions — not checked into the project)"
        : f.type === 'project'
          ? "(project instructions, checked into the codebase)"
          : "(project-private instructions — not checked in)"

    return `Contents of ${f.path} ${typeLabel}:\n\n${f.content}`
  })

  return `## Project & User Instructions\n\n${sections.join('\n\n---\n\n')}`
}
