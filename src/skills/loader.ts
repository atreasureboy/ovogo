/**
 * Skills loader — extensible slash-command system
 *
 * A skill is a prompt template invoked by /skill-name in the REPL.
 * When triggered, the skill's prompt is sent to the engine as a task.
 *
 * Resolution order (later entries override earlier):
 *   1. Built-in skills (shipped with ovogogogo)
 *   2. ~/.ovogo/skills/        (global user skills)
 *   3. .ovogo/skills/          (project-specific skills)
 *
 * Supported file layouts:
 *   .ovogo/skills/nmap.md          → skill name "nmap"  (flat file)
 *   .ovogo/skills/agentos/SKILL.md → skill name "agentos"  (directory + SKILL.md)
 *
 * YAML frontmatter (optional):
 *   ---
 *   name: nmap
 *   description: nmap — 网络端口扫描与服务识别
 *   ---
 *   If present, name/description are read from it.
 *   If absent, name = filename stem, description = first heading line.
 *
 * Skills support $ARGS substitution:
 *   /nmap scan 10.0.0.1  →  $ARGS = "scan 10.0.0.1"
 */

import { readdirSync, readFileSync, existsSync } from 'fs'
import { join, basename, resolve } from 'path'
import { homedir } from 'os'

export interface Skill {
  name: string
  description: string
  prompt: string
  source: 'builtin' | 'global' | 'project'
}

// ─────────────────────────────────────────────────────────────
// YAML frontmatter parser (no external deps)
// ─────────────────────────────────────────────────────────────

function parseFrontmatter(content: string): {
  frontmatter: Record<string, string>
  body: string
} {
  const match = content.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/)
  if (!match) return { frontmatter: {}, body: content }

  const fm: Record<string, string> = {}
  for (const line of match[1].split('\n')) {
    const colonIdx = line.indexOf(':')
    if (colonIdx > 0) {
      const key = line.slice(0, colonIdx).trim()
      // Strip surrounding quotes from value
      const value = line.slice(colonIdx + 1).trim().replace(/^["']|["']$/g, '')
      if (key) fm[key] = value
    }
  }

  return { frontmatter: fm, body: (match[2] ?? '').trim() }
}

// ─────────────────────────────────────────────────────────────
// File parser
// ─────────────────────────────────────────────────────────────

function parseSkillFile(
  filePath: string,
  defaultName: string,
  source: 'global' | 'project',
): Skill | null {
  try {
    const raw = readFileSync(filePath, 'utf8').trim()
    const { frontmatter, body } = parseFrontmatter(raw)

    const name = (frontmatter.name ?? defaultName).trim()

    // Description: frontmatter > first heading line > name
    let description = frontmatter.description ?? ''
    if (!description) {
      const firstLine = (body || raw).split('\n').find((l) => l.trim()) ?? ''
      description = firstLine.replace(/^#+\s*/, '').trim() || name
    }

    // Prompt: body (frontmatter stripped), or full raw if no frontmatter
    const prompt = body || raw

    return { name, description, prompt, source }
  } catch {
    return null
  }
}

// ─────────────────────────────────────────────────────────────
// Directory loader
// ─────────────────────────────────────────────────────────────

function loadFromDir(dir: string, source: 'global' | 'project'): Skill[] {
  if (!existsSync(dir)) return []
  const skills: Skill[] = []

  try {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.isFile() && entry.name.endsWith('.md')) {
        // Flat file: skills/nmap.md → name = "nmap"
        const name = basename(entry.name, '.md')
        const skill = parseSkillFile(join(dir, entry.name), name, source)
        if (skill) skills.push(skill)
      } else if (entry.isDirectory()) {
        // Directory: skills/agentos/SKILL.md → name = "agentos"
        const skillFile = join(dir, entry.name, 'SKILL.md')
        if (existsSync(skillFile)) {
          const skill = parseSkillFile(skillFile, entry.name, source)
          if (skill) skills.push(skill)
        }
      }
    }
  } catch {
    // ignore unreadable dirs
  }

  return skills
}

// ─────────────────────────────────────────────────────────────
// Built-in skills
// ─────────────────────────────────────────────────────────────

const BUILTIN_SKILLS: Skill[] = [
  {
    name: 'commit',
    description: 'Analyze staged changes and create a semantic git commit',
    prompt: `Analyze the staged git changes and create a well-formed commit.

Steps:
1. Run \`git status\` to see what is staged
2. Run \`git diff --staged\` to read the actual changes
3. Run \`git log --oneline -5\` to match the project's commit message style
4. Draft a concise commit message: imperative mood, under 72 chars, explain the "why" not just the "what"
5. Commit with \`git commit -m "..."\`

Do NOT push. Do NOT amend previous commits unless explicitly asked.
If nothing is staged, say so and stop.`,
    source: 'builtin',
  },
  {
    name: 'review',
    description: 'Review recent or staged changes for quality, bugs, and security',
    prompt: `Review the code changes for correctness, quality, and security issues.
$ARGS

Steps:
1. Determine what to review: if $ARGS specifies a file/path use that, otherwise check \`git diff --staged\` or \`git diff HEAD~1 HEAD\`
2. For each changed section, evaluate:
   - **Correctness**: edge cases, off-by-one errors, null/undefined handling, race conditions
   - **Security**: SQL injection, XSS, command injection, hardcoded secrets, path traversal
   - **Quality**: unnecessary complexity, missing error handling, dead code, magic numbers
3. Output findings grouped by severity:
   - 🔴 Critical — must fix before merge
   - 🟡 Warning — should fix
   - 🔵 Suggestion — nice to have
4. If no issues found, say so explicitly.

Do NOT make changes — only report your analysis.`,
    source: 'builtin',
  },
  {
    name: 'fix-types',
    description: 'Find and fix all TypeScript type errors',
    prompt: `Find and fix all TypeScript type errors in the project.

Steps:
1. Run \`npx tsc --noEmit 2>&1\` to get the full list of errors
2. If no errors, report success and stop
3. Fix each error systematically, starting with the ones that cascade (base types first)
4. After fixing, re-run tsc to confirm zero errors
5. Do not change runtime behavior — only fix types`,
    source: 'builtin',
  },
  {
    name: 'test',
    description: 'Run the test suite and fix any failures',
    prompt: `Run the test suite and fix any failures.
$ARGS

Steps:
1. Detect the test runner: check package.json scripts for "test", look for jest/vitest/mocha config
2. Run the tests: \`npm test $ARGS\` or equivalent
3. If all tests pass, report the results and stop
4. For each failing test:
   - Read the test file to understand what it expects
   - Read the implementation to understand what it does
   - Fix the implementation (not the test, unless the test is clearly wrong)
5. Re-run tests to confirm all pass`,
    source: 'builtin',
  },
]

// ─────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────

export function loadSkills(cwd: string): Map<string, Skill> {
  const map = new Map<string, Skill>()

  // Built-in (lowest priority)
  for (const s of BUILTIN_SKILLS) map.set(s.name, s)

  // Global user skills override built-ins
  for (const s of loadFromDir(join(homedir(), '.ovogo', 'skills'), 'global')) {
    map.set(s.name, s)
  }

  // Project skills override all
  for (const s of loadFromDir(resolve(cwd, '.ovogo', 'skills'), 'project')) {
    map.set(s.name, s)
  }

  return map
}

/**
 * Expand a skill prompt, substituting $ARGS with the provided arguments string.
 */
export function expandSkillPrompt(skill: Skill, args: string): string {
  return skill.prompt.replace(/\$ARGS/g, args.trim())
}
