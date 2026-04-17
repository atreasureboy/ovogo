/**
 * SkillDefinition — type for phase-based skill tool grouping.
 *
 * Used by src/skills/*.ts to define which tools belong to each
 * penetration testing phase.
 */

import type { Tool, ToolDefinition } from './types.js'

export interface SkillDefinition {
  name: string
  description: string
  /** Which engagement phases this skill is active in */
  phases: string[]
  /** Tools provided by this skill */
  tools: Tool[]
}

/** Get tool definitions from a list of skills */
export function getSkillTools(skills: SkillDefinition[]): Tool[] {
  return skills.flatMap((s) => s.tools)
}
