/**
 * Shell command execution — thin re-export for agent modules.
 *
 * Agent modules (lateral, c2, report, privesc) import `executeCommand` from
 * here rather than reaching into src/tools/shellSession directly.
 */
export { executeCommand } from '../tools/shellSession.js'
