/**
 * Tool descriptions
 */

export const BASH_DESCRIPTION = `Executes a bash command and returns its output (stdout + stderr combined).

The working directory persists between calls via absolute paths. Shell state (variables, aliases) does NOT persist.

IMPORTANT: Avoid using this for file operations when dedicated tools exist:
- File search: Use Glob (NOT find or ls)
- Content search: Use Grep (NOT grep or rg)
- Read files: Use ReadFile (NOT cat/head/tail)
- Edit files: Use EditFile (NOT sed/awk)
- Write files: Use WriteFile (NOT echo > or cat <<EOF)

Reserve Bash for: running scripts, package installation, git operations, test execution, and system commands.

Instructions:
- Always quote paths with spaces: "path with spaces/file.txt"
- Use absolute paths to avoid cwd confusion
- For multiple independent commands, make parallel tool calls
- For dependent sequential commands, chain with && in one call
- Default timeout: 120 seconds
- Use run_in_background=true for long-running processes you don't need to wait for`

export const READ_FILE_DESCRIPTION = `Reads a file from the filesystem and returns its contents with line numbers.

Usage:
- Provide an absolute file path
- Optionally specify offset (start line) and limit (number of lines) for large files
- Returns content in cat -n format: "line_number\\tcontent"
- Can read text files, code files, JSON, YAML, etc.`

export const WRITE_FILE_DESCRIPTION = `Writes content to a file, creating it if it doesn't exist or overwriting if it does.

IMPORTANT: For existing files, prefer EditFile (precise string replacement) over WriteFile (full overwrite).
Only use WriteFile for:
- Creating new files
- Complete rewrites where the entire content changes

Always read the file first before overwriting to avoid losing content.`

export const EDIT_FILE_DESCRIPTION = `Performs exact string replacement in a file.

Usage:
- Provide the file path, the exact string to find (old_string), and the replacement (new_string)
- The old_string must match EXACTLY including whitespace and indentation
- If old_string appears multiple times, use more context to make it unique
- Use replace_all=true to replace all occurrences

This is the preferred way to modify existing files — it's precise and shows exactly what changed.`

export const GLOB_DESCRIPTION = `Finds files matching a glob pattern, sorted by modification time (newest first).

Examples:
- "**/*.ts" — all TypeScript files recursively
- "src/**/*.{js,ts}" — JS/TS files under src/
- "*.json" — JSON files in current directory

Returns a list of matching absolute file paths.`

export const GREP_DESCRIPTION = `Searches file contents using regex patterns (powered by ripgrep).

Parameters:
- pattern: regex pattern to search for
- path: directory or file to search (defaults to cwd)
- glob: file pattern filter (e.g. "*.ts")
- output_mode: "files_with_matches" (default) | "content" | "count"
- context: lines before/after each match (when output_mode="content")
- case_insensitive: true/false

Examples:
- Find files containing "useEffect": pattern="useEffect", glob="*.tsx"
- Show matching lines: pattern="TODO", output_mode="content"
- Count matches: pattern="console.log", output_mode="count"`
