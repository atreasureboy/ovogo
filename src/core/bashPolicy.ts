export type BashCommandCapability =
  | 'read'
  | 'write'
  | 'network'
  | 'destructive'
  | 'dynamic_code'
  | 'unknown'

export interface BashCommandPolicy {
  readOnly: boolean
  capabilities: BashCommandCapability[]
  reason?: string
}

const READ_ONLY_COMMANDS = new Set([
  'awk',
  'bat',
  'cat',
  'cmp',
  'df',
  'diff',
  'du',
  'egrep',
  'fgrep',
  'file',
  'find',
  'free',
  'git',
  'grep',
  'head',
  'hostname',
  'id',
  'ip',
  'jq',
  'less',
  'ls',
  'more',
  'netstat',
  'nl',
  'pwd',
  'rg',
  'sed',
  'sort',
  'ss',
  'stat',
  'tail',
  'tree',
  'uname',
  'uniq',
  'uptime',
  'w',
  'wc',
  'who',
  'whoami',
])

const READ_ONLY_GIT_SUBCOMMANDS = new Set([
  'branch',
  'config',
  'diff',
  'log',
  'remote',
  'rev-parse',
  'show',
  'status',
])

const WRITE_COMMANDS = new Set([
  'chmod',
  'chown',
  'cp',
  'dd',
  'install',
  'ln',
  'mkdir',
  'mv',
  'tee',
  'touch',
  'truncate',
])

const NETWORK_COMMANDS = new Set([
  'curl',
  'fetch',
  'git',
  'npm',
  'npx',
  'pip',
  'pip3',
  'pnpm',
  'scp',
  'sftp',
  'ssh',
  'wget',
  'yarn',
])

const DYNAMIC_CODE_COMMANDS = new Set([
  '.',
  'bash',
  'eval',
  'node',
  'perl',
  'python',
  'python3',
  'ruby',
  'sh',
  'source',
  'zsh',
])

const DESTRUCTIVE_COMMANDS = new Set([
  'pkill',
  'killall',
  'rm',
  'rmdir',
  'shutdown',
  'systemctl',
])

/**
 * Small, deterministic Bash capability classifier used by permission gating.
 * It intentionally prefers "unknown" over clever shell parsing when syntax is
 * ambiguous; callers can then require approval for anything not clearly read-only.
 */
export function classifyBashCommand(command: string): BashCommandPolicy {
  const trimmed = command.trim()
  if (!trimmed) {
    return deny('unknown', 'empty command')
  }

  if (hasDynamicShellSyntax(trimmed)) {
    return deny('dynamic_code', 'command uses dynamic shell syntax that cannot be statically inspected')
  }

  if (hasWriteRedirection(trimmed)) {
    return deny('write', 'command writes through shell redirection')
  }

  const segments = splitShellSegments(trimmed)
  if (segments.length === 0) {
    return deny('unknown', 'could not identify command segments')
  }

  const capabilities = new Set<BashCommandCapability>(['read'])

  for (const segment of segments) {
    const decision = classifySegment(segment)
    for (const capability of decision.capabilities) capabilities.add(capability)
    if (!decision.readOnly) {
      return {
        readOnly: false,
        capabilities: [...capabilities].filter((capability) => capability !== 'read' || capabilities.size === 1),
        reason: decision.reason,
      }
    }
  }

  return { readOnly: true, capabilities: ['read'] }
}

export function extractBashWriteTargets(command: string): string[] {
  const targets: string[] = []
  const redirectionPattern = /(?:^|\s)(?:\d?>>?|&>|>>|>)\s*(?:"([^"]+)"|'([^']+)'|([^\s;&|]+))/g
  for (const match of command.matchAll(redirectionPattern)) {
    const target = match[1] ?? match[2] ?? match[3]
    if (!target || target.startsWith('&') || target === '/dev/null') continue
    targets.push(target)
  }

  for (const segment of splitShellSegments(command)) {
    targets.push(...extractSegmentWriteTargets(segment))
  }

  return targets
}

export function extractBashReadTargets(command: string): string[] {
  const targets: string[] = []
  for (const segment of splitShellSegments(command)) {
    targets.push(...extractSegmentReadTargets(segment))
  }
  return targets
}

function extractSegmentWriteTargets(segment: string): string[] {
  const tokens = tokenizeSegment(stripSubshell(segment))
  if (tokens.length === 0) return []

  const command = normalizeCommandName(tokens[0])
  const args = tokens.slice(1)
  switch (command) {
    case 'tee':
    case 'mkdir':
    case 'touch':
      return args.filter(isLikelyPathArg)
    case 'truncate':
      return args.filter((arg, index) => isLikelyPathArg(arg) && args[index - 1] !== '-s' && args[index - 1] !== '--size')
    case 'cp':
    case 'install':
    case 'ln':
    case 'mv':
      return lastPathArg(args)
    case 'chmod':
    case 'chown':
      return args.filter(isLikelyPathArg).slice(1)
    case 'dd':
      return args
        .filter((arg) => arg.startsWith('of='))
        .map((arg) => arg.slice('of='.length))
        .filter(Boolean)
    case 'find':
      return args.some((arg) => arg === '-delete' || arg === '-exec')
        ? findSearchRoots(args)
        : []
    default:
      return []
  }
}

function extractSegmentReadTargets(segment: string): string[] {
  const tokens = tokenizeSegment(stripSubshell(segment))
  if (tokens.length === 0) return []

  const command = normalizeCommandName(tokens[0])
  const args = tokens.slice(1)
  switch (command) {
    case 'bat':
    case 'cat':
    case 'cmp':
    case 'df':
    case 'diff':
    case 'du':
    case 'file':
    case 'head':
    case 'less':
    case 'ls':
    case 'more':
    case 'nl':
    case 'stat':
    case 'tail':
    case 'tree':
    case 'wc':
      return args.filter(isLikelyPathArg)
    case 'cp':
    case 'install':
    case 'ln':
    case 'mv':
      return allButLastPathArg(args)
    case 'dd':
      return args
        .filter((arg) => arg.startsWith('if='))
        .map((arg) => arg.slice('if='.length))
        .filter(Boolean)
    case 'find':
      return findSearchRoots(args)
    case 'grep':
    case 'egrep':
    case 'fgrep':
    case 'rg':
      return skipFirstPathArg(args)
    case 'sed':
    case 'awk':
      return skipFirstPathArg(args)
    case 'git':
      return gitWorkingDirectories(args)
    default:
      return []
  }
}

function lastPathArg(args: string[]): string[] {
  const paths = args.filter(isLikelyPathArg)
  return paths.length > 0 ? [paths[paths.length - 1]] : []
}

function allButLastPathArg(args: string[]): string[] {
  const paths = args.filter(isLikelyPathArg)
  return paths.slice(0, Math.max(0, paths.length - 1))
}

function skipFirstPathArg(args: string[]): string[] {
  const paths = args.filter(isLikelyPathArg)
  return paths.slice(1)
}

function gitWorkingDirectories(args: string[]): string[] {
  const roots: string[] = []
  for (let index = 0; index < args.length; index += 1) {
    if (args[index] === '-C' && args[index + 1]) {
      roots.push(args[index + 1])
      index += 1
    }
  }
  return roots
}

function findSearchRoots(args: string[]): string[] {
  const roots: string[] = []
  for (const arg of args) {
    if (arg.startsWith('-')) break
    roots.push(arg)
  }
  return roots.length > 0 ? roots : ['.']
}

function isLikelyPathArg(arg: string): boolean {
  return Boolean(arg)
    && !['>', '>>', '2>', '2>>', '&>'].includes(arg)
    && !arg.startsWith('-')
    && !arg.includes('=')
}

function classifySegment(segment: string): BashCommandPolicy {
  const tokens = tokenizeSegment(stripSubshell(segment))
  if (tokens.length === 0) return { readOnly: true, capabilities: ['read'] }

  const command = normalizeCommandName(tokens[0])
  if (!command) return deny('unknown', 'missing command name')

  if (DESTRUCTIVE_COMMANDS.has(command)) {
    return deny('destructive', `${command} is destructive`)
  }

  if (WRITE_COMMANDS.has(command)) {
    return deny('write', `${command} mutates files or permissions`)
  }

  if (command === 'find' && tokens.some((token) => token === '-delete' || token === '-exec')) {
    return deny('write', 'find with -delete/-exec can mutate state')
  }

  if (command === 'sed' && tokens.some((token) => token === '-i' || token.startsWith('-i'))) {
    return deny('write', 'sed -i mutates files')
  }

  if (command === 'git') {
    return classifyGit(tokens)
  }

  if (NETWORK_COMMANDS.has(command)) {
    return deny('network', `${command} may access the network`)
  }

  if (DYNAMIC_CODE_COMMANDS.has(command)) {
    return deny('dynamic_code', `${command} executes dynamic code or shell scripts`)
  }

  if (READ_ONLY_COMMANDS.has(command)) {
    return { readOnly: true, capabilities: ['read'] }
  }

  return deny('unknown', `${command} is not in the read-only Bash allowlist`)
}

function classifyGit(tokens: string[]): BashCommandPolicy {
  const subcommand = firstGitSubcommand(tokens)
  if (!subcommand) return deny('unknown', 'git subcommand is missing')
  if (READ_ONLY_GIT_SUBCOMMANDS.has(subcommand)) {
    return { readOnly: true, capabilities: ['read'] }
  }
  if (['clone', 'fetch', 'pull', 'push'].includes(subcommand)) {
    return deny('network', `git ${subcommand} may access the network`)
  }
  return deny('write', `git ${subcommand} may mutate repository state`)
}

function firstGitSubcommand(tokens: string[]): string | null {
  for (let index = 1; index < tokens.length; index += 1) {
    const token = tokens[index]
    if (token === '-C') {
      index += 1
      continue
    }
    if (token.startsWith('-')) continue
    return normalizeCommandName(token)
  }
  return null
}

function splitShellSegments(command: string): string[] {
  return command
    .split(/&&|\|\||[;\n|]/)
    .map((segment) => segment.trim())
    .filter(Boolean)
}

function stripSubshell(segment: string): string {
  let current = segment.trim()
  while (current.startsWith('(') && current.endsWith(')')) {
    current = current.slice(1, -1).trim()
  }
  return current
}

function tokenizeSegment(segment: string): string[] {
  const tokens = segment
    .match(/"[^"]*"|'[^']*'|[^\s]+/g)
    ?.map((token) => token.replace(/^['"]|['"]$/g, ''))
    .filter((token) => token.length > 0)
    ?? []

  while (tokens[0] && /^[A-Za-z_][A-Za-z0-9_]*=.*/.test(tokens[0])) {
    tokens.shift()
  }

  return tokens
}

function normalizeCommandName(command: string): string {
  const base = command.split('/').pop() ?? command
  return base.toLowerCase()
}

function hasWriteRedirection(command: string): boolean {
  return /(^|[^<>])(?:\d?>|&>|>>)/.test(command)
}

function hasDynamicShellSyntax(command: string): boolean {
  return /\$\(|`|<<|<\(/.test(command)
}

function deny(capability: BashCommandCapability, reason: string): BashCommandPolicy {
  return {
    readOnly: false,
    capabilities: [capability],
    reason,
  }
}
