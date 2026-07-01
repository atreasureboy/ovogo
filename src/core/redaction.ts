const REDACTED = '[REDACTED]'
const SENSITIVE_KEY_RE = /(^|_)(access_token|api_key|authorization|client_secret|cookie|credential|credentials|password|passwd|private_key|refresh_token|secret|token)($|_)/i
const SAFE_METRIC_KEY_RE = /(^|_)(tokens?|credentials?|secrets?|cookies?|passwords?)_(after|before|count|length|limit|max|min|size|total)$/i
const INLINE_SECRET_KEYS = [
  'secret[_-]?access[_-]?key',
  'access[_-]?key',
  'access[_-]?token',
  'api[_-]?key',
  'client[_-]?secret',
  'password',
  'private[_-]?key',
  'refresh[_-]?token',
  'secret',
  'token',
].join('|')
const SECRET_VALUE_PATTERNS: Array<[RegExp, string]> = [
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, REDACTED],
  [/\b((?:Bearer|Basic|Digest)\s+)[A-Za-z0-9._~+/=:-]+/gi, `$1${REDACTED}`],
  [/\b((?:set-cookie|cookie)\s*:\s*)[^\r\n]+/gi, `$1${REDACTED}`],
  [/\b(https?:\/\/[^:\s/@]+:)[^@\s/]+(@)/gi, `$1${REDACTED}$2`],
  [/\b(sk-[A-Za-z0-9_-]{10,})\b/g, REDACTED],
  [/\b(AKIA[0-9A-Z]{16})\b/g, REDACTED],
  [/\b(xox[baprs]-[A-Za-z0-9-]{10,})\b/gi, REDACTED],
  [/\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g, REDACTED],
  [/\b([A-Z0-9_]*(?:ACCESS_TOKEN|API_KEY|CLIENT_SECRET|PASSWORD|PASSWD|PRIVATE_KEY|REFRESH_TOKEN|SECRET_ACCESS_KEY|SECRET|TOKEN)\s*=\s*)[^\s&]+/gi, `$1${REDACTED}`],
  [new RegExp(`\\b((?:${INLINE_SECRET_KEYS})=)[^\\s&]+`, 'gi'), `$1${REDACTED}`],
  [new RegExp(`((?:"|')(?:${INLINE_SECRET_KEYS})(?:"|')\\s*:\\s*(?:"|'))[^"'\\r\\n]+((?:"|'))`, 'gi'), `$1${REDACTED}$2`],
  [new RegExp(`\\b((?:${INLINE_SECRET_KEYS})\\s*:\\s*(?:"|'))[^"'\\r\\n]+((?:"|'))`, 'gi'), `$1${REDACTED}$2`],
  [new RegExp(`\\b((?:${INLINE_SECRET_KEYS})\\s*:\\s*)[^\\s,;]+`, 'gi'), `$1${REDACTED}`],
]

export function redactRecord(detail: Record<string, unknown>): Record<string, unknown> {
  return redactValue(detail, new WeakSet(), 0) as Record<string, unknown>
}

export function redactText(value: string): string {
  let redacted = value
  for (const [pattern, replacement] of SECRET_VALUE_PATTERNS) {
    redacted = redacted.replace(pattern, replacement)
  }
  return redacted
}

function redactValue(value: unknown, seen: WeakSet<object>, depth: number): unknown {
  if (typeof value === 'string') return redactText(value)
  if (value === null || typeof value !== 'object') return value
  if (depth > 12) return '[MaxDepth]'
  if (seen.has(value)) return '[Circular]'
  seen.add(value)

  if (Array.isArray(value)) {
    return value.map((item) => redactValue(item, seen, depth + 1))
  }

  const output: Record<string, unknown> = {}
  for (const [key, entryValue] of Object.entries(value)) {
    output[key] = isSensitiveKey(key)
      ? REDACTED
      : redactValue(entryValue, seen, depth + 1)
  }
  return output
}

function isSensitiveKey(key: string): boolean {
  const normalized = key
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/[-\s]+/g, '_')
    .toLowerCase()

  if (SAFE_METRIC_KEY_RE.test(normalized)) return false
  return SENSITIVE_KEY_RE.test(normalized)
}
