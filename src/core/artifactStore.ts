import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs'
import { join } from 'path'
import { createHash } from 'crypto'
import { redactRecord, redactText } from './redaction.js'

export interface ArtifactRecord {
  path: string
  bytes: number
  sha256: string
  createdAt: string
  prefix: string
}

export class ArtifactStore {
  private readonly dir: string
  private readonly manifestPath: string
  private counter = 0

  constructor(sessionDir: string) {
    this.dir = join(sessionDir, 'artifacts')
    this.manifestPath = join(this.dir, 'manifest.ndjson')
    try { mkdirSync(this.dir, { recursive: true }) } catch { /* best-effort */ }
  }

  writeText(prefix: string, content: string): ArtifactRecord | null {
    const safePrefix = redactText(prefix).replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 40) || 'artifact'
    this.counter += 1
    const path = join(this.dir, `${Date.now()}_${this.counter}_${safePrefix}.txt`)
    const safeContent = redactText(content)
    try {
      writeFileSync(path, safeContent, 'utf8')
      const record = {
        path,
        bytes: Buffer.byteLength(safeContent, 'utf8'),
        sha256: createHash('sha256').update(safeContent).digest('hex'),
        createdAt: new Date().toISOString(),
        prefix: safePrefix,
      }
      this.appendManifest(record)
      return record
    } catch {
      return null
    }
  }

  getManifestPath(): string {
    return this.manifestPath
  }

  readManifest(): ArtifactRecord[] {
    return this.readManifestWithDiagnostics().entries
  }

  readManifestWithDiagnostics(): { entries: ArtifactRecord[]; invalidLines: number } {
    if (!existsSync(this.manifestPath)) return { entries: [], invalidLines: 0 }
    try {
      const lines = readFileSync(this.manifestPath, 'utf8').trim().split('\n').filter(Boolean)
      const entries: ArtifactRecord[] = []
      let invalidLines = 0
      for (const line of lines) {
        try {
          entries.push(redactRecord(JSON.parse(line) as Record<string, unknown>) as unknown as ArtifactRecord)
        } catch {
          invalidLines += 1
        }
      }
      return { entries, invalidLines }
    } catch {
      return { entries: [], invalidLines: 0 }
    }
  }

  private appendManifest(record: ArtifactRecord): void {
    try {
      appendFileSync(this.manifestPath, JSON.stringify(redactRecord({ ...record })) + '\n', 'utf8')
    } catch {
      // Artifact content has already been persisted; manifest indexing is best-effort.
    }
  }
}
