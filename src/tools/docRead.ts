/**
 * DocReadTool — read PDF, Word, Excel, PowerPoint, and image files.
 *
 * Dispatch table:
 *   .pdf               → pdftotext (CLI) → pdfminer.six (Python fallback)
 *   .docx / .doc       → python-docx
 *   .xlsx / .xls       → openpyxl
 *   .pptx / .ppt       → python-pptx (text extraction per slide)
 *   .csv               → plain read with utf-8
 *   .png/.jpg/.jpeg    → OpenAI Vision API (base64 multimodal call)
 *   .gif/.webp/.bmp    → OpenAI Vision API
 *
 * Image analysis requires a vision-capable model (e.g. gpt-4o, claude-3-5-sonnet).
 * The tool reuses the engine's apiConfig from ToolContext so no extra credentials
 * are needed.
 */

import { readFile } from 'fs/promises'
import { exec } from 'child_process'
import { promisify } from 'util'
import path from 'path'
import OpenAI from 'openai'
import type { Tool, ToolContext, ToolDefinition, ToolResult } from '../core/types.js'

const execAsync = promisify(exec)

// Maximum characters returned to the LLM (prevent context overload)
const MAX_TEXT_LENGTH = 40_000

// ── Extension maps ───────────────────────────────────────────────────────────

const PDF_EXT   = new Set(['.pdf'])
const WORD_EXT  = new Set(['.docx', '.doc'])
const EXCEL_EXT = new Set(['.xlsx', '.xls'])
const PPT_EXT   = new Set(['.pptx', '.ppt'])
const CSV_EXT   = new Set(['.csv'])
const IMAGE_EXT = new Set(['.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp', '.tiff', '.tif'])

const IMAGE_MIME: Record<string, string> = {
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.webp': 'image/webp',
  '.bmp': 'image/bmp',
  '.tiff': 'image/tiff',
  '.tif': 'image/tiff',
}

// ── Python snippets ──────────────────────────────────────────────────────────

function pyDocx(filePath: string): string {
  // Escape single quotes in path
  const p = filePath.replace(/'/g, "'\\''")
  return `python3 - <<'PYEOF'
import sys
try:
    import docx
    doc = docx.Document('${p}')
    parts = []
    for para in doc.paragraphs:
        if para.text.strip():
            parts.append(para.text)
    # Also extract tables
    for table in doc.tables:
        for row in table.rows:
            parts.append('\\t'.join(cell.text.strip() for cell in row.cells))
    print('\\n'.join(parts))
except Exception as e:
    print(f'ERROR: {e}', file=sys.stderr)
    sys.exit(1)
PYEOF`
}

function pyExcel(filePath: string): string {
  const p = filePath.replace(/'/g, "'\\''")
  return `python3 - <<'PYEOF'
import sys
try:
    import openpyxl
    wb = openpyxl.load_workbook('${p}', read_only=True, data_only=True)
    parts = []
    for sheet in wb.sheetnames:
        ws = wb[sheet]
        parts.append(f'=== Sheet: {sheet} ===')
        for row in ws.iter_rows(values_only=True):
            row_str = '\\t'.join(str(c) if c is not None else '' for c in row)
            if row_str.strip():
                parts.append(row_str)
    print('\\n'.join(parts))
except Exception as e:
    print(f'ERROR: {e}', file=sys.stderr)
    sys.exit(1)
PYEOF`
}

function pyPptx(filePath: string): string {
  const p = filePath.replace(/'/g, "'\\''")
  return `python3 - <<'PYEOF'
import sys
try:
    from pptx import Presentation
    prs = Presentation('${p}')
    parts = []
    for i, slide in enumerate(prs.slides, 1):
        parts.append(f'--- Slide {i} ---')
        for shape in slide.shapes:
            if hasattr(shape, 'text') and shape.text.strip():
                parts.append(shape.text.strip())
    print('\\n'.join(parts))
except Exception as e:
    print(f'ERROR: {e}', file=sys.stderr)
    sys.exit(1)
PYEOF`
}

function pyPdfMiner(filePath: string): string {
  const p = filePath.replace(/'/g, "'\\''")
  return `python3 - <<'PYEOF'
import sys
try:
    from pdfminer.high_level import extract_text
    print(extract_text('${p}'))
except Exception as e:
    print(f'ERROR: {e}', file=sys.stderr)
    sys.exit(1)
PYEOF`
}

// ── Tool implementation ──────────────────────────────────────────────────────

export interface DocReadInput {
  file_path: string
  /** For images: natural language instruction passed to the vision model */
  prompt?: string
}

export class DocReadTool implements Tool {
  name = 'DocRead'

  definition: ToolDefinition = {
    type: 'function',
    function: {
      name: 'DocRead',
      description: `读取 PDF、Word、Excel、PowerPoint 文件内容，或对图片进行 AI 识别。

## 支持格式
| 格式 | 扩展名 | 方式 |
|------|--------|------|
| PDF | .pdf | pdftotext + pdfminer 提取文字 |
| Word | .docx .doc | python-docx 提取段落+表格 |
| Excel | .xlsx .xls | openpyxl 提取所有 Sheet |
| PPT | .pptx .ppt | python-pptx 提取每页文字 |
| CSV | .csv | 直接读取文本 |
| 图片 | .png .jpg .jpeg .gif .webp .bmp | Vision API 识别（OCR+内容理解） |

## 使用场景（渗透测试）
- 读取目标上传的 PDF 报告/合同提取敏感信息
- 分析截图/扫描图片中的配置、凭证、代码
- 读取 Office 文件中隐藏的宏代码路径、内网地址
- OCR 识别验证码图片（配合 prompt 参数）`,
      parameters: {
        type: 'object',
        properties: {
          file_path: {
            type: 'string',
            description: '文件绝对路径',
          },
          prompt: {
            type: 'string',
            description: '仅图片有效：传给 Vision API 的指令（默认：提取所有文字和关键信息）',
          },
        },
        required: ['file_path'],
      },
    },
  }

  async execute(input: Record<string, unknown>, context: ToolContext): Promise<ToolResult> {
    const { file_path, prompt } = input as unknown as DocReadInput

    if (!file_path || typeof file_path !== 'string') {
      return { content: 'Error: file_path is required', isError: true }
    }

    const ext = path.extname(file_path).toLowerCase()

    if (IMAGE_EXT.has(ext)) {
      return this.analyzeImage(file_path, ext, prompt, context)
    }
    if (PDF_EXT.has(ext))   return this.extractPdf(file_path)
    if (WORD_EXT.has(ext))  return this.extractWord(file_path)
    if (EXCEL_EXT.has(ext)) return this.extractExcel(file_path)
    if (PPT_EXT.has(ext))   return this.extractPptx(file_path)
    if (CSV_EXT.has(ext))   return this.extractCsv(file_path)

    return {
      content: `DocRead: unsupported extension "${ext}". Supported: pdf, docx, doc, xlsx, xls, pptx, ppt, csv, png, jpg, jpeg, gif, webp, bmp`,
      isError: true,
    }
  }

  // ── PDF ─────────────────────────────────────────────────────────────────

  private async extractPdf(filePath: string): Promise<ToolResult> {
    // Primary: pdftotext (poppler-utils, fast, preserves layout)
    try {
      const { stdout } = await execAsync(`pdftotext -layout "${filePath}" -`, { timeout: 60_000 })
      if (stdout.trim()) {
        return { content: this.truncate(stdout, filePath, 'pdftotext'), isError: false }
      }
    } catch {
      // fall through to Python
    }

    // Fallback: pdfminer.six
    try {
      const { stdout, stderr } = await execAsync(pyPdfMiner(filePath), { timeout: 120_000 })
      if (stderr?.startsWith('ERROR')) {
        return { content: `PDF extraction failed: ${stderr}`, isError: true }
      }
      return { content: this.truncate(stdout, filePath, 'pdfminer'), isError: false }
    } catch (err) {
      return { content: `PDF extraction failed: ${(err as Error).message}`, isError: true }
    }
  }

  // ── Word ─────────────────────────────────────────────────────────────────

  private async extractWord(filePath: string): Promise<ToolResult> {
    try {
      const { stdout, stderr } = await execAsync(pyDocx(filePath), { timeout: 60_000 })
      if (stderr?.startsWith('ERROR')) {
        return { content: `Word extraction failed: ${stderr}`, isError: true }
      }
      return { content: this.truncate(stdout, filePath, 'python-docx'), isError: false }
    } catch (err) {
      return { content: `Word extraction failed: ${(err as Error).message}`, isError: true }
    }
  }

  // ── Excel ────────────────────────────────────────────────────────────────

  private async extractExcel(filePath: string): Promise<ToolResult> {
    try {
      const { stdout, stderr } = await execAsync(pyExcel(filePath), { timeout: 60_000 })
      if (stderr?.startsWith('ERROR')) {
        return { content: `Excel extraction failed: ${stderr}`, isError: true }
      }
      return { content: this.truncate(stdout, filePath, 'openpyxl'), isError: false }
    } catch (err) {
      return { content: `Excel extraction failed: ${(err as Error).message}`, isError: true }
    }
  }

  // ── PowerPoint ───────────────────────────────────────────────────────────

  private async extractPptx(filePath: string): Promise<ToolResult> {
    try {
      const { stdout, stderr } = await execAsync(pyPptx(filePath), { timeout: 60_000 })
      if (stderr?.startsWith('ERROR')) {
        return { content: `PPT extraction failed: ${stderr}`, isError: true }
      }
      return { content: this.truncate(stdout, filePath, 'python-pptx'), isError: false }
    } catch (err) {
      return { content: `PPT extraction failed: ${(err as Error).message}`, isError: true }
    }
  }

  // ── CSV ──────────────────────────────────────────────────────────────────

  private async extractCsv(filePath: string): Promise<ToolResult> {
    try {
      const raw = await readFile(filePath, 'utf8')
      return { content: this.truncate(raw, filePath, 'csv'), isError: false }
    } catch (err) {
      return { content: `CSV read failed: ${(err as Error).message}`, isError: true }
    }
  }

  // ── Image (Vision API) ───────────────────────────────────────────────────

  private async analyzeImage(
    filePath: string,
    ext: string,
    userPrompt: string | undefined,
    context: ToolContext,
  ): Promise<ToolResult> {
    if (!context.apiConfig) {
      return {
        content: 'DocRead image analysis requires apiConfig in ToolContext (engine not initialised properly)',
        isError: true,
      }
    }

    const { apiKey, baseURL, model } = context.apiConfig

    let imageData: Buffer
    try {
      imageData = await readFile(filePath)
    } catch (err) {
      return { content: `Cannot read image file: ${(err as Error).message}`, isError: true }
    }

    const base64 = imageData.toString('base64')
    const mimeType = IMAGE_MIME[ext] ?? 'image/jpeg'
    const visionPrompt = userPrompt ??
      '请详细描述这张图片的内容。提取所有可见的文字（OCR）、数字、表格、配置项、凭证、IP地址、代码片段等关键信息，以结构化方式输出。'

    try {
      const client = new OpenAI({ apiKey, baseURL })
      const response = await client.chat.completions.create({
        model,
        messages: [
          {
            role: 'user',
            content: [
              { type: 'text', text: visionPrompt },
              {
                type: 'image_url',
                image_url: { url: `data:${mimeType};base64,${base64}`, detail: 'high' },
              },
            ],
          },
        ],
        max_tokens: 4096,
      })

      const result = response.choices[0]?.message?.content ?? ''
      return {
        content: `[DocRead: image analysis — ${path.basename(filePath)}]\n\n${result}`,
        isError: false,
      }
    } catch (err) {
      const msg = (err as Error).message
      // Vision not supported by this model/endpoint
      if (msg.includes('vision') || msg.includes('image') || msg.includes('multimodal')) {
        return {
          content: `Image analysis failed: model "${model}" may not support vision. Error: ${msg}`,
          isError: true,
        }
      }
      return { content: `Image analysis failed: ${msg}`, isError: true }
    }
  }

  // ── Helpers ──────────────────────────────────────────────────────────────

  private truncate(text: string, filePath: string, method: string): string {
    const header = `[DocRead: ${path.basename(filePath)} via ${method}]\n\n`
    const body = text.trim()
    if (body.length <= MAX_TEXT_LENGTH) return header + body
    const half = MAX_TEXT_LENGTH / 2
    return (
      header +
      body.slice(0, half) +
      `\n\n[... ${body.length - MAX_TEXT_LENGTH} chars truncated — use offset/limit with Read for full content ...]\n\n` +
      body.slice(body.length - half)
    )
  }
}
