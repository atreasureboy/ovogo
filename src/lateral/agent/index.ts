import Anthropic from '@anthropic-ai/sdk';
import { ToolResult } from '../../core/types';
import {
  discoverInternalHosts,
  scanHostPorts,
  collectSSHKeys,
  harvestCredentials,
  collectKerberosTickets
} from '../tools';
import {
  comprehensiveInternalRecon,
  collectAndOrganizeCredentials,
  batchSSHLateralMovement,
  batchWindowsLateralMovement,
  intelligentCredentialReuse,
  establishPersistentLateralChannel
} from '../skills';

/**
 * 横向移动拓扑图
 */
interface LateralGraph {
  sourceShellId: string;

  // 内网拓扑
  internalNetwork: {
    subnet: string;
    hosts: Array<{
      ip: string;
      hostname?: string;
      os?: string;
      openPorts: Array<{ port: number; service: string; version?: string }>;
      compromised: boolean;
      shellId?: string;
    }>;
  };

  // 凭据库
  credentialVault: {
    sshKeys: Array<{ user: string; keyPath: string; keyType: string }>;
    passwords: Array<{ username: string; password: string; source: string }>;
    hashes: Array<{ username: string; hash: string; hashType: string }>;
    tickets: Array<{ user: string; ticketPath: string }>;
    validCredentials: Array<{ targetIp: string; username: string; password: string; service: string }>;
  };

  // 横向移动路径
  lateralPaths: Array<{
    fromIp: string;
    toIp: string;
    method: string;
    username: string;
    timestamp: Date;
    shellId: string;
  }>;

  // 已攻陷主机
  compromisedHosts: Array<{
    ip: string;
    hostname?: string;
    username: string;
    method: string;
    shellId: string;
    timestamp: Date;
  }>;
}

/**
 * Lateral Agent - 横向移动智能体
 *
 * 职责：
 * 1. 全面侦察内网拓扑和存活主机
 * 2. 收集并整理所有可用凭据
 * 3. 智能选择横向移动目标和方法
 * 4. 批量尝试凭据复用和横向移动
 * 5. 建立持久化横向通道
 * 6. 维护横向移动拓扑图
 */
export class LateralAgent {
  private client: Anthropic;
  private graph: LateralGraph;
  private conversationHistory: Array<{ role: 'user' | 'assistant'; content: string }> = [];

  constructor(
    private shellId: string,
    private sessionDir: string,
    private subnet?: string,
    apiKey?: string
  ) {
    this.client = new Anthropic({
      apiKey: apiKey || process.env.ANTHROPIC_API_KEY
    });

    this.graph = {
      sourceShellId: shellId,
      internalNetwork: {
        subnet: subnet || '192.168.1.0/24',
        hosts: []
      },
      credentialVault: {
        sshKeys: [],
        passwords: [],
        hashes: [],
        tickets: [],
        validCredentials: []
      },
      lateralPaths: [],
      compromisedHosts: []
    };
  }

  /**
   * 系统提示词 - 定义 Agent 的角色和能力
   */
  private getSystemPrompt(): string {
    return `你是一个专业的横向移动智能体（Lateral Movement Agent），负责在内网中进行横向渗透和扩展立足点。

你的核心能力：
1. **内网侦察** - 发现存活主机、开放端口、运行服务
2. **凭据收集** - 收集SSH密钥、明文密码、哈希、Kerberos票据
3. **智能决策** - 根据目标特征选择最佳横向移动方法
4. **批量攻击** - 并行尝试多个目标和凭据组合
5. **持久化** - 建立稳定的横向移动通道

可用的技能（Skills）：
- comprehensiveInternalRecon: 全面内网侦察（主机发现→端口扫描→服务枚举）
- collectAndOrganizeCredentials: 凭据收集与整理（SSH密钥+密码+哈希+票据）
- batchSSHLateralMovement: SSH横向移动批量尝试
- batchWindowsLateralMovement: Windows横向移动批量尝试（SMB/WinRM/RDP）
- intelligentCredentialReuse: 智能凭据复用（凭据喷洒）
- establishPersistentLateralChannel: 建立持久化横向通道

决策原则：
1. **先侦察后行动** - 始终先全面侦察内网，再选择目标
2. **凭据优先** - 优先使用已知凭据，再尝试凭据喷洒
3. **批量并行** - 同时攻击多个目标以提高效率
4. **Linux优先** - SSH横向移动成功率高于Windows方法
5. **建立持久化** - 每个成功的主机都应建立持久化通道

当前状态：
- 源Shell: ${this.graph.sourceShellId}
- 内网子网: ${this.graph.internalNetwork.subnet}
- 已发现主机: ${this.graph.internalNetwork.hosts.length}
- 已攻陷主机: ${this.graph.compromisedHosts.length}
- 凭据库: ${this.graph.credentialVault.sshKeys.length} 密钥, ${this.graph.credentialVault.passwords.length} 密码

请根据当前状态和可用技能，制定下一步横向移动计划。`;
  }

  /**
   * LLM 驱动的决策引擎
   */
  private async makeDecision(): Promise<string> {
    this.conversationHistory.push({
      role: 'user',
      content: `当前横向移动状态：
- 已发现主机: ${this.graph.internalNetwork.hosts.length}
- 已攻陷主机: ${this.graph.compromisedHosts.length}
- 可用凭据: ${this.graph.credentialVault.sshKeys.length} SSH密钥, ${this.graph.credentialVault.passwords.length} 密码
- 横向移动路径: ${this.graph.lateralPaths.length}

未攻陷的目标主机:
${this.graph.internalNetwork.hosts
  .filter(h => !h.compromised)
  .slice(0, 5)
  .map(h => `- ${h.ip} (${h.openPorts.length} 个开放端口)`)
  .join('\n')}

请决定下一步行动。可选操作：
1. recon_network - 侦察内网拓扑
2. collect_credentials - 收集凭据
3. ssh_lateral - SSH横向移动
4. windows_lateral - Windows横向移动
5. credential_spray - 凭据喷洒
6. establish_persistence - 建立持久化
7. complete - 横向移动完成

请只返回操作名称，不要有其他内容。`
    });

    try {
      const response = await this.client.messages.create({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 500,
        system: this.getSystemPrompt(),
        messages: this.conversationHistory
      });

      const decision = response.content[0].type === 'text'
        ? response.content[0].text.trim().toLowerCase()
        : 'recon_network';

      this.conversationHistory.push({
        role: 'assistant',
        content: decision
      });

      return decision;
    } catch (error) {
      console.error('LLM decision failed:', error);
      return this.fallbackDecision();
    }
  }

  /**
   * 降级决策逻辑（当 LLM 失败时）
   */
  private fallbackDecision(): string {
    // 如果还没侦察内网，先侦察
    if (this.graph.internalNetwork.hosts.length === 0) {
      return 'recon_network';
    }

    // 如果还没收集凭据，先收集
    const totalCredentials = this.graph.credentialVault.sshKeys.length +
      this.graph.credentialVault.passwords.length;
    if (totalCredentials === 0) {
      return 'collect_credentials';
    }

    // 如果有未攻陷的Linux主机（22端口开放），尝试SSH横向移动
    const linuxTargets = this.graph.internalNetwork.hosts.filter(
      h => !h.compromised && h.openPorts.some(p => p.port === 22)
    );
    if (linuxTargets.length > 0) {
      return 'ssh_lateral';
    }

    // 如果有未攻陷的Windows主机（445/3389/5985端口开放），尝试Windows横向移动
    const windowsTargets = this.graph.internalNetwork.hosts.filter(
      h => !h.compromised && h.openPorts.some(p => [445, 3389, 5985, 5986].includes(p.port))
    );
    if (windowsTargets.length > 0) {
      return 'windows_lateral';
    }

    // 如果还有未攻陷的主机，尝试凭据喷洒
    const uncompromisedHosts = this.graph.internalNetwork.hosts.filter(h => !h.compromised);
    if (uncompromisedHosts.length > 0) {
      return 'credential_spray';
    }

    // 所有主机都已尝试，完成任务
    return 'complete';
  }

  /**
   * 执行内网侦察
   */
  private async executeReconNetwork(): Promise<void> {
    console.log('[LateralAgent] 开始内网侦察...');

    const result = await comprehensiveInternalRecon(
      this.graph.sourceShellId,
      this.sessionDir,
      this.subnet
    );

    if (result.success && result.data) {
      // 更新内网拓扑图
      this.graph.internalNetwork.hosts = result.data.hosts.map(h => ({
        ...h,
        compromised: false
      }));

      console.log(`[LateralAgent] 侦察完成: ${result.data.totalHosts} 个主机, ${result.data.totalOpenPorts} 个开放端口`);
    } else {
      console.error('[LateralAgent] 内网侦察失败:', result.error);
    }
  }

  /**
   * 执行凭据收集
   */
  private async executeCollectCredentials(): Promise<void> {
    console.log('[LateralAgent] 开始凭据收集...');

    const result = await collectAndOrganizeCredentials(
      this.graph.sourceShellId,
      this.sessionDir
    );

    if (result.success && result.data) {
      // 更新凭据库
      this.graph.credentialVault.sshKeys = result.data.sshKeys;
      this.graph.credentialVault.passwords = result.data.passwords;
      this.graph.credentialVault.hashes = result.data.hashes;
      this.graph.credentialVault.tickets = result.data.tickets;

      console.log(`[LateralAgent] 凭据收集完成: ${result.data.totalCredentials} 个凭据`);
    } else {
      console.error('[LateralAgent] 凭据收集失败:', result.error);
    }
  }

  /**
   * 执行SSH横向移动
   */
  private async executeSSHLateral(): Promise<void> {
    console.log('[LateralAgent] 开始SSH横向移动...');

    // 筛选Linux目标（22端口开放且未攻陷）
    const targets = this.graph.internalNetwork.hosts
      .filter(h => !h.compromised && h.openPorts.some(p => p.port === 22))
      .map(h => ({ ip: h.ip, port: 22 }));

    if (targets.length === 0) {
      console.log('[LateralAgent] 没有可用的SSH目标');
      return;
    }

    const result = await batchSSHLateralMovement(
      this.graph.sourceShellId,
      this.sessionDir,
      targets,
      {
        sshKeys: this.graph.credentialVault.sshKeys,
        passwords: this.graph.credentialVault.passwords
      }
    );

    if (result.success && result.data) {
      // 更新攻陷主机列表
      for (const success of result.data.successful) {
        const host = this.graph.internalNetwork.hosts.find(h => h.ip === success.targetIp);
        if (host) {
          host.compromised = true;
          host.shellId = success.shellId;
        }

        this.graph.compromisedHosts.push({
          ip: success.targetIp,
          username: success.username,
          method: success.method,
          shellId: success.shellId,
          timestamp: new Date()
        });

        this.graph.lateralPaths.push({
          fromIp: 'source',
          toIp: success.targetIp,
          method: success.method,
          username: success.username,
          timestamp: new Date(),
          shellId: success.shellId
        });
      }

      console.log(`[LateralAgent] SSH横向移动完成: ${result.data.successful.length}/${targets.length} 成功`);
    } else {
      console.error('[LateralAgent] SSH横向移动失败:', result.error);
    }
  }

  /**
   * 执行Windows横向移动
   */
  private async executeWindowsLateral(): Promise<void> {
    console.log('[LateralAgent] 开始Windows横向移动...');

    // 筛选Windows目标（445/3389/5985端口开放且未攻陷）
    const targets = this.graph.internalNetwork.hosts
      .filter(h => !h.compromised && h.openPorts.some(p => [445, 3389, 5985, 5986].includes(p.port)))
      .map(h => ({
        ip: h.ip,
        openPorts: h.openPorts.map(p => p.port)
      }));

    if (targets.length === 0) {
      console.log('[LateralAgent] 没有可用的Windows目标');
      return;
    }

    const result = await batchWindowsLateralMovement(
      this.graph.sourceShellId,
      this.sessionDir,
      targets,
      this.graph.credentialVault.passwords
    );

    if (result.success && result.data) {
      // 更新攻陷主机列表
      for (const success of result.data.successful) {
        const host = this.graph.internalNetwork.hosts.find(h => h.ip === success.targetIp);
        if (host) {
          host.compromised = true;
          host.shellId = success.shellId;
        }

        this.graph.compromisedHosts.push({
          ip: success.targetIp,
          username: success.username,
          method: success.method,
          shellId: success.shellId,
          timestamp: new Date()
        });

        this.graph.lateralPaths.push({
          fromIp: 'source',
          toIp: success.targetIp,
          method: success.method,
          username: success.username,
          timestamp: new Date(),
          shellId: success.shellId
        });
      }

      console.log(`[LateralAgent] Windows横向移动完成: ${result.data.successful.length}/${targets.length} 成功`);
    } else {
      console.error('[LateralAgent] Windows横向移动失败:', result.error);
    }
  }

  /**
   * 执行凭据喷洒
   */
  private async executeCredentialSpray(): Promise<void> {
    console.log('[LateralAgent] 开始凭据喷洒...');

    // 筛选未攻陷的目标
    const targets = this.graph.internalNetwork.hosts
      .filter(h => !h.compromised)
      .map(h => ({
        ip: h.ip,
        openPorts: h.openPorts.map(p => p.port)
      }));

    if (targets.length === 0) {
      console.log('[LateralAgent] 没有可用的目标');
      return;
    }

    const result = await intelligentCredentialReuse(
      this.graph.sourceShellId,
      this.sessionDir,
      targets,
      this.graph.credentialVault.passwords
    );

    if (result.success && result.data) {
      // 更新有效凭据库
      this.graph.credentialVault.validCredentials.push(...result.data.validCredentials);

      console.log(`[LateralAgent] 凭据喷洒完成: 发现 ${result.data.validCredentials.length} 个有效凭据`);
    } else {
      console.error('[LateralAgent] 凭据喷洒失败:', result.error);
    }
  }

  /**
   * 建立持久化
   */
  private async executeEstablishPersistence(): Promise<void> {
    console.log('[LateralAgent] 建立持久化通道...');

    // 对所有已攻陷主机建立持久化
    for (const host of this.graph.compromisedHosts) {
      if (host.shellId) {
        const result = await establishPersistentLateralChannel(
          this.graph.sourceShellId,
          this.sessionDir,
          host.shellId,
          host.ip
        );

        if (result.success) {
          console.log(`[LateralAgent] ✓ 持久化通道建立成功: ${host.ip}`);
        }
      }
    }
  }

  /**
   * 生成横向移动报告
   */
  private generateReport(): any {
    return {
      summary: {
        sourceShell: this.graph.sourceShellId,
        subnet: this.graph.internalNetwork.subnet,
        totalHosts: this.graph.internalNetwork.hosts.length,
        compromisedHosts: this.graph.compromisedHosts.length,
        compromiseRate: this.graph.internalNetwork.hosts.length > 0
          ? (this.graph.compromisedHosts.length / this.graph.internalNetwork.hosts.length * 100).toFixed(1) + '%'
          : '0%',
        lateralPaths: this.graph.lateralPaths.length
      },
      internalNetwork: {
        hosts: this.graph.internalNetwork.hosts.map(h => ({
          ip: h.ip,
          hostname: h.hostname,
          openPorts: h.openPorts.length,
          compromised: h.compromised,
          shellId: h.shellId
        }))
      },
      credentialVault: {
        sshKeys: this.graph.credentialVault.sshKeys.length,
        passwords: this.graph.credentialVault.passwords.length,
        hashes: this.graph.credentialVault.hashes.length,
        tickets: this.graph.credentialVault.tickets.length,
        validCredentials: this.graph.credentialVault.validCredentials.length
      },
      compromisedHosts: this.graph.compromisedHosts.map(h => ({
        ip: h.ip,
        hostname: h.hostname,
        username: h.username,
        method: h.method,
        shellId: h.shellId,
        timestamp: h.timestamp.toISOString()
      })),
      lateralPaths: this.graph.lateralPaths.map(p => ({
        from: p.fromIp,
        to: p.toIp,
        method: p.method,
        username: p.username,
        timestamp: p.timestamp.toISOString()
      })),
      recommendations: this.generateRecommendations()
    };
  }

  /**
   * 生成横向移动建议
   */
  private generateRecommendations(): string[] {
    const recommendations: string[] = [];

    const compromiseRate = this.graph.internalNetwork.hosts.length > 0
      ? (this.graph.compromisedHosts.length / this.graph.internalNetwork.hosts.length) * 100
      : 0;

    if (compromiseRate >= 80) {
      recommendations.push(`✓ 横向移动成功率高 (${compromiseRate.toFixed(1)}%)，已控制大部分内网主机`);
    } else if (compromiseRate >= 50) {
      recommendations.push(`横向移动成功率中等 (${compromiseRate.toFixed(1)}%)，建议继续扩展`);
    } else {
      recommendations.push(`横向移动成功率较低 (${compromiseRate.toFixed(1)}%)，建议收集更多凭据`);
    }

    const uncompromisedHosts = this.graph.internalNetwork.hosts.filter(h => !h.compromised);
    if (uncompromisedHosts.length > 0) {
      recommendations.push(`还有 ${uncompromisedHosts.length} 个主机未攻陷`);

      const linuxTargets = uncompromisedHosts.filter(h => h.openPorts.some(p => p.port === 22));
      if (linuxTargets.length > 0) {
        recommendations.push(`建议: 继续尝试SSH横向移动 (${linuxTargets.length} 个Linux目标)`);
      }

      const windowsTargets = uncompromisedHosts.filter(h =>
        h.openPorts.some(p => [445, 3389, 5985].includes(p.port))
      );
      if (windowsTargets.length > 0) {
        recommendations.push(`建议: 继续尝试Windows横向移动 (${windowsTargets.length} 个Windows目标)`);
      }
    }

    if (this.graph.credentialVault.validCredentials.length > 0) {
      recommendations.push(`发现 ${this.graph.credentialVault.validCredentials.length} 个有效凭据，可用于进一步横向移动`);
    }

    return recommendations;
  }

  /**
   * 主执行循环
   */
  async run(): Promise<ToolResult<any>> {
    console.log('[LateralAgent] 启动横向移动智能体...');
    console.log(`[LateralAgent] 源Shell: ${this.graph.sourceShellId}`);
    console.log(`[LateralAgent] 目标子网: ${this.graph.internalNetwork.subnet}`);

    let maxIterations = 15;
    let iteration = 0;

    while (iteration < maxIterations) {
      iteration++;
      console.log(`\n[LateralAgent] === 迭代 ${iteration}/${maxIterations} ===`);

      // LLM 决策
      const decision = await this.makeDecision();
      console.log(`[LateralAgent] 决策: ${decision}`);

      // 执行决策
      switch (decision) {
        case 'recon_network':
          await this.executeReconNetwork();
          break;

        case 'collect_credentials':
          await this.executeCollectCredentials();
          break;

        case 'ssh_lateral':
          await this.executeSSHLateral();
          break;

        case 'windows_lateral':
          await this.executeWindowsLateral();
          break;

        case 'credential_spray':
          await this.executeCredentialSpray();
          break;

        case 'establish_persistence':
          await this.executeEstablishPersistence();
          break;

        case 'complete':
          console.log('[LateralAgent] 任务完成，生成报告...');
          maxIterations = 0; // 退出循环
          break;

        default:
          console.log(`[LateralAgent] 未知决策: ${decision}，使用降级逻辑`);
          const fallback = this.fallbackDecision();
          if (fallback === 'complete') {
            maxIterations = 0;
          }
      }

      // 如果所有主机都已尝试，提前退出
      const uncompromisedHosts = this.graph.internalNetwork.hosts.filter(h => !h.compromised);
      if (this.graph.internalNetwork.hosts.length > 0 && uncompromisedHosts.length === 0) {
        console.log('[LateralAgent] 所有主机已尝试，提前结束');
        break;
      }
    }

    // 生成最终报告
    const report = this.generateReport();

    console.log('\n[LateralAgent] ========== 横向移动报告 ==========');
    console.log(`内网子网: ${report.summary.subnet}`);
    console.log(`发现主机: ${report.summary.totalHosts}`);
    console.log(`攻陷主机: ${report.summary.compromisedHosts} (${report.summary.compromiseRate})`);
    console.log(`横向路径: ${report.summary.lateralPaths}`);
    console.log('\n凭据库:');
    console.log(`  - SSH密钥: ${report.credentialVault.sshKeys}`);
    console.log(`  - 明文密码: ${report.credentialVault.passwords}`);
    console.log(`  - 密码哈希: ${report.credentialVault.hashes}`);
    console.log(`  - 有效凭据: ${report.credentialVault.validCredentials}`);
    console.log('\n攻陷主机列表:');
    report.compromisedHosts.forEach((h: any) => {
      console.log(`  - ${h.ip} (${h.username}@${h.method})`);
    });
    console.log('\n建议:');
    report.recommendations.forEach((rec: string) => console.log(`  ${rec}`));
    console.log('==========================================\n');

    return {
      success: true,
      data: report,
      message: `横向移动完成: 攻陷 ${report.summary.compromisedHosts}/${report.summary.totalHosts} 主机`
    };
  }
}

/**
 * 导出便捷函数
 */
export async function runLateralAgent(
  shellId: string,
  sessionDir: string,
  subnet?: string,
  apiKey?: string
): Promise<ToolResult<any>> {
  const agent = new LateralAgent(shellId, sessionDir, subnet, apiKey);
  return agent.run();
}
