import Anthropic from '@anthropic-ai/sdk';
import { ToolResult } from '../../core/types';
import {
  enumerateSUIDBinaries,
  checkSudoPrivileges,
  matchKernelExploits,
  enumerateCronJobs,
  enumerateCapabilities,
  detectDockerEscape,
  detectEnvHijack,
  checkWritableSystemPaths
} from '../tools';
import {
  enumerateAllPrivescVectors,
  attemptAutoPrivesc,
  executeKernelExploit,
  executeDockerEscape
} from '../skills';

/**
 * 权限提升状态图
 */
interface PrivescGraph {
  shellId: string;
  currentUser: string;
  isRoot: boolean;

  // 权限提升向量
  vectors: {
    suid: Array<{ binary: string; exploitable: boolean; method?: string }>;
    sudo: Array<{ command: string; nopasswd: boolean; exploit?: string }>;
    kernel: Array<{ name: string; cve: string; risk: string }>;
    cron: Array<{ job: string; writable: boolean; path?: string }>;
    capabilities: Array<{ binary: string; caps: string[]; exploit?: string }>;
    docker: Array<{ type: string; method: string }>;
    env: Array<{ type: string; variable: string; exploit: string }>;
    writable: Array<{ path: string; risk: string }>;
  };

  // 尝试记录
  attempts: Array<{
    method: string;
    vector: string;
    timestamp: Date;
    success: boolean;
    error?: string;
  }>;

  // 成功的提权方法
  successfulMethod?: {
    type: string;
    vector: string;
    command: string;
    timestamp: Date;
  };
}

/**
 * Privesc Agent - 权限提升智能体
 *
 * 职责：
 * 1. 枚举所有可能的权限提升向量
 * 2. 智能选择最佳提权路径
 * 3. 从低风险到高风险自动尝试提权
 * 4. 验证提权成功并维护root shell
 * 5. 生成详细的提权报告
 */
export class PrivescAgent {
  private client: Anthropic;
  private graph: PrivescGraph;
  private conversationHistory: Array<{ role: 'user' | 'assistant'; content: string }> = [];

  constructor(
    private shellId: string,
    private sessionDir: string,
    apiKey?: string
  ) {
    this.client = new Anthropic({
      apiKey: apiKey || process.env.ANTHROPIC_API_KEY
    });

    this.graph = {
      shellId,
      currentUser: 'unknown',
      isRoot: false,
      vectors: {
        suid: [],
        sudo: [],
        kernel: [],
        cron: [],
        capabilities: [],
        docker: [],
        env: [],
        writable: []
      },
      attempts: []
    };
  }

  /**
   * 系统提示词 - 定义 Agent 的角色和能力
   */
  private getSystemPrompt(): string {
    return `你是一个专业的权限提升智能体（Privilege Escalation Agent），负责在已获得的shell上进行权限提升。

你的核心能力：
1. **全面枚举** - 识别所有可能的提权向量（SUID、sudo、内核漏洞、cron、capabilities、Docker逃逸、环境变量劫持等）
2. **智能决策** - 根据目标环境特征选择最佳提权路径
3. **风险控制** - 从低风险方法开始，逐步尝试高风险方法
4. **自动化执行** - 自动下载、编译、执行exploit
5. **持久化验证** - 确保提权成功并维护root访问

可用的技能（Skills）：
- enumerateAllPrivescVectors: 并行枚举所有提权向量，返回优先级排序的建议
- attemptAutoPrivesc: 自动尝试提权（从低风险到高风险）
- executeKernelExploit: 执行内核漏洞利用（下载→编译→执行→验证）
- executeDockerEscape: 执行Docker容器逃逸

决策原则：
1. **先枚举后行动** - 始终先全面枚举所有向量，再选择最佳路径
2. **优先低风险** - sudo NOPASSWD > SUID > capabilities > cron > 环境变量 > 内核漏洞
3. **避免系统崩溃** - 内核漏洞利用风险高，仅在其他方法失败后使用
4. **验证每次尝试** - 每次提权尝试后立即验证是否获得root
5. **记录所有操作** - 详细记录每次尝试的方法、结果和错误

当前状态：
- Shell ID: ${this.graph.shellId}
- 当前用户: ${this.graph.currentUser}
- Root权限: ${this.graph.isRoot ? '已获得' : '未获得'}
- 已尝试方法: ${this.graph.attempts.length}

请根据当前状态和可用技能，制定下一步行动计划。`;
  }

  /**
   * LLM 驱动的决策引擎
   */
  private async makeDecision(): Promise<string> {
    this.conversationHistory.push({
      role: 'user',
      content: `当前权限提升状态：
- 是否已获得root: ${this.graph.isRoot}
- 已发现的提权向量: ${JSON.stringify(this.graph.vectors, null, 2)}
- 已尝试的方法: ${this.graph.attempts.map(a => `${a.method}(${a.success ? '成功' : '失败'})`).join(', ')}

请决定下一步行动。可选操作：
1. enumerate_vectors - 枚举所有提权向量
2. auto_privesc - 自动尝试提权
3. kernel_exploit - 执行内核漏洞利用
4. docker_escape - 执行Docker逃逸
5. complete - 提权完成，生成报告

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
        : 'enumerate_vectors';

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
    // 如果已经是root，完成任务
    if (this.graph.isRoot) {
      return 'complete';
    }

    // 如果还没枚举向量，先枚举
    const totalVectors = Object.values(this.graph.vectors).reduce((sum, v) => sum + v.length, 0);
    if (totalVectors === 0) {
      return 'enumerate_vectors';
    }

    // 如果枚举了向量但还没尝试自动提权，尝试自动提权
    const autoPrivescAttempted = this.graph.attempts.some(a => a.method === 'auto_privesc');
    if (!autoPrivescAttempted) {
      return 'auto_privesc';
    }

    // 如果有内核漏洞且还没尝试，尝试内核利用
    if (this.graph.vectors.kernel.length > 0) {
      const kernelAttempted = this.graph.attempts.some(a => a.method === 'kernel_exploit');
      if (!kernelAttempted) {
        return 'kernel_exploit';
      }
    }

    // 如果有Docker环境且还没尝试，尝试Docker逃逸
    if (this.graph.vectors.docker.length > 0) {
      const dockerAttempted = this.graph.attempts.some(a => a.method === 'docker_escape');
      if (!dockerAttempted) {
        return 'docker_escape';
      }
    }

    // 所有方法都尝试过了，完成任务
    return 'complete';
  }

  /**
   * 执行枚举所有提权向量
   */
  private async executeEnumerateVectors(): Promise<void> {
    console.log('[PrivescAgent] 枚举所有权限提升向量...');

    const result = await enumerateAllPrivescVectors(this.shellId, this.sessionDir);

    if (result.success && result.data) {
      // 更新状态图
      this.graph.vectors = result.data.vectors;
      this.graph.currentUser = result.data.currentUser;
      this.graph.isRoot = result.data.isRoot;

      console.log(`[PrivescAgent] 发现 ${result.data.recommendations.length} 个提权向量`);
      console.log('[PrivescAgent] 优先级排序:');
      result.data.recommendations.forEach((rec, idx) => {
        console.log(`  ${idx + 1}. [${rec.priority}] ${rec.type}: ${rec.description}`);
      });
    } else {
      console.error('[PrivescAgent] 枚举失败:', result.error);
    }
  }

  /**
   * 执行自动提权
   */
  private async executeAutoPrivesc(): Promise<void> {
    console.log('[PrivescAgent] 开始自动提权尝试...');

    const result = await attemptAutoPrivesc(this.shellId, this.sessionDir);

    // 记录尝试
    this.graph.attempts.push({
      method: 'auto_privesc',
      vector: 'multiple',
      timestamp: new Date(),
      success: result.success && result.data?.rootAchieved === true,
      error: result.error
    });

    if (result.success && result.data) {
      this.graph.isRoot = result.data.rootAchieved;

      if (result.data.rootAchieved && result.data.successfulMethod) {
        this.graph.successfulMethod = {
          type: result.data.successfulMethod.type,
          vector: result.data.successfulMethod.vector,
          command: result.data.successfulMethod.command,
          timestamp: new Date()
        };
        console.log(`[PrivescAgent] ✓ 提权成功！方法: ${result.data.successfulMethod.type}`);
      } else {
        console.log(`[PrivescAgent] ✗ 自动提权失败，已尝试 ${result.data.attempts.length} 个方法`);
      }
    } else {
      console.error('[PrivescAgent] 自动提权执行失败:', result.error);
    }
  }

  /**
   * 执行内核漏洞利用
   */
  private async executeKernelExploit(): Promise<void> {
    if (this.graph.vectors.kernel.length === 0) {
      console.log('[PrivescAgent] 没有可用的内核漏洞');
      return;
    }

    // 选择风险最低的内核漏洞
    const exploit = this.graph.vectors.kernel.sort((a, b) => {
      const riskOrder = { low: 0, medium: 1, high: 2 };
      return riskOrder[a.risk as keyof typeof riskOrder] - riskOrder[b.risk as keyof typeof riskOrder];
    })[0];

    console.log(`[PrivescAgent] 尝试内核漏洞利用: ${exploit.name} (${exploit.cve})`);

    const result = await executeKernelExploit(
      this.shellId,
      this.sessionDir,
      exploit.name
    );

    // 记录尝试
    this.graph.attempts.push({
      method: 'kernel_exploit',
      vector: exploit.name,
      timestamp: new Date(),
      success: result.success && result.data?.rootAchieved === true,
      error: result.error
    });

    if (result.success && result.data) {
      this.graph.isRoot = result.data.rootAchieved;

      if (result.data.rootAchieved) {
        this.graph.successfulMethod = {
          type: 'kernel_exploit',
          vector: exploit.name,
          command: result.data.exploitCommand || '',
          timestamp: new Date()
        };
        console.log(`[PrivescAgent] ✓ 内核漏洞利用成功！`);
      } else {
        console.log(`[PrivescAgent] ✗ 内核漏洞利用失败`);
      }
    } else {
      console.error('[PrivescAgent] 内核漏洞利用执行失败:', result.error);
    }
  }

  /**
   * 执行 Docker 逃逸
   */
  private async executeDockerEscape(): Promise<void> {
    if (this.graph.vectors.docker.length === 0) {
      console.log('[PrivescAgent] 没有可用的Docker逃逸方法');
      return;
    }

    const method = this.graph.vectors.docker[0];
    console.log(`[PrivescAgent] 尝试Docker逃逸: ${method.type}`);

    const result = await executeDockerEscape(
      this.shellId,
      this.sessionDir,
      method.type
    );

    // 记录尝试
    this.graph.attempts.push({
      method: 'docker_escape',
      vector: method.type,
      timestamp: new Date(),
      success: result.success && result.data?.rootAchieved === true,
      error: result.error
    });

    if (result.success && result.data) {
      this.graph.isRoot = result.data.rootAchieved;

      if (result.data.rootAchieved) {
        this.graph.successfulMethod = {
          type: 'docker_escape',
          vector: method.type,
          command: result.data.escapeCommand || '',
          timestamp: new Date()
        };
        console.log(`[PrivescAgent] ✓ Docker逃逸成功！`);
      } else {
        console.log(`[PrivescAgent] ✗ Docker逃逸失败`);
      }
    } else {
      console.error('[PrivescAgent] Docker逃逸执行失败:', result.error);
    }
  }

  /**
   * 生成权限提升报告
   */
  private generateReport(): any {
    return {
      summary: {
        shellId: this.graph.shellId,
        initialUser: this.graph.currentUser,
        rootAchieved: this.graph.isRoot,
        totalAttempts: this.graph.attempts.length,
        successfulMethod: this.graph.successfulMethod
      },
      vectors: {
        suid: {
          total: this.graph.vectors.suid.length,
          exploitable: this.graph.vectors.suid.filter(s => s.exploitable).length,
          items: this.graph.vectors.suid
        },
        sudo: {
          total: this.graph.vectors.sudo.length,
          nopasswd: this.graph.vectors.sudo.filter(s => s.nopasswd).length,
          items: this.graph.vectors.sudo
        },
        kernel: {
          total: this.graph.vectors.kernel.length,
          items: this.graph.vectors.kernel
        },
        cron: {
          total: this.graph.vectors.cron.length,
          writable: this.graph.vectors.cron.filter(c => c.writable).length,
          items: this.graph.vectors.cron
        },
        capabilities: {
          total: this.graph.vectors.capabilities.length,
          items: this.graph.vectors.capabilities
        },
        docker: {
          total: this.graph.vectors.docker.length,
          items: this.graph.vectors.docker
        },
        env: {
          total: this.graph.vectors.env.length,
          items: this.graph.vectors.env
        },
        writable: {
          total: this.graph.vectors.writable.length,
          items: this.graph.vectors.writable
        }
      },
      attempts: this.graph.attempts.map(a => ({
        method: a.method,
        vector: a.vector,
        timestamp: a.timestamp.toISOString(),
        success: a.success,
        error: a.error
      })),
      recommendations: this.generateRecommendations()
    };
  }

  /**
   * 生成提权建议
   */
  private generateRecommendations(): string[] {
    const recommendations: string[] = [];

    if (this.graph.isRoot) {
      recommendations.push('✓ 已成功获得root权限');
      if (this.graph.successfulMethod) {
        recommendations.push(`成功方法: ${this.graph.successfulMethod.type} - ${this.graph.successfulMethod.vector}`);
        recommendations.push(`执行命令: ${this.graph.successfulMethod.command}`);
      }
    } else {
      recommendations.push('✗ 未能获得root权限');

      // 分析未尝试的向量
      const attemptedMethods = new Set(this.graph.attempts.map(a => a.method));

      if (!attemptedMethods.has('auto_privesc') && Object.values(this.graph.vectors).some(v => v.length > 0)) {
        recommendations.push('建议: 尝试自动提权（attemptAutoPrivesc）');
      }

      if (this.graph.vectors.kernel.length > 0 && !attemptedMethods.has('kernel_exploit')) {
        recommendations.push(`建议: 尝试内核漏洞利用（发现 ${this.graph.vectors.kernel.length} 个内核漏洞）`);
      }

      if (this.graph.vectors.docker.length > 0 && !attemptedMethods.has('docker_escape')) {
        recommendations.push(`建议: 尝试Docker逃逸（发现 ${this.graph.vectors.docker.length} 个逃逸方法）`);
      }

      if (recommendations.length === 1) {
        recommendations.push('所有已知方法均已尝试，可能需要手动分析');
      }
    }

    return recommendations;
  }

  /**
   * 主执行循环
   */
  async run(): Promise<ToolResult<any>> {
    console.log('[PrivescAgent] 启动权限提升智能体...');
    console.log(`[PrivescAgent] Shell ID: ${this.shellId}`);

    let maxIterations = 10;
    let iteration = 0;

    while (iteration < maxIterations && !this.graph.isRoot) {
      iteration++;
      console.log(`\n[PrivescAgent] === 迭代 ${iteration}/${maxIterations} ===`);

      // LLM 决策
      const decision = await this.makeDecision();
      console.log(`[PrivescAgent] 决策: ${decision}`);

      // 执行决策
      switch (decision) {
        case 'enumerate_vectors':
          await this.executeEnumerateVectors();
          break;

        case 'auto_privesc':
          await this.executeAutoPrivesc();
          break;

        case 'kernel_exploit':
          await this.executeKernelExploit();
          break;

        case 'docker_escape':
          await this.executeDockerEscape();
          break;

        case 'complete':
          console.log('[PrivescAgent] 任务完成，生成报告...');
          maxIterations = 0; // 退出循环
          break;

        default:
          console.log(`[PrivescAgent] 未知决策: ${decision}，使用降级逻辑`);
          const fallback = this.fallbackDecision();
          if (fallback === 'complete') {
            maxIterations = 0;
          }
      }

      // 如果已经获得root，提前退出
      if (this.graph.isRoot) {
        console.log('[PrivescAgent] ✓ 已获得root权限，提前结束');
        break;
      }
    }

    // 生成最终报告
    const report = this.generateReport();

    console.log('\n[PrivescAgent] ========== 权限提升报告 ==========');
    console.log(`Root权限: ${report.summary.rootAchieved ? '✓ 已获得' : '✗ 未获得'}`);
    console.log(`总尝试次数: ${report.summary.totalAttempts}`);
    if (report.summary.successfulMethod) {
      console.log(`成功方法: ${report.summary.successfulMethod.type} - ${report.summary.successfulMethod.vector}`);
    }
    console.log('\n发现的提权向量:');
    console.log(`  - SUID二进制: ${report.vectors.suid.total} (可利用: ${report.vectors.suid.exploitable})`);
    console.log(`  - Sudo权限: ${report.vectors.sudo.total} (NOPASSWD: ${report.vectors.sudo.nopasswd})`);
    console.log(`  - 内核漏洞: ${report.vectors.kernel.total}`);
    console.log(`  - Cron任务: ${report.vectors.cron.total} (可写: ${report.vectors.cron.writable})`);
    console.log(`  - Capabilities: ${report.vectors.capabilities.total}`);
    console.log(`  - Docker逃逸: ${report.vectors.docker.total}`);
    console.log(`  - 环境变量劫持: ${report.vectors.env.total}`);
    console.log(`  - 可写系统路径: ${report.vectors.writable.total}`);
    console.log('\n建议:');
    report.recommendations.forEach((rec: string) => console.log(`  ${rec}`));
    console.log('==========================================\n');

    return {
      success: true,
      data: report,
      message: report.summary.rootAchieved
        ? `权限提升成功，使用方法: ${report.summary.successfulMethod?.type}`
        : `权限提升失败，已尝试 ${report.summary.totalAttempts} 个方法`
    };
  }
}

/**
 * 导出便捷函数
 */
export async function runPrivescAgent(
  shellId: string,
  sessionDir: string,
  apiKey?: string
): Promise<ToolResult<any>> {
  const agent = new PrivescAgent(shellId, sessionDir, apiKey);
  return agent.run();
}
