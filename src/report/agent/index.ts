import Anthropic from '@anthropic-ai/sdk';
import { ToolResult } from '../../core/types';
import {
  generateMarkdownReport,
  generateHTMLReport,
  generateJSONReport,
  calculateRiskScore
} from '../tools';
import {
  aggregateAllAgentResults,
  generateComprehensiveReport,
  generateExecutiveSummary,
  generateComplianceAnalysis
} from '../skills';

/**
 * 报告状态图
 */
interface ReportGraph {
  sessionDir: string;

  // 原始数据
  rawData: {
    recon?: any;
    vulnScan?: any;
    exploit?: any;
    postExploit?: any;
    privesc?: any;
    lateral?: any;
    c2?: any;
  };

  // 整合后的数据
  aggregatedData?: {
    target: string;
    executiveSummary: string;
    vulnerabilities: Array<any>;
    attackPath: string[];
    recommendations: Array<any>;
  };

  // 风险评估
  riskAssessment?: {
    riskScore: number;
    riskLevel: string;
    breakdown: any;
  };

  // 生成的报告
  generatedReports: {
    markdown?: string;
    html?: string;
    json?: string;
    pdf?: string;
    executiveSummary?: string;
    compliance?: string;
  };

  // 报告元数据
  metadata: {
    generatedAt?: Date;
    totalVulnerabilities: number;
    criticalCount: number;
    highCount: number;
    reportFormats: string[];
  };
}

/**
 * Report Agent - 报告生成智能体
 *
 * 职责：
 * 1. 收集所有子智能体的执行结果
 * 2. 整合数据并进行风险评估
 * 3. 生成多格式的渗透测试报告
 * 4. 生成执行摘要和管理层报告
 * 5. 生成合规性分析报告
 * 6. 提供报告定制和导出功能
 */
export class ReportAgent {
  private client: Anthropic;
  private graph: ReportGraph;
  private conversationHistory: Array<{ role: 'user' | 'assistant'; content: string }> = [];

  constructor(
    private shellId: string,
    private sessionDir: string,
    private agentResults: any,
    apiKey?: string
  ) {
    this.client = new Anthropic({
      apiKey: apiKey || process.env.ANTHROPIC_API_KEY
    });

    this.graph = {
      sessionDir,
      rawData: agentResults,
      generatedReports: {},
      metadata: {
        totalVulnerabilities: 0,
        criticalCount: 0,
        highCount: 0,
        reportFormats: []
      }
    };
  }

  /**
   * 系统提示词 - 定义 Agent 的角色和能力
   */
  private getSystemPrompt(): string {
    return `你是一个专业的报告生成智能体（Report Generation Agent），负责生成全面的渗透测试报告。

你的核心能力：
1. **数据整合** - 收集并整合所有子智能体的执行结果
2. **风险评估** - 计算风险评分并进行风险分级
3. **报告生成** - 生成多格式报告（Markdown、HTML、JSON、PDF）
4. **执行摘要** - 为管理层生成简化的执行摘要
5. **合规性分析** - 对照安全标准进行合规性检查

可用的技能（Skills）：
- aggregateAllAgentResults: 整合所有子智能体结果
- generateComprehensiveReport: 生成完整的多格式报告
- generateExecutiveSummary: 生成执行摘要和管理层报告
- generateComplianceAnalysis: 生成合规性分析报告

决策原则：
1. **数据优先** - 始终先整合数据再生成报告
2. **多格式输出** - 同时生成多种格式以满足不同需求
3. **风险导向** - 突出显示高风险漏洞和关键发现
4. **可操作性** - 提供具体的修复建议和优先级
5. **合规性** - 对照行业标准进行合规性检查

当前状态：
- 会话目录: ${this.graph.sessionDir}
- 可用数据源: ${Object.keys(this.graph.rawData).join(', ')}
- 已生成报告: ${Object.keys(this.graph.generatedReports).length}

请根据当前状态和可用技能，制定下一步报告生成计划。`;
  }

  /**
   * LLM 驱动的决策引擎
   */
  private async makeDecision(): Promise<string> {
    this.conversationHistory.push({
      role: 'user',
      content: `当前报告生成状态：
- 原始数据源: ${Object.keys(this.graph.rawData).join(', ')}
- 数据已整合: ${this.graph.aggregatedData ? 'Yes' : 'No'}
- 风险评估完成: ${this.graph.riskAssessment ? 'Yes' : 'No'}
- 已生成报告: ${Object.keys(this.graph.generatedReports).join(', ') || 'None'}
- 总漏洞数: ${this.graph.metadata.totalVulnerabilities}

请决定下一步行动。可选操作：
1. aggregate_data - 整合所有子智能体数据
2. generate_reports - 生成完整的多格式报告
3. generate_executive - 生成执行摘要
4. generate_compliance - 生成合规性分析
5. complete - 报告生成完成

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
        : 'aggregate_data';

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
    // 如果数据还没整合，先整合
    if (!this.graph.aggregatedData) {
      return 'aggregate_data';
    }

    // 如果还没生成主报告，生成主报告
    if (Object.keys(this.graph.generatedReports).length === 0) {
      return 'generate_reports';
    }

    // 如果还没生成执行摘要，生成执行摘要
    if (!this.graph.generatedReports.executiveSummary) {
      return 'generate_executive';
    }

    // 如果还没生成合规性报告，生成合规性报告
    if (!this.graph.generatedReports.compliance) {
      return 'generate_compliance';
    }

    // 所有报告都已生成
    return 'complete';
  }

  /**
   * 执行数据整合
   */
  private async executeAggregateData(): Promise<void> {
    console.log('[ReportAgent] 整合所有子智能体数据...');

    const result = await aggregateAllAgentResults(this.graph.rawData);

    if (result.success && result.data) {
      this.graph.aggregatedData = result.data;

      // 计算风险评分
      const riskResult = await calculateRiskScore(result.data.vulnerabilities);
      if (riskResult.success && riskResult.data) {
        this.graph.riskAssessment = riskResult.data;
      }

      // 更新元数据
      this.graph.metadata.totalVulnerabilities = result.data.vulnerabilities.length;
      this.graph.metadata.criticalCount = result.data.vulnerabilities.filter((v: any) => v.severity === 'critical').length;
      this.graph.metadata.highCount = result.data.vulnerabilities.filter((v: any) => v.severity === 'high').length;

      console.log(`[ReportAgent] 数据整合完成: ${result.data.vulnerabilities.length} 个漏洞`);
    } else {
      console.error('[ReportAgent] 数据整合失败:', result.error);
    }
  }

  /**
   * 执行生成完整报告
   */
  private async executeGenerateReports(): Promise<void> {
    console.log('[ReportAgent] 生成完整报告...');

    const result = await generateComprehensiveReport(
      this.shellId,
      this.graph.sessionDir,
      this.graph.rawData
    );

    if (result.success && result.data) {
      this.graph.generatedReports = {
        ...this.graph.generatedReports,
        ...result.data.reports
      };

      // 更新元数据
      this.graph.metadata.reportFormats = Object.keys(result.data.reports);
      this.graph.metadata.generatedAt = new Date();

      console.log(`[ReportAgent] 报告生成完成: ${Object.keys(result.data.reports).length} 个格式`);
      console.log(`[ReportAgent] 风险评分: ${result.data.riskScore}/100 (${result.data.riskLevel})`);
    } else {
      console.error('[ReportAgent] 报告生成失败:', result.error);
    }
  }

  /**
   * 执行生成执行摘要
   */
  private async executeGenerateExecutive(): Promise<void> {
    console.log('[ReportAgent] 生成执行摘要...');

    if (!this.graph.aggregatedData) {
      console.log('[ReportAgent] 数据未整合，跳过执行摘要生成');
      return;
    }

    const reportData = {
      ...this.graph.aggregatedData,
      riskScore: this.graph.riskAssessment?.riskScore || 0,
      riskLevel: this.graph.riskAssessment?.riskLevel || 'Unknown'
    };

    const result = await generateExecutiveSummary(this.graph.sessionDir, reportData);

    if (result.success && result.data) {
      this.graph.generatedReports.executiveSummary = result.data.summaryPath;
      console.log(`[ReportAgent] 执行摘要生成完成: ${result.data.summaryPath}`);
    } else {
      console.error('[ReportAgent] 执行摘要生成失败:', result.error);
    }
  }

  /**
   * 执行生成合规性分析
   */
  private async executeGenerateCompliance(): Promise<void> {
    console.log('[ReportAgent] 生成合规性分析...');

    if (!this.graph.aggregatedData) {
      console.log('[ReportAgent] 数据未整合，跳过合规性分析');
      return;
    }

    const result = await generateComplianceAnalysis(
      this.graph.sessionDir,
      this.graph.aggregatedData.vulnerabilities
    );

    if (result.success && result.data) {
      this.graph.generatedReports.compliance = result.data.compliancePath;
      console.log(`[ReportAgent] 合规性分析完成: ${result.data.compliancePath} (评分: ${result.data.complianceScore}/100)`);
    } else {
      console.error('[ReportAgent] 合规性分析失败:', result.error);
    }
  }

  /**
   * 生成最终报告摘要
   */
  private generateFinalSummary(): any {
    return {
      metadata: {
        generatedAt: this.graph.metadata.generatedAt?.toISOString() || new Date().toISOString(),
        sessionDir: this.graph.sessionDir
      },
      statistics: {
        totalVulnerabilities: this.graph.metadata.totalVulnerabilities,
        criticalCount: this.graph.metadata.criticalCount,
        highCount: this.graph.metadata.highCount,
        mediumCount: this.graph.aggregatedData?.vulnerabilities.filter((v: any) => v.severity === 'medium').length || 0,
        lowCount: this.graph.aggregatedData?.vulnerabilities.filter((v: any) => v.severity === 'low').length || 0
      },
      riskAssessment: {
        riskScore: this.graph.riskAssessment?.riskScore || 0,
        riskLevel: this.graph.riskAssessment?.riskLevel || 'Unknown'
      },
      generatedReports: {
        formats: this.graph.metadata.reportFormats,
        files: this.graph.generatedReports
      },
      target: this.graph.aggregatedData?.target || 'Unknown',
      attackPath: this.graph.aggregatedData?.attackPath || [],
      recommendations: this.graph.aggregatedData?.recommendations || []
    };
  }

  /**
   * 主执行循环
   */
  async run(): Promise<ToolResult<any>> {
    console.log('[ReportAgent] 启动报告生成智能体...');
    console.log(`[ReportAgent] 会话目录: ${this.graph.sessionDir}`);
    console.log(`[ReportAgent] 数据源: ${Object.keys(this.graph.rawData).join(', ')}`);

    let maxIterations = 8;
    let iteration = 0;

    while (iteration < maxIterations) {
      iteration++;
      console.log(`\n[ReportAgent] === 迭代 ${iteration}/${maxIterations} ===`);

      // LLM 决策
      const decision = await this.makeDecision();
      console.log(`[ReportAgent] 决策: ${decision}`);

      // 执行决策
      switch (decision) {
        case 'aggregate_data':
          await this.executeAggregateData();
          break;

        case 'generate_reports':
          await this.executeGenerateReports();
          break;

        case 'generate_executive':
          await this.executeGenerateExecutive();
          break;

        case 'generate_compliance':
          await this.executeGenerateCompliance();
          break;

        case 'complete':
          console.log('[ReportAgent] 任务完成，生成最终摘要...');
          maxIterations = 0; // 退出循环
          break;

        default:
          console.log(`[ReportAgent] 未知决策: ${decision}，使用降级逻辑`);
          const fallback = this.fallbackDecision();
          if (fallback === 'complete') {
            maxIterations = 0;
          }
      }
    }

    // 生成最终摘要
    const finalSummary = this.generateFinalSummary();

    console.log('\n[ReportAgent] ========== 报告生成摘要 ==========');
    console.log(`目标: ${finalSummary.target}`);
    console.log(`生成时间: ${finalSummary.metadata.generatedAt}`);
    console.log('\n漏洞统计:');
    console.log(`  - 总计: ${finalSummary.statistics.totalVulnerabilities}`);
    console.log(`  - 严重: ${finalSummary.statistics.criticalCount}`);
    console.log(`  - 高危: ${finalSummary.statistics.highCount}`);
    console.log(`  - 中危: ${finalSummary.statistics.mediumCount}`);
    console.log(`  - 低危: ${finalSummary.statistics.lowCount}`);
    console.log('\n风险评估:');
    console.log(`  - 风险评分: ${finalSummary.riskAssessment.riskScore}/100`);
    console.log(`  - 风险等级: ${finalSummary.riskAssessment.riskLevel}`);
    console.log('\n生成的报告:');
    Object.entries(finalSummary.generatedReports.files).forEach(([format, path]) => {
      console.log(`  - ${format.toUpperCase()}: ${path}`);
    });
    console.log('\n攻击路径:');
    console.log(`  ${finalSummary.attackPath.join(' → ')}`);
    console.log('==========================================\n');

    return {
      success: true,
      data: finalSummary,
      message: `报告生成完成: ${finalSummary.generatedReports.formats.length} 个格式, 风险评分 ${finalSummary.riskAssessment.riskScore}/100`
    };
  }
}

/**
 * 导出便捷函数
 */
export async function runReportAgent(
  shellId: string,
  sessionDir: string,
  agentResults: any,
  apiKey?: string
): Promise<ToolResult<any>> {
  const agent = new ReportAgent(shellId, sessionDir, agentResults, apiKey);
  return agent.run();
}
