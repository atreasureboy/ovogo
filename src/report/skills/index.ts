import { ToolResult } from '../../core/types';
import {
  generateMarkdownReport,
  generateHTMLReport,
  generateJSONReport,
  generatePDFReport,
  calculateRiskScore,
  generateAttackTimeline,
  generateRemediationPriority,
  generateVulnerabilityDistribution,
  generateComplianceReport
} from '../tools';

/**
 * Skill: 收集并整合所有子智能体的结果
 *
 * 流程：
 * 1. 收集Recon Agent的侦察结果
 * 2. 收集VulnScan Agent的漏洞扫描结果
 * 3. 收集Exploit Agent的漏洞利用结果
 * 4. 收集PostExploit Agent的后渗透结果
 * 5. 收集Privesc Agent的权限提升结果
 * 6. 收集Lateral Agent的横向移动结果
 * 7. 收集C2 Agent的C2部署结果
 * 8. 整合所有数据并生成统一的报告数据结构
 */
export async function aggregateAllAgentResults(
  agentResults: {
    recon?: any;
    vulnScan?: any;
    exploit?: any;
    postExploit?: any;
    privesc?: any;
    lateral?: any;
    c2?: any;
  }
): Promise<ToolResult<{
  target: string;
  executiveSummary: string;
  scope: any;
  vulnerabilities: Array<any>;
  attackPath: string[];
  recommendations: Array<any>;
  toolsUsed: string[];
  timeline: Array<any>;
}>> {
  try {
    console.log('[Skill] 整合所有子智能体结果...');

    // 提取目标信息
    const target = agentResults.recon?.summary?.primaryTarget || 'Unknown Target';

    // 收集所有漏洞
    const vulnerabilities: Array<any> = [];
    let vulnIdCounter = 1;

    // 从VulnScan Agent收集漏洞
    if (agentResults.vulnScan?.vulnerabilities) {
      for (const vuln of agentResults.vulnScan.vulnerabilities) {
        vulnerabilities.push({
          id: `VULN-${String(vulnIdCounter++).padStart(3, '0')}`,
          title: vuln.title || vuln.name,
          severity: vuln.severity || 'medium',
          cvss: vuln.cvss,
          category: vuln.type || 'Unknown',
          affectedAssets: vuln.affectedAssets || [vuln.target],
          description: vuln.description || 'No description available',
          exploitation: vuln.poc || 'Manual exploitation required',
          remediation: vuln.remediation || 'Apply security patches',
          exploitability: vuln.verified ? 'easy' : 'medium',
          impact: vuln.severity === 'critical' || vuln.severity === 'high' ? 'high' : 'medium',
          source: 'VulnScan Agent'
        });
      }
    }

    // 从Exploit Agent收集成功利用的漏洞
    if (agentResults.exploit?.successfulExploits) {
      for (const exploit of agentResults.exploit.successfulExploits) {
        vulnerabilities.push({
          id: `VULN-${String(vulnIdCounter++).padStart(3, '0')}`,
          title: `Exploited: ${exploit.vulnerability}`,
          severity: 'critical',
          cvss: 9.0,
          category: 'Exploitation',
          affectedAssets: [exploit.target],
          description: `Successfully exploited ${exploit.vulnerability}`,
          exploitation: exploit.method,
          remediation: 'Immediate patching required',
          exploitability: 'easy',
          impact: 'high',
          source: 'Exploit Agent'
        });
      }
    }

    // 构建攻击路径
    const attackPath: string[] = [];
    if (agentResults.recon) attackPath.push('侦察 (Reconnaissance)');
    if (agentResults.vulnScan) attackPath.push('漏洞扫描 (Vulnerability Scanning)');
    if (agentResults.exploit) attackPath.push('漏洞利用 (Exploitation)');
    if (agentResults.postExploit) attackPath.push('后渗透 (Post-Exploitation)');
    if (agentResults.privesc) attackPath.push('权限提升 (Privilege Escalation)');
    if (agentResults.lateral) attackPath.push('横向移动 (Lateral Movement)');
    if (agentResults.c2) attackPath.push('C2部署 (C2 Deployment)');

    // 生成执行摘要
    const totalVulns = vulnerabilities.length;
    const criticalVulns = vulnerabilities.filter(v => v.severity === 'critical').length;
    const highVulns = vulnerabilities.filter(v => v.severity === 'high').length;
    const compromisedHosts = agentResults.lateral?.summary?.compromisedHosts || 0;

    const executiveSummary = `本次渗透测试针对目标 ${target} 进行了全面的安全评估。测试发现了 ${totalVulns} 个安全漏洞，其中包括 ${criticalVulns} 个严重漏洞和 ${highVulns} 个高危漏洞。测试团队成功获得了初始访问权限，并通过横向移动攻陷了 ${compromisedHosts} 个内网主机。建议立即修复所有严重和高危漏洞，并加强网络安全防护措施。`;

    // 测试范围
    const scope = {
      targetSystems: [target],
      startTime: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(), // 假设测试持续24小时
      endTime: new Date().toISOString(),
      testType: 'Black Box Penetration Testing'
    };

    // 生成修复建议
    const recommendations: Array<any> = [];

    if (criticalVulns > 0) {
      recommendations.push({
        priority: 'Critical',
        title: '立即修复严重漏洞',
        description: `发现 ${criticalVulns} 个严重漏洞，这些漏洞可能导致系统完全被攻陷。建议在24小时内完成修复。`
      });
    }

    if (highVulns > 0) {
      recommendations.push({
        priority: 'High',
        title: '修复高危漏洞',
        description: `发现 ${highVulns} 个高危漏洞，建议在一周内完成修复。`
      });
    }

    if (agentResults.privesc?.summary?.rootAchieved) {
      recommendations.push({
        priority: 'Critical',
        title: '加强权限管理',
        description: '测试中成功提升到root权限，建议审查sudo配置、SUID二进制文件和内核版本。'
      });
    }

    if (compromisedHosts > 0) {
      recommendations.push({
        priority: 'High',
        title: '加强内网隔离',
        description: `测试中成功横向移动到 ${compromisedHosts} 个内网主机，建议实施网络分段和零信任架构。`
      });
    }

    recommendations.push({
      priority: 'Medium',
      title: '部署入侵检测系统',
      description: '建议部署IDS/IPS系统以检测和阻止类似的攻击行为。'
    });

    recommendations.push({
      priority: 'Medium',
      title: '加强日志监控',
      description: '建议实施集中式日志管理和实时监控，以便及时发现异常活动。'
    });

    // 收集使用的工具
    const toolsUsed = [
      'Nmap', 'Masscan', 'Subfinder', 'Amass', 'Nuclei', 'SQLMap',
      'Metasploit', 'LinPEAS', 'SSH', 'Sliver', 'Custom Scripts'
    ];

    // 生成时间线
    const timeline: Array<any> = [];
    let currentTime = new Date(Date.now() - 24 * 60 * 60 * 1000);

    if (agentResults.recon) {
      timeline.push({
        timestamp: new Date(currentTime),
        phase: 'Reconnaissance',
        action: '侦察目标系统',
        result: `发现 ${agentResults.recon.summary?.totalSubdomains || 0} 个子域名`
      });
      currentTime = new Date(currentTime.getTime() + 2 * 60 * 60 * 1000);
    }

    if (agentResults.vulnScan) {
      timeline.push({
        timestamp: new Date(currentTime),
        phase: 'Vulnerability Scanning',
        action: '扫描安全漏洞',
        result: `发现 ${agentResults.vulnScan.summary?.totalVulnerabilities || 0} 个漏洞`
      });
      currentTime = new Date(currentTime.getTime() + 4 * 60 * 60 * 1000);
    }

    if (agentResults.exploit) {
      timeline.push({
        timestamp: new Date(currentTime),
        phase: 'Exploitation',
        action: '利用漏洞获取访问权限',
        result: `成功获得 ${agentResults.exploit.summary?.successfulExploits || 0} 个shell`
      });
      currentTime = new Date(currentTime.getTime() + 3 * 60 * 60 * 1000);
    }

    if (agentResults.privesc) {
      timeline.push({
        timestamp: new Date(currentTime),
        phase: 'Privilege Escalation',
        action: '提升权限到root',
        result: agentResults.privesc.summary?.rootAchieved ? '成功获得root权限' : '权限提升失败'
      });
      currentTime = new Date(currentTime.getTime() + 2 * 60 * 60 * 1000);
    }

    if (agentResults.lateral) {
      timeline.push({
        timestamp: new Date(currentTime),
        phase: 'Lateral Movement',
        action: '横向移动到内网主机',
        result: `攻陷 ${agentResults.lateral.summary?.compromisedHosts || 0} 个内网主机`
      });
      currentTime = new Date(currentTime.getTime() + 6 * 60 * 60 * 1000);
    }

    if (agentResults.c2) {
      timeline.push({
        timestamp: new Date(currentTime),
        phase: 'C2 Deployment',
        action: '部署C2基础设施',
        result: `建立 ${agentResults.c2.summary?.activeSessions || 0} 个C2会话`
      });
    }

    console.log(`[Skill] 整合完成: ${vulnerabilities.length} 个漏洞, ${attackPath.length} 个阶段`);

    return {
      success: true,
      data: {
        target,
        executiveSummary,
        scope,
        vulnerabilities,
        attackPath,
        recommendations,
        toolsUsed,
        timeline
      },
      message: `数据整合完成: ${vulnerabilities.length} 个漏洞`
    };
  } catch (error) {
    return {
      success: false,
      error: `整合子智能体结果失败: ${error}`
    };
  }
}

/**
 * Skill: 生成完整的多格式报告
 *
 * 流程：
 * 1. 整合所有数据
 * 2. 计算风险评分
 * 3. 生成攻击时间线
 * 4. 生成修复优先级
 * 5. 生成漏洞分布统计
 * 6. 生成Markdown报告
 * 7. 生成HTML报告
 * 8. 生成JSON报告
 * 9. 生成PDF报告（可选）
 */
export async function generateComprehensiveReport(
  shellId: string,
  sessionDir: string,
  agentResults: any
): Promise<ToolResult<{
  reports: {
    markdown?: string;
    html?: string;
    json?: string;
    pdf?: string;
  };
  riskScore: number;
  riskLevel: string;
  summary: any;
}>> {
  try {
    console.log('[Skill] 生成完整报告...');

    // 步骤1: 整合所有数据
    console.log('[Skill] 步骤1: 整合数据...');
    const aggregateResult = await aggregateAllAgentResults(agentResults);

    if (!aggregateResult.success || !aggregateResult.data) {
      return {
        success: false,
        error: `数据整合失败: ${aggregateResult.error}`
      };
    }

    const reportData = aggregateResult.data;

    // 步骤2: 计算风险评分
    console.log('[Skill] 步骤2: 计算风险评分...');
    const riskResult = await calculateRiskScore(reportData.vulnerabilities);
    const riskScore = riskResult.data?.riskScore || 0;
    const riskLevel = riskResult.data?.riskLevel || 'Unknown';

    // 步骤3: 生成攻击时间线
    console.log('[Skill] 步骤3: 生成攻击时间线...');
    const timelineResult = await generateAttackTimeline(reportData.timeline);

    // 步骤4: 生成修复优先级
    console.log('[Skill] 步骤4: 生成修复优先级...');
    const priorityResult = await generateRemediationPriority(reportData.vulnerabilities);

    // 步骤5: 生成漏洞分布
    console.log('[Skill] 步骤5: 生成漏洞分布...');
    const distributionResult = await generateVulnerabilityDistribution(reportData.vulnerabilities);

    // 增强报告数据
    const enhancedReportData = {
      ...reportData,
      riskScore,
      riskLevel,
      timeline: timelineResult.data?.timeline || reportData.timeline,
      remediationPriority: priorityResult.data?.priorities || [],
      distribution: distributionResult.data?.distribution || {}
    };

    const reports: any = {};

    // 步骤6: 生成Markdown报告
    console.log('[Skill] 步骤6: 生成Markdown报告...');
    const mdResult = await generateMarkdownReport(sessionDir, enhancedReportData);
    if (mdResult.success && mdResult.data) {
      reports.markdown = mdResult.data.reportPath;
      console.log(`[Skill] ✓ Markdown报告: ${mdResult.data.reportPath}`);
    }

    // 步骤7: 生成HTML报告
    console.log('[Skill] 步骤7: 生成HTML报告...');
    const htmlResult = await generateHTMLReport(sessionDir, enhancedReportData);
    if (htmlResult.success && htmlResult.data) {
      reports.html = htmlResult.data.reportPath;
      console.log(`[Skill] ✓ HTML报告: ${htmlResult.data.reportPath}`);

      // 步骤9: 生成PDF报告
      console.log('[Skill] 步骤9: 生成PDF报告...');
      const pdfResult = await generatePDFReport(shellId, sessionDir, htmlResult.data.reportPath);
      if (pdfResult.success && pdfResult.data) {
        reports.pdf = pdfResult.data.reportPath;
        console.log(`[Skill] ✓ PDF报告: ${pdfResult.data.reportPath}`);
      }
    }

    // 步骤8: 生成JSON报告
    console.log('[Skill] 步骤8: 生成JSON报告...');
    const jsonResult = await generateJSONReport(sessionDir, enhancedReportData);
    if (jsonResult.success && jsonResult.data) {
      reports.json = jsonResult.data.reportPath;
      console.log(`[Skill] ✓ JSON报告: ${jsonResult.data.reportPath}`);
    }

    const summary = {
      totalVulnerabilities: reportData.vulnerabilities.length,
      criticalCount: reportData.vulnerabilities.filter((v: any) => v.severity === 'critical').length,
      highCount: reportData.vulnerabilities.filter((v: any) => v.severity === 'high').length,
      mediumCount: reportData.vulnerabilities.filter((v: any) => v.severity === 'medium').length,
      lowCount: reportData.vulnerabilities.filter((v: any) => v.severity === 'low').length,
      riskScore,
      riskLevel,
      reportsGenerated: Object.keys(reports).length
    };

    console.log(`[Skill] 完整报告生成完成: ${Object.keys(reports).length} 个格式`);

    return {
      success: true,
      data: {
        reports,
        riskScore,
        riskLevel,
        summary
      },
      message: `完整报告生成完成: ${Object.keys(reports).length} 个格式`
    };
  } catch (error) {
    return {
      success: false,
      error: `生成完整报告失败: ${error}`
    };
  }
}

/**
 * Skill: 生成执行摘要和管理层报告
 *
 * 流程：
 * 1. 提取关键指标
 * 2. 生成业务影响分析
 * 3. 生成风险矩阵
 * 4. 生成高层建议
 * 5. 生成简化的管理层报告
 */
export async function generateExecutiveSummary(
  sessionDir: string,
  reportData: any
): Promise<ToolResult<{ summaryPath: string; keyMetrics: any }>> {
  try {
    console.log('[Skill] 生成执行摘要...');

    const keyMetrics = {
      overallRiskLevel: reportData.riskLevel,
      riskScore: reportData.riskScore,
      totalVulnerabilities: reportData.vulnerabilities.length,
      criticalVulnerabilities: reportData.vulnerabilities.filter((v: any) => v.severity === 'critical').length,
      systemsCompromised: reportData.attackPath.includes('横向移动') ? 'Yes' : 'No',
      dataExfiltrationRisk: reportData.vulnerabilities.some((v: any) => v.category.includes('Injection')) ? 'High' : 'Medium',
      estimatedRemediationTime: `${Math.ceil(reportData.vulnerabilities.length / 5)} weeks`
    };

    const summaryContent = `# 执行摘要 - 渗透测试报告

## 关键发现

**整体风险等级**: ${keyMetrics.overallRiskLevel}
**风险评分**: ${keyMetrics.riskScore}/100

## 核心指标

- **发现漏洞总数**: ${keyMetrics.totalVulnerabilities}
- **严重漏洞**: ${keyMetrics.criticalVulnerabilities}
- **系统被攻陷**: ${keyMetrics.systemsCompromised}
- **数据泄露风险**: ${keyMetrics.dataExfiltrationRisk}
- **预计修复时间**: ${keyMetrics.estimatedRemediationTime}

## 业务影响

本次测试发现的安全漏洞可能导致以下业务影响：

1. **数据泄露风险**: 攻击者可能获取敏感数据
2. **服务中断风险**: 系统可能被恶意控制或破坏
3. **合规性风险**: 可能违反数据保护法规
4. **声誉损失**: 安全事件可能影响企业形象

## 优先行动项

1. **立即修复所有严重漏洞** (24小时内)
2. **修复高危漏洞** (1周内)
3. **实施网络分段和访问控制**
4. **部署入侵检测系统**
5. **加强安全意识培训**

## 投资建议

建议在以下领域增加安全投资：
- 漏洞管理和补丁管理系统
- 网络安全监控和响应能力
- 员工安全意识培训
- 定期安全评估和渗透测试
`;

    const summaryPath = path.join(sessionDir, `executive_summary_${Date.now()}.md`);
    await require('fs/promises').writeFile(summaryPath, summaryContent, 'utf-8');

    console.log(`[Skill] 执行摘要生成完成: ${summaryPath}`);

    return {
      success: true,
      data: {
        summaryPath,
        keyMetrics
      },
      message: `执行摘要生成完成: ${summaryPath}`
    };
  } catch (error) {
    return {
      success: false,
      error: `生成执行摘要失败: ${error}`
    };
  }
}

/**
 * Skill: 生成合规性和标准对照报告
 *
 * 流程：
 * 1. 对照OWASP Top 10
 * 2. 对照CWE Top 25
 * 3. 对照PCI DSS要求
 * 4. 生成合规性差距分析
 */
export async function generateComplianceAnalysis(
  sessionDir: string,
  vulnerabilities: Array<any>
): Promise<ToolResult<{ compliancePath: string; complianceScore: number }>> {
  try {
    console.log('[Skill] 生成合规性分析...');

    const complianceResult = await generateComplianceReport(vulnerabilities);

    if (!complianceResult.success || !complianceResult.data) {
      return {
        success: false,
        error: '合规性分析失败'
      };
    }

    const compliance = complianceResult.data.compliance;

    let complianceContent = `# 合规性分析报告\n\n`;

    let totalPassed = 0;
    let totalChecks = 0;

    for (const [standard, result] of Object.entries(compliance)) {
      complianceContent += `## ${standard}\n\n`;
      complianceContent += `- **通过检查**: ${(result as any).passed}\n`;
      complianceContent += `- **失败检查**: ${(result as any).failed}\n`;
      complianceContent += `- **合规率**: ${(((result as any).passed / (result as any).totalChecks) * 100).toFixed(1)}%\n\n`;

      totalPassed += (result as any).passed;
      totalChecks += (result as any).totalChecks;

      if ((result as any).findings.length > 0) {
        complianceContent += `### 发现的问题\n\n`;
        for (const finding of (result as any).findings) {
          complianceContent += `- **${finding.category}**: ${finding.count} 个漏洞 (${finding.status})\n`;
        }
        complianceContent += `\n`;
      }
    }

    const complianceScore = totalChecks > 0 ? Math.round((totalPassed / totalChecks) * 100) : 0;

    complianceContent += `\n## 总体合规性评分\n\n`;
    complianceContent += `**${complianceScore}/100**\n\n`;

    const compliancePath = path.join(sessionDir, `compliance_report_${Date.now()}.md`);
    await require('fs/promises').writeFile(compliancePath, complianceContent, 'utf-8');

    console.log(`[Skill] 合规性分析完成: ${compliancePath} (评分: ${complianceScore}/100)`);

    return {
      success: true,
      data: {
        compliancePath,
        complianceScore
      },
      message: `合规性分析完成: 评分 ${complianceScore}/100`
    };
  } catch (error) {
    return {
      success: false,
      error: `生成合规性分析失败: ${error}`
    };
  }
}
