import { executeCommand } from '../../core/shell.js';
import type { ToolResult } from '../../core/agentTypes.js';
import * as fs from 'fs/promises';
import * as path from 'path';

/**
 * 生成Markdown格式报告
 */
export async function generateMarkdownReport(
  sessionDir: string,
  reportData: any
): Promise<ToolResult<{ reportPath: string; reportSize: number }>> {
  try {
    const reportPath = path.join(sessionDir, `pentest_report_${Date.now()}.md`);

    let markdown = `# 渗透测试报告\n\n`;
    markdown += `**生成时间**: ${new Date().toISOString()}\n\n`;
    markdown += `**目标**: ${reportData.target}\n\n`;
    markdown += `---\n\n`;

    // 执行摘要
    markdown += `## 执行摘要\n\n`;
    markdown += `${reportData.executiveSummary}\n\n`;

    // 测试范围
    markdown += `## 测试范围\n\n`;
    markdown += `- **目标系统**: ${reportData.scope.targetSystems.join(', ')}\n`;
    markdown += `- **测试时间**: ${reportData.scope.startTime} - ${reportData.scope.endTime}\n`;
    markdown += `- **测试类型**: ${reportData.scope.testType}\n\n`;

    // 发现的漏洞
    markdown += `## 发现的漏洞\n\n`;
    markdown += `### 漏洞统计\n\n`;
    markdown += `| 严重程度 | 数量 |\n`;
    markdown += `|---------|------|\n`;
    markdown += `| 严重 (Critical) | ${reportData.vulnerabilities.filter((v: any) => v.severity === 'critical').length} |\n`;
    markdown += `| 高危 (High) | ${reportData.vulnerabilities.filter((v: any) => v.severity === 'high').length} |\n`;
    markdown += `| 中危 (Medium) | ${reportData.vulnerabilities.filter((v: any) => v.severity === 'medium').length} |\n`;
    markdown += `| 低危 (Low) | ${reportData.vulnerabilities.filter((v: any) => v.severity === 'low').length} |\n\n`;

    // 漏洞详情
    markdown += `### 漏洞详情\n\n`;
    for (const vuln of reportData.vulnerabilities) {
      markdown += `#### ${vuln.title}\n\n`;
      markdown += `- **严重程度**: ${vuln.severity.toUpperCase()}\n`;
      markdown += `- **CVSS评分**: ${vuln.cvss || 'N/A'}\n`;
      markdown += `- **影响范围**: ${vuln.affectedAssets.join(', ')}\n`;
      markdown += `- **描述**: ${vuln.description}\n`;
      markdown += `- **利用方法**: ${vuln.exploitation}\n`;
      markdown += `- **修复建议**: ${vuln.remediation}\n\n`;
    }

    // 攻击路径
    markdown += `## 攻击路径\n\n`;
    markdown += `\`\`\`\n`;
    markdown += reportData.attackPath.join(' → ');
    markdown += `\n\`\`\`\n\n`;

    // 修复建议
    markdown += `## 修复建议\n\n`;
    for (const rec of reportData.recommendations) {
      markdown += `### ${rec.priority} - ${rec.title}\n\n`;
      markdown += `${rec.description}\n\n`;
    }

    // 附录
    markdown += `## 附录\n\n`;
    markdown += `### 使用的工具\n\n`;
    for (const tool of reportData.toolsUsed) {
      markdown += `- ${tool}\n`;
    }

    await fs.writeFile(reportPath, markdown, 'utf-8');

    const stats = await fs.stat(reportPath);

    return {
      success: true,
      data: {
        reportPath,
        reportSize: stats.size
      },
      message: `Markdown报告生成成功: ${reportPath}`
    };
  } catch (error) {
    return {
      success: false,
      data: null as any,
      error: `生成Markdown报告失败: ${error}`
    };
  }
}

/**
 * 生成HTML格式报告
 */
export async function generateHTMLReport(
  sessionDir: string,
  reportData: any
): Promise<ToolResult<{ reportPath: string; reportSize: number }>> {
  try {
    const reportPath = path.join(sessionDir, `pentest_report_${Date.now()}.html`);

    let html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>渗透测试报告</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
        h1 { color: #333; border-bottom: 3px solid #e74c3c; padding-bottom: 10px; }
        h2 { color: #555; border-bottom: 2px solid #3498db; padding-bottom: 8px; margin-top: 30px; }
        h3 { color: #666; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #3498db; color: white; }
        .critical { color: #e74c3c; font-weight: bold; }
        .high { color: #e67e22; font-weight: bold; }
        .medium { color: #f39c12; font-weight: bold; }
        .low { color: #27ae60; font-weight: bold; }
        .vuln-box { border: 1px solid #ddd; padding: 15px; margin: 15px 0; border-radius: 5px; }
        .attack-path { background: #ecf0f1; padding: 15px; border-radius: 5px; font-family: monospace; }
    </style>
</head>
<body>
    <h1>渗透测试报告</h1>
    <p><strong>生成时间:</strong> ${new Date().toISOString()}</p>
    <p><strong>目标:</strong> ${reportData.target}</p>
    <hr>

    <h2>执行摘要</h2>
    <p>${reportData.executiveSummary}</p>

    <h2>测试范围</h2>
    <ul>
        <li><strong>目标系统:</strong> ${reportData.scope.targetSystems.join(', ')}</li>
        <li><strong>测试时间:</strong> ${reportData.scope.startTime} - ${reportData.scope.endTime}</li>
        <li><strong>测试类型:</strong> ${reportData.scope.testType}</li>
    </ul>

    <h2>发现的漏洞</h2>
    <h3>漏洞统计</h3>
    <table>
        <tr>
            <th>严重程度</th>
            <th>数量</th>
        </tr>
        <tr>
            <td class="critical">严重 (Critical)</td>
            <td>${reportData.vulnerabilities.filter((v: any) => v.severity === 'critical').length}</td>
        </tr>
        <tr>
            <td class="high">高危 (High)</td>
            <td>${reportData.vulnerabilities.filter((v: any) => v.severity === 'high').length}</td>
        </tr>
        <tr>
            <td class="medium">中危 (Medium)</td>
            <td>${reportData.vulnerabilities.filter((v: any) => v.severity === 'medium').length}</td>
        </tr>
        <tr>
            <td class="low">低危 (Low)</td>
            <td>${reportData.vulnerabilities.filter((v: any) => v.severity === 'low').length}</td>
        </tr>
    </table>

    <h3>漏洞详情</h3>`;

    for (const vuln of reportData.vulnerabilities) {
      html += `
    <div class="vuln-box">
        <h4>${vuln.title}</h4>
        <p><strong>严重程度:</strong> <span class="${vuln.severity}">${vuln.severity.toUpperCase()}</span></p>
        <p><strong>CVSS评分:</strong> ${vuln.cvss || 'N/A'}</p>
        <p><strong>影响范围:</strong> ${vuln.affectedAssets.join(', ')}</p>
        <p><strong>描述:</strong> ${vuln.description}</p>
        <p><strong>利用方法:</strong> ${vuln.exploitation}</p>
        <p><strong>修复建议:</strong> ${vuln.remediation}</p>
    </div>`;
    }

    html += `
    <h2>攻击路径</h2>
    <div class="attack-path">
        ${reportData.attackPath.join(' → ')}
    </div>

    <h2>修复建议</h2>`;

    for (const rec of reportData.recommendations) {
      html += `
    <h3>${rec.priority} - ${rec.title}</h3>
    <p>${rec.description}</p>`;
    }

    html += `
    <h2>附录</h2>
    <h3>使用的工具</h3>
    <ul>`;

    for (const tool of reportData.toolsUsed) {
      html += `<li>${tool}</li>`;
    }

    html += `
    </ul>
</body>
</html>`;

    await fs.writeFile(reportPath, html, 'utf-8');

    const stats = await fs.stat(reportPath);

    return {
      success: true,
      data: {
        reportPath,
        reportSize: stats.size
      },
      message: `HTML报告生成成功: ${reportPath}`
    };
  } catch (error) {
    return {
      success: false,
      data: null as any,
      error: `生成HTML报告失败: ${error}`
    };
  }
}

/**
 * 生成JSON格式报告
 */
export async function generateJSONReport(
  sessionDir: string,
  reportData: any
): Promise<ToolResult<{ reportPath: string; reportSize: number }>> {
  try {
    const reportPath = path.join(sessionDir, `pentest_report_${Date.now()}.json`);

    const jsonReport = {
      metadata: {
        generatedAt: new Date().toISOString(),
        target: reportData.target,
        version: '1.0'
      },
      executiveSummary: reportData.executiveSummary,
      scope: reportData.scope,
      vulnerabilities: reportData.vulnerabilities,
      attackPath: reportData.attackPath,
      recommendations: reportData.recommendations,
      toolsUsed: reportData.toolsUsed,
      statistics: {
        totalVulnerabilities: reportData.vulnerabilities.length,
        criticalCount: reportData.vulnerabilities.filter((v: any) => v.severity === 'critical').length,
        highCount: reportData.vulnerabilities.filter((v: any) => v.severity === 'high').length,
        mediumCount: reportData.vulnerabilities.filter((v: any) => v.severity === 'medium').length,
        lowCount: reportData.vulnerabilities.filter((v: any) => v.severity === 'low').length
      }
    };

    await fs.writeFile(reportPath, JSON.stringify(jsonReport, null, 2), 'utf-8');

    const stats = await fs.stat(reportPath);

    return {
      success: true,
      data: {
        reportPath,
        reportSize: stats.size
      },
      message: `JSON报告生成成功: ${reportPath}`
    };
  } catch (error) {
    return {
      success: false,
      data: null as any,
      error: `生成JSON报告失败: ${error}`
    };
  }
}

/**
 * 生成PDF格式报告（使用wkhtmltopdf）
 */
export async function generatePDFReport(
  shellId: string,
  sessionDir: string,
  htmlReportPath: string
): Promise<ToolResult<{ reportPath: string; reportSize: number }>> {
  try {
    const pdfPath = htmlReportPath.replace('.html', '.pdf');

    // 使用wkhtmltopdf将HTML转换为PDF
    const result = await executeCommand(
      shellId,
      `which wkhtmltopdf && wkhtmltopdf ${htmlReportPath} ${pdfPath} || echo "wkhtmltopdf not found"`,
      { timeout: 30000 }
    );

    if (result.output.includes('wkhtmltopdf not found')) {
      return {
        success: false,
        data: null as any,
        error: 'wkhtmltopdf工具未安装'
      };
    }

    const stats = await fs.stat(pdfPath);

    return {
      success: true,
      data: {
        reportPath: pdfPath,
        reportSize: stats.size
      },
      message: `PDF报告生成成功: ${pdfPath}`
    };
  } catch (error) {
    return {
      success: false,
      data: null as any,
      error: `生成PDF报告失败: ${error}`
    };
  }
}

/**
 * 计算漏洞风险评分
 */
export async function calculateRiskScore(
  vulnerabilities: Array<{
    severity: 'critical' | 'high' | 'medium' | 'low';
    cvss?: number;
    exploitability: 'easy' | 'medium' | 'hard';
    impact: 'high' | 'medium' | 'low';
  }>
): Promise<ToolResult<{ riskScore: number; riskLevel: string; breakdown: any }>> {
  try {
    const severityWeights = {
      critical: 10,
      high: 7,
      medium: 4,
      low: 1
    };

    const exploitabilityWeights = {
      easy: 3,
      medium: 2,
      hard: 1
    };

    const impactWeights = {
      high: 3,
      medium: 2,
      low: 1
    };

    let totalScore = 0;
    let maxScore = 0;

    for (const vuln of vulnerabilities) {
      const severityScore = severityWeights[vuln.severity];
      const exploitScore = exploitabilityWeights[vuln.exploitability];
      const impactScore = impactWeights[vuln.impact];

      const vulnScore = severityScore * exploitScore * impactScore;
      totalScore += vulnScore;
      maxScore += 10 * 3 * 3; // 最大可能分数
    }

    // 归一化到0-100
    const riskScore = vulnerabilities.length > 0 ? (totalScore / maxScore) * 100 : 0;

    let riskLevel = 'Low';
    if (riskScore >= 75) {
      riskLevel = 'Critical';
    } else if (riskScore >= 50) {
      riskLevel = 'High';
    } else if (riskScore >= 25) {
      riskLevel = 'Medium';
    }

    const breakdown = {
      totalVulnerabilities: vulnerabilities.length,
      criticalCount: vulnerabilities.filter(v => v.severity === 'critical').length,
      highCount: vulnerabilities.filter(v => v.severity === 'high').length,
      mediumCount: vulnerabilities.filter(v => v.severity === 'medium').length,
      lowCount: vulnerabilities.filter(v => v.severity === 'low').length,
      easyExploitCount: vulnerabilities.filter(v => v.exploitability === 'easy').length
    };

    return {
      success: true,
      data: {
        riskScore: Math.round(riskScore),
        riskLevel,
        breakdown
      },
      message: `风险评分计算完成: ${Math.round(riskScore)}/100 (${riskLevel})`
    };
  } catch (error) {
    return {
      success: false,
      data: null as any,
      error: `计算风险评分失败: ${error}`
    };
  }
}

/**
 * 生成攻击时间线
 */
export async function generateAttackTimeline(
  events: Array<{
    timestamp: Date;
    phase: string;
    action: string;
    result: string;
  }>
): Promise<ToolResult<{ timeline: Array<any> }>> {
  try {
    // 按时间排序
    const sortedEvents = events.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());

    const timeline = sortedEvents.map((event, index) => ({
      step: index + 1,
      timestamp: event.timestamp.toISOString(),
      phase: event.phase,
      action: event.action,
      result: event.result,
      duration: index > 0
        ? Math.round((event.timestamp.getTime() - sortedEvents[index - 1].timestamp.getTime()) / 1000)
        : 0
    }));

    return {
      success: true,
      data: { timeline },
      message: `攻击时间线生成完成: ${timeline.length} 个事件`
    };
  } catch (error) {
    return {
      success: false,
      data: null as any,
      error: `生成攻击时间线失败: ${error}`
    };
  }
}

/**
 * 生成修复优先级列表
 */
export async function generateRemediationPriority(
  vulnerabilities: Array<{
    id: string;
    title: string;
    severity: string;
    cvss?: number;
    exploitability: string;
    affectedAssets: string[];
    remediation: string;
  }>
): Promise<ToolResult<{ priorities: Array<any> }>> {
  try {
    // 计算每个漏洞的优先级分数
    const priorityScores = vulnerabilities.map(vuln => {
      let score = 0;

      // 严重程度权重
      const severityMap: { [key: string]: number } = {
        critical: 40,
        high: 30,
        medium: 20,
        low: 10
      };
      score += severityMap[vuln.severity] || 0;

      // CVSS评分权重
      if (vuln.cvss) {
        score += vuln.cvss * 3;
      }

      // 可利用性权重
      const exploitMap: { [key: string]: number } = {
        easy: 20,
        medium: 10,
        hard: 5
      };
      score += exploitMap[vuln.exploitability] || 0;

      // 影响范围权重
      score += vuln.affectedAssets.length * 2;

      return {
        ...vuln,
        priorityScore: score
      };
    });

    // 按优先级分数排序
    const sortedPriorities = priorityScores.sort((a, b) => b.priorityScore - a.priorityScore);

    const priorities = sortedPriorities.map((vuln, index) => ({
      rank: index + 1,
      id: vuln.id,
      title: vuln.title,
      severity: vuln.severity,
      priorityScore: vuln.priorityScore,
      affectedAssets: vuln.affectedAssets.length,
      remediation: vuln.remediation,
      urgency: index < 3 ? 'Immediate' : (index < 10 ? 'High' : 'Medium')
    }));

    return {
      success: true,
      data: { priorities },
      message: `修复优先级列表生成完成: ${priorities.length} 个漏洞`
    };
  } catch (error) {
    return {
      success: false,
      data: null as any,
      error: `生成修复优先级列表失败: ${error}`
    };
  }
}

/**
 * 生成漏洞分布图数据
 */
export async function generateVulnerabilityDistribution(
  vulnerabilities: Array<{
    severity: string;
    category: string;
    affectedAssets: string[];
  }>
): Promise<ToolResult<{ distribution: any }>> {
  try {
    const distribution = {
      bySeverity: {
        critical: vulnerabilities.filter(v => v.severity === 'critical').length,
        high: vulnerabilities.filter(v => v.severity === 'high').length,
        medium: vulnerabilities.filter(v => v.severity === 'medium').length,
        low: vulnerabilities.filter(v => v.severity === 'low').length
      },
      byCategory: {} as { [key: string]: number },
      byAsset: {} as { [key: string]: number }
    };

    // 按类别统计
    for (const vuln of vulnerabilities) {
      distribution.byCategory[vuln.category] = (distribution.byCategory[vuln.category] || 0) + 1;
    }

    // 按资产统计
    for (const vuln of vulnerabilities) {
      for (const asset of vuln.affectedAssets) {
        distribution.byAsset[asset] = (distribution.byAsset[asset] || 0) + 1;
      }
    }

    return {
      success: true,
      data: { distribution },
      message: '漏洞分布统计完成'
    };
  } catch (error) {
    return {
      success: false,
      data: null as any,
      error: `生成漏洞分布失败: ${error}`
    };
  }
}

/**
 * 生成合规性检查报告
 */
export async function generateComplianceReport(
  vulnerabilities: Array<any>,
  standards: string[] = ['OWASP Top 10', 'CWE Top 25', 'PCI DSS']
): Promise<ToolResult<{ compliance: any }>> {
  try {
    const compliance: { [key: string]: any } = {};

    for (const standard of standards) {
      compliance[standard] = {
        totalChecks: 10, // 简化：假设每个标准有10项检查
        passed: 0,
        failed: 0,
        findings: []
      };

      // 简化的合规性映射
      if (standard === 'OWASP Top 10') {
        const owaspCategories = ['Injection', 'Broken Authentication', 'XSS', 'XXE', 'Broken Access Control'];
        for (const category of owaspCategories) {
          const relatedVulns = vulnerabilities.filter(v => v.category === category);
          if (relatedVulns.length > 0) {
            compliance[standard].failed++;
            compliance[standard].findings.push({
              category,
              count: relatedVulns.length,
              status: 'Failed'
            });
          } else {
            compliance[standard].passed++;
          }
        }
      }
    }

    return {
      success: true,
      data: { compliance },
      message: '合规性检查报告生成完成'
    };
  } catch (error) {
    return {
      success: false,
      data: null as any,
      error: `生成合规性报告失败: ${error}`
    };
  }
}
