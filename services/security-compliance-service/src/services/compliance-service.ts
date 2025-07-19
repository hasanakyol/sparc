import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';
import { telemetry } from '@sparc/shared/telemetry';
import {
  ComplianceReport,
  ComplianceFinding,
  ComplianceFramework,
  ComplianceStatus,
  ComplianceDashboard,
  Attestation,
  FrameworkStatus,
  ComplianceCheckResult
} from '../types';
import {
  ComplianceReportRequest,
  ComplianceFindingInput,
  AttestationInput,
  DashboardQuery
} from '../types/schemas';
import PDFDocument from 'pdfkit';
import { COMPLIANCE_CONTROLS } from '../config/compliance-controls';

export class ComplianceService {
  private frameworks: Map<string, any> = new Map();

  constructor(
    private prisma: PrismaClient,
    private redis: Redis
  ) {}

  async initializeFrameworks(frameworks: string[]) {
    for (const framework of frameworks) {
      if (COMPLIANCE_CONTROLS[framework]) {
        this.frameworks.set(framework, COMPLIANCE_CONTROLS[framework]);
      }
    }
  }

  async getAvailableFrameworks() {
    return Array.from(this.frameworks.keys()).map(key => ({
      id: key,
      name: COMPLIANCE_CONTROLS[key]?.name || key,
      description: COMPLIANCE_CONTROLS[key]?.description || '',
      controls: COMPLIANCE_CONTROLS[key]?.controls?.length || 0
    }));
  }

  async generateComplianceReport(
    tenantId: string,
    userId: string,
    request: ComplianceReportRequest
  ): Promise<ComplianceReport> {
    return telemetry.withSpan('complianceService.generateReport', async (span) => {
      span.setAttributes({
        'tenant.id': tenantId,
        'report.framework': request.framework
      });

      // Get compliance check results
      const checkResults = await this.getComplianceCheckResults(
        tenantId,
        request.framework,
        request.startDate,
        request.endDate
      );

      // Calculate compliance score
      const score = this.calculateComplianceScore(checkResults);

      // Generate findings
      const findings = await this.generateFindings(
        tenantId,
        request.framework,
        checkResults
      );

      // Generate recommendations
      const recommendations = this.generateRecommendations(findings);

      // Create report
      const report = await this.prisma.complianceReport.create({
        data: {
          tenantId,
          framework: request.framework,
          status: this.determineComplianceStatus(score),
          score,
          findings: findings as any,
          recommendations,
          generatedAt: new Date(),
          generatedBy: userId,
          validUntil: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000), // 90 days
          reportData: {
            startDate: request.startDate,
            endDate: request.endDate,
            includeEvidence: request.includeEvidence
          }
        }
      });

      // Generate report file if needed
      if (request.format === 'pdf') {
        const pdfBuffer = await this.generatePDFReport(report);
        await this.storeReportFile(report.id, pdfBuffer, 'pdf');
      }

      // Log report generation
      await this.prisma.auditLog.create({
        data: {
          tenantId,
          userId,
          action: 'COMPLIANCE_CHECK',
          resourceType: 'COMPLIANCE_REPORT',
          resourceId: report.id,
          details: {
            framework: request.framework,
            score,
            status: report.status
          },
          ipAddress: 'system',
          userAgent: 'compliance-service'
        }
      });

      return report;
    });
  }

  async getComplianceReports(
    tenantId: string,
    filters: { framework?: string; status?: string }
  ): Promise<ComplianceReport[]> {
    const where: any = { tenantId };
    
    if (filters.framework) {
      where.framework = filters.framework;
    }
    
    if (filters.status) {
      where.status = filters.status;
    }

    return this.prisma.complianceReport.findMany({
      where,
      orderBy: { generatedAt: 'desc' }
    });
  }

  async downloadReport(
    tenantId: string,
    reportId: string
  ): Promise<{ data: Buffer; format: string; filename: string }> {
    const report = await this.prisma.complianceReport.findFirst({
      where: { id: reportId, tenantId }
    });

    if (!report) {
      throw new Error('Report not found');
    }

    // Check if PDF exists in storage
    const pdfData = await this.getReportFile(reportId, 'pdf');
    if (pdfData) {
      return {
        data: pdfData,
        format: 'pdf',
        filename: `compliance-report-${report.framework}-${reportId}.pdf`
      };
    }

    // Generate on demand if not found
    const pdfBuffer = await this.generatePDFReport(report);
    return {
      data: pdfBuffer,
      format: 'pdf',
      filename: `compliance-report-${report.framework}-${reportId}.pdf`
    };
  }

  async getComplianceDashboard(
    tenantId: string,
    query: DashboardQuery
  ): Promise<ComplianceDashboard> {
    return telemetry.withSpan('complianceService.getDashboard', async (span) => {
      span.setAttribute('tenant.id', tenantId);

      // Get overall compliance score
      const overallScore = await this.calculateOverallComplianceScore(
        tenantId,
        query.frameworks
      );

      // Get framework statuses
      const frameworks = await this.getFrameworkStatuses(
        tenantId,
        query.frameworks
      );

      // Get recent findings
      const recentFindings = await this.getRecentFindings(
        tenantId,
        query.period
      );

      // Get upcoming audits
      const upcomingAudits = await this.getUpcomingAudits(tenantId);

      // Get compliance metrics
      const metrics = await this.getComplianceMetrics(
        tenantId,
        query.period
      );

      return {
        overallScore,
        frameworks,
        recentFindings,
        upcomingAudits,
        metrics
      };
    });
  }

  async getFrameworkStatus(
    tenantId: string,
    framework: string
  ): Promise<FrameworkStatus> {
    const latestReport = await this.prisma.complianceReport.findFirst({
      where: {
        tenantId,
        framework
      },
      orderBy: { generatedAt: 'desc' }
    });

    const criticalFindings = await this.prisma.complianceFinding.count({
      where: {
        tenantId,
        framework,
        severity: 'CRITICAL',
        status: { not: 'COMPLIANT' }
      }
    });

    return {
      framework: framework as ComplianceFramework,
      status: latestReport?.status || ComplianceStatus.PENDING,
      score: latestReport?.score || 0,
      lastAssessment: latestReport?.generatedAt || new Date(),
      nextAssessment: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000),
      criticalFindings
    };
  }

  async getComplianceFindings(
    tenantId: string,
    filters: { framework?: string; severity?: string; status?: string }
  ): Promise<ComplianceFinding[]> {
    const where: any = { tenantId };

    if (filters.framework) where.framework = filters.framework;
    if (filters.severity) where.severity = filters.severity;
    if (filters.status) where.status = filters.status;

    return this.prisma.complianceFinding.findMany({
      where,
      orderBy: [
        { severity: 'desc' },
        { createdAt: 'desc' }
      ]
    });
  }

  async createComplianceFinding(
    tenantId: string,
    userId: string,
    finding: ComplianceFindingInput
  ): Promise<ComplianceFinding> {
    const createdFinding = await this.prisma.complianceFinding.create({
      data: {
        tenantId,
        ...finding,
        createdBy: userId,
        createdAt: new Date()
      }
    });

    // Log finding creation
    await this.prisma.auditLog.create({
      data: {
        tenantId,
        userId,
        action: 'CREATE',
        resourceType: 'COMPLIANCE_REPORT',
        resourceId: createdFinding.id,
        details: finding,
        ipAddress: 'system',
        userAgent: 'compliance-service'
      }
    });

    return createdFinding;
  }

  async updateComplianceFinding(
    tenantId: string,
    findingId: string,
    userId: string,
    updates: Partial<ComplianceFinding>
  ): Promise<ComplianceFinding> {
    const updatedFinding = await this.prisma.complianceFinding.update({
      where: {
        id: findingId,
        tenantId
      },
      data: {
        ...updates,
        updatedBy: userId,
        updatedAt: new Date()
      }
    });

    // Log finding update
    await this.prisma.auditLog.create({
      data: {
        tenantId,
        userId,
        action: 'UPDATE',
        resourceType: 'COMPLIANCE_REPORT',
        resourceId: findingId,
        details: updates,
        ipAddress: 'system',
        userAgent: 'compliance-service'
      }
    });

    return updatedFinding;
  }

  async createAttestation(
    tenantId: string,
    userId: string,
    attestation: AttestationInput
  ): Promise<Attestation> {
    const created = await this.prisma.attestation.create({
      data: {
        tenantId,
        attestedBy: userId,
        attestedAt: new Date(),
        statement: attestation.statement,
        validUntil: new Date(attestation.validUntil)
      }
    });

    return created;
  }

  async runComplianceCheck(
    tenantId: string,
    framework: string,
    userId: string
  ): Promise<ComplianceCheckResult> {
    return telemetry.withSpan('complianceService.runCheck', async (span) => {
      span.setAttributes({
        'tenant.id': tenantId,
        'compliance.framework': framework
      });

      const frameworkControls = this.frameworks.get(framework);
      if (!frameworkControls) {
        throw new Error(`Framework ${framework} not supported`);
      }

      const results: ComplianceCheckResult[] = [];

      // Run checks for each control
      for (const control of frameworkControls.controls) {
        const result = await this.checkControl(tenantId, framework, control);
        results.push(result);
      }

      // Calculate overall status and score
      const compliantControls = results.filter(r => r.status === ComplianceStatus.COMPLIANT).length;
      const totalControls = results.length;
      const score = Math.round((compliantControls / totalControls) * 100);
      const status = this.determineComplianceStatus(score);

      // Store check results
      await this.storeCheckResults(tenantId, framework, results);

      return {
        framework: framework as ComplianceFramework,
        control: 'overall',
        status,
        evidence: [],
        lastChecked: new Date(),
        nextCheck: new Date(Date.now() + 24 * 60 * 60 * 1000),
        automatedCheck: true,
        score
      };
    });
  }

  async getFrameworkControls(framework: string) {
    const controls = this.frameworks.get(framework);
    if (!controls) {
      throw new Error(`Framework ${framework} not supported`);
    }

    return controls.controls;
  }

  private async checkControl(
    tenantId: string,
    framework: string,
    control: any
  ): Promise<ComplianceCheckResult> {
    // Implementation would check specific control requirements
    // This is a simplified version
    const evidence: string[] = [];
    let status = ComplianceStatus.COMPLIANT;

    // Example checks based on control type
    switch (control.type) {
      case 'access_control':
        const accessLogs = await this.checkAccessControlCompliance(tenantId);
        evidence.push(...accessLogs);
        if (accessLogs.length === 0) status = ComplianceStatus.NON_COMPLIANT;
        break;
      
      case 'encryption':
        const encryptionStatus = await this.checkEncryptionCompliance(tenantId);
        evidence.push(encryptionStatus);
        if (!encryptionStatus.includes('enabled')) status = ComplianceStatus.PARTIAL;
        break;
      
      case 'audit_logging':
        const auditStatus = await this.checkAuditLoggingCompliance(tenantId);
        evidence.push(auditStatus);
        break;
    }

    return {
      framework: framework as ComplianceFramework,
      control: control.id,
      status,
      evidence,
      lastChecked: new Date(),
      nextCheck: new Date(Date.now() + 24 * 60 * 60 * 1000),
      automatedCheck: true
    };
  }

  private async checkAccessControlCompliance(tenantId: string): Promise<string[]> {
    // Check access control policies
    const evidence: string[] = [];
    
    // Check if MFA is enabled
    const mfaEnabled = await this.redis.get(`tenant:${tenantId}:mfa:enabled`);
    if (mfaEnabled === 'true') {
      evidence.push('Multi-factor authentication is enabled');
    }

    // Check password policy
    const passwordPolicy = await this.redis.get(`tenant:${tenantId}:password:policy`);
    if (passwordPolicy) {
      evidence.push('Password policy is configured');
    }

    return evidence;
  }

  private async checkEncryptionCompliance(tenantId: string): Promise<string> {
    // Check encryption status
    const encryptionEnabled = await this.redis.get(`tenant:${tenantId}:encryption:enabled`);
    return encryptionEnabled === 'true' 
      ? 'Encryption at rest is enabled'
      : 'Encryption at rest is not enabled';
  }

  private async checkAuditLoggingCompliance(tenantId: string): Promise<string> {
    // Check if audit logging is active
    const recentLogs = await this.prisma.auditLog.count({
      where: {
        tenantId,
        timestamp: {
          gte: new Date(Date.now() - 24 * 60 * 60 * 1000)
        }
      }
    });

    return recentLogs > 0 
      ? `Audit logging is active (${recentLogs} logs in last 24h)`
      : 'No recent audit logs found';
  }

  private async getComplianceCheckResults(
    tenantId: string,
    framework: string,
    startDate: string,
    endDate: string
  ) {
    return this.prisma.complianceCheckResult.findMany({
      where: {
        tenantId,
        framework,
        lastChecked: {
          gte: new Date(startDate),
          lte: new Date(endDate)
        }
      }
    });
  }

  private calculateComplianceScore(checkResults: any[]): number {
    if (checkResults.length === 0) return 0;
    
    const compliant = checkResults.filter(r => r.status === 'COMPLIANT').length;
    return Math.round((compliant / checkResults.length) * 100);
  }

  private determineComplianceStatus(score: number): ComplianceStatus {
    if (score >= 95) return ComplianceStatus.COMPLIANT;
    if (score >= 80) return ComplianceStatus.PARTIAL;
    return ComplianceStatus.NON_COMPLIANT;
  }

  private async generateFindings(
    tenantId: string,
    framework: string,
    checkResults: any[]
  ): Promise<ComplianceFinding[]> {
    const findings: ComplianceFinding[] = [];

    for (const result of checkResults) {
      if (result.status !== 'COMPLIANT') {
        findings.push({
          id: `finding-${Date.now()}-${Math.random()}`,
          control: result.control,
          description: `Control ${result.control} is ${result.status}`,
          status: result.status,
          severity: result.status === 'NON_COMPLIANT' ? 'HIGH' : 'MEDIUM',
          evidence: result.evidence,
          remediationSteps: this.getRemediationSteps(result.control)
        });
      }
    }

    return findings;
  }

  private generateRecommendations(findings: ComplianceFinding[]): string[] {
    const recommendations: string[] = [];

    // Group findings by type and generate recommendations
    const criticalFindings = findings.filter(f => f.severity === 'CRITICAL');
    if (criticalFindings.length > 0) {
      recommendations.push(`Address ${criticalFindings.length} critical findings immediately`);
    }

    const highFindings = findings.filter(f => f.severity === 'HIGH');
    if (highFindings.length > 0) {
      recommendations.push(`Remediate ${highFindings.length} high-severity findings within 30 days`);
    }

    return recommendations;
  }

  private getRemediationSteps(control: string): string[] {
    // Return control-specific remediation steps
    // This would be defined in the compliance controls configuration
    return [
      `Review current implementation of ${control}`,
      'Update configuration to meet compliance requirements',
      'Document changes and evidence',
      'Schedule re-assessment'
    ];
  }

  private async generatePDFReport(report: any): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const doc = new PDFDocument();
      const chunks: Buffer[] = [];

      doc.on('data', chunks.push.bind(chunks));
      doc.on('end', () => resolve(Buffer.concat(chunks)));
      doc.on('error', reject);

      // Generate PDF content
      doc.fontSize(20).text(`Compliance Report - ${report.framework}`, 50, 50);
      doc.fontSize(14).text(`Generated: ${report.generatedAt}`, 50, 80);
      doc.fontSize(14).text(`Score: ${report.score}%`, 50, 100);
      doc.fontSize(14).text(`Status: ${report.status}`, 50, 120);

      // Add findings section
      doc.moveDown();
      doc.fontSize(16).text('Findings', 50, 160);
      
      let y = 190;
      for (const finding of report.findings || []) {
        doc.fontSize(12).text(`• ${finding.description}`, 70, y);
        y += 20;
      }

      doc.end();
    });
  }

  private async storeReportFile(reportId: string, data: Buffer, format: string) {
    const key = `report:${reportId}:${format}`;
    await this.redis.setex(key, 7 * 24 * 60 * 60, data); // Store for 7 days
  }

  private async getReportFile(reportId: string, format: string): Promise<Buffer | null> {
    const key = `report:${reportId}:${format}`;
    const data = await this.redis.getBuffer(key);
    return data;
  }

  private async calculateOverallComplianceScore(
    tenantId: string,
    frameworks?: ComplianceFramework[]
  ): Promise<number> {
    const scores = await Promise.all(
      (frameworks || Object.values(ComplianceFramework)).map(async (framework) => {
        const status = await this.getFrameworkStatus(tenantId, framework);
        return status.score;
      })
    );

    return Math.round(scores.reduce((sum, score) => sum + score, 0) / scores.length);
  }

  private async getFrameworkStatuses(
    tenantId: string,
    frameworks?: ComplianceFramework[]
  ): Promise<FrameworkStatus[]> {
    return Promise.all(
      (frameworks || Object.values(ComplianceFramework)).map(framework =>
        this.getFrameworkStatus(tenantId, framework)
      )
    );
  }

  private async getRecentFindings(
    tenantId: string,
    period: string
  ): Promise<ComplianceFinding[]> {
    let startDate: Date;
    switch (period) {
      case '24h':
        startDate = new Date(Date.now() - 24 * 60 * 60 * 1000);
        break;
      case '7d':
        startDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
        break;
      case '30d':
        startDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
        break;
      default:
        startDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    }

    return this.prisma.complianceFinding.findMany({
      where: {
        tenantId,
        createdAt: { gte: startDate }
      },
      orderBy: { createdAt: 'desc' },
      take: 10
    });
  }

  private async getUpcomingAudits(tenantId: string) {
    return this.prisma.scheduledAudit.findMany({
      where: {
        tenantId,
        scheduledDate: { gte: new Date() },
        status: { in: ['scheduled', 'in_progress'] }
      },
      orderBy: { scheduledDate: 'asc' },
      take: 5
    });
  }

  private async getComplianceMetrics(
    tenantId: string,
    period: string
  ) {
    const totalControls = await this.prisma.complianceCheckResult.count({
      where: { tenantId }
    });

    const compliantControls = await this.prisma.complianceCheckResult.count({
      where: {
        tenantId,
        status: 'COMPLIANT'
      }
    });

    const nonCompliantControls = await this.prisma.complianceCheckResult.count({
      where: {
        tenantId,
        status: 'NON_COMPLIANT'
      }
    });

    const partialControls = await this.prisma.complianceCheckResult.count({
      where: {
        tenantId,
        status: 'PARTIAL'
      }
    });

    // Calculate average remediation time
    const remediatedFindings = await this.prisma.complianceFinding.findMany({
      where: {
        tenantId,
        status: 'COMPLIANT',
        remediatedAt: { not: null }
      }
    });

    const avgRemediationTime = remediatedFindings.length > 0
      ? remediatedFindings.reduce((sum, f) => {
          const time = f.remediatedAt!.getTime() - f.createdAt.getTime();
          return sum + time;
        }, 0) / remediatedFindings.length / (24 * 60 * 60 * 1000) // Convert to days
      : 0;

    // Get trends for last 30 days
    const trends = await this.getComplianceTrends(tenantId, 30);

    return {
      totalControls,
      compliantControls,
      nonCompliantControls,
      partialControls,
      averageRemediationTime: Math.round(avgRemediationTime),
      trendsLast30Days: trends
    };
  }

  private async getComplianceTrends(tenantId: string, days: number) {
    const trends = [];
    const now = new Date();

    for (let i = days - 1; i >= 0; i--) {
      const date = new Date(now);
      date.setDate(date.getDate() - i);
      
      const score = await this.getComplianceScoreForDate(tenantId, date);
      trends.push({
        date: date.toISOString().split('T')[0],
        score
      });
    }

    return trends;
  }

  private async getComplianceScoreForDate(tenantId: string, date: Date): Promise<number> {
    // Get compliance score for a specific date
    // This is a simplified implementation
    const report = await this.prisma.complianceReport.findFirst({
      where: {
        tenantId,
        generatedAt: {
          gte: new Date(date.setHours(0, 0, 0, 0)),
          lt: new Date(date.setHours(23, 59, 59, 999))
        }
      }
    });

    return report?.score || 0;
  }

  private async storeCheckResults(
    tenantId: string,
    framework: string,
    results: ComplianceCheckResult[]
  ) {
    await this.prisma.complianceCheckResult.createMany({
      data: results.map(result => ({
        tenantId,
        framework,
        control: result.control,
        status: result.status,
        evidence: result.evidence,
        lastChecked: result.lastChecked,
        nextCheck: result.nextCheck,
        automatedCheck: result.automatedCheck
      }))
    });
  }

  async isHealthy(): Promise<boolean> {
    try {
      await this.prisma.$queryRaw`SELECT 1`;
      return true;
    } catch {
      return false;
    }
  }
}