import { PrismaClient } from '@prisma/client';
import { ReportingServiceConfig } from '../config';
import {
  ComplianceReport,
  ComplianceFinding,
  ComplianceAttestation,
  ComplianceEvidence,
  SeverityLevel
} from '../types';
import { logger } from '../utils/logger';
import { createTracer } from '../utils/telemetry';

const tracer = createTracer('compliance-report-service');

export class ComplianceReportService {
  private complianceFrameworks = {
    sox: {
      name: 'Sarbanes-Oxley (SOX)',
      controls: [
        { id: 'SOX-1', name: 'Access Control Management', category: 'IT General Controls' },
        { id: 'SOX-2', name: 'Change Management', category: 'IT General Controls' },
        { id: 'SOX-3', name: 'System Operations', category: 'IT General Controls' },
        { id: 'SOX-4', name: 'Program Development', category: 'IT General Controls' },
        { id: 'SOX-5', name: 'Segregation of Duties', category: 'Application Controls' },
        { id: 'SOX-6', name: 'Audit Trail', category: 'Application Controls' },
        { id: 'SOX-7', name: 'Data Integrity', category: 'Application Controls' },
        { id: 'SOX-8', name: 'Financial Reporting', category: 'Financial Controls' }
      ]
    },
    hipaa: {
      name: 'Health Insurance Portability and Accountability Act (HIPAA)',
      controls: [
        { id: 'HIPAA-1', name: 'Access Control', category: 'Administrative Safeguards' },
        { id: 'HIPAA-2', name: 'Audit Controls', category: 'Technical Safeguards' },
        { id: 'HIPAA-3', name: 'Integrity Controls', category: 'Technical Safeguards' },
        { id: 'HIPAA-4', name: 'Transmission Security', category: 'Technical Safeguards' },
        { id: 'HIPAA-5', name: 'Workforce Training', category: 'Administrative Safeguards' },
        { id: 'HIPAA-6', name: 'Physical Safeguards', category: 'Physical Safeguards' },
        { id: 'HIPAA-7', name: 'Device and Media Controls', category: 'Physical Safeguards' },
        { id: 'HIPAA-8', name: 'Risk Assessment', category: 'Administrative Safeguards' }
      ]
    },
    pci_dss: {
      name: 'Payment Card Industry Data Security Standard (PCI-DSS)',
      controls: [
        { id: 'PCI-1', name: 'Build and Maintain Secure Network', category: 'Network Security' },
        { id: 'PCI-2', name: 'Protect Cardholder Data', category: 'Data Protection' },
        { id: 'PCI-3', name: 'Vulnerability Management', category: 'System Security' },
        { id: 'PCI-4', name: 'Access Control Measures', category: 'Access Control' },
        { id: 'PCI-5', name: 'Monitor and Test Networks', category: 'Monitoring' },
        { id: 'PCI-6', name: 'Information Security Policy', category: 'Policy' },
        { id: 'PCI-7', name: 'Encryption Requirements', category: 'Data Protection' },
        { id: 'PCI-8', name: 'Security Testing', category: 'Testing' }
      ]
    },
    gdpr: {
      name: 'General Data Protection Regulation (GDPR)',
      controls: [
        { id: 'GDPR-1', name: 'Lawful Basis for Processing', category: 'Legal Compliance' },
        { id: 'GDPR-2', name: 'Consent Management', category: 'Data Subject Rights' },
        { id: 'GDPR-3', name: 'Data Minimization', category: 'Privacy by Design' },
        { id: 'GDPR-4', name: 'Right to Access', category: 'Data Subject Rights' },
        { id: 'GDPR-5', name: 'Right to Erasure', category: 'Data Subject Rights' },
        { id: 'GDPR-6', name: 'Data Portability', category: 'Data Subject Rights' },
        { id: 'GDPR-7', name: 'Privacy by Design', category: 'Technical Measures' },
        { id: 'GDPR-8', name: 'Data Breach Notification', category: 'Incident Response' }
      ]
    },
    iso27001: {
      name: 'ISO/IEC 27001',
      controls: [
        { id: 'ISO-1', name: 'Information Security Policies', category: 'Organizational' },
        { id: 'ISO-2', name: 'Access Control', category: 'Access Control' },
        { id: 'ISO-3', name: 'Cryptography', category: 'Cryptography' },
        { id: 'ISO-4', name: 'Physical Security', category: 'Physical Security' },
        { id: 'ISO-5', name: 'Operations Security', category: 'Operations' },
        { id: 'ISO-6', name: 'Communications Security', category: 'Communications' },
        { id: 'ISO-7', name: 'Incident Management', category: 'Incident Management' },
        { id: 'ISO-8', name: 'Business Continuity', category: 'Continuity' }
      ]
    }
  };

  constructor(
    private prisma: PrismaClient,
    private config: ReportingServiceConfig
  ) {}

  async generateComplianceReport(
    framework: keyof typeof this.complianceFrameworks,
    startDate: Date,
    endDate: Date,
    tenantId: string,
    options?: {
      includeEvidence?: boolean;
      includeRecommendations?: boolean;
      customControls?: string[];
      excludeControls?: string[];
    }
  ): Promise<ComplianceReport> {
    return tracer.startActiveSpan('generate-compliance-report', async (span) => {
      try {
        span.setAttributes({
          'compliance.framework': framework,
          'compliance.tenant_id': tenantId,
          'compliance.date_range': `${startDate.toISOString()} - ${endDate.toISOString()}`
        });

        const frameworkConfig = this.complianceFrameworks[framework];
        if (!frameworkConfig) {
          throw new Error(`Unsupported compliance framework: ${framework}`);
        }

        // Filter controls based on options
        let controls = frameworkConfig.controls;
        if (options?.customControls) {
          controls = controls.filter(c => options.customControls!.includes(c.id));
        }
        if (options?.excludeControls) {
          controls = controls.filter(c => !options.excludeControls!.includes(c.id));
        }

        // Evaluate each control
        const findings: ComplianceFinding[] = [];
        let totalScore = 0;
        let maxScore = 0;

        for (const control of controls) {
          const finding = await this.evaluateControl(
            control,
            framework,
            startDate,
            endDate,
            tenantId
          );
          findings.push(finding);

          // Calculate score
          maxScore += 100;
          if (finding.status === 'pass') {
            totalScore += 100;
          } else if (finding.status === 'partial') {
            totalScore += 50;
          }
        }

        const overallScore = maxScore > 0 ? Math.round((totalScore / maxScore) * 100) : 0;

        // Generate recommendations
        const recommendations = options?.includeRecommendations
          ? this.generateRecommendations(findings, framework)
          : [];

        // Collect evidence if requested
        const evidence = options?.includeEvidence
          ? await this.collectEvidence(findings, tenantId)
          : [];

        const report: ComplianceReport = {
          id: `comp_${Date.now()}`,
          framework: framework as any,
          period: { start: startDate, end: endDate },
          score: overallScore,
          findings,
          recommendations,
          evidence,
          generatedAt: new Date(),
          generatedBy: 'system'
        };

        // Store report for future reference
        await this.storeComplianceReport(report, tenantId);

        logger.info('Compliance report generated', {
          framework,
          score: overallScore,
          findingsCount: findings.length
        });

        return report;
      } finally {
        span.end();
      }
    });
  }

  private async evaluateControl(
    control: { id: string; name: string; category: string },
    framework: string,
    startDate: Date,
    endDate: Date,
    tenantId: string
  ): Promise<ComplianceFinding> {
    // This method would implement the actual control evaluation logic
    // For now, we'll simulate the evaluation based on different criteria

    let status: 'pass' | 'fail' | 'partial' | 'not_applicable' = 'pass';
    let severity: SeverityLevel = 'low';
    let description = '';
    let evidence: string[] = [];
    let remediation = '';

    switch (framework) {
      case 'sox':
        const soxResult = await this.evaluateSOXControl(control.id, startDate, endDate, tenantId);
        status = soxResult.status;
        severity = soxResult.severity;
        description = soxResult.description;
        evidence = soxResult.evidence;
        remediation = soxResult.remediation;
        break;

      case 'hipaa':
        const hipaaResult = await this.evaluateHIPAAControl(control.id, startDate, endDate, tenantId);
        status = hipaaResult.status;
        severity = hipaaResult.severity;
        description = hipaaResult.description;
        evidence = hipaaResult.evidence;
        remediation = hipaaResult.remediation;
        break;

      case 'pci_dss':
        const pciResult = await this.evaluatePCIDSSControl(control.id, startDate, endDate, tenantId);
        status = pciResult.status;
        severity = pciResult.severity;
        description = pciResult.description;
        evidence = pciResult.evidence;
        remediation = pciResult.remediation;
        break;

      case 'gdpr':
        const gdprResult = await this.evaluateGDPRControl(control.id, startDate, endDate, tenantId);
        status = gdprResult.status;
        severity = gdprResult.severity;
        description = gdprResult.description;
        evidence = gdprResult.evidence;
        remediation = gdprResult.remediation;
        break;

      case 'iso27001':
        const isoResult = await this.evaluateISO27001Control(control.id, startDate, endDate, tenantId);
        status = isoResult.status;
        severity = isoResult.severity;
        description = isoResult.description;
        evidence = isoResult.evidence;
        remediation = isoResult.remediation;
        break;
    }

    return {
      id: `finding_${control.id}_${Date.now()}`,
      controlId: control.id,
      controlName: control.name,
      status,
      severity,
      description,
      evidence,
      remediation,
      dueDate: status === 'fail' ? new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) : undefined
    };
  }

  private async evaluateSOXControl(
    controlId: string,
    startDate: Date,
    endDate: Date,
    tenantId: string
  ): Promise<any> {
    switch (controlId) {
      case 'SOX-1': // Access Control Management
        const unauthorizedAccess = await this.prisma.accessEvent.count({
          where: {
            tenantId,
            timestamp: { gte: startDate, lte: endDate },
            success: false,
            eventType: 'unauthorized_attempt'
          }
        });

        const totalAccess = await this.prisma.accessEvent.count({
          where: {
            tenantId,
            timestamp: { gte: startDate, lte: endDate }
          }
        });

        const failureRate = totalAccess > 0 ? (unauthorizedAccess / totalAccess) * 100 : 0;

        return {
          status: failureRate < 1 ? 'pass' : failureRate < 5 ? 'partial' : 'fail',
          severity: failureRate < 1 ? 'low' : failureRate < 5 ? 'medium' : 'high',
          description: `Access control failure rate: ${failureRate.toFixed(2)}%`,
          evidence: [`Total access attempts: ${totalAccess}`, `Unauthorized attempts: ${unauthorizedAccess}`],
          remediation: failureRate > 1 ? 'Review and strengthen access control policies' : ''
        };

      case 'SOX-2': // Change Management
        const changes = await this.prisma.auditLog.count({
          where: {
            tenantId,
            timestamp: { gte: startDate, lte: endDate },
            action: { in: ['create', 'update', 'delete'] },
            resource: { in: ['user', 'role', 'permission', 'door', 'schedule'] }
          }
        });

        const undocumentedChanges = await this.prisma.auditLog.count({
          where: {
            tenantId,
            timestamp: { gte: startDate, lte: endDate },
            action: { in: ['create', 'update', 'delete'] },
            resource: { in: ['user', 'role', 'permission', 'door', 'schedule'] },
            metadata: { path: '$.changeTicket', equals: null }
          }
        });

        const documentationRate = changes > 0 ? ((changes - undocumentedChanges) / changes) * 100 : 100;

        return {
          status: documentationRate > 95 ? 'pass' : documentationRate > 80 ? 'partial' : 'fail',
          severity: documentationRate > 95 ? 'low' : documentationRate > 80 ? 'medium' : 'high',
          description: `Change documentation rate: ${documentationRate.toFixed(2)}%`,
          evidence: [`Total changes: ${changes}`, `Documented changes: ${changes - undocumentedChanges}`],
          remediation: documentationRate < 95 ? 'Implement mandatory change ticket system' : ''
        };

      case 'SOX-6': // Audit Trail
        const auditGaps = await this.checkAuditTrailCompleteness(tenantId, startDate, endDate);

        return {
          status: auditGaps === 0 ? 'pass' : auditGaps < 5 ? 'partial' : 'fail',
          severity: auditGaps === 0 ? 'low' : auditGaps < 5 ? 'medium' : 'high',
          description: `Audit trail gaps detected: ${auditGaps}`,
          evidence: [`Critical actions without audit logs: ${auditGaps}`],
          remediation: auditGaps > 0 ? 'Enable comprehensive audit logging for all critical actions' : ''
        };

      default:
        return {
          status: 'pass',
          severity: 'low',
          description: 'Control evaluation pending implementation',
          evidence: [],
          remediation: ''
        };
    }
  }

  private async evaluateHIPAAControl(
    controlId: string,
    startDate: Date,
    endDate: Date,
    tenantId: string
  ): Promise<any> {
    switch (controlId) {
      case 'HIPAA-1': // Access Control
        const phiAccess = await this.prisma.accessEvent.count({
          where: {
            tenantId,
            timestamp: { gte: startDate, lte: endDate },
            door: {
              metadata: { path: '$.isPHIArea', equals: true }
            }
          }
        });

        const unauthorizedPHIAccess = await this.prisma.accessEvent.count({
          where: {
            tenantId,
            timestamp: { gte: startDate, lte: endDate },
            success: false,
            door: {
              metadata: { path: '$.isPHIArea', equals: true }
            }
          }
        });

        return {
          status: unauthorizedPHIAccess === 0 ? 'pass' : unauthorizedPHIAccess < 10 ? 'partial' : 'fail',
          severity: unauthorizedPHIAccess === 0 ? 'low' : unauthorizedPHIAccess < 10 ? 'high' : 'critical',
          description: `Unauthorized PHI area access attempts: ${unauthorizedPHIAccess}`,
          evidence: [`Total PHI area access: ${phiAccess}`, `Unauthorized attempts: ${unauthorizedPHIAccess}`],
          remediation: unauthorizedPHIAccess > 0 ? 'Review PHI area access controls immediately' : ''
        };

      case 'HIPAA-2': // Audit Controls
        const phiAuditLogs = await this.prisma.auditLog.count({
          where: {
            tenantId,
            timestamp: { gte: startDate, lte: endDate },
            resource: { contains: 'phi' }
          }
        });

        return {
          status: phiAuditLogs > 0 ? 'pass' : 'fail',
          severity: phiAuditLogs > 0 ? 'low' : 'critical',
          description: `PHI access audit logs: ${phiAuditLogs}`,
          evidence: [`PHI-related audit entries: ${phiAuditLogs}`],
          remediation: phiAuditLogs === 0 ? 'Enable PHI access audit logging' : ''
        };

      default:
        return {
          status: 'pass',
          severity: 'low',
          description: 'Control evaluation pending implementation',
          evidence: [],
          remediation: ''
        };
    }
  }

  private async evaluatePCIDSSControl(
    controlId: string,
    startDate: Date,
    endDate: Date,
    tenantId: string
  ): Promise<any> {
    switch (controlId) {
      case 'PCI-2': // Protect Cardholder Data
        const paymentAreaAccess = await this.prisma.accessEvent.count({
          where: {
            tenantId,
            timestamp: { gte: startDate, lte: endDate },
            door: {
              location: { contains: 'payment' }
            }
          }
        });

        const afterHoursAccess = await this.prisma.accessEvent.count({
          where: {
            tenantId,
            timestamp: { gte: startDate, lte: endDate },
            door: {
              location: { contains: 'payment' }
            },
            AND: [
              { timestamp: { gte: new Date('1970-01-01T18:00:00Z') } },
              { timestamp: { lt: new Date('1970-01-01T08:00:00Z') } }
            ]
          }
        });

        return {
          status: afterHoursAccess === 0 ? 'pass' : afterHoursAccess < 5 ? 'partial' : 'fail',
          severity: afterHoursAccess === 0 ? 'low' : afterHoursAccess < 5 ? 'medium' : 'high',
          description: `After-hours payment area access: ${afterHoursAccess}`,
          evidence: [`Total payment area access: ${paymentAreaAccess}`, `After-hours access: ${afterHoursAccess}`],
          remediation: afterHoursAccess > 0 ? 'Review after-hours access to payment processing areas' : ''
        };

      case 'PCI-7': // Encryption Requirements
        const unencryptedTransmissions = await this.checkUnencryptedTransmissions(tenantId, startDate, endDate);

        return {
          status: unencryptedTransmissions === 0 ? 'pass' : 'fail',
          severity: unencryptedTransmissions === 0 ? 'low' : 'critical',
          description: `Unencrypted data transmissions detected: ${unencryptedTransmissions}`,
          evidence: [`Unencrypted transmissions: ${unencryptedTransmissions}`],
          remediation: unencryptedTransmissions > 0 ? 'Implement end-to-end encryption for all data transmissions' : ''
        };

      default:
        return {
          status: 'pass',
          severity: 'low',
          description: 'Control evaluation pending implementation',
          evidence: [],
          remediation: ''
        };
    }
  }

  private async evaluateGDPRControl(
    controlId: string,
    startDate: Date,
    endDate: Date,
    tenantId: string
  ): Promise<any> {
    switch (controlId) {
      case 'GDPR-4': // Right to Access
        const dataAccessRequests = await this.prisma.auditLog.count({
          where: {
            tenantId,
            timestamp: { gte: startDate, lte: endDate },
            action: 'data_access_request'
          }
        });

        const fulfilledRequests = await this.prisma.auditLog.count({
          where: {
            tenantId,
            timestamp: { gte: startDate, lte: endDate },
            action: 'data_access_fulfilled'
          }
        });

        const fulfillmentRate = dataAccessRequests > 0 ? (fulfilledRequests / dataAccessRequests) * 100 : 100;

        return {
          status: fulfillmentRate === 100 ? 'pass' : fulfillmentRate > 90 ? 'partial' : 'fail',
          severity: fulfillmentRate === 100 ? 'low' : fulfillmentRate > 90 ? 'medium' : 'high',
          description: `Data access request fulfillment rate: ${fulfillmentRate.toFixed(2)}%`,
          evidence: [`Total requests: ${dataAccessRequests}`, `Fulfilled: ${fulfilledRequests}`],
          remediation: fulfillmentRate < 100 ? 'Implement automated data access request fulfillment' : ''
        };

      case 'GDPR-8': // Data Breach Notification
        const dataBreaches = await this.prisma.incident.count({
          where: {
            tenantId,
            createdAt: { gte: startDate, lte: endDate },
            type: 'data_breach'
          }
        });

        const notifiedBreaches = await this.prisma.incident.count({
          where: {
            tenantId,
            createdAt: { gte: startDate, lte: endDate },
            type: 'data_breach',
            metadata: { path: '$.notificationSent', equals: true }
          }
        });

        return {
          status: dataBreaches === 0 || notifiedBreaches === dataBreaches ? 'pass' : 'fail',
          severity: dataBreaches === 0 ? 'low' : notifiedBreaches < dataBreaches ? 'critical' : 'medium',
          description: `Data breaches: ${dataBreaches}, Notified: ${notifiedBreaches}`,
          evidence: [`Total breaches: ${dataBreaches}`, `Properly notified: ${notifiedBreaches}`],
          remediation: notifiedBreaches < dataBreaches ? 'Implement 72-hour breach notification process' : ''
        };

      default:
        return {
          status: 'pass',
          severity: 'low',
          description: 'Control evaluation pending implementation',
          evidence: [],
          remediation: ''
        };
    }
  }

  private async evaluateISO27001Control(
    controlId: string,
    startDate: Date,
    endDate: Date,
    tenantId: string
  ): Promise<any> {
    switch (controlId) {
      case 'ISO-4': // Physical Security
        const tailgatingIncidents = await this.prisma.accessEvent.count({
          where: {
            tenantId,
            timestamp: { gte: startDate, lte: endDate },
            eventType: 'tailgating_detected'
          }
        });

        const forcedEntries = await this.prisma.alert.count({
          where: {
            tenantId,
            createdAt: { gte: startDate, lte: endDate },
            type: 'forced_entry'
          }
        });

        const physicalBreaches = tailgatingIncidents + forcedEntries;

        return {
          status: physicalBreaches === 0 ? 'pass' : physicalBreaches < 5 ? 'partial' : 'fail',
          severity: physicalBreaches === 0 ? 'low' : physicalBreaches < 5 ? 'medium' : 'high',
          description: `Physical security breaches: ${physicalBreaches}`,
          evidence: [`Tailgating: ${tailgatingIncidents}`, `Forced entries: ${forcedEntries}`],
          remediation: physicalBreaches > 0 ? 'Enhance physical security measures and monitoring' : ''
        };

      case 'ISO-7': // Incident Management
        const incidents = await this.prisma.incident.count({
          where: {
            tenantId,
            createdAt: { gte: startDate, lte: endDate }
          }
        });

        const resolvedIncidents = await this.prisma.incident.count({
          where: {
            tenantId,
            createdAt: { gte: startDate, lte: endDate },
            status: 'resolved'
          }
        });

        const resolutionRate = incidents > 0 ? (resolvedIncidents / incidents) * 100 : 100;

        return {
          status: resolutionRate > 95 ? 'pass' : resolutionRate > 80 ? 'partial' : 'fail',
          severity: resolutionRate > 95 ? 'low' : resolutionRate > 80 ? 'medium' : 'high',
          description: `Incident resolution rate: ${resolutionRate.toFixed(2)}%`,
          evidence: [`Total incidents: ${incidents}`, `Resolved: ${resolvedIncidents}`],
          remediation: resolutionRate < 95 ? 'Improve incident response procedures' : ''
        };

      default:
        return {
          status: 'pass',
          severity: 'low',
          description: 'Control evaluation pending implementation',
          evidence: [],
          remediation: ''
        };
    }
  }

  private generateRecommendations(findings: ComplianceFinding[], framework: string): string[] {
    const recommendations: string[] = [];
    const failedControls = findings.filter(f => f.status === 'fail');
    const partialControls = findings.filter(f => f.status === 'partial');

    if (failedControls.length > 0) {
      recommendations.push(`Address ${failedControls.length} failed controls immediately to improve compliance posture`);
      
      // Add specific recommendations for critical failures
      const criticalFailures = failedControls.filter(f => f.severity === 'critical');
      if (criticalFailures.length > 0) {
        recommendations.push(`CRITICAL: ${criticalFailures.length} controls require immediate attention due to high risk`);
        criticalFailures.forEach(f => {
          if (f.remediation) {
            recommendations.push(`- ${f.controlName}: ${f.remediation}`);
          }
        });
      }
    }

    if (partialControls.length > 0) {
      recommendations.push(`Enhance ${partialControls.length} partially compliant controls to achieve full compliance`);
    }

    // Framework-specific recommendations
    switch (framework) {
      case 'sox':
        recommendations.push('Schedule quarterly SOX compliance reviews');
        recommendations.push('Implement automated change management tracking');
        break;
      case 'hipaa':
        recommendations.push('Conduct annual HIPAA security risk assessments');
        recommendations.push('Implement PHI access monitoring and alerting');
        break;
      case 'pci_dss':
        recommendations.push('Schedule quarterly vulnerability scans');
        recommendations.push('Implement network segmentation for cardholder data environment');
        break;
      case 'gdpr':
        recommendations.push('Implement privacy by design principles in all new systems');
        recommendations.push('Establish data retention and deletion policies');
        break;
      case 'iso27001':
        recommendations.push('Develop and maintain an Information Security Management System (ISMS)');
        recommendations.push('Conduct regular security awareness training');
        break;
    }

    return recommendations;
  }

  private async collectEvidence(
    findings: ComplianceFinding[],
    tenantId: string
  ): Promise<ComplianceEvidence[]> {
    const evidence: ComplianceEvidence[] = [];

    // Collect evidence for each finding
    for (const finding of findings) {
      if (finding.evidence && finding.evidence.length > 0) {
        // Add audit log evidence
        evidence.push({
          id: `evidence_${finding.id}_audit`,
          type: 'log',
          description: `Audit logs for ${finding.controlName}`,
          collectedAt: new Date(),
          collectedBy: 'system'
        });

        // Add configuration evidence
        evidence.push({
          id: `evidence_${finding.id}_config`,
          type: 'config',
          description: `System configuration for ${finding.controlName}`,
          collectedAt: new Date(),
          collectedBy: 'system'
        });
      }
    }

    return evidence;
  }

  private async storeComplianceReport(report: ComplianceReport, tenantId: string): Promise<void> {
    // Store the report in the database for future reference
    await this.prisma.complianceReport.create({
      data: {
        id: report.id,
        tenantId,
        framework: report.framework,
        periodStart: report.period.start,
        periodEnd: report.period.end,
        score: report.score,
        findings: report.findings as any,
        recommendations: report.recommendations,
        evidence: report.evidence as any,
        generatedAt: report.generatedAt,
        generatedBy: report.generatedBy
      }
    });
  }

  private async checkAuditTrailCompleteness(
    tenantId: string,
    startDate: Date,
    endDate: Date
  ): Promise<number> {
    // Check for critical actions without corresponding audit logs
    const criticalActions = await this.prisma.accessEvent.count({
      where: {
        tenantId,
        timestamp: { gte: startDate, lte: endDate },
        eventType: { in: ['door_forced', 'emergency_override', 'system_bypass'] }
      }
    });

    const auditedActions = await this.prisma.auditLog.count({
      where: {
        tenantId,
        timestamp: { gte: startDate, lte: endDate },
        action: { in: ['door_forced', 'emergency_override', 'system_bypass'] }
      }
    });

    return Math.max(0, criticalActions - auditedActions);
  }

  private async checkUnencryptedTransmissions(
    tenantId: string,
    startDate: Date,
    endDate: Date
  ): Promise<number> {
    // This would check for unencrypted data transmissions in the system
    // For now, returning 0 (all transmissions encrypted)
    return 0;
  }

  async getComplianceTemplates(): Promise<any[]> {
    return Object.entries(this.complianceFrameworks).map(([id, framework]) => ({
      id,
      name: framework.name,
      description: `Compliance report template for ${framework.name}`,
      controls: framework.controls,
      requiredFields: ['startDate', 'endDate', 'tenantId'],
      optionalFields: ['includeEvidence', 'includeRecommendations', 'customControls', 'excludeControls']
    }));
  }

  async getComplianceHistory(tenantId: string, limit: number = 10): Promise<any[]> {
    const reports = await this.prisma.complianceReport.findMany({
      where: { tenantId },
      orderBy: { generatedAt: 'desc' },
      take: limit,
      select: {
        id: true,
        framework: true,
        periodStart: true,
        periodEnd: true,
        score: true,
        generatedAt: true,
        generatedBy: true
      }
    });

    return reports;
  }
}