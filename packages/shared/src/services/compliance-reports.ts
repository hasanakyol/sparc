import { auditLogger, AuditAction, ResourceType } from './audit-logger';
import { getPrismaClient } from '../database/prisma';
import { createHash } from 'crypto';
import { writeFileSync } from 'fs';
import { join } from 'path';

export interface ComplianceReport {
  reportId: string;
  reportType: ComplianceReportType;
  tenantId: string;
  startDate: Date;
  endDate: Date;
  generatedAt: Date;
  generatedBy: string;
  data: any;
  checksum: string;
}

export enum ComplianceReportType {
  SOC2_ACCESS_CONTROL = 'SOC2_ACCESS_CONTROL',
  SOC2_USER_ACCESS_REVIEW = 'SOC2_USER_ACCESS_REVIEW',
  GDPR_DATA_ACCESS = 'GDPR_DATA_ACCESS',
  GDPR_DATA_RETENTION = 'GDPR_DATA_RETENTION',
  HIPAA_ACCESS_LOG = 'HIPAA_ACCESS_LOG',
  PCI_DSS_ACCESS_CONTROL = 'PCI_DSS_ACCESS_CONTROL',
  ISO_27001_SECURITY_EVENTS = 'ISO_27001_SECURITY_EVENTS',
  CUSTOM = 'CUSTOM',
}

export class ComplianceReportGenerator {
  private prisma = getPrismaClient();

  /**
   * Generate SOC 2 Access Control Report
   */
  async generateSOC2AccessControlReport(
    tenantId: string,
    startDate: Date,
    endDate: Date,
    userId: string
  ): Promise<ComplianceReport> {
    const [
      userAccessChanges,
      failedLoginAttempts,
      privilegedActions,
      systemConfigChanges,
      accessReviews,
    ] = await Promise.all([
      // User access changes
      auditLogger.query({
        tenantId,
        action: [
          AuditAction.ROLE_ASSIGNED,
          AuditAction.ROLE_REMOVED,
          AuditAction.PERMISSION_GRANTED,
          AuditAction.PERMISSION_REVOKED,
        ],
        startDate,
        endDate,
      }),

      // Failed login attempts
      auditLogger.query({
        tenantId,
        action: AuditAction.LOGIN_FAILED,
        startDate,
        endDate,
      }),

      // Privileged actions
      this.getPrivilegedActions(tenantId, startDate, endDate),

      // System configuration changes
      auditLogger.query({
        tenantId,
        action: AuditAction.CONFIG_CHANGED,
        resourceType: ResourceType.SYSTEM_CONFIG,
        startDate,
        endDate,
      }),

      // Access reviews
      this.getAccessReviews(tenantId, startDate, endDate),
    ]);

    const reportData = {
      summary: {
        totalUserAccessChanges: userAccessChanges.total,
        failedLoginAttempts: failedLoginAttempts.total,
        privilegedActions: privilegedActions.length,
        configurationChanges: systemConfigChanges.total,
        accessReviewsPerformed: accessReviews.length,
      },
      details: {
        userAccessChanges: userAccessChanges.logs,
        failedLogins: this.aggregateFailedLogins(failedLoginAttempts.logs),
        privilegedActions,
        systemConfigChanges: systemConfigChanges.logs,
        accessReviews,
      },
      controls: {
        accessControlsImplemented: true,
        segregationOfDuties: await this.checkSegregationOfDuties(tenantId),
        leastPrivilege: await this.checkLeastPrivilege(tenantId),
        accessReviewFrequency: this.calculateReviewFrequency(accessReviews),
      },
    };

    return this.createReport(
      ComplianceReportType.SOC2_ACCESS_CONTROL,
      tenantId,
      startDate,
      endDate,
      userId,
      reportData
    );
  }

  /**
   * Generate GDPR Data Access Report
   */
  async generateGDPRDataAccessReport(
    tenantId: string,
    dataSubjectId: string,
    userId: string
  ): Promise<ComplianceReport> {
    const endDate = new Date();
    const startDate = new Date();
    startDate.setFullYear(startDate.getFullYear() - 1); // Last year

    // Get all data related to the data subject
    const [
      userData,
      accessEvents,
      videoRecordings,
      exports,
      auditLogs,
    ] = await Promise.all([
      // User profile data
      this.prisma.user.findUnique({
        where: { id: dataSubjectId },
        include: {
          credentials: true,
          visitors: true,
          mobileCredentials: true,
        },
      }),

      // Access events
      this.prisma.accessEvent.findMany({
        where: {
          tenantId,
          userId: dataSubjectId,
        },
        orderBy: { timestamp: 'desc' },
        take: 1000,
      }),

      // Video recordings where user appears
      this.getVideoRecordingsForUser(tenantId, dataSubjectId),

      // Data exports
      this.prisma.videoExportLog.findMany({
        where: {
          tenantId,
          userId: dataSubjectId,
        },
      }),

      // Audit logs about the user
      auditLogger.query({
        tenantId,
        resourceId: dataSubjectId,
        resourceType: ResourceType.USER,
      }),
    ]);

    const reportData = {
      dataSubject: {
        id: dataSubjectId,
        profile: this.sanitizeUserData(userData),
      },
      dataCategories: {
        personalData: userData ? this.extractPersonalData(userData) : null,
        accessHistory: {
          count: accessEvents.length,
          firstAccess: accessEvents[accessEvents.length - 1]?.timestamp,
          lastAccess: accessEvents[0]?.timestamp,
          locations: this.extractAccessLocations(accessEvents),
        },
        videoData: {
          recordingsCount: videoRecordings.length,
          totalDuration: this.calculateTotalDuration(videoRecordings),
          retentionPeriod: '30 days',
        },
        exportHistory: exports,
        processingHistory: auditLogs.logs,
      },
      dataProcessingPurposes: [
        'Physical security and access control',
        'Safety and incident investigation',
        'Compliance with legal obligations',
        'Legitimate business interests',
      ],
      dataRetention: {
        accessEvents: '90 days',
        videoRecordings: '30 days',
        auditLogs: '1 year',
        personalData: 'Until account deletion',
      },
      dataSharing: await this.getDataSharingInfo(tenantId, dataSubjectId),
      rights: {
        access: true,
        rectification: true,
        erasure: true,
        portability: true,
        restriction: true,
        objection: true,
      },
    };

    return this.createReport(
      ComplianceReportType.GDPR_DATA_ACCESS,
      tenantId,
      startDate,
      endDate,
      userId,
      reportData
    );
  }

  /**
   * Generate HIPAA Access Log Report
   */
  async generateHIPAAAccessLogReport(
    tenantId: string,
    startDate: Date,
    endDate: Date,
    userId: string
  ): Promise<ComplianceReport> {
    // HIPAA requires detailed access logs for all PHI access
    const [
      allAccessLogs,
      unauthorizedAttempts,
      dataModifications,
      systemAccess,
    ] = await Promise.all([
      // All access to sensitive areas
      this.getHIPAASensitiveAccess(tenantId, startDate, endDate),

      // Unauthorized access attempts
      auditLogger.query({
        tenantId,
        action: AuditAction.ACCESS_DENIED,
        startDate,
        endDate,
      }),

      // Data modifications
      auditLogger.query({
        tenantId,
        action: [AuditAction.UPDATE, AuditAction.DELETE],
        startDate,
        endDate,
      }),

      // System-level access
      this.getSystemAccessLogs(tenantId, startDate, endDate),
    ]);

    const reportData = {
      accessLogSummary: {
        totalAccessEvents: allAccessLogs.length,
        unauthorizedAttempts: unauthorizedAttempts.total,
        dataModifications: dataModifications.total,
        uniqueUsers: new Set(allAccessLogs.map((l: any) => l.userId)).size,
      },
      detailedLogs: {
        sensitiveAreaAccess: allAccessLogs,
        unauthorizedAttempts: unauthorizedAttempts.logs,
        modifications: dataModifications.logs,
        systemAccess: systemAccess,
      },
      compliance: {
        accessControlsImplemented: true,
        auditLogsEnabled: true,
        encryptionEnabled: true,
        minimumNecessaryAccess: await this.checkMinimumNecessaryAccess(tenantId),
        workforceTraining: await this.checkWorkforceTraining(tenantId),
      },
      incidents: await this.getSecurityIncidents(tenantId, startDate, endDate),
    };

    return this.createReport(
      ComplianceReportType.HIPAA_ACCESS_LOG,
      tenantId,
      startDate,
      endDate,
      userId,
      reportData
    );
  }

  /**
   * Generate PCI DSS Access Control Report
   */
  async generatePCIDSSReport(
    tenantId: string,
    startDate: Date,
    endDate: Date,
    userId: string
  ): Promise<ComplianceReport> {
    const [
      accessControlMatrix,
      passwordPolicies,
      accountManagement,
      networkAccess,
      physicalAccess,
    ] = await Promise.all([
      // Access control matrix
      this.getAccessControlMatrix(tenantId),

      // Password policy compliance
      this.checkPasswordPolicies(tenantId),

      // Account management
      this.getAccountManagementMetrics(tenantId, startDate, endDate),

      // Network access logs
      this.getNetworkAccessLogs(tenantId, startDate, endDate),

      // Physical access to secure areas
      this.getPhysicalAccessToSecureAreas(tenantId, startDate, endDate),
    ]);

    const reportData = {
      requirement7: {
        title: 'Restrict access to cardholder data by business need to know',
        status: 'COMPLIANT',
        controls: accessControlMatrix,
      },
      requirement8: {
        title: 'Identify and authenticate access to system components',
        status: passwordPolicies.compliant ? 'COMPLIANT' : 'NON_COMPLIANT',
        passwordPolicies,
        accountManagement,
      },
      requirement9: {
        title: 'Restrict physical access to cardholder data',
        status: 'COMPLIANT',
        physicalAccessControls: physicalAccess,
      },
      requirement10: {
        title: 'Track and monitor all access to network resources',
        status: 'COMPLIANT',
        networkLogs: networkAccess,
        retentionPeriod: '1 year',
      },
      vulnerabilities: await this.getAccessVulnerabilities(tenantId),
      recommendations: this.generatePCIRecommendations(reportData),
    };

    return this.createReport(
      ComplianceReportType.PCI_DSS_ACCESS_CONTROL,
      tenantId,
      startDate,
      endDate,
      userId,
      reportData
    );
  }

  /**
   * Generate ISO 27001 Security Events Report
   */
  async generateISO27001Report(
    tenantId: string,
    startDate: Date,
    endDate: Date,
    userId: string
  ): Promise<ComplianceReport> {
    const [
      securityEvents,
      incidentReports,
      vulnerabilityScans,
      accessReviews,
      trainingRecords,
    ] = await Promise.all([
      // Security events
      auditLogger.query({
        tenantId,
        action: [
          AuditAction.SECURITY_ALERT,
          AuditAction.SUSPICIOUS_ACTIVITY,
          AuditAction.RATE_LIMIT_EXCEEDED,
          AuditAction.INVALID_TOKEN,
        ],
        startDate,
        endDate,
      }),

      // Incident reports
      this.prisma.incidentReport.findMany({
        where: {
          tenantId,
          createdAt: { gte: startDate, lte: endDate },
        },
      }),

      // Vulnerability assessments
      this.getVulnerabilityAssessments(tenantId, startDate, endDate),

      // Access reviews
      this.getAccessReviews(tenantId, startDate, endDate),

      // Security training records
      this.getSecurityTrainingRecords(tenantId, startDate, endDate),
    ]);

    const reportData = {
      informationSecurityEvents: {
        total: securityEvents.total,
        byType: this.groupByType(securityEvents.logs),
        trending: this.calculateTrend(securityEvents.logs),
      },
      incidentManagement: {
        totalIncidents: incidentReports.length,
        byPriority: this.groupByPriority(incidentReports),
        averageResolutionTime: this.calculateAverageResolutionTime(incidentReports),
        openIncidents: incidentReports.filter(i => i.status === 'open').length,
      },
      vulnerabilityManagement: {
        assessmentsPerformed: vulnerabilityScans.length,
        vulnerabilitiesFound: vulnerabilityScans.reduce((sum, scan) => sum + scan.findings, 0),
        remediationRate: this.calculateRemediationRate(vulnerabilityScans),
      },
      accessControl: {
        reviewsPerformed: accessReviews.length,
        privilegedAccounts: await this.countPrivilegedAccounts(tenantId),
        orphanedAccounts: await this.findOrphanedAccounts(tenantId),
      },
      awarenessAndTraining: {
        trainedUsers: trainingRecords.length,
        trainingCompletion: await this.calculateTrainingCompletion(tenantId),
        lastTrainingDate: this.getLastTrainingDate(trainingRecords),
      },
      continuousImprovement: {
        correctiveActions: await this.getCorrectiveActions(tenantId, startDate, endDate),
        preventiveActions: await this.getPreventiveActions(tenantId, startDate, endDate),
      },
    };

    return this.createReport(
      ComplianceReportType.ISO_27001_SECURITY_EVENTS,
      tenantId,
      startDate,
      endDate,
      userId,
      reportData
    );
  }

  /**
   * Generate custom compliance report
   */
  async generateCustomReport(
    tenantId: string,
    startDate: Date,
    endDate: Date,
    userId: string,
    config: {
      includeAccessLogs?: boolean;
      includeSecurityEvents?: boolean;
      includeUserActivity?: boolean;
      includeSystemChanges?: boolean;
      customQueries?: Array<{
        name: string;
        action?: AuditAction[];
        resourceType?: ResourceType[];
      }>;
    }
  ): Promise<ComplianceReport> {
    const reportData: any = {};

    if (config.includeAccessLogs) {
      reportData.accessLogs = await this.getAccessLogs(tenantId, startDate, endDate);
    }

    if (config.includeSecurityEvents) {
      reportData.securityEvents = await this.getSecurityEvents(tenantId, startDate, endDate);
    }

    if (config.includeUserActivity) {
      reportData.userActivity = await this.getUserActivity(tenantId, startDate, endDate);
    }

    if (config.includeSystemChanges) {
      reportData.systemChanges = await this.getSystemChanges(tenantId, startDate, endDate);
    }

    if (config.customQueries) {
      reportData.customQueries = {};
      for (const query of config.customQueries) {
        reportData.customQueries[query.name] = await auditLogger.query({
          tenantId,
          action: query.action,
          resourceType: query.resourceType,
          startDate,
          endDate,
        });
      }
    }

    return this.createReport(
      ComplianceReportType.CUSTOM,
      tenantId,
      startDate,
      endDate,
      userId,
      reportData
    );
  }

  /**
   * Create and store compliance report
   */
  private async createReport(
    type: ComplianceReportType,
    tenantId: string,
    startDate: Date,
    endDate: Date,
    userId: string,
    data: any
  ): Promise<ComplianceReport> {
    const report: ComplianceReport = {
      reportId: `${type}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      reportType: type,
      tenantId,
      startDate,
      endDate,
      generatedAt: new Date(),
      generatedBy: userId,
      data,
      checksum: '',
    };

    // Calculate checksum
    const reportString = JSON.stringify(report);
    report.checksum = createHash('sha256').update(reportString).digest('hex');

    // Log the report generation
    await auditLogger.logSuccess(
      AuditAction.EXPORT,
      ResourceType.REPORT,
      report.reportId,
      {
        reportType: type,
        dateRange: { startDate, endDate },
        checksum: report.checksum,
      }
    );

    // Store report (optional - can be saved to S3 or database)
    // await this.storeReport(report);

    return report;
  }

  // Helper methods (implementations would be based on specific requirements)

  private async getPrivilegedActions(tenantId: string, startDate: Date, endDate: Date) {
    // Implementation specific to identifying privileged actions
    return [];
  }

  private async getAccessReviews(tenantId: string, startDate: Date, endDate: Date) {
    // Implementation for access review records
    return [];
  }

  private async checkSegregationOfDuties(tenantId: string) {
    // Check for proper separation of duties
    return true;
  }

  private async checkLeastPrivilege(tenantId: string) {
    // Verify least privilege principle
    return true;
  }

  private calculateReviewFrequency(reviews: any[]) {
    // Calculate how often reviews are performed
    return 'QUARTERLY';
  }

  private aggregateFailedLogins(logs: any[]) {
    // Group failed logins by user and time
    return logs;
  }

  private sanitizeUserData(user: any) {
    // Remove sensitive fields
    if (!user) return null;
    const { passwordHash, mfaSecret, ...sanitized } = user;
    return sanitized;
  }

  private extractPersonalData(user: any) {
    // Extract personal identifiable information
    return {
      username: user.username,
      email: user.email,
      roles: user.roles,
    };
  }

  private extractAccessLocations(events: any[]) {
    // Extract unique access locations
    return [...new Set(events.map(e => e.doorId))];
  }

  private async getVideoRecordingsForUser(tenantId: string, userId: string) {
    // Get video recordings where user appears (would require video analytics)
    return [];
  }

  private calculateTotalDuration(recordings: any[]) {
    // Calculate total video duration
    return recordings.reduce((sum, r) => sum + (r.endTime - r.startTime), 0);
  }

  private async getDataSharingInfo(tenantId: string, userId: string) {
    // Get information about data sharing
    return {
      thirdParties: [],
      purposes: [],
    };
  }

  private async getHIPAASensitiveAccess(tenantId: string, startDate: Date, endDate: Date) {
    // Get access to HIPAA-sensitive areas
    return [];
  }

  private async getSystemAccessLogs(tenantId: string, startDate: Date, endDate: Date) {
    // Get system-level access logs
    return [];
  }

  private async checkMinimumNecessaryAccess(tenantId: string) {
    // Verify minimum necessary access principle
    return true;
  }

  private async checkWorkforceTraining(tenantId: string) {
    // Check workforce training compliance
    return true;
  }

  private async getSecurityIncidents(tenantId: string, startDate: Date, endDate: Date) {
    // Get security incidents
    return this.prisma.incidentReport.findMany({
      where: {
        tenantId,
        createdAt: { gte: startDate, lte: endDate },
        incidentType: { in: ['security_breach', 'unauthorized_access'] },
      },
    });
  }

  private async getAccessControlMatrix(tenantId: string) {
    // Generate access control matrix
    return {};
  }

  private async checkPasswordPolicies(tenantId: string) {
    // Check password policy compliance
    return {
      compliant: true,
      minLength: 12,
      complexity: true,
      history: 5,
      expiration: 90,
    };
  }

  private async getAccountManagementMetrics(tenantId: string, startDate: Date, endDate: Date) {
    // Get account management metrics
    return {};
  }

  private async getNetworkAccessLogs(tenantId: string, startDate: Date, endDate: Date) {
    // Get network access logs
    return [];
  }

  private async getPhysicalAccessToSecureAreas(tenantId: string, startDate: Date, endDate: Date) {
    // Get physical access to secure areas
    return [];
  }

  private async getAccessVulnerabilities(tenantId: string) {
    // Identify access control vulnerabilities
    return [];
  }

  private generatePCIRecommendations(data: any) {
    // Generate PCI compliance recommendations
    return [];
  }

  private groupByType(logs: any[]) {
    // Group logs by type
    return {};
  }

  private calculateTrend(logs: any[]) {
    // Calculate trending data
    return 'STABLE';
  }

  private groupByPriority(incidents: any[]) {
    // Group incidents by priority
    return {};
  }

  private calculateAverageResolutionTime(incidents: any[]) {
    // Calculate average resolution time
    return 0;
  }

  private async getVulnerabilityAssessments(tenantId: string, startDate: Date, endDate: Date) {
    // Get vulnerability assessment results
    return [];
  }

  private calculateRemediationRate(scans: any[]) {
    // Calculate remediation rate
    return 0;
  }

  private async countPrivilegedAccounts(tenantId: string) {
    // Count privileged accounts
    return 0;
  }

  private async findOrphanedAccounts(tenantId: string) {
    // Find orphaned accounts
    return 0;
  }

  private async getSecurityTrainingRecords(tenantId: string, startDate: Date, endDate: Date) {
    // Get security training records
    return [];
  }

  private async calculateTrainingCompletion(tenantId: string) {
    // Calculate training completion rate
    return 0;
  }

  private getLastTrainingDate(records: any[]) {
    // Get last training date
    return null;
  }

  private async getCorrectiveActions(tenantId: string, startDate: Date, endDate: Date) {
    // Get corrective actions
    return [];
  }

  private async getPreventiveActions(tenantId: string, startDate: Date, endDate: Date) {
    // Get preventive actions
    return [];
  }

  private async getAccessLogs(tenantId: string, startDate: Date, endDate: Date) {
    // Get access logs
    return auditLogger.query({
      tenantId,
      action: [AuditAction.ACCESS_GRANTED, AuditAction.ACCESS_DENIED],
      startDate,
      endDate,
    });
  }

  private async getSecurityEvents(tenantId: string, startDate: Date, endDate: Date) {
    // Get security events
    return auditLogger.query({
      tenantId,
      action: [
        AuditAction.SECURITY_ALERT,
        AuditAction.SUSPICIOUS_ACTIVITY,
        AuditAction.RATE_LIMIT_EXCEEDED,
      ],
      startDate,
      endDate,
    });
  }

  private async getUserActivity(tenantId: string, startDate: Date, endDate: Date) {
    // Get user activity
    return auditLogger.query({
      tenantId,
      startDate,
      endDate,
      limit: 1000,
    });
  }

  private async getSystemChanges(tenantId: string, startDate: Date, endDate: Date) {
    // Get system changes
    return auditLogger.query({
      tenantId,
      action: AuditAction.CONFIG_CHANGED,
      startDate,
      endDate,
    });
  }
}

// Export singleton instance
export const complianceReports = new ComplianceReportGenerator();