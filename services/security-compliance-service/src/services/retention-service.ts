import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';
import { telemetry } from '@sparc/shared/telemetry';
import * as cron from 'node-cron';
import {
  DataRetentionPolicy,
  RetentionRecord,
  RetentionStatus,
  DataClassification
} from '../types';
import { RetentionPolicyInput, LegalHoldInput } from '../types/schemas';

export class RetentionService {
  private scheduledJobs: Map<string, cron.ScheduledTask> = new Map();
  
  constructor(
    private prisma: PrismaClient,
    private redis: Redis,
    private defaultRetentionDays: number
  ) {}

  async startScheduledJobs(): Promise<void> {
    // Daily retention job at 2 AM
    const dailyJob = cron.schedule('0 2 * * *', async () => {
      await this.runRetentionProcess();
    });

    this.scheduledJobs.set('daily-retention', dailyJob);
    dailyJob.start();

    // Weekly compliance check
    const weeklyJob = cron.schedule('0 3 * * 0', async () => {
      await this.runComplianceCheck();
    });

    this.scheduledJobs.set('weekly-compliance', weeklyJob);
    weeklyJob.start();
  }

  async stopScheduledJobs(): Promise<void> {
    for (const [name, job] of this.scheduledJobs) {
      job.stop();
    }
    this.scheduledJobs.clear();
  }

  async getRetentionPolicies(
    tenantId: string,
    filters: { dataType?: string; classification?: string }
  ): Promise<DataRetentionPolicy[]> {
    const where: any = { tenantId };
    
    if (filters.dataType) where.dataType = filters.dataType;
    if (filters.classification) where.classification = filters.classification;

    return this.prisma.dataRetentionPolicy.findMany({
      where,
      orderBy: { dataType: 'asc' }
    });
  }

  async createRetentionPolicy(
    tenantId: string,
    userId: string,
    policy: RetentionPolicyInput
  ): Promise<DataRetentionPolicy> {
    return telemetry.withSpan('retentionService.createPolicy', async (span) => {
      span.setAttributes({
        'tenant.id': tenantId,
        'policy.dataType': policy.dataType,
        'policy.retentionDays': policy.retentionPeriodDays
      });

      // Check if policy already exists for this data type
      const existing = await this.prisma.dataRetentionPolicy.findFirst({
        where: {
          tenantId,
          dataType: policy.dataType
        }
      });

      if (existing) {
        throw new Error(`Retention policy already exists for data type: ${policy.dataType}`);
      }

      const createdPolicy = await this.prisma.dataRetentionPolicy.create({
        data: {
          tenantId,
          ...policy,
          createdAt: new Date(),
          updatedAt: new Date()
        }
      });

      // Log policy creation
      await this.prisma.auditLog.create({
        data: {
          tenantId,
          userId,
          action: 'CREATE',
          resourceType: 'DATA_RETENTION_POLICY',
          resourceId: createdPolicy.id,
          details: policy,
          ipAddress: 'system',
          userAgent: 'retention-service'
        }
      });

      return createdPolicy;
    });
  }

  async updateRetentionPolicy(
    tenantId: string,
    policyId: string,
    userId: string,
    updates: Partial<DataRetentionPolicy>
  ): Promise<DataRetentionPolicy> {
    return telemetry.withSpan('retentionService.updatePolicy', async (span) => {
      span.setAttributes({
        'tenant.id': tenantId,
        'policy.id': policyId
      });

      const updatedPolicy = await this.prisma.dataRetentionPolicy.update({
        where: {
          id: policyId,
          tenantId
        },
        data: {
          ...updates,
          updatedAt: new Date()
        }
      });

      // Log policy update
      await this.prisma.auditLog.create({
        data: {
          tenantId,
          userId,
          action: 'UPDATE',
          resourceType: 'DATA_RETENTION_POLICY',
          resourceId: policyId,
          details: updates,
          ipAddress: 'system',
          userAgent: 'retention-service'
        }
      });

      return updatedPolicy;
    });
  }

  async deleteRetentionPolicy(
    tenantId: string,
    policyId: string,
    userId: string
  ): Promise<void> {
    await this.prisma.dataRetentionPolicy.delete({
      where: {
        id: policyId,
        tenantId
      }
    });

    // Log policy deletion
    await this.prisma.auditLog.create({
      data: {
        tenantId,
        userId,
        action: 'DELETE',
        resourceType: 'DATA_RETENTION_POLICY',
        resourceId: policyId,
        ipAddress: 'system',
        userAgent: 'retention-service'
      }
    });
  }

  async getRetentionStatus(
    tenantId: string,
    dataType?: string
  ): Promise<any> {
    const where: any = { tenantId };
    if (dataType) where.dataType = dataType;

    const [
      totalRecords,
      activeRecords,
      archivedRecords,
      pendingDeletion,
      legalHolds
    ] = await Promise.all([
      this.prisma.retentionRecord.count({ where }),
      this.prisma.retentionRecord.count({
        where: { ...where, status: RetentionStatus.ACTIVE }
      }),
      this.prisma.retentionRecord.count({
        where: { ...where, status: RetentionStatus.ARCHIVED }
      }),
      this.prisma.retentionRecord.count({
        where: { ...where, status: RetentionStatus.PENDING_DELETION }
      }),
      this.prisma.retentionRecord.count({
        where: { ...where, legalHold: true }
      })
    ]);

    return {
      totalRecords,
      activeRecords,
      archivedRecords,
      pendingDeletion,
      legalHolds,
      summary: {
        retentionCompliance: ((activeRecords + archivedRecords) / totalRecords) * 100,
        deletionBacklog: pendingDeletion
      }
    };
  }

  async applyLegalHold(
    tenantId: string,
    userId: string,
    holdRequest: LegalHoldInput
  ): Promise<{ appliedCount: number }> {
    return telemetry.withSpan('retentionService.applyLegalHold', async (span) => {
      span.setAttributes({
        'tenant.id': tenantId,
        'hold.recordCount': holdRequest.recordIds.length
      });

      let appliedCount = 0;

      for (const recordId of holdRequest.recordIds) {
        const updated = await this.prisma.retentionRecord.updateMany({
          where: {
            tenantId,
            recordId,
            legalHold: false
          },
          data: {
            legalHold: true,
            legalHoldReason: holdRequest.reason,
            status: RetentionStatus.HOLD
          }
        });

        appliedCount += updated.count;
      }

      // Log legal hold application
      await this.prisma.auditLog.create({
        data: {
          tenantId,
          userId,
          action: 'CREATE',
          resourceType: 'LEGAL_HOLD',
          details: {
            recordCount: holdRequest.recordIds.length,
            appliedCount,
            reason: holdRequest.reason,
            validUntil: holdRequest.validUntil
          },
          ipAddress: 'system',
          userAgent: 'retention-service'
        }
      });

      return { appliedCount };
    });
  }

  async removeLegalHold(
    tenantId: string,
    userId: string,
    recordIds: string[]
  ): Promise<{ removedCount: number }> {
    return telemetry.withSpan('retentionService.removeLegalHold', async (span) => {
      span.setAttributes({
        'tenant.id': tenantId,
        'hold.recordCount': recordIds.length
      });

      let removedCount = 0;

      for (const recordId of recordIds) {
        const record = await this.prisma.retentionRecord.findFirst({
          where: {
            tenantId,
            recordId,
            legalHold: true
          }
        });

        if (record) {
          // Determine new status based on retention policy
          const policy = await this.prisma.dataRetentionPolicy.findFirst({
            where: {
              tenantId,
              dataType: record.dataType
            }
          });

          const newStatus = this.determineRetentionStatus(record, policy);

          await this.prisma.retentionRecord.update({
            where: { id: record.id },
            data: {
              legalHold: false,
              legalHoldReason: null,
              status: newStatus
            }
          });

          removedCount++;
        }
      }

      // Log legal hold removal
      await this.prisma.auditLog.create({
        data: {
          tenantId,
          userId,
          action: 'DELETE',
          resourceType: 'LEGAL_HOLD',
          details: {
            recordCount: recordIds.length,
            removedCount
          },
          ipAddress: 'system',
          userAgent: 'retention-service'
        }
      });

      return { removedCount };
    });
  }

  async getRecordsPendingDeletion(
    tenantId: string,
    days: number
  ): Promise<RetentionRecord[]> {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() + days);

    return this.prisma.retentionRecord.findMany({
      where: {
        tenantId,
        status: RetentionStatus.PENDING_DELETION,
        deletionScheduledAt: {
          lte: cutoffDate
        }
      },
      orderBy: { deletionScheduledAt: 'asc' },
      take: 1000
    });
  }

  async executeRetention(
    tenantId: string,
    userId: string,
    options: { dryRun?: boolean; dataType?: string }
  ): Promise<{
    processed: number;
    deleted: number;
    archived: number;
    errors: number;
  }> {
    return telemetry.withSpan('retentionService.executeRetention', async (span) => {
      span.setAttributes({
        'tenant.id': tenantId,
        'retention.dryRun': options.dryRun || false
      });

      const stats = {
        processed: 0,
        deleted: 0,
        archived: 0,
        errors: 0
      };

      // Get retention policies
      const policies = await this.getRetentionPolicies(tenantId, {
        dataType: options.dataType
      });

      for (const policy of policies) {
        try {
          const result = await this.processRetentionPolicy(
            tenantId,
            policy,
            options.dryRun || false
          );

          stats.processed += result.processed;
          stats.deleted += result.deleted;
          stats.archived += result.archived;
          stats.errors += result.errors;
        } catch (error) {
          stats.errors++;
          console.error(`Error processing retention policy ${policy.id}:`, error);
        }
      }

      // Log retention execution
      if (!options.dryRun) {
        await this.prisma.auditLog.create({
          data: {
            tenantId,
            userId,
            action: 'RETENTION_EXECUTION',
            resourceType: 'DATA_RETENTION',
            details: {
              ...stats,
              dataType: options.dataType
            },
            ipAddress: 'system',
            userAgent: 'retention-service'
          }
        });
      }

      return stats;
    });
  }

  async getRetentionDashboard(tenantId: string): Promise<any> {
    const [
      policies,
      status,
      upcomingDeletions,
      retentionHistory
    ] = await Promise.all([
      this.getRetentionPolicies(tenantId, {}),
      this.getRetentionStatus(tenantId),
      this.getRecordsPendingDeletion(tenantId, 7),
      this.getRetentionHistory(tenantId, 30)
    ]);

    return {
      policiesCount: policies.length,
      status,
      upcomingDeletions: upcomingDeletions.length,
      retentionHistory,
      dataClassificationBreakdown: await this.getDataClassificationBreakdown(tenantId)
    };
  }

  async getRetentionHistory(
    tenantId: string,
    days: number
  ): Promise<any[]> {
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);

    const history = await this.prisma.auditLog.findMany({
      where: {
        tenantId,
        action: 'RETENTION_EXECUTION',
        timestamp: { gte: startDate }
      },
      orderBy: { timestamp: 'desc' },
      take: 100
    });

    return history.map(h => ({
      date: h.timestamp,
      stats: h.details
    }));
  }

  async generateRetentionReport(
    tenantId: string,
    options: {
      format: 'pdf' | 'csv' | 'json';
      startDate?: string;
      endDate?: string;
    }
  ): Promise<Buffer> {
    const where: any = { tenantId };
    
    if (options.startDate || options.endDate) {
      where.timestamp = {};
      if (options.startDate) where.timestamp.gte = new Date(options.startDate);
      if (options.endDate) where.timestamp.lte = new Date(options.endDate);
    }

    // Get retention data
    const [policies, records, history] = await Promise.all([
      this.getRetentionPolicies(tenantId, {}),
      this.prisma.retentionRecord.findMany({ where }),
      this.prisma.auditLog.findMany({
        where: {
          ...where,
          action: { in: ['RETENTION_EXECUTION', 'DELETE'] }
        }
      })
    ]);

    // Generate report based on format
    switch (options.format) {
      case 'csv':
        return this.generateCSVReport({ policies, records, history });
      case 'pdf':
        return this.generatePDFReport({ policies, records, history });
      default:
        return Buffer.from(JSON.stringify({ policies, records, history }, null, 2));
    }
  }

  private async runRetentionProcess(): Promise<void> {
    console.log('Running scheduled retention process...');
    
    try {
      // Get all tenants
      const tenants = await this.prisma.organization.findMany({
        where: { active: true }
      });

      for (const tenant of tenants) {
        await this.executeRetention(tenant.id, 'system', { dryRun: false });
      }
    } catch (error) {
      console.error('Error in retention process:', error);
    }
  }

  private async runComplianceCheck(): Promise<void> {
    console.log('Running retention compliance check...');
    
    try {
      // Check for policies that need review
      const policiesNeedingReview = await this.prisma.dataRetentionPolicy.findMany({
        where: {
          updatedAt: {
            lt: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000) // 90 days
          }
        }
      });

      if (policiesNeedingReview.length > 0) {
        // Send notification about policies needing review
        await this.redis.publish('retention:compliance:review', JSON.stringify({
          policies: policiesNeedingReview.map(p => ({
            id: p.id,
            dataType: p.dataType,
            lastUpdated: p.updatedAt
          }))
        }));
      }
    } catch (error) {
      console.error('Error in compliance check:', error);
    }
  }

  private async processRetentionPolicy(
    tenantId: string,
    policy: DataRetentionPolicy,
    dryRun: boolean
  ): Promise<{
    processed: number;
    deleted: number;
    archived: number;
    errors: number;
  }> {
    const stats = {
      processed: 0,
      deleted: 0,
      archived: 0,
      errors: 0
    };

    const retentionDate = new Date();
    retentionDate.setDate(retentionDate.getDate() - policy.retentionPeriodDays);

    // Find records that need processing
    const records = await this.prisma.retentionRecord.findMany({
      where: {
        tenantId,
        dataType: policy.dataType,
        status: { in: [RetentionStatus.ACTIVE, RetentionStatus.ARCHIVED] },
        retentionUntil: { lte: new Date() },
        legalHold: false
      },
      take: 1000 // Process in batches
    });

    for (const record of records) {
      try {
        stats.processed++;

        if (!dryRun) {
          switch (policy.deletionMethod) {
            case 'hard':
              await this.hardDeleteRecord(record);
              stats.deleted++;
              break;
            case 'soft':
              await this.softDeleteRecord(record);
              stats.deleted++;
              break;
            case 'anonymize':
              await this.anonymizeRecord(record);
              stats.archived++;
              break;
          }
        }
      } catch (error) {
        stats.errors++;
        console.error(`Error processing record ${record.id}:`, error);
      }
    }

    return stats;
  }

  private async hardDeleteRecord(record: RetentionRecord): Promise<void> {
    // Implement actual deletion based on data type
    // This would involve calling the appropriate service
    
    await this.prisma.retentionRecord.update({
      where: { id: record.id },
      data: {
        status: RetentionStatus.DELETED,
        deletedAt: new Date()
      }
    });
  }

  private async softDeleteRecord(record: RetentionRecord): Promise<void> {
    // Implement soft deletion
    
    await this.prisma.retentionRecord.update({
      where: { id: record.id },
      data: {
        status: RetentionStatus.DELETED,
        deletedAt: new Date()
      }
    });
  }

  private async anonymizeRecord(record: RetentionRecord): Promise<void> {
    // Implement anonymization
    
    await this.prisma.retentionRecord.update({
      where: { id: record.id },
      data: {
        status: RetentionStatus.ARCHIVED,
        metadata: {
          anonymized: true,
          anonymizedAt: new Date()
        }
      }
    });
  }

  private determineRetentionStatus(
    record: RetentionRecord,
    policy: DataRetentionPolicy | null
  ): RetentionStatus {
    if (!policy) return RetentionStatus.ACTIVE;

    const retentionDate = new Date();
    retentionDate.setDate(retentionDate.getDate() - policy.retentionPeriodDays);

    if (record.createdAt < retentionDate) {
      return RetentionStatus.PENDING_DELETION;
    }

    return RetentionStatus.ACTIVE;
  }

  private async getDataClassificationBreakdown(tenantId: string) {
    const breakdown: Record<string, number> = {};

    for (const classification of Object.values(DataClassification)) {
      const count = await this.prisma.dataRetentionPolicy.count({
        where: {
          tenantId,
          classification
        }
      });
      breakdown[classification] = count;
    }

    return breakdown;
  }

  private generateCSVReport(data: any): Buffer {
    // Implement CSV generation
    const csv = 'Retention Report\n';
    return Buffer.from(csv);
  }

  private generatePDFReport(data: any): Buffer {
    // Implement PDF generation
    return Buffer.from('PDF Report');
  }
}