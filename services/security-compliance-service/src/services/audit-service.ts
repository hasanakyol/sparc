import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';
import { telemetry } from '@sparc/shared/telemetry';
import { 
  AuditLog, 
  AuditAction, 
  ResourceType 
} from '../types';
import { 
  AuditLogQuery, 
  AuditLogExport 
} from '../types/schemas';
import PDFDocument from 'pdfkit';
import { createObjectCsvStringifier } from 'csv-writer';

export class AuditService {
  constructor(
    private prisma: PrismaClient,
    private redis: Redis
  ) {}

  async createAuditLog(data: Omit<AuditLog, 'id' | 'timestamp'>): Promise<AuditLog> {
    return telemetry.withSpan('auditService.createAuditLog', async (span) => {
      span.setAttributes({
        'audit.action': data.action,
        'audit.resourceType': data.resourceType,
        'tenant.id': data.tenantId
      });

      const auditLog = await this.prisma.auditLog.create({
        data: {
          ...data,
          timestamp: new Date()
        }
      });

      // Publish audit event
      await this.redis.publish('audit:created', JSON.stringify(auditLog));

      // Update metrics
      await this.updateAuditMetrics(data.tenantId, data.action);

      return auditLog;
    });
  }

  async getAuditLogs(
    tenantId: string, 
    query: AuditLogQuery
  ): Promise<{
    logs: AuditLog[];
    pagination: {
      page: number;
      limit: number;
      total: number;
      pages: number;
    };
  }> {
    return telemetry.withSpan('auditService.getAuditLogs', async (span) => {
      span.setAttribute('tenant.id', tenantId);

      const where: any = { tenantId };

      // Apply filters
      if (query.startDate || query.endDate) {
        where.timestamp = {};
        if (query.startDate) where.timestamp.gte = new Date(query.startDate);
        if (query.endDate) where.timestamp.lte = new Date(query.endDate);
      }

      if (query.action) where.action = query.action;
      if (query.resourceType) where.resourceType = query.resourceType;
      if (query.userId) where.userId = query.userId;

      if (query.search) {
        where.OR = [
          { action: { contains: query.search, mode: 'insensitive' } },
          { resourceType: { contains: query.search, mode: 'insensitive' } },
          { details: { path: ['$'], string_contains: query.search } }
        ];
      }

      // Get total count
      const total = await this.prisma.auditLog.count({ where });

      // Get paginated results
      const logs = await this.prisma.auditLog.findMany({
        where,
        orderBy: { timestamp: 'desc' },
        skip: (query.page - 1) * query.limit,
        take: query.limit,
        include: {
          user: {
            select: {
              id: true,
              email: true,
              name: true
            }
          }
        }
      });

      return {
        logs,
        pagination: {
          page: query.page,
          limit: query.limit,
          total,
          pages: Math.ceil(total / query.limit)
        }
      };
    });
  }

  async getAuditLogById(tenantId: string, logId: string): Promise<AuditLog | null> {
    return this.prisma.auditLog.findFirst({
      where: {
        id: logId,
        tenantId
      },
      include: {
        user: {
          select: {
            id: true,
            email: true,
            name: true
          }
        }
      }
    });
  }

  async searchAuditLogs(
    tenantId: string, 
    searchQuery: any
  ): Promise<AuditLog[]> {
    return telemetry.withSpan('auditService.searchAuditLogs', async (span) => {
      span.setAttribute('tenant.id', tenantId);

      // Build complex search query based on input
      const where: any = { tenantId };

      // Add search conditions based on searchQuery
      // This is a simplified implementation - could be enhanced with Elasticsearch
      
      const logs = await this.prisma.auditLog.findMany({
        where,
        orderBy: { timestamp: 'desc' },
        take: 100 // Limit results
      });

      return logs;
    });
  }

  async exportAuditLogs(
    tenantId: string, 
    exportRequest: AuditLogExport
  ): Promise<Buffer> {
    return telemetry.withSpan('auditService.exportAuditLogs', async (span) => {
      span.setAttributes({
        'tenant.id': tenantId,
        'export.format': exportRequest.format
      });

      // Get audit logs for export
      const where: any = {
        tenantId,
        timestamp: {
          gte: new Date(exportRequest.startDate),
          lte: new Date(exportRequest.endDate)
        }
      };

      if (exportRequest.filters?.actions) {
        where.action = { in: exportRequest.filters.actions };
      }

      if (exportRequest.filters?.resourceTypes) {
        where.resourceType = { in: exportRequest.filters.resourceTypes };
      }

      if (exportRequest.filters?.userIds) {
        where.userId = { in: exportRequest.filters.userIds };
      }

      const logs = await this.prisma.auditLog.findMany({
        where,
        orderBy: { timestamp: 'desc' },
        include: {
          user: {
            select: {
              id: true,
              email: true,
              name: true
            }
          }
        }
      });

      span.setAttribute('export.count', logs.length);

      // Generate export based on format
      switch (exportRequest.format) {
        case 'csv':
          return this.generateCSVExport(logs);
        case 'pdf':
          return this.generatePDFExport(logs, exportRequest.framework);
        default:
          return Buffer.from(JSON.stringify(logs, null, 2));
      }
    });
  }

  async getAuditStats(tenantId: string, period: string) {
    return telemetry.withSpan('auditService.getAuditStats', async (span) => {
      span.setAttribute('tenant.id', tenantId);

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
          startDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
      }

      // Get action statistics
      const actionStats = await this.prisma.auditLog.groupBy({
        by: ['action'],
        where: {
          tenantId,
          timestamp: { gte: startDate }
        },
        _count: { action: true }
      });

      // Get resource type statistics
      const resourceStats = await this.prisma.auditLog.groupBy({
        by: ['resourceType'],
        where: {
          tenantId,
          timestamp: { gte: startDate }
        },
        _count: { resourceType: true }
      });

      // Get user activity
      const userActivity = await this.prisma.auditLog.groupBy({
        by: ['userId'],
        where: {
          tenantId,
          timestamp: { gte: startDate },
          userId: { not: null }
        },
        _count: { userId: true },
        orderBy: { _count: { userId: 'desc' } },
        take: 10
      });

      // Get hourly activity
      const hourlyActivity = await this.prisma.$queryRaw`
        SELECT 
          DATE_TRUNC('hour', timestamp) as hour,
          COUNT(*) as count
        FROM audit_logs
        WHERE tenant_id = ${tenantId}
          AND timestamp >= ${startDate}
        GROUP BY DATE_TRUNC('hour', timestamp)
        ORDER BY hour
      `;

      return {
        period,
        actions: actionStats,
        resources: resourceStats,
        topUsers: userActivity,
        hourlyActivity
      };
    });
  }

  async getRetentionStatus(tenantId: string) {
    const retentionPolicy = await this.prisma.dataRetentionPolicy.findFirst({
      where: {
        tenantId,
        dataType: 'audit_logs'
      }
    });

    const totalLogs = await this.prisma.auditLog.count({
      where: { tenantId }
    });

    const oldestLog = await this.prisma.auditLog.findFirst({
      where: { tenantId },
      orderBy: { timestamp: 'asc' }
    });

    const retentionDate = retentionPolicy
      ? new Date(Date.now() - retentionPolicy.retentionPeriodDays * 24 * 60 * 60 * 1000)
      : null;

    const logsToDelete = retentionDate
      ? await this.prisma.auditLog.count({
          where: {
            tenantId,
            timestamp: { lt: retentionDate }
          }
        })
      : 0;

    return {
      policy: retentionPolicy,
      totalLogs,
      oldestLog: oldestLog?.timestamp,
      retentionDate,
      logsToDelete
    };
  }

  private async updateAuditMetrics(tenantId: string, action: AuditAction) {
    const key = `audit:metrics:${tenantId}:${new Date().toISOString().split('T')[0]}`;
    const field = `action:${action}`;
    
    await this.redis.hincrby(key, field, 1);
    await this.redis.expire(key, 30 * 24 * 60 * 60); // 30 days
  }

  private generateCSVExport(logs: any[]): Buffer {
    const csvStringifier = createObjectCsvStringifier({
      header: [
        { id: 'timestamp', title: 'Timestamp' },
        { id: 'action', title: 'Action' },
        { id: 'resourceType', title: 'Resource Type' },
        { id: 'resourceId', title: 'Resource ID' },
        { id: 'userId', title: 'User ID' },
        { id: 'userEmail', title: 'User Email' },
        { id: 'ipAddress', title: 'IP Address' },
        { id: 'userAgent', title: 'User Agent' },
        { id: 'details', title: 'Details' }
      ]
    });

    const records = logs.map(log => ({
      timestamp: log.timestamp.toISOString(),
      action: log.action,
      resourceType: log.resourceType,
      resourceId: log.resourceId || '',
      userId: log.userId || '',
      userEmail: log.user?.email || '',
      ipAddress: log.ipAddress,
      userAgent: log.userAgent,
      details: JSON.stringify(log.details || {})
    }));

    const header = csvStringifier.getHeaderString();
    const body = csvStringifier.stringifyRecords(records);

    return Buffer.from(header + body);
  }

  private async generatePDFExport(logs: any[], framework?: string): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const doc = new PDFDocument();
      const chunks: Buffer[] = [];

      doc.on('data', chunks.push.bind(chunks));
      doc.on('end', () => resolve(Buffer.concat(chunks)));
      doc.on('error', reject);

      // Add header
      doc.fontSize(20).text('Audit Log Report', 50, 50);
      doc.fontSize(12).text(`Generated: ${new Date().toISOString()}`, 50, 80);
      
      if (framework) {
        doc.text(`Compliance Framework: ${framework}`, 50, 100);
      }

      doc.moveDown();

      // Add logs
      let y = 140;
      for (const log of logs) {
        if (y > 700) {
          doc.addPage();
          y = 50;
        }

        doc.fontSize(10);
        doc.text(`${log.timestamp.toISOString()} - ${log.action}`, 50, y);
        doc.text(`Resource: ${log.resourceType} ${log.resourceId || ''}`, 70, y + 15);
        doc.text(`User: ${log.user?.email || log.userId || 'System'}`, 70, y + 30);
        
        y += 50;
      }

      doc.end();
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