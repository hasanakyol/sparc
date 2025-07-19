import { PrismaClient } from '@prisma/client';
import { getPrismaClient } from '../database/prisma';
import { logger } from '../utils/logger';
import { AsyncLocalStorage } from 'async_hooks';

// Async context for audit metadata
export const auditContext = new AsyncLocalStorage<AuditContext>();

export interface AuditContext {
  userId?: string;
  tenantId?: string;
  ipAddress?: string;
  userAgent?: string;
  requestId?: string;
  sessionId?: string;
}

export interface AuditLogEntry {
  action: AuditAction;
  resourceType: ResourceType;
  resourceId: string;
  details?: Record<string, any>;
  oldValues?: Record<string, any>;
  newValues?: Record<string, any>;
  result?: 'success' | 'failure';
  errorMessage?: string;
}

export enum AuditAction {
  // Authentication
  LOGIN = 'LOGIN',
  LOGOUT = 'LOGOUT',
  LOGIN_FAILED = 'LOGIN_FAILED',
  PASSWORD_RESET = 'PASSWORD_RESET',
  PASSWORD_CHANGED = 'PASSWORD_CHANGED',
  MFA_ENABLED = 'MFA_ENABLED',
  MFA_DISABLED = 'MFA_DISABLED',
  MFA_VERIFIED = 'MFA_VERIFIED',
  
  // Resource CRUD
  CREATE = 'CREATE',
  READ = 'READ',
  UPDATE = 'UPDATE',
  DELETE = 'DELETE',
  BULK_CREATE = 'BULK_CREATE',
  BULK_UPDATE = 'BULK_UPDATE',
  BULK_DELETE = 'BULK_DELETE',
  
  // Access Control
  ACCESS_GRANTED = 'ACCESS_GRANTED',
  ACCESS_DENIED = 'ACCESS_DENIED',
  PERMISSION_GRANTED = 'PERMISSION_GRANTED',
  PERMISSION_REVOKED = 'PERMISSION_REVOKED',
  ROLE_ASSIGNED = 'ROLE_ASSIGNED',
  ROLE_REMOVED = 'ROLE_REMOVED',
  
  // Data Operations
  EXPORT = 'EXPORT',
  IMPORT = 'IMPORT',
  DOWNLOAD = 'DOWNLOAD',
  SHARE = 'SHARE',
  
  // System Operations
  CONFIG_CHANGED = 'CONFIG_CHANGED',
  INTEGRATION_CONNECTED = 'INTEGRATION_CONNECTED',
  INTEGRATION_DISCONNECTED = 'INTEGRATION_DISCONNECTED',
  BACKUP_CREATED = 'BACKUP_CREATED',
  BACKUP_RESTORED = 'BACKUP_RESTORED',
  
  // Security Events
  SECURITY_ALERT = 'SECURITY_ALERT',
  SUSPICIOUS_ACTIVITY = 'SUSPICIOUS_ACTIVITY',
  RATE_LIMIT_EXCEEDED = 'RATE_LIMIT_EXCEEDED',
  INVALID_TOKEN = 'INVALID_TOKEN',
  
  // Compliance
  DATA_RETENTION_APPLIED = 'DATA_RETENTION_APPLIED',
  DATA_PURGED = 'DATA_PURGED',
  CONSENT_GRANTED = 'CONSENT_GRANTED',
  CONSENT_REVOKED = 'CONSENT_REVOKED',
}

export enum ResourceType {
  USER = 'USER',
  ORGANIZATION = 'ORGANIZATION',
  SITE = 'SITE',
  BUILDING = 'BUILDING',
  FLOOR = 'FLOOR',
  ZONE = 'ZONE',
  DOOR = 'DOOR',
  CAMERA = 'CAMERA',
  ACCESS_EVENT = 'ACCESS_EVENT',
  ACCESS_PANEL = 'ACCESS_PANEL',
  CREDENTIAL = 'CREDENTIAL',
  ACCESS_GROUP = 'ACCESS_GROUP',
  SCHEDULE = 'SCHEDULE',
  ALERT = 'ALERT',
  VIDEO_RECORDING = 'VIDEO_RECORDING',
  VISITOR = 'VISITOR',
  INCIDENT_REPORT = 'INCIDENT_REPORT',
  SYSTEM_CONFIG = 'SYSTEM_CONFIG',
  INTEGRATION = 'INTEGRATION',
  BACKUP = 'BACKUP',
  REPORT = 'REPORT',
  API_KEY = 'API_KEY',
}

class AuditLogger {
  private prisma: PrismaClient;
  private batchQueue: AuditLogEntry[] = [];
  private batchTimer: NodeJS.Timeout | null = null;
  private readonly BATCH_SIZE = 100;
  private readonly BATCH_DELAY = 5000; // 5 seconds

  constructor() {
    this.prisma = getPrismaClient();
  }

  /**
   * Log an audit event
   */
  async log(entry: AuditLogEntry): Promise<void> {
    const context = auditContext.getStore();
    
    if (!context?.tenantId) {
      logger.warn('Audit log attempted without tenant context', { entry });
      return;
    }

    // Add to batch queue
    this.batchQueue.push(entry);

    // Process immediately if batch is full
    if (this.batchQueue.length >= this.BATCH_SIZE) {
      await this.processBatch();
    } else {
      // Schedule batch processing
      this.scheduleBatchProcessing();
    }
  }

  /**
   * Log a successful action
   */
  async logSuccess(
    action: AuditAction,
    resourceType: ResourceType,
    resourceId: string,
    details?: Record<string, any>
  ): Promise<void> {
    await this.log({
      action,
      resourceType,
      resourceId,
      details,
      result: 'success',
    });
  }

  /**
   * Log a failed action
   */
  async logFailure(
    action: AuditAction,
    resourceType: ResourceType,
    resourceId: string,
    error: string,
    details?: Record<string, any>
  ): Promise<void> {
    await this.log({
      action,
      resourceType,
      resourceId,
      details,
      result: 'failure',
      errorMessage: error,
    });
  }

  /**
   * Log a data change with before/after values
   */
  async logChange(
    action: AuditAction,
    resourceType: ResourceType,
    resourceId: string,
    oldValues: Record<string, any>,
    newValues: Record<string, any>
  ): Promise<void> {
    // Filter out sensitive fields
    const sanitizedOld = this.sanitizeData(oldValues);
    const sanitizedNew = this.sanitizeData(newValues);

    await this.log({
      action,
      resourceType,
      resourceId,
      oldValues: sanitizedOld,
      newValues: sanitizedNew,
      details: {
        changedFields: Object.keys(newValues).filter(
          key => JSON.stringify(oldValues[key]) !== JSON.stringify(newValues[key])
        ),
      },
    });
  }

  /**
   * Schedule batch processing
   */
  private scheduleBatchProcessing(): void {
    if (this.batchTimer) return;

    this.batchTimer = setTimeout(() => {
      this.processBatch().catch(err => {
        logger.error('Failed to process audit log batch', err);
      });
    }, this.BATCH_DELAY);
  }

  /**
   * Process the batch queue
   */
  private async processBatch(): Promise<void> {
    if (this.batchQueue.length === 0) return;

    // Clear timer
    if (this.batchTimer) {
      clearTimeout(this.batchTimer);
      this.batchTimer = null;
    }

    // Get batch to process
    const batch = [...this.batchQueue];
    this.batchQueue = [];

    const context = auditContext.getStore() || {};

    try {
      // Create audit log entries
      const auditLogs = batch.map(entry => ({
        tenantId: context.tenantId!,
        userId: context.userId || null,
        action: entry.action,
        resourceType: entry.resourceType,
        resourceId: entry.resourceId,
        details: {
          ...entry.details,
          oldValues: entry.oldValues,
          newValues: entry.newValues,
          result: entry.result,
          errorMessage: entry.errorMessage,
          requestId: context.requestId,
          sessionId: context.sessionId,
        },
        ipAddress: context.ipAddress || 'unknown',
        userAgent: context.userAgent || 'unknown',
        timestamp: new Date(),
      }));

      // Batch insert
      await this.prisma.auditLog.createMany({
        data: auditLogs,
        skipDuplicates: true,
      });

      logger.debug(`Processed ${auditLogs.length} audit log entries`);
    } catch (error) {
      logger.error('Failed to write audit logs', {
        error,
        batchSize: batch.length,
      });
      
      // Don't lose the logs - try to write them individually
      for (const entry of batch) {
        try {
          await this.prisma.auditLog.create({
            data: {
              tenantId: context.tenantId!,
              userId: context.userId || null,
              action: entry.action,
              resourceType: entry.resourceType,
              resourceId: entry.resourceId,
              details: {
                ...entry.details,
                oldValues: entry.oldValues,
                newValues: entry.newValues,
                result: entry.result,
                errorMessage: entry.errorMessage,
              },
              ipAddress: context.ipAddress || 'unknown',
              userAgent: context.userAgent || 'unknown',
              timestamp: new Date(),
            },
          });
        } catch (innerError) {
          logger.error('Failed to write individual audit log', {
            error: innerError,
            entry,
          });
        }
      }
    }
  }

  /**
   * Sanitize sensitive data before logging
   */
  private sanitizeData(data: Record<string, any>): Record<string, any> {
    const sensitiveFields = [
      'password',
      'passwordHash',
      'token',
      'secret',
      'apiKey',
      'privateKey',
      'creditCard',
      'ssn',
      'pinCode',
      'mfaSecret',
      'encryptionKey',
    ];

    const sanitized = { ...data };

    for (const field of sensitiveFields) {
      if (field in sanitized) {
        sanitized[field] = '[REDACTED]';
      }
    }

    // Recursively sanitize nested objects
    for (const [key, value] of Object.entries(sanitized)) {
      if (value && typeof value === 'object' && !Array.isArray(value)) {
        sanitized[key] = this.sanitizeData(value);
      }
    }

    return sanitized;
  }

  /**
   * Force flush any pending audit logs
   */
  async flush(): Promise<void> {
    if (this.batchQueue.length > 0) {
      await this.processBatch();
    }
  }

  /**
   * Query audit logs
   */
  async query(filters: {
    tenantId?: string;
    userId?: string;
    action?: AuditAction | AuditAction[];
    resourceType?: ResourceType | ResourceType[];
    resourceId?: string;
    startDate?: Date;
    endDate?: Date;
    ipAddress?: string;
    result?: 'success' | 'failure';
    limit?: number;
    offset?: number;
    orderBy?: 'timestamp' | 'action' | 'resourceType';
    order?: 'asc' | 'desc';
  }): Promise<{ logs: any[]; total: number }> {
    const where: any = {};

    if (filters.tenantId) where.tenantId = filters.tenantId;
    if (filters.userId) where.userId = filters.userId;
    if (filters.resourceId) where.resourceId = filters.resourceId;
    if (filters.ipAddress) where.ipAddress = filters.ipAddress;

    if (filters.action) {
      where.action = Array.isArray(filters.action)
        ? { in: filters.action }
        : filters.action;
    }

    if (filters.resourceType) {
      where.resourceType = Array.isArray(filters.resourceType)
        ? { in: filters.resourceType }
        : filters.resourceType;
    }

    if (filters.startDate || filters.endDate) {
      where.timestamp = {};
      if (filters.startDate) where.timestamp.gte = filters.startDate;
      if (filters.endDate) where.timestamp.lte = filters.endDate;
    }

    if (filters.result) {
      where.details = {
        path: ['result'],
        equals: filters.result,
      };
    }

    const [logs, total] = await Promise.all([
      this.prisma.auditLog.findMany({
        where,
        take: filters.limit || 100,
        skip: filters.offset || 0,
        orderBy: {
          [filters.orderBy || 'timestamp']: filters.order || 'desc',
        },
        include: {
          user: {
            select: {
              id: true,
              username: true,
              email: true,
            },
          },
        },
      }),
      this.prisma.auditLog.count({ where }),
    ]);

    return { logs, total };
  }

  /**
   * Generate audit report
   */
  async generateReport(
    tenantId: string,
    startDate: Date,
    endDate: Date,
    options?: {
      groupBy?: 'action' | 'resourceType' | 'user' | 'day';
      includeFailures?: boolean;
    }
  ): Promise<any> {
    const baseWhere = {
      tenantId,
      timestamp: {
        gte: startDate,
        lte: endDate,
      },
    };

    if (!options?.includeFailures) {
      (baseWhere as any).details = {
        path: ['result'],
        not: 'failure',
      };
    }

    // Get summary statistics
    const [
      totalEvents,
      uniqueUsers,
      topActions,
      topResources,
      failureRate,
    ] = await Promise.all([
      // Total events
      this.prisma.auditLog.count({ where: baseWhere }),
      
      // Unique users
      this.prisma.auditLog.findMany({
        where: baseWhere,
        select: { userId: true },
        distinct: ['userId'],
      }).then(r => r.filter(u => u.userId).length),
      
      // Top actions
      this.prisma.$queryRaw`
        SELECT action, COUNT(*) as count
        FROM audit_logs
        WHERE tenant_id = ${tenantId}
          AND timestamp >= ${startDate}
          AND timestamp <= ${endDate}
        GROUP BY action
        ORDER BY count DESC
        LIMIT 10
      `,
      
      // Top resources
      this.prisma.$queryRaw`
        SELECT resource_type, COUNT(*) as count
        FROM audit_logs
        WHERE tenant_id = ${tenantId}
          AND timestamp >= ${startDate}
          AND timestamp <= ${endDate}
        GROUP BY resource_type
        ORDER BY count DESC
        LIMIT 10
      `,
      
      // Failure rate
      this.prisma.$queryRaw`
        SELECT 
          COUNT(CASE WHEN details->>'result' = 'failure' THEN 1 END)::float / 
          COUNT(*)::float * 100 as failure_rate
        FROM audit_logs
        WHERE tenant_id = ${tenantId}
          AND timestamp >= ${startDate}
          AND timestamp <= ${endDate}
      `.then((r: any) => r[0]?.failure_rate || 0),
    ]);

    // Time-based grouping
    let timeBasedData;
    if (options?.groupBy === 'day') {
      timeBasedData = await this.prisma.$queryRaw`
        SELECT 
          DATE_TRUNC('day', timestamp) as date,
          COUNT(*) as count,
          COUNT(DISTINCT user_id) as unique_users
        FROM audit_logs
        WHERE tenant_id = ${tenantId}
          AND timestamp >= ${startDate}
          AND timestamp <= ${endDate}
        GROUP BY DATE_TRUNC('day', timestamp)
        ORDER BY date
      `;
    }

    return {
      summary: {
        totalEvents,
        uniqueUsers,
        failureRate: Math.round(failureRate * 100) / 100,
        dateRange: {
          start: startDate,
          end: endDate,
        },
      },
      topActions,
      topResources,
      timeBasedData,
    };
  }

  /**
   * Clean up old audit logs based on retention policy
   */
  async cleanup(retentionDays: number): Promise<number> {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - retentionDays);

    const result = await this.prisma.auditLog.deleteMany({
      where: {
        timestamp: {
          lt: cutoffDate,
        },
      },
    });

    logger.info(`Cleaned up ${result.count} audit logs older than ${retentionDays} days`);
    
    // Log the cleanup action itself
    await this.logSuccess(
      AuditAction.DATA_RETENTION_APPLIED,
      ResourceType.SYSTEM_CONFIG,
      'audit-logs',
      {
        retentionDays,
        recordsDeleted: result.count,
        cutoffDate,
      }
    );

    return result.count;
  }
}

// Export singleton instance
export const auditLogger = new AuditLogger();

// Express middleware for setting audit context
export function auditContextMiddleware(req: any, res: any, next: any) {
  const context: AuditContext = {
    userId: req.user?.id,
    tenantId: req.user?.tenantId || req.headers['x-tenant-id'],
    ipAddress: req.ip || req.connection.remoteAddress,
    userAgent: req.headers['user-agent'],
    requestId: req.id || req.headers['x-request-id'],
    sessionId: req.session?.id,
  };

  auditContext.run(context, () => {
    // Ensure logs are flushed after request
    res.on('finish', () => {
      auditLogger.flush().catch(err => {
        logger.error('Failed to flush audit logs', err);
      });
    });

    next();
  });
}