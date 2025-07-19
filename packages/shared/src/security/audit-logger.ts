/**
 * Comprehensive Audit Logging Service for SPARC Platform
 * Provides centralized security audit logging with compliance support
 */

import { Context } from 'hono';
import { z } from 'zod';
import crypto from 'crypto';
import { OpenSearch } from '@opensearch-project/opensearch';
import Redis from 'ioredis';

// Audit event types
export enum AuditEventType {
  // Authentication events
  AUTH_LOGIN_SUCCESS = 'auth.login.success',
  AUTH_LOGIN_FAILURE = 'auth.login.failure',
  AUTH_LOGOUT = 'auth.logout',
  AUTH_TOKEN_REFRESH = 'auth.token.refresh',
  AUTH_MFA_SUCCESS = 'auth.mfa.success',
  AUTH_MFA_FAILURE = 'auth.mfa.failure',
  AUTH_PASSWORD_CHANGE = 'auth.password.change',
  AUTH_PASSWORD_RESET = 'auth.password.reset',
  
  // Authorization events
  AUTHZ_ACCESS_GRANTED = 'authz.access.granted',
  AUTHZ_ACCESS_DENIED = 'authz.access.denied',
  AUTHZ_PRIVILEGE_ESCALATION = 'authz.privilege.escalation',
  AUTHZ_ROLE_ASSIGNMENT = 'authz.role.assignment',
  
  // Data access events
  DATA_READ = 'data.read',
  DATA_CREATE = 'data.create',
  DATA_UPDATE = 'data.update',
  DATA_DELETE = 'data.delete',
  DATA_EXPORT = 'data.export',
  DATA_IMPORT = 'data.import',
  
  // System events
  SYSTEM_CONFIG_CHANGE = 'system.config.change',
  SYSTEM_SERVICE_START = 'system.service.start',
  SYSTEM_SERVICE_STOP = 'system.service.stop',
  SYSTEM_ERROR = 'system.error',
  SYSTEM_SECURITY_ALERT = 'system.security.alert',
  
  // Video events
  VIDEO_ACCESS = 'video.access',
  VIDEO_DOWNLOAD = 'video.download',
  VIDEO_DELETE = 'video.delete',
  VIDEO_SHARE = 'video.share',
  
  // Incident events
  INCIDENT_CREATE = 'incident.create',
  INCIDENT_UPDATE = 'incident.update',
  INCIDENT_ESCALATE = 'incident.escalate',
  INCIDENT_CLOSE = 'incident.close',
  
  // Compliance events
  COMPLIANCE_VIOLATION = 'compliance.violation',
  COMPLIANCE_AUDIT_ACCESS = 'compliance.audit.access',
  COMPLIANCE_DATA_RETENTION = 'compliance.data.retention',
  COMPLIANCE_DATA_DELETION = 'compliance.data.deletion',
}

// Severity levels
export enum AuditSeverity {
  INFO = 'info',
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical',
}

// Audit log schema
export const auditLogSchema = z.object({
  id: z.string().uuid(),
  timestamp: z.date(),
  eventType: z.nativeEnum(AuditEventType),
  severity: z.nativeEnum(AuditSeverity),
  
  // Actor information
  actor: z.object({
    type: z.enum(['user', 'service', 'system', 'anonymous']),
    id: z.string().optional(),
    name: z.string().optional(),
    email: z.string().email().optional(),
    tenantId: z.string().uuid().optional(),
    organizationId: z.string().uuid().optional(),
    roles: z.array(z.string()).optional(),
  }),
  
  // Target resource
  target: z.object({
    type: z.string(),
    id: z.string().optional(),
    name: z.string().optional(),
    path: z.string().optional(),
    tenantId: z.string().uuid().optional(),
  }).optional(),
  
  // Action details
  action: z.object({
    method: z.string(),
    operation: z.string(),
    result: z.enum(['success', 'failure', 'error']),
    reason: z.string().optional(),
    errorCode: z.string().optional(),
  }),
  
  // Request context
  context: z.object({
    ip: z.string(),
    userAgent: z.string().optional(),
    sessionId: z.string().optional(),
    correlationId: z.string().uuid(),
    requestId: z.string().uuid(),
    deviceId: z.string().optional(),
    location: z.object({
      country: z.string().optional(),
      city: z.string().optional(),
      latitude: z.number().optional(),
      longitude: z.number().optional(),
    }).optional(),
  }),
  
  // Data changes (for update operations)
  changes: z.object({
    before: z.record(z.unknown()).optional(),
    after: z.record(z.unknown()).optional(),
    fields: z.array(z.string()).optional(),
  }).optional(),
  
  // Compliance metadata
  compliance: z.object({
    standards: z.array(z.string()),
    retention: z.number(), // days
    encrypted: z.boolean(),
    dataClassification: z.enum(['public', 'internal', 'confidential', 'restricted']),
    gdprRelevant: z.boolean().optional(),
    piiPresent: z.boolean().optional(),
  }),
  
  // Additional metadata
  metadata: z.record(z.unknown()).optional(),
  
  // Integrity
  hash: z.string(), // SHA-256 hash of the log entry
  signature: z.string().optional(), // Digital signature for non-repudiation
});

export type AuditLog = z.infer<typeof auditLogSchema>;

/**
 * Audit Logger Configuration
 */
export interface AuditLoggerConfig {
  opensearch: {
    node: string;
    auth?: {
      username: string;
      password: string;
    };
    index: string;
  };
  redis?: Redis;
  encryption?: {
    enabled: boolean;
    keyId: string;
  };
  signing?: {
    enabled: boolean;
    privateKey: string;
  };
  retention?: {
    defaultDays: number;
    complianceOverrides: Record<string, number>;
  };
  alerts?: {
    enabled: boolean;
    thresholds: Record<AuditEventType, number>;
    webhooks: string[];
  };
}

/**
 * Centralized Audit Logger
 */
export class AuditLogger {
  private opensearch: OpenSearch;
  private redis?: Redis;
  private config: AuditLoggerConfig;
  private signingKey?: crypto.KeyObject;

  constructor(config: AuditLoggerConfig) {
    this.config = config;
    
    // Initialize OpenSearch client
    this.opensearch = new OpenSearch({
      node: config.opensearch.node,
      auth: config.opensearch.auth,
      ssl: {
        rejectUnauthorized: process.env.NODE_ENV === 'production',
      },
    });
    
    this.redis = config.redis;
    
    // Initialize signing key if enabled
    if (config.signing?.enabled && config.signing.privateKey) {
      this.signingKey = crypto.createPrivateKey(config.signing.privateKey);
    }
  }

  /**
   * Log an audit event
   */
  async log(event: Partial<AuditLog>, context?: Context): Promise<void> {
    try {
      // Build complete audit log entry
      const auditLog = await this.buildAuditLog(event, context);
      
      // Validate the log entry
      const validated = auditLogSchema.parse(auditLog);
      
      // Store in OpenSearch
      await this.storeLog(validated);
      
      // Check for alerts
      await this.checkAlerts(validated);
      
      // Cache recent events for real-time monitoring
      if (this.redis) {
        await this.cacheRecentEvent(validated);
      }
      
    } catch (error) {
      console.error('Audit logging error:', error);
      // Audit logging should never break the application
      // Consider sending to a backup location
    }
  }

  /**
   * Build complete audit log entry
   */
  private async buildAuditLog(
    event: Partial<AuditLog>,
    context?: Context
  ): Promise<AuditLog> {
    const id = crypto.randomUUID();
    const timestamp = new Date();
    const correlationId = context?.get('correlationId') || crypto.randomUUID();
    const requestId = context?.get('requestId') || crypto.randomUUID();
    
    // Extract actor information from context
    const actor = event.actor || {
      type: 'anonymous' as const,
      id: context?.get('userId'),
      email: context?.get('userEmail'),
      tenantId: context?.get('tenantId'),
      organizationId: context?.get('organizationId'),
      roles: context?.get('userRoles'),
    };
    
    // Extract request context
    const requestContext = {
      ip: this.getClientIP(context) || 'unknown',
      userAgent: context?.req.header('user-agent'),
      sessionId: context?.get('sessionId'),
      correlationId,
      requestId,
      deviceId: context?.req.header('x-device-id'),
      location: await this.getGeoLocation(this.getClientIP(context)),
    };
    
    // Determine compliance requirements
    const compliance = this.determineCompliance(event);
    
    // Build the log entry
    const logEntry: Omit<AuditLog, 'hash' | 'signature'> = {
      id,
      timestamp,
      eventType: event.eventType || AuditEventType.SYSTEM_ERROR,
      severity: event.severity || AuditSeverity.INFO,
      actor,
      target: event.target,
      action: event.action || {
        method: context?.req.method || 'UNKNOWN',
        operation: 'unknown',
        result: 'error',
      },
      context: requestContext,
      changes: event.changes,
      compliance,
      metadata: event.metadata,
    };
    
    // Calculate hash for integrity
    const hash = this.calculateHash(logEntry);
    
    // Sign the log entry if configured
    const signature = this.config.signing?.enabled 
      ? this.signLog(logEntry, hash)
      : undefined;
    
    return {
      ...logEntry,
      hash,
      signature,
    };
  }

  /**
   * Store log in OpenSearch
   */
  private async storeLog(log: AuditLog): Promise<void> {
    const index = `${this.config.opensearch.index}-${log.timestamp.toISOString().slice(0, 7)}`; // Monthly indices
    
    await this.opensearch.index({
      index,
      body: {
        ...log,
        '@timestamp': log.timestamp.toISOString(),
      },
      refresh: log.severity === AuditSeverity.CRITICAL ? 'true' : 'false',
    });
  }

  /**
   * Check if alerts should be triggered
   */
  private async checkAlerts(log: AuditLog): Promise<void> {
    if (!this.config.alerts?.enabled) return;
    
    const threshold = this.config.alerts.thresholds[log.eventType];
    if (!threshold) return;
    
    // Count recent events of this type
    const count = await this.countRecentEvents(log.eventType, 300); // 5 minutes
    
    if (count >= threshold) {
      await this.sendAlert({
        eventType: log.eventType,
        count,
        threshold,
        severity: log.severity,
        log,
      });
    }
  }

  /**
   * Count recent events of a specific type
   */
  private async countRecentEvents(
    eventType: AuditEventType,
    seconds: number
  ): Promise<number> {
    if (!this.redis) return 0;
    
    const key = `audit:count:${eventType}`;
    const now = Date.now();
    const windowStart = now - (seconds * 1000);
    
    // Remove old entries and count current ones
    await this.redis.zremrangebyscore(key, '-inf', windowStart);
    const count = await this.redis.zcard(key);
    
    // Add current event
    await this.redis.zadd(key, now, now);
    await this.redis.expire(key, seconds + 60);
    
    return count + 1;
  }

  /**
   * Send security alert
   */
  private async sendAlert(alert: any): Promise<void> {
    console.warn('Security Alert:', alert);
    
    // Send to configured webhooks
    for (const webhook of this.config.alerts?.webhooks || []) {
      try {
        await fetch(webhook, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            type: 'security_alert',
            timestamp: new Date().toISOString(),
            alert,
          }),
        });
      } catch (error) {
        console.error('Failed to send alert to webhook:', webhook, error);
      }
    }
  }

  /**
   * Cache recent event for real-time monitoring
   */
  private async cacheRecentEvent(log: AuditLog): Promise<void> {
    if (!this.redis) return;
    
    const key = 'audit:recent';
    const ttl = 3600; // 1 hour
    
    await this.redis.zadd(key, log.timestamp.getTime(), JSON.stringify({
      id: log.id,
      eventType: log.eventType,
      severity: log.severity,
      actor: log.actor,
      timestamp: log.timestamp,
    }));
    
    // Keep only last 1000 events
    await this.redis.zremrangebyrank(key, 0, -1001);
    await this.redis.expire(key, ttl);
  }

  /**
   * Calculate hash for log integrity
   */
  private calculateHash(log: Omit<AuditLog, 'hash' | 'signature'>): string {
    const content = JSON.stringify(log, Object.keys(log).sort());
    return crypto.createHash('sha256').update(content).digest('hex');
  }

  /**
   * Sign log entry for non-repudiation
   */
  private signLog(
    log: Omit<AuditLog, 'hash' | 'signature'>,
    hash: string
  ): string | undefined {
    if (!this.signingKey) return undefined;
    
    const sign = crypto.createSign('SHA256');
    sign.update(hash);
    return sign.sign(this.signingKey, 'base64');
  }

  /**
   * Determine compliance requirements for the event
   */
  private determineCompliance(event: Partial<AuditLog>): AuditLog['compliance'] {
    const standards: string[] = ['SOC2'];
    let retention = this.config.retention?.defaultDays || 2555; // 7 years default
    let dataClassification: AuditLog['compliance']['dataClassification'] = 'internal';
    let gdprRelevant = false;
    let piiPresent = false;
    
    // Check event type for compliance requirements
    switch (event.eventType) {
      case AuditEventType.AUTH_LOGIN_SUCCESS:
      case AuditEventType.AUTH_LOGIN_FAILURE:
      case AuditEventType.AUTH_PASSWORD_CHANGE:
        standards.push('ISO27001', 'PCI-DSS');
        dataClassification = 'confidential';
        gdprRelevant = true;
        piiPresent = true;
        break;
        
      case AuditEventType.DATA_DELETE:
      case AuditEventType.COMPLIANCE_DATA_DELETION:
        standards.push('GDPR');
        gdprRelevant = true;
        retention = 365; // 1 year for deletion logs
        break;
        
      case AuditEventType.VIDEO_ACCESS:
      case AuditEventType.VIDEO_DOWNLOAD:
        standards.push('CCTV-CoP');
        dataClassification = 'restricted';
        retention = 31; // 31 days for video access logs
        break;
        
      case AuditEventType.INCIDENT_CREATE:
      case AuditEventType.INCIDENT_UPDATE:
        standards.push('ISO27001');
        dataClassification = 'confidential';
        retention = 1095; // 3 years for incident logs
        break;
    }
    
    // Check for compliance overrides
    if (this.config.retention?.complianceOverrides) {
      for (const [standard, days] of Object.entries(this.config.retention.complianceOverrides)) {
        if (standards.includes(standard)) {
          retention = Math.max(retention, days);
        }
      }
    }
    
    return {
      standards,
      retention,
      encrypted: this.config.encryption?.enabled || false,
      dataClassification,
      gdprRelevant,
      piiPresent,
    };
  }

  /**
   * Get client IP address
   */
  private getClientIP(context?: Context): string | null {
    if (!context) return null;
    
    return context.req.header('x-forwarded-for')?.split(',')[0].trim() ||
           context.req.header('x-real-ip') ||
           context.req.header('cf-connecting-ip') ||
           null;
  }

  /**
   * Get geo-location from IP (placeholder - implement with real service)
   */
  private async getGeoLocation(ip: string | null): Promise<AuditLog['context']['location']> {
    if (!ip || ip === 'unknown') return undefined;
    
    // TODO: Implement with real geo-location service (MaxMind, etc.)
    return undefined;
  }

  /**
   * Query audit logs
   */
  async query(params: {
    startDate?: Date;
    endDate?: Date;
    eventTypes?: AuditEventType[];
    severity?: AuditSeverity[];
    actorId?: string;
    targetId?: string;
    tenantId?: string;
    limit?: number;
    offset?: number;
  }): Promise<{ logs: AuditLog[]; total: number }> {
    const must: any[] = [];
    
    // Date range
    if (params.startDate || params.endDate) {
      must.push({
        range: {
          timestamp: {
            gte: params.startDate?.toISOString(),
            lte: params.endDate?.toISOString(),
          },
        },
      });
    }
    
    // Event types
    if (params.eventTypes?.length) {
      must.push({
        terms: { eventType: params.eventTypes },
      });
    }
    
    // Severity
    if (params.severity?.length) {
      must.push({
        terms: { severity: params.severity },
      });
    }
    
    // Actor
    if (params.actorId) {
      must.push({
        term: { 'actor.id': params.actorId },
      });
    }
    
    // Target
    if (params.targetId) {
      must.push({
        term: { 'target.id': params.targetId },
      });
    }
    
    // Tenant
    if (params.tenantId) {
      must.push({
        bool: {
          should: [
            { term: { 'actor.tenantId': params.tenantId } },
            { term: { 'target.tenantId': params.tenantId } },
          ],
        },
      });
    }
    
    const response = await this.opensearch.search({
      index: `${this.config.opensearch.index}-*`,
      body: {
        query: must.length ? { bool: { must } } : { match_all: {} },
        sort: [{ timestamp: { order: 'desc' } }],
        size: params.limit || 100,
        from: params.offset || 0,
      },
    });
    
    const logs = response.body.hits.hits.map((hit: any) => hit._source as AuditLog);
    const total = response.body.hits.total.value;
    
    return { logs, total };
  }

  /**
   * Verify log integrity
   */
  async verifyIntegrity(logId: string): Promise<boolean> {
    const response = await this.opensearch.search({
      index: `${this.config.opensearch.index}-*`,
      body: {
        query: { term: { id: logId } },
      },
    });
    
    if (response.body.hits.hits.length === 0) {
      return false;
    }
    
    const log = response.body.hits.hits[0]._source as AuditLog;
    const { hash, signature, ...logData } = log;
    
    // Verify hash
    const calculatedHash = this.calculateHash(logData);
    if (calculatedHash !== hash) {
      return false;
    }
    
    // Verify signature if present
    if (signature && this.signingKey) {
      const verify = crypto.createVerify('SHA256');
      verify.update(hash);
      
      try {
        return verify.verify(this.signingKey, signature, 'base64');
      } catch {
        return false;
      }
    }
    
    return true;
  }

  /**
   * Export logs for compliance
   */
  async exportLogs(params: {
    startDate: Date;
    endDate: Date;
    format: 'json' | 'csv';
    encrypt?: boolean;
  }): Promise<Buffer> {
    const { logs } = await this.query({
      startDate: params.startDate,
      endDate: params.endDate,
      limit: 10000, // Adjust based on requirements
    });
    
    let output: Buffer;
    
    if (params.format === 'csv') {
      // Convert to CSV
      const csv = this.convertToCSV(logs);
      output = Buffer.from(csv, 'utf-8');
    } else {
      // JSON format
      output = Buffer.from(JSON.stringify(logs, null, 2), 'utf-8');
    }
    
    // Encrypt if requested
    if (params.encrypt && this.config.encryption?.enabled) {
      // TODO: Implement encryption using KMS
      // output = await this.encryptData(output);
    }
    
    return output;
  }

  /**
   * Convert logs to CSV format
   */
  private convertToCSV(logs: AuditLog[]): string {
    const headers = [
      'id', 'timestamp', 'eventType', 'severity',
      'actorType', 'actorId', 'actorEmail',
      'targetType', 'targetId',
      'action', 'result', 'ip', 'userAgent',
    ];
    
    const rows = logs.map(log => [
      log.id,
      log.timestamp.toISOString(),
      log.eventType,
      log.severity,
      log.actor.type,
      log.actor.id || '',
      log.actor.email || '',
      log.target?.type || '',
      log.target?.id || '',
      log.action.operation,
      log.action.result,
      log.context.ip,
      log.context.userAgent || '',
    ]);
    
    return [
      headers.join(','),
      ...rows.map(row => row.map(cell => `"${cell}"`).join(',')),
    ].join('\n');
  }
}

/**
 * Create audit logger middleware
 */
export function createAuditMiddleware(logger: AuditLogger) {
  return async (c: Context, next: () => Promise<void>) => {
    const startTime = Date.now();
    const method = c.req.method;
    const path = c.req.path;
    
    try {
      await next();
      
      const duration = Date.now() - startTime;
      const status = c.res.status;
      
      // Log successful data access
      if (status < 400 && ['GET', 'POST', 'PUT', 'DELETE'].includes(method)) {
        await logger.log({
          eventType: getEventTypeFromRequest(method, path),
          severity: AuditSeverity.INFO,
          action: {
            method,
            operation: `${method} ${path}`,
            result: 'success',
          },
          metadata: {
            duration,
            status,
          },
        }, c);
      }
    } catch (error) {
      const duration = Date.now() - startTime;
      
      // Log errors
      await logger.log({
        eventType: AuditEventType.SYSTEM_ERROR,
        severity: AuditSeverity.HIGH,
        action: {
          method,
          operation: `${method} ${path}`,
          result: 'error',
          reason: error instanceof Error ? error.message : 'Unknown error',
        },
        metadata: {
          duration,
          error: error instanceof Error ? {
            name: error.name,
            message: error.message,
            stack: error.stack,
          } : error,
        },
      }, c);
      
      throw error;
    }
  };
}

/**
 * Determine event type from request
 */
function getEventTypeFromRequest(method: string, path: string): AuditEventType {
  // Auth endpoints
  if (path.includes('/auth/login')) return AuditEventType.AUTH_LOGIN_SUCCESS;
  if (path.includes('/auth/logout')) return AuditEventType.AUTH_LOGOUT;
  if (path.includes('/auth/password')) return AuditEventType.AUTH_PASSWORD_CHANGE;
  
  // Video endpoints
  if (path.includes('/videos') && method === 'GET') return AuditEventType.VIDEO_ACCESS;
  if (path.includes('/videos') && path.includes('/download')) return AuditEventType.VIDEO_DOWNLOAD;
  if (path.includes('/videos') && method === 'DELETE') return AuditEventType.VIDEO_DELETE;
  
  // Incident endpoints
  if (path.includes('/incidents') && method === 'POST') return AuditEventType.INCIDENT_CREATE;
  if (path.includes('/incidents') && method === 'PUT') return AuditEventType.INCIDENT_UPDATE;
  
  // Generic data operations
  switch (method) {
    case 'GET': return AuditEventType.DATA_READ;
    case 'POST': return AuditEventType.DATA_CREATE;
    case 'PUT':
    case 'PATCH': return AuditEventType.DATA_UPDATE;
    case 'DELETE': return AuditEventType.DATA_DELETE;
    default: return AuditEventType.DATA_READ;
  }
}

export default AuditLogger;