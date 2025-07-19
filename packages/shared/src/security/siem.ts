import { EventEmitter } from 'events';
import { Redis } from 'ioredis';
import { logger } from '../utils/logger';
import { prisma } from '../database/prisma';

export interface SecurityEvent {
  id: string;
  timestamp: Date;
  eventType: SecurityEventType;
  severity: SecuritySeverity;
  source: string;
  userId?: string;
  organizationId?: string;
  ipAddress?: string;
  userAgent?: string;
  details: Record<string, any>;
  metadata?: Record<string, any>;
}

export enum SecurityEventType {
  // Authentication Events
  LOGIN_SUCCESS = 'LOGIN_SUCCESS',
  LOGIN_FAILURE = 'LOGIN_FAILURE',
  LOGOUT = 'LOGOUT',
  PASSWORD_RESET = 'PASSWORD_RESET',
  MFA_CHALLENGE = 'MFA_CHALLENGE',
  MFA_SUCCESS = 'MFA_SUCCESS',
  MFA_FAILURE = 'MFA_FAILURE',
  
  // Authorization Events
  ACCESS_GRANTED = 'ACCESS_GRANTED',
  ACCESS_DENIED = 'ACCESS_DENIED',
  PRIVILEGE_ESCALATION = 'PRIVILEGE_ESCALATION',
  ROLE_CHANGE = 'ROLE_CHANGE',
  
  // Security Violations
  BRUTE_FORCE_DETECTED = 'BRUTE_FORCE_DETECTED',
  RATE_LIMIT_EXCEEDED = 'RATE_LIMIT_EXCEEDED',
  SUSPICIOUS_ACTIVITY = 'SUSPICIOUS_ACTIVITY',
  CSRF_VIOLATION = 'CSRF_VIOLATION',
  SQL_INJECTION_ATTEMPT = 'SQL_INJECTION_ATTEMPT',
  XSS_ATTEMPT = 'XSS_ATTEMPT',
  
  // Data Access
  SENSITIVE_DATA_ACCESS = 'SENSITIVE_DATA_ACCESS',
  DATA_EXPORT = 'DATA_EXPORT',
  BULK_OPERATION = 'BULK_OPERATION',
  
  // System Events
  SERVICE_START = 'SERVICE_START',
  SERVICE_STOP = 'SERVICE_STOP',
  CONFIGURATION_CHANGE = 'CONFIGURATION_CHANGE',
  CERTIFICATE_EXPIRY = 'CERTIFICATE_EXPIRY',
  JWT_SECRET_ROTATED = 'JWT_SECRET_ROTATED',
  
  // Compliance Events
  AUDIT_LOG_ACCESS = 'AUDIT_LOG_ACCESS',
  COMPLIANCE_VIOLATION = 'COMPLIANCE_VIOLATION',
  DATA_RETENTION_VIOLATION = 'DATA_RETENTION_VIOLATION'
}

export enum SecuritySeverity {
  CRITICAL = 'CRITICAL',
  HIGH = 'HIGH',
  MEDIUM = 'MEDIUM',
  LOW = 'LOW',
  INFO = 'INFO'
}

interface AlertRule {
  id: string;
  name: string;
  description: string;
  conditions: AlertCondition[];
  actions: AlertAction[];
  enabled: boolean;
  cooldownMinutes?: number;
}

interface AlertCondition {
  field: string;
  operator: 'equals' | 'contains' | 'greater_than' | 'less_than' | 'in' | 'not_in';
  value: any;
  aggregation?: {
    window: number; // minutes
    threshold: number;
  };
}

interface AlertAction {
  type: 'email' | 'webhook' | 'sms' | 'slack' | 'pagerduty';
  config: Record<string, any>;
}

export class SecurityMonitoring extends EventEmitter {
  private redis: Redis;
  private alertRules: Map<string, AlertRule> = new Map();
  private correlationEngine: CorrelationEngine;
  
  constructor(redis: Redis) {
    super();
    this.redis = redis;
    this.correlationEngine = new CorrelationEngine();
    this.loadAlertRules();
  }
  
  async recordEvent(event: Omit<SecurityEvent, 'id' | 'timestamp'>): Promise<void> {
    const securityEvent: SecurityEvent = {
      id: crypto.randomUUID(),
      timestamp: new Date(),
      ...event
    };
    
    try {
      // Store in database for persistence
      await prisma.$executeRawUnsafe(`
        INSERT INTO security_events (
          id, timestamp, event_type, severity, source, 
          user_id, organization_id, ip_address, user_agent, 
          details, metadata
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
      `,
        securityEvent.id,
        securityEvent.timestamp,
        securityEvent.eventType,
        securityEvent.severity,
        securityEvent.source,
        securityEvent.userId,
        securityEvent.organizationId,
        securityEvent.ipAddress,
        securityEvent.userAgent,
        JSON.stringify(securityEvent.details),
        JSON.stringify(securityEvent.metadata || {})
      );
      
      // Store in Redis for real-time processing
      const key = `security:events:${securityEvent.eventType}`;
      await this.redis.zadd(
        key,
        Date.now(),
        JSON.stringify(securityEvent)
      );
      
      // Expire old events (keep last 24 hours)
      await this.redis.zremrangebyscore(
        key,
        '-inf',
        Date.now() - 24 * 60 * 60 * 1000
      );
      
      // Process event through correlation engine
      const correlatedEvents = await this.correlationEngine.correlate(securityEvent);
      
      // Check alert rules
      await this.checkAlertRules(securityEvent, correlatedEvents);
      
      // Emit event for real-time dashboards
      this.emit('securityEvent', securityEvent);
      
    } catch (error) {
      logger.error('Failed to record security event', { error, event: securityEvent });
    }
  }
  
  async checkAlertRules(
    event: SecurityEvent, 
    correlatedEvents: SecurityEvent[]
  ): Promise<void> {
    for (const [ruleId, rule] of this.alertRules) {
      if (!rule.enabled) continue;
      
      // Check cooldown
      const lastAlertKey = `alert:cooldown:${ruleId}`;
      const lastAlert = await this.redis.get(lastAlertKey);
      if (lastAlert && rule.cooldownMinutes) {
        const lastAlertTime = parseInt(lastAlert);
        if (Date.now() - lastAlertTime < rule.cooldownMinutes * 60 * 1000) {
          continue;
        }
      }
      
      // Check conditions
      const matches = await this.evaluateConditions(
        rule.conditions, 
        event, 
        correlatedEvents
      );
      
      if (matches) {
        // Trigger actions
        for (const action of rule.actions) {
          await this.executeAction(action, event, rule);
        }
        
        // Set cooldown
        if (rule.cooldownMinutes) {
          await this.redis.set(
            lastAlertKey,
            Date.now(),
            'EX',
            rule.cooldownMinutes * 60
          );
        }
      }
    }
  }
  
  private async evaluateConditions(
    conditions: AlertCondition[],
    event: SecurityEvent,
    correlatedEvents: SecurityEvent[]
  ): Promise<boolean> {
    for (const condition of conditions) {
      const fieldValue = this.getFieldValue(event, condition.field);
      
      if (condition.aggregation) {
        // Time-based aggregation
        const windowStart = Date.now() - condition.aggregation.window * 60 * 1000;
        const eventsInWindow = correlatedEvents.filter(
          e => e.timestamp.getTime() >= windowStart
        );
        
        if (eventsInWindow.length < condition.aggregation.threshold) {
          return false;
        }
      } else {
        // Simple field comparison
        if (!this.evaluateOperator(fieldValue, condition.operator, condition.value)) {
          return false;
        }
      }
    }
    
    return true;
  }
  
  private getFieldValue(event: SecurityEvent, field: string): any {
    const fields = field.split('.');
    let value: any = event;
    
    for (const f of fields) {
      value = value?.[f];
    }
    
    return value;
  }
  
  private evaluateOperator(value: any, operator: string, target: any): boolean {
    switch (operator) {
      case 'equals':
        return value === target;
      case 'contains':
        return String(value).includes(String(target));
      case 'greater_than':
        return Number(value) > Number(target);
      case 'less_than':
        return Number(value) < Number(target);
      case 'in':
        return Array.isArray(target) && target.includes(value);
      case 'not_in':
        return Array.isArray(target) && !target.includes(value);
      default:
        return false;
    }
  }
  
  private async executeAction(
    action: AlertAction,
    event: SecurityEvent,
    rule: AlertRule
  ): Promise<void> {
    try {
      switch (action.type) {
        case 'email':
          await this.sendEmailAlert(action.config, event, rule);
          break;
        case 'webhook':
          await this.sendWebhookAlert(action.config, event, rule);
          break;
        case 'slack':
          await this.sendSlackAlert(action.config, event, rule);
          break;
        case 'pagerduty':
          await this.sendPagerDutyAlert(action.config, event, rule);
          break;
        case 'sms':
          await this.sendSMSAlert(action.config, event, rule);
          break;
      }
    } catch (error) {
      logger.error('Failed to execute alert action', { error, action, event });
    }
  }
  
  private async sendEmailAlert(
    config: any,
    event: SecurityEvent,
    rule: AlertRule
  ): Promise<void> {
    // Import email service
    const { sendEmail } = await import('../services/email');
    
    await sendEmail({
      to: config.recipients,
      subject: `Security Alert: ${rule.name}`,
      template: 'security-alert',
      data: {
        ruleName: rule.name,
        eventType: event.eventType,
        severity: event.severity,
        timestamp: event.timestamp.toISOString(),
        details: event.details,
        source: event.source
      }
    });
  }
  
  private async sendWebhookAlert(
    config: any,
    event: SecurityEvent,
    rule: AlertRule
  ): Promise<void> {
    const response = await fetch(config.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...config.headers
      },
      body: JSON.stringify({
        rule,
        event,
        timestamp: new Date().toISOString()
      })
    });
    
    if (!response.ok) {
      throw new Error(`Webhook failed: ${response.statusText}`);
    }
  }
  
  private async sendSlackAlert(
    config: any,
    event: SecurityEvent,
    rule: AlertRule
  ): Promise<void> {
    const color = {
      CRITICAL: 'danger',
      HIGH: 'warning',
      MEDIUM: 'warning',
      LOW: '#36a64f',
      INFO: '#2eb886'
    }[event.severity];
    
    await fetch(config.webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        attachments: [{
          color,
          title: `Security Alert: ${rule.name}`,
          fields: [
            { title: 'Event Type', value: event.eventType, short: true },
            { title: 'Severity', value: event.severity, short: true },
            { title: 'Source', value: event.source, short: true },
            { title: 'Time', value: event.timestamp.toISOString(), short: true }
          ],
          footer: 'SPARC Security Monitoring',
          ts: Math.floor(event.timestamp.getTime() / 1000)
        }]
      })
    });
  }
  
  private async sendPagerDutyAlert(
    config: any,
    event: SecurityEvent,
    rule: AlertRule
  ): Promise<void> {
    await fetch('https://events.pagerduty.com/v2/enqueue', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Token token=${config.apiKey}`
      },
      body: JSON.stringify({
        routing_key: config.routingKey,
        event_action: 'trigger',
        payload: {
          summary: `${rule.name}: ${event.eventType}`,
          severity: event.severity.toLowerCase(),
          source: event.source,
          custom_details: event.details
        }
      })
    });
  }
  
  private async sendSMSAlert(
    config: any,
    event: SecurityEvent,
    rule: AlertRule
  ): Promise<void> {
    // Implementation would use SMS service like Twilio
    logger.info('SMS alert would be sent', { config, event, rule });
  }
  
  private async loadAlertRules(): Promise<void> {
    // Default alert rules
    const defaultRules: AlertRule[] = [
      {
        id: 'brute-force',
        name: 'Brute Force Detection',
        description: 'Alert on multiple failed login attempts',
        enabled: true,
        cooldownMinutes: 30,
        conditions: [
          {
            field: 'eventType',
            operator: 'equals',
            value: SecurityEventType.LOGIN_FAILURE,
            aggregation: { window: 5, threshold: 5 }
          }
        ],
        actions: [
          { type: 'email', config: { recipients: ['security@sparc.com'] } }
        ]
      },
      {
        id: 'privilege-escalation',
        name: 'Privilege Escalation',
        description: 'Alert on privilege escalation attempts',
        enabled: true,
        conditions: [
          {
            field: 'eventType',
            operator: 'equals',
            value: SecurityEventType.PRIVILEGE_ESCALATION
          }
        ],
        actions: [
          { type: 'email', config: { recipients: ['security@sparc.com'] } },
          { type: 'slack', config: { webhookUrl: process.env.SLACK_WEBHOOK_URL } }
        ]
      },
      {
        id: 'sql-injection',
        name: 'SQL Injection Attempt',
        description: 'Alert on SQL injection attempts',
        enabled: true,
        conditions: [
          {
            field: 'eventType',
            operator: 'equals',
            value: SecurityEventType.SQL_INJECTION_ATTEMPT
          }
        ],
        actions: [
          { type: 'pagerduty', config: { 
            apiKey: process.env.PAGERDUTY_API_KEY,
            routingKey: process.env.PAGERDUTY_ROUTING_KEY
          }}
        ]
      },
      {
        id: 'suspicious-data-access',
        name: 'Suspicious Data Access',
        description: 'Alert on unusual data access patterns',
        enabled: true,
        cooldownMinutes: 60,
        conditions: [
          {
            field: 'eventType',
            operator: 'in',
            value: [
              SecurityEventType.SENSITIVE_DATA_ACCESS,
              SecurityEventType.DATA_EXPORT,
              SecurityEventType.BULK_OPERATION
            ],
            aggregation: { window: 10, threshold: 10 }
          }
        ],
        actions: [
          { type: 'email', config: { recipients: ['security@sparc.com'] } }
        ]
      }
    ];
    
    // Load custom rules from database
    try {
      const customRules = await prisma.$queryRaw<any[]>`
        SELECT * FROM alert_rules WHERE enabled = true
      `;
      
      for (const rule of [...defaultRules, ...customRules]) {
        this.alertRules.set(rule.id, rule);
      }
    } catch (error) {
      // Use default rules if database not available
      for (const rule of defaultRules) {
        this.alertRules.set(rule.id, rule);
      }
    }
  }
  
  async getSecurityMetrics(timeRange: { start: Date; end: Date }): Promise<any> {
    const metrics = {
      totalEvents: 0,
      eventsByType: {} as Record<string, number>,
      eventsBySeverity: {} as Record<string, number>,
      topUsers: [] as any[],
      topSources: [] as any[],
      trendsOverTime: [] as any[]
    };
    
    try {
      // Get total events
      const totalResult = await prisma.$queryRaw<any[]>`
        SELECT COUNT(*) as count 
        FROM security_events 
        WHERE timestamp BETWEEN ${timeRange.start} AND ${timeRange.end}
      `;
      metrics.totalEvents = parseInt(totalResult[0]?.count || 0);
      
      // Get events by type
      const typeResults = await prisma.$queryRaw<any[]>`
        SELECT event_type, COUNT(*) as count 
        FROM security_events 
        WHERE timestamp BETWEEN ${timeRange.start} AND ${timeRange.end}
        GROUP BY event_type
      `;
      for (const result of typeResults) {
        metrics.eventsByType[result.event_type] = parseInt(result.count);
      }
      
      // Get events by severity
      const severityResults = await prisma.$queryRaw<any[]>`
        SELECT severity, COUNT(*) as count 
        FROM security_events 
        WHERE timestamp BETWEEN ${timeRange.start} AND ${timeRange.end}
        GROUP BY severity
      `;
      for (const result of severityResults) {
        metrics.eventsBySeverity[result.severity] = parseInt(result.count);
      }
      
      // Get top users with events
      const userResults = await prisma.$queryRaw<any[]>`
        SELECT user_id, COUNT(*) as count 
        FROM security_events 
        WHERE timestamp BETWEEN ${timeRange.start} AND ${timeRange.end}
          AND user_id IS NOT NULL
        GROUP BY user_id
        ORDER BY count DESC
        LIMIT 10
      `;
      metrics.topUsers = userResults;
      
      // Get top sources
      const sourceResults = await prisma.$queryRaw<any[]>`
        SELECT source, COUNT(*) as count 
        FROM security_events 
        WHERE timestamp BETWEEN ${timeRange.start} AND ${timeRange.end}
        GROUP BY source
        ORDER BY count DESC
        LIMIT 10
      `;
      metrics.topSources = sourceResults;
      
      // Get trends over time (hourly)
      const trendResults = await prisma.$queryRaw<any[]>`
        SELECT 
          DATE_TRUNC('hour', timestamp) as hour,
          severity,
          COUNT(*) as count
        FROM security_events 
        WHERE timestamp BETWEEN ${timeRange.start} AND ${timeRange.end}
        GROUP BY hour, severity
        ORDER BY hour
      `;
      metrics.trendsOverTime = trendResults;
      
    } catch (error) {
      logger.error('Failed to get security metrics', { error });
    }
    
    return metrics;
  }
}

class CorrelationEngine {
  async correlate(event: SecurityEvent): Promise<SecurityEvent[]> {
    const correlatedEvents: SecurityEvent[] = [];
    
    // Define correlation rules
    const correlationWindow = 5 * 60 * 1000; // 5 minutes
    
    try {
      // Correlate by user
      if (event.userId) {
        const userEvents = await prisma.$queryRaw<SecurityEvent[]>`
          SELECT * FROM security_events
          WHERE user_id = ${event.userId}
            AND timestamp >= ${new Date(event.timestamp.getTime() - correlationWindow)}
            AND id != ${event.id}
          ORDER BY timestamp DESC
          LIMIT 20
        `;
        correlatedEvents.push(...userEvents);
      }
      
      // Correlate by IP address
      if (event.ipAddress) {
        const ipEvents = await prisma.$queryRaw<SecurityEvent[]>`
          SELECT * FROM security_events
          WHERE ip_address = ${event.ipAddress}
            AND timestamp >= ${new Date(event.timestamp.getTime() - correlationWindow)}
            AND id != ${event.id}
          ORDER BY timestamp DESC
          LIMIT 20
        `;
        correlatedEvents.push(...ipEvents);
      }
      
      // Correlate by organization
      if (event.organizationId) {
        const orgEvents = await prisma.$queryRaw<SecurityEvent[]>`
          SELECT * FROM security_events
          WHERE organization_id = ${event.organizationId}
            AND timestamp >= ${new Date(event.timestamp.getTime() - correlationWindow)}
            AND id != ${event.id}
            AND severity IN ('CRITICAL', 'HIGH')
          ORDER BY timestamp DESC
          LIMIT 10
        `;
        correlatedEvents.push(...orgEvents);
      }
      
      // Remove duplicates
      const uniqueEvents = Array.from(
        new Map(correlatedEvents.map(e => [e.id, e])).values()
      );
      
      return uniqueEvents;
      
    } catch (error) {
      logger.error('Failed to correlate events', { error });
      return [];
    }
  }
}

// Create singleton instance
export const securityMonitoring = new SecurityMonitoring(
  new Redis({
    host: process.env.REDIS_HOST || 'localhost',
    port: parseInt(process.env.REDIS_PORT || '6379'),
    password: process.env.REDIS_PASSWORD
  })
);

// Export helper function for easy use
export async function logSecurityEvent(
  eventType: SecurityEventType,
  details: Partial<Omit<SecurityEvent, 'id' | 'timestamp' | 'eventType'>>
): Promise<void> {
  await securityMonitoring.recordEvent({
    eventType,
    severity: details.severity || SecuritySeverity.INFO,
    source: details.source || 'unknown',
    ...details
  });
}