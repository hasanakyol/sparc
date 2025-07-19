import { PrismaClient } from '@prisma/client';
import { Redis } from 'ioredis';
import { EventEmitter } from 'events';
import { z } from 'zod';
import { Logger } from 'winston';

// Alert Types and Schemas
export enum AlertType {
  UNAUTHORIZED_ACCESS = 'UNAUTHORIZED_ACCESS',
  DOOR_AJAR = 'DOOR_AJAR',
  ENVIRONMENTAL_THRESHOLD = 'ENVIRONMENTAL_THRESHOLD',
  SYSTEM_FAILURE = 'SYSTEM_FAILURE',
  CAMERA_OFFLINE = 'CAMERA_OFFLINE',
  DEVICE_TAMPER = 'DEVICE_TAMPER',
  CREDENTIAL_BREACH = 'CREDENTIAL_BREACH',
  NETWORK_FAILURE = 'NETWORK_FAILURE',
  POWER_FAILURE = 'POWER_FAILURE',
  INTRUSION_DETECTION = 'INTRUSION_DETECTION',
  FIRE_ALARM = 'FIRE_ALARM',
  EMERGENCY_BUTTON = 'EMERGENCY_BUTTON'
}

export enum AlertSeverity {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL',
  EMERGENCY = 'EMERGENCY'
}

export enum AlertStatus {
  ACTIVE = 'ACTIVE',
  ACKNOWLEDGED = 'ACKNOWLEDGED',
  RESOLVED = 'RESOLVED',
  ESCALATED = 'ESCALATED',
  SUPPRESSED = 'SUPPRESSED'
}

export enum NotificationChannel {
  EMAIL = 'EMAIL',
  SMS = 'SMS',
  PUSH = 'PUSH',
  WEBHOOK = 'WEBHOOK',
  DASHBOARD = 'DASHBOARD',
  MOBILE_APP = 'MOBILE_APP'
}

// Zod Schemas for Validation
const AlertRuleSchema = z.object({
  id: z.string().uuid(),
  tenantId: z.string().uuid(),
  name: z.string().min(1).max(255),
  description: z.string().optional(),
  alertType: z.nativeEnum(AlertType),
  severity: z.nativeEnum(AlertSeverity),
  conditions: z.record(z.any()),
  enabled: z.boolean().default(true),
  suppressionDuration: z.number().min(0).default(0), // minutes
  escalationDelay: z.number().min(0).default(15), // minutes
  autoResolve: z.boolean().default(false),
  autoResolveDelay: z.number().min(0).default(60), // minutes
  notificationChannels: z.array(z.nativeEnum(NotificationChannel)),
  recipients: z.array(z.string()),
  metadata: z.record(z.any()).optional(),
  createdAt: z.date(),
  updatedAt: z.date()
});

const AlertSchema = z.object({
  id: z.string().uuid(),
  tenantId: z.string().uuid(),
  ruleId: z.string().uuid(),
  alertType: z.nativeEnum(AlertType),
  severity: z.nativeEnum(AlertSeverity),
  status: z.nativeEnum(AlertStatus),
  title: z.string().min(1).max(255),
  description: z.string(),
  sourceId: z.string().optional(), // door, camera, sensor ID
  sourceType: z.string().optional(), // 'door', 'camera', 'sensor', 'system'
  locationId: z.string().uuid().optional(),
  eventData: z.record(z.any()),
  acknowledgedBy: z.string().uuid().optional(),
  acknowledgedAt: z.date().optional(),
  resolvedBy: z.string().uuid().optional(),
  resolvedAt: z.date().optional(),
  escalatedAt: z.date().optional(),
  suppressedUntil: z.date().optional(),
  notificationsSent: z.array(z.object({
    channel: z.nativeEnum(NotificationChannel),
    recipient: z.string(),
    sentAt: z.date(),
    status: z.enum(['SENT', 'FAILED', 'PENDING'])
  })),
  correlationId: z.string().optional(),
  parentAlertId: z.string().uuid().optional(),
  metadata: z.record(z.any()).optional(),
  createdAt: z.date(),
  updatedAt: z.date()
});

const EscalationRuleSchema = z.object({
  id: z.string().uuid(),
  tenantId: z.string().uuid(),
  name: z.string().min(1).max(255),
  alertTypes: z.array(z.nativeEnum(AlertType)),
  severities: z.array(z.nativeEnum(AlertSeverity)),
  escalationSteps: z.array(z.object({
    stepNumber: z.number().min(1),
    delayMinutes: z.number().min(0),
    recipients: z.array(z.string()),
    channels: z.array(z.nativeEnum(NotificationChannel)),
    requireAcknowledgment: z.boolean().default(true)
  })),
  enabled: z.boolean().default(true),
  createdAt: z.date(),
  updatedAt: z.date()
});

export type AlertRule = z.infer<typeof AlertRuleSchema>;
export type Alert = z.infer<typeof AlertSchema>;
export type EscalationRule = z.infer<typeof EscalationRuleSchema>;

// Alert Service Interface
export interface IAlertService {
  // Alert Rule Management
  createAlertRule(tenantId: string, rule: Partial<AlertRule>): Promise<AlertRule>;
  updateAlertRule(tenantId: string, ruleId: string, updates: Partial<AlertRule>): Promise<AlertRule>;
  deleteAlertRule(tenantId: string, ruleId: string): Promise<void>;
  getAlertRule(tenantId: string, ruleId: string): Promise<AlertRule | null>;
  getAlertRules(tenantId: string, filters?: any): Promise<AlertRule[]>;

  // Alert Generation and Management
  generateAlert(tenantId: string, alertData: Partial<Alert>): Promise<Alert>;
  acknowledgeAlert(tenantId: string, alertId: string, userId: string): Promise<Alert>;
  resolveAlert(tenantId: string, alertId: string, userId: string, resolution?: string): Promise<Alert>;
  suppressAlert(tenantId: string, alertId: string, suppressionDuration: number): Promise<Alert>;
  escalateAlert(tenantId: string, alertId: string): Promise<Alert>;

  // Alert Querying
  getAlert(tenantId: string, alertId: string): Promise<Alert | null>;
  getAlerts(tenantId: string, filters?: any): Promise<Alert[]>;
  getActiveAlerts(tenantId: string): Promise<Alert[]>;
  getAlertsByLocation(tenantId: string, locationId: string): Promise<Alert[]>;

  // Escalation Management
  createEscalationRule(tenantId: string, rule: Partial<EscalationRule>): Promise<EscalationRule>;
  updateEscalationRule(tenantId: string, ruleId: string, updates: Partial<EscalationRule>): Promise<EscalationRule>;
  deleteEscalationRule(tenantId: string, ruleId: string): Promise<void>;
  getEscalationRules(tenantId: string): Promise<EscalationRule[]>;

  // Event Processing
  processEvent(tenantId: string, eventType: string, eventData: any): Promise<Alert[]>;
  correlateEvents(tenantId: string, events: any[]): Promise<Alert[]>;

  // Notification Management
  sendNotification(alert: Alert, channel: NotificationChannel, recipient: string): Promise<boolean>;
  retryFailedNotifications(tenantId: string): Promise<void>;

  // Analytics and Reporting
  getAlertStatistics(tenantId: string, timeRange?: { start: Date; end: Date }): Promise<any>;
  getAlertTrends(tenantId: string, timeRange?: { start: Date; end: Date }): Promise<any>;
}

// Alert Service Implementation
export class AlertService extends EventEmitter implements IAlertService {
  private prisma: PrismaClient;
  private redis: Redis;
  private logger: Logger;
  private notificationService: any; // Will be injected
  private escalationTimers: Map<string, NodeJS.Timeout> = new Map();

  constructor(
    prisma: PrismaClient,
    redis: Redis,
    logger: Logger,
    notificationService?: any
  ) {
    super();
    this.prisma = prisma;
    this.redis = redis;
    this.logger = logger;
    this.notificationService = notificationService;

    // Start background processes
    this.startEscalationProcessor();
    this.startAutoResolveProcessor();
    this.startNotificationRetryProcessor();
  }

  // Alert Rule Management
  async createAlertRule(tenantId: string, rule: Partial<AlertRule>): Promise<AlertRule> {
    try {
      const ruleData = {
        ...rule,
        id: rule.id || crypto.randomUUID(),
        tenantId,
        createdAt: new Date(),
        updatedAt: new Date()
      };

      const validatedRule = AlertRuleSchema.parse(ruleData);

      const createdRule = await this.prisma.alertRule.create({
        data: validatedRule
      });

      this.logger.info('Alert rule created', {
        tenantId,
        ruleId: createdRule.id,
        alertType: createdRule.alertType
      });

      // Cache the rule for fast access
      await this.redis.setex(
        `alert_rule:${tenantId}:${createdRule.id}`,
        3600,
        JSON.stringify(createdRule)
      );

      return createdRule;
    } catch (error) {
      this.logger.error('Failed to create alert rule', {
        tenantId,
        error: error.message
      });
      throw error;
    }
  }

  async updateAlertRule(tenantId: string, ruleId: string, updates: Partial<AlertRule>): Promise<AlertRule> {
    try {
      const updatedRule = await this.prisma.alertRule.update({
        where: {
          id: ruleId,
          tenantId
        },
        data: {
          ...updates,
          updatedAt: new Date()
        }
      });

      // Update cache
      await this.redis.setex(
        `alert_rule:${tenantId}:${ruleId}`,
        3600,
        JSON.stringify(updatedRule)
      );

      this.logger.info('Alert rule updated', {
        tenantId,
        ruleId,
        updates: Object.keys(updates)
      });

      return updatedRule;
    } catch (error) {
      this.logger.error('Failed to update alert rule', {
        tenantId,
        ruleId,
        error: error.message
      });
      throw error;
    }
  }

  async deleteAlertRule(tenantId: string, ruleId: string): Promise<void> {
    try {
      await this.prisma.alertRule.delete({
        where: {
          id: ruleId,
          tenantId
        }
      });

      // Remove from cache
      await this.redis.del(`alert_rule:${tenantId}:${ruleId}`);

      this.logger.info('Alert rule deleted', {
        tenantId,
        ruleId
      });
    } catch (error) {
      this.logger.error('Failed to delete alert rule', {
        tenantId,
        ruleId,
        error: error.message
      });
      throw error;
    }
  }

  async getAlertRule(tenantId: string, ruleId: string): Promise<AlertRule | null> {
    try {
      // Try cache first
      const cached = await this.redis.get(`alert_rule:${tenantId}:${ruleId}`);
      if (cached) {
        return JSON.parse(cached);
      }

      const rule = await this.prisma.alertRule.findFirst({
        where: {
          id: ruleId,
          tenantId
        }
      });

      if (rule) {
        // Cache for future use
        await this.redis.setex(
          `alert_rule:${tenantId}:${ruleId}`,
          3600,
          JSON.stringify(rule)
        );
      }

      return rule;
    } catch (error) {
      this.logger.error('Failed to get alert rule', {
        tenantId,
        ruleId,
        error: error.message
      });
      throw error;
    }
  }

  async getAlertRules(tenantId: string, filters?: any): Promise<AlertRule[]> {
    try {
      const where: any = { tenantId };

      if (filters?.alertType) {
        where.alertType = filters.alertType;
      }
      if (filters?.severity) {
        where.severity = filters.severity;
      }
      if (filters?.enabled !== undefined) {
        where.enabled = filters.enabled;
      }

      const rules = await this.prisma.alertRule.findMany({
        where,
        orderBy: { createdAt: 'desc' }
      });

      return rules;
    } catch (error) {
      this.logger.error('Failed to get alert rules', {
        tenantId,
        error: error.message
      });
      throw error;
    }
  }

  // Alert Generation and Management
  async generateAlert(tenantId: string, alertData: Partial<Alert>): Promise<Alert> {
    try {
      const alertId = crypto.randomUUID();
      const now = new Date();

      const alert: Alert = {
        id: alertId,
        tenantId,
        ruleId: alertData.ruleId || '',
        alertType: alertData.alertType!,
        severity: alertData.severity!,
        status: AlertStatus.ACTIVE,
        title: alertData.title!,
        description: alertData.description!,
        sourceId: alertData.sourceId,
        sourceType: alertData.sourceType,
        locationId: alertData.locationId,
        eventData: alertData.eventData || {},
        notificationsSent: [],
        metadata: alertData.metadata || {},
        createdAt: now,
        updatedAt: now,
        ...alertData
      };

      // Check for suppression
      if (await this.isAlertSuppressed(tenantId, alert)) {
        this.logger.info('Alert suppressed', {
          tenantId,
          alertId,
          alertType: alert.alertType
        });
        return alert;
      }

      // Save to database
      const createdAlert = await this.prisma.alert.create({
        data: alert
      });

      // Cache active alert
      await this.redis.setex(
        `alert:${tenantId}:${alertId}`,
        86400, // 24 hours
        JSON.stringify(createdAlert)
      );

      // Add to active alerts set
      await this.redis.sadd(`active_alerts:${tenantId}`, alertId);

      this.logger.info('Alert generated', {
        tenantId,
        alertId,
        alertType: alert.alertType,
        severity: alert.severity
      });

      // Emit event for real-time updates
      this.emit('alertGenerated', createdAlert);

      // Send notifications
      await this.sendAlertNotifications(createdAlert);

      // Schedule escalation if needed
      await this.scheduleEscalation(createdAlert);

      // Schedule auto-resolve if configured
      await this.scheduleAutoResolve(createdAlert);

      return createdAlert;
    } catch (error) {
      this.logger.error('Failed to generate alert', {
        tenantId,
        error: error.message,
        alertData
      });
      throw error;
    }
  }

  async acknowledgeAlert(tenantId: string, alertId: string, userId: string): Promise<Alert> {
    try {
      const now = new Date();

      const updatedAlert = await this.prisma.alert.update({
        where: {
          id: alertId,
          tenantId
        },
        data: {
          status: AlertStatus.ACKNOWLEDGED,
          acknowledgedBy: userId,
          acknowledgedAt: now,
          updatedAt: now
        }
      });

      // Update cache
      await this.redis.setex(
        `alert:${tenantId}:${alertId}`,
        86400,
        JSON.stringify(updatedAlert)
      );

      // Cancel escalation timer
      const escalationKey = `escalation:${alertId}`;
      if (this.escalationTimers.has(escalationKey)) {
        clearTimeout(this.escalationTimers.get(escalationKey)!);
        this.escalationTimers.delete(escalationKey);
      }

      this.logger.info('Alert acknowledged', {
        tenantId,
        alertId,
        userId
      });

      this.emit('alertAcknowledged', updatedAlert);

      return updatedAlert;
    } catch (error) {
      this.logger.error('Failed to acknowledge alert', {
        tenantId,
        alertId,
        userId,
        error: error.message
      });
      throw error;
    }
  }

  async resolveAlert(tenantId: string, alertId: string, userId: string, resolution?: string): Promise<Alert> {
    try {
      const now = new Date();

      const updatedAlert = await this.prisma.alert.update({
        where: {
          id: alertId,
          tenantId
        },
        data: {
          status: AlertStatus.RESOLVED,
          resolvedBy: userId,
          resolvedAt: now,
          updatedAt: now,
          metadata: {
            resolution: resolution || 'Manually resolved'
          }
        }
      });

      // Remove from active alerts
      await this.redis.srem(`active_alerts:${tenantId}`, alertId);

      // Update cache
      await this.redis.setex(
        `alert:${tenantId}:${alertId}`,
        86400,
        JSON.stringify(updatedAlert)
      );

      // Cancel any pending timers
      const escalationKey = `escalation:${alertId}`;
      const autoResolveKey = `auto_resolve:${alertId}`;
      
      if (this.escalationTimers.has(escalationKey)) {
        clearTimeout(this.escalationTimers.get(escalationKey)!);
        this.escalationTimers.delete(escalationKey);
      }
      
      if (this.escalationTimers.has(autoResolveKey)) {
        clearTimeout(this.escalationTimers.get(autoResolveKey)!);
        this.escalationTimers.delete(autoResolveKey);
      }

      this.logger.info('Alert resolved', {
        tenantId,
        alertId,
        userId,
        resolution
      });

      this.emit('alertResolved', updatedAlert);

      return updatedAlert;
    } catch (error) {
      this.logger.error('Failed to resolve alert', {
        tenantId,
        alertId,
        userId,
        error: error.message
      });
      throw error;
    }
  }

  async suppressAlert(tenantId: string, alertId: string, suppressionDuration: number): Promise<Alert> {
    try {
      const suppressedUntil = new Date(Date.now() + suppressionDuration * 60 * 1000);

      const updatedAlert = await this.prisma.alert.update({
        where: {
          id: alertId,
          tenantId
        },
        data: {
          status: AlertStatus.SUPPRESSED,
          suppressedUntil,
          updatedAt: new Date()
        }
      });

      // Update cache
      await this.redis.setex(
        `alert:${tenantId}:${alertId}`,
        86400,
        JSON.stringify(updatedAlert)
      );

      this.logger.info('Alert suppressed', {
        tenantId,
        alertId,
        suppressionDuration,
        suppressedUntil
      });

      this.emit('alertSuppressed', updatedAlert);

      return updatedAlert;
    } catch (error) {
      this.logger.error('Failed to suppress alert', {
        tenantId,
        alertId,
        suppressionDuration,
        error: error.message
      });
      throw error;
    }
  }

  async escalateAlert(tenantId: string, alertId: string): Promise<Alert> {
    try {
      const now = new Date();

      const updatedAlert = await this.prisma.alert.update({
        where: {
          id: alertId,
          tenantId
        },
        data: {
          status: AlertStatus.ESCALATED,
          escalatedAt: now,
          updatedAt: now
        }
      });

      // Update cache
      await this.redis.setex(
        `alert:${tenantId}:${alertId}`,
        86400,
        JSON.stringify(updatedAlert)
      );

      this.logger.info('Alert escalated', {
        tenantId,
        alertId
      });

      // Send escalation notifications
      await this.sendEscalationNotifications(updatedAlert);

      this.emit('alertEscalated', updatedAlert);

      return updatedAlert;
    } catch (error) {
      this.logger.error('Failed to escalate alert', {
        tenantId,
        alertId,
        error: error.message
      });
      throw error;
    }
  }

  // Alert Querying
  async getAlert(tenantId: string, alertId: string): Promise<Alert | null> {
    try {
      // Try cache first
      const cached = await this.redis.get(`alert:${tenantId}:${alertId}`);
      if (cached) {
        return JSON.parse(cached);
      }

      const alert = await this.prisma.alert.findFirst({
        where: {
          id: alertId,
          tenantId
        }
      });

      if (alert) {
        // Cache for future use
        await this.redis.setex(
          `alert:${tenantId}:${alertId}`,
          86400,
          JSON.stringify(alert)
        );
      }

      return alert;
    } catch (error) {
      this.logger.error('Failed to get alert', {
        tenantId,
        alertId,
        error: error.message
      });
      throw error;
    }
  }

  async getAlerts(tenantId: string, filters?: any): Promise<Alert[]> {
    try {
      const where: any = { tenantId };

      if (filters?.status) {
        where.status = filters.status;
      }
      if (filters?.alertType) {
        where.alertType = filters.alertType;
      }
      if (filters?.severity) {
        where.severity = filters.severity;
      }
      if (filters?.locationId) {
        where.locationId = filters.locationId;
      }
      if (filters?.dateRange) {
        where.createdAt = {
          gte: filters.dateRange.start,
          lte: filters.dateRange.end
        };
      }

      const alerts = await this.prisma.alert.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        take: filters?.limit || 100,
        skip: filters?.offset || 0
      });

      return alerts;
    } catch (error) {
      this.logger.error('Failed to get alerts', {
        tenantId,
        error: error.message
      });
      throw error;
    }
  }

  async getActiveAlerts(tenantId: string): Promise<Alert[]> {
    try {
      const alertIds = await this.redis.smembers(`active_alerts:${tenantId}`);
      const alerts: Alert[] = [];

      for (const alertId of alertIds) {
        const alert = await this.getAlert(tenantId, alertId);
        if (alert && alert.status === AlertStatus.ACTIVE) {
          alerts.push(alert);
        }
      }

      return alerts.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
    } catch (error) {
      this.logger.error('Failed to get active alerts', {
        tenantId,
        error: error.message
      });
      throw error;
    }
  }

  async getAlertsByLocation(tenantId: string, locationId: string): Promise<Alert[]> {
    return this.getAlerts(tenantId, { locationId });
  }

  // Escalation Management
  async createEscalationRule(tenantId: string, rule: Partial<EscalationRule>): Promise<EscalationRule> {
    try {
      const ruleData = {
        ...rule,
        id: rule.id || crypto.randomUUID(),
        tenantId,
        createdAt: new Date(),
        updatedAt: new Date()
      };

      const validatedRule = EscalationRuleSchema.parse(ruleData);

      const createdRule = await this.prisma.escalationRule.create({
        data: validatedRule
      });

      this.logger.info('Escalation rule created', {
        tenantId,
        ruleId: createdRule.id
      });

      return createdRule;
    } catch (error) {
      this.logger.error('Failed to create escalation rule', {
        tenantId,
        error: error.message
      });
      throw error;
    }
  }

  async updateEscalationRule(tenantId: string, ruleId: string, updates: Partial<EscalationRule>): Promise<EscalationRule> {
    try {
      const updatedRule = await this.prisma.escalationRule.update({
        where: {
          id: ruleId,
          tenantId
        },
        data: {
          ...updates,
          updatedAt: new Date()
        }
      });

      this.logger.info('Escalation rule updated', {
        tenantId,
        ruleId
      });

      return updatedRule;
    } catch (error) {
      this.logger.error('Failed to update escalation rule', {
        tenantId,
        ruleId,
        error: error.message
      });
      throw error;
    }
  }

  async deleteEscalationRule(tenantId: string, ruleId: string): Promise<void> {
    try {
      await this.prisma.escalationRule.delete({
        where: {
          id: ruleId,
          tenantId
        }
      });

      this.logger.info('Escalation rule deleted', {
        tenantId,
        ruleId
      });
    } catch (error) {
      this.logger.error('Failed to delete escalation rule', {
        tenantId,
        ruleId,
        error: error.message
      });
      throw error;
    }
  }

  async getEscalationRules(tenantId: string): Promise<EscalationRule[]> {
    try {
      const rules = await this.prisma.escalationRule.findMany({
        where: { tenantId },
        orderBy: { createdAt: 'desc' }
      });

      return rules;
    } catch (error) {
      this.logger.error('Failed to get escalation rules', {
        tenantId,
        error: error.message
      });
      throw error;
    }
  }

  // Event Processing
  async processEvent(tenantId: string, eventType: string, eventData: any): Promise<Alert[]> {
    try {
      const alerts: Alert[] = [];
      const rules = await this.getAlertRules(tenantId, { enabled: true });

      for (const rule of rules) {
        if (await this.evaluateRule(rule, eventType, eventData)) {
          const alert = await this.generateAlert(tenantId, {
            ruleId: rule.id,
            alertType: rule.alertType,
            severity: rule.severity,
            title: this.generateAlertTitle(rule, eventData),
            description: this.generateAlertDescription(rule, eventData),
            sourceId: eventData.sourceId,
            sourceType: eventData.sourceType,
            locationId: eventData.locationId,
            eventData,
            correlationId: eventData.correlationId
          });

          alerts.push(alert);
        }
      }

      return alerts;
    } catch (error) {
      this.logger.error('Failed to process event', {
        tenantId,
        eventType,
        error: error.message
      });
      throw error;
    }
  }

  async correlateEvents(tenantId: string, events: any[]): Promise<Alert[]> {
    try {
      const correlatedAlerts: Alert[] = [];
      
      // Group events by correlation criteria
      const eventGroups = this.groupEventsByCorrelation(events);

      for (const group of eventGroups) {
        if (group.length > 1) {
          // Generate correlated alert
          const correlatedAlert = await this.generateAlert(tenantId, {
            alertType: AlertType.SYSTEM_FAILURE,
            severity: AlertSeverity.HIGH,
            title: 'Correlated Security Events Detected',
            description: `Multiple related events detected: ${group.map(e => e.type).join(', ')}`,
            eventData: { correlatedEvents: group },
            correlationId: crypto.randomUUID()
          });

          correlatedAlerts.push(correlatedAlert);
        }
      }

      return correlatedAlerts;
    } catch (error) {
      this.logger.error('Failed to correlate events', {
        tenantId,
        error: error.message
      });
      throw error;
    }
  }

  // Notification Management
  async sendNotification(alert: Alert, channel: NotificationChannel, recipient: string): Promise<boolean> {
    try {
      if (!this.notificationService) {
        this.logger.warn('Notification service not configured');
        return false;
      }

      const success = await this.notificationService.send({
        channel,
        recipient,
        subject: alert.title,
        message: alert.description,
        alertId: alert.id,
        severity: alert.severity,
        metadata: alert.metadata
      });

      // Update notification status
      const notification = {
        channel,
        recipient,
        sentAt: new Date(),
        status: success ? 'SENT' : 'FAILED'
      };

      await this.prisma.alert.update({
        where: { id: alert.id },
        data: {
          notificationsSent: {
            push: notification
          }
        }
      });

      return success;
    } catch (error) {
      this.logger.error('Failed to send notification', {
        alertId: alert.id,
        channel,
        recipient,
        error: error.message
      });
      return false;
    }
  }

  async retryFailedNotifications(tenantId: string): Promise<void> {
    try {
      const alerts = await this.prisma.alert.findMany({
        where: {
          tenantId,
          notificationsSent: {
            some: {
              status: 'FAILED'
            }
          }
        }
      });

      for (const alert of alerts) {
        const failedNotifications = alert.notificationsSent.filter(n => n.status === 'FAILED');
        
        for (const notification of failedNotifications) {
          await this.sendNotification(alert, notification.channel, notification.recipient);
        }
      }
    } catch (error) {
      this.logger.error('Failed to retry notifications', {
        tenantId,
        error: error.message
      });
    }
  }

  // Analytics and Reporting
  async getAlertStatistics(tenantId: string, timeRange?: { start: Date; end: Date }): Promise<any> {
    try {
      const where: any = { tenantId };
      
      if (timeRange) {
        where.createdAt = {
          gte: timeRange.start,
          lte: timeRange.end
        };
      }

      const [
        totalAlerts,
        activeAlerts,
        resolvedAlerts,
        alertsBySeverity,
        alertsByType
      ] = await Promise.all([
        this.prisma.alert.count({ where }),
        this.prisma.alert.count({ where: { ...where, status: AlertStatus.ACTIVE } }),
        this.prisma.alert.count({ where: { ...where, status: AlertStatus.RESOLVED } }),
        this.prisma.alert.groupBy({
          by: ['severity'],
          where,
          _count: true
        }),
        this.prisma.alert.groupBy({
          by: ['alertType'],
          where,
          _count: true
        })
      ]);

      return {
        totalAlerts,
        activeAlerts,
        resolvedAlerts,
        alertsBySeverity,
        alertsByType,
        resolutionRate: totalAlerts > 0 ? (resolvedAlerts / totalAlerts) * 100 : 0
      };
    } catch (error) {
      this.logger.error('Failed to get alert statistics', {
        tenantId,
        error: error.message
      });
      throw error;
    }
  }

  async getAlertTrends(tenantId: string, timeRange?: { start: Date; end: Date }): Promise<any> {
    try {
      const where: any = { tenantId };
      
      if (timeRange) {
        where.createdAt = {
          gte: timeRange.start,
          lte: timeRange.end
        };
      }

      const trends = await this.prisma.alert.groupBy({
        by: ['createdAt'],
        where,
        _count: true,
        orderBy: { createdAt: 'asc' }
      });

      return trends;
    } catch (error) {
      this.logger.error('Failed to get alert trends', {
        tenantId,
        error: error.message
      });
      throw error;
    }
  }

  // Private Helper Methods
  private async isAlertSuppressed(tenantId: string, alert: Alert): Promise<boolean> {
    const suppressionKey = `suppression:${tenantId}:${alert.alertType}:${alert.sourceId}`;
    const suppressed = await this.redis.get(suppressionKey);
    return !!suppressed;
  }

  private async sendAlertNotifications(alert: Alert): Promise<void> {
    try {
      const rule = await this.getAlertRule(alert.tenantId, alert.ruleId);
      if (!rule) return;

      for (const channel of rule.notificationChannels) {
        for (const recipient of rule.recipients) {
          await this.sendNotification(alert, channel, recipient);
        }
      }
    } catch (error) {
      this.logger.error('Failed to send alert notifications', {
        alertId: alert.id,
        error: error.message
      });
    }
  }

  private async scheduleEscalation(alert: Alert): Promise<void> {
    try {
      const rule = await this.getAlertRule(alert.tenantId, alert.ruleId);
      if (!rule || rule.escalationDelay <= 0) return;

      const escalationKey = `escalation:${alert.id}`;
      const timer = setTimeout(async () => {
        try {
          const currentAlert = await this.getAlert(alert.tenantId, alert.id);
          if (currentAlert && currentAlert.status === AlertStatus.ACTIVE) {
            await this.escalateAlert(alert.tenantId, alert.id);
          }
        } catch (error) {
          this.logger.error('Escalation timer error', {
            alertId: alert.id,
            error: error.message
          });
        }
        this.escalationTimers.delete(escalationKey);
      }, rule.escalationDelay * 60 * 1000);

      this.escalationTimers.set(escalationKey, timer);
    } catch (error) {
      this.logger.error('Failed to schedule escalation', {
        alertId: alert.id,
        error: error.message
      });
    }
  }

  private async scheduleAutoResolve(alert: Alert): Promise<void> {
    try {
      const rule = await this.getAlertRule(alert.tenantId, alert.ruleId);
      if (!rule || !rule.autoResolve || rule.autoResolveDelay <= 0) return;

      const autoResolveKey = `auto_resolve:${alert.id}`;
      const timer = setTimeout(async () => {
        try {
          const currentAlert = await this.getAlert(alert.tenantId, alert.id);
          if (currentAlert && currentAlert.status === AlertStatus.ACTIVE) {
            await this.resolveAlert(alert.tenantId, alert.id, 'system', 'Auto-resolved');
          }
        } catch (error) {
          this.logger.error('Auto-resolve timer error', {
            alertId: alert.id,
            error: error.message
          });
        }
        this.escalationTimers.delete(autoResolveKey);
      }, rule.autoResolveDelay * 60 * 1000);

      this.escalationTimers.set(autoResolveKey, timer);
    } catch (error) {
      this.logger.error('Failed to schedule auto-resolve', {
        alertId: alert.id,
        error: error.message
      });
    }
  }

  private async sendEscalationNotifications(alert: Alert): Promise<void> {
    try {
      const escalationRules = await this.getEscalationRules(alert.tenantId);
      
      for (const rule of escalationRules) {
        if (rule.alertTypes.includes(alert.alertType) && 
            rule.severities.includes(alert.severity)) {
          
          for (const step of rule.escalationSteps) {
            for (const channel of step.channels) {
              for (const recipient of step.recipients) {
                await this.sendNotification(alert, channel, recipient);
              }
            }
          }
        }
      }
    } catch (error) {
      this.logger.error('Failed to send escalation notifications', {
        alertId: alert.id,
        error: error.message
      });
    }
  }

  private async evaluateRule(rule: AlertRule, eventType: string, eventData: any): Promise<boolean> {
    try {
      // Basic rule evaluation logic
      if (rule.alertType === AlertType.UNAUTHORIZED_ACCESS && eventType === 'access_denied') {
        return true;
      }
      
      if (rule.alertType === AlertType.DOOR_AJAR && eventType === 'door_ajar') {
        const duration = eventData.duration || 0;
        const threshold = rule.conditions?.duration || 30; // seconds
        return duration > threshold;
      }

      if (rule.alertType === AlertType.ENVIRONMENTAL_THRESHOLD && eventType === 'environmental_reading') {
        const value = eventData.value;
        const threshold = rule.conditions?.threshold;
        const operator = rule.conditions?.operator || 'gt';
        
        switch (operator) {
          case 'gt': return value > threshold;
          case 'lt': return value < threshold;
          case 'eq': return value === threshold;
          default: return false;
        }
      }

      if (rule.alertType === AlertType.SYSTEM_FAILURE && eventType === 'system_error') {
        return true;
      }

      return false;
    } catch (error) {
      this.logger.error('Rule evaluation error', {
        ruleId: rule.id,
        eventType,
        error: error.message
      });
      return false;
    }
  }

  private generateAlertTitle(rule: AlertRule, eventData: any): string {
    const templates = {
      [AlertType.UNAUTHORIZED_ACCESS]: 'Unauthorized Access Attempt',
      [AlertType.DOOR_AJAR]: 'Door Held Open',
      [AlertType.ENVIRONMENTAL_THRESHOLD]: 'Environmental Threshold Exceeded',
      [AlertType.SYSTEM_FAILURE]: 'System Failure Detected',
      [AlertType.CAMERA_OFFLINE]: 'Camera Offline',
      [AlertType.DEVICE_TAMPER]: 'Device Tampering Detected'
    };

    return templates[rule.alertType] || 'Security Alert';
  }

  private generateAlertDescription(rule: AlertRule, eventData: any): string {
    const location = eventData.locationName || eventData.locationId || 'Unknown Location';
    const source = eventData.sourceName || eventData.sourceId || 'Unknown Source';
    
    switch (rule.alertType) {
      case AlertType.UNAUTHORIZED_ACCESS:
        return `Unauthorized access attempt detected at ${location} from ${source}`;
      case AlertType.DOOR_AJAR:
        return `Door at ${location} has been held open for ${eventData.duration} seconds`;
      case AlertType.ENVIRONMENTAL_THRESHOLD:
        return `Environmental reading of ${eventData.value} ${eventData.unit} exceeds threshold at ${location}`;
      case AlertType.SYSTEM_FAILURE:
        return `System failure detected: ${eventData.error || 'Unknown error'}`;
      default:
        return `Security alert triggered at ${location}`;
    }
  }

  private groupEventsByCorrelation(events: any[]): any[][] {
    const groups: Map<string, any[]> = new Map();
    
    for (const event of events) {
      const key = `${event.locationId}-${event.sourceType}-${Math.floor(event.timestamp / 60000)}`; // Group by location, type, and minute
      
      if (!groups.has(key)) {
        groups.set(key, []);
      }
      groups.get(key)!.push(event);
    }
    
    return Array.from(groups.values());
  }

  // Background Processors
  private startEscalationProcessor(): void {
    setInterval(async () => {
      try {
        // Process escalations for all tenants
        const tenants = await this.redis.smembers('active_tenants');
        
        for (const tenantId of tenants) {
          const activeAlerts = await this.getActiveAlerts(tenantId);
          
          for (const alert of activeAlerts) {
            const rule = await this.getAlertRule(tenantId, alert.ruleId);
            if (rule && rule.escalationDelay > 0) {
              const escalationTime = new Date(alert.createdAt.getTime() + rule.escalationDelay * 60 * 1000);
              
              if (new Date() >= escalationTime && alert.status === AlertStatus.ACTIVE) {
                await this.escalateAlert(tenantId, alert.id);
              }
            }
          }
        }
      } catch (error) {
        this.logger.error('Escalation processor error', { error: error.message });
      }
    }, 60000); // Run every minute
  }

  private startAutoResolveProcessor(): void {
    setInterval(async () => {
      try {
        const tenants = await this.redis.smembers('active_tenants');
        
        for (const tenantId of tenants) {
          const activeAlerts = await this.getActiveAlerts(tenantId);
          
          for (const alert of activeAlerts) {
            const rule = await this.getAlertRule(tenantId, alert.ruleId);
            if (rule && rule.autoResolve && rule.autoResolveDelay > 0) {
              const resolveTime = new Date(alert.createdAt.getTime() + rule.autoResolveDelay * 60 * 1000);
              
              if (new Date() >= resolveTime && alert.status === AlertStatus.ACTIVE) {
                await this.resolveAlert(tenantId, alert.id, 'system', 'Auto-resolved');
              }
            }
          }
        }
      } catch (error) {
        this.logger.error('Auto-resolve processor error', { error: error.message });
      }
    }, 300000); // Run every 5 minutes
  }

  private startNotificationRetryProcessor(): void {
    setInterval(async () => {
      try {
        const tenants = await this.redis.smembers('active_tenants');
        
        for (const tenantId of tenants) {
          await this.retryFailedNotifications(tenantId);
        }
      } catch (error) {
        this.logger.error('Notification retry processor error', { error: error.message });
      }
    }, 600000); // Run every 10 minutes
  }
}

// Factory function for creating AlertService instances
export function createAlertService(
  prisma: PrismaClient,
  redis: Redis,
  logger: Logger,
  notificationService?: any
): AlertService {
  return new AlertService(prisma, redis, logger, notificationService);
}

// Export default instance
export default AlertService;