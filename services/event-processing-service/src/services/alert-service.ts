import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';
import { NotificationService } from './notification-service';

export interface Alert {
  id: string;
  tenantId: string;
  type: 'security' | 'environmental' | 'system' | 'maintenance';
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  sourceEvents: string[];
  location: {
    buildingId: string;
    floorId: string;
    zoneId?: string;
  };
  timestamp: string;
  acknowledged: boolean;
  acknowledgedBy?: string;
  acknowledgedAt?: string;
  resolved: boolean;
  resolvedBy?: string;
  resolvedAt?: string;
  metadata?: Record<string, any>;
}

export class AlertService {
  private alertCache = new Map<string, Alert>();
  private correlationRules: any[] = [];

  constructor(
    private prisma: PrismaClient,
    private redis: Redis,
    private notificationService: NotificationService
  ) {}

  async createAlert(tenantId: string, alertData: Partial<Alert>): Promise<Alert> {
    const alert: Alert = {
      id: crypto.randomUUID(),
      tenantId,
      timestamp: new Date().toISOString(),
      acknowledged: false,
      resolved: false,
      ...alertData
    } as Alert;

    // Save to database
    await this.prisma.alert.create({ data: alert });

    // Cache alert
    this.alertCache.set(alert.id, alert);
    await this.redis.hset('alerts', alert.id, JSON.stringify(alert));
    await this.redis.sadd(`active_alerts:${tenantId}`, alert.id);

    // Send notifications
    await this.sendNotifications(alert);

    console.log(`Alert created: ${alert.id} - ${alert.title}`);
    
    return alert;
  }

  async getAlert(alertId: string, tenantId: string): Promise<Alert | null> {
    // Check cache first
    if (this.alertCache.has(alertId)) {
      const alert = this.alertCache.get(alertId)!;
      if (alert.tenantId === tenantId) {
        return alert;
      }
    }

    // Check Redis
    const cached = await this.redis.hget('alerts', alertId);
    if (cached) {
      const alert = JSON.parse(cached);
      if (alert.tenantId === tenantId) {
        this.alertCache.set(alertId, alert);
        return alert;
      }
    }

    // Fallback to database
    const alert = await this.prisma.alert.findFirst({
      where: { id: alertId, tenantId }
    });

    if (alert) {
      this.alertCache.set(alertId, alert as Alert);
    }

    return alert as Alert | null;
  }

  async getAlerts(tenantId: string, filters: any): Promise<Alert[]> {
    const where: any = { tenantId };

    if (filters.status) {
      if (filters.status === 'active') {
        where.resolved = false;
      } else if (filters.status === 'resolved') {
        where.resolved = true;
      }
    }
    
    if (filters.type) where.type = filters.type;
    if (filters.severity) where.severity = filters.severity;
    if (filters.buildingId) {
      where.location = { path: ['buildingId'], equals: filters.buildingId };
    }
    if (filters.floorId) {
      where.location = { path: ['floorId'], equals: filters.floorId };
    }
    if (filters.startTime || filters.endTime) {
      where.timestamp = {};
      if (filters.startTime) where.timestamp.gte = filters.startTime;
      if (filters.endTime) where.timestamp.lte = filters.endTime;
    }

    const alerts = await this.prisma.alert.findMany({
      where,
      orderBy: { timestamp: 'desc' },
      take: filters.limit || 100,
      skip: filters.offset || 0
    });

    return alerts as Alert[];
  }

  async getActiveAlerts(tenantId: string): Promise<Alert[]> {
    const alertIds = await this.redis.smembers(`active_alerts:${tenantId}`);
    const alerts: Alert[] = [];

    for (const alertId of alertIds) {
      const alert = await this.getAlert(alertId, tenantId);
      if (alert && !alert.resolved) {
        alerts.push(alert);
      }
    }

    return alerts.sort((a, b) => 
      new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    );
  }

  async acknowledgeAlert(alertId: string, userId: string, tenantId: string): Promise<Alert> {
    const alert = await this.getAlert(alertId, tenantId);
    if (!alert) {
      throw new Error('Alert not found');
    }

    const updatedAlert = {
      ...alert,
      acknowledged: true,
      acknowledgedBy: userId,
      acknowledgedAt: new Date().toISOString()
    };

    await this.prisma.alert.update({
      where: { id: alertId },
      data: updatedAlert
    });

    // Update cache
    this.alertCache.set(alertId, updatedAlert);
    await this.redis.hset('alerts', alertId, JSON.stringify(updatedAlert));

    console.log(`Alert acknowledged: ${alertId} by ${userId}`);
    
    return updatedAlert;
  }

  async resolveAlert(alertId: string, userId: string, tenantId: string, resolution?: string): Promise<Alert> {
    const alert = await this.getAlert(alertId, tenantId);
    if (!alert) {
      throw new Error('Alert not found');
    }

    const updatedAlert = {
      ...alert,
      resolved: true,
      resolvedBy: userId,
      resolvedAt: new Date().toISOString(),
      metadata: {
        ...alert.metadata,
        resolution: resolution || 'Manually resolved'
      }
    };

    await this.prisma.alert.update({
      where: { id: alertId },
      data: updatedAlert
    });

    // Update cache and remove from active alerts
    this.alertCache.set(alertId, updatedAlert);
    await this.redis.hset('alerts', alertId, JSON.stringify(updatedAlert));
    await this.redis.srem(`active_alerts:${tenantId}`, alertId);

    console.log(`Alert resolved: ${alertId} by ${userId}`);
    
    return updatedAlert;
  }

  async getAlertStatistics(tenantId: string, period: string): Promise<any> {
    const now = new Date();
    const startTime = this.getStartTimeForPeriod(now, period);

    const [total, active, bySeverity, byType] = await Promise.all([
      this.prisma.alert.count({
        where: { tenantId, timestamp: { gte: startTime } }
      }),
      this.prisma.alert.count({
        where: { tenantId, resolved: false }
      }),
      this.prisma.alert.groupBy({
        by: ['severity'],
        where: { tenantId, timestamp: { gte: startTime } },
        _count: true
      }),
      this.prisma.alert.groupBy({
        by: ['type'],
        where: { tenantId, timestamp: { gte: startTime } },
        _count: true
      })
    ]);

    const meanTimeToAcknowledge = await this.calculateMTTA(tenantId, startTime);
    const meanTimeToResolve = await this.calculateMTTR(tenantId, startTime);

    return {
      total,
      active,
      resolved: total - active,
      bySeverity: bySeverity.reduce((acc, item) => {
        acc[item.severity] = item._count;
        return acc;
      }, {} as Record<string, number>),
      byType: byType.reduce((acc, item) => {
        acc[item.type] = item._count;
        return acc;
      }, {} as Record<string, number>),
      meanTimeToAcknowledge,
      meanTimeToResolve,
      period,
      startTime,
      endTime: now
    };
  }

  async getCorrelationRules(tenantId: string): Promise<any[]> {
    // In production, these would be stored in the database
    return this.correlationRules;
  }

  async updateCorrelationRule(tenantId: string, ruleId: string, ruleData: any): Promise<any> {
    // In production, update in database
    const index = this.correlationRules.findIndex(r => r.id === ruleId);
    if (index >= 0) {
      this.correlationRules[index] = { ...this.correlationRules[index], ...ruleData };
      return this.correlationRules[index];
    }
    throw new Error('Rule not found');
  }

  async getStats(): Promise<any> {
    const [total, active] = await Promise.all([
      this.prisma.alert.count(),
      this.prisma.alert.count({ where: { resolved: false } })
    ]);

    return { total, active };
  }

  private async sendNotifications(alert: Alert): Promise<void> {
    try {
      const preferences = await this.notificationService.getPreferences(alert.tenantId);
      
      if (this.shouldNotify(alert.severity, preferences.email.minSeverity)) {
        for (const recipient of preferences.email.recipients) {
          await this.notificationService.sendEmail(
            recipient,
            `SPARC Alert: ${alert.title}`,
            this.formatAlertEmail(alert)
          );
        }
      }

      if (this.shouldNotify(alert.severity, preferences.sms.minSeverity)) {
        for (const recipient of preferences.sms.recipients) {
          await this.notificationService.sendSMS(
            recipient,
            `SPARC Alert: ${alert.title} - ${alert.description}`
          );
        }
      }

      if (this.shouldNotify(alert.severity, preferences.push.minSeverity)) {
        await this.notificationService.sendPushToTenant(
          alert.tenantId,
          {
            title: alert.title,
            body: alert.description,
            data: {
              alertId: alert.id,
              type: alert.type,
              severity: alert.severity
            }
          }
        );
      }
    } catch (error) {
      console.error('Failed to send alert notifications:', error);
    }
  }

  private shouldNotify(alertSeverity: string, minSeverity: string): boolean {
    const severityLevels = { low: 1, medium: 2, high: 3, critical: 4 };
    return severityLevels[alertSeverity as keyof typeof severityLevels] >= 
           severityLevels[minSeverity as keyof typeof severityLevels];
  }

  private formatAlertEmail(alert: Alert): string {
    return `
      <h2>SPARC Security Alert</h2>
      <p><strong>Severity:</strong> ${alert.severity.toUpperCase()}</p>
      <p><strong>Type:</strong> ${alert.type}</p>
      <p><strong>Title:</strong> ${alert.title}</p>
      <p><strong>Description:</strong> ${alert.description}</p>
      <p><strong>Location:</strong> Building ${alert.location.buildingId}, Floor ${alert.location.floorId}</p>
      <p><strong>Time:</strong> ${new Date(alert.timestamp).toLocaleString()}</p>
      <p><strong>Alert ID:</strong> ${alert.id}</p>
    `;
  }

  private getStartTimeForPeriod(now: Date, period: string): Date {
    const match = period.match(/(\d+)([hdwm])/);
    if (!match) return new Date(now.getTime() - 24 * 60 * 60 * 1000);
    
    const [, value, unit] = match;
    const num = parseInt(value);
    
    switch (unit) {
      case 'h': return new Date(now.getTime() - num * 60 * 60 * 1000);
      case 'd': return new Date(now.getTime() - num * 24 * 60 * 60 * 1000);
      case 'w': return new Date(now.getTime() - num * 7 * 24 * 60 * 60 * 1000);
      case 'm': return new Date(now.getTime() - num * 30 * 24 * 60 * 60 * 1000);
      default: return new Date(now.getTime() - 24 * 60 * 60 * 1000);
    }
  }

  private async calculateMTTA(tenantId: string, startTime: Date): Promise<number> {
    const alerts = await this.prisma.alert.findMany({
      where: {
        tenantId,
        timestamp: { gte: startTime },
        acknowledged: true
      }
    });

    if (alerts.length === 0) return 0;

    const totalTime = alerts.reduce((sum, alert) => {
      const created = new Date(alert.timestamp).getTime();
      const acknowledged = new Date(alert.acknowledgedAt!).getTime();
      return sum + (acknowledged - created);
    }, 0);

    return Math.round(totalTime / alerts.length / 60000); // Return in minutes
  }

  private async calculateMTTR(tenantId: string, startTime: Date): Promise<number> {
    const alerts = await this.prisma.alert.findMany({
      where: {
        tenantId,
        timestamp: { gte: startTime },
        resolved: true
      }
    });

    if (alerts.length === 0) return 0;

    const totalTime = alerts.reduce((sum, alert) => {
      const created = new Date(alert.timestamp).getTime();
      const resolved = new Date(alert.resolvedAt!).getTime();
      return sum + (resolved - created);
    }, 0);

    return Math.round(totalTime / alerts.length / 60000); // Return in minutes
  }
}