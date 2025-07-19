import { eq, and, desc, gte, lte, sql } from 'drizzle-orm';
import { db } from '../db';
import { alerts, alertEscalations, alertNotifications } from '@sparc/database/schemas/alerts';
import type { 
  Alert, 
  CreateAlertDTO, 
  UpdateAlertDTO,
  AlertListResponse,
  AlertStatistics,
  AlertPriority,
  AlertStatus,
  PRIORITY_CONFIG,
  ALERT_TYPE_CONFIG
} from '@sparc/shared/types/alerts';
import { Redis } from 'ioredis';
import { v4 as uuidv4 } from 'uuid';

export class AlertService {
  constructor(private redis: Redis) {}

  async createAlert(tenantId: string, data: CreateAlertDTO): Promise<Alert> {
    const [alert] = await db.insert(alerts).values({
      id: uuidv4(),
      tenantId,
      ...data,
      status: 'open' as const,
      createdAt: new Date(),
      updatedAt: new Date()
    }).returning();

    // Cache the alert
    await this.cacheAlert(alert);

    // Update stats
    await this.updateAlertStats(tenantId, alert.priority as AlertPriority, 'increment');

    return this.mapToAlert(alert);
  }

  async getAlert(tenantId: string, alertId: string): Promise<Alert | null> {
    // Check cache first
    const cached = await this.redis.get(`alert:${alertId}`);
    if (cached) {
      const alert = JSON.parse(cached);
      if (alert.tenantId === tenantId) {
        return alert;
      }
    }

    const [alert] = await db.select()
      .from(alerts)
      .where(and(
        eq(alerts.id, alertId),
        eq(alerts.tenantId, tenantId)
      ))
      .limit(1);

    if (!alert) {
      return null;
    }

    const mappedAlert = this.mapToAlert(alert);
    await this.cacheAlert(alert);
    return mappedAlert;
  }

  async listAlerts(
    tenantId: string,
    options: {
      page?: number;
      limit?: number;
      status?: AlertStatus;
      priority?: AlertPriority;
      alertType?: string;
      sourceType?: string;
      startDate?: string;
      endDate?: string;
    }
  ): Promise<AlertListResponse> {
    const page = options.page || 1;
    const limit = options.limit || 50;
    const offset = (page - 1) * limit;

    // Build where conditions
    const conditions = [eq(alerts.tenantId, tenantId)];
    
    if (options.status) {
      conditions.push(eq(alerts.status, options.status));
    }
    if (options.priority) {
      conditions.push(eq(alerts.priority, options.priority));
    }
    if (options.alertType) {
      conditions.push(eq(alerts.alertType, options.alertType as any));
    }
    if (options.sourceType) {
      conditions.push(eq(alerts.sourceType, options.sourceType as any));
    }
    if (options.startDate) {
      conditions.push(gte(alerts.createdAt, new Date(options.startDate)));
    }
    if (options.endDate) {
      conditions.push(lte(alerts.createdAt, new Date(options.endDate)));
    }

    // Get total count
    const [{ count }] = await db.select({ count: sql<number>`count(*)` })
      .from(alerts)
      .where(and(...conditions));

    // Get paginated results
    const results = await db.select()
      .from(alerts)
      .where(and(...conditions))
      .orderBy(desc(alerts.priority), desc(alerts.createdAt))
      .limit(limit)
      .offset(offset);

    return {
      alerts: results.map(this.mapToAlert),
      pagination: {
        page,
        limit,
        total: Number(count),
        pages: Math.ceil(Number(count) / limit)
      }
    };
  }

  async updateAlert(
    tenantId: string, 
    alertId: string, 
    data: UpdateAlertDTO
  ): Promise<Alert | null> {
    const updateData: any = {
      ...data,
      updatedAt: new Date()
    };

    // Set timestamps based on status changes
    if (data.status === 'acknowledged' && data.acknowledgedBy) {
      updateData.acknowledgedAt = new Date();
    }
    if (data.status === 'resolved') {
      updateData.resolvedAt = new Date();
    }
    if (data.status === 'closed') {
      updateData.closedAt = new Date();
    }

    const [updated] = await db.update(alerts)
      .set(updateData)
      .where(and(
        eq(alerts.id, alertId),
        eq(alerts.tenantId, tenantId)
      ))
      .returning();

    if (!updated) {
      return null;
    }

    // Update cache
    await this.cacheAlert(updated);

    // Update stats if status changed
    if (data.status) {
      await this.updateAlertStats(tenantId, updated.priority as AlertPriority, 'update', data.status);
    }

    return this.mapToAlert(updated);
  }

  async acknowledgeAlert(
    tenantId: string,
    alertId: string,
    acknowledgedBy: string
  ): Promise<Alert | null> {
    return this.updateAlert(tenantId, alertId, {
      status: 'acknowledged' as AlertStatus,
      acknowledgedBy
    });
  }

  async deleteAlert(tenantId: string, alertId: string): Promise<boolean> {
    const [deleted] = await db.delete(alerts)
      .where(and(
        eq(alerts.id, alertId),
        eq(alerts.tenantId, tenantId)
      ))
      .returning();

    if (deleted) {
      // Remove from cache
      await this.redis.del(`alert:${alertId}`);
      
      // Update stats
      await this.updateAlertStats(tenantId, deleted.priority as AlertPriority, 'decrement');
      
      return true;
    }

    return false;
  }

  async getAlertStatistics(
    tenantId: string,
    timeframe: string = '24h'
  ): Promise<AlertStatistics> {
    const startDate = this.getStartDateForTimeframe(timeframe);

    const conditions = [
      eq(alerts.tenantId, tenantId),
      gte(alerts.createdAt, startDate)
    ];

    // Get counts by status
    const statusCounts = await db.select({
      status: alerts.status,
      count: sql<number>`count(*)`
    })
      .from(alerts)
      .where(and(...conditions))
      .groupBy(alerts.status);

    // Get counts by priority
    const priorityCounts = await db.select({
      priority: alerts.priority,
      count: sql<number>`count(*)`
    })
      .from(alerts)
      .where(and(...conditions))
      .groupBy(alerts.priority);

    // Get counts by type
    const typeCounts = await db.select({
      alertType: alerts.alertType,
      count: sql<number>`count(*)`
    })
      .from(alerts)
      .where(and(...conditions))
      .groupBy(alerts.alertType);

    // Build response
    const summary = {
      total: 0,
      open: 0,
      acknowledged: 0,
      resolved: 0,
      critical: 0
    };

    statusCounts.forEach(({ status, count }) => {
      const countNum = Number(count);
      summary.total += countNum;
      if (status === 'open') summary.open = countNum;
      if (status === 'acknowledged') summary.acknowledged = countNum;
      if (status === 'resolved') summary.resolved = countNum;
    });

    priorityCounts.forEach(({ priority, count }) => {
      if (priority === 'critical') {
        summary.critical = Number(count);
      }
    });

    const byType: Record<string, number> = {};
    typeCounts.forEach(({ alertType, count }) => {
      byType[alertType] = Number(count);
    });

    const byPriority: Record<string, number> = {};
    priorityCounts.forEach(({ priority, count }) => {
      byPriority[priority] = Number(count);
    });

    return {
      timeframe,
      summary,
      byType,
      byPriority
    };
  }

  async addEscalation(
    alertId: string,
    escalationLevel: string,
    escalatedTo?: string,
    notes?: string
  ): Promise<void> {
    await db.insert(alertEscalations).values({
      id: uuidv4(),
      alertId,
      escalationLevel,
      escalatedTo,
      notes,
      escalatedAt: new Date()
    });
  }

  async trackNotification(
    alertId: string,
    notificationType: string,
    recipientId?: string,
    recipientAddress?: string
  ): Promise<string> {
    const [notification] = await db.insert(alertNotifications).values({
      id: uuidv4(),
      alertId,
      notificationType,
      recipientId,
      recipientAddress,
      sentAt: new Date(),
      retryCount: '0'
    }).returning();

    return notification.id;
  }

  async updateNotificationStatus(
    notificationId: string,
    status: 'delivered' | 'failed',
    failureReason?: string
  ): Promise<void> {
    const updateData: any = {};
    
    if (status === 'delivered') {
      updateData.deliveredAt = new Date();
    } else {
      updateData.failedAt = new Date();
      updateData.failureReason = failureReason;
      updateData.retryCount = sql`${alertNotifications.retryCount}::int + 1`;
    }

    await db.update(alertNotifications)
      .set(updateData)
      .where(eq(alertNotifications.id, notificationId));
  }

  private async cacheAlert(alert: any): Promise<void> {
    await this.redis.setex(
      `alert:${alert.id}`,
      3600, // 1 hour TTL
      JSON.stringify(this.mapToAlert(alert))
    );
  }

  private async updateAlertStats(
    tenantId: string,
    priority: AlertPriority,
    action: 'increment' | 'decrement' | 'update',
    newStatus?: AlertStatus
  ): Promise<void> {
    const key = `alert_stats:${tenantId}`;
    
    if (action === 'increment') {
      await this.redis.hincrby(key, priority, 1);
      await this.redis.hincrby(key, 'open', 1);
      await this.redis.hincrby(key, 'total', 1);
    } else if (action === 'decrement') {
      await this.redis.hincrby(key, priority, -1);
      await this.redis.hincrby(key, 'total', -1);
    } else if (action === 'update' && newStatus) {
      // Update status counts
      await this.redis.hincrby(key, newStatus, 1);
      if (newStatus === 'acknowledged') {
        await this.redis.hincrby(key, 'open', -1);
      } else if (newStatus === 'resolved') {
        await this.redis.hincrby(key, 'acknowledged', -1);
      }
    }

    // Set expiry on stats
    await this.redis.expire(key, 86400); // 24 hours
  }

  private getStartDateForTimeframe(timeframe: string): Date {
    const now = Date.now();
    switch (timeframe) {
      case '1h':
        return new Date(now - 60 * 60 * 1000);
      case '24h':
        return new Date(now - 24 * 60 * 60 * 1000);
      case '7d':
        return new Date(now - 7 * 24 * 60 * 60 * 1000);
      case '30d':
        return new Date(now - 30 * 24 * 60 * 60 * 1000);
      default:
        return new Date(now - 24 * 60 * 60 * 1000);
    }
  }

  private mapToAlert(dbAlert: any): Alert {
    return {
      id: dbAlert.id,
      tenantId: dbAlert.tenantId,
      alertType: dbAlert.alertType,
      priority: dbAlert.priority,
      sourceId: dbAlert.sourceId,
      sourceType: dbAlert.sourceType,
      message: dbAlert.message,
      details: dbAlert.details || {},
      status: dbAlert.status,
      acknowledgedBy: dbAlert.acknowledgedBy,
      acknowledgedAt: dbAlert.acknowledgedAt,
      resolvedAt: dbAlert.resolvedAt,
      closedAt: dbAlert.closedAt,
      createdAt: dbAlert.createdAt,
      updatedAt: dbAlert.updatedAt
    };
  }
}