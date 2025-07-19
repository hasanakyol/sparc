import { eq, and, desc, gte, lte, sql, inArray } from 'drizzle-orm';
import { db } from '../db';
import { 
  events, 
  eventCorrelations, 
  eventProcessingRules 
} from '@sparc/database/schemas/events';
import { 
  alerts, 
  alertEscalations, 
  alertNotifications 
} from '@sparc/database/schemas/alerts';
import type { 
  Alert, 
  CreateAlertDTO, 
  UpdateAlertDTO,
  AlertListResponse,
  AlertStatistics,
  AlertPriority,
  AlertStatus
} from '@sparc/shared/types/alerts';
import { Redis } from 'ioredis';
import { v4 as uuidv4 } from 'uuid';
import { logger } from '@sparc/shared';
import { Server as SocketIOServer } from 'socket.io';

interface EventData {
  id?: string;
  tenantId: string;
  timestamp: string;
  eventType: string;
  eventSubType: string;
  sourceId: string;
  sourceType: string;
  location?: {
    buildingId: string;
    floorId: string;
    zoneId?: string;
  };
  metadata?: any;
  value?: string;
  threshold?: string;
  confidence?: string;
  userId?: string;
  description?: string;
}

interface CorrelationRule {
  id: string;
  name: string;
  eventTypes: string[];
  eventSubTypes?: string[];
  timeWindow: number;
  locationMatch: boolean;
  condition: (events: EventData[]) => boolean;
  alertTemplate: {
    alertType: string;
    priority: 'low' | 'medium' | 'high' | 'critical';
    sourceType: string;
    message: string;
    details?: any;
  };
}

export class UnifiedEventService {
  private eventBuffer: Map<string, EventData[]> = new Map();
  private correlationRules: CorrelationRule[] = [];
  private processing = false;
  private correlationInterval?: NodeJS.Timeout;
  private eventStats = {
    access: 0,
    video: 0,
    environmental: 0,
    system: 0,
    security: 0
  };

  constructor(
    private redis: Redis,
    private redisSubscriber: Redis,
    private io?: SocketIOServer
  ) {
    this.initializeCorrelationRules();
  }

  // ==================== Alert Management ====================

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

    // Broadcast alert
    if (this.io) {
      await this.broadcastAlert('created', tenantId, alert);
    }

    logger.info('Alert created', { 
      alertId: alert.id, 
      tenantId,
      type: alert.alertType,
      priority: alert.priority 
    });

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

    // Broadcast update
    if (this.io) {
      await this.broadcastAlert('updated', tenantId, updated);
    }

    logger.info('Alert updated', { 
      alertId: updated.id, 
      tenantId,
      status: updated.status 
    });

    return this.mapToAlert(updated);
  }

  async acknowledgeAlert(
    tenantId: string,
    alertId: string,
    acknowledgedBy: string
  ): Promise<Alert | null> {
    const alert = await this.updateAlert(tenantId, alertId, {
      status: 'acknowledged' as AlertStatus,
      acknowledgedBy
    });

    if (alert && this.io) {
      // Cancel escalation
      await this.redis.publish('escalation:cancel', alertId);
    }

    return alert;
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
      
      // Broadcast deletion
      if (this.io) {
        await this.broadcastAlert('deleted', tenantId, { id: alertId });
      }

      // Cancel escalation
      await this.redis.publish('escalation:cancel', alertId);
      
      logger.info('Alert deleted', { alertId, tenantId });
      
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

  // ==================== Event Processing ====================

  private initializeCorrelationRules(): void {
    // Multiple failed access attempts
    this.correlationRules.push({
      id: 'multiple_failed_access',
      name: 'Multiple Failed Access Attempts',
      eventTypes: ['access'],
      eventSubTypes: ['access_denied'],
      timeWindow: 300, // 5 minutes
      locationMatch: true,
      condition: (events) => events.length >= 3,
      alertTemplate: {
        alertType: 'security_breach',
        priority: 'high',
        sourceType: 'security',
        message: 'Multiple failed access attempts detected',
        details: { ruleId: 'multiple_failed_access' }
      }
    });

    // Door forced followed by motion
    this.correlationRules.push({
      id: 'door_forced_with_motion',
      name: 'Door Forced with Motion',
      eventTypes: ['access', 'video'],
      eventSubTypes: ['door_forced', 'motion_detected'],
      timeWindow: 60, // 1 minute
      locationMatch: true,
      condition: (events) => {
        const doorForced = events.find(e => e.eventSubType === 'door_forced');
        const motion = events.find(e => e.eventSubType === 'motion_detected');
        return !!(doorForced && motion);
      },
      alertTemplate: {
        alertType: 'security_breach',
        priority: 'critical',
        sourceType: 'security',
        message: 'Door forced open followed by motion detection',
        details: { ruleId: 'door_forced_with_motion' }
      }
    });

    // Environmental threshold cascade
    this.correlationRules.push({
      id: 'environmental_cascade',
      name: 'Environmental Threshold Cascade',
      eventTypes: ['environmental'],
      eventSubTypes: ['temperature_high', 'humidity_high'],
      timeWindow: 600, // 10 minutes
      locationMatch: true,
      condition: (events) => {
        const tempEvents = events.filter(e => e.eventSubType === 'temperature_high');
        const humidityEvents = events.filter(e => e.eventSubType === 'humidity_high');
        return tempEvents.length > 0 && humidityEvents.length > 0;
      },
      alertTemplate: {
        alertType: 'maintenance_required',
        priority: 'high',
        sourceType: 'environmental',
        message: 'Multiple environmental thresholds exceeded',
        details: { ruleId: 'environmental_cascade' }
      }
    });

    // Camera offline cascade
    this.correlationRules.push({
      id: 'multiple_cameras_offline',
      name: 'Multiple Cameras Offline',
      eventTypes: ['video'],
      eventSubTypes: ['camera_offline'],
      timeWindow: 300, // 5 minutes
      locationMatch: false,
      condition: (events) => events.length >= 3,
      alertTemplate: {
        alertType: 'system_offline',
        priority: 'high',
        sourceType: 'video',
        message: 'Multiple cameras offline',
        details: { ruleId: 'multiple_cameras_offline' }
      }
    });
  }

  async startProcessing(): Promise<void> {
    if (this.processing) return;
    
    this.processing = true;
    
    // Subscribe to Redis streams
    await this.subscribeToEventStreams();
    
    // Start correlation processing
    this.correlationInterval = setInterval(() => {
      this.processCorrelations();
    }, 5000); // Process every 5 seconds
    
    // Load custom rules from database
    await this.loadCustomRules();
    
    logger.info('Event processing started');
  }

  async stopProcessing(): Promise<void> {
    this.processing = false;
    
    if (this.correlationInterval) {
      clearInterval(this.correlationInterval);
    }
    
    await this.redisSubscriber.unsubscribe();
    
    logger.info('Event processing stopped');
  }

  isProcessing(): boolean {
    return this.processing;
  }

  async getStats(): Promise<any> {
    return {
      eventCounts: this.eventStats,
      bufferSize: this.eventBuffer.size,
      activeRules: this.correlationRules.length,
      processing: this.processing
    };
  }

  private async subscribeToEventStreams(): Promise<void> {
    // Subscribe to event channels
    await this.redisSubscriber.subscribe(
      'events:access',
      'events:video',
      'events:environmental',
      'events:system',
      'events:security'
    );

    this.redisSubscriber.on('message', async (channel, message) => {
      try {
        const eventData = JSON.parse(message);
        await this.processEvent(channel.split(':')[1], eventData);
      } catch (error) {
        logger.error('Failed to process event:', error);
      }
    });
  }

  private async processEvent(eventType: string, eventData: EventData): Promise<void> {
    // Store event in database
    const storedEvent = await this.storeEvent(eventData);
    
    // Add to buffer for correlation
    this.addEventToBuffer(eventType, storedEvent);
    
    // Emit real-time event
    if (this.io) {
      this.emitRealTimeEvent(storedEvent);
    }
    
    // Update stats
    if (eventType in this.eventStats) {
      this.eventStats[eventType as keyof typeof this.eventStats]++;
    }
    
    logger.debug(`Processed ${eventType} event:`, { eventId: storedEvent.id });
  }

  private addEventToBuffer(type: string, event: EventData): void {
    const key = `${type}_${event.tenantId}_${event.location?.buildingId || 'none'}_${event.location?.floorId || 'none'}`;
    if (!this.eventBuffer.has(key)) {
      this.eventBuffer.set(key, []);
    }
    this.eventBuffer.get(key)!.push(event);
    
    // Clean old events from buffer
    this.cleanEventBuffer();
  }

  private cleanEventBuffer(): void {
    const now = Date.now();
    const maxAge = 3600000; // 1 hour
    
    for (const [key, events] of this.eventBuffer.entries()) {
      const filtered = events.filter(event => {
        const eventTime = new Date(event.timestamp).getTime();
        return now - eventTime < maxAge;
      });
      
      if (filtered.length === 0) {
        this.eventBuffer.delete(key);
      } else {
        this.eventBuffer.set(key, filtered);
      }
    }
  }

  private async processCorrelations(): Promise<void> {
    for (const rule of this.correlationRules) {
      await this.applyCorrelationRule(rule);
    }
  }

  private async applyCorrelationRule(rule: CorrelationRule): Promise<void> {
    const now = new Date();
    const windowStart = new Date(now.getTime() - rule.timeWindow * 1000);

    // Track processed event groups to avoid duplicate alerts
    const processedGroups = new Set<string>();

    for (const [bufferKey, events] of this.eventBuffer.entries()) {
      const relevantEvents = events.filter(event => {
        const eventTime = new Date(event.timestamp);
        return eventTime >= windowStart && 
               rule.eventTypes.includes(event.eventType) &&
               (!rule.eventSubTypes || rule.eventSubTypes.includes(event.eventSubType));
      });

      if (relevantEvents.length > 0 && rule.condition(relevantEvents)) {
        const groupKey = `${rule.id}_${relevantEvents[0].tenantId}_${JSON.stringify(relevantEvents[0].location)}`;
        
        if (!processedGroups.has(groupKey)) {
          processedGroups.add(groupKey);
          await this.generateCorrelatedAlert(rule, relevantEvents);
        }
      }
    }
  }

  private async generateCorrelatedAlert(rule: CorrelationRule, correlatedEvents: EventData[]): Promise<void> {
    const firstEvent = correlatedEvents[0];
    
    // Check if we've already created an alert for these events recently
    const recentAlertKey = `alert:correlation:${rule.id}:${firstEvent.tenantId}:${JSON.stringify(firstEvent.location)}`;
    const recentAlert = await this.redis.get(recentAlertKey);
    
    if (recentAlert) {
      return; // Skip if we've already created an alert for this correlation
    }
    
    // Create the alert
    const alert = await this.createAlert(firstEvent.tenantId, {
      ...rule.alertTemplate,
      sourceId: correlatedEvents.map(e => e.sourceId).join(','),
      details: {
        ...rule.alertTemplate.details,
        correlatedEvents: correlatedEvents.map(e => ({
          id: e.id,
          type: e.eventType,
          subType: e.eventSubType,
          timestamp: e.timestamp,
          sourceId: e.sourceId
        })),
        location: firstEvent.location
      }
    });
    
    // Store correlation records
    for (const event of correlatedEvents) {
      if (event.id && alert.id) {
        await db.insert(eventCorrelations).values({
          id: uuidv4(),
          alertId: alert.id,
          eventId: event.id,
          correlationRuleId: rule.id,
          createdAt: new Date()
        });
      }
    }
    
    // Mark this correlation as processed for 5 minutes
    await this.redis.setex(recentAlertKey, 300, '1');
    
    logger.info('Generated correlated alert', {
      alertId: alert.id,
      ruleId: rule.id,
      eventCount: correlatedEvents.length
    });
  }

  // ==================== Event Submission ====================

  async submitEvent(eventData: Partial<EventData>): Promise<EventData> {
    const event: EventData = {
      id: uuidv4(),
      timestamp: new Date().toISOString(),
      ...eventData
    } as EventData;
    
    // Validate required fields
    if (!event.tenantId || !event.eventType || !event.eventSubType || !event.sourceId || !event.sourceType) {
      throw new Error('Missing required event fields');
    }
    
    // Publish to Redis for processing
    await this.redis.publish(`events:${event.eventType}`, JSON.stringify(event));
    
    return event;
  }

  async submitAccessEvent(tenantId: string, eventData: any): Promise<EventData> {
    return this.submitEvent({
      tenantId,
      eventType: 'access',
      ...eventData
    });
  }

  async submitVideoEvent(tenantId: string, eventData: any): Promise<EventData> {
    return this.submitEvent({
      tenantId,
      eventType: 'video',
      ...eventData
    });
  }

  async submitEnvironmentalEvent(tenantId: string, eventData: any): Promise<EventData> {
    return this.submitEvent({
      tenantId,
      eventType: 'environmental',
      ...eventData
    });
  }

  async submitSystemEvent(tenantId: string, eventData: any): Promise<EventData> {
    return this.submitEvent({
      tenantId,
      eventType: 'system',
      ...eventData
    });
  }

  async submitSecurityEvent(tenantId: string, eventData: any): Promise<EventData> {
    return this.submitEvent({
      tenantId,
      eventType: 'security',
      ...eventData
    });
  }

  async submitBulkEvents(tenantId: string, eventsData: any[]): Promise<any> {
    const results = {
      processed: 0,
      failed: 0,
      results: [] as any[]
    };
    
    for (const eventData of eventsData) {
      try {
        const event = await this.submitEvent({
          tenantId,
          ...eventData
        });
        
        results.processed++;
        results.results.push({ success: true, eventId: event.id });
      } catch (error: any) {
        results.failed++;
        results.results.push({ success: false, error: error.message });
      }
    }
    
    return results;
  }

  // ==================== Event Querying ====================

  async getEvents(tenantId: string, filters: any): Promise<EventData[]> {
    const conditions = [eq(events.tenantId, tenantId)];
    
    if (filters.type) {
      conditions.push(eq(events.eventType, filters.type));
    }
    if (filters.subType) {
      conditions.push(eq(events.eventSubType, filters.subType));
    }
    if (filters.sourceId) {
      conditions.push(eq(events.sourceId, filters.sourceId));
    }
    if (filters.startTime) {
      conditions.push(gte(events.timestamp, new Date(filters.startTime)));
    }
    if (filters.endTime) {
      conditions.push(lte(events.timestamp, new Date(filters.endTime)));
    }
    
    const results = await db.select()
      .from(events)
      .where(and(...conditions))
      .orderBy(desc(events.timestamp))
      .limit(filters.limit || 100);
    
    return results.map(this.mapToEvent);
  }

  async getEvent(tenantId: string, eventId: string): Promise<EventData | null> {
    // Try cache first
    const cached = await this.redis.get(`event:${eventId}`);
    if (cached) {
      const event = JSON.parse(cached);
      if (event.tenantId === tenantId) {
        return event;
      }
    }
    
    const [event] = await db.select()
      .from(events)
      .where(and(
        eq(events.id, eventId),
        eq(events.tenantId, tenantId)
      ))
      .limit(1);
    
    if (!event) {
      return null;
    }
    
    const mappedEvent = this.mapToEvent(event);
    await this.cacheEvent(mappedEvent);
    return mappedEvent;
  }

  async getEventStatistics(tenantId: string, period: string): Promise<any> {
    const startTime = this.getStartDateForTimeframe(period);
    
    const conditions = [
      eq(events.tenantId, tenantId),
      gte(events.timestamp, startTime)
    ];
    
    // Get counts by type
    const typeCounts = await db.select({
      eventType: events.eventType,
      count: sql<number>`count(*)`
    })
      .from(events)
      .where(and(...conditions))
      .groupBy(events.eventType);
    
    // Get counts by sub-type
    const subTypeCounts = await db.select({
      eventSubType: events.eventSubType,
      count: sql<number>`count(*)`
    })
      .from(events)
      .where(and(...conditions))
      .groupBy(events.eventSubType);
    
    const total = typeCounts.reduce((sum, { count }) => sum + Number(count), 0);
    
    return {
      total,
      byType: typeCounts.reduce((acc, { eventType, count }) => {
        acc[eventType] = Number(count);
        return acc;
      }, {} as Record<string, number>),
      bySubType: subTypeCounts.reduce((acc, { eventSubType, count }) => {
        acc[eventSubType] = Number(count);
        return acc;
      }, {} as Record<string, number>),
      period,
      startTime,
      endTime: new Date()
    };
  }

  async getEventTrends(tenantId: string, options: any): Promise<any> {
    const { startTime, endTime, interval = '1h' } = options;
    
    // This is a simplified implementation
    // In production, you'd want to use proper time bucketing
    const conditions = [
      eq(events.tenantId, tenantId),
      gte(events.timestamp, startTime),
      lte(events.timestamp, endTime)
    ];
    
    const results = await db.select({
      eventType: events.eventType,
      count: sql<number>`count(*)`
    })
      .from(events)
      .where(and(...conditions))
      .groupBy(events.eventType);
    
    return {
      trends: results,
      interval,
      startTime,
      endTime
    };
  }

  // ==================== Helper Methods ====================

  private async storeEvent(eventData: EventData): Promise<EventData> {
    const [stored] = await db.insert(events).values({
      ...eventData,
      id: eventData.id || uuidv4(),
      createdAt: new Date()
    }).returning();
    
    const mappedEvent = this.mapToEvent(stored);
    
    // Cache event
    await this.cacheEvent(mappedEvent);
    
    return mappedEvent;
  }

  private async cacheEvent(event: EventData): Promise<void> {
    await this.redis.setex(
      `event:${event.id}`,
      86400, // 24 hour TTL
      JSON.stringify(event)
    );
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

  private async broadcastAlert(action: string, tenantId: string, alert: any): Promise<void> {
    await this.redis.publish('alert:broadcast', JSON.stringify({
      action,
      tenantId,
      alert
    }));
  }

  private emitRealTimeEvent(event: EventData): void {
    if (!this.io) return;
    
    // Emit to tenant-specific room
    this.io.to(`tenant:${event.tenantId}`).emit(`event:${event.eventType}`, event);
    
    // Emit to location-specific rooms
    if (event.location?.buildingId) {
      this.io.to(`building:${event.tenantId}:${event.location.buildingId}`).emit(`event:${event.eventType}`, event);
    }
    
    if (event.location?.floorId) {
      this.io.to(`floor:${event.tenantId}:${event.location.buildingId}:${event.location.floorId}`).emit(`event:${event.eventType}`, event);
    }
  }

  private getStartDateForTimeframe(timeframe: string): Date {
    const now = Date.now();
    const match = timeframe.match(/(\d+)([hdwm])/);
    
    if (!match) {
      return new Date(now - 24 * 60 * 60 * 1000); // Default 24h
    }
    
    const [, value, unit] = match;
    const num = parseInt(value);
    
    switch (unit) {
      case 'h': return new Date(now - num * 60 * 60 * 1000);
      case 'd': return new Date(now - num * 24 * 60 * 60 * 1000);
      case 'w': return new Date(now - num * 7 * 24 * 60 * 60 * 1000);
      case 'm': return new Date(now - num * 30 * 24 * 60 * 60 * 1000);
      default: return new Date(now - 24 * 60 * 60 * 1000);
    }
  }

  private async loadCustomRules(): Promise<void> {
    // Load enabled rules from database
    const customRules = await db.select()
      .from(eventProcessingRules)
      .where(eq(eventProcessingRules.enabled, 'true'));
    
    // Convert database rules to CorrelationRule format
    for (const dbRule of customRules) {
      try {
        const rule: CorrelationRule = {
          id: dbRule.id,
          name: dbRule.name,
          eventTypes: dbRule.eventTypes as string[],
          timeWindow: this.parseTimeWindow(dbRule.timeWindow || '5m'),
          locationMatch: dbRule.conditions?.locationMatch || false,
          condition: this.buildConditionFunction(dbRule.conditions),
          alertTemplate: {
            alertType: dbRule.actions?.alertType || 'system',
            priority: dbRule.priority as any || 'medium',
            sourceType: dbRule.actions?.sourceType || 'system',
            message: dbRule.actions?.message || dbRule.description || 'Event correlation triggered',
            details: {
              ruleId: dbRule.id,
              ruleName: dbRule.name,
              ...dbRule.actions?.details
            }
          }
        };
        
        this.correlationRules.push(rule);
      } catch (error) {
        logger.error('Failed to load custom rule', { ruleId: dbRule.id, error });
      }
    }
    
    logger.info(`Loaded ${customRules.length} custom correlation rules`);
  }

  private parseTimeWindow(timeWindow: string): number {
    const match = timeWindow.match(/(\d+)([smhd])/);
    if (!match) return 300; // Default 5 minutes
    
    const [, value, unit] = match;
    const num = parseInt(value);
    
    switch (unit) {
      case 's': return num;
      case 'm': return num * 60;
      case 'h': return num * 3600;
      case 'd': return num * 86400;
      default: return 300;
    }
  }

  private buildConditionFunction(conditions: any): (events: EventData[]) => boolean {
    // Simple condition builder - in production, you'd want a more sophisticated DSL
    return (events: EventData[]) => {
      if (conditions.minCount && events.length < conditions.minCount) {
        return false;
      }
      
      if (conditions.maxCount && events.length > conditions.maxCount) {
        return false;
      }
      
      if (conditions.requiredSubTypes) {
        const subTypes = new Set(events.map(e => e.eventSubType));
        for (const required of conditions.requiredSubTypes) {
          if (!subTypes.has(required)) {
            return false;
          }
        }
      }
      
      return true;
    };
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

  private mapToEvent(dbEvent: any): EventData {
    return {
      id: dbEvent.id,
      tenantId: dbEvent.tenantId,
      timestamp: dbEvent.timestamp,
      eventType: dbEvent.eventType,
      eventSubType: dbEvent.eventSubType,
      sourceId: dbEvent.sourceId,
      sourceType: dbEvent.sourceType,
      location: dbEvent.location,
      metadata: dbEvent.metadata,
      value: dbEvent.value,
      threshold: dbEvent.threshold,
      confidence: dbEvent.confidence,
      userId: dbEvent.userId,
      description: dbEvent.description
    };
  }

  // ==================== Alert Helper Methods ====================

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
}