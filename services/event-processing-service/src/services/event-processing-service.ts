import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';
import { Server as SocketIOServer } from 'socket.io';
import { AlertService } from './alert-service';

interface EventData {
  id?: string;
  tenantId: string;
  timestamp: string;
  type: string;
  location?: {
    buildingId: string;
    floorId: string;
    zoneId?: string;
  };
  [key: string]: any;
}

interface CorrelationRule {
  id: string;
  name: string;
  eventTypes: string[];
  timeWindow: number;
  locationMatch: boolean;
  condition: (events: EventData[]) => boolean;
  alertTemplate: {
    type: 'security' | 'environmental' | 'system' | 'maintenance';
    severity: 'low' | 'medium' | 'high' | 'critical';
    title: string;
    description: string;
  };
}

export class EventProcessingService {
  private eventBuffer: Map<string, EventData[]> = new Map();
  private correlationRules: CorrelationRule[] = [];
  private processing = false;
  private correlationInterval?: NodeJS.Timeout;
  private eventStats = {
    access: 0,
    video: 0,
    environmental: 0
  };

  constructor(
    private prisma: PrismaClient,
    private redis: Redis,
    private redisSubscriber: Redis,
    private io: SocketIOServer,
    private alertService: AlertService
  ) {
    this.initializeCorrelationRules();
  }

  private initializeCorrelationRules(): void {
    // Multiple failed access attempts
    this.correlationRules.push({
      id: 'multiple_failed_access',
      name: 'Multiple Failed Access Attempts',
      eventTypes: ['access_denied'],
      timeWindow: 300, // 5 minutes
      locationMatch: true,
      condition: (events) => events.length >= 3,
      alertTemplate: {
        type: 'security',
        severity: 'high',
        title: 'Multiple Failed Access Attempts',
        description: 'Multiple failed access attempts detected'
      }
    });

    // Door forced followed by motion
    this.correlationRules.push({
      id: 'door_forced_with_motion',
      name: 'Door Forced with Motion',
      eventTypes: ['door_forced', 'motion_detected'],
      timeWindow: 60, // 1 minute
      locationMatch: true,
      condition: (events) => {
        const doorForced = events.find(e => e.eventType === 'door_forced');
        const motion = events.find(e => e.eventType === 'motion_detected');
        return !!(doorForced && motion);
      },
      alertTemplate: {
        type: 'security',
        severity: 'critical',
        title: 'Security Breach Detected',
        description: 'Door forced open followed by motion detection'
      }
    });

    // Environmental threshold cascade
    this.correlationRules.push({
      id: 'environmental_cascade',
      name: 'Environmental Threshold Cascade',
      eventTypes: ['temperature_high', 'humidity_high'],
      timeWindow: 600, // 10 minutes
      locationMatch: true,
      condition: (events) => {
        const tempEvents = events.filter(e => e.eventType === 'temperature_high');
        const humidityEvents = events.filter(e => e.eventType === 'humidity_high');
        return tempEvents.length > 0 && humidityEvents.length > 0;
      },
      alertTemplate: {
        type: 'environmental',
        severity: 'high',
        title: 'Environmental System Failure',
        description: 'Multiple environmental thresholds exceeded'
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
    
    console.log('Event processing started');
  }

  async stopProcessing(): Promise<void> {
    this.processing = false;
    
    if (this.correlationInterval) {
      clearInterval(this.correlationInterval);
    }
    
    await this.redisSubscriber.unsubscribe();
    
    console.log('Event processing stopped');
  }

  isProcessing(): boolean {
    return this.processing;
  }

  async getStats(): Promise<any> {
    return this.eventStats;
  }

  private async subscribeToEventStreams(): Promise<void> {
    // Subscribe to event channels
    await this.redisSubscriber.subscribe(
      'events:access',
      'events:video',
      'events:environmental'
    );

    this.redisSubscriber.on('message', (channel, message) => {
      try {
        const eventData = JSON.parse(message);
        this.processEvent(channel.split(':')[1], eventData);
      } catch (error) {
        console.error('Failed to process event:', error);
      }
    });
  }

  private async processEvent(eventType: string, eventData: EventData): Promise<void> {
    // Add to buffer for correlation
    this.addEventToBuffer(eventType, eventData);
    
    // Emit real-time event
    this.emitRealTimeEvent(`${eventType}_event`, eventData);
    
    // Update stats
    if (eventType in this.eventStats) {
      this.eventStats[eventType as keyof typeof this.eventStats]++;
    }
    
    // Store event
    await this.storeEvent(eventData);
    
    console.log(`Processed ${eventType} event:`, eventData.id);
  }

  private addEventToBuffer(type: string, event: EventData): void {
    const key = `${type}_${event.tenantId}_${event.location?.buildingId}_${event.location?.floorId}`;
    if (!this.eventBuffer.has(key)) {
      this.eventBuffer.set(key, []);
    }
    this.eventBuffer.get(key)!.push({
      ...event,
      receivedAt: new Date().toISOString(),
    });
    
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

    for (const [bufferKey, events] of this.eventBuffer.entries()) {
      const relevantEvents = events.filter(event => {
        const eventTime = new Date(event.timestamp);
        return eventTime >= windowStart && 
               rule.eventTypes.includes(event.eventType || event.type);
      });

      if (relevantEvents.length > 0 && rule.condition(relevantEvents)) {
        await this.generateCorrelatedAlert(rule, relevantEvents);
      }
    }
  }

  private async generateCorrelatedAlert(rule: CorrelationRule, events: EventData[]): Promise<void> {
    const firstEvent = events[0];
    
    await this.alertService.createAlert(firstEvent.tenantId, {
      ...rule.alertTemplate,
      sourceEvents: events.map(e => e.id).filter(Boolean) as string[],
      location: firstEvent.location!,
      metadata: {
        correlationRuleId: rule.id,
        eventCount: events.length,
        eventTypes: [...new Set(events.map(e => e.eventType || e.type))]
      }
    });
  }

  private emitRealTimeEvent(eventType: string, data: EventData): void {
    // Emit to tenant-specific room
    this.io.to(`tenant_${data.tenantId}`).emit(eventType, data);
    
    // Emit to building-specific room
    if (data.location?.buildingId) {
      this.io.to(`building_${data.tenantId}_${data.location.buildingId}`).emit(eventType, data);
    }
    
    // Emit to floor-specific room
    if (data.location?.floorId) {
      this.io.to(`floor_${data.tenantId}_${data.location.buildingId}_${data.location.floorId}`).emit(eventType, data);
    }
  }

  private async storeEvent(event: EventData): Promise<void> {
    // Store in database
    await this.prisma.event.create({
      data: {
        ...event,
        id: event.id || crypto.randomUUID(),
        metadata: event.metadata || {}
      }
    });
    
    // Store in Redis for quick access
    const key = `event:${event.tenantId}:${event.id}`;
    await this.redis.setex(key, 86400, JSON.stringify(event)); // 24 hour TTL
  }

  // Public methods for route handlers
  async submitAccessEvent(tenantId: string, eventData: any): Promise<EventData> {
    const event: EventData = {
      id: crypto.randomUUID(),
      tenantId,
      timestamp: new Date().toISOString(),
      type: 'access',
      ...eventData
    };
    
    // Publish to Redis for processing
    await this.redis.publish('events:access', JSON.stringify(event));
    
    return event;
  }

  async submitVideoEvent(tenantId: string, eventData: any): Promise<EventData> {
    const event: EventData = {
      id: crypto.randomUUID(),
      tenantId,
      timestamp: new Date().toISOString(),
      type: 'video',
      ...eventData
    };
    
    await this.redis.publish('events:video', JSON.stringify(event));
    
    return event;
  }

  async submitEnvironmentalEvent(tenantId: string, eventData: any): Promise<EventData> {
    const event: EventData = {
      id: crypto.randomUUID(),
      tenantId,
      timestamp: new Date().toISOString(),
      type: 'environmental',
      ...eventData
    };
    
    await this.redis.publish('events:environmental', JSON.stringify(event));
    
    return event;
  }

  async submitBulkEvents(tenantId: string, events: any[]): Promise<any> {
    const results = {
      processed: 0,
      failed: 0,
      results: [] as any[]
    };
    
    for (const eventData of events) {
      try {
        let event;
        switch (eventData.type) {
          case 'access':
            event = await this.submitAccessEvent(tenantId, eventData);
            break;
          case 'video':
            event = await this.submitVideoEvent(tenantId, eventData);
            break;
          case 'environmental':
            event = await this.submitEnvironmentalEvent(tenantId, eventData);
            break;
          default:
            throw new Error(`Unknown event type: ${eventData.type}`);
        }
        
        results.processed++;
        results.results.push({ success: true, eventId: event.id });
      } catch (error) {
        results.failed++;
        results.results.push({ success: false, error: error.message });
      }
    }
    
    return results;
  }

  async getEvents(tenantId: string, filters: any): Promise<EventData[]> {
    const where: any = { tenantId };
    
    if (filters.type) where.type = filters.type;
    if (filters.buildingId) where.location = { path: ['buildingId'], equals: filters.buildingId };
    if (filters.floorId) where.location = { path: ['floorId'], equals: filters.floorId };
    if (filters.startTime) where.timestamp = { gte: filters.startTime };
    if (filters.endTime) where.timestamp = { ...where.timestamp, lte: filters.endTime };
    
    const events = await this.prisma.event.findMany({
      where,
      orderBy: { timestamp: 'desc' },
      take: filters.limit || 100
    });
    
    return events;
  }

  async getEvent(tenantId: string, eventId: string): Promise<EventData | null> {
    // Try cache first
    const cached = await this.redis.get(`event:${tenantId}:${eventId}`);
    if (cached) {
      return JSON.parse(cached);
    }
    
    const event = await this.prisma.event.findFirst({
      where: { id: eventId, tenantId }
    });
    
    return event;
  }

  async getEventStatistics(tenantId: string, period: string): Promise<any> {
    const now = new Date();
    const startTime = this.getStartTimeForPeriod(now, period);
    
    const stats = await this.prisma.event.groupBy({
      by: ['type'],
      where: {
        tenantId,
        timestamp: { gte: startTime }
      },
      _count: true
    });
    
    return {
      total: stats.reduce((sum, s) => sum + s._count, 0),
      byType: stats.reduce((acc, s) => {
        acc[s.type] = s._count;
        return acc;
      }, {} as Record<string, number>),
      period,
      startTime,
      endTime: now
    };
  }

  async getEventTrends(tenantId: string, options: any): Promise<any> {
    // Implementation would group events by time intervals
    // For now, return mock data
    return {
      intervals: [],
      total: 0
    };
  }

  private getStartTimeForPeriod(now: Date, period: string): Date {
    const match = period.match(/(\d+)([hdwm])/);
    if (!match) return new Date(now.getTime() - 24 * 60 * 60 * 1000); // Default 24h
    
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
}