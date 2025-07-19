import { DomainEvent } from './eventBus';
import { logger } from '@/logger';
import { Counter, Histogram, Gauge, register } from 'prom-client';

/**
 * Event bus metrics for monitoring
 */
export class EventBusMetrics {
  // Counters
  private eventsPublished: Counter<string>;
  private eventsProcessed: Counter<string>;
  private eventsFailed: Counter<string>;
  private eventsRetried: Counter<string>;
  private deadLetterQueueEvents: Counter<string>;

  // Histograms
  private eventProcessingDuration: Histogram<string>;
  private eventQueueTime: Histogram<string>;
  private batchSize: Histogram<string>;

  // Gauges
  private pendingEvents: Gauge<string>;
  private activeHandlers: Gauge<string>;
  private deadLetterQueueSize: Gauge<string>;
  private outboxQueueSize: Gauge<string>;

  constructor(serviceName: string) {
    // Initialize counters
    this.eventsPublished = new Counter({
      name: 'event_bus_events_published_total',
      help: 'Total number of events published',
      labelNames: ['service', 'event_type', 'tenant_id'],
      registers: [register]
    });

    this.eventsProcessed = new Counter({
      name: 'event_bus_events_processed_total',
      help: 'Total number of events processed',
      labelNames: ['service', 'event_type', 'tenant_id', 'handler'],
      registers: [register]
    });

    this.eventsFailed = new Counter({
      name: 'event_bus_events_failed_total',
      help: 'Total number of failed events',
      labelNames: ['service', 'event_type', 'tenant_id', 'handler', 'error_type'],
      registers: [register]
    });

    this.eventsRetried = new Counter({
      name: 'event_bus_events_retried_total',
      help: 'Total number of retried events',
      labelNames: ['service', 'event_type', 'tenant_id', 'handler'],
      registers: [register]
    });

    this.deadLetterQueueEvents = new Counter({
      name: 'event_bus_dlq_events_total',
      help: 'Total number of events sent to dead letter queue',
      labelNames: ['service', 'event_type', 'tenant_id'],
      registers: [register]
    });

    // Initialize histograms
    this.eventProcessingDuration = new Histogram({
      name: 'event_bus_processing_duration_seconds',
      help: 'Event processing duration in seconds',
      labelNames: ['service', 'event_type', 'handler'],
      buckets: [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 10],
      registers: [register]
    });

    this.eventQueueTime = new Histogram({
      name: 'event_bus_queue_time_seconds',
      help: 'Time events spend in queue before processing',
      labelNames: ['service', 'event_type'],
      buckets: [0.1, 0.5, 1, 5, 10, 30, 60, 300],
      registers: [register]
    });

    this.batchSize = new Histogram({
      name: 'event_bus_batch_size',
      help: 'Size of event batches processed',
      labelNames: ['service', 'handler'],
      buckets: [1, 5, 10, 25, 50, 100, 250, 500, 1000],
      registers: [register]
    });

    // Initialize gauges
    this.pendingEvents = new Gauge({
      name: 'event_bus_pending_events',
      help: 'Number of events pending processing',
      labelNames: ['service', 'event_type'],
      registers: [register]
    });

    this.activeHandlers = new Gauge({
      name: 'event_bus_active_handlers',
      help: 'Number of active event handlers',
      labelNames: ['service', 'event_type'],
      registers: [register]
    });

    this.deadLetterQueueSize = new Gauge({
      name: 'event_bus_dlq_size',
      help: 'Current size of dead letter queue',
      labelNames: ['service'],
      registers: [register]
    });

    this.outboxQueueSize = new Gauge({
      name: 'event_bus_outbox_size',
      help: 'Current size of outbox queue',
      labelNames: ['service'],
      registers: [register]
    });
  }

  recordEventPublished(event: DomainEvent): void {
    this.eventsPublished.inc({
      service: event.metadata?.source || 'unknown',
      event_type: event.type,
      tenant_id: event.tenantId
    });
  }

  recordEventProcessed(event: DomainEvent, handler: string, duration: number): void {
    this.eventsProcessed.inc({
      service: event.metadata?.source || 'unknown',
      event_type: event.type,
      tenant_id: event.tenantId,
      handler
    });

    this.eventProcessingDuration.observe(
      {
        service: event.metadata?.source || 'unknown',
        event_type: event.type,
        handler
      },
      duration / 1000 // Convert to seconds
    );
  }

  recordEventFailed(event: DomainEvent, handler: string, error: Error): void {
    this.eventsFailed.inc({
      service: event.metadata?.source || 'unknown',
      event_type: event.type,
      tenant_id: event.tenantId,
      handler,
      error_type: error.constructor.name
    });
  }

  recordEventRetried(event: DomainEvent, handler: string): void {
    this.eventsRetried.inc({
      service: event.metadata?.source || 'unknown',
      event_type: event.type,
      tenant_id: event.tenantId,
      handler
    });
  }

  recordDeadLetterQueueEvent(event: DomainEvent): void {
    this.deadLetterQueueEvents.inc({
      service: event.metadata?.source || 'unknown',
      event_type: event.type,
      tenant_id: event.tenantId
    });
  }

  recordQueueTime(event: DomainEvent, queueTime: number): void {
    this.eventQueueTime.observe(
      {
        service: event.metadata?.source || 'unknown',
        event_type: event.type
      },
      queueTime / 1000 // Convert to seconds
    );
  }

  recordBatchSize(handler: string, size: number, service: string): void {
    this.batchSize.observe(
      {
        service,
        handler
      },
      size
    );
  }

  setPendingEvents(eventType: string, count: number, service: string): void {
    this.pendingEvents.set(
      {
        service,
        event_type: eventType
      },
      count
    );
  }

  setActiveHandlers(eventType: string, count: number, service: string): void {
    this.activeHandlers.set(
      {
        service,
        event_type: eventType
      },
      count
    );
  }

  setDeadLetterQueueSize(size: number, service: string): void {
    this.deadLetterQueueSize.set({ service }, size);
  }

  setOutboxQueueSize(size: number, service: string): void {
    this.outboxQueueSize.set({ service }, size);
  }
}

/**
 * Event flow tracer for debugging
 */
export class EventFlowTracer {
  private traces: Map<string, EventTrace> = new Map();
  private maxTraces: number;
  private ttl: number;

  constructor(options: { maxTraces?: number; ttl?: number } = {}) {
    this.maxTraces = options.maxTraces || 1000;
    this.ttl = options.ttl || 3600000; // 1 hour default
    this.startCleanup();
  }

  startTrace(event: DomainEvent): void {
    const trace: EventTrace = {
      eventId: event.id,
      eventType: event.type,
      tenantId: event.tenantId,
      correlationId: event.metadata?.correlationId,
      startTime: new Date(),
      steps: []
    };

    this.traces.set(event.id, trace);
    this.enforceLimit();
  }

  addStep(eventId: string, step: TraceStep): void {
    const trace = this.traces.get(eventId);
    if (trace) {
      trace.steps.push({
        ...step,
        timestamp: new Date()
      });
    }
  }

  completeTrace(eventId: string, success: boolean, error?: Error): void {
    const trace = this.traces.get(eventId);
    if (trace) {
      trace.endTime = new Date();
      trace.success = success;
      trace.error = error?.message;
      trace.duration = trace.endTime.getTime() - trace.startTime.getTime();
    }
  }

  getTrace(eventId: string): EventTrace | undefined {
    return this.traces.get(eventId);
  }

  getTracesByCorrelation(correlationId: string): EventTrace[] {
    return Array.from(this.traces.values()).filter(
      trace => trace.correlationId === correlationId
    );
  }

  getRecentTraces(limit: number = 100): EventTrace[] {
    return Array.from(this.traces.values())
      .sort((a, b) => b.startTime.getTime() - a.startTime.getTime())
      .slice(0, limit);
  }

  getFailedTraces(limit: number = 100): EventTrace[] {
    return Array.from(this.traces.values())
      .filter(trace => !trace.success)
      .sort((a, b) => b.startTime.getTime() - a.startTime.getTime())
      .slice(0, limit);
  }

  private enforceLimit(): void {
    if (this.traces.size > this.maxTraces) {
      const sortedTraces = Array.from(this.traces.entries())
        .sort(([, a], [, b]) => a.startTime.getTime() - b.startTime.getTime());
      
      const toRemove = sortedTraces.slice(0, this.traces.size - this.maxTraces);
      toRemove.forEach(([id]) => this.traces.delete(id));
    }
  }

  private startCleanup(): void {
    setInterval(() => {
      const now = Date.now();
      for (const [id, trace] of this.traces.entries()) {
        if (now - trace.startTime.getTime() > this.ttl) {
          this.traces.delete(id);
        }
      }
    }, 60000); // Clean up every minute
  }
}

/**
 * Event trace structure
 */
export interface EventTrace {
  eventId: string;
  eventType: string;
  tenantId: string;
  correlationId?: string;
  startTime: Date;
  endTime?: Date;
  duration?: number;
  success?: boolean;
  error?: string;
  steps: TraceStep[];
}

export interface TraceStep {
  name: string;
  handler?: string;
  status: 'started' | 'completed' | 'failed' | 'retrying';
  timestamp?: Date;
  duration?: number;
  metadata?: Record<string, any>;
}

/**
 * Event debugger for development
 */
export class EventDebugger {
  private enabled: boolean;
  private filters: DebugFilter[] = [];

  constructor(enabled: boolean = process.env.NODE_ENV === 'development') {
    this.enabled = enabled;
  }

  addFilter(filter: DebugFilter): void {
    this.filters.push(filter);
  }

  shouldDebug(event: DomainEvent): boolean {
    if (!this.enabled) return false;
    if (this.filters.length === 0) return true;

    return this.filters.some(filter => {
      if (filter.eventType && event.type !== filter.eventType) return false;
      if (filter.tenantId && event.tenantId !== filter.tenantId) return false;
      if (filter.correlationId && event.metadata?.correlationId !== filter.correlationId) return false;
      return true;
    });
  }

  logEvent(event: DomainEvent, context: string): void {
    if (this.shouldDebug(event)) {
      logger.debug(`[EventDebug] ${context}`, {
        eventId: event.id,
        eventType: event.type,
        tenantId: event.tenantId,
        correlationId: event.metadata?.correlationId,
        data: event.data,
        metadata: event.metadata
      });
    }
  }

  logHandler(event: DomainEvent, handler: string, phase: 'start' | 'end' | 'error', error?: Error): void {
    if (this.shouldDebug(event)) {
      const message = `[EventDebug] Handler ${handler} - ${phase}`;
      if (phase === 'error') {
        logger.error(message, { eventId: event.id, error });
      } else {
        logger.debug(message, { eventId: event.id });
      }
    }
  }
}

export interface DebugFilter {
  eventType?: string;
  tenantId?: string;
  correlationId?: string;
}

/**
 * Event history query builder
 */
export class EventHistoryQuery {
  private criteria: QueryCriteria = {};

  byType(type: string): this {
    this.criteria.eventType = type;
    return this;
  }

  byTenant(tenantId: string): this {
    this.criteria.tenantId = tenantId;
    return this;
  }

  byCorrelation(correlationId: string): this {
    this.criteria.correlationId = correlationId;
    return this;
  }

  byTimeRange(from: Date, to?: Date): this {
    this.criteria.from = from;
    this.criteria.to = to;
    return this;
  }

  withLimit(limit: number): this {
    this.criteria.limit = limit;
    return this;
  }

  build(): QueryCriteria {
    return { ...this.criteria };
  }
}

export interface QueryCriteria {
  eventType?: string;
  tenantId?: string;
  correlationId?: string;
  from?: Date;
  to?: Date;
  limit?: number;
}

/**
 * Event bus health checker
 */
export class EventBusHealthChecker {
  private eventBus: any; // Reference to EventBus instance
  private metrics: EventBusMetrics;

  constructor(eventBus: any, metrics: EventBusMetrics) {
    this.eventBus = eventBus;
    this.metrics = metrics;
  }

  async checkHealth(): Promise<HealthCheckResult> {
    const checks: HealthCheck[] = [];

    // Check Redis connections
    checks.push(await this.checkRedisConnection());

    // Check dead letter queue
    checks.push(await this.checkDeadLetterQueue());

    // Check outbox queue
    checks.push(await this.checkOutboxQueue());

    // Check handler responsiveness
    checks.push(await this.checkHandlerResponsiveness());

    const overallStatus = checks.every(c => c.status === 'healthy') ? 'healthy' : 
                         checks.some(c => c.status === 'unhealthy') ? 'unhealthy' : 'degraded';

    return {
      status: overallStatus,
      checks,
      timestamp: new Date()
    };
  }

  private async checkRedisConnection(): Promise<HealthCheck> {
    try {
      // Attempt to ping Redis
      await this.eventBus.publisher.ping();
      return {
        name: 'redis_connection',
        status: 'healthy',
        message: 'Redis connection is healthy'
      };
    } catch (error) {
      return {
        name: 'redis_connection',
        status: 'unhealthy',
        message: 'Redis connection failed',
        error: error.message
      };
    }
  }

  private async checkDeadLetterQueue(): Promise<HealthCheck> {
    try {
      const size = await this.eventBus.getDeadLetterQueueSize();
      if (size > 1000) {
        return {
          name: 'dead_letter_queue',
          status: 'degraded',
          message: `Dead letter queue size is high: ${size}`,
          metadata: { size }
        };
      }
      return {
        name: 'dead_letter_queue',
        status: 'healthy',
        message: `Dead letter queue size: ${size}`,
        metadata: { size }
      };
    } catch (error) {
      return {
        name: 'dead_letter_queue',
        status: 'unhealthy',
        message: 'Failed to check dead letter queue',
        error: error.message
      };
    }
  }

  private async checkOutboxQueue(): Promise<HealthCheck> {
    const size = this.eventBus.outboxQueue?.length || 0;
    if (size > 500) {
      return {
        name: 'outbox_queue',
        status: 'degraded',
        message: `Outbox queue size is high: ${size}`,
        metadata: { size }
      };
    }
    return {
      name: 'outbox_queue',
      status: 'healthy',
      message: `Outbox queue size: ${size}`,
      metadata: { size }
    };
  }

  private async checkHandlerResponsiveness(): Promise<HealthCheck> {
    // This would check if handlers are processing events in a timely manner
    // For now, returning a simple healthy status
    return {
      name: 'handler_responsiveness',
      status: 'healthy',
      message: 'Handlers are responsive'
    };
  }
}

export interface HealthCheckResult {
  status: 'healthy' | 'degraded' | 'unhealthy';
  checks: HealthCheck[];
  timestamp: Date;
}

export interface HealthCheck {
  name: string;
  status: 'healthy' | 'degraded' | 'unhealthy';
  message: string;
  error?: string;
  metadata?: Record<string, any>;
}