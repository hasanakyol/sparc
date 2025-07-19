import Redis from 'ioredis';
import { EventEmitter } from 'events';
import { v4 as uuidv4 } from 'uuid';
import { db } from '@/database/prisma';
import { logger } from '@/logger';

/**
 * Domain event interface with standardized structure
 */
export interface DomainEvent<T = any> {
  id: string;
  type: string;
  version: number;
  tenantId: string;
  timestamp: Date;
  data: T;
  metadata?: {
    correlationId?: string;
    causationId?: string;
    userId?: string;
    source?: string;
    [key: string]: any;
  };
}

/**
 * Event handler interface
 */
export interface EventHandler<T = any> {
  (event: DomainEvent<T>): Promise<void>;
}

/**
 * Event bus configuration
 */
export interface EventBusConfig {
  redisUrl: string;
  serviceName: string;
  maxRetries?: number;
  retryDelay?: number;
  enablePersistence?: boolean;
  enableOrdering?: boolean;
  batchSize?: number;
  flushInterval?: number;
}

/**
 * Event store for persistence
 */
export interface StoredEvent extends DomainEvent {
  processedAt?: Date;
  failureCount?: number;
  lastError?: string;
}

/**
 * Enhanced Event Bus with event sourcing support
 */
export class EventBus extends EventEmitter {
  private publisher: Redis;
  private subscriber: Redis;
  private config: EventBusConfig;
  private handlers: Map<string, EventHandler[]> = new Map();
  private deadLetterQueue: string;
  private outboxQueue: StoredEvent[] = [];
  private flushTimer?: NodeJS.Timeout;
  private processingOrder: Map<string, number> = new Map();

  constructor(config: EventBusConfig) {
    super();
    this.config = {
      maxRetries: 3,
      retryDelay: 1000,
      enablePersistence: true,
      enableOrdering: true,
      batchSize: 100,
      flushInterval: 1000,
      ...config
    };
    
    this.publisher = new Redis(config.redisUrl);
    this.subscriber = new Redis(config.redisUrl);
    this.deadLetterQueue = `dlq:${config.serviceName}`;
    
    // Start outbox processor
    if (this.config.enablePersistence) {
      this.startOutboxProcessor();
    }
  }

  /**
   * Publish a domain event
   */
  async publish<T = any>(
    type: string,
    data: T,
    metadata?: DomainEvent['metadata']
  ): Promise<void> {
    const event: DomainEvent<T> = {
      id: uuidv4(),
      type,
      version: 1,
      tenantId: metadata?.tenantId || 'system',
      timestamp: new Date(),
      data,
      metadata: {
        source: this.config.serviceName,
        ...metadata
      }
    };

    // Add to outbox for transactional guarantee
    if (this.config.enablePersistence) {
      await this.addToOutbox(event);
    }

    // Publish immediately if not using outbox pattern
    if (!this.config.enablePersistence) {
      await this.publishEvent(event);
    }

    // Emit locally for same-service handlers
    this.emit(type, event);
  }

  /**
   * Publish multiple events as a batch
   */
  async publishBatch(events: Array<{ type: string; data: any; metadata?: DomainEvent['metadata'] }>): Promise<void> {
    const domainEvents = events.map(e => ({
      id: uuidv4(),
      type: e.type,
      version: 1,
      tenantId: e.metadata?.tenantId || 'system',
      timestamp: new Date(),
      data: e.data,
      metadata: {
        source: this.config.serviceName,
        ...e.metadata
      }
    }));

    if (this.config.enablePersistence) {
      await this.addBatchToOutbox(domainEvents);
    } else {
      await Promise.all(domainEvents.map(e => this.publishEvent(e)));
    }

    // Emit locally
    domainEvents.forEach(e => this.emit(e.type, e));
  }

  /**
   * Subscribe to an event type with type safety
   */
  async subscribe<T = any>(
    type: string,
    handler: EventHandler<T>,
    options?: { 
      filter?: (event: DomainEvent<T>) => boolean;
      priority?: number;
    }
  ): Promise<void> {
    // Create wrapped handler with filtering
    const wrappedHandler: EventHandler = async (event) => {
      if (options?.filter && !options.filter(event)) {
        return;
      }
      await handler(event);
    };

    // Add handler to local map
    if (!this.handlers.has(type)) {
      this.handlers.set(type, []);
    }
    
    const handlers = this.handlers.get(type)!;
    if (options?.priority !== undefined) {
      handlers.splice(options.priority, 0, wrappedHandler);
    } else {
      handlers.push(wrappedHandler);
    }

    // Subscribe to Redis channel
    const channel = `events:${type}`;
    await this.subscriber.subscribe(channel);

    // Set up message handler if not already done
    if (this.subscriber.listenerCount('message') === 0) {
      this.subscriber.on('message', async (channel, message) => {
        await this.handleMessage(channel, message);
      });
    }
  }

  /**
   * Subscribe to multiple event types with pattern
   */
  async subscribePattern(pattern: string, handler: EventHandler): Promise<void> {
    await this.subscriber.psubscribe(`events:${pattern}`);
    
    const patternKey = `pattern:${pattern}`;
    if (!this.handlers.has(patternKey)) {
      this.handlers.set(patternKey, []);
    }
    this.handlers.get(patternKey)!.push(handler);
  }

  /**
   * Replay events from a specific point in time
   */
  async replay(
    options: {
      type?: string;
      from: Date;
      to?: Date;
      tenantId?: string;
      handler?: EventHandler;
    }
  ): Promise<DomainEvent[]> {
    const events = await this.getStoredEvents(options);
    
    if (options.handler) {
      for (const event of events) {
        try {
          await options.handler(event);
        } catch (error) {
          logger.error('Error replaying event', { event, error });
        }
      }
    }
    
    return events;
  }

  /**
   * Get event history with filtering
   */
  async getEventHistory(
    filters: {
      type?: string;
      tenantId?: string;
      from?: Date;
      to?: Date;
      limit?: number;
    }
  ): Promise<DomainEvent[]> {
    return this.getStoredEvents(filters);
  }

  /**
   * Process dead letter queue
   */
  async processDeadLetterQueue(
    handler: (event: DomainEvent, error: string) => Promise<void>
  ): Promise<void> {
    while (true) {
      const item = await this.publisher.rpop(this.deadLetterQueue);
      if (!item) break;

      try {
        const entry = JSON.parse(item);
        await handler(entry.event, entry.error);
      } catch (error) {
        logger.error('Failed to process DLQ entry:', error);
      }
    }
  }

  /**
   * Get dead letter queue size
   */
  async getDeadLetterQueueSize(): Promise<number> {
    return this.publisher.llen(this.deadLetterQueue);
  }

  /**
   * Handle correlation and causation
   */
  createCorrelatedEvent<T = any>(
    parentEvent: DomainEvent,
    type: string,
    data: T,
    metadata?: Partial<DomainEvent['metadata']>
  ): DomainEvent<T> {
    return {
      id: uuidv4(),
      type,
      version: 1,
      tenantId: parentEvent.tenantId,
      timestamp: new Date(),
      data,
      metadata: {
        correlationId: parentEvent.metadata?.correlationId || parentEvent.id,
        causationId: parentEvent.id,
        source: this.config.serviceName,
        ...metadata
      }
    };
  }

  /**
   * Aggregate events by correlation ID
   */
  async getCorrelatedEvents(correlationId: string): Promise<DomainEvent[]> {
    const events = await this.getStoredEvents({
      limit: 1000
    });
    
    return events.filter(e => 
      e.metadata?.correlationId === correlationId ||
      e.id === correlationId
    ).sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
  }

  /**
   * Close connections
   */
  async close(): Promise<void> {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
    }
    await this.flushOutbox();
    await this.publisher.quit();
    await this.subscriber.quit();
  }

  // Private methods

  private async publishEvent(event: DomainEvent): Promise<void> {
    const channel = `events:${event.type}`;
    const message = JSON.stringify(event);

    // Ensure ordering if enabled
    if (this.config.enableOrdering) {
      const orderKey = `${event.tenantId}:${event.type}`;
      const order = (this.processingOrder.get(orderKey) || 0) + 1;
      this.processingOrder.set(orderKey, order);
      event.metadata = { ...event.metadata, order };
    }

    // Publish to Redis
    await this.publisher.publish(channel, message);

    // Store event for durability
    if (this.config.enablePersistence) {
      await this.storeEvent(event);
    }
  }

  private async handleMessage(channel: string, message: string): Promise<void> {
    try {
      const event: DomainEvent = JSON.parse(message);
      
      // Skip events from self (already handled locally)
      if (event.metadata?.source === this.config.serviceName) {
        return;
      }

      const eventType = channel.replace('events:', '');
      const handlers = this.handlers.get(eventType) || [];

      // Also check pattern handlers
      for (const [key, patternHandlers] of this.handlers.entries()) {
        if (key.startsWith('pattern:')) {
          const pattern = key.replace('pattern:', '');
          const regex = new RegExp(pattern.replace('*', '.*'));
          if (regex.test(eventType)) {
            handlers.push(...patternHandlers);
          }
        }
      }

      // Execute handlers with ordering guarantee
      if (this.config.enableOrdering && event.metadata?.order) {
        await this.executeOrderedHandlers(event, handlers);
      } else {
        await this.executeHandlers(event, handlers);
      }
    } catch (error) {
      logger.error('Failed to handle message:', error);
    }
  }

  private async executeHandlers(event: DomainEvent, handlers: EventHandler[]): Promise<void> {
    for (const handler of handlers) {
      try {
        await this.executeWithRetry(handler, event);
      } catch (error) {
        logger.error(`Handler failed for event ${event.type}:`, error);
        await this.sendToDeadLetterQueue(event, error);
      }
    }
  }

  private async executeOrderedHandlers(event: DomainEvent, handlers: EventHandler[]): Promise<void> {
    const orderKey = `${event.tenantId}:${event.type}`;
    const expectedOrder = (this.processingOrder.get(orderKey) || 0) + 1;
    const eventOrder = event.metadata?.order || 0;

    // Wait if event came out of order
    if (eventOrder > expectedOrder) {
      await new Promise(resolve => setTimeout(resolve, 100));
      return this.executeOrderedHandlers(event, handlers);
    }

    await this.executeHandlers(event, handlers);
    this.processingOrder.set(orderKey, eventOrder);
  }

  private async executeWithRetry(handler: EventHandler, event: DomainEvent): Promise<void> {
    const maxRetries = this.config.maxRetries || 3;
    const retryDelay = this.config.retryDelay || 1000;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        await handler(event);
        return;
      } catch (error) {
        if (attempt === maxRetries) {
          throw error;
        }
        await new Promise(resolve => setTimeout(resolve, retryDelay * attempt));
      }
    }
  }

  private async addToOutbox(event: DomainEvent): Promise<void> {
    this.outboxQueue.push(event as StoredEvent);
    
    if (this.outboxQueue.length >= (this.config.batchSize || 100)) {
      await this.flushOutbox();
    }
  }

  private async addBatchToOutbox(events: DomainEvent[]): Promise<void> {
    this.outboxQueue.push(...events.map(e => e as StoredEvent));
    
    if (this.outboxQueue.length >= (this.config.batchSize || 100)) {
      await this.flushOutbox();
    }
  }

  private async flushOutbox(): Promise<void> {
    if (this.outboxQueue.length === 0) return;

    const events = [...this.outboxQueue];
    this.outboxQueue = [];

    try {
      // Store events in database
      await this.storeBatchEvents(events);

      // Publish events
      await Promise.all(events.map(e => this.publishEvent(e)));
    } catch (error) {
      logger.error('Failed to flush outbox:', error);
      // Re-add to queue
      this.outboxQueue.unshift(...events);
    }
  }

  private startOutboxProcessor(): void {
    this.flushTimer = setInterval(async () => {
      await this.flushOutbox();
      await this.processFailedEvents();
    }, this.config.flushInterval || 1000);
  }

  private async processFailedEvents(): Promise<void> {
    // Implement retry logic for failed events
    const failedEvents = await this.getFailedEvents();
    
    for (const event of failedEvents) {
      try {
        await this.publishEvent(event);
        await this.markEventProcessed(event.id);
      } catch (error) {
        await this.incrementFailureCount(event.id);
      }
    }
  }

  private async storeEvent(event: DomainEvent): Promise<void> {
    const key = `event:${event.id}`;
    const ttl = 86400 * 7; // 7 days
    await this.publisher.setex(key, ttl, JSON.stringify(event));
  }

  private async storeBatchEvents(events: StoredEvent[]): Promise<void> {
    // In a real implementation, this would store to a database
    // For now, using Redis
    const pipeline = this.publisher.pipeline();
    const ttl = 86400 * 7; // 7 days
    
    for (const event of events) {
      const key = `event:${event.id}`;
      pipeline.setex(key, ttl, JSON.stringify(event));
    }
    
    await pipeline.exec();
  }

  private async getStoredEvents(filters: {
    type?: string;
    tenantId?: string;
    from?: Date;
    to?: Date;
    limit?: number;
  }): Promise<DomainEvent[]> {
    // In a real implementation, this would query from a database
    // For now, using Redis pattern matching
    const pattern = 'event:*';
    const keys = await this.publisher.keys(pattern);
    const events: DomainEvent[] = [];
    
    for (const key of keys) {
      const data = await this.publisher.get(key);
      if (data) {
        const event = JSON.parse(data) as DomainEvent;
        
        // Apply filters
        if (filters.type && event.type !== filters.type) continue;
        if (filters.tenantId && event.tenantId !== filters.tenantId) continue;
        if (filters.from && event.timestamp < filters.from) continue;
        if (filters.to && event.timestamp > filters.to) continue;
        
        events.push(event);
      }
    }
    
    // Sort by timestamp
    events.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
    
    // Apply limit
    if (filters.limit) {
      return events.slice(0, filters.limit);
    }
    
    return events;
  }

  private async getFailedEvents(): Promise<StoredEvent[]> {
    // In a real implementation, query failed events from database
    return [];
  }

  private async markEventProcessed(eventId: string): Promise<void> {
    // In a real implementation, update event status in database
  }

  private async incrementFailureCount(eventId: string): Promise<void> {
    // In a real implementation, increment failure count in database
  }

  private async sendToDeadLetterQueue(event: DomainEvent, error: any): Promise<void> {
    const dlqEntry = {
      event,
      error: error.message || String(error),
      failedAt: new Date(),
      service: this.config.serviceName
    };

    await this.publisher.lpush(this.deadLetterQueue, JSON.stringify(dlqEntry));
  }
}

/**
 * Typed event bus for better type safety
 */
export class TypedEventBus<TEvents extends Record<string, any>> {
  private eventBus: EventBus;

  constructor(config: EventBusConfig) {
    this.eventBus = new EventBus(config);
  }

  async publish<K extends keyof TEvents>(
    type: K,
    data: TEvents[K],
    metadata?: DomainEvent['metadata']
  ): Promise<void> {
    await this.eventBus.publish(type as string, data, metadata);
  }

  async publishBatch(
    events: Array<{
      type: keyof TEvents;
      data: TEvents[keyof TEvents];
      metadata?: DomainEvent['metadata'];
    }>
  ): Promise<void> {
    await this.eventBus.publishBatch(events.map(e => ({
      type: e.type as string,
      data: e.data,
      metadata: e.metadata
    })));
  }

  async subscribe<K extends keyof TEvents>(
    type: K,
    handler: (event: DomainEvent<TEvents[K]>) => Promise<void>,
    options?: { 
      filter?: (event: DomainEvent<TEvents[K]>) => boolean;
      priority?: number;
    }
  ): Promise<void> {
    await this.eventBus.subscribe(type as string, handler, options);
  }

  async replay<K extends keyof TEvents>(
    options: {
      type?: K;
      from: Date;
      to?: Date;
      tenantId?: string;
      handler?: (event: DomainEvent<TEvents[K]>) => Promise<void>;
    }
  ): Promise<DomainEvent<TEvents[K]>[]> {
    return this.eventBus.replay({
      ...options,
      type: options.type as string
    });
  }

  createCorrelatedEvent<K extends keyof TEvents>(
    parentEvent: DomainEvent,
    type: K,
    data: TEvents[K],
    metadata?: Partial<DomainEvent['metadata']>
  ): DomainEvent<TEvents[K]> {
    return this.eventBus.createCorrelatedEvent(parentEvent, type as string, data, metadata);
  }

  async getCorrelatedEvents(correlationId: string): Promise<DomainEvent[]> {
    return this.eventBus.getCorrelatedEvents(correlationId);
  }

  async close(): Promise<void> {
    await this.eventBus.close();
  }
}