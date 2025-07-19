import { DomainEvent, EventHandler } from './eventBus';
import { logger } from '@/logger';
import { circuitBreaker } from '@/utils/circuit-breaker';
import { RetryPolicy } from '@/utils/retry';

/**
 * Base event handler with common functionality
 */
export abstract class BaseEventHandler<T = any> implements EventHandler<T> {
  protected readonly name: string;
  protected readonly retryPolicy: RetryPolicy;
  protected readonly breaker: any;

  constructor(name: string, options?: {
    maxRetries?: number;
    retryDelay?: number;
    breakerThreshold?: number;
  }) {
    this.name = name;
    this.retryPolicy = new RetryPolicy({
      maxAttempts: options?.maxRetries || 3,
      delay: options?.retryDelay || 1000,
      backoff: 'exponential'
    });
    
    this.breaker = circuitBreaker(this.name, {
      threshold: options?.breakerThreshold || 5,
      timeout: 30000,
      resetTimeout: 60000
    });
  }

  async handle(event: DomainEvent<T>): Promise<void> {
    const startTime = Date.now();
    
    try {
      logger.info(`${this.name} processing event`, {
        eventId: event.id,
        eventType: event.type,
        tenantId: event.tenantId
      });

      // Validate event
      await this.validate(event);

      // Process with circuit breaker
      await this.breaker.execute(async () => {
        await this.process(event);
      });

      // Post-process hooks
      await this.afterProcess(event);

      const duration = Date.now() - startTime;
      logger.info(`${this.name} completed event processing`, {
        eventId: event.id,
        duration
      });
    } catch (error) {
      const duration = Date.now() - startTime;
      logger.error(`${this.name} failed to process event`, {
        eventId: event.id,
        eventType: event.type,
        error,
        duration
      });

      // Handle error
      await this.handleError(event, error);
      throw error;
    }
  }

  /**
   * Validate event before processing
   */
  protected async validate(event: DomainEvent<T>): Promise<void> {
    if (!event.tenantId) {
      throw new Error('Event missing tenantId');
    }
  }

  /**
   * Main processing logic - must be implemented by subclasses
   */
  protected abstract process(event: DomainEvent<T>): Promise<void>;

  /**
   * Hook for post-processing actions
   */
  protected async afterProcess(event: DomainEvent<T>): Promise<void> {
    // Override in subclasses if needed
  }

  /**
   * Error handling logic
   */
  protected async handleError(event: DomainEvent<T>, error: any): Promise<void> {
    // Override in subclasses for custom error handling
  }
}

/**
 * Composite handler that runs multiple handlers
 */
export class CompositeEventHandler<T = any> extends BaseEventHandler<T> {
  private handlers: EventHandler<T>[];

  constructor(name: string, handlers: EventHandler<T>[]) {
    super(name);
    this.handlers = handlers;
  }

  protected async process(event: DomainEvent<T>): Promise<void> {
    await Promise.all(
      this.handlers.map(handler => handler(event))
    );
  }
}

/**
 * Conditional handler that only processes events matching criteria
 */
export class ConditionalEventHandler<T = any> extends BaseEventHandler<T> {
  private condition: (event: DomainEvent<T>) => boolean | Promise<boolean>;
  private handler: EventHandler<T>;

  constructor(
    name: string,
    condition: (event: DomainEvent<T>) => boolean | Promise<boolean>,
    handler: EventHandler<T>
  ) {
    super(name);
    this.condition = condition;
    this.handler = handler;
  }

  protected async process(event: DomainEvent<T>): Promise<void> {
    const shouldProcess = await this.condition(event);
    if (shouldProcess) {
      await this.handler(event);
    } else {
      logger.debug(`${this.name} skipped event due to condition`, {
        eventId: event.id
      });
    }
  }
}

/**
 * Batch handler that accumulates events and processes in batches
 */
export class BatchEventHandler<T = any> extends BaseEventHandler<T> {
  private batch: DomainEvent<T>[] = [];
  private batchSize: number;
  private flushInterval: number;
  private flushTimer?: NodeJS.Timeout;
  private processBatch: (events: DomainEvent<T>[]) => Promise<void>;

  constructor(
    name: string,
    processBatch: (events: DomainEvent<T>[]) => Promise<void>,
    options: {
      batchSize?: number;
      flushInterval?: number;
    } = {}
  ) {
    super(name);
    this.processBatch = processBatch;
    this.batchSize = options.batchSize || 100;
    this.flushInterval = options.flushInterval || 5000;
    this.startFlushTimer();
  }

  protected async process(event: DomainEvent<T>): Promise<void> {
    this.batch.push(event);
    
    if (this.batch.length >= this.batchSize) {
      await this.flush();
    }
  }

  private async flush(): Promise<void> {
    if (this.batch.length === 0) return;

    const events = [...this.batch];
    this.batch = [];

    try {
      await this.processBatch(events);
      logger.info(`${this.name} processed batch`, {
        batchSize: events.length
      });
    } catch (error) {
      logger.error(`${this.name} failed to process batch`, {
        batchSize: events.length,
        error
      });
      // Re-add failed events to batch
      this.batch.unshift(...events);
      throw error;
    }
  }

  private startFlushTimer(): void {
    this.flushTimer = setInterval(() => {
      this.flush().catch(error => {
        logger.error(`${this.name} flush timer error`, { error });
      });
    }, this.flushInterval);
  }

  async destroy(): Promise<void> {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
    }
    await this.flush();
  }
}

/**
 * Transform handler that transforms events before passing to another handler
 */
export class TransformEventHandler<TIn = any, TOut = any> extends BaseEventHandler<TIn> {
  private transformer: (event: DomainEvent<TIn>) => DomainEvent<TOut> | Promise<DomainEvent<TOut>>;
  private handler: EventHandler<TOut>;

  constructor(
    name: string,
    transformer: (event: DomainEvent<TIn>) => DomainEvent<TOut> | Promise<DomainEvent<TOut>>,
    handler: EventHandler<TOut>
  ) {
    super(name);
    this.transformer = transformer;
    this.handler = handler;
  }

  protected async process(event: DomainEvent<TIn>): Promise<void> {
    const transformedEvent = await this.transformer(event);
    await this.handler(transformedEvent);
  }
}

/**
 * Dedupe handler that prevents duplicate event processing
 */
export class DedupeEventHandler<T = any> extends BaseEventHandler<T> {
  private cache: Map<string, Date> = new Map();
  private handler: EventHandler<T>;
  private ttl: number;
  private keyGenerator: (event: DomainEvent<T>) => string;

  constructor(
    name: string,
    handler: EventHandler<T>,
    options: {
      ttl?: number;
      keyGenerator?: (event: DomainEvent<T>) => string;
    } = {}
  ) {
    super(name);
    this.handler = handler;
    this.ttl = options.ttl || 3600000; // 1 hour default
    this.keyGenerator = options.keyGenerator || (event => event.id);
    this.startCleanup();
  }

  protected async process(event: DomainEvent<T>): Promise<void> {
    const key = this.keyGenerator(event);
    
    if (this.cache.has(key)) {
      logger.debug(`${this.name} skipped duplicate event`, {
        eventId: event.id,
        key
      });
      return;
    }

    this.cache.set(key, new Date());
    await this.handler(event);
  }

  private startCleanup(): void {
    setInterval(() => {
      const now = Date.now();
      for (const [key, timestamp] of this.cache.entries()) {
        if (now - timestamp.getTime() > this.ttl) {
          this.cache.delete(key);
        }
      }
    }, 60000); // Clean up every minute
  }
}

/**
 * Aggregator handler that aggregates events over a time window
 */
export class AggregatorEventHandler<T = any> extends BaseEventHandler<T> {
  private aggregates: Map<string, { events: DomainEvent<T>[]; firstSeen: Date }> = new Map();
  private windowSize: number;
  private keyGenerator: (event: DomainEvent<T>) => string;
  private processAggregate: (key: string, events: DomainEvent<T>[]) => Promise<void>;
  private cleanupTimer?: NodeJS.Timeout;

  constructor(
    name: string,
    keyGenerator: (event: DomainEvent<T>) => string,
    processAggregate: (key: string, events: DomainEvent<T>[]) => Promise<void>,
    options: {
      windowSize?: number;
    } = {}
  ) {
    super(name);
    this.keyGenerator = keyGenerator;
    this.processAggregate = processAggregate;
    this.windowSize = options.windowSize || 60000; // 1 minute default
    this.startCleanup();
  }

  protected async process(event: DomainEvent<T>): Promise<void> {
    const key = this.keyGenerator(event);
    
    if (!this.aggregates.has(key)) {
      this.aggregates.set(key, {
        events: [],
        firstSeen: new Date()
      });
    }
    
    const aggregate = this.aggregates.get(key)!;
    aggregate.events.push(event);
  }

  private async processExpiredAggregates(): Promise<void> {
    const now = Date.now();
    
    for (const [key, aggregate] of this.aggregates.entries()) {
      if (now - aggregate.firstSeen.getTime() >= this.windowSize) {
        this.aggregates.delete(key);
        
        try {
          await this.processAggregate(key, aggregate.events);
          logger.info(`${this.name} processed aggregate`, {
            key,
            eventCount: aggregate.events.length
          });
        } catch (error) {
          logger.error(`${this.name} failed to process aggregate`, {
            key,
            eventCount: aggregate.events.length,
            error
          });
        }
      }
    }
  }

  private startCleanup(): void {
    this.cleanupTimer = setInterval(() => {
      this.processExpiredAggregates().catch(error => {
        logger.error(`${this.name} cleanup error`, { error });
      });
    }, 10000); // Check every 10 seconds
  }

  async destroy(): Promise<void> {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
    }
    // Process remaining aggregates
    for (const [key, aggregate] of this.aggregates.entries()) {
      await this.processAggregate(key, aggregate.events);
    }
  }
}

/**
 * Handler registry for managing event handlers
 */
export class HandlerRegistry {
  private handlers: Map<string, EventHandler[]> = new Map();

  register(eventType: string, handler: EventHandler): void {
    if (!this.handlers.has(eventType)) {
      this.handlers.set(eventType, []);
    }
    this.handlers.get(eventType)!.push(handler);
  }

  unregister(eventType: string, handler: EventHandler): void {
    const handlers = this.handlers.get(eventType);
    if (handlers) {
      const index = handlers.indexOf(handler);
      if (index > -1) {
        handlers.splice(index, 1);
      }
    }
  }

  getHandlers(eventType: string): EventHandler[] {
    return this.handlers.get(eventType) || [];
  }

  getAllHandlers(): Map<string, EventHandler[]> {
    return new Map(this.handlers);
  }

  clear(): void {
    this.handlers.clear();
  }
}

/**
 * Event correlation helper
 */
export class EventCorrelator {
  private correlations: Map<string, Set<string>> = new Map();

  addCorrelation(correlationId: string, eventId: string): void {
    if (!this.correlations.has(correlationId)) {
      this.correlations.set(correlationId, new Set());
    }
    this.correlations.get(correlationId)!.add(eventId);
  }

  getCorrelatedEvents(correlationId: string): string[] {
    return Array.from(this.correlations.get(correlationId) || []);
  }

  removeCorrelation(correlationId: string): void {
    this.correlations.delete(correlationId);
  }
}