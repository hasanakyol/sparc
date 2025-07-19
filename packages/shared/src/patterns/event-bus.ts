import Redis from 'ioredis';
import { EventEmitter } from 'events';

export interface Event {
  id: string;
  type: string;
  source: string;
  timestamp: Date;
  data: any;
  metadata?: Record<string, any>;
}

export interface EventHandler {
  (event: Event): Promise<void>;
}

export interface EventBusConfig {
  redisUrl: string;
  serviceName: string;
  maxRetries?: number;
  retryDelay?: number;
}

/**
 * Distributed event bus for microservices communication
 */
export class EventBus extends EventEmitter {
  private publisher: Redis;
  private subscriber: Redis;
  private config: EventBusConfig;
  private handlers: Map<string, EventHandler[]> = new Map();
  private deadLetterQueue: string;

  constructor(config: EventBusConfig) {
    super();
    this.config = config;
    this.publisher = new Redis(config.redisUrl);
    this.subscriber = new Redis(config.redisUrl);
    this.deadLetterQueue = `dlq:${config.serviceName}`;
  }

  /**
   * Publish an event
   */
  async publish(type: string, data: any, metadata?: Record<string, any>): Promise<void> {
    const event: Event = {
      id: crypto.randomUUID(),
      type,
      source: this.config.serviceName,
      timestamp: new Date(),
      data,
      metadata
    };

    const channel = `events:${type}`;
    const message = JSON.stringify(event);

    // Publish to Redis
    await this.publisher.publish(channel, message);

    // Store event for durability
    await this.storeEvent(event);

    // Emit locally for same-service handlers
    this.emit(type, event);
  }

  /**
   * Subscribe to an event type
   */
  async subscribe(type: string, handler: EventHandler): Promise<void> {
    // Add handler to local map
    if (!this.handlers.has(type)) {
      this.handlers.set(type, []);
    }
    this.handlers.get(type)!.push(handler);

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
   * Unsubscribe from an event type
   */
  async unsubscribe(type: string, handler?: EventHandler): Promise<void> {
    if (handler) {
      const handlers = this.handlers.get(type) || [];
      const index = handlers.indexOf(handler);
      if (index > -1) {
        handlers.splice(index, 1);
      }
    } else {
      this.handlers.delete(type);
    }

    // Unsubscribe from Redis if no handlers left
    if (!this.handlers.has(type) || this.handlers.get(type)!.length === 0) {
      const channel = `events:${type}`;
      await this.subscriber.unsubscribe(channel);
    }
  }

  /**
   * Subscribe to multiple event types with pattern
   */
  async subscribePattern(pattern: string, handler: EventHandler): Promise<void> {
    await this.subscriber.psubscribe(`events:${pattern}`);
    
    // Store pattern handlers separately
    const patternKey = `pattern:${pattern}`;
    if (!this.handlers.has(patternKey)) {
      this.handlers.set(patternKey, []);
    }
    this.handlers.get(patternKey)!.push(handler);
  }

  /**
   * Handle incoming messages
   */
  private async handleMessage(channel: string, message: string): Promise<void> {
    try {
      const event: Event = JSON.parse(message);
      
      // Skip events from self (already handled locally)
      if (event.source === this.config.serviceName) {
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

      // Execute handlers
      for (const handler of handlers) {
        try {
          await this.executeWithRetry(handler, event);
        } catch (error) {
          console.error(`Handler failed for event ${event.type}:`, error);
          await this.sendToDeadLetterQueue(event, error);
        }
      }
    } catch (error) {
      console.error('Failed to handle message:', error);
    }
  }

  /**
   * Execute handler with retry logic
   */
  private async executeWithRetry(handler: EventHandler, event: Event): Promise<void> {
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

  /**
   * Store event for durability
   */
  private async storeEvent(event: Event): Promise<void> {
    const key = `event:${event.id}`;
    await this.publisher.setex(key, 86400, JSON.stringify(event)); // 24 hour TTL
  }

  /**
   * Send failed event to dead letter queue
   */
  private async sendToDeadLetterQueue(event: Event, error: any): Promise<void> {
    const dlqEntry = {
      event,
      error: error.message,
      failedAt: new Date(),
      service: this.config.serviceName
    };

    await this.publisher.lpush(this.deadLetterQueue, JSON.stringify(dlqEntry));
  }

  /**
   * Process dead letter queue
   */
  async processDeadLetterQueue(handler: (entry: any) => Promise<void>): Promise<void> {
    while (true) {
      const item = await this.publisher.rpop(this.deadLetterQueue);
      if (!item) break;

      try {
        const entry = JSON.parse(item);
        await handler(entry);
      } catch (error) {
        console.error('Failed to process DLQ entry:', error);
      }
    }
  }

  /**
   * Get event history
   */
  async getEventHistory(type: string, limit: number = 100): Promise<Event[]> {
    const pattern = `event:*`;
    const keys = await this.publisher.keys(pattern);
    const events: Event[] = [];

    for (const key of keys.slice(0, limit)) {
      const data = await this.publisher.get(key);
      if (data) {
        const event = JSON.parse(data);
        if (event.type === type) {
          events.push(event);
        }
      }
    }

    return events.sort((a, b) => 
      new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    );
  }

  /**
   * Close connections
   */
  async close(): Promise<void> {
    await this.publisher.quit();
    await this.subscriber.quit();
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
    metadata?: Record<string, any>
  ): Promise<void> {
    await this.eventBus.publish(type as string, data, metadata);
  }

  async subscribe<K extends keyof TEvents>(
    type: K,
    handler: (event: Event & { data: TEvents[K] }) => Promise<void>
  ): Promise<void> {
    await this.eventBus.subscribe(type as string, handler);
  }

  async close(): Promise<void> {
    await this.eventBus.close();
  }
}

// Example usage with typed events
interface AppEvents {
  'user.created': { userId: string; email: string };
  'user.deleted': { userId: string };
  'credential.issued': { credentialId: string; userId: string };
  'credential.revoked': { credentialId: string; reason: string };
}

// const eventBus = new TypedEventBus<AppEvents>({ ... });
// await eventBus.publish('user.created', { userId: '123', email: 'test@example.com' });