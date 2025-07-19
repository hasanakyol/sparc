# SPARC Event Bus

A comprehensive event-driven architecture implementation for the SPARC security platform, providing reliable cross-service communication with event sourcing, monitoring, and debugging capabilities.

## Features

- **Domain Event Pattern**: Standardized event structure with versioning support
- **Type Safety**: Full TypeScript support with typed event definitions
- **Reliable Delivery**: Transactional outbox pattern with retry logic
- **Event Sourcing**: Event persistence and replay capabilities
- **Dead Letter Queue**: Automatic handling of failed events
- **Monitoring**: Built-in metrics, tracing, and health checks
- **Ordering Guarantees**: Optional event ordering per tenant/type
- **Batch Processing**: Efficient batch event handling
- **Event Correlation**: Track related events across services

## Quick Start

```typescript
import { createSparcEventBus, SparcDomainEvents } from '@shared/events';

// Create event bus instance
const eventBus = createSparcEventBus({
  redisUrl: process.env.REDIS_URL,
  serviceName: 'my-service',
  enablePersistence: true,
  enableOrdering: true
});

// Publish an event
await eventBus.publish('security.incident.created', {
  incidentId: 'INC-123',
  type: 'intrusion',
  severity: 'high',
  siteId: 'site-1',
  description: 'Unauthorized access detected'
}, {
  tenantId: 'tenant-123',
  userId: 'user-456'
});

// Subscribe to events
await eventBus.subscribe('security.incident.created', async (event) => {
  console.log('New incident:', event.data);
  // Handle the event
});
```

## Architecture

### Event Structure

All events follow a standardized structure:

```typescript
interface DomainEvent<T = any> {
  id: string;              // Unique event ID
  type: string;            // Event type (e.g., 'security.incident.created')
  version: number;         // Event schema version
  tenantId: string;        // Multi-tenant context
  timestamp: Date;         // Event timestamp
  data: T;                 // Event payload
  metadata?: {
    correlationId?: string;  // Track related events
    causationId?: string;    // Parent event ID
    userId?: string;         // User who triggered event
    source?: string;         // Service that created event
    [key: string]: any;      // Additional metadata
  };
}
```

### Event Types

SPARC defines domain events across several categories:

- **Security Events**: Incidents, alerts, access control
- **Video Events**: Recording, streaming, motion detection
- **System Events**: Device status, configuration changes
- **Analytics Events**: Thresholds, anomalies, predictions
- **User Events**: Authentication, authorization, account management

See `domainEvents.ts` for the complete list of event types.

## Event Handlers

### Basic Handler

```typescript
import { BaseEventHandler } from '@shared/events';

class MyEventHandler extends BaseEventHandler<SecurityIncidentCreated> {
  constructor() {
    super('MyEventHandler', {
      maxRetries: 3,
      retryDelay: 1000
    });
  }

  protected async process(event: DomainEvent<SecurityIncidentCreated>): Promise<void> {
    // Process the event
    console.log('Processing incident:', event.data.incidentId);
  }
}
```

### Batch Handler

Process multiple events efficiently:

```typescript
const batchHandler = new BatchEventHandler(
  'MyBatchHandler',
  async (events) => {
    // Process batch of events
    await db.insertMany(events.map(e => e.data));
  },
  {
    batchSize: 100,
    flushInterval: 5000
  }
);
```

### Aggregator Handler

Aggregate events over time windows:

```typescript
const aggregator = new AggregatorEventHandler(
  'FailedLoginAggregator',
  (event) => event.data.userId, // Group by user
  async (userId, events) => {
    if (events.length > 5) {
      // Too many failed logins - lock account
      await lockUserAccount(userId);
    }
  },
  { windowSize: 300000 } // 5 minutes
);
```

## Monitoring

### Metrics

The event bus exposes Prometheus metrics:

- `event_bus_events_published_total`: Total events published
- `event_bus_events_processed_total`: Total events processed
- `event_bus_events_failed_total`: Total failed events
- `event_bus_processing_duration_seconds`: Processing duration histogram
- `event_bus_dlq_size`: Dead letter queue size
- `event_bus_outbox_size`: Outbox queue size

### Tracing

Enable event flow tracing for debugging:

```typescript
const tracer = new EventFlowTracer();

// Get trace for specific event
const trace = tracer.getTrace(eventId);

// Get all events in a correlation
const correlated = tracer.getTracesByCorrelation(correlationId);

// Get recent failed events
const failed = tracer.getFailedTraces(20);
```

### Health Checks

```typescript
const healthChecker = new EventBusHealthChecker(eventBus, metrics);
const health = await healthChecker.checkHealth();

console.log(health.status); // 'healthy' | 'degraded' | 'unhealthy'
```

## Event Replay

Replay historical events for recovery or testing:

```typescript
// Replay events from a time range
const events = await eventBus.replay({
  type: 'security.incident.created',
  from: new Date('2024-01-01'),
  to: new Date('2024-01-31'),
  tenantId: 'tenant-123',
  handler: async (event) => {
    // Process replayed event
  }
});
```

## Service Integration

### Extending MicroserviceBase

```typescript
import { EventDrivenMicroservice } from '@shared/events/examples';

class MyService extends EventDrivenMicroservice {
  constructor() {
    super({
      serviceName: 'my-service',
      port: 3000
    });
  }

  protected async registerEventHandlers(): Promise<void> {
    // Register service-specific handlers
    await this.eventBus.subscribe('video.motion.detected', async (event) => {
      await this.handleMotionDetection(event);
    });
  }

  private async handleMotionDetection(event: DomainEvent): Promise<void> {
    // Service-specific logic
  }
}
```

### Publishing from API Routes

```typescript
app.post('/incidents', async (c) => {
  const data = await c.req.json();
  
  // Publish event
  await eventBus.publish('security.incident.created', {
    incidentId: generateId(),
    ...data
  }, {
    tenantId: c.get('tenantId'),
    userId: c.get('userId')
  });

  return c.json({ success: true });
});
```

## Best Practices

### 1. Event Naming

Follow the convention: `<entity>.<action>`
- ✅ `security.incident.created`
- ✅ `video.recording.started`
- ❌ `create_incident`
- ❌ `IncidentCreatedEvent`

### 2. Event Versioning

Always include version in event definitions:
```typescript
const EVENT_VERSIONS = {
  'user.created': 2,  // Increment when schema changes
  'user.updated': 1
};
```

### 3. Idempotency

Make handlers idempotent using deduplication:
```typescript
const dedupeHandler = new DedupeEventHandler(
  'MyHandler',
  actualHandler,
  {
    ttl: 3600000, // 1 hour
    keyGenerator: (event) => `${event.type}:${event.data.id}`
  }
);
```

### 4. Error Handling

Always handle errors gracefully:
```typescript
class MyHandler extends BaseEventHandler {
  protected async handleError(event: DomainEvent, error: Error): Promise<void> {
    // Log error with context
    logger.error('Event processing failed', {
      eventId: event.id,
      eventType: event.type,
      error
    });
    
    // Send to monitoring
    await alerting.sendAlert({
      severity: 'high',
      message: `Failed to process ${event.type}`,
      context: { eventId: event.id, error: error.message }
    });
  }
}
```

### 5. Testing

Test event handlers in isolation:
```typescript
describe('SecurityIncidentHandler', () => {
  it('should create incident in database', async () => {
    const handler = new SecurityIncidentHandler();
    const event = createMockEvent('security.incident.created', {
      incidentId: 'INC-123',
      severity: 'high'
    });

    await handler.handle(event);

    const incident = await db.incident.findUnique({
      where: { id: 'INC-123' }
    });
    expect(incident).toBeDefined();
    expect(incident.severity).toBe('high');
  });
});
```

## Troubleshooting

### Events Not Being Received

1. Check Redis connection
2. Verify subscription pattern matches event type
3. Check for errors in dead letter queue
4. Enable debug logging

### High Memory Usage

1. Reduce batch sizes
2. Decrease trace retention
3. Implement event cleanup policies
4. Monitor outbox queue size

### Event Ordering Issues

1. Enable ordering in configuration
2. Ensure consistent tenant/type combinations
3. Check for race conditions in handlers
4. Use correlation IDs for related events

## Performance Considerations

- **Batch Size**: Adjust based on event size and processing capacity
- **Flush Interval**: Balance between latency and efficiency
- **Retry Policy**: Exponential backoff prevents thundering herd
- **Connection Pooling**: Share Redis connections across handlers
- **Event Size**: Keep payloads small, use references for large data

## Security

- All events include tenant context for isolation
- Sensitive data should be encrypted in event payloads
- Use correlation IDs to track event chains
- Implement rate limiting for event publishing
- Monitor for event storms and anomalies