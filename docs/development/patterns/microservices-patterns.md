# SPARC Microservices Patterns

## Overview

This document describes the standardized patterns and best practices for building microservices in the SPARC platform. All services should follow these patterns to ensure consistency, maintainability, and scalability.

## Core Patterns

### 1. Service Base Class

All microservices should extend the `MicroserviceBase` class which provides:

```typescript
import { MicroserviceBase, ServiceConfig } from '@shared/patterns/service-base';

class MyService extends MicroserviceBase {
  constructor(config: ServiceConfig) {
    super(config);
  }

  public setupRoutes(): void {
    // Define your routes here
    this.app.route('/api/v1/resource', createResourceRoutes(this.prisma, this.redis));
  }

  protected async customHealthChecks(): Promise<Record<string, boolean>> {
    // Add service-specific health checks
    return {
      customCheck: true
    };
  }
}
```

**Features provided:**
- Standardized health checks (`/health`, `/ready`, `/metrics`)
- Database and Redis connections
- Middleware setup (CORS, auth, rate limiting, metrics)
- Graceful shutdown handling
- Request ID tracking
- Error handling
- Transaction and caching utilities

### 2. Service Registry & Discovery

Services automatically register themselves and can discover other services:

```typescript
import { ServiceDiscovery } from '@shared/patterns/service-registry';

// In your service
const discovery = new ServiceDiscovery(config.redisUrl);

// Call another service
const response = await discovery.call('user-service', '/api/v1/users/123', {
  method: 'GET',
  headers: {
    'Authorization': `Bearer ${token}`
  }
});
```

**Features:**
- Automatic service registration
- Health-based load balancing
- Failover support
- Service caching
- TTL-based cleanup

### 3. Event Bus

Asynchronous communication between services using events:

```typescript
import { TypedEventBus } from '@shared/patterns/event-bus';

// Define your events
interface ServiceEvents {
  'user.created': { userId: string; email: string };
  'order.placed': { orderId: string; userId: string; total: number };
}

// Create typed event bus
const eventBus = new TypedEventBus<ServiceEvents>({
  redisUrl: config.redisUrl,
  serviceName: 'my-service'
});

// Publish events
await eventBus.publish('user.created', {
  userId: '123',
  email: 'user@example.com'
});

// Subscribe to events
await eventBus.subscribe('order.placed', async (event) => {
  console.log('New order:', event.data);
});
```

**Features:**
- Type-safe events
- Durability (events stored in Redis)
- Retry logic
- Dead letter queue
- Pattern subscriptions
- Event history

### 4. Modular Architecture

Services should be organized into modules:

```
service-name/src/
├── index.ts              # Entry point using MicroserviceBase
├── types/                # TypeScript types and schemas
│   ├── index.ts         # Interfaces
│   └── schemas.ts       # Zod validation schemas
├── services/             # Business logic
│   └── main-service.ts  # Core service logic
├── routes/              # HTTP route handlers
│   └── main.ts         # Route definitions
├── utils/               # Utility functions
└── middleware/          # Custom middleware
```

### 5. Standardized Routes

All routes should follow RESTful conventions:

```typescript
// Routes module
export function createResourceRoutes(prisma: PrismaClient, redis: Redis) {
  const app = new Hono();
  
  // Apply auth middleware
  app.use('*', authMiddleware);
  
  // RESTful endpoints
  app.get('/', listResources);           // GET /api/v1/resources
  app.get('/:id', getResource);          // GET /api/v1/resources/:id
  app.post('/', createResource);         // POST /api/v1/resources
  app.put('/:id', updateResource);       // PUT /api/v1/resources/:id
  app.patch('/:id', patchResource);      // PATCH /api/v1/resources/:id
  app.delete('/:id', deleteResource);    // DELETE /api/v1/resources/:id
  
  return app;
}
```

## Implementation Guidelines

### 1. Configuration

Use environment variables with validation:

```typescript
const config: ServiceConfig = {
  serviceName: 'my-service',
  port: parseInt(process.env.PORT || '3000'),
  version: process.env.npm_package_version || '1.0.0',
  jwtSecret: process.env.JWT_SECRET!,
  redisUrl: process.env.REDIS_URL || 'redis://localhost:6379',
  databaseUrl: process.env.DATABASE_URL!,
  enableAuth: true,
  enableRateLimit: true,
  enableMetrics: true
};
```

### 2. Error Handling

Errors are automatically handled by the base class, but use proper error types:

```typescript
import { HTTPException } from 'hono/http-exception';

// In your route handler
if (!resource) {
  throw new HTTPException(404, { message: 'Resource not found' });
}

// Validation errors are automatically handled
const data = c.req.valid('json'); // Throws 400 with validation details
```

### 3. Database Operations

Use transactions for multi-step operations:

```typescript
const result = await this.withTransaction(async (tx) => {
  const user = await tx.user.create({ data: userData });
  const profile = await tx.profile.create({ data: { userId: user.id } });
  return { user, profile };
});
```

### 4. Caching

Use the built-in cache utilities:

```typescript
const user = await this.withCache(
  `user:${userId}`,
  300, // 5 minutes TTL
  async () => {
    return await this.prisma.user.findUnique({ where: { id: userId } });
  }
);

// Invalidate cache
await this.invalidateCache('user:*');
```

### 5. Inter-Service Communication

Choose the appropriate pattern:

**Synchronous (Request-Response):**
```typescript
const userResponse = await discovery.call('user-service', `/api/v1/users/${userId}`);
const user = await userResponse.json();
```

**Asynchronous (Event-Driven):**
```typescript
// Service A publishes
await eventBus.publish('order.placed', orderData);

// Service B subscribes
await eventBus.subscribe('order.placed', async (event) => {
  await processOrder(event.data);
});
```

### 6. Health Checks

Implement comprehensive health checks:

```typescript
protected async customHealthChecks(): Promise<Record<string, boolean>> {
  const checks: Record<string, boolean> = {};
  
  // Check external dependencies
  try {
    await fetch('https://api.external.com/health');
    checks.externalApi = true;
  } catch {
    checks.externalApi = false;
  }
  
  // Check critical resources
  checks.diskSpace = await this.checkDiskSpace();
  checks.memoryUsage = process.memoryUsage().heapUsed < 1e9; // < 1GB
  
  return checks;
}
```

### 7. Metrics

Custom metrics can be added:

```typescript
import { Counter, Histogram } from 'prom-client';

const orderCounter = new Counter({
  name: 'orders_total',
  help: 'Total number of orders',
  labelNames: ['status']
});

// In your handler
orderCounter.inc({ status: 'completed' });
```

## Migration Guide

To migrate a monolithic service:

1. **Run the modularization script:**
   ```bash
   ./scripts/modularize-service.sh my-service
   ```

2. **Extract code into modules:**
   - Types → `/types`
   - Business logic → `/services`
   - Routes → `/routes`
   - Utilities → `/utils`

3. **Update to use MicroserviceBase:**
   ```typescript
   // Old
   const app = new Hono();
   // ... manual setup
   
   // New
   class MyService extends MicroserviceBase {
     // ... simplified setup
   }
   ```

4. **Add service discovery:**
   - Replace hardcoded URLs with service discovery
   - Register service on startup

5. **Implement events:**
   - Replace direct database updates with events
   - Subscribe to relevant events from other services

## Best Practices

1. **Single Responsibility**: Each service should have one clear purpose
2. **API Versioning**: Use `/api/v1/` prefix for all routes
3. **Idempotency**: Make operations idempotent where possible
4. **Circuit Breakers**: Use circuit breakers for external calls
5. **Timeouts**: Set appropriate timeouts for all operations
6. **Logging**: Use structured logging with request IDs
7. **Documentation**: Document all APIs with OpenAPI
8. **Testing**: Write unit and integration tests for all components

## Example Service

See `mobile-credential-service` for a complete example implementing all patterns:
- Modular architecture
- Service base class
- Event publishing
- Service discovery
- Health checks
- Caching
- Transactions

## Monitoring

All services automatically expose:
- `/health` - Basic health status
- `/ready` - Readiness check
- `/metrics` - Prometheus metrics

Configure your monitoring stack to scrape these endpoints.

## Security

- All services require JWT authentication by default
- Rate limiting is enabled by default
- CORS is configured per service
- Use environment variables for secrets
- Implement proper authorization in route handlers

## Performance

- Use caching for frequently accessed data
- Implement pagination for list endpoints
- Use database indexes appropriately
- Monitor query performance
- Use connection pooling (provided by base class)

## Troubleshooting

Common issues and solutions:

1. **Service not discoverable**: Check Redis connection and service registration
2. **Events not received**: Verify Redis pub/sub and event subscriptions
3. **High latency**: Check database queries, add caching
4. **Memory leaks**: Review event listeners and cleanup
5. **Connection exhaustion**: Ensure proper connection pooling

## Next Steps

1. Review existing services for migration opportunities
2. Create service templates for common patterns
3. Implement distributed tracing
4. Add API gateway with these patterns
5. Create development tools for service generation