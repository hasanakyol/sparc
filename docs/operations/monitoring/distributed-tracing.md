# SPARC Distributed Tracing Guide

This guide covers the implementation and usage of distributed tracing in the SPARC platform using OpenTelemetry and Jaeger.

## Overview

SPARC uses OpenTelemetry for instrumentation and Jaeger as the tracing backend to provide:

- End-to-end request tracing across all microservices
- Performance bottleneck identification
- Error tracking and root cause analysis
- Service dependency mapping
- Trace-based alerting

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Service   │────▶│ OpenTelemetry│────▶│   Jaeger    │
│  (w/ SDK)   │     │  Collector   │     │  Collector  │
└─────────────┘     └─────────────┘     └─────────────┘
                                               │
                                               ▼
                                         ┌─────────────┐
                                         │ Jaeger UI   │
                                         └─────────────┘
                                               │
                                               ▼
                                         ┌─────────────┐
                                         │ Prometheus  │
                                         │  (Metrics)  │
                                         └─────────────┘
```

## Quick Start

### 1. Setup Jaeger in Kubernetes

```bash
# Deploy Jaeger
./scripts/setup-jaeger.sh

# With example trace generation
./scripts/setup-jaeger.sh --with-examples
```

### 2. Initialize Telemetry in Your Service

```typescript
import { initializeService, applyTelemetryToHono } from '@sparc/shared/telemetry';

// Initialize telemetry
const { logger, shutdown } = await initializeService({
  serviceName: 'my-service',
  serviceVersion: '1.0.0'
});

// Apply to Hono app
const app = new Hono();
applyTelemetryToHono(app, 'my-service');
```

## Service Instrumentation

### Basic Setup

Every SPARC service should initialize telemetry on startup:

```typescript
// services/my-service/src/index.ts
import { 
  initializeService, 
  applyTelemetryToHono,
  createHealthCheckRoute 
} from '@sparc/shared/telemetry';

async function startService() {
  // Initialize telemetry
  const { logger, shutdown } = await initializeService({
    serviceName: 'my-service',
    serviceVersion: process.env.SERVICE_VERSION || '1.0.0',
    environment: process.env.NODE_ENV || 'development',
    customAttributes: {
      'service.type': 'api',
      'service.tier': 'backend'
    }
  });

  const app = new Hono();
  
  // Apply telemetry middleware
  applyTelemetryToHono(app, 'my-service');
  
  // Your routes here...
  
  // Health check with tracing
  createHealthCheckRoute(app, 'my-service', {
    database: async () => checkDatabase(),
    redis: async () => checkRedis()
  });
  
  // Graceful shutdown
  process.on('SIGTERM', async () => {
    await shutdown();
    process.exit(0);
  });
}
```

### Using Decorators

Decorate your service methods for automatic tracing:

```typescript
import { 
  Trace, 
  TraceDB, 
  TraceCache, 
  TraceService,
  MeasurePerformance 
} from '@sparc/shared/telemetry';

class UserService {
  // Database operations
  @TraceDB('select', 'users')
  @MeasurePerformance(100) // Alert if > 100ms
  async getUserById(id: string) {
    return prisma.user.findUnique({ where: { id } });
  }

  // Cache operations
  @TraceCache('get')
  async getCachedUser(id: string) {
    return this.redis.get(`user:${id}`);
  }

  // External service calls
  @TraceService('auth-service', 'validateToken')
  async validateToken(token: string) {
    // Service call with automatic tracing
  }

  // Business operations
  @TraceBusiness('user-management', 'createUser')
  async createUser(data: CreateUserDto) {
    // Complex business logic
  }
}
```

### Manual Span Creation

For complex operations, create spans manually:

```typescript
import { telemetry, SpanKind, SpanStatusCode } from '@sparc/shared/telemetry';

async function complexOperation() {
  // Using withSpan helper
  return telemetry.withSpan(
    'operation.complex',
    async (span) => {
      span.setAttributes({
        'operation.type': 'batch',
        'operation.size': items.length
      });

      try {
        const result = await processItems(items);
        span.setStatus({ code: SpanStatusCode.OK });
        return result;
      } catch (error) {
        span.recordException(error);
        span.setStatus({
          code: SpanStatusCode.ERROR,
          message: error.message
        });
        throw error;
      }
    },
    { kind: SpanKind.INTERNAL }
  );
}

// Or manual span management
async function batchProcess(items: any[]) {
  const span = telemetry.startSpan('batch.process', {
    kind: SpanKind.INTERNAL,
    attributes: {
      'batch.size': items.length
    }
  });

  try {
    for (const item of items) {
      // Create child spans
      await telemetry.withSpan(
        'batch.process_item',
        async (childSpan) => {
          childSpan.setAttribute('item.id', item.id);
          await processItem(item);
        },
        { parent: span }
      );
    }
    
    span.setStatus({ code: SpanStatusCode.OK });
  } catch (error) {
    span.recordException(error);
    span.setStatus({ code: SpanStatusCode.ERROR });
    throw error;
  } finally {
    span.end();
  }
}
```

### Service-to-Service Tracing

Trace context is automatically propagated in service calls:

```typescript
// Automatic propagation with fetch
const response = await fetch('http://other-service/api/endpoint', {
  headers: {
    ...telemetry.injectTraceContext(),
    'Content-Type': 'application/json'
  }
});

// Using traced service client
const authClient = createTracedServiceClient<AuthServiceClient>(
  'auth-service',
  'http://auth-service:3001',
  ['validateToken', 'refreshToken']
);

const result = await authClient.validateToken({ token });
```

## Error Handling

Use TracedError for errors with trace context:

```typescript
import { TracedError } from '@sparc/shared/telemetry';

// Throw traced errors
throw new TracedError('User not found', 'USER_NOT_FOUND', { userId });

// Convert regular errors
try {
  await riskyOperation();
} catch (error) {
  throw TracedError.from(error, 'OPERATION_FAILED');
}

// Errors automatically include trace context
{
  "error": {
    "message": "User not found",
    "code": "USER_NOT_FOUND",
    "traceId": "abc123...",
    "spanId": "def456...",
    "correlationContext": {
      "tenantId": "tenant-123",
      "userId": "user-456",
      "requestId": "req-789"
    }
  }
}
```

## Logging with Trace Context

Use TraceLogger for correlated logs:

```typescript
import { createTraceLogger } from '@sparc/shared/telemetry';

const logger = createTraceLogger('my-service');

// Logs automatically include trace context
logger.info('Processing request', { userId });
// Output: {"traceId":"abc123","spanId":"def456","message":"Processing request",...}

// Log errors with automatic exception recording
logger.error('Operation failed', error);

// Log performance metrics
logger.logPerformance('database.query', 150, { query: 'SELECT...' });

// Log security events
logger.logSecurity('unauthorized_access', 'high', { 
  ip: request.ip,
  path: request.path 
});
```

## Trace Analysis

### Grafana Dashboards

Access pre-built dashboards:

1. **Distributed Tracing Dashboard**: Overview of all traces
2. **Trace Analysis Dashboard**: Deep dive into trace patterns
3. **Service Dependencies**: Visualize service communication
4. **Error Analysis**: Track errors across services

### Jaeger UI

Access Jaeger UI:
```bash
kubectl port-forward -n observability svc/jaeger-query 16686:16686
# Open http://localhost:16686
```

Features:
- Search traces by service, operation, tags
- View trace timeline and spans
- Analyze service dependencies
- Compare traces

### Example Queries

Find slow operations:
```
service="api-gateway" AND duration>1000ms
```

Find errors in specific service:
```
service="auth-service" AND error=true
```

Find traces for specific tenant:
```
tenant.id="tenant-123"
```

## Performance Optimization

### Sampling Configuration

Configure sampling per service:

```typescript
// Development: 100% sampling
const samplingRatio = 1.0;

// Production: 10% sampling for high-traffic services
const samplingRatio = 0.1;

// Adaptive sampling based on service
const samplingConfig = {
  'api-gateway': 0.1,      // High traffic
  'auth-service': 0.1,     // High traffic
  'video-service': 0.05,   // Very high traffic
  'analytics-service': 0.5  // Lower traffic, more sampling
};
```

### Span Attributes Best Practices

```typescript
// DO: Add meaningful attributes
span.setAttributes({
  'user.id': userId,
  'tenant.id': tenantId,
  'operation.type': 'batch',
  'batch.size': items.length
});

// DON'T: Add sensitive data
span.setAttribute('user.password', password); // Never!
span.setAttribute('credit_card', cardNumber); // Never!

// DO: Use semantic conventions
span.setAttributes({
  'http.method': 'POST',
  'http.status_code': 200,
  'http.url': '/api/users',
  'db.system': 'postgresql',
  'db.operation': 'SELECT'
});
```

## Alerting

Trace-based alerts are configured in `monitoring/alerts/trace-based-alerts.yaml`:

- **High Error Rate**: > 5% errors in traces
- **High Latency**: p95 > 1s
- **Trace Export Failures**: Failed to send traces
- **Service Dependency Errors**: > 10% errors between services

## Troubleshooting

### No Traces Appearing

1. Check Jaeger is running:
```bash
kubectl get pods -n observability | grep jaeger
```

2. Check service logs for telemetry initialization:
```bash
kubectl logs deployment/my-service | grep "OpenTelemetry initialized"
```

3. Verify environment variables:
```bash
kubectl describe deployment my-service | grep JAEGER_ENDPOINT
```

### Missing Spans

1. Check sampling ratio isn't too low
2. Verify trace context propagation in headers
3. Check for span export errors in logs

### Performance Impact

1. Reduce sampling ratio for high-traffic services
2. Limit span attributes to essential data
3. Use batch span processors
4. Configure appropriate timeouts

## Best Practices

1. **Always initialize telemetry** at service startup
2. **Use semantic conventions** for span attributes
3. **Propagate trace context** in all service calls
4. **Handle errors properly** with TracedError
5. **Add meaningful attributes** but avoid sensitive data
6. **Set appropriate sampling** based on traffic
7. **Monitor trace export** success rates
8. **Use child spans** for complex operations
9. **Correlate logs** with trace context
10. **Review traces regularly** for optimization opportunities

## Environment Variables

```bash
# Required
SERVICE_NAME=my-service
JAEGER_ENDPOINT=http://jaeger-collector.observability:4317

# Optional
SERVICE_VERSION=1.0.0
NODE_ENV=production
TRACE_SAMPLING_RATIO=0.1
OTEL_LOG_LEVEL=info
OTEL_PROPAGATORS=tracecontext,baggage,jaeger,b3
```

## Additional Resources

- [OpenTelemetry Documentation](https://opentelemetry.io/docs/)
- [Jaeger Documentation](https://www.jaegertracing.io/docs/)
- [SPARC Telemetry Package](@sparc/shared/telemetry)
- [Example Service](services/example-telemetry-service)