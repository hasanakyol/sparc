# Error Monitoring Documentation

## Overview

The SPARC platform includes a comprehensive error monitoring system that tracks, analyzes, and alerts on application errors across all services. This system provides real-time error tracking, trend analysis, and integration with external monitoring services.

## Architecture

### Components

1. **Error Tracker**
   - Centralized error collection
   - Automatic error grouping by fingerprint
   - Batch processing for performance
   - Real-time metrics calculation

2. **Sentry Integration**
   - External error tracking service
   - Performance profiling
   - Release tracking
   - Source map support

3. **Grafana Dashboards**
   - Real-time error visualization
   - Service-level error rates
   - Error distribution analysis
   - Circuit breaker monitoring

4. **Prometheus Alerts**
   - Automated error rate alerting
   - SLO violation detection
   - Cascading failure detection

## Error Tracking

### Automatic Error Capture

The error tracker automatically captures:
- Unhandled exceptions
- Promise rejections
- HTTP 5xx responses
- Database connection errors
- Circuit breaker state changes

### Manual Error Tracking

```typescript
import { trackError } from '@sparc/shared/monitoring/error-tracker';

// Track a standard error
try {
  await riskyOperation();
} catch (error) {
  await trackError(error, {
    operation: 'riskyOperation',
    userId: user.id,
    additionalContext: { ... }
  });
  throw error;
}

// Track a custom error event
await trackError({
  level: 'error',
  message: 'Payment processing failed',
  errorType: 'PaymentError',
  context: {
    orderId: order.id,
    amount: order.total,
    gateway: 'stripe'
  },
  user: {
    id: user.id,
    email: user.email,
    organizationId: user.organizationId
  }
});
```

### Error Fingerprinting

Errors are automatically grouped by fingerprint based on:
- Service name
- Error type/class
- Normalized error message
- Request path (if available)

This allows tracking of error trends and identifying recurring issues.

## Express Integration

### Error Handler Middleware

```typescript
import { errorHandler } from '@sparc/shared/monitoring/error-tracker';
import express from 'express';

const app = express();

// Your routes here...

// Add error handler as last middleware
app.use(errorHandler);
```

The error handler:
- Captures all unhandled errors
- Adds request context automatically
- Returns appropriate error responses
- Tracks errors for monitoring

## Grafana Dashboards

### Error Monitoring Dashboard

Access at: `https://grafana.sparc.com/d/sparc-error-monitoring`

**Panels include:**

1. **Error Rate by Service**
   - Time series of 4xx and 5xx errors
   - Service-level breakdown
   - 5-minute moving average

2. **Overall Error Rate**
   - System-wide error percentage
   - Visual gauge with thresholds
   - Real-time updates

3. **Error Distribution**
   - Pie chart of error types
   - HTTP status code breakdown
   - Last hour summary

4. **Top Errors by Type**
   - Table of most frequent errors
   - Service and error type
   - Occurrence count

5. **Unhandled Exceptions**
   - Time series by service
   - Stack trace samples
   - Trend analysis

6. **Circuit Breaker Status**
   - State changes over time
   - Service dependencies
   - Failure cascades

7. **Retry Attempts**
   - Success vs failure rates
   - Service breakdown
   - Retry strategies

8. **Recent Error Logs**
   - Live log stream
   - Filterable by service/level
   - Full error details

## Prometheus Alerts

### Critical Alerts

1. **HighErrorRate**
   - Triggers: Error rate > 5% for 5 minutes
   - Action: Page on-call engineer
   - Runbook: Check service health, recent deployments

2. **MultipleServiceFailures**
   - Triggers: > 3 services with 10% error rate
   - Action: Incident response team activation
   - Runbook: Check infrastructure, dependencies

3. **CascadingFailures**
   - Triggers: > 2 circuit breakers open
   - Action: Emergency response
   - Runbook: Isolate failing services, scale resources

### Warning Alerts

1. **ErrorSpike**
   - Triggers: 3x normal error rate
   - Action: Engineering team notification
   - Runbook: Investigate recent changes

2. **UnhandledExceptions**
   - Triggers: > 0.1 per second for 5 minutes
   - Action: Development team notification
   - Runbook: Review error logs, fix code

3. **DatabaseConnectionErrors**
   - Triggers: > 0.05 per second
   - Action: Database team notification
   - Runbook: Check connection pool, database health

## Error Metrics API

### Get Error Metrics

```typescript
import { getErrorMetrics } from '@sparc/shared/monitoring/error-tracker';

const metrics = await getErrorMetrics({
  start: new Date(Date.now() - 3600000), // Last hour
  end: new Date()
});

// Returns:
{
  totalErrors: 142,
  errorsByType: {
    'ValidationError': 89,
    'DatabaseError': 23,
    'NetworkError': 30
  },
  errorsByService: {
    'auth-service': 45,
    'api-gateway': 67,
    'video-service': 30
  },
  errorsByLevel: {
    'error': 120,
    'warning': 22
  },
  errorRate: 0.039, // Errors per second
  topErrors: [
    {
      fingerprint: 'auth-service:ValidationError:Invalid email format',
      count: 45,
      lastSeen: '2024-01-20T10:30:00Z',
      example: { ... }
    }
  ]
}
```

## Sentry Configuration

### Environment Variables

```bash
# Sentry configuration
SENTRY_DSN=https://xxx@sentry.io/xxx
SENTRY_ENVIRONMENT=production
SENTRY_RELEASE=1.2.3
SENTRY_TRACES_SAMPLE_RATE=0.1
SENTRY_PROFILES_SAMPLE_RATE=0.1
```

### Source Maps

For production error tracking with source maps:

```bash
# Upload source maps during deployment
sentry-cli releases files $VERSION upload-sourcemaps ./dist \
  --url-prefix "~/app"
```

## Database Schema

### error_events table
```sql
CREATE TABLE error_events (
  id UUID PRIMARY KEY,
  timestamp TIMESTAMPTZ NOT NULL,
  service VARCHAR(100) NOT NULL,
  environment VARCHAR(50) NOT NULL,
  error_type VARCHAR(255) NOT NULL,
  message TEXT NOT NULL,
  stack TEXT,
  context JSONB,
  user_data JSONB,
  request_data JSONB,
  tags JSONB,
  fingerprint JSONB,
  level VARCHAR(20) NOT NULL
);
```

### error_metrics_hourly table
```sql
CREATE TABLE error_metrics_hourly (
  hour TIMESTAMPTZ NOT NULL,
  service VARCHAR(100) NOT NULL,
  error_type VARCHAR(255),
  level VARCHAR(20),
  count INTEGER NOT NULL,
  PRIMARY KEY (hour, service, error_type, level)
);
```

## Best Practices

1. **Error Context**
   - Always include relevant context when tracking errors
   - Add user information for debugging
   - Include operation/transaction IDs

2. **Error Levels**
   - `fatal`: System crashes, data corruption
   - `error`: Failures requiring investigation
   - `warning`: Degraded functionality
   - `info`: Notable events

3. **Performance**
   - Errors are batched for database writes
   - Real-time metrics use Redis
   - Sampling applied in production

4. **Privacy**
   - Sensitive data is automatically scrubbed
   - PII is not stored in error messages
   - Request bodies are sanitized

## Integration Examples

### Service Integration

```typescript
// In service initialization
import { errorTracker } from '@sparc/shared/monitoring/error-tracker';

// Listen for critical errors
errorTracker.on('error', (error) => {
  if (error.level === 'fatal') {
    // Trigger emergency procedures
    notifyOncall(error);
  }
});

// Get service-specific metrics
errorTracker.on('metrics', (metrics) => {
  if (metrics.errorRate > 0.1) {
    // Consider circuit breaking
    logger.warn('High error rate detected', metrics);
  }
});
```

### Custom Error Types

```typescript
class PaymentError extends Error {
  constructor(message: string, public code: string, public details: any) {
    super(message);
    this.name = 'PaymentError';
  }
}

// Usage
try {
  await processPayment(order);
} catch (error) {
  if (error.code === 'insufficient_funds') {
    await trackError(new PaymentError(
      'Payment failed due to insufficient funds',
      'INSUFFICIENT_FUNDS',
      { orderId: order.id, amount: order.total }
    ));
  }
}
```

## Monitoring Workflows

### Daily Error Review

1. Check error summary dashboard
2. Review top errors by occurrence
3. Investigate new error types
4. Update error handling as needed

### Incident Response

1. Alert triggers (Prometheus/PagerDuty)
2. Check error monitoring dashboard
3. Identify affected services
4. Review error details and stack traces
5. Implement fix or mitigation
6. Monitor error rates post-fix

### Performance Impact

- Error tracking adds < 5ms overhead
- Batch processing reduces database load
- Redis caching enables real-time metrics
- Sampling reduces volume in production

## Troubleshooting

### Common Issues

1. **Errors not appearing in dashboard**
   - Check Sentry DSN configuration
   - Verify error handler is registered
   - Check service logs for tracking errors

2. **High error rates**
   - Review recent deployments
   - Check external dependencies
   - Verify database connections
   - Review circuit breaker states

3. **Missing error context**
   - Ensure context is passed to trackError
   - Verify user data is available
   - Check middleware ordering

## Future Enhancements

1. **Machine Learning**
   - Anomaly detection for error patterns
   - Predictive error forecasting
   - Automated root cause analysis

2. **Integration**
   - Slack notifications for critical errors
   - JIRA ticket creation for recurring errors
   - Deployment correlation

3. **Advanced Features**
   - Error replay functionality
   - Session replay for frontend errors
   - Distributed tracing integration