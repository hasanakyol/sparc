# Comprehensive Error Handling Implementation

## Overview

SPARC implements a multi-layered error handling strategy with:
- Global error handlers for consistent error responses
- Circuit breakers for fault tolerance
- Retry logic for transient failures
- Structured error logging and monitoring

## Components

### 1. Global Error Handler

The global error handler provides consistent error responses across all services:

```typescript
import { globalErrorHandler, notFoundHandler } from '@sparc/shared/middleware/error-handler';

// Apply to Hono app
app.onError(globalErrorHandler);
app.notFound(notFoundHandler);
```

#### Error Response Format

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Validation failed",
    "details": [
      {
        "field": "email",
        "message": "Invalid email format",
        "code": "invalid_string"
      }
    ],
    "timestamp": "2024-01-20T10:30:00.000Z",
    "requestId": "123e4567-e89b-12d3-a456-426614174000",
    "path": "/api/users"
  }
}
```

#### Error Types Handled

1. **HTTPException** - Standard HTTP errors
2. **ZodError** - Validation errors
3. **PrismaClientKnownRequestError** - Database errors
4. **UnauthorizedError** - Authentication errors
5. **TimeoutError** - Request timeouts
6. **Connection Errors** - Service unavailable

### 2. Circuit Breaker

Circuit breakers prevent cascading failures by stopping requests to failing services:

```typescript
import { CircuitBreaker, CircuitBreakerFactory } from '@sparc/shared/utils/circuit-breaker';

// Create circuit breaker
const dbBreaker = CircuitBreakerFactory.create({
  name: 'database',
  failureThreshold: 5,
  resetTimeout: 60000, // 1 minute
  timeout: 30000 // 30 seconds
});

// Use with async operations
const result = await dbBreaker.execute(async () => {
  return await prisma.user.findMany();
});
```

#### Circuit States

1. **CLOSED** - Normal operation, requests pass through
2. **OPEN** - Failures exceeded threshold, requests blocked
3. **HALF_OPEN** - Testing if service recovered

#### Configuration Options

```typescript
{
  name: string;                    // Unique identifier
  failureThreshold: number;        // Failures before opening (default: 5)
  resetTimeout: number;           // Time before attempting reset (default: 60s)
  timeout: number;                // Request timeout (default: 30s)
  volumeThreshold: number;        // Min requests before opening (default: 10)
  halfOpenMaxAttempts: number;    // Successful requests to close (default: 3)
  errorFilter: (error) => boolean; // Which errors trigger breaker
}
```

#### Using Decorators

```typescript
class UserService {
  @CircuitBreakerProtected({
    failureThreshold: 3,
    resetTimeout: 30000
  })
  async getUsers() {
    return await prisma.user.findMany();
  }
}
```

### 3. Retry Logic

Automatic retry with exponential backoff for transient failures:

```typescript
import { retry, RetryPolicies } from '@sparc/shared/utils/retry';

// Basic retry
const result = await retry(
  async () => await fetchExternalAPI(),
  {
    maxAttempts: 3,
    initialDelay: 1000,
    maxDelay: 10000,
    factor: 2,
    jitter: true
  }
);

// Using predefined policies
const data = await retry(
  async () => await prisma.user.findMany(),
  RetryPolicies.database
);
```

#### Retry Policies

1. **Database** - Quick retries for deadlocks/timeouts
2. **API** - Longer delays for external services
3. **Service** - Balanced for internal services
4. **Quick** - Minimal delay for fast recovery

#### Using Decorators

```typescript
class ExternalService {
  @Retryable({
    maxAttempts: 5,
    initialDelay: 1000
  })
  async callAPI() {
    return await fetch('https://api.example.com/data');
  }
}
```

## Implementation Examples

### Service Setup

```typescript
import { Hono } from 'hono';
import { globalErrorHandler, CircuitBreakerFactory, retry, RetryPolicies } from '@sparc/shared';

const app = new Hono();

// Global error handling
app.onError(globalErrorHandler);

// Database circuit breaker
const dbBreaker = CircuitBreakerFactory.create({
  name: 'database',
  failureThreshold: 5,
  resetTimeout: 60000
});

// API endpoint with error handling
app.get('/users', async (c) => {
  try {
    // Execute with circuit breaker and retry
    const users = await dbBreaker.execute(async () => {
      return await retry(
        async () => await prisma.user.findMany(),
        RetryPolicies.database
      );
    });
    
    return c.json(users);
  } catch (error) {
    // Global handler will catch and format
    throw error;
  }
});
```

### Error Monitoring Integration

```typescript
// Circuit breaker events
dbBreaker.on('open', (data) => {
  logger.alert('Circuit breaker opened', data);
  metrics.increment('circuit_breaker.open', { name: data.name });
});

dbBreaker.on('halfOpen', (data) => {
  logger.info('Circuit breaker half-open', data);
});

// Get circuit breaker stats
const stats = CircuitBreakerFactory.getAllStats();
```

## Error Codes Reference

### Client Errors (4xx)

- `BAD_REQUEST` - Invalid request format
- `UNAUTHORIZED` - Authentication required
- `FORBIDDEN` - Insufficient permissions
- `NOT_FOUND` - Resource not found
- `CONFLICT` - Resource conflict (duplicate)
- `VALIDATION_ERROR` - Input validation failed
- `RATE_LIMIT_EXCEEDED` - Too many requests

### Server Errors (5xx)

- `INTERNAL_SERVER_ERROR` - Unexpected error
- `SERVICE_UNAVAILABLE` - Service down/overloaded
- `TIMEOUT` - Operation timeout

### Business Logic Errors

- `INSUFFICIENT_PERMISSIONS` - Missing required permission
- `RESOURCE_LOCKED` - Resource temporarily unavailable
- `OPERATION_NOT_ALLOWED` - Business rule violation
- `QUOTA_EXCEEDED` - Usage limit reached

### Authentication Errors

- `INVALID_CREDENTIALS` - Wrong username/password
- `TOKEN_EXPIRED` - JWT expired
- `TOKEN_INVALID` - Malformed/invalid JWT
- `MFA_REQUIRED` - 2FA verification needed
- `MFA_INVALID` - Wrong 2FA code

## Best Practices

### 1. Error Classification

```typescript
// Classify errors for appropriate handling
function classifyError(error: Error): 'transient' | 'permanent' | 'unknown' {
  if (isRetryableError(error)) return 'transient';
  if (error.name === 'ValidationError') return 'permanent';
  return 'unknown';
}
```

### 2. Contextual Error Information

```typescript
// Add context to errors
class ServiceError extends Error {
  constructor(
    message: string,
    public code: string,
    public context?: any
  ) {
    super(message);
    this.name = 'ServiceError';
  }
}

throw new ServiceError(
  'User not found',
  'USER_NOT_FOUND',
  { userId, tenantId }
);
```

### 3. Error Recovery Strategies

```typescript
// Fallback on circuit breaker open
async function getUsersWithFallback() {
  try {
    return await dbBreaker.execute(async () => {
      return await prisma.user.findMany();
    });
  } catch (error) {
    if (error.message.includes('Circuit breaker')) {
      // Return cached data or default response
      return await getCachedUsers();
    }
    throw error;
  }
}
```

### 4. Error Aggregation

```typescript
// Aggregate errors for bulk operations
const results = await retryBulk(
  operations.map(op => () => processOperation(op)),
  RetryPolicies.api
);

const errors = results
  .filter(r => r.error)
  .map(r => ({ operation: op, error: r.error }));
```

## Monitoring and Alerting

### Key Metrics

1. **Error Rate** - Errors per minute by type
2. **Circuit Breaker State** - Open/closed breakers
3. **Retry Success Rate** - Successful retries vs failures
4. **Response Time** - Including retry delays
5. **Error Distribution** - By error code

### Dashboard Queries

```sql
-- Error rate by service
SELECT 
  service,
  error_code,
  COUNT(*) as count,
  DATE_TRUNC('minute', timestamp) as minute
FROM error_logs
WHERE timestamp > NOW() - INTERVAL '1 hour'
GROUP BY service, error_code, minute;

-- Circuit breaker state changes
SELECT 
  breaker_name,
  state,
  COUNT(*) as changes,
  DATE_TRUNC('hour', timestamp) as hour
FROM circuit_breaker_events
WHERE timestamp > NOW() - INTERVAL '24 hours'
GROUP BY breaker_name, state, hour;
```

## Testing Error Handling

### Unit Tests

```typescript
describe('Error Handler', () => {
  it('should handle validation errors', async () => {
    const error = new ZodError([
      { path: ['email'], message: 'Invalid email', code: 'invalid_string' }
    ]);
    
    const response = globalErrorHandler(error, mockContext);
    expect(response.status).toBe(400);
    expect(response.body.error.code).toBe('VALIDATION_ERROR');
  });
});
```

### Integration Tests

```typescript
describe('Circuit Breaker', () => {
  it('should open after threshold failures', async () => {
    const breaker = new CircuitBreaker({
      name: 'test',
      failureThreshold: 2
    });
    
    // Fail twice
    await expect(breaker.execute(() => Promise.reject(new Error()))).rejects.toThrow();
    await expect(breaker.execute(() => Promise.reject(new Error()))).rejects.toThrow();
    
    // Should be open
    await expect(breaker.execute(() => Promise.resolve())).rejects.toThrow('Circuit breaker test is OPEN');
  });
});
```

## Migration Guide

### Adding to Existing Service

1. **Install dependencies**
   ```bash
   npm install @sparc/shared
   ```

2. **Add global error handler**
   ```typescript
   import { globalErrorHandler } from '@sparc/shared/middleware/error-handler';
   app.onError(globalErrorHandler);
   ```

3. **Wrap critical operations**
   ```typescript
   const dbBreaker = CircuitBreakerFactory.create({ name: 'db' });
   const result = await dbBreaker.execute(() => dbOperation());
   ```

4. **Add retry logic**
   ```typescript
   const data = await retry(() => fetchData(), RetryPolicies.api);
   ```

## Troubleshooting

### Common Issues

1. **Circuit Breaker Won't Close**
   - Check error filter configuration
   - Verify success threshold is reachable
   - Monitor half-open attempts

2. **Excessive Retries**
   - Review retry condition logic
   - Check max delay settings
   - Monitor retry metrics

3. **Inconsistent Error Responses**
   - Ensure global handler is registered
   - Check for error handling before global handler
   - Verify error propagation