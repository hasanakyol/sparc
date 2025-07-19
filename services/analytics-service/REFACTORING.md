# Analytics Service Refactoring

## Overview

The Analytics Service has been refactored to use the standardized `MicroserviceBase` pattern, bringing it in line with other services in the SPARC platform.

## Changes Made

### 1. Service Architecture
- **Before**: Custom Hono app setup with manual configuration
- **After**: Extends `MicroserviceBase` class with standardized patterns

### 2. Key Improvements

#### Standardized Service Structure
```typescript
class AnalyticsService extends MicroserviceBase {
  // Centralized configuration
  // Consistent error handling
  // Unified logging
  // Graceful shutdown
}
```

#### Better Connection Management
- Connections are tested during startup
- Proper cleanup on shutdown
- Better error handling for connection failures

#### Enhanced OpenSearch Integration
- Automatic index creation with proper mappings
- Type-specific mappings for different analytics data
- Better error handling for index operations

#### Improved WebSocket Support
- Separate WebSocket server on configurable port
- Structured message handling
- Channel-based subscriptions

### 3. Configuration

The service now uses standardized environment variables:
```bash
# Core settings (from MicroserviceBase)
PORT=3009
NODE_ENV=production
LOG_LEVEL=info

# Analytics-specific settings
OPENSEARCH_URL=http://localhost:9200
OPENSEARCH_INDEX=sparc-analytics
OPENSEARCH_USERNAME=admin
OPENSEARCH_PASSWORD=admin
ENABLE_WEBSOCKET=true
WS_PORT=3019
```

### 4. Health Checks

Enhanced health check endpoint at `/health/detailed`:
```json
{
  "service": "analytics-service",
  "status": "healthy",
  "connections": {
    "database": true,
    "redis": true,
    "opensearch": "green"
  },
  "websocket": {
    "enabled": true,
    "clients": 5
  },
  "timestamp": "2025-01-19T12:00:00.000Z"
}
```

### 5. WebSocket Protocol

Standardized WebSocket message format:
```typescript
// Subscribe to channel
{ "type": "subscribe", "channel": "anomalies" }

// Unsubscribe
{ "type": "unsubscribe" }

// Ping/Pong health check
{ "type": "ping" }
```

### 6. Benefits

1. **Consistency**: Same patterns as other microservices
2. **Maintainability**: Less custom code to maintain
3. **Observability**: Standardized logging and metrics
4. **Reliability**: Better error handling and recovery
5. **Scalability**: Easier to scale with consistent patterns

## Migration Guide

### For Developers

1. The service API remains unchanged
2. WebSocket connections now use port 3019 by default
3. All existing routes work as before
4. Enhanced health checks available at `/health/detailed`

### For Operations

1. Update environment variables if needed
2. WebSocket server runs on separate port (3019)
3. Monitor new health check endpoints
4. Review OpenSearch index mappings

### Breaking Changes

- None for HTTP API
- WebSocket server now on separate port (configurable via `WS_PORT`)

## Testing

Run tests to verify the refactoring:
```bash
npm test
npm run test:integration
```

## Rollback

If issues arise, the previous version can be restored from git history. The refactoring maintains API compatibility, so no client changes are required.