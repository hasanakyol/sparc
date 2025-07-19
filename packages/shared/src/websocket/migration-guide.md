# WebSocket Migration Guide

This guide explains how to migrate from the existing separate WebSocket implementations to the unified WebSocket service.

## Overview

The unified WebSocket service consolidates three separate implementations:
1. Security Monitoring Service WebSocket (ws library)
2. Alert Service WebSocket (Socket.IO)
3. Video Management Service WebSocket (Socket.IO)

## Key Benefits

- **Single WebSocket connection** per client instead of multiple
- **Consistent event patterns** across all services
- **Redis-based horizontal scaling** for all WebSocket traffic
- **Unified authentication and authorization**
- **Centralized rate limiting and monitoring**
- **Automatic reconnection handling**

## Server-Side Migration

### 1. Security Monitoring Service

**Before:**
```typescript
// services/security-monitoring-service/src/services/realtime-service.ts
private wss: WebSocketServer;
private clients: Map<string, WSClient> = new Map();

// Direct WebSocket handling
this.wss.on('connection', async (ws, req) => {
  // Custom auth and client management
});
```

**After:**
```typescript
// Use unified WebSocket service
import { UnifiedWebSocketService } from '@sparc/shared/websocket';

// Emit events to unified service
this.websocketService.broadcastToTenant(
  tenantId, 
  'monitoring', 
  'security:event',
  { event: securityEvent, analysis: threatAnalysis }
);
```

### 2. Alert Service

**Before:**
```typescript
// services/alert-service/src/index.ts
private io: SocketIOServer;

// Socket.IO with custom setup
this.io.on('connection', (socket) => {
  socket.on('join-tenant', (tenantId: string) => {
    socket.join(`tenant:${tenantId}`);
  });
});
```

**After:**
```typescript
// Emit to unified service
this.websocketService.broadcastToTenant(
  tenantId,
  'alerts',
  'alert:created',
  alert
);
```

### 3. Video Management Service

**Before:**
```typescript
// Direct Socket.IO integration
this.io.of('/video').on('connection', (socket) => {
  // Video-specific handling
});
```

**After:**
```typescript
// Video events are handled by unified service
this.websocketService.on('video:stream:start', async (data) => {
  // Handle stream start
  await this.startVideoStream(data.cameraId, data.quality);
});
```

## Client-Side Migration

### 1. Security Monitoring Client

**Before:**
```typescript
// Direct WebSocket connection
const ws = new WebSocket(`wss://api.sparc.io/security?token=${token}`);
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  // Handle security events
};
```

**After:**
```typescript
import { MonitoringWebSocketClient } from '@sparc/shared/websocket';

const client = new MonitoringWebSocketClient({
  url: 'wss://api.sparc.io',
  token: authToken
});

await client.connect();
await client.subscribeToEvents(['security:events', 'incidents']);

client.on('message', (event) => {
  // Handle events with proper typing
});
```

### 2. Alert Client

**Before:**
```typescript
import { io } from 'socket.io-client';

const socket = io('wss://api.sparc.io', {
  auth: { token }
});

socket.on('alert:created', (alert) => {
  // Handle alert
});
```

**After:**
```typescript
import { AlertWebSocketClient } from '@sparc/shared/websocket';

const client = new AlertWebSocketClient({
  url: 'wss://api.sparc.io',
  token: authToken
});

await client.connect();
await client.subscribeToAlerts(['security', 'system'], ['high', 'critical']);

client.on('message', (event) => {
  if (event.event === 'alert:created') {
    // Type-safe alert handling
  }
});
```

### 3. Video Client

**Before:**
```typescript
const socket = io('wss://api.sparc.io/video');

socket.emit('stream:start', { cameraId });
```

**After:**
```typescript
import { VideoWebSocketClient } from '@sparc/shared/websocket';

const client = new VideoWebSocketClient({
  url: 'wss://api.sparc.io',
  token: authToken
});

await client.connect();
await client.startStream('camera-123', 'high');
```

## Service Integration Steps

### Step 1: Update Service Dependencies

```json
{
  "dependencies": {
    "@sparc/shared": "workspace:*"
  }
}
```

### Step 2: Initialize Unified WebSocket

```typescript
// In service initialization
import { UnifiedWebSocketService } from '@sparc/shared/websocket';

const websocketService = new UnifiedWebSocketService({
  port: 3100,
  jwtSecret: process.env.JWT_SECRET,
  redisUrl: process.env.REDIS_URL,
  corsOrigins: ['http://localhost:3000'],
  namespaces: [
    // Custom namespace configurations if needed
  ]
});

await websocketService.start();
```

### Step 3: Update Event Emitters

Replace direct WebSocket/Socket.IO emissions with unified service calls:

```typescript
// Before
this.io.to(`tenant:${tenantId}`).emit('alert:created', alert);

// After
await this.websocketService.broadcastToTenant(
  tenantId,
  'alerts',
  'alert:created',
  alert
);
```

### Step 4: Handle Service Events

```typescript
// Listen for WebSocket events that need service processing
this.websocketService.on('video:recording:start', async (data) => {
  const { cameraId, duration, tenantId } = data;
  
  // Validate and start recording
  const recording = await this.startRecording(cameraId, duration, tenantId);
  
  // Emit response
  await this.websocketService.broadcastToUser(
    data.userId,
    'video',
    'recording:started',
    recording
  );
});
```

## Environment Variables

Add to your service configuration:

```env
# WebSocket Configuration
WEBSOCKET_PORT=3100
WEBSOCKET_PING_INTERVAL=30000
WEBSOCKET_PING_TIMEOUT=5000
WEBSOCKET_MAX_PAYLOAD_SIZE=1048576
```

## Testing Migration

### 1. Unit Tests

```typescript
import { UnifiedWebSocketService } from '@sparc/shared/websocket';
import { createMockRedis } from '@sparc/shared/testing';

describe('WebSocket Integration', () => {
  let websocketService: UnifiedWebSocketService;

  beforeEach(() => {
    websocketService = new UnifiedWebSocketService({
      port: 0, // Random port for testing
      jwtSecret: 'test-secret',
      redisUrl: 'redis://localhost:6379'
    });
  });

  it('should broadcast to tenant', async () => {
    const spy = jest.spyOn(websocketService, 'broadcast');
    
    await websocketService.broadcastToTenant(
      'tenant-123',
      'alerts',
      'alert:created',
      { id: 'alert-1' }
    );

    expect(spy).toHaveBeenCalledWith(
      'alerts',
      'tenant:tenant-123',
      'alert:created',
      { id: 'alert-1' }
    );
  });
});
```

### 2. Integration Tests

```typescript
describe('WebSocket E2E', () => {
  it('should receive events after subscription', async () => {
    const client = new AlertWebSocketClient({
      url: 'ws://localhost:3100',
      token: validToken
    });

    await client.connect();
    await client.subscribe(['tenant:123']);

    const eventPromise = new Promise((resolve) => {
      client.on('message', resolve);
    });

    // Trigger event from service
    await service.createAlert(alertData);

    const event = await eventPromise;
    expect(event.event).toBe('alert:created');
  });
});
```

## Rollback Plan

If issues arise during migration:

1. **Feature Flag**: Use environment variable to toggle between old and new implementations
```typescript
const useUnifiedWebSocket = process.env.USE_UNIFIED_WEBSOCKET === 'true';

if (useUnifiedWebSocket) {
  // New implementation
} else {
  // Old implementation
}
```

2. **Gradual Rollout**: Migrate one namespace at a time
3. **Parallel Running**: Run both implementations temporarily with event forwarding

## Monitoring

Monitor the migration with these metrics:

```typescript
// Connection metrics
websocketService.on('client:connected', ({ client, namespace }) => {
  metrics.increment('websocket.connections', { namespace });
});

// Message metrics
websocketService.on('message:sent', ({ namespace, event }) => {
  metrics.increment('websocket.messages', { namespace, event });
});

// Error tracking
websocketService.on('error', (error) => {
  logger.error('WebSocket error', error);
  metrics.increment('websocket.errors');
});
```

## Common Issues and Solutions

### Issue 1: Authentication Failures
**Solution**: Ensure JWT token includes all required fields (userId, tenantId, roles)

### Issue 2: Missing Events
**Solution**: Check namespace and room subscriptions, verify event names match

### Issue 3: Performance Degradation
**Solution**: Adjust rate limits, implement event batching for high-frequency updates

### Issue 4: Connection Limits
**Solution**: Configure Redis cluster mode, increase system ulimits

## Timeline

1. **Week 1**: Set up unified WebSocket service
2. **Week 2**: Migrate monitoring namespace
3. **Week 3**: Migrate alerts namespace
4. **Week 4**: Migrate video namespace
5. **Week 5**: Remove old implementations
6. **Week 6**: Performance optimization and monitoring