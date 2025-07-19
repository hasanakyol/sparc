# Unified WebSocket Service

A consolidated WebSocket service for the SPARC security platform that unifies video streaming, alert notifications, and real-time monitoring into a single, scalable WebSocket infrastructure.

## Features

- **Single WebSocket Server**: Consolidates multiple WebSocket implementations into one unified service
- **Namespace Isolation**: Separate namespaces for different concerns (video, alerts, monitoring)
- **Horizontal Scaling**: Redis adapter for multi-instance deployments
- **Tenant Isolation**: Built-in multi-tenant support with room-based broadcasting
- **Authentication & Authorization**: JWT-based auth with role validation
- **Rate Limiting**: Configurable rate limits per namespace
- **Auto-reconnection**: Client-side reconnection with exponential backoff
- **Type Safety**: Full TypeScript support with event type definitions
- **Monitoring**: Built-in metrics and health checks

## Installation

The unified WebSocket service is part of the `@sparc/shared` package:

```bash
npm install @sparc/shared
```

## Server Setup

### Basic Usage

```typescript
import { UnifiedWebSocketService } from '@sparc/shared/websocket';

const websocketService = new UnifiedWebSocketService({
  port: 3100,
  jwtSecret: process.env.JWT_SECRET,
  redisUrl: process.env.REDIS_URL,
  corsOrigins: ['http://localhost:3000'],
});

await websocketService.start();
```

### Custom Namespace Configuration

```typescript
const websocketService = new UnifiedWebSocketService({
  port: 3100,
  jwtSecret: process.env.JWT_SECRET,
  redisUrl: process.env.REDIS_URL,
  namespaces: [
    {
      name: 'custom',
      roomStrategy: 'tenant',
      rateLimitOptions: { points: 100, duration: 60 },
      eventHandlers: {
        'custom:action': async (socket, data) => {
          // Handle custom action
        },
      },
    },
  ],
});
```

### Broadcasting Events

```typescript
// Broadcast to all clients in a tenant
await websocketService.broadcastToTenant(
  'tenant-123',
  'alerts',
  'alert:created',
  { id: 'alert-1', message: 'Security breach detected' }
);

// Broadcast to organization
await websocketService.broadcastToOrganization(
  'org-456',
  'monitoring',
  'metrics:update',
  { cpu: 45, memory: 78 }
);

// Broadcast to specific user
await websocketService.broadcastToUser(
  'user-789',
  'video',
  'stream:ready',
  { cameraId: 'cam-1', url: 'rtsp://...' }
);
```

## Client Usage

### Basic Connection

```typescript
import { WebSocketClient } from '@sparc/shared/websocket';

const client = new WebSocketClient({
  url: 'wss://api.sparc.io',
  namespace: 'alerts',
  token: authToken,
  autoReconnect: true,
});

await client.connect();

// Subscribe to channels
await client.subscribe(['tenant:123', 'alerts:high']);

// Listen for events
client.on('message', (event) => {
  console.log('Received:', event.event, event.data);
});

// Send events
client.send('custom:action', { action: 'refresh' });
```

### Specialized Clients

```typescript
import { VideoWebSocketClient, AlertWebSocketClient } from '@sparc/shared/websocket';

// Video client
const videoClient = new VideoWebSocketClient({
  url: 'wss://api.sparc.io',
  token: authToken,
});

await videoClient.connect();
await videoClient.startStream('camera-123', 'high');

// Alert client
const alertClient = new AlertWebSocketClient({
  url: 'wss://api.sparc.io',
  token: authToken,
});

await alertClient.connect();
await alertClient.subscribeToAlerts(['security'], ['high', 'critical']);
```

## Event Types

The service provides comprehensive type definitions for all events:

```typescript
import { VideoEvents, AlertEvents, MonitoringEvents } from '@sparc/shared/websocket';

// Type-safe event handling
client.on('message', (event) => {
  if (event.event === 'video:stream:started') {
    const data = event.data as VideoEvents.StreamStarted;
    console.log('Stream started:', data.cameraId, data.streamUrl);
  }
});
```

## Namespaces

### Video Namespace (`/video`)

Handles video streaming, recording, and analytics:

- `stream:start` / `stream:stop` - Video stream control
- `recording:start` / `recording:stop` - Recording control
- `motion:detected` - Motion detection events
- `analytics` - Video analytics data

### Alerts Namespace (`/alerts`)

Manages security alerts and notifications:

- `alert:created` - New alert created
- `alert:updated` - Alert status changed
- `alert:acknowledged` - Alert acknowledged by user
- `alert:resolved` - Alert resolved

### Monitoring Namespace (`/monitoring`)

Real-time system monitoring and metrics:

- `metrics:update` - System metrics updates
- `service:status` - Service health status
- `threshold:breached` - Metric threshold alerts
- `security:event` - Security-related events

## Authentication

All connections require a valid JWT token containing:

```typescript
{
  userId: string;
  tenantId: string;
  organizationId?: string;
  roles: string[];
}
```

## Room Management

The service automatically manages rooms based on the namespace strategy:

- **Tenant Strategy**: Clients join `tenant:{tenantId}` rooms
- **Organization Strategy**: Clients join `org:{organizationId}` rooms
- **Custom Strategy**: Manual room management

## Rate Limiting

Each namespace can have its own rate limits:

```typescript
{
  points: 100,  // Number of requests
  duration: 60  // Per 60 seconds
}
```

## Monitoring & Metrics

```typescript
// Get service metrics
const metrics = await websocketService.getMetrics();
// {
//   totalClients: 150,
//   namespaces: {
//     video: { connectedClients: 50 },
//     alerts: { connectedClients: 75 },
//     monitoring: { connectedClients: 25 }
//   }
// }

// Listen to connection events
websocketService.on('client:connected', ({ client, namespace }) => {
  console.log('Client connected:', client.id, namespace);
});
```

## Error Handling

The service provides comprehensive error handling:

```typescript
client.on('error', (error) => {
  console.error('WebSocket error:', error);
});

// Server-side error events
websocketService.on('error', (error) => {
  logger.error('WebSocket service error:', error);
});
```

## Testing

```typescript
import { UnifiedWebSocketService } from '@sparc/shared/websocket';
import { createMockRedis } from '@sparc/shared/testing';

describe('WebSocket Integration', () => {
  let service: UnifiedWebSocketService;

  beforeEach(() => {
    service = new UnifiedWebSocketService({
      port: 0, // Random port
      jwtSecret: 'test-secret',
      redisUrl: 'redis://localhost:6379',
    });
  });

  it('should broadcast events', async () => {
    await service.broadcastToTenant('tenant-1', 'alerts', 'test', { data: 'test' });
    // Assert Redis publish was called
  });
});
```

## Migration Guide

See [migration-guide.md](./migration-guide.md) for detailed instructions on migrating from separate WebSocket implementations.

## Performance Considerations

- **Connection Limits**: Configure based on system resources
- **Message Size**: Default 1MB limit, configurable
- **Heartbeat**: 30-second interval by default
- **Redis**: Use Redis Cluster for high-traffic deployments

## Security

- JWT tokens expire and must be refreshed
- Tenant isolation enforced at connection and room level
- Rate limiting prevents abuse
- Input validation on all events
- CORS configuration for browser clients

## Troubleshooting

### Connection Issues

1. Verify JWT token is valid and not expired
2. Check CORS configuration matches client origin
3. Ensure Redis is running and accessible
4. Verify firewall allows WebSocket connections

### Performance Issues

1. Monitor Redis memory usage
2. Check rate limit configurations
3. Verify connection pool settings
4. Monitor event handler performance

### Debugging

Enable debug logging:

```bash
DEBUG=socket.io:* node your-service.js
```

## License

Part of the SPARC Security Platform