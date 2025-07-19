# Event Processing Service (Unified)

## Overview

The Event Processing Service is a unified microservice that combines alert management and event processing functionality. It provides real-time event correlation, alert generation, and WebSocket-based notifications for the SPARC security platform.

This service consolidates the functionality of the former `alert-service` and `event-processing-service` into a single, more efficient service.

## Features

- **Unified Alert & Event Management**: Single service for both alerts and events
- **Real-time Event Processing**: Process access, video, environmental, system, and security events
- **Event Correlation**: Automatic correlation of related events to generate alerts
- **WebSocket Support**: Real-time notifications via Socket.IO with Redis adapter
- **Multi-tenant**: Complete tenant isolation for all operations
- **Scalable**: Horizontal scaling support with Redis pub/sub
- **Extensible**: Custom correlation rules and event types

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   API Gateway   │────▶│  Event Process  │────▶│   PostgreSQL    │
└─────────────────┘     │     Service     │     └─────────────────┘
                        └─────────────────┘              │
                               │    │                    │
                               │    └───────────────────┬┘
                               │                        │
                        ┌──────▼────────┐      ┌───────▼────────┐
                        │  Redis Pub/Sub │      │ Redis Cache    │
                        └───────────────┘       └────────────────┘
                               │
                        ┌──────▼────────┐
                        │  WebSocket     │
                        │  Clients       │
                        └───────────────┘
```

## API Endpoints

### Alert Management

- `GET /api/alerts` - List alerts with filtering
- `GET /api/alerts/stats` - Get alert statistics  
- `GET /api/alerts/:id` - Get single alert
- `POST /api/alerts` - Create new alert
- `PUT /api/alerts/:id` - Update alert
- `POST /api/alerts/:id/acknowledge` - Acknowledge alert
- `DELETE /api/alerts/:id` - Delete alert

### Event Processing

- `POST /api/events/access` - Submit access event
- `POST /api/events/video` - Submit video event
- `POST /api/events/environmental` - Submit environmental event
- `POST /api/events/system` - Submit system event
- `POST /api/events/security` - Submit security event
- `GET /api/events` - Get events with filtering
- `GET /api/events/:id` - Get single event
- `GET /api/events/stats/summary` - Event statistics
- `GET /api/events/stats/trends` - Event trends
- `POST /api/events/bulk` - Bulk event submission

### Processing Control

- `POST /api/processing/start` - Start event processing
- `POST /api/processing/stop` - Stop event processing
- `GET /api/processing/status` - Get processing status

## WebSocket Events

### Connection
```javascript
const socket = io('http://localhost:3010', {
  auth: {
    token: 'your-jwt-token',
    tenantId: 'tenant-123'
  }
});
```

### Subscribe to Locations
```javascript
// Subscribe to building events
socket.emit('subscribe:building', 'building-123');

// Subscribe to floor events
socket.emit('subscribe:floor', { 
  buildingId: 'building-123', 
  floorId: 'floor-1' 
});
```

### Event Types
- `event:access` - Access control events
- `event:video` - Video analytics events
- `event:environmental` - Environmental sensor events
- `event:system` - System events
- `event:security` - Security events
- `alert:created` - New alert created
- `alert:updated` - Alert updated
- `alert:acknowledged` - Alert acknowledged
- `alert:resolved` - Alert resolved

## Environment Variables

```bash
# Service Configuration
PORT=3010
NODE_ENV=production

# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/sparc

# Redis
REDIS_URL=redis://localhost:6379

# WebSocket
ALLOWED_ORIGINS=http://localhost:3000,https://app.sparc.com

# Logging
LOG_LEVEL=info
```

## Event Correlation Rules

The service includes built-in correlation rules:

1. **Multiple Failed Access**: 3+ access denied events in 5 minutes
2. **Door Forced with Motion**: Door forced + motion detected within 1 minute
3. **Environmental Cascade**: Multiple environmental thresholds exceeded
4. **Multiple Cameras Offline**: 3+ cameras offline within 5 minutes

### Custom Rules

Create custom rules in the database:

```sql
INSERT INTO event_processing_rules (
  tenant_id,
  name,
  rule_type,
  event_types,
  conditions,
  actions,
  time_window,
  priority
) VALUES (
  'tenant-123',
  'Custom Security Rule',
  'correlation',
  '["access", "video"]',
  '{"minCount": 2, "locationMatch": true}',
  '{"alertType": "security", "severity": "high"}',
  '5m',
  'high'
);
```

## Development

### Setup
```bash
# Install dependencies
npm install

# Run database migrations
npm run db:migrate

# Start in development
npm run dev
```

### Testing
```bash
# Run unit tests
npm test

# Run integration tests
npm run test:integration

# Run with coverage
npm run test:coverage
```

### Building
```bash
# Build for production
npm run build

# Build Docker image
docker build -t sparc/event-processing-service .
```

## Deployment

### Docker
```bash
docker run -d \
  --name event-processing-service \
  -p 3010:3010 \
  -e DATABASE_URL=postgresql://... \
  -e REDIS_URL=redis://... \
  sparc/event-processing-service
```

### Kubernetes
```bash
kubectl apply -f k8s/event-processing-service.yaml
```

### PM2
```bash
pm2 start dist/index.js --name event-processing-service
```

## Monitoring

### Health Check
```bash
curl http://localhost:3010/health
```

### Metrics
The service exports Prometheus metrics at `/metrics`:
- `events_processed_total` - Total events processed
- `alerts_generated_total` - Total alerts generated
- `websocket_connections` - Active WebSocket connections
- `event_processing_duration` - Event processing time

### Logging
Structured JSON logs with correlation IDs:
```json
{
  "timestamp": "2025-01-19T10:30:00.000Z",
  "level": "info",
  "service": "event-processing-service",
  "message": "Event processed",
  "eventId": "evt-123",
  "eventType": "access",
  "tenantId": "tenant-123",
  "duration": 25
}
```

## Migration from Alert Service

If migrating from the old alert-service:

1. Run migration script: `./scripts/migrate-to-unified-event-service.sh`
2. Update environment variables (port 3006 → 3010)
3. Update API Gateway routing
4. Test all alert functionality
5. Remove old alert-service

## Troubleshooting

### Common Issues

1. **WebSocket Connection Failed**
   - Check CORS configuration
   - Verify Redis is running
   - Check authentication token

2. **Events Not Processing**
   - Verify Redis pub/sub is working
   - Check event processing status
   - Review correlation rules

3. **High Memory Usage**
   - Adjust event buffer size
   - Configure event TTL
   - Enable event archival

### Debug Mode
```bash
LOG_LEVEL=debug npm run dev
```

## License

Copyright (c) 2024 SPARC Security Platform