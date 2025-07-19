# Alert Service

The Alert Service is a critical component of the SPARC platform that manages alerts, notifications, and escalations across the system. It provides real-time alert processing, multi-channel notifications, and automated escalation workflows.

## Features

- **Real-time Alert Management**: Create, update, acknowledge, and resolve alerts
- **Multi-channel Notifications**: Email, SMS, Push, and Webhook notifications
- **Automated Escalation**: Time-based escalation with configurable priorities
- **WebSocket Support**: Real-time alert streaming to connected clients
- **Webhook Processing**: Ingest alerts from external systems
- **Environmental Monitoring**: Process sensor data and generate threshold alerts
- **Tenant Isolation**: Complete data isolation between tenants
- **OpenTelemetry Integration**: Full observability and tracing support

## Architecture

The service follows the MicroserviceBase pattern with:
- Clean separation of routes, services, and data layers
- Drizzle ORM for type-safe database operations
- Redis for caching and real-time operations
- Socket.IO for WebSocket connections
- Comprehensive error handling and validation

## API Endpoints

### Alert Management
- `GET /api/alerts` - List alerts with filtering and pagination
- `GET /api/alerts/:id` - Get single alert
- `POST /api/alerts` - Create new alert
- `PUT /api/alerts/:id` - Update alert
- `DELETE /api/alerts/:id` - Delete alert
- `POST /api/alerts/:id/acknowledge` - Acknowledge alert
- `GET /api/alerts/stats` - Get alert statistics

### Webhook Processing
- `POST /api/webhooks/events` - Process generic webhook events
- `POST /api/webhooks/environmental` - Process environmental sensor data
- `POST /api/webhooks/security` - Process security system events

### Notification Management
- `GET /api/notifications/preferences` - Get notification preferences
- `PUT /api/notifications/preferences` - Update preferences
- `POST /api/notifications/preferences/email` - Add email addresses
- `POST /api/notifications/preferences/sms` - Add SMS numbers
- `POST /api/notifications/preferences/push/subscribe` - Register push subscription
- `POST /api/notifications/test` - Send test notification

### Health & Monitoring
- `GET /health` - Health check endpoint
- `GET /ready` - Readiness check endpoint
- `GET /metrics` - Prometheus metrics

## Environment Variables

```bash
# Database
DATABASE_URL=postgresql://user:password@localhost:5432/sparc

# Redis
REDIS_URL=redis://localhost:6379

# JWT
JWT_SECRET=your-jwt-secret

# Service Configuration
PORT=3008
NODE_ENV=development

# Email Notifications
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_FROM=alerts@sparc.io

# SMS Notifications (Twilio)
TWILIO_ACCOUNT_SID=your-account-sid
TWILIO_AUTH_TOKEN=your-auth-token
TWILIO_FROM_NUMBER=+1234567890

# Push Notifications
WEBPUSH_SUBJECT=mailto:alerts@sparc.io
WEBPUSH_PUBLIC_KEY=your-vapid-public-key
WEBPUSH_PRIVATE_KEY=your-vapid-private-key

# Webhook Security
WEBHOOK_API_KEY=your-webhook-api-key

# OpenTelemetry
ENABLE_TRACING=true
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318/v1/traces

# CORS
CORS_ORIGINS=http://localhost:3000,http://localhost:3003
```

## Development

### Setup
```bash
# Install dependencies
npm install

# Copy environment variables
cp .env.example .env

# Run database migrations
npm run db:generate
npm run db:push

# Start development server
npm run dev
```

### Testing
```bash
# Run unit tests
npm test

# Run with coverage
npm run test:coverage

# Run integration tests
npm run test:integration
```

### Linting
```bash
# Run ESLint
npm run lint

# Auto-fix issues
npm run lint:fix

# Type checking
npm run type-check
```

## Alert Types

The service supports various alert types:
- `access_denied` - Multiple failed access attempts
- `door_forced` - Forced door entry detected
- `door_held_open` - Door held open beyond threshold
- `system_offline` - System or service offline
- `camera_offline` - Camera disconnected
- `motion_detected` - Motion detection event
- `temperature_threshold` - Temperature outside range
- `humidity_threshold` - Humidity outside range
- `leak_detected` - Water leak detected
- `emergency_lockdown` - Emergency lockdown activated
- `security_breach` - Security breach detected
- `maintenance_required` - Maintenance needed

## Alert Priorities

Alerts have four priority levels with different escalation timeouts:
- `low` - 60 minute escalation timeout
- `medium` - 30 minute escalation timeout
- `high` - 15 minute escalation timeout
- `critical` - 5 minute escalation timeout

## WebSocket Events

The service emits the following WebSocket events:
- `alert:created` - New alert created
- `alert:updated` - Alert updated
- `alert:acknowledged` - Alert acknowledged
- `alert:escalated` - Alert escalated
- `alert:deleted` - Alert deleted

## Database Schema

The service uses the following main tables:
- `alerts` - Core alert data
- `alert_escalations` - Escalation history
- `alert_notifications` - Notification tracking
- `notification_preferences` - User/tenant notification settings

## Performance Considerations

- Alerts are cached in Redis for 1 hour
- Real-time statistics are maintained in Redis
- Database queries use proper indexing
- WebSocket connections are managed efficiently
- Notification sending is handled asynchronously

## Security

- All endpoints require JWT authentication (except webhooks)
- Webhook endpoints can use API key authentication
- Complete tenant isolation enforced
- Input validation on all endpoints
- SQL injection protection via parameterized queries

## Monitoring

The service exposes Prometheus metrics for:
- Total alerts created
- Alerts by status and priority
- Escalations performed
- Notifications sent by type
- Webhook events processed

## Deployment

The service is designed to run in Kubernetes with:
- Horizontal pod autoscaling
- Health and readiness probes
- Resource limits and requests
- Persistent volume for logs
- Service mesh integration