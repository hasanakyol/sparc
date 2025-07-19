# Maintenance Service

The Maintenance Service is a comprehensive microservice for managing equipment maintenance, work orders, and preventive maintenance schedules in the SPARC platform.

## Features

### Core Functionality
- **Work Order Management**: Create, track, and manage maintenance work orders
- **Preventive Maintenance**: Schedule and automate recurring maintenance tasks
- **Parts Inventory**: Track spare parts inventory and usage
- **Device Diagnostics**: Run and store diagnostic results for equipment
- **Maintenance History**: Complete audit trail of all maintenance activities

### Advanced Features
- **Predictive Maintenance**: AI-driven failure prediction and automated alerts
- **SLA Management**: Track and enforce service level agreements
- **IoT Integration**: Ingest and analyze device metrics for anomaly detection
- **Cost Tracking**: Monitor maintenance costs and budget analysis
- **Real-time Updates**: WebSocket support for live status updates

## Architecture

The service is built using the MicroserviceBase pattern and includes:

- **API Routes**: RESTful endpoints for all maintenance operations
- **Background Services**: 
  - Preventive Maintenance Scheduler
  - SLA Monitoring Service
  - Predictive Maintenance Service
- **Real-time Communication**: Socket.IO for live updates
- **Event-Driven**: Redis pub/sub for inter-service communication

## API Endpoints

### Work Orders
- `GET /work-orders` - List work orders with filtering
- `POST /work-orders` - Create new work order
- `GET /work-orders/:id` - Get work order details
- `PUT /work-orders/:id` - Update work order
- `DELETE /work-orders/:id` - Delete work order
- `POST /work-orders/:id/complete` - Complete work order
- `POST /work-orders/:id/assign` - Assign technician

### Preventive Maintenance
- `GET /preventive-maintenance/schedules` - List schedules
- `POST /preventive-maintenance/schedules` - Create schedule
- `PUT /preventive-maintenance/schedules/:id` - Update schedule
- `POST /preventive-maintenance/schedules/:id/generate` - Generate work orders
- `GET /preventive-maintenance/statistics` - Get PM statistics

### Inventory
- `GET /inventory/parts` - List parts
- `POST /inventory/parts` - Add new part
- `GET /inventory/parts/low-stock` - Get low stock alerts
- `POST /inventory/parts/:id/usage` - Record part usage
- `GET /inventory/parts/:id/history` - Get usage history

### Diagnostics
- `POST /diagnostics/run` - Run device diagnostics
- `GET /diagnostics/history/:deviceId` - Get diagnostic history
- `POST /diagnostics/analyze` - Analyze diagnostic trends

### Analytics
- `GET /analytics/overview` - Maintenance overview
- `GET /analytics/trends` - Trend analysis
- `GET /analytics/costs` - Cost analysis
- `GET /analytics/device-performance` - Device performance metrics
- `GET /analytics/predictive-insights` - Predictive maintenance insights

### SLA Management
- `GET /sla/config` - List SLA configurations
- `POST /sla/config` - Create SLA config
- `GET /sla/violations` - Get SLA violations
- `GET /sla/performance` - SLA performance metrics

### IoT Integration
- `POST /iot/metrics` - Ingest device metrics
- `GET /iot/devices/:deviceId/metrics` - Get device metrics
- `GET /iot/devices/:deviceId/health` - Get device health score
- `GET /iot/anomalies` - Get detected anomalies

## Configuration

### Environment Variables

```bash
# Service Configuration
SERVICE_NAME=maintenance-service
SERVICE_PORT=3010

# Database
DATABASE_URL=postgresql://user:password@localhost:5432/sparc

# Redis
REDIS_URL=redis://localhost:6379

# JWT Configuration
JWT_SECRET=your-secret-key

# Socket.IO
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:3001

# Notification Channels (Optional)
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=notifications@example.com
SMTP_PASS=password

SMS_API_KEY=your-sms-api-key
SMS_API_URL=https://api.sms-provider.com

PUSH_SERVICE_URL=https://push.example.com
PUSH_API_KEY=your-push-api-key

# OpenTelemetry
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
OTEL_SERVICE_NAME=maintenance-service
```

## Database Schema

The service uses the following main tables:
- `work_orders` - Work order records
- `preventive_maintenance_schedules` - PM schedule configurations
- `parts_inventory` - Spare parts inventory
- `maintenance_history` - Activity history
- `device_diagnostics` - Diagnostic results
- `maintenance_costs` - Cost tracking
- `maintenance_sla_config` - SLA configurations
- `iot_device_metrics` - IoT metrics data

## Background Services

### Preventive Maintenance Service
- Runs on configurable cron schedules
- Automatically generates work orders based on schedules
- Supports device-specific and type-based maintenance

### SLA Monitoring Service
- Monitors work orders for SLA compliance
- Sends alerts for approaching violations
- Escalates critical violations

### Predictive Maintenance Service
- Analyzes device health based on:
  - Failure history
  - IoT sensor anomalies
  - Diagnostic results
- Calculates health scores and risk levels
- Automatically creates work orders for high-risk devices

## Real-time Events

The service publishes the following events via Redis pub/sub:
- `maintenance:work-order:created`
- `maintenance:work-order:updated`
- `maintenance:work-order:completed`
- `maintenance:inventory:low-stock`
- `maintenance:sla:violation`
- `maintenance:predictive:alert`

Socket.IO events:
- `work-order:created`
- `work-order:updated`
- `work-order:completed`
- `inventory:low-stock`
- `sla:violation`
- `predictive:alert`

## Development

### Running Locally

```bash
# Install dependencies
npm install

# Run migrations
npm run db:migrate

# Start development server
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
# Build TypeScript
npm run build

# Build Docker image
docker build -t sparc/maintenance-service .
```

## Integration

The service integrates with:
- **Auth Service**: User authentication and authorization
- **Device Service**: Device information and status
- **Notification Service**: Alert and notification delivery
- **Analytics Service**: Data aggregation and reporting
- **API Gateway**: Request routing and rate limiting

## Monitoring

The service provides:
- Health check endpoint: `/health`
- Metrics endpoint: `/metrics`
- OpenTelemetry instrumentation
- Structured logging with correlation IDs

## Performance

- Supports 10,000+ concurrent work orders
- Real-time updates via WebSocket
- Efficient batch processing for PM generation
- Caching for frequently accessed data
- Optimized database queries with proper indexing

## Security

- JWT-based authentication
- Tenant isolation
- Input validation with Zod schemas
- SQL injection prevention
- Rate limiting per tenant
- Audit logging for all operations