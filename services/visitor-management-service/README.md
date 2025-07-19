# Visitor Management Service

The Visitor Management Service is a comprehensive solution for managing visitor access in the SPARC security platform. It provides features for visitor pre-registration, check-in/out processes, badge printing, watchlist management, and temporary credential issuance.

## Features

### Core Functionality
- **Visitor Pre-Registration**: Allow hosts to pre-register visitors with QR code invitations
- **Check-In/Out Process**: Streamlined visitor check-in with photo capture and ID verification
- **Walk-In Support**: Handle unregistered visitors with on-the-spot registration
- **Group Management**: Manage visitor groups for events or team visits
- **Badge Printing**: Generate and print visitor badges with customizable templates
- **Watchlist Integration**: Security screening against organization watchlists
- **Credential Management**: Issue and validate temporary access credentials
- **Real-Time Tracking**: Monitor active visitors and overstays
- **Emergency Evacuation**: Quick access to all on-site visitors
- **Analytics & Reporting**: Comprehensive visitor statistics and trends

### Technical Features
- Multi-tenant architecture with strict data isolation
- Real-time WebSocket updates for visitor events
- OpenTelemetry instrumentation for observability
- Prometheus metrics for monitoring
- High-performance caching with Redis
- Comprehensive audit logging
- RESTful API with OpenAPI documentation

## Architecture

The service follows the MicroserviceBase pattern and integrates with:
- PostgreSQL for persistent storage
- Redis for caching and session management
- Socket.IO for real-time updates
- Email/SMS providers for notifications
- Badge printing services

## API Endpoints

### Visitors
- `POST /api/visitors/pre-register` - Pre-register a visitor
- `POST /api/visitors/check-in` - Check in a visitor
- `POST /api/visitors/:id/check-out` - Check out a visitor
- `GET /api/visitors` - Search and list visitors
- `GET /api/visitors/:id` - Get visitor details
- `PUT /api/visitors/:id` - Update visitor information
- `POST /api/visitors/:id/approval` - Approve or deny visitor
- `GET /api/visitors/active/all` - Get all active visitors
- `GET /api/visitors/overstay/all` - Get overstaying visitors
- `GET /api/visitors/analytics/summary` - Get visitor analytics
- `GET /api/visitors/emergency/evacuation` - Emergency evacuation list

### Badges
- `POST /api/badges/print` - Generate and print badge
- `GET /api/badges/print/:visitorId/pdf` - Get badge PDF
- `POST /api/badges/:visitorId/reprint` - Reprint visitor badge
- `POST /api/badges/preview` - Preview badge without saving
- `GET /api/badges/templates` - Get available badge templates
- `POST /api/badges/batch-print` - Batch print multiple badges

### Watchlist
- `POST /api/watchlist/check` - Check if visitor is on watchlist
- `POST /api/watchlist` - Add entry to watchlist
- `PUT /api/watchlist/:id` - Update watchlist entry
- `DELETE /api/watchlist/:id` - Remove from watchlist
- `GET /api/watchlist` - Search watchlist entries
- `GET /api/watchlist/stats` - Get watchlist statistics
- `POST /api/watchlist/bulk-check` - Bulk check multiple visitors
- `POST /api/watchlist/import` - Import watchlist entries
- `GET /api/watchlist/export` - Export watchlist data

### Credentials
- `POST /api/credentials/validate` - Validate visitor credential
- `GET /api/credentials/visitor/:visitorId` - Get visitor credentials
- `POST /api/credentials/:id/revoke` - Revoke credential
- `GET /api/credentials/access-logs` - Get access logs
- `POST /api/credentials/mobile` - Issue mobile credential
- `GET /api/credentials/stats` - Get credential statistics

### Groups
- `POST /api/groups` - Create visitor group
- `GET /api/groups/:id` - Get group details
- `GET /api/groups` - List visitor groups
- `POST /api/groups/:id/check-in` - Check in entire group
- `POST /api/groups/:id/check-out` - Check out entire group
- `POST /api/groups/:id/members` - Add member to group
- `DELETE /api/groups/:groupId/members/:visitorId` - Remove member

## Development

### Prerequisites
- Node.js 18+
- PostgreSQL 14+
- Redis 6+
- Docker (optional)

### Setup
```bash
# Install dependencies
npm install

# Run database migrations
npm run db:migrate

# Start development server
npm run dev
```

### Testing
```bash
# Run all tests
npm test

# Run unit tests
npm run test:unit

# Run integration tests
npm run test:integration

# Run with coverage
npm run test:coverage
```

### Environment Variables
```env
NODE_ENV=development
PORT=3006

# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/sparc_visitors

# Redis
REDIS_URL=redis://localhost:6379

# JWT
JWT_SECRET=your-secret-key

# Email (Optional)
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=user@example.com
SMTP_PASS=password
SMTP_FROM=noreply@example.com

# SMS (Optional)
TWILIO_ACCOUNT_SID=your-account-sid
TWILIO_AUTH_TOKEN=your-auth-token
TWILIO_FROM=+1234567890

# OpenTelemetry (Optional)
ENABLE_TRACING=true
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318/v1/traces
```

## Security Considerations

1. **Multi-Tenant Isolation**: All queries are scoped by organization ID
2. **Authentication**: JWT-based authentication required for all endpoints
3. **Authorization**: Role-based access control for sensitive operations
4. **Watchlist Screening**: Automatic security checks during registration
5. **Audit Logging**: All visitor activities are logged for compliance
6. **Data Privacy**: Visitor data is encrypted and access is controlled
7. **Credential Security**: Temporary credentials with automatic expiration

## Monitoring

The service exposes Prometheus metrics at `/metrics`:
- `visitors_total` - Total visitors registered
- `visitors_active` - Currently on-site visitors
- `visitors_checked_in_total` - Total check-ins
- `visitors_checked_out_total` - Total check-outs
- `visitor_overstays` - Current overstaying visitors
- `badges_printed_total` - Total badges printed
- `watchlist_checks_total` - Watchlist checks performed
- `watchlist_matches_total` - Watchlist matches found
- `credential_validations_total` - Credential validations
- `credential_validation_failures_total` - Failed validations

## WebSocket Events

Connect to WebSocket on port `{SERVICE_PORT} + 1` for real-time updates:

### Events
- `visitor:created` - New visitor registered
- `visitor:updated` - Visitor information updated
- `visitor:checked-in` - Visitor checked in
- `visitor:checked-out` - Visitor checked out
- `visitor:approved` - Visitor approved
- `visitor:denied` - Visitor denied access

### Room Management
- `join-organization` - Join organization-specific room
- `leave-organization` - Leave organization room

## License

UNLICENSED - Private SPARC Security Platform