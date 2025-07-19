# Tenant Service

The Tenant Service is a critical microservice in the SPARC platform that manages multi-tenant functionality, including tenant management, organization hierarchies, and resource quotas.

## Features

- **Multi-tenant Management**: Create, read, update, and delete tenants
- **Hierarchical Organization Structure**: Manage organizations, sites, buildings, floors, and zones
- **Resource Quota Management**: Track and enforce resource limits per tenant
- **Tenant Isolation**: Ensure proper data isolation between tenants
- **Caching**: Redis-based caching for improved performance
- **Health Monitoring**: Built-in health checks and metrics
- **OpenTelemetry Integration**: Distributed tracing support

## Architecture

The service follows the MicroserviceBase pattern and includes:

- RESTful API endpoints using Hono framework
- PostgreSQL database with Drizzle ORM
- Redis for caching and metrics
- Comprehensive validation using Zod schemas
- Proper error handling and HTTP status codes

## API Endpoints

### Tenant Management
- `GET /api/tenants` - List all tenants (Super Admin only)
- `GET /api/tenants/:id` - Get tenant by ID
- `POST /api/tenants` - Create new tenant
- `PUT /api/tenants/:id` - Update tenant
- `DELETE /api/tenants/:id` - Delete tenant
- `GET /api/tenants/:id/usage` - Get tenant resource usage

### Organization Management
- `GET /api/organizations` - List organizations
- `GET /api/organizations/:id` - Get organization by ID
- `POST /api/organizations` - Create new organization
- `PUT /api/organizations/:id` - Update organization
- `DELETE /api/organizations/:id` - Delete organization

### Site Management
- `GET /api/sites` - List sites
- `GET /api/sites/:id` - Get site by ID
- `POST /api/sites` - Create new site
- `PUT /api/sites/:id` - Update site
- `DELETE /api/sites/:id` - Delete site

### Building Management
- `GET /api/buildings` - List buildings
- `GET /api/buildings/:id` - Get building by ID
- `POST /api/buildings` - Create new building
- `PUT /api/buildings/:id` - Update building
- `DELETE /api/buildings/:id` - Delete building

### Floor Management
- `GET /api/floors` - List floors
- `GET /api/floors/:id` - Get floor by ID
- `POST /api/floors` - Create new floor
- `PUT /api/floors/:id` - Update floor
- `DELETE /api/floors/:id` - Delete floor

### Zone Management
- `GET /api/zones` - List zones
- `GET /api/zones/:id` - Get zone by ID
- `POST /api/zones` - Create new zone
- `PUT /api/zones/:id` - Update zone
- `DELETE /api/zones/:id` - Delete zone

### Configuration Management
- `GET /api/config/:tenantId` - Get tenant configuration
- `PUT /api/config/:tenantId` - Update tenant configuration
- `GET /api/config/:tenantId/usage` - Get tenant resource usage

## Database Schema

The service manages the following entities:

- **Tenants**: Root level multi-tenant entities
- **Organizations**: Companies or entities within a tenant
- **Sites**: Physical locations
- **Buildings**: Buildings within a site
- **Floors**: Floors within a building
- **Zones**: Areas within a floor
- **TenantResourceUsage**: Resource usage tracking

## Development

### Prerequisites
- Node.js 18+
- PostgreSQL
- Redis

### Setup
```bash
npm install
npm run db:generate
npm run db:push
```

### Running
```bash
# Development
npm run dev

# Production
npm run build
npm start
```

### Testing
```bash
# Run all tests
npm test

# Run with coverage
npm run test:coverage
```

## Environment Variables

```env
DATABASE_URL=postgresql://user:password@localhost:5432/sparc
REDIS_URL=redis://localhost:6379
JWT_SECRET=your-jwt-secret
PORT=3002
NODE_ENV=development
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
```

## Security

- All endpoints require authentication (except health checks)
- Role-based access control (RBAC)
- Super Admin: Full access to all tenants
- Tenant Admin: Access to their tenant only
- Organization Admin: Access to their organization and below

## Monitoring

The service exposes the following endpoints for monitoring:

- `/health` - Health check endpoint
- `/ready` - Readiness check endpoint
- `/metrics` - Prometheus-compatible metrics

## Caching Strategy

- Tenant data: 5-minute TTL
- Organization data: 5-minute TTL
- Stats: 1-minute TTL
- Cache invalidation on updates

## Error Handling

The service uses standard HTTP status codes:
- 200: Success
- 201: Created
- 400: Bad Request (validation errors)
- 401: Unauthorized
- 403: Forbidden
- 404: Not Found
- 409: Conflict
- 500: Internal Server Error

## Dependencies

Key dependencies:
- `@sparc/shared`: Shared utilities and patterns
- `@sparc/database`: Database schemas and connections
- `hono`: Web framework
- `drizzle-orm`: ORM
- `ioredis`: Redis client
- `zod`: Schema validation
- `@opentelemetry/*`: Observability