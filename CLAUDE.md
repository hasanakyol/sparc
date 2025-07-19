# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Quick Start

SPARC is a fully implemented production-ready security platform with video surveillance, incident management, and advanced analytics. The system handles 10,000+ concurrent users and 100,000+ video streams.

**Technology Stack:**
- Backend: Node.js/TypeScript, Hono framework
- Frontend: Next.js 14 (App Router), React, TypeScript, Tailwind CSS
- Database: PostgreSQL with Drizzle ORM
- Infrastructure: Kubernetes, Terraform (AWS/Azure/GCP)
- Monitoring: Prometheus, Grafana, OpenTelemetry

## Repository Structure

```
sparc/
├── packages/           # Shared packages
│   ├── database/      # Database schemas, migrations
│   ├── shared/        # Shared utilities, types
│   └── ui/           # UI component library
├── services/          # Microservices (24 services)
│   ├── api-gateway/   # Main API gateway
│   ├── auth/         # Authentication service
│   ├── video-processor/ # Video processing
│   └── ...           # Other services
├── web/              # Next.js frontend application
├── infra/            # Infrastructure as code
├── k8s/              # Kubernetes manifests
└── monitoring/       # Monitoring configuration
```

## Essential Commands

### Development Setup
```bash
# Automated setup (recommended)
npm run setup:dev

# Manual setup if needed
npm install
npm run db:generate
npm run db:push
npm run db:seed
```

### Common Tasks
```bash
# Development
npm run dev              # Start all services
npm run dev:web         # Frontend only
npm run dev:api         # Backend only

# Testing
npm test                # Run all tests
npm run test:unit       # Unit tests only
npm run test:e2e        # E2E tests
npm test -- path/to/test.spec.ts  # Single test

# Linting & Type Checking
npm run lint            # ESLint
npm run lint:fix        # Auto-fix
npm run typecheck       # TypeScript check

# Database
npm run db:generate     # Generate migrations
npm run db:push        # Apply migrations
npm run db:seed        # Seed data
npm run db:studio      # Drizzle Studio GUI

# Production Build
npm run build          # Build all
npm run build:docker   # Docker images

# Validation & Deployment
npm run validate        # Run comprehensive validation
npm run deploy:staging  # Deploy to staging
npm run deploy:production # Deploy to production
```

## Scripts Directory

The `scripts/` directory contains all operational scripts in a flat structure with category prefixes:

### Key Scripts
- **`setup.sh`** - Complete development environment setup
- **`deploy-unified.sh`** - All deployment, rollback, and validation operations
- **`validate-unified.sh`** - Comprehensive validation, health checks, and readiness verification
- **`security-scan-unified.sh`** - All security scanning and auditing
- **`test-device-integration.sh`** - Hardware device integration testing
- **`demo-setup.sh`** - Quick demo environment with sample data
- **`disaster-recovery.sh`** - Disaster recovery automation
- **`backup-scheduler.ts`** - Automated backup scheduling

### Common Script Usage
```bash
# Validate implementation
./scripts/validate-unified.sh production all

# Health check only
./scripts/deploy-unified.sh production --health-check-only

# Deploy with validation
./scripts/deploy-unified.sh production --version v1.2.3

# Test device integration
./scripts/test-device-integration.sh camera full

# Security scan
./scripts/security-scan-unified.sh
```

## Architecture Overview

### Multi-Tenant Hierarchy
```
Organization (e.g., "ACME Corp")
└── Site (e.g., "Chicago HQ")
    └── Zone (e.g., "Building A - Floor 2")
        └── Resources (Cameras, Sensors, etc.)
```

### Service Communication
- Services communicate via gRPC and REST
- API Gateway handles routing and authentication
- Event-driven architecture using message queues
- WebSocket connections for real-time updates

### Database Schema Pattern
Each service has isolated schemas:
```typescript
// packages/database/schemas/auth.ts
export const users = pgTable('users', {
  id: uuid('id').primaryKey(),
  organizationId: uuid('organization_id').references(() => organizations.id),
  // ... fields
});
```

## Key Development Patterns

### API Routes (Hono)
```typescript
// services/*/src/routes/*.ts
const app = new Hono()
  .use(authMiddleware)
  .get('/items', async (c) => {
    const tenantId = c.get('tenantId'); // Always available
    const items = await getItems(tenantId);
    return c.json(items);
  })
  .post('/items', zValidator('json', createItemSchema), async (c) => {
    const data = c.req.valid('json');
    const item = await createItem(data);
    return c.json(item, 201);
  });
```

### Frontend Components (Next.js App Router)
```typescript
// web/app/(dashboard)/[org]/[site]/page.tsx
export default async function SitePage({ params }: { params: { org: string; site: string } }) {
  const data = await fetchSiteData(params);
  return <SiteView data={data} />;
}
```

### Error Handling
```typescript
// Consistent error responses
throw new HTTPException(400, { message: 'Validation failed' });

// Frontend error boundaries
export function ErrorBoundary({ error }: { error: Error }) {
  return <ErrorDisplay error={error} />;
}
```

## Important Files

- `packages/database/schemas/*.ts` - Database schemas
- `packages/shared/types/*.ts` - Shared TypeScript types
- `services/*/src/routes/*.ts` - API endpoints
- `web/app/(dashboard)/*` - Main app pages
- `infra/terraform/environments/*/main.tf` - Infrastructure config
- `k8s/overlays/*/kustomization.yaml` - K8s environments

## Common Pitfalls

1. **Tenant Context**: Always validate tenant access in API routes
2. **Service Communication**: Use service discovery, not hardcoded URLs
3. **Database Transactions**: Use proper transaction isolation
4. **Real-time Updates**: Handle WebSocket reconnection
5. **Video Processing**: Check codec compatibility
6. **Offline Mode**: Implement proper queue and retry logic

## Testing Guidelines

### Unit Tests
```typescript
// *.test.ts files
describe('VideoProcessor', () => {
  it('should transcode video', async () => {
    const result = await processVideo(mockFile);
    expect(result.format).toBe('h264');
  });
});
```

### Integration Tests
```typescript
// *.integration.test.ts
it('should create incident via API', async () => {
  const response = await request(app)
    .post('/api/incidents')
    .send(validIncident);
  expect(response.status).toBe(201);
});
```

### E2E Tests
```typescript
// tests/e2e/*.spec.ts
test('user can view live video', async ({ page }) => {
  await page.goto('/org/site/cameras');
  await expect(page.locator('[data-testid="video-player"]')).toBeVisible();
});
```

## Performance Requirements

- API response time: < 200ms (p95)
- Video latency: < 500ms
- Dashboard load: < 2s
- Support 10,000+ concurrent users
- Handle 100,000+ video streams

## Quick Reference

### Environment Variables
```bash
DATABASE_URL=postgresql://...
REDIS_URL=redis://...
JWT_SECRET=...
S3_BUCKET=...
```

### Path Aliases
- `@/` → `src/`
- `@db` → `packages/database`
- `@shared` → `packages/shared`
- `@ui` → `packages/ui`

### Service Ports
- API Gateway: 3000
- Auth Service: 3001
- Video Service: 3002
- Web App: 3003

### Common Debugging
```bash
# Check service logs
kubectl logs -f deployment/api-gateway

# Database queries
npm run db:studio

# API testing
curl http://localhost:3000/health

# Frontend debugging
npm run dev:web -- --inspect
```

## When Adding Features

1. Check existing patterns in similar services
2. Update database schema if needed
3. Add TypeScript types to `packages/shared`
4. Implement API endpoint with validation
5. Add frontend components
6. Write tests (unit + integration)
7. Update documentation

## Code Review Focus

- Tenant isolation and security
- Proper error handling
- Performance implications
- Database query optimization
- Type safety
- Test coverage