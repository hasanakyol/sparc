# ADR-003: Multi-Tenancy Strategy

## Status
Accepted

## Context
SPARC needs to support multiple organizations with complete data isolation, customizable features, and the ability to scale independently. We need a multi-tenancy approach that balances isolation, performance, and operational complexity.

## Decision
We will implement a hybrid multi-tenancy model:

### Data Layer
- **Shared Database with Row-Level Security (RLS)**
- Each table includes `organization_id` or `tenant_id`
- PostgreSQL RLS policies enforce isolation
- Separate schemas for extremely sensitive data

### Application Layer
- **Tenant context in every request**
- Middleware validates and injects tenant context
- All queries automatically scoped to tenant
- Tenant-specific configuration and features

### Infrastructure Layer
- **Shared Kubernetes cluster**
- Namespace isolation for large enterprise customers
- Resource quotas per tenant
- Option for dedicated clusters (enterprise)

## Implementation Details

```typescript
// Tenant context middleware
app.use(async (c, next) => {
  const tenantId = await resolveTenant(c.req);
  c.set('tenantId', tenantId);
  await next();
});

// Automatic tenant scoping
const getResources = async (tenantId: string) => {
  return db.select()
    .from(resources)
    .where(eq(resources.tenantId, tenantId));
};
```

## Consequences

### Positive
- Cost-effective for most tenants
- Easy maintenance and updates
- Good performance with proper indexing
- Flexible isolation options

### Negative
- Shared database risks
- Complex RLS policies
- Careful query optimization needed
- Backup/restore complexity

## Security Measures
1. Mandatory tenant context validation
2. RLS policies on all tables
3. Regular tenant isolation testing
4. Audit logging for all cross-tenant queries
5. Encrypted tenant data at rest