# Row Level Security (RLS) Implementation

## Overview

SPARC implements PostgreSQL Row Level Security (RLS) to enforce tenant isolation at the database level. This ensures that even if application-level security is bypassed, data remains isolated between tenants.

## Key Features

1. **Database-Level Isolation**: All queries automatically filter by tenant
2. **Super Admin Support**: Special role for cross-tenant operations
3. **Automatic Context Injection**: Middleware automatically sets tenant context
4. **Performance Optimized**: Indexes on all tenant_id columns
5. **Comprehensive Coverage**: RLS policies on all 33 tables

## Architecture

### Database Functions

```sql
-- Get current tenant from session
current_tenant_id() RETURNS TEXT

-- Check if user is super admin
is_super_admin() RETURNS BOOLEAN
```

### Policy Pattern

Each table has four policies:
- **SELECT**: View only tenant's data
- **INSERT**: Create only in tenant's context
- **UPDATE**: Modify only tenant's data
- **DELETE**: Remove only tenant's data

## Implementation

### 1. Enable RLS Migration

```bash
# Apply RLS to database
npm run db:apply-rls

# Or manually
cd packages/database
npx ts-node scripts/apply-rls.ts
```

### 2. Application Integration

#### Express Middleware

```typescript
import { tenantContextMiddleware } from '@sparc/shared/utils/rls-context';

// Add after authentication
app.use(tenantContextMiddleware);
```

#### Service Implementation

```typescript
import { getTenantAwarePrismaClient } from '@sparc/shared/database/prisma';
import { withTenantContext } from '@sparc/shared/utils/rls-context';

// Option 1: Use tenant-aware client
const prisma = getTenantAwarePrismaClient();

// Option 2: Wrap operations
await withTenantContext(prisma, tenantId, false, async () => {
  // Database operations here
});
```

#### Background Jobs

```typescript
// For system operations
await runMigrationWithSuperAdmin(prisma, async () => {
  // Cross-tenant operations
});

// For tenant-specific jobs
await withTenantContext(prisma, job.tenantId, false, async () => {
  // Tenant-scoped operations
});
```

## Security Model

### Tenant Users
- Can only access data where `tenant_id = current_tenant_id()`
- Cannot see or modify other tenants' data
- Automatically filtered at database level

### Super Admins
- Can access all tenant data
- Required for system maintenance
- Must be explicitly granted

### Indirect Relationships
Tables without direct `tenant_id` use joins:
- Buildings → Sites → Tenants
- Floors → Buildings → Sites → Tenants
- Cameras/Doors → Floors → Buildings → Sites → Tenants

## Performance Considerations

### Indexes
All tenant_id columns are indexed:
```sql
CREATE INDEX idx_[table]_tenant_id ON [table](tenant_id);
```

### Query Optimization
- RLS adds WHERE clause to every query
- Indexes ensure minimal performance impact
- Connection pooling reduces overhead

### Monitoring
```typescript
// Check RLS performance
const stats = await prisma.$queryRaw`
  SELECT 
    schemaname,
    tablename,
    n_tup_ins as inserts,
    n_tup_upd as updates,
    n_tup_del as deletes,
    n_live_tup as live_rows
  FROM pg_stat_user_tables
  WHERE schemaname = 'public'
`;
```

## Testing RLS

### Unit Tests
```typescript
describe('RLS Enforcement', () => {
  it('should isolate tenant data', async () => {
    // Set tenant A context
    await withTenantContext(prisma, 'tenant-a', false, async () => {
      const users = await prisma.user.findMany();
      expect(users.every(u => u.tenantId === 'tenant-a')).toBe(true);
    });
  });
  
  it('should prevent cross-tenant access', async () => {
    await withTenantContext(prisma, 'tenant-a', false, async () => {
      // This should return null (not found in tenant-a)
      const user = await prisma.user.findUnique({
        where: { id: 'user-from-tenant-b' }
      });
      expect(user).toBeNull();
    });
  });
});
```

### Manual Verification
```sql
-- Check RLS status
SELECT tablename, rowsecurity 
FROM pg_tables 
WHERE schemaname = 'public';

-- View policies
SELECT * FROM pg_policies 
WHERE schemaname = 'public';

-- Test as specific tenant
SET app.tenant_id = 'test-tenant';
SET app.is_super_admin = 'false';
SELECT * FROM users; -- Should only see test-tenant users
```

## Troubleshooting

### Common Issues

1. **"Tenant context is required" error**
   - Ensure `tenantContextMiddleware` is applied
   - Check JWT contains `tenantId`

2. **No data returned**
   - Verify tenant context is set correctly
   - Check if data exists for the tenant
   - Ensure RLS policies are applied

3. **Performance degradation**
   - Check indexes exist on tenant_id columns
   - Monitor slow query log
   - Consider connection pooling settings

### Debug Mode
```typescript
// Enable query logging
const prisma = new PrismaClient({
  log: ['query', 'error', 'warn']
});

// Check current context
const context = await prisma.$queryRaw`
  SELECT 
    current_setting('app.tenant_id', true) as tenant_id,
    current_setting('app.is_super_admin', true) as is_super_admin
`;
```

## Best Practices

1. **Always use middleware** for API endpoints
2. **Validate tenant access** for cross-tenant operations
3. **Use transactions** for complex operations
4. **Monitor performance** regularly
5. **Test RLS policies** in development
6. **Document super admin** operations

## Migration Guide

### From Non-RLS to RLS

1. **Backup database** before migration
2. **Apply RLS migration** using script
3. **Update services** to use tenant context
4. **Test thoroughly** in staging
5. **Monitor closely** after deployment

### Rollback Plan

```sql
-- Disable RLS (emergency only)
DO $$
DECLARE
  r RECORD;
BEGIN
  FOR r IN SELECT tablename FROM pg_tables WHERE schemaname = 'public'
  LOOP
    EXECUTE 'ALTER TABLE ' || quote_ident(r.tablename) || ' DISABLE ROW LEVEL SECURITY';
  END LOOP;
END $$;
```

## Compliance

RLS helps meet compliance requirements:
- **SOC 2**: Logical access controls
- **HIPAA**: Data isolation
- **GDPR**: Data segregation
- **PCI DSS**: Access restrictions

## Future Enhancements

1. **Column-level security** for sensitive fields
2. **Dynamic policies** based on user roles
3. **Audit logging** of policy violations
4. **Performance monitoring** dashboard
5. **Automated testing** framework