import { Prisma } from '@prisma/client';

/**
 * Sets the tenant context for Row Level Security (RLS) in PostgreSQL
 * This must be called before any database operations to ensure proper tenant isolation
 */
export async function setTenantContext(
  prisma: any, // Prisma client instance
  tenantId: string | null,
  isSuperAdmin: boolean = false
): Promise<void> {
  if (!tenantId && !isSuperAdmin) {
    throw new Error('Tenant ID is required for non-super admin users');
  }

  // Set the tenant context in PostgreSQL session
  await prisma.$executeRawUnsafe(
    `SET LOCAL app.tenant_id = '${tenantId || ''}'`
  );
  
  await prisma.$executeRawUnsafe(
    `SET LOCAL app.is_super_admin = '${isSuperAdmin ? 'true' : 'false'}'`
  );
}

/**
 * Creates a Prisma client extension that automatically sets tenant context
 * based on the provided context
 */
export function createTenantAwarePrismaClient(baseClient: any) {
  return baseClient.$extends({
    query: {
      async $allOperations({ operation, model, args, query, ...rest }: any) {
        // Get tenant context from the current async context (if using AsyncLocalStorage)
        const context = (globalThis as any).__tenantContext;
        
        if (context && context.tenantId) {
          // Set tenant context before the query
          await baseClient.$executeRawUnsafe(
            `SET LOCAL app.tenant_id = '${context.tenantId}'`
          );
          await baseClient.$executeRawUnsafe(
            `SET LOCAL app.is_super_admin = '${context.isSuperAdmin ? 'true' : 'false'}'`
          );
        }
        
        // Execute the actual query
        return query(args);
      },
    },
  });
}

/**
 * Middleware to automatically inject tenant_id into create/update operations
 * This provides an additional layer of security on top of RLS
 */
export function createTenantMiddleware(): Prisma.Middleware {
  return async (params, next) => {
    const context = (globalThis as any).__tenantContext;
    
    if (!context || !context.tenantId) {
      // If no tenant context, proceed without modification
      return next(params);
    }

    const modelsWithTenantId = [
      'Tenant', 'Organization', 'Site', 'User', 'AccessEvent', 'AccessPanel',
      'Credential', 'AccessGroup', 'Schedule', 'Alert', 'AuditLog',
      'VideoRecording', 'Visitor', 'MaintenanceWorkOrder', 'IncidentReport',
      'EnvironmentalSensor', 'EnvironmentalReading', 'MobileCredential',
      'PrivacyMask', 'VideoExportLog', 'ElevatorControl', 'SystemConfiguration',
      'OfflineEventQueue', 'PolicyTemplate', 'OfflineOperationLog',
      'Certificate', 'BackupJob', 'IntegrationConfiguration'
    ];

    // Automatically add tenant_id to create operations
    if (params.action === 'create' && modelsWithTenantId.includes(params.model || '')) {
      if (params.args.data) {
        params.args.data.tenantId = context.tenantId;
      }
    }

    // Automatically add tenant_id to createMany operations
    if (params.action === 'createMany' && modelsWithTenantId.includes(params.model || '')) {
      if (params.args.data) {
        if (Array.isArray(params.args.data)) {
          params.args.data = params.args.data.map((item: any) => ({
            ...item,
            tenantId: context.tenantId
          }));
        } else {
          params.args.data.tenantId = context.tenantId;
        }
      }
    }

    // Add tenant filter to all queries (as an additional safety measure)
    if (['findUnique', 'findFirst', 'findMany', 'update', 'updateMany', 'delete', 'deleteMany'].includes(params.action || '')) {
      if (modelsWithTenantId.includes(params.model || '') && !context.isSuperAdmin) {
        params.args = params.args || {};
        params.args.where = params.args.where || {};
        
        // Don't override existing tenant filters
        if (!params.args.where.tenantId) {
          params.args.where.tenantId = context.tenantId;
        }
      }
    }

    return next(params);
  };
}

/**
 * Express middleware to set tenant context from JWT
 */
export function tenantContextMiddleware(req: any, res: any, next: any) {
  const tenantId = req.user?.tenantId || req.headers['x-tenant-id'];
  const isSuperAdmin = req.user?.roles?.includes('super_admin') || false;

  if (!tenantId && !isSuperAdmin) {
    return res.status(400).json({ error: 'Tenant context is required' });
  }

  // Store context in global for this request
  (globalThis as any).__tenantContext = {
    tenantId,
    isSuperAdmin,
    userId: req.user?.id
  };

  // Clean up after request
  res.on('finish', () => {
    delete (globalThis as any).__tenantContext;
  });

  next();
}

/**
 * Wraps a database operation with tenant context
 * Useful for background jobs and scripts
 */
export async function withTenantContext<T>(
  prisma: any,
  tenantId: string,
  isSuperAdmin: boolean,
  operation: () => Promise<T>
): Promise<T> {
  // Use a transaction to ensure context is set for the entire operation
  return prisma.$transaction(async (tx: any) => {
    await setTenantContext(tx, tenantId, isSuperAdmin);
    return operation();
  });
}

/**
 * Validates that a user has access to a specific tenant
 * This is useful for API endpoints that accept a tenant ID parameter
 */
export async function validateTenantAccess(
  prisma: any,
  userId: string,
  requestedTenantId: string
): Promise<boolean> {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { tenantId: true, roles: true }
  });

  if (!user) {
    return false;
  }

  // Super admins can access any tenant
  if (user.roles?.includes('super_admin')) {
    return true;
  }

  // Regular users can only access their own tenant
  return user.tenantId === requestedTenantId;
}

/**
 * Helper to run database migrations with super admin context
 */
export async function runMigrationWithSuperAdmin<T>(
  prisma: any,
  migration: () => Promise<T>
): Promise<T> {
  return withTenantContext(prisma, null, true, migration);
}