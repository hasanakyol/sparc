import { Context, Next } from 'hono';
import { HTTPException } from 'hono/http-exception';
import jwt from 'jsonwebtoken';
import { z } from 'zod';

// Tenant context type definition
export interface TenantContext {
  tenantId: string;
  organizationId?: string;
  siteId?: string;
  permissions: string[];
  deploymentModel: 'ssp-managed' | 'self-managed' | 'hybrid';
  isSSPTechnician?: boolean;
  resourceLimits: {
    maxDoors: number;
    maxCameras: number;
    maxUsers: number;
    storageQuotaGB: number;
  };
}

// JWT payload schema for validation
const JWTPayloadSchema = z.object({
  userId: z.string().uuid(),
  tenantId: z.string().uuid(),
  organizationId: z.string().uuid().optional(),
  siteId: z.string().uuid().optional(),
  permissions: z.array(z.string()),
  deploymentModel: z.enum(['ssp-managed', 'self-managed', 'hybrid']),
  isSSPTechnician: z.boolean().optional(),
  iat: z.number(),
  exp: z.number(),
});

// Request tenant extraction schema
const TenantRequestSchema = z.object({
  tenantId: z.string().uuid().optional(),
  organizationId: z.string().uuid().optional(),
  siteId: z.string().uuid().optional(),
});

// Extend Hono's context variable map for type safety
declare module 'hono' {
  interface ContextVariableMap {
    tenant: TenantContext;
    userId: string;
    jwtPayload: z.infer<typeof JWTPayloadSchema>;
  }
}

/**
 * Tenant-aware middleware that extracts and validates tenant context from requests.
 * Implements tenant isolation by ensuring all database queries include appropriate tenantId filter.
 * Supports multi-tenant architecture as defined in Requirement 15.
 */
export const tenantMiddleware = async (c: Context, next: Next) => {
  try {
    // Extract JWT token from Authorization header
    const authHeader = c.req.header('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new HTTPException(401, { message: 'Missing or invalid authorization header' });
    }

    const token = authHeader.substring(7);
    
    // Verify and decode JWT token
    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
      throw new HTTPException(500, { message: 'JWT secret not configured' });
    }

    let decodedToken: any;
    try {
      decodedToken = jwt.verify(token, jwtSecret);
    } catch (error) {
      throw new HTTPException(401, { message: 'Invalid or expired token' });
    }

    // Validate JWT payload structure
    const jwtPayload = JWTPayloadSchema.parse(decodedToken);

    // Extract tenant information from request headers or query parameters
    const requestTenantId = c.req.header('X-Tenant-ID') || c.req.query('tenantId');
    const requestOrgId = c.req.header('X-Organization-ID') || c.req.query('organizationId');
    const requestSiteId = c.req.header('X-Site-ID') || c.req.query('siteId');

    // Validate request tenant information
    const requestTenant = TenantRequestSchema.parse({
      tenantId: requestTenantId,
      organizationId: requestOrgId,
      siteId: requestSiteId,
    });

    // Enforce tenant isolation - ensure user can only access their tenant's data
    if (requestTenant.tenantId && requestTenant.tenantId !== jwtPayload.tenantId) {
      // Special case: SSP technicians can switch between client tenants
      if (!jwtPayload.isSSPTechnician) {
        throw new HTTPException(403, { 
          message: 'Access denied: Cannot access data from different tenant' 
        });
      }
      
      // For SSP technicians, validate they have permission to access the requested tenant
      if (!await validateSSPTenantAccess(jwtPayload.tenantId, requestTenant.tenantId)) {
        throw new HTTPException(403, { 
          message: 'Access denied: SSP technician not authorized for requested tenant' 
        });
      }
    }

    // Determine effective tenant ID (for SSP tenant switching)
    const effectiveTenantId = requestTenant.tenantId || jwtPayload.tenantId;
    
    // Get tenant resource limits and configuration
    const resourceLimits = await getTenantResourceLimits(effectiveTenantId);
    
    // Validate organization and site access within tenant
    if (requestTenant.organizationId && jwtPayload.organizationId) {
      if (requestTenant.organizationId !== jwtPayload.organizationId && 
          !jwtPayload.permissions.includes('access:all-organizations')) {
        throw new HTTPException(403, { 
          message: 'Access denied: Insufficient permissions for requested organization' 
        });
      }
    }

    if (requestTenant.siteId && jwtPayload.siteId) {
      if (requestTenant.siteId !== jwtPayload.siteId && 
          !jwtPayload.permissions.includes('access:all-sites')) {
        throw new HTTPException(403, { 
          message: 'Access denied: Insufficient permissions for requested site' 
        });
      }
    }

    // Create tenant context
    const tenantContext: TenantContext = {
      tenantId: effectiveTenantId,
      organizationId: requestTenant.organizationId || jwtPayload.organizationId,
      siteId: requestTenant.siteId || jwtPayload.siteId,
      permissions: jwtPayload.permissions,
      deploymentModel: jwtPayload.deploymentModel,
      isSSPTechnician: jwtPayload.isSSPTechnician || false,
      resourceLimits,
    };

    // Set context variables for use in route handlers
    c.set('tenant', tenantContext);
    c.set('userId', jwtPayload.userId);
    c.set('jwtPayload', jwtPayload);

    // Add tenant context to request headers for downstream services
    c.req.addHeader('X-Effective-Tenant-ID', effectiveTenantId);
    if (tenantContext.organizationId) {
      c.req.addHeader('X-Effective-Organization-ID', tenantContext.organizationId);
    }
    if (tenantContext.siteId) {
      c.req.addHeader('X-Effective-Site-ID', tenantContext.siteId);
    }

    await next();
  } catch (error) {
    if (error instanceof HTTPException) {
      throw error;
    }
    
    if (error instanceof z.ZodError) {
      throw new HTTPException(400, { 
        message: 'Invalid request format', 
        cause: error.errors 
      });
    }

    console.error('Tenant middleware error:', error);
    throw new HTTPException(500, { message: 'Internal server error in tenant validation' });
  }
};

/**
 * Utility function to get tenant context from Hono context
 */
export const getTenantContext = (c: Context): TenantContext => {
  const tenant = c.get('tenant');
  if (!tenant) {
    throw new HTTPException(500, { message: 'Tenant context not available' });
  }
  return tenant;
};

/**
 * Utility function to get user ID from Hono context
 */
export const getUserId = (c: Context): string => {
  const userId = c.get('userId');
  if (!userId) {
    throw new HTTPException(500, { message: 'User ID not available' });
  }
  return userId;
};

/**
 * Utility function to check if user has specific permission
 */
export const hasPermission = (c: Context, permission: string): boolean => {
  const tenant = getTenantContext(c);
  return tenant.permissions.includes(permission) || 
         tenant.permissions.includes('admin:all') ||
         (tenant.isSSPTechnician && tenant.permissions.includes('ssp:all'));
};

/**
 * Utility function to require specific permission
 */
export const requirePermission = (permission: string) => {
  return async (c: Context, next: Next) => {
    if (!hasPermission(c, permission)) {
      throw new HTTPException(403, { 
        message: `Access denied: Required permission '${permission}' not found` 
      });
    }
    await next();
  };
};

/**
 * Utility function to create tenant-scoped database filter
 */
export const createTenantFilter = (c: Context, additionalFilters: Record<string, any> = {}) => {
  const tenant = getTenantContext(c);
  
  const filter: Record<string, any> = {
    tenantId: tenant.tenantId,
    ...additionalFilters,
  };

  // Add organization filter if specified and user doesn't have all-org access
  if (tenant.organizationId && !hasPermission(c, 'access:all-organizations')) {
    filter.organizationId = tenant.organizationId;
  }

  // Add site filter if specified and user doesn't have all-site access
  if (tenant.siteId && !hasPermission(c, 'access:all-sites')) {
    filter.siteId = tenant.siteId;
  }

  return filter;
};

/**
 * Utility function to validate tenant switching for SSP technicians
 */
export const validateTenantSwitch = async (c: Context, targetTenantId: string): Promise<boolean> => {
  const tenant = getTenantContext(c);
  
  // Only SSP technicians can switch tenants
  if (!tenant.isSSPTechnician) {
    return false;
  }

  // Validate SSP has access to target tenant
  return await validateSSPTenantAccess(tenant.tenantId, targetTenantId);
};

/**
 * Helper function to validate SSP tenant access
 */
async function validateSSPTenantAccess(sspTenantId: string, targetTenantId: string): Promise<boolean> {
  // This would typically query the database to check if the SSP tenant
  // has management rights over the target tenant
  // For now, return true as a placeholder - implement actual validation
  // based on your tenant relationship model
  
  try {
    // Example implementation:
    // const relationship = await prisma.tenantRelationship.findFirst({
    //   where: {
    //     sspTenantId: sspTenantId,
    //     clientTenantId: targetTenantId,
    //     relationshipType: 'MANAGED',
    //     isActive: true,
    //   }
    // });
    // return !!relationship;
    
    return true; // Placeholder
  } catch (error) {
    console.error('Error validating SSP tenant access:', error);
    return false;
  }
}

/**
 * Helper function to get tenant resource limits
 */
async function getTenantResourceLimits(tenantId: string): Promise<TenantContext['resourceLimits']> {
  try {
    // This would typically query the database for tenant-specific limits
    // For now, return default limits - implement actual database query
    
    // Example implementation:
    // const tenant = await prisma.tenant.findUnique({
    //   where: { id: tenantId },
    //   select: {
    //     maxDoors: true,
    //     maxCameras: true,
    //     maxUsers: true,
    //     storageQuotaGB: true,
    //   }
    // });
    
    // return {
    //   maxDoors: tenant?.maxDoors || 10000,
    //   maxCameras: tenant?.maxCameras || 1000,
    //   maxUsers: tenant?.maxUsers || 10000,
    //   storageQuotaGB: tenant?.storageQuotaGB || 1000,
    // };

    // Default limits as placeholder
    return {
      maxDoors: 10000,
      maxCameras: 1000,
      maxUsers: 10000,
      storageQuotaGB: 1000,
    };
  } catch (error) {
    console.error('Error getting tenant resource limits:', error);
    // Return default limits on error
    return {
      maxDoors: 1000,
      maxCameras: 100,
      maxUsers: 1000,
      storageQuotaGB: 100,
    };
  }
}

/**
 * Middleware to enforce resource limits
 */
export const enforceResourceLimits = (resourceType: keyof TenantContext['resourceLimits']) => {
  return async (c: Context, next: Next) => {
    const tenant = getTenantContext(c);
    const currentUsage = await getCurrentResourceUsage(tenant.tenantId, resourceType);
    const limit = tenant.resourceLimits[resourceType];

    if (currentUsage >= limit) {
      throw new HTTPException(429, { 
        message: `Resource limit exceeded: ${resourceType} limit of ${limit} reached` 
      });
    }

    await next();
  };
};

/**
 * Helper function to get current resource usage
 */
async function getCurrentResourceUsage(
  tenantId: string, 
  resourceType: keyof TenantContext['resourceLimits']
): Promise<number> {
  try {
    // This would query the database for current usage
    // Placeholder implementation
    switch (resourceType) {
      case 'maxDoors':
        // return await prisma.door.count({ where: { tenantId } });
        return 0;
      case 'maxCameras':
        // return await prisma.camera.count({ where: { tenantId } });
        return 0;
      case 'maxUsers':
        // return await prisma.user.count({ where: { tenantId } });
        return 0;
      case 'storageQuotaGB':
        // return await getStorageUsageGB(tenantId);
        return 0;
      default:
        return 0;
    }
  } catch (error) {
    console.error(`Error getting ${resourceType} usage:`, error);
    return 0;
  }
}

/**
 * Audit logging utility for tenant operations
 */
export const auditTenantOperation = async (
  c: Context,
  operation: string,
  resourceType: string,
  resourceId?: string,
  additionalData?: Record<string, any>
) => {
  try {
    const tenant = getTenantContext(c);
    const userId = getUserId(c);

    const auditLog = {
      tenantId: tenant.tenantId,
      userId,
      operation,
      resourceType,
      resourceId,
      timestamp: new Date(),
      ipAddress: c.req.header('X-Forwarded-For') || c.req.header('X-Real-IP') || 'unknown',
      userAgent: c.req.header('User-Agent') || 'unknown',
      additionalData,
    };

    // Log to audit system - implement actual logging
    console.log('Audit log:', auditLog);
    
    // Example implementation:
    // await prisma.auditLog.create({ data: auditLog });
  } catch (error) {
    console.error('Error creating audit log:', error);
    // Don't throw error to avoid breaking the main operation
  }
};