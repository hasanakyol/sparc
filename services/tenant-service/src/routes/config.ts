import { Hono } from 'hono';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { 
  ResourceQuotasSchema,
  BrandingConfigSchema
} from '@sparc/shared/src/types/tenant';
import { TenantService } from '../services/tenantService';
import { HTTPException } from 'hono/http-exception';
import tenantService from '../index';

const app = new Hono();

// Initialize service with Redis from the main service instance
const service = new TenantService(tenantService.redis);

// Middleware for tenant admin authorization
const requireTenantAdmin = async (c: any, next: any) => {
  const user = c.get('user');
  if (!user || !['SUPER_ADMIN', 'TENANT_ADMIN'].includes(user.role)) {
    throw new HTTPException(403, { message: 'Forbidden: Tenant admin access required' });
  }
  await next();
};

// Configuration update schema
const updateConfigSchema = z.object({
  settings: z.record(z.any()).optional(),
  resourceQuotas: ResourceQuotasSchema.optional(),
  brandingConfig: BrandingConfigSchema.optional()
});

// GET /config/:tenantId - Get tenant configuration
app.get('/:tenantId',
  requireTenantAdmin,
  async (c) => {
    try {
      await tenantService.incrementMetric('api_requests');
      
      const tenantId = c.req.param('tenantId');
      const user = c.get('user');
      
      // Verify access
      if (user.role !== 'SUPER_ADMIN' && tenantId !== user.tenantId) {
        throw new HTTPException(403, { message: 'Access denied' });
      }
      
      const tenant = await service.getTenantById(tenantId);
      
      if (!tenant) {
        throw new HTTPException(404, { message: 'Tenant not found' });
      }
      
      return c.json({
        data: {
          id: tenant.id,
          name: tenant.name,
          domain: tenant.domain,
          settings: tenant.settings,
          resourceQuotas: tenant.resourceQuotas,
          brandingConfig: tenant.brandingConfig,
          status: tenant.status,
          plan: tenant.plan
        }
      });
    } catch (error) {
      console.error('Error fetching tenant configuration:', error);
      throw error;
    }
  }
);

// PUT /config/:tenantId - Update tenant configuration
app.put('/:tenantId',
  requireTenantAdmin,
  zValidator('json', updateConfigSchema),
  async (c) => {
    try {
      await tenantService.incrementMetric('api_requests');
      
      const tenantId = c.req.param('tenantId');
      const data = c.req.valid('json');
      const user = c.get('user');
      
      // Verify access
      if (user.role !== 'SUPER_ADMIN' && tenantId !== user.tenantId) {
        throw new HTTPException(403, { message: 'Access denied' });
      }
      
      const tenant = await service.updateTenant(tenantId, data, user?.id);
      
      return c.json({
        data: {
          id: tenant.id,
          name: tenant.name,
          domain: tenant.domain,
          settings: tenant.settings,
          resourceQuotas: tenant.resourceQuotas,
          brandingConfig: tenant.brandingConfig,
          status: tenant.status,
          plan: tenant.plan
        }
      });
    } catch (error) {
      console.error('Error updating tenant configuration:', error);
      throw error;
    }
  }
);

// GET /config/:tenantId/usage - Get tenant resource usage
app.get('/:tenantId/usage',
  requireTenantAdmin,
  async (c) => {
    try {
      await tenantService.incrementMetric('api_requests');
      
      const tenantId = c.req.param('tenantId');
      const user = c.get('user');
      
      // Verify access
      if (user.role !== 'SUPER_ADMIN' && tenantId !== user.tenantId) {
        throw new HTTPException(403, { message: 'Access denied' });
      }
      
      const usage = await service.getTenantResourceUsage(tenantId);
      
      return c.json({ data: usage });
    } catch (error) {
      console.error('Error fetching tenant usage:', error);
      throw error;
    }
  }
);

export default app;