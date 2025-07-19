import { Hono } from 'hono';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { 
  createTenantSchema, 
  updateTenantSchema,
  paginationSchema,
  tenantQuerySchema
} from '@sparc/shared/src/types/tenant';
import { TenantService } from '../services/tenantService';
import { HTTPException } from 'hono/http-exception';
import tenantService from '../index';

const app = new Hono();

// Initialize service with Redis from the main service instance
const service = new TenantService(tenantService.redis);

// Middleware for super admin authorization
const requireSuperAdmin = async (c: any, next: any) => {
  const user = c.get('user');
  if (!user || user.role !== 'SUPER_ADMIN') {
    throw new HTTPException(403, { message: 'Forbidden: Super admin access required' });
  }
  await next();
};

// GET /tenants - List all tenants (Super Admin only)
app.get('/', 
  requireSuperAdmin,
  zValidator('query', paginationSchema.merge(tenantQuerySchema)),
  async (c) => {
    try {
      await tenantService.incrementMetric('api_requests');
      
      const query = c.req.valid('query');
      const result = await service.getTenants(query);
      
      return c.json(result);
    } catch (error) {
      console.error('Error fetching tenants:', error);
      throw error;
    }
  }
);

// GET /tenants/:id - Get tenant by ID
app.get('/:id',
  requireSuperAdmin,
  async (c) => {
    try {
      await tenantService.incrementMetric('api_requests');
      
      const tenantId = c.req.param('id');
      const includeRelations = c.req.query('include') === 'all';
      
      const tenant = await service.getTenantById(tenantId, includeRelations);
      
      if (!tenant) {
        throw new HTTPException(404, { message: 'Tenant not found' });
      }
      
      return c.json({ data: tenant });
    } catch (error) {
      console.error('Error fetching tenant:', error);
      throw error;
    }
  }
);

// POST /tenants - Create new tenant
app.post('/',
  requireSuperAdmin,
  zValidator('json', createTenantSchema),
  async (c) => {
    try {
      await tenantService.incrementMetric('api_requests');
      
      const data = c.req.valid('json');
      const user = c.get('user');
      
      const tenant = await service.createTenant(data, user?.id);
      
      return c.json({ data: tenant }, 201);
    } catch (error) {
      console.error('Error creating tenant:', error);
      throw error;
    }
  }
);

// PUT /tenants/:id - Update tenant
app.put('/:id',
  requireSuperAdmin,
  zValidator('json', updateTenantSchema),
  async (c) => {
    try {
      await tenantService.incrementMetric('api_requests');
      
      const tenantId = c.req.param('id');
      const data = c.req.valid('json');
      const user = c.get('user');
      
      const tenant = await service.updateTenant(tenantId, data, user?.id);
      
      return c.json({ data: tenant });
    } catch (error) {
      console.error('Error updating tenant:', error);
      throw error;
    }
  }
);

// DELETE /tenants/:id - Delete tenant
app.delete('/:id',
  requireSuperAdmin,
  async (c) => {
    try {
      await tenantService.incrementMetric('api_requests');
      
      const tenantId = c.req.param('id');
      
      await service.deleteTenant(tenantId);
      
      return c.json({ message: 'Tenant deleted successfully' });
    } catch (error) {
      console.error('Error deleting tenant:', error);
      throw error;
    }
  }
);

// GET /tenants/:id/usage - Get tenant resource usage
app.get('/:id/usage',
  requireSuperAdmin,
  async (c) => {
    try {
      await tenantService.incrementMetric('api_requests');
      
      const tenantId = c.req.param('id');
      
      const usage = await service.getTenantResourceUsage(tenantId);
      
      return c.json({ data: usage });
    } catch (error) {
      console.error('Error fetching tenant usage:', error);
      throw error;
    }
  }
);

export default app;