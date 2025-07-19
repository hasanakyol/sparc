import { Hono } from 'hono';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { 
  createOrganizationSchema, 
  updateOrganizationSchema,
  paginationSchema
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

// Middleware for organization admin authorization
const requireOrgAdmin = async (c: any, next: any) => {
  const user = c.get('user');
  if (!user || !['SUPER_ADMIN', 'TENANT_ADMIN', 'ORG_ADMIN'].includes(user.role)) {
    throw new HTTPException(403, { message: 'Forbidden: Organization admin access required' });
  }
  await next();
};

// GET /organizations - List organizations
app.get('/', 
  requireTenantAdmin,
  zValidator('query', paginationSchema),
  async (c) => {
    try {
      await tenantService.incrementMetric('api_requests');
      
      const query = c.req.valid('query');
      const user = c.get('user');
      const tenantId = c.req.query('tenantId') || user.tenantId;
      
      const result = await service.getOrganizations({
        ...query,
        tenantId
      });
      
      return c.json(result);
    } catch (error) {
      console.error('Error fetching organizations:', error);
      throw error;
    }
  }
);

// GET /organizations/:id - Get organization by ID
app.get('/:id',
  requireOrgAdmin,
  async (c) => {
    try {
      await tenantService.incrementMetric('api_requests');
      
      const organizationId = c.req.param('id');
      
      const organization = await service.getOrganizationById(organizationId);
      
      if (!organization) {
        throw new HTTPException(404, { message: 'Organization not found' });
      }
      
      // Check user has access to this organization
      const user = c.get('user');
      if (user.role !== 'SUPER_ADMIN' && organization.tenantId !== user.tenantId) {
        throw new HTTPException(403, { message: 'Access denied' });
      }
      
      return c.json({ data: organization });
    } catch (error) {
      console.error('Error fetching organization:', error);
      throw error;
    }
  }
);

// POST /organizations - Create new organization
app.post('/',
  requireTenantAdmin,
  zValidator('json', createOrganizationSchema),
  async (c) => {
    try {
      await tenantService.incrementMetric('api_requests');
      
      const data = c.req.valid('json');
      const user = c.get('user');
      const tenantId = c.req.query('tenantId') || user.tenantId;
      
      // Verify user has access to create in this tenant
      if (user.role !== 'SUPER_ADMIN' && tenantId !== user.tenantId) {
        throw new HTTPException(403, { message: 'Access denied' });
      }
      
      const organization = await service.createOrganization(tenantId, data, user?.id);
      
      return c.json({ data: organization }, 201);
    } catch (error) {
      console.error('Error creating organization:', error);
      throw error;
    }
  }
);

// PUT /organizations/:id - Update organization
app.put('/:id',
  requireOrgAdmin,
  zValidator('json', updateOrganizationSchema),
  async (c) => {
    try {
      await tenantService.incrementMetric('api_requests');
      
      const organizationId = c.req.param('id');
      const data = c.req.valid('json');
      const user = c.get('user');
      
      // Verify access
      const existing = await service.getOrganizationById(organizationId);
      if (!existing) {
        throw new HTTPException(404, { message: 'Organization not found' });
      }
      
      if (user.role !== 'SUPER_ADMIN' && existing.tenantId !== user.tenantId) {
        throw new HTTPException(403, { message: 'Access denied' });
      }
      
      const organization = await service.updateOrganization(organizationId, data, user?.id);
      
      return c.json({ data: organization });
    } catch (error) {
      console.error('Error updating organization:', error);
      throw error;
    }
  }
);

// DELETE /organizations/:id - Delete organization
app.delete('/:id',
  requireOrgAdmin,
  async (c) => {
    try {
      await tenantService.incrementMetric('api_requests');
      
      const organizationId = c.req.param('id');
      const user = c.get('user');
      
      // Verify access
      const existing = await service.getOrganizationById(organizationId);
      if (!existing) {
        throw new HTTPException(404, { message: 'Organization not found' });
      }
      
      if (user.role !== 'SUPER_ADMIN' && existing.tenantId !== user.tenantId) {
        throw new HTTPException(403, { message: 'Access denied' });
      }
      
      await service.deleteOrganization(organizationId);
      
      return c.json({ message: 'Organization deleted successfully' });
    } catch (error) {
      console.error('Error deleting organization:', error);
      throw error;
    }
  }
);

export default app;