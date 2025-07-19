import { createRoute, z } from '@hono/zod-openapi';
import { createOpenAPIApp, createApiResponses, PaginatedResponseSchema } from '@sparc/shared';
import { PrismaClient } from '@prisma/client';
import type { Context, Next } from 'hono';

const prisma = new PrismaClient();

// Create OpenAPI app
const { app, registry } = createOpenAPIApp({
  serviceName: 'tenant-service',
  serviceVersion: '1.0.0',
  serviceDescription: 'Manages tenants, organizations, sites, and hierarchical structures',
  basePath: '/api/v1/tenants'
});

// Define schemas
const TenantSchema = z.object({
  id: z.string().uuid(),
  name: z.string().min(1).max(255),
  domain: z.string().optional(),
  status: z.enum(['ACTIVE', 'INACTIVE', 'SUSPENDED']),
  contactEmail: z.string().email(),
  contactPhone: z.string().optional(),
  billingEmail: z.string().email().optional(),
  maxUsers: z.number().int().positive(),
  maxSites: z.number().int().positive(),
  maxCamerasPerSite: z.number().int().positive(),
  features: z.object({
    videoAnalytics: z.boolean(),
    accessControl: z.boolean(),
    visitorManagement: z.boolean(),
    environmentalMonitoring: z.boolean(),
    mobileCredentials: z.boolean()
  }),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime()
});

const CreateTenantSchema = TenantSchema.omit({ 
  id: true, 
  createdAt: true, 
  updatedAt: true 
});

const UpdateTenantSchema = CreateTenantSchema.partial();

const TenantQuerySchema = z.object({
  page: z.string().optional().default('1').transform(val => parseInt(val)),
  limit: z.string().optional().default('10').transform(val => parseInt(val)),
  search: z.string().optional(),
  status: z.enum(['ACTIVE', 'INACTIVE', 'SUSPENDED']).optional(),
  sortBy: z.string().optional(),
  sortOrder: z.enum(['asc', 'desc']).optional().default('asc')
});

// Register schemas
registry.registerComponent('schemas', 'Tenant', TenantSchema);
registry.registerComponent('schemas', 'CreateTenant', CreateTenantSchema);
registry.registerComponent('schemas', 'UpdateTenant', UpdateTenantSchema);

// Middleware
const requireSuperAdmin = async (c: Context, next: Next) => {
  const user = c.get('user');
  if (!user || user.role !== 'SUPER_ADMIN') {
    return c.json({ 
      error: {
        code: 403,
        message: 'Super admin access required',
        timestamp: new Date().toISOString()
      }
    }, 403);
  }
  await next();
};

// Define routes using OpenAPI

// GET /tenants - List all tenants
const listTenantsRoute = createRoute({
  method: 'get',
  path: '/tenants',
  summary: 'List all tenants',
  description: 'Retrieve a paginated list of all tenants in the system. Requires super admin access.',
  tags: ['Tenants'],
  security: [{ bearerAuth: [] }],
  request: {
    query: TenantQuerySchema
  },
  responses: createApiResponses({
    successSchema: PaginatedResponseSchema(TenantSchema),
    successDescription: 'List of tenants retrieved successfully'
  })
});

app.openapi(listTenantsRoute, requireSuperAdmin, async (c) => {
  const { page, limit, search, status, sortBy, sortOrder } = c.req.valid('query');
  const skip = (page - 1) * limit;

  const where: any = {};
  
  if (search) {
    where.OR = [
      { name: { contains: search, mode: 'insensitive' } },
      { domain: { contains: search, mode: 'insensitive' } },
      { contactEmail: { contains: search, mode: 'insensitive' } }
    ];
  }

  if (status) {
    where.status = status;
  }

  const orderBy: any = {};
  if (sortBy) {
    orderBy[sortBy] = sortOrder;
  } else {
    orderBy.createdAt = 'desc';
  }

  const [tenants, total] = await Promise.all([
    prisma.tenant.findMany({
      where,
      skip,
      take: limit,
      orderBy,
      include: {
        _count: {
          select: {
            organizations: true,
            users: true
          }
        }
      }
    }),
    prisma.tenant.count({ where })
  ]);

  return c.json({
    data: tenants,
    pagination: {
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit)
    },
    timestamp: new Date().toISOString()
  });
});

// GET /tenants/:id - Get tenant by ID
const getTenantRoute = createRoute({
  method: 'get',
  path: '/tenants/{id}',
  summary: 'Get tenant by ID',
  description: 'Retrieve detailed information about a specific tenant',
  tags: ['Tenants'],
  security: [{ bearerAuth: [] }],
  request: {
    params: z.object({
      id: z.string().uuid()
    })
  },
  responses: createApiResponses({
    successSchema: TenantSchema,
    successDescription: 'Tenant details retrieved successfully',
    includeNotFound: true
  })
});

app.openapi(getTenantRoute, requireSuperAdmin, async (c) => {
  const { id } = c.req.valid('param');

  const tenant = await prisma.tenant.findUnique({
    where: { id },
    include: {
      organizations: {
        include: {
          _count: {
            select: {
              sites: true,
              users: true
            }
          }
        }
      }
    }
  });

  if (!tenant) {
    return c.json({
      error: {
        code: 404,
        message: 'Tenant not found',
        timestamp: new Date().toISOString()
      }
    }, 404);
  }

  return c.json(tenant);
});

// POST /tenants - Create a new tenant
const createTenantRoute = createRoute({
  method: 'post',
  path: '/tenants',
  summary: 'Create a new tenant',
  description: 'Create a new tenant in the system. Requires super admin access.',
  tags: ['Tenants'],
  security: [{ bearerAuth: [] }],
  request: {
    body: {
      content: {
        'application/json': {
          schema: CreateTenantSchema
        }
      }
    }
  },
  responses: {
    201: {
      description: 'Tenant created successfully',
      content: {
        'application/json': {
          schema: TenantSchema
        }
      }
    },
    ...createApiResponses({ includeValidation: true }).responses
  }
});

app.openapi(createTenantRoute, requireSuperAdmin, async (c) => {
  const data = c.req.valid('json');

  // Check if domain already exists
  if (data.domain) {
    const existing = await prisma.tenant.findUnique({
      where: { domain: data.domain }
    });

    if (existing) {
      return c.json({
        error: {
          code: 400,
          message: 'Domain already exists',
          timestamp: new Date().toISOString(),
          details: [{ field: 'domain', message: 'This domain is already registered' }]
        }
      }, 400);
    }
  }

  const tenant = await prisma.tenant.create({
    data: {
      ...data,
      features: data.features || {
        videoAnalytics: true,
        accessControl: true,
        visitorManagement: true,
        environmentalMonitoring: true,
        mobileCredentials: true
      }
    }
  });

  return c.json(tenant, 201);
});

// PUT /tenants/:id - Update tenant
const updateTenantRoute = createRoute({
  method: 'put',
  path: '/tenants/{id}',
  summary: 'Update tenant',
  description: 'Update an existing tenant\'s information',
  tags: ['Tenants'],
  security: [{ bearerAuth: [] }],
  request: {
    params: z.object({
      id: z.string().uuid()
    }),
    body: {
      content: {
        'application/json': {
          schema: UpdateTenantSchema
        }
      }
    }
  },
  responses: createApiResponses({
    successSchema: TenantSchema,
    successDescription: 'Tenant updated successfully',
    includeNotFound: true,
    includeValidation: true
  })
});

app.openapi(updateTenantRoute, requireSuperAdmin, async (c) => {
  const { id } = c.req.valid('param');
  const data = c.req.valid('json');

  // Check if tenant exists
  const existing = await prisma.tenant.findUnique({
    where: { id }
  });

  if (!existing) {
    return c.json({
      error: {
        code: 404,
        message: 'Tenant not found',
        timestamp: new Date().toISOString()
      }
    }, 404);
  }

  // Check domain uniqueness if changing
  if (data.domain && data.domain !== existing.domain) {
    const domainExists = await prisma.tenant.findUnique({
      where: { domain: data.domain }
    });

    if (domainExists) {
      return c.json({
        error: {
          code: 400,
          message: 'Domain already exists',
          timestamp: new Date().toISOString(),
          details: [{ field: 'domain', message: 'This domain is already registered' }]
        }
      }, 400);
    }
  }

  const tenant = await prisma.tenant.update({
    where: { id },
    data
  });

  return c.json(tenant);
});

// DELETE /tenants/:id - Delete tenant
const deleteTenantRoute = createRoute({
  method: 'delete',
  path: '/tenants/{id}',
  summary: 'Delete tenant',
  description: 'Delete a tenant and all associated data. This action cannot be undone.',
  tags: ['Tenants'],
  security: [{ bearerAuth: [] }],
  request: {
    params: z.object({
      id: z.string().uuid()
    })
  },
  responses: {
    204: {
      description: 'Tenant deleted successfully'
    },
    ...createApiResponses({ includeNotFound: true }).responses
  }
});

app.openapi(deleteTenantRoute, requireSuperAdmin, async (c) => {
  const { id } = c.req.valid('param');

  // Check if tenant exists
  const existing = await prisma.tenant.findUnique({
    where: { id },
    include: {
      _count: {
        select: {
          organizations: true,
          users: true
        }
      }
    }
  });

  if (!existing) {
    return c.json({
      error: {
        code: 404,
        message: 'Tenant not found',
        timestamp: new Date().toISOString()
      }
    }, 404);
  }

  // Prevent deletion if tenant has data
  if (existing._count.organizations > 0 || existing._count.users > 0) {
    return c.json({
      error: {
        code: 400,
        message: 'Cannot delete tenant with existing data',
        timestamp: new Date().toISOString(),
        details: {
          organizations: existing._count.organizations,
          users: existing._count.users
        }
      }
    }, 400);
  }

  await prisma.tenant.delete({
    where: { id }
  });

  return c.body(null, 204);
});

export default app;