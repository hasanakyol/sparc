import { Hono } from 'hono';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { 
  createSiteSchema, 
  updateSiteSchema,
  paginationSchema
} from '@sparc/shared/src/types/tenant';
import { HTTPException } from 'hono/http-exception';

const app = new Hono();

// Middleware for organization admin authorization
const requireOrgAdmin = async (c: any, next: any) => {
  const user = c.get('user');
  if (!user || !['SUPER_ADMIN', 'TENANT_ADMIN', 'ORG_ADMIN'].includes(user.role)) {
    throw new HTTPException(403, { message: 'Forbidden: Organization admin access required' });
  }
  await next();
};

// GET /sites - List sites
app.get('/', 
  requireOrgAdmin,
  zValidator('query', paginationSchema),
  async (c) => {
    // TODO: Implement site listing with proper tenant isolation
    return c.json({ data: [], pagination: { page: 1, limit: 10, total: 0, totalPages: 0 } });
  }
);

// GET /sites/:id - Get site by ID
app.get('/:id',
  requireOrgAdmin,
  async (c) => {
    // TODO: Implement get site by ID with access control
    const siteId = c.req.param('id');
    throw new HTTPException(404, { message: 'Site not found' });
  }
);

// POST /sites - Create new site
app.post('/',
  requireOrgAdmin,
  zValidator('json', createSiteSchema),
  async (c) => {
    // TODO: Implement site creation
    const data = c.req.valid('json');
    return c.json({ data: { id: 'temp-id', ...data } }, 201);
  }
);

// PUT /sites/:id - Update site
app.put('/:id',
  requireOrgAdmin,
  zValidator('json', updateSiteSchema),
  async (c) => {
    // TODO: Implement site update
    const siteId = c.req.param('id');
    const data = c.req.valid('json');
    return c.json({ data: { id: siteId, ...data } });
  }
);

// DELETE /sites/:id - Delete site
app.delete('/:id',
  requireOrgAdmin,
  async (c) => {
    // TODO: Implement site deletion
    const siteId = c.req.param('id');
    return c.json({ message: 'Site deleted successfully' });
  }
);

export default app;