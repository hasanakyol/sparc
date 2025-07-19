import { Hono } from 'hono';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { 
  createFloorSchema, 
  updateFloorSchema,
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

// GET /floors - List floors
app.get('/', 
  requireOrgAdmin,
  zValidator('query', paginationSchema),
  async (c) => {
    // TODO: Implement floor listing with proper tenant isolation
    return c.json({ data: [], pagination: { page: 1, limit: 10, total: 0, totalPages: 0 } });
  }
);

// GET /floors/:id - Get floor by ID
app.get('/:id',
  requireOrgAdmin,
  async (c) => {
    // TODO: Implement get floor by ID with access control
    const floorId = c.req.param('id');
    throw new HTTPException(404, { message: 'Floor not found' });
  }
);

// POST /floors - Create new floor
app.post('/',
  requireOrgAdmin,
  zValidator('json', createFloorSchema),
  async (c) => {
    // TODO: Implement floor creation
    const data = c.req.valid('json');
    return c.json({ data: { id: 'temp-id', ...data } }, 201);
  }
);

// PUT /floors/:id - Update floor
app.put('/:id',
  requireOrgAdmin,
  zValidator('json', updateFloorSchema),
  async (c) => {
    // TODO: Implement floor update
    const floorId = c.req.param('id');
    const data = c.req.valid('json');
    return c.json({ data: { id: floorId, ...data } });
  }
);

// DELETE /floors/:id - Delete floor
app.delete('/:id',
  requireOrgAdmin,
  async (c) => {
    // TODO: Implement floor deletion
    const floorId = c.req.param('id');
    return c.json({ message: 'Floor deleted successfully' });
  }
);

export default app;