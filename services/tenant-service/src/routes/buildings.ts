import { Hono } from 'hono';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { 
  createBuildingSchema, 
  updateBuildingSchema,
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

// GET /buildings - List buildings
app.get('/', 
  requireOrgAdmin,
  zValidator('query', paginationSchema),
  async (c) => {
    // TODO: Implement building listing with proper tenant isolation
    return c.json({ data: [], pagination: { page: 1, limit: 10, total: 0, totalPages: 0 } });
  }
);

// GET /buildings/:id - Get building by ID
app.get('/:id',
  requireOrgAdmin,
  async (c) => {
    // TODO: Implement get building by ID with access control
    const buildingId = c.req.param('id');
    throw new HTTPException(404, { message: 'Building not found' });
  }
);

// POST /buildings - Create new building
app.post('/',
  requireOrgAdmin,
  zValidator('json', createBuildingSchema),
  async (c) => {
    // TODO: Implement building creation
    const data = c.req.valid('json');
    return c.json({ data: { id: 'temp-id', ...data } }, 201);
  }
);

// PUT /buildings/:id - Update building
app.put('/:id',
  requireOrgAdmin,
  zValidator('json', updateBuildingSchema),
  async (c) => {
    // TODO: Implement building update
    const buildingId = c.req.param('id');
    const data = c.req.valid('json');
    return c.json({ data: { id: buildingId, ...data } });
  }
);

// DELETE /buildings/:id - Delete building
app.delete('/:id',
  requireOrgAdmin,
  async (c) => {
    // TODO: Implement building deletion
    const buildingId = c.req.param('id');
    return c.json({ message: 'Building deleted successfully' });
  }
);

export default app;