import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { PermissionService } from '../services/permissionService';

const app = new Hono();

// Initialize service
let permissionService: PermissionService;

app.use('*', async (c, next) => {
  if (!permissionService) {
    const { prisma, redis } = c.get('services');
    permissionService = new PermissionService(prisma, redis);
  }
  await next();
});

// Middleware to check permissions
const requirePermission = (resource: string, action: string) => {
  return async (c: any, next: any) => {
    const userId = c.get('userId');
    const organizationId = c.get('organizationId');
    
    // TODO: Implement actual permission check
    await next();
  };
};

// List all permissions grouped by resource
app.get(
  '/',
  requirePermission('roles', 'read'), // Need role read permission to see available permissions
  async (c) => {
    try {
      const permissions = await permissionService.listPermissions();
      return c.json(permissions);
    } catch (error) {
      throw new HTTPException(500, { message: 'Failed to list permissions' });
    }
  }
);

// Get permissions by resource
app.get(
  '/resource/:resource',
  requirePermission('roles', 'read'),
  async (c) => {
    const { resource } = c.req.param();

    try {
      const permissions = await permissionService.getPermissionsByResource(resource);
      return c.json(permissions);
    } catch (error) {
      throw new HTTPException(500, { message: 'Failed to get permissions' });
    }
  }
);

// Get current user's permissions
app.get(
  '/my-permissions',
  async (c) => {
    const userId = c.get('userId');
    const organizationId = c.get('organizationId');

    try {
      const permissions = await permissionService.getUserPermissions(userId, organizationId);
      return c.json(permissions);
    } catch (error) {
      throw new HTTPException(500, { message: 'Failed to get user permissions' });
    }
  }
);

// Get specific user's permissions
app.get(
  '/user/:userId',
  requirePermission('users', 'read'),
  async (c) => {
    const { userId } = c.req.param();
    const organizationId = c.get('organizationId');

    try {
      const permissions = await permissionService.getUserPermissions(userId, organizationId);
      return c.json(permissions);
    } catch (error) {
      throw new HTTPException(500, { message: 'Failed to get user permissions' });
    }
  }
);

// Check if user has permission
app.post(
  '/check',
  async (c) => {
    const { resource, action, context } = await c.req.json();
    const userId = c.get('userId');
    const organizationId = c.get('organizationId');

    if (!resource || !action) {
      throw new HTTPException(400, { message: 'Resource and action are required' });
    }

    try {
      const hasPermission = await permissionService.checkUserPermission(
        userId,
        organizationId,
        resource,
        action,
        context
      );

      return c.json({ hasPermission });
    } catch (error) {
      throw new HTTPException(500, { message: 'Failed to check permission' });
    }
  }
);

// Seed default permissions (admin only)
app.post(
  '/seed',
  requirePermission('system', 'manage_settings'),
  async (c) => {
    try {
      await permissionService.seedDefaultPermissions();
      return c.json({ message: 'Default permissions seeded successfully' });
    } catch (error) {
      throw new HTTPException(500, { message: 'Failed to seed permissions' });
    }
  }
);

export default app;