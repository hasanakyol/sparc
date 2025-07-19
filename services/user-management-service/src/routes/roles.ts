import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { zValidator } from '@hono/zod-validator';
import { RoleService } from '../services/roleService';
import {
  createRoleSchema,
  updateRoleSchema,
  roleQuerySchema,
  assignRolesSchema,
  removeRoleSchema
} from '../types/schemas';

const app = new Hono();

// Initialize service
let roleService: RoleService;

app.use('*', async (c, next) => {
  if (!roleService) {
    const { prisma, redis } = c.get('services');
    roleService = new RoleService(prisma, redis);
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

// Create role
app.post(
  '/',
  requirePermission('roles', 'create'),
  zValidator('json', createRoleSchema),
  async (c) => {
    const data = c.req.valid('json');
    const organizationId = c.get('organizationId');
    const createdBy = c.get('userId');

    try {
      const role = await roleService.createRole(
        { ...data, organizationId },
        createdBy
      );

      return c.json(role, 201);
    } catch (error) {
      if (error instanceof HTTPException) {
        throw error;
      }
      throw new HTTPException(500, { message: 'Failed to create role' });
    }
  }
);

// List roles
app.get(
  '/',
  requirePermission('roles', 'list'),
  zValidator('query', roleQuerySchema),
  async (c) => {
    const query = c.req.valid('query');
    const organizationId = c.get('organizationId');

    try {
      const result = await roleService.listRoles(organizationId, query);
      return c.json(result);
    } catch (error) {
      throw new HTTPException(500, { message: 'Failed to list roles' });
    }
  }
);

// Get role by ID
app.get(
  '/:roleId',
  requirePermission('roles', 'read'),
  async (c) => {
    const { roleId } = c.req.param();
    const organizationId = c.get('organizationId');

    try {
      const role = await roleService.getRoleById(roleId, organizationId);
      if (!role) {
        throw new HTTPException(404, { message: 'Role not found' });
      }

      return c.json(role);
    } catch (error) {
      if (error instanceof HTTPException) {
        throw error;
      }
      throw new HTTPException(500, { message: 'Failed to get role' });
    }
  }
);

// Update role
app.patch(
  '/:roleId',
  requirePermission('roles', 'update'),
  zValidator('json', updateRoleSchema),
  async (c) => {
    const { roleId } = c.req.param();
    const data = c.req.valid('json');
    const organizationId = c.get('organizationId');
    const updatedBy = c.get('userId');

    try {
      const role = await roleService.updateRole(
        roleId,
        organizationId,
        data,
        updatedBy
      );

      return c.json(role);
    } catch (error) {
      if (error instanceof HTTPException) {
        throw error;
      }
      throw new HTTPException(500, { message: 'Failed to update role' });
    }
  }
);

// Delete role
app.delete(
  '/:roleId',
  requirePermission('roles', 'delete'),
  async (c) => {
    const { roleId } = c.req.param();
    const organizationId = c.get('organizationId');
    const deletedBy = c.get('userId');

    try {
      await roleService.deleteRole(roleId, organizationId, deletedBy);
      return c.json({ message: 'Role deleted successfully' });
    } catch (error) {
      if (error instanceof HTTPException) {
        throw error;
      }
      throw new HTTPException(500, { message: 'Failed to delete role' });
    }
  }
);

// Assign roles to user
app.post(
  '/assign/:userId',
  requirePermission('roles', 'assign'),
  zValidator('json', assignRolesSchema),
  async (c) => {
    const { userId } = c.req.param();
    const data = c.req.valid('json');
    const organizationId = c.get('organizationId');
    const assignedBy = c.get('userId');

    try {
      const result = await roleService.assignRolesToUser(
        userId,
        organizationId,
        data,
        assignedBy
      );

      return c.json(result);
    } catch (error) {
      if (error instanceof HTTPException) {
        throw error;
      }
      throw new HTTPException(500, { message: 'Failed to assign roles' });
    }
  }
);

// Remove role from user
app.delete(
  '/assign/:userId/:roleId',
  requirePermission('roles', 'assign'),
  async (c) => {
    const { userId, roleId } = c.req.param();
    const organizationId = c.get('organizationId');
    const removedBy = c.get('userId');

    try {
      await roleService.removeRoleFromUser(
        userId,
        roleId,
        organizationId,
        removedBy
      );

      return c.json({ message: 'Role removed successfully' });
    } catch (error) {
      if (error instanceof HTTPException) {
        throw error;
      }
      throw new HTTPException(500, { message: 'Failed to remove role' });
    }
  }
);

// Get users by role
app.get(
  '/:roleId/users',
  requirePermission('roles', 'read'),
  async (c) => {
    const { roleId } = c.req.param();
    const organizationId = c.get('organizationId');
    const page = Number(c.req.query('page') || 1);
    const limit = Number(c.req.query('limit') || 20);

    try {
      const role = await roleService.getRoleById(roleId, organizationId);
      if (!role) {
        throw new HTTPException(404, { message: 'Role not found' });
      }

      // TODO: Implement getUsersByRole in roleService
      return c.json({
        data: [],
        pagination: {
          page,
          limit,
          total: 0,
          totalPages: 0
        }
      });
    } catch (error) {
      if (error instanceof HTTPException) {
        throw error;
      }
      throw new HTTPException(500, { message: 'Failed to get users by role' });
    }
  }
);

export default app;