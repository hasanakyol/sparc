import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { zValidator } from '@hono/zod-validator';
import { UserService } from '../services/userService';
import {
  createUserSchema,
  updateUserSchema,
  userQuerySchema,
  changePasswordSchema,
  deactivateUserSchema,
  activateUserSchema,
  bulkOperationSchema
} from '../types/schemas';

const app = new Hono();

// Get service from context
app.use('*', async (c, next) => {
  const { userService: service } = c.get('services');
  if (!service) {
    throw new HTTPException(500, { message: 'User service not initialized' });
  }
  c.set('userService', service);
  await next();
});

// Middleware to check permissions
const requirePermission = (resource: string, action: string) => {
  return async (c: any, next: any) => {
    const userId = c.get('userId');
    const organizationId = c.get('organizationId');
    
    // TODO: Implement actual permission check
    // For now, we'll assume all authenticated users have access
    // In production, you would check against the permission service
    
    await next();
  };
};

// Create user
app.post(
  '/',
  requirePermission('users', 'create'),
  zValidator('json', createUserSchema),
  async (c) => {
    const data = c.req.valid('json');
    const organizationId = c.get('organizationId');
    const userId = c.get('userId');
    const userService = c.get('userService');

    try {
      const user = await userService.createUser(
        { ...data, organizationId },
        userId
      );

      return c.json(user, 201);
    } catch (error) {
      if (error instanceof HTTPException) {
        throw error;
      }
      throw new HTTPException(500, { message: 'Failed to create user' });
    }
  }
);

// List users
app.get(
  '/',
  requirePermission('users', 'list'),
  zValidator('query', userQuerySchema),
  async (c) => {
    const query = c.req.valid('query');
    const organizationId = c.get('organizationId');
    const userService = c.get('userService');

    try {
      const result = await userService.listUsers(organizationId, query);
      return c.json(result);
    } catch (error) {
      throw new HTTPException(500, { message: 'Failed to list users' });
    }
  }
);

// Get user by ID
app.get(
  '/:userId',
  requirePermission('users', 'read'),
  async (c) => {
    const { userId } = c.req.param();
    const organizationId = c.get('organizationId');
    const userService = c.get('userService');

    try {
      const user = await userService.getUserById(userId, organizationId);
      if (!user) {
        throw new HTTPException(404, { message: 'User not found' });
      }

      return c.json(user);
    } catch (error) {
      if (error instanceof HTTPException) {
        throw error;
      }
      throw new HTTPException(500, { message: 'Failed to get user' });
    }
  }
);

// Update user
app.patch(
  '/:userId',
  requirePermission('users', 'update'),
  zValidator('json', updateUserSchema),
  async (c) => {
    const { userId } = c.req.param();
    const data = c.req.valid('json');
    const organizationId = c.get('organizationId');
    const updatedBy = c.get('userId');
    const userService = c.get('userService');

    try {
      const user = await userService.updateUser(
        userId,
        organizationId,
        data,
        updatedBy
      );

      return c.json(user);
    } catch (error) {
      if (error instanceof HTTPException) {
        throw error;
      }
      throw new HTTPException(500, { message: 'Failed to update user' });
    }
  }
);

// Change password
app.post(
  '/:userId/change-password',
  zValidator('json', changePasswordSchema),
  async (c) => {
    const { userId } = c.req.param();
    const data = c.req.valid('json');
    const organizationId = c.get('organizationId');
    const requestingUserId = c.get('userId');
    const userService = c.get('userService');

    // Users can only change their own password unless they have permission
    if (userId !== requestingUserId) {
      // Check permission
      const hasPermission = true; // TODO: Implement actual check
      if (!hasPermission) {
        throw new HTTPException(403, { message: 'Forbidden' });
      }
    }

    try {
      await userService.changePassword(userId, organizationId, data);
      return c.json({ message: 'Password changed successfully' });
    } catch (error) {
      if (error instanceof HTTPException) {
        throw error;
      }
      throw new HTTPException(500, { message: 'Failed to change password' });
    }
  }
);

// Deactivate user
app.post(
  '/:userId/deactivate',
  requirePermission('users', 'deactivate'),
  zValidator('json', deactivateUserSchema),
  async (c) => {
    const { userId } = c.req.param();
    const data = c.req.valid('json');
    const organizationId = c.get('organizationId');
    const deactivatedBy = c.get('userId');
    const userService = c.get('userService');

    try {
      await userService.deactivateUser(
        userId,
        organizationId,
        data,
        deactivatedBy
      );

      return c.json({ message: 'User deactivated successfully' });
    } catch (error) {
      if (error instanceof HTTPException) {
        throw error;
      }
      throw new HTTPException(500, { message: 'Failed to deactivate user' });
    }
  }
);

// Activate user
app.post(
  '/:userId/activate',
  requirePermission('users', 'activate'),
  zValidator('json', activateUserSchema),
  async (c) => {
    const { userId } = c.req.param();
    const data = c.req.valid('json');
    const organizationId = c.get('organizationId');
    const activatedBy = c.get('userId');
    const userService = c.get('userService');

    try {
      await userService.activateUser(
        userId,
        organizationId,
        data,
        activatedBy
      );

      return c.json({ message: 'User activated successfully' });
    } catch (error) {
      if (error instanceof HTTPException) {
        throw error;
      }
      throw new HTTPException(500, { message: 'Failed to activate user' });
    }
  }
);

// Bulk operations
app.post(
  '/bulk',
  requirePermission('users', 'update'),
  zValidator('json', bulkOperationSchema),
  async (c) => {
    const data = c.req.valid('json');
    const organizationId = c.get('organizationId');
    const performedBy = c.get('userId');
    const userService = c.get('userService');

    try {
      const results = [];
      const errors = [];

      for (const userId of data.userIds) {
        try {
          switch (data.operation) {
            case 'activate':
              await userService.activateUser(
                userId,
                organizationId,
                { reason: data.data?.reason },
                performedBy
              );
              results.push({ userId, status: 'success' });
              break;

            case 'deactivate':
              await userService.deactivateUser(
                userId,
                organizationId,
                { reason: data.data?.reason || 'Bulk deactivation' },
                performedBy
              );
              results.push({ userId, status: 'success' });
              break;

            default:
              errors.push({ userId, error: 'Unsupported operation' });
          }
        } catch (error) {
          errors.push({
            userId,
            error: error instanceof Error ? error.message : 'Unknown error'
          });
        }
      }

      return c.json({
        results,
        errors,
        summary: {
          total: data.userIds.length,
          succeeded: results.length,
          failed: errors.length
        }
      });
    } catch (error) {
      throw new HTTPException(500, { message: 'Bulk operation failed' });
    }
  }
);

export default app;