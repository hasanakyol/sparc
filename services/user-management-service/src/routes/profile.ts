import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { zValidator } from '@hono/zod-validator';
import { UserService } from '../services/userService';
import { PermissionService } from '../services/permissionService';
import {
  updateUserSchema,
  changePasswordSchema
} from '../types/schemas';

const app = new Hono();

// Initialize services
let userService: UserService;
let permissionService: PermissionService;

app.use('*', async (c, next) => {
  if (!userService || !permissionService) {
    const { prisma, redis } = c.get('services');
    userService = new UserService(prisma, redis);
    permissionService = new PermissionService(prisma, redis);
  }
  await next();
});

// Get current user's profile
app.get('/', async (c) => {
  const userId = c.get('userId');
  const organizationId = c.get('organizationId');

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
    throw new HTTPException(500, { message: 'Failed to get profile' });
  }
});

// Update current user's profile
app.patch(
  '/',
  zValidator('json', updateUserSchema),
  async (c) => {
    const data = c.req.valid('json');
    const userId = c.get('userId');
    const organizationId = c.get('organizationId');

    try {
      // Users can update their own profile (limited fields)
      const allowedFields = [
        'firstName',
        'lastName',
        'displayName',
        'phone',
        'avatarUrl',
        'bio',
        'preferences'
      ];

      const filteredData = Object.keys(data)
        .filter(key => allowedFields.includes(key))
        .reduce((obj, key) => {
          obj[key] = data[key];
          return obj;
        }, {} as any);

      const user = await userService.updateUser(
        userId,
        organizationId,
        filteredData,
        userId
      );

      return c.json(user);
    } catch (error) {
      if (error instanceof HTTPException) {
        throw error;
      }
      throw new HTTPException(500, { message: 'Failed to update profile' });
    }
  }
);

// Change current user's password
app.post(
  '/change-password',
  zValidator('json', changePasswordSchema),
  async (c) => {
    const data = c.req.valid('json');
    const userId = c.get('userId');
    const organizationId = c.get('organizationId');

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

// Get current user's permissions
app.get('/permissions', async (c) => {
  const userId = c.get('userId');
  const organizationId = c.get('organizationId');

  try {
    const permissions = await permissionService.getUserPermissions(userId, organizationId);
    return c.json(permissions);
  } catch (error) {
    throw new HTTPException(500, { message: 'Failed to get permissions' });
  }
});

// Get current user's roles
app.get('/roles', async (c) => {
  const userId = c.get('userId');
  const organizationId = c.get('organizationId');

  try {
    const user = await userService.getUserById(userId, organizationId);
    if (!user) {
      throw new HTTPException(404, { message: 'User not found' });
    }

    const roles = user.roles?.map(ur => ur.role) || [];
    return c.json(roles);
  } catch (error) {
    throw new HTTPException(500, { message: 'Failed to get roles' });
  }
});

// Upload avatar
app.post('/avatar', async (c) => {
  const userId = c.get('userId');
  const organizationId = c.get('organizationId');

  try {
    // TODO: Implement file upload logic
    // This would typically:
    // 1. Validate the uploaded file (size, type)
    // 2. Upload to S3 or similar storage
    // 3. Update user's avatarUrl
    
    throw new HTTPException(501, { message: 'Avatar upload not implemented' });
  } catch (error) {
    if (error instanceof HTTPException) {
      throw error;
    }
    throw new HTTPException(500, { message: 'Failed to upload avatar' });
  }
});

// Delete avatar
app.delete('/avatar', async (c) => {
  const userId = c.get('userId');
  const organizationId = c.get('organizationId');

  try {
    await userService.updateUser(
      userId,
      organizationId,
      { avatarUrl: null },
      userId
    );

    return c.json({ message: 'Avatar deleted successfully' });
  } catch (error) {
    throw new HTTPException(500, { message: 'Failed to delete avatar' });
  }
});

// Get activity/audit log for current user
app.get('/activity', async (c) => {
  const userId = c.get('userId');
  const organizationId = c.get('organizationId');
  const page = Number(c.req.query('page') || 1);
  const limit = Number(c.req.query('limit') || 20);

  try {
    // TODO: Implement activity log retrieval
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
    throw new HTTPException(500, { message: 'Failed to get activity log' });
  }
});

export default app;