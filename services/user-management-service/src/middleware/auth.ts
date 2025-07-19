import { Context, Next } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { verify } from 'hono/jwt';
import { config } from '@sparc/shared';

export const authMiddleware = async (c: Context, next: Next) => {
  try {
    // Get token from Authorization header
    const authorization = c.req.header('Authorization');
    if (!authorization) {
      throw new HTTPException(401, { message: 'Authorization header required' });
    }

    const token = authorization.replace('Bearer ', '');
    if (!token) {
      throw new HTTPException(401, { message: 'Token required' });
    }

    // Verify token
    const payload = await verify(token, config.jwt?.accessTokenSecret || process.env.JWT_SECRET!);

    if (!payload) {
      throw new HTTPException(401, { message: 'Invalid token' });
    }

    // Check if token is expired
    if (payload.exp && payload.exp * 1000 < Date.now()) {
      throw new HTTPException(401, { message: 'Token expired' });
    }

    // Set user context
    c.set('userId', payload.sub);
    c.set('organizationId', payload.organizationId);
    c.set('email', payload.email);
    c.set('roles', payload.roles || []);

    // Check if user is active (optional - could check Redis blacklist)
    const redis = c.get('redis');
    if (redis) {
      const isBlacklisted = await redis.get(`blacklist:user:${payload.sub}`);
      if (isBlacklisted) {
        throw new HTTPException(401, { message: 'User account is suspended' });
      }
    }

    await next();
  } catch (error) {
    if (error instanceof HTTPException) {
      throw error;
    }
    throw new HTTPException(401, { message: 'Authentication failed' });
  }
};

// Permission checking middleware
export const requirePermission = (resource: string, action: string) => {
  return async (c: Context, next: Next) => {
    const userId = c.get('userId');
    const organizationId = c.get('organizationId');

    if (!userId || !organizationId) {
      throw new HTTPException(401, { message: 'Authentication required' });
    }

    // Get permission service from context
    const { permissionService } = c.get('services');
    
    if (!permissionService) {
      // If no permission service available, allow access (development mode)
      console.warn('Permission service not available, allowing access');
      await next();
      return;
    }

    // Extract context from request (e.g., siteId, zoneId)
    const context: Record<string, any> = {};
    if (c.req.param('siteId')) {
      context.siteId = c.req.param('siteId');
    }
    if (c.req.param('zoneId')) {
      context.zoneId = c.req.param('zoneId');
    }

    // Check permission
    const hasPermission = await permissionService.checkUserPermission(
      userId,
      organizationId,
      resource,
      action,
      context
    );

    if (!hasPermission) {
      throw new HTTPException(403, { 
        message: `Permission denied: ${resource}:${action}` 
      });
    }

    await next();
  };
};

// Role checking middleware
export const requireRole = (roleNames: string[]) => {
  return async (c: Context, next: Next) => {
    const userId = c.get('userId');
    const organizationId = c.get('organizationId');
    const userRoles = c.get('roles') || [];

    if (!userId || !organizationId) {
      throw new HTTPException(401, { message: 'Authentication required' });
    }

    // Check if user has any of the required roles
    const hasRole = roleNames.some(roleName => 
      userRoles.some((role: any) => role.name === roleName)
    );

    if (!hasRole) {
      throw new HTTPException(403, { 
        message: `Required role(s): ${roleNames.join(', ')}` 
      });
    }

    await next();
  };
};

// Organization context middleware
export const organizationContext = async (c: Context, next: Next) => {
  const organizationId = c.get('organizationId');
  
  if (!organizationId) {
    throw new HTTPException(403, { message: 'Organization context required' });
  }

  // Optionally validate organization exists and is active
  const prisma = c.get('prisma');
  if (prisma) {
    const organization = await prisma.organizations.findUnique({
      where: { id: organizationId }
    });

    if (!organization) {
      throw new HTTPException(403, { message: 'Invalid organization' });
    }

    if (!organization.isActive) {
      throw new HTTPException(403, { message: 'Organization is inactive' });
    }

    c.set('organization', organization);
  }

  await next();
};