import { Context, Next } from 'hono';
import { verify, sign } from 'hono/jwt';
import { createClient } from 'redis';
import { z } from 'zod';
import { v4 as uuidv4 } from 'uuid';

// Types for JWT payload and user context
interface JWTPayload {
  sub: string; // User ID
  tenantId: string;
  organizationId?: string;
  email: string;
  roles: string[];
  permissions: string[];
  sessionId: string;
  iat: number;
  exp: number;
  type: 'access' | 'refresh';
}

interface UserContext {
  userId: string;
  tenantId: string;
  organizationId?: string;
  email: string;
  roles: string[];
  permissions: string[];
  sessionId: string;
}

// Validation schemas
const authHeaderSchema = z.string().regex(/^Bearer\s+[\w-]+\.[\w-]+\.[\w-]+$/);
const refreshTokenSchema = z.object({
  refreshToken: z.string(),
});

// Redis client for session management
const redisClient = createClient({
  url: process.env.REDIS_URL || 'redis://localhost:6379',
});

// Initialize Redis connection
let redisConnected = false;
redisClient.on('connect', () => {
  redisConnected = true;
  console.log('Redis connected for auth middleware');
});

redisClient.on('error', (err) => {
  console.error('Redis connection error:', err);
  redisConnected = false;
});

// Connect to Redis
redisClient.connect().catch(console.error);

// Configuration - Require environment variables for secrets
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;

if (!JWT_SECRET) {
  throw new Error('JWT_SECRET environment variable is required');
}
if (!JWT_REFRESH_SECRET) {
  throw new Error('JWT_REFRESH_SECRET environment variable is required');
}

const ACCESS_TOKEN_EXPIRY = process.env.ACCESS_TOKEN_EXPIRY || '15m';
const REFRESH_TOKEN_EXPIRY = process.env.REFRESH_TOKEN_EXPIRY || '7d';
const SESSION_EXPIRY = 7 * 24 * 60 * 60; // 7 days in seconds

/**
 * Validates session in Redis
 */
async function validateSession(sessionId: string, userId: string): Promise<boolean> {
  if (!redisConnected) {
    console.warn('Redis not connected, skipping session validation');
    return true; // Allow access if Redis is down
  }

  try {
    const sessionKey = `session:${sessionId}`;
    const sessionData = await redisClient.get(sessionKey);
    
    if (!sessionData) {
      return false;
    }

    const session = JSON.parse(sessionData);
    return session.userId === userId && session.active === true;
  } catch (error) {
    console.error('Session validation error:', error);
    return false;
  }
}

/**
 * Creates or updates session in Redis
 */
async function createSession(sessionId: string, userContext: UserContext): Promise<void> {
  if (!redisConnected) {
    console.warn('Redis not connected, skipping session creation');
    return;
  }

  try {
    const sessionKey = `session:${sessionId}`;
    const sessionData = {
      userId: userContext.userId,
      tenantId: userContext.tenantId,
      organizationId: userContext.organizationId,
      email: userContext.email,
      roles: userContext.roles,
      permissions: userContext.permissions,
      active: true,
      createdAt: new Date().toISOString(),
      lastAccessedAt: new Date().toISOString(),
    };

    await redisClient.setEx(sessionKey, SESSION_EXPIRY, JSON.stringify(sessionData));
  } catch (error) {
    console.error('Session creation error:', error);
  }
}

/**
 * Updates session last accessed time
 */
async function updateSessionAccess(sessionId: string): Promise<void> {
  if (!redisConnected) {
    return;
  }

  try {
    const sessionKey = `session:${sessionId}`;
    const sessionData = await redisClient.get(sessionKey);
    
    if (sessionData) {
      const session = JSON.parse(sessionData);
      session.lastAccessedAt = new Date().toISOString();
      await redisClient.setEx(sessionKey, SESSION_EXPIRY, JSON.stringify(session));
    }
  } catch (error) {
    console.error('Session update error:', error);
  }
}

/**
 * Invalidates session in Redis
 */
async function invalidateSession(sessionId: string): Promise<void> {
  if (!redisConnected) {
    return;
  }

  try {
    const sessionKey = `session:${sessionId}`;
    await redisClient.del(sessionKey);
  } catch (error) {
    console.error('Session invalidation error:', error);
  }
}

/**
 * Generates new access token
 */
async function generateAccessToken(userContext: UserContext): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const expirySeconds = parseExpiry(ACCESS_TOKEN_EXPIRY);
  
  const payload: JWTPayload = {
    sub: userContext.userId,
    tenantId: userContext.tenantId,
    organizationId: userContext.organizationId,
    email: userContext.email,
    roles: userContext.roles,
    permissions: userContext.permissions,
    sessionId: userContext.sessionId,
    type: 'access',
    iat: now,
    exp: now + expirySeconds,
  };

  return await sign(payload, JWT_SECRET);
}

/**
 * Generates new refresh token
 */
async function generateRefreshToken(userContext: UserContext): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const expirySeconds = parseExpiry(REFRESH_TOKEN_EXPIRY);
  
  const payload: JWTPayload = {
    sub: userContext.userId,
    tenantId: userContext.tenantId,
    organizationId: userContext.organizationId,
    email: userContext.email,
    roles: userContext.roles,
    permissions: userContext.permissions,
    sessionId: userContext.sessionId,
    type: 'refresh',
    iat: now,
    exp: now + expirySeconds,
  };

  return await sign(payload, JWT_REFRESH_SECRET);
}

/**
 * Parses expiry string to seconds
 */
function parseExpiry(expiry: string): number {
  const match = expiry.match(/^(\d+)([smhd])$/);
  if (!match) {
    throw new Error(`Invalid expiry format: ${expiry}`);
  }
  
  const value = parseInt(match[1]);
  const unit = match[2];
  
  switch (unit) {
    case 's': return value;
    case 'm': return value * 60;
    case 'h': return value * 60 * 60;
    case 'd': return value * 24 * 60 * 60;
    default: throw new Error(`Invalid expiry unit: ${unit}`);
  }
}

/**
 * Extracts and validates JWT token from Authorization header
 */
async function extractAndValidateToken(authHeader: string): Promise<JWTPayload | null> {
  try {
    // Validate header format
    const validatedHeader = authHeaderSchema.parse(authHeader);
    const token = validatedHeader.replace('Bearer ', '');

    // Verify JWT token
    const payload = await verify(token, JWT_SECRET) as JWTPayload;
    
    // Validate token type
    if (payload.type !== 'access') {
      throw new Error('Invalid token type');
    }

    return payload;
  } catch (error) {
    console.error('Token validation error:', error);
    return null;
  }
}

/**
 * Main JWT authentication middleware
 */
export const authMiddleware = async (c: Context, next: Next) => {
  try {
    // Extract Authorization header
    const authHeader = c.req.header('Authorization');
    
    if (!authHeader) {
      return c.json({
        error: 'Authentication required',
        message: 'Authorization header is missing',
        code: 'AUTH_MISSING_HEADER',
      }, 401);
    }

    // Validate and extract JWT payload
    const payload = await extractAndValidateToken(authHeader);
    
    if (!payload) {
      return c.json({
        error: 'Invalid token',
        message: 'The provided token is invalid or expired',
        code: 'AUTH_INVALID_TOKEN',
      }, 401);
    }

    // Validate session
    const isValidSession = await validateSession(payload.sessionId, payload.sub);
    
    if (!isValidSession) {
      return c.json({
        error: 'Session expired',
        message: 'Your session has expired. Please log in again.',
        code: 'AUTH_SESSION_EXPIRED',
      }, 401);
    }

    // Create user context
    const userContext: UserContext = {
      userId: payload.sub,
      tenantId: payload.tenantId,
      organizationId: payload.organizationId,
      email: payload.email,
      roles: payload.roles,
      permissions: payload.permissions,
      sessionId: payload.sessionId,
    };

    // Set user context in Hono context
    c.set('user', userContext);
    c.set('jwtPayload', payload);

    // Update session last accessed time (async, don't wait)
    updateSessionAccess(payload.sessionId).catch(err => 
      console.error('Failed to update session access:', err)
    );

    // Add user context to request headers for downstream services
    // Note: These headers will be forwarded to backend services
    c.req.raw.headers.set('X-User-ID', userContext.userId);
    c.req.raw.headers.set('X-Tenant-ID', userContext.tenantId);
    c.req.raw.headers.set('X-User-Email', userContext.email);
    c.req.raw.headers.set('X-User-Roles', JSON.stringify(userContext.roles));
    c.req.raw.headers.set('X-User-Permissions', JSON.stringify(userContext.permissions));
    c.req.raw.headers.set('X-Session-ID', userContext.sessionId);
    
    if (userContext.organizationId) {
      c.req.raw.headers.set('X-Organization-ID', userContext.organizationId);
    }

    await next();
  } catch (error) {
    console.error('Authentication middleware error:', error);
    return c.json({
      error: 'Authentication failed',
      message: 'An error occurred during authentication',
      code: 'AUTH_INTERNAL_ERROR',
    }, 500);
  }
};

/**
 * Optional authentication middleware (doesn't fail if no token)
 */
export const optionalAuthMiddleware = async (c: Context, next: Next) => {
  const authHeader = c.req.header('Authorization');
  
  if (authHeader) {
    try {
      const payload = await extractAndValidateToken(authHeader);
      
      if (payload) {
        const isValidSession = await validateSession(payload.sessionId, payload.sub);
        
        if (isValidSession) {
          const userContext: UserContext = {
            userId: payload.sub,
            tenantId: payload.tenantId,
            organizationId: payload.organizationId,
            email: payload.email,
            roles: payload.roles,
            permissions: payload.permissions,
            sessionId: payload.sessionId,
          };

          c.set('user', userContext);
          c.set('jwtPayload', payload);
          
          // Update session
          await updateSessionAccess(payload.sessionId);
        }
      }
    } catch (error) {
      console.error('Optional auth middleware error:', error);
      // Continue without authentication
    }
  }

  await next();
};

/**
 * Token refresh endpoint handler
 */
export const refreshTokenHandler = async (c: Context) => {
  try {
    const body = await c.req.json();
    const { refreshToken } = refreshTokenSchema.parse(body);

    // Verify refresh token
    const payload = await verify(refreshToken, JWT_REFRESH_SECRET) as JWTPayload;
    
    if (payload.type !== 'refresh') {
      throw new Error('Invalid token type');
    }

    // Validate session
    const isValidSession = await validateSession(payload.sessionId, payload.sub);
    
    if (!isValidSession) {
      return c.json({
        error: 'Session expired',
        message: 'Your session has expired. Please log in again.',
        code: 'AUTH_SESSION_EXPIRED',
      }, 401);
    }

    // Create user context
    const userContext: UserContext = {
      userId: payload.sub,
      tenantId: payload.tenantId,
      organizationId: payload.organizationId,
      email: payload.email,
      roles: payload.roles,
      permissions: payload.permissions,
      sessionId: payload.sessionId,
    };

    // Generate new tokens
    const newAccessToken = await generateAccessToken(userContext);
    const newRefreshToken = await generateRefreshToken(userContext);

    // Update session
    await updateSessionAccess(payload.sessionId);

    return c.json({
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
      tokenType: 'Bearer',
      expiresIn: parseExpiry(ACCESS_TOKEN_EXPIRY),
    });
  } catch (error) {
    console.error('Token refresh error:', error);
    return c.json({
      error: 'Token refresh failed',
      message: 'Unable to refresh token. Please log in again.',
      code: 'AUTH_REFRESH_FAILED',
    }, 401);
  }
};

/**
 * Logout handler
 */
export const logoutHandler = async (c: Context) => {
  try {
    const user = c.get('user') as UserContext;
    
    if (user?.sessionId) {
      await invalidateSession(user.sessionId);
    }

    return c.json({
      message: 'Logged out successfully',
    });
  } catch (error) {
    console.error('Logout error:', error);
    return c.json({
      error: 'Logout failed',
      message: 'An error occurred during logout',
      code: 'AUTH_LOGOUT_FAILED',
    }, 500);
  }
};

/**
 * Permission checking middleware
 */
export const requirePermission = (permission: string) => {
  return async (c: Context, next: Next) => {
    const user = c.get('user') as UserContext;
    
    if (!user) {
      return c.json({
        error: 'Authentication required',
        message: 'You must be authenticated to access this resource',
        code: 'AUTH_REQUIRED',
      }, 401);
    }

    if (!user.permissions.includes(permission)) {
      return c.json({
        error: 'Insufficient permissions',
        message: `You don't have the required permission: ${permission}`,
        code: 'AUTH_INSUFFICIENT_PERMISSIONS',
      }, 403);
    }

    await next();
  };
};

/**
 * Role checking middleware
 */
export const requireRole = (role: string) => {
  return async (c: Context, next: Next) => {
    const user = c.get('user') as UserContext;
    
    if (!user) {
      return c.json({
        error: 'Authentication required',
        message: 'You must be authenticated to access this resource',
        code: 'AUTH_REQUIRED',
      }, 401);
    }

    if (!user.roles.includes(role)) {
      return c.json({
        error: 'Insufficient role',
        message: `You don't have the required role: ${role}`,
        code: 'AUTH_INSUFFICIENT_ROLE',
      }, 403);
    }

    await next();
  };
};

/**
 * Tenant isolation middleware
 */
export const requireTenant = async (c: Context, next: Next) => {
  const user = c.get('user') as UserContext;
  
  if (!user?.tenantId) {
    return c.json({
      error: 'Tenant context required',
      message: 'A valid tenant context is required for this operation',
      code: 'AUTH_TENANT_REQUIRED',
    }, 400);
  }

  await next();
};

/**
 * Tenant validation middleware - ensures user belongs to specified tenant
 */
export const validateTenantAccess = (allowedTenantId?: string) => {
  return async (c: Context, next: Next) => {
    const user = c.get('user') as UserContext;
    
    if (!user) {
      return c.json({
        error: 'Authentication required',
        message: 'You must be authenticated to access this resource',
        code: 'AUTH_REQUIRED',
      }, 401);
    }

    // If specific tenant is required, validate access
    if (allowedTenantId && user.tenantId !== allowedTenantId) {
      return c.json({
        error: 'Tenant access denied',
        message: 'You do not have access to this tenant',
        code: 'AUTH_TENANT_ACCESS_DENIED',
      }, 403);
    }

    await next();
  };
};

/**
 * Multi-permission checking middleware
 */
export const requireAnyPermission = (permissions: string[]) => {
  return async (c: Context, next: Next) => {
    const user = c.get('user') as UserContext;
    
    if (!user) {
      return c.json({
        error: 'Authentication required',
        message: 'You must be authenticated to access this resource',
        code: 'AUTH_REQUIRED',
      }, 401);
    }

    const hasPermission = permissions.some(permission => 
      user.permissions.includes(permission)
    );

    if (!hasPermission) {
      return c.json({
        error: 'Insufficient permissions',
        message: `You need one of these permissions: ${permissions.join(', ')}`,
        code: 'AUTH_INSUFFICIENT_PERMISSIONS',
      }, 403);
    }

    await next();
  };
};

/**
 * Multi-role checking middleware
 */
export const requireAnyRole = (roles: string[]) => {
  return async (c: Context, next: Next) => {
    const user = c.get('user') as UserContext;
    
    if (!user) {
      return c.json({
        error: 'Authentication required',
        message: 'You must be authenticated to access this resource',
        code: 'AUTH_REQUIRED',
      }, 401);
    }

    const hasRole = roles.some(role => user.roles.includes(role));

    if (!hasRole) {
      return c.json({
        error: 'Insufficient role',
        message: `You need one of these roles: ${roles.join(', ')}`,
        code: 'AUTH_INSUFFICIENT_ROLE',
      }, 403);
    }

    await next();
  };
};

// Export utility functions for session management
export {
  validateSession,
  createSession,
  updateSessionAccess,
  invalidateSession,
  generateAccessToken,
  generateRefreshToken,
};

// Export types
export type { JWTPayload, UserContext };
