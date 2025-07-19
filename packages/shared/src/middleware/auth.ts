/**
 * Shared Authentication Middleware
 * 
 * This middleware provides JWT validation and blacklist checking
 * for all SPARC services.
 */

import { Context, Next } from 'hono';
import jwt from 'jsonwebtoken';
import { Redis } from 'ioredis';
import { JWTBlacklistService } from '../utils/jwt-blacklist';
import { validateEnvironment } from '../utils/env-validation';

export interface AuthMiddlewareOptions {
  redis: Redis;
  jwtSecret?: string;
  jwtRefreshSecret?: string;
  requireAuth?: boolean;
  allowServiceTokens?: boolean;
  requiredRoles?: string[];
  requiredPermissions?: string[];
  skipPaths?: string[];
}

export interface JWTPayload {
  sub: string; // User ID
  email: string;
  tenantId: string;
  role: string;
  permissions: string[];
  type: 'access' | 'refresh' | 'service';
  sessionId?: string;
  serviceId?: string; // For service-to-service auth
  iat: number;
  exp: number;
  jti: string;
}

/**
 * Create authentication middleware for Hono
 */
export function createAuthMiddleware(options: AuthMiddlewareOptions) {
  // Validate environment on initialization
  const jwtSecret = options.jwtSecret || process.env.JWT_SECRET;
  const jwtRefreshSecret = options.jwtRefreshSecret || process.env.JWT_REFRESH_SECRET;

  if (!jwtSecret) {
    throw new Error('JWT_SECRET is required for auth middleware');
  }

  // Initialize blacklist service
  const blacklistService = new JWTBlacklistService({
    redis: options.redis,
    keyPrefix: 'jwt:blacklist',
    defaultTTL: 86400 // 24 hours
  });

  return async (c: Context, next: Next) => {
    const path = c.req.path;
    const method = c.req.method;

    // Skip authentication for certain paths
    if (options.skipPaths?.some(skip => path.startsWith(skip))) {
      return next();
    }

    // Skip authentication for health checks
    if (path === '/health' || path === '/ready' || path === '/metrics') {
      return next();
    }

    // Extract token from various sources
    const token = extractToken(c);

    if (!token) {
      if (options.requireAuth !== false) {
        return c.json({
          error: {
            code: 'AUTH_TOKEN_REQUIRED',
            message: 'Authentication token is required',
            timestamp: new Date().toISOString()
          }
        }, 401);
      }
      return next();
    }

    try {
      // Check if token is blacklisted
      const isBlacklisted = await blacklistService.isBlacklisted(token);
      if (isBlacklisted) {
        return c.json({
          error: {
            code: 'TOKEN_REVOKED',
            message: 'Token has been revoked',
            timestamp: new Date().toISOString()
          }
        }, 401);
      }

      // Verify token
      const secret = token.startsWith('srv_') ? jwtSecret : jwtSecret; // Use same secret for now
      const payload = jwt.verify(token, secret) as JWTPayload;

      // Validate token type
      if (payload.type === 'refresh' && path !== '/refresh-token') {
        return c.json({
          error: {
            code: 'INVALID_TOKEN_TYPE',
            message: 'Refresh token cannot be used for API access',
            timestamp: new Date().toISOString()
          }
        }, 401);
      }

      // Check if service tokens are allowed
      if (payload.type === 'service' && !options.allowServiceTokens) {
        return c.json({
          error: {
            code: 'SERVICE_TOKEN_NOT_ALLOWED',
            message: 'Service tokens are not allowed for this endpoint',
            timestamp: new Date().toISOString()
          }
        }, 403);
      }

      // Check required roles
      if (options.requiredRoles && options.requiredRoles.length > 0) {
        if (!options.requiredRoles.includes(payload.role)) {
          return c.json({
            error: {
              code: 'INSUFFICIENT_ROLE',
              message: 'Insufficient role privileges',
              timestamp: new Date().toISOString()
            }
          }, 403);
        }
      }

      // Check required permissions
      if (options.requiredPermissions && options.requiredPermissions.length > 0) {
        const hasAllPermissions = options.requiredPermissions.every(
          perm => payload.permissions.includes(perm)
        );

        if (!hasAllPermissions) {
          return c.json({
            error: {
              code: 'INSUFFICIENT_PERMISSIONS',
              message: 'Insufficient permissions',
              timestamp: new Date().toISOString()
            }
          }, 403);
        }
      }

      // Add user/service info to context
      c.set('user', payload);
      c.set('userId', payload.sub);
      c.set('tenantId', payload.tenantId);
      c.set('userRole', payload.role);
      c.set('isServiceToken', payload.type === 'service');

      // Add session validation for user tokens
      if (payload.type === 'access' && payload.sessionId) {
        // Check if session exists in Redis
        const sessionKey = `session:${payload.sub}:${payload.tenantId}:${payload.sessionId}`;
        const sessionExists = await options.redis.exists(sessionKey);

        if (!sessionExists) {
          return c.json({
            error: {
              code: 'SESSION_EXPIRED',
              message: 'Session has expired or been revoked',
              timestamp: new Date().toISOString()
            }
          }, 401);
        }

        // Update session last activity
        await options.redis.expire(sessionKey, 7 * 24 * 60 * 60); // Extend for 7 days
      }

      return next();

    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        return c.json({
          error: {
            code: 'TOKEN_EXPIRED',
            message: 'Token has expired',
            timestamp: new Date().toISOString()
          }
        }, 401);
      }

      if (error instanceof jwt.JsonWebTokenError) {
        return c.json({
          error: {
            code: 'INVALID_TOKEN',
            message: 'Invalid token',
            timestamp: new Date().toISOString()
          }
        }, 401);
      }

      // Log unexpected errors
      console.error('Auth middleware error:', error);

      return c.json({
        error: {
          code: 'AUTH_ERROR',
          message: 'Authentication failed',
          timestamp: new Date().toISOString()
        }
      }, 401);
    }
  };
}

/**
 * Extract token from request
 */
function extractToken(c: Context): string | null {
  // 1. Check Authorization header
  const authHeader = c.req.header('Authorization');
  if (authHeader?.startsWith('Bearer ')) {
    return authHeader.slice(7);
  }

  // 2. Check cookies
  const cookieHeader = c.req.header('Cookie');
  if (cookieHeader) {
    const cookies = parseCookies(cookieHeader);
    if (cookies.accessToken) {
      return cookies.accessToken;
    }
  }

  // 3. Check query parameter (for specific use cases like downloads)
  const url = new URL(c.req.url);
  const queryToken = url.searchParams.get('token');
  if (queryToken) {
    return queryToken;
  }

  // 4. Check custom header for service-to-service auth
  const serviceToken = c.req.header('X-Service-Token');
  if (serviceToken) {
    return serviceToken;
  }

  return null;
}

/**
 * Parse cookies from header
 */
function parseCookies(cookieHeader: string): Record<string, string> {
  const cookies: Record<string, string> = {};
  
  cookieHeader.split(';').forEach(cookie => {
    const [name, value] = cookie.trim().split('=');
    if (name && value) {
      cookies[name] = decodeURIComponent(value);
    }
  });

  return cookies;
}

/**
 * Role-based middleware factory
 */
export function requireRole(...roles: string[]) {
  return async (c: Context, next: Next) => {
    const user = c.get('user') as JWTPayload | undefined;
    
    if (!user) {
      return c.json({
        error: {
          code: 'AUTH_REQUIRED',
          message: 'Authentication required',
          timestamp: new Date().toISOString()
        }
      }, 401);
    }

    if (!roles.includes(user.role)) {
      return c.json({
        error: {
          code: 'INSUFFICIENT_ROLE',
          message: `One of these roles required: ${roles.join(', ')}`,
          timestamp: new Date().toISOString()
        }
      }, 403);
    }

    return next();
  };
}

/**
 * Permission-based middleware factory
 */
export function requirePermission(...permissions: string[]) {
  return async (c: Context, next: Next) => {
    const user = c.get('user') as JWTPayload | undefined;
    
    if (!user) {
      return c.json({
        error: {
          code: 'AUTH_REQUIRED',
          message: 'Authentication required',
          timestamp: new Date().toISOString()
        }
      }, 401);
    }

    const hasAllPermissions = permissions.every(
      perm => user.permissions.includes(perm)
    );

    if (!hasAllPermissions) {
      return c.json({
        error: {
          code: 'INSUFFICIENT_PERMISSIONS',
          message: `Required permissions: ${permissions.join(', ')}`,
          timestamp: new Date().toISOString()
        }
      }, 403);
    }

    return next();
  };
}

/**
 * Tenant isolation middleware
 */
export function requireTenantAccess() {
  return async (c: Context, next: Next) => {
    const user = c.get('user') as JWTPayload | undefined;
    const requestTenantId = c.req.header('X-Tenant-ID') || c.req.param('tenantId');
    
    if (!user) {
      return c.json({
        error: {
          code: 'AUTH_REQUIRED',
          message: 'Authentication required',
          timestamp: new Date().toISOString()
        }
      }, 401);
    }

    // Super admins can access any tenant
    if (user.role === 'SUPER_ADMIN') {
      if (requestTenantId) {
        c.set('tenantId', requestTenantId);
      }
      return next();
    }

    // Service tokens can access any tenant
    if (user.type === 'service') {
      if (requestTenantId) {
        c.set('tenantId', requestTenantId);
      }
      return next();
    }

    // Regular users can only access their own tenant
    if (requestTenantId && requestTenantId !== user.tenantId) {
      return c.json({
        error: {
          code: 'TENANT_ACCESS_DENIED',
          message: 'Access denied to this tenant',
          timestamp: new Date().toISOString()
        }
      }, 403);
    }

    return next();
  };
}

/**
 * Rate limiting middleware (integrates with auth)
 */
export function createRateLimitMiddleware(options: {
  redis: Redis;
  windowMs?: number;
  maxRequests?: number;
  keyGenerator?: (c: Context) => string;
}) {
  const {
    redis,
    windowMs = 15 * 60 * 1000, // 15 minutes
    maxRequests = 100,
    keyGenerator = (c) => {
      const user = c.get('user') as JWTPayload | undefined;
      return user ? `rate:${user.sub}` : `rate:${c.req.header('CF-Connecting-IP') || 'unknown'}`;
    }
  } = options;

  return async (c: Context, next: Next) => {
    const key = keyGenerator(c);
    const now = Date.now();
    const windowStart = now - windowMs;

    // Remove old entries
    await redis.zremrangebyscore(key, 0, windowStart);

    // Count requests in current window
    const requestCount = await redis.zcard(key);

    if (requestCount >= maxRequests) {
      const oldestRequest = await redis.zrange(key, 0, 0, 'WITHSCORES');
      const resetTime = oldestRequest.length > 1 
        ? parseInt(oldestRequest[1]) + windowMs
        : now + windowMs;

      return c.json({
        error: {
          code: 'RATE_LIMIT_EXCEEDED',
          message: 'Too many requests',
          timestamp: new Date().toISOString(),
          retryAfter: Math.ceil((resetTime - now) / 1000)
        }
      }, 429);
    }

    // Add current request
    await redis.zadd(key, now, `${now}-${Math.random()}`);
    await redis.expire(key, Math.ceil(windowMs / 1000));

    // Add rate limit headers
    c.header('X-RateLimit-Limit', maxRequests.toString());
    c.header('X-RateLimit-Remaining', (maxRequests - requestCount - 1).toString());
    c.header('X-RateLimit-Reset', new Date(now + windowMs).toISOString());

    return next();
  };
}