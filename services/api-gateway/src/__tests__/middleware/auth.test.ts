import { describe, it, expect, jest, beforeEach, afterEach } from '@jest/globals';
import { Context } from 'hono';
import { sign } from 'hono/jwt';
import { createClient } from 'redis';
import {
  authMiddleware,
  optionalAuthMiddleware,
  refreshTokenHandler,
  logoutHandler,
  requirePermission,
  requireRole,
  requireTenant,
  validateTenantAccess,
  requireAnyPermission,
  requireAnyRole,
  validateSession,
  createSession,
  updateSessionAccess,
  invalidateSession,
  generateAccessToken,
  generateRefreshToken,
  type JWTPayload,
  type UserContext,
} from '../../middleware/auth';

// Mock Redis
jest.mock('redis', () => ({
  createClient: jest.fn(),
}));

// Mock environment variables
const originalEnv = process.env;
beforeEach(() => {
  process.env = {
    ...originalEnv,
    JWT_SECRET: 'test-secret',
    JWT_REFRESH_SECRET: 'test-refresh-secret',
    REDIS_URL: 'redis://localhost:6379',
    ACCESS_TOKEN_EXPIRY: '15m',
    REFRESH_TOKEN_EXPIRY: '7d',
  };
});

afterEach(() => {
  process.env = originalEnv;
  jest.clearAllMocks();
});

describe('Auth Middleware', () => {
  let mockContext: Context;
  let mockNext: jest.Mock;
  let mockRedisClient: any;

  beforeEach(() => {
    // Setup mock Redis client
    mockRedisClient = {
      connect: jest.fn().mockResolvedValue(undefined),
      on: jest.fn(),
      get: jest.fn(),
      setEx: jest.fn(),
      del: jest.fn(),
    };
    (createClient as jest.Mock).mockReturnValue(mockRedisClient);

    // Setup mock context
    mockContext = {
      req: {
        header: jest.fn(),
        json: jest.fn(),
        raw: {
          headers: new Map(),
        },
      },
      json: jest.fn().mockReturnValue({ json: true }),
      set: jest.fn(),
      get: jest.fn(),
    } as any;

    mockNext = jest.fn().mockResolvedValue(undefined);
  });

  describe('authMiddleware', () => {
    it('should reject request without Authorization header', async () => {
      mockContext.req.header = jest.fn().mockReturnValue(undefined);

      await authMiddleware(mockContext, mockNext);

      expect(mockContext.json).toHaveBeenCalledWith({
        error: 'Authentication required',
        message: 'Authorization header is missing',
        code: 'AUTH_MISSING_HEADER',
      }, 401);
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should reject request with invalid Authorization header format', async () => {
      mockContext.req.header = jest.fn().mockReturnValue('InvalidFormat');

      await authMiddleware(mockContext, mockNext);

      expect(mockContext.json).toHaveBeenCalledWith({
        error: 'Invalid token',
        message: 'The provided token is invalid or expired',
        code: 'AUTH_INVALID_TOKEN',
      }, 401);
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should reject request with invalid JWT token', async () => {
      mockContext.req.header = jest.fn().mockReturnValue('Bearer invalid.jwt.token');

      await authMiddleware(mockContext, mockNext);

      expect(mockContext.json).toHaveBeenCalledWith({
        error: 'Invalid token',
        message: 'The provided token is invalid or expired',
        code: 'AUTH_INVALID_TOKEN',
      }, 401);
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should accept valid access token and set user context', async () => {
      const userContext: UserContext = {
        userId: 'user-123',
        tenantId: 'tenant-456',
        organizationId: 'org-789',
        email: 'test@example.com',
        roles: ['user', 'admin'],
        permissions: ['read', 'write'],
        sessionId: 'session-abc',
      };

      const payload: JWTPayload = {
        sub: userContext.userId,
        tenantId: userContext.tenantId,
        organizationId: userContext.organizationId,
        email: userContext.email,
        roles: userContext.roles,
        permissions: userContext.permissions,
        sessionId: userContext.sessionId,
        type: 'access',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 900, // 15 minutes
      };

      const token = await sign(payload, 'test-secret');
      mockContext.req.header = jest.fn().mockReturnValue(`Bearer ${token}`);

      // Mock successful session validation
      mockRedisClient.get.mockResolvedValue(JSON.stringify({
        userId: userContext.userId,
        active: true,
      }));

      await authMiddleware(mockContext, mockNext);

      expect(mockContext.set).toHaveBeenCalledWith('user', userContext);
      expect(mockContext.set).toHaveBeenCalledWith('jwtPayload', expect.objectContaining({
        sub: userContext.userId,
        tenantId: userContext.tenantId,
      }));
      expect(mockNext).toHaveBeenCalled();
    });

    it('should reject token with invalid session', async () => {
      const payload: JWTPayload = {
        sub: 'user-123',
        tenantId: 'tenant-456',
        email: 'test@example.com',
        roles: ['user'],
        permissions: ['read'],
        sessionId: 'session-abc',
        type: 'access',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 900,
      };

      const token = await sign(payload, 'test-secret');
      mockContext.req.header = jest.fn().mockReturnValue(`Bearer ${token}`);

      // Mock invalid session
      mockRedisClient.get.mockResolvedValue(null);

      await authMiddleware(mockContext, mockNext);

      expect(mockContext.json).toHaveBeenCalledWith({
        error: 'Session expired',
        message: 'Your session has expired. Please log in again.',
        code: 'AUTH_SESSION_EXPIRED',
      }, 401);
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should reject refresh token when access token is expected', async () => {
      const payload: JWTPayload = {
        sub: 'user-123',
        tenantId: 'tenant-456',
        email: 'test@example.com',
        roles: ['user'],
        permissions: ['read'],
        sessionId: 'session-abc',
        type: 'refresh', // Wrong type
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 900,
      };

      const token = await sign(payload, 'test-secret');
      mockContext.req.header = jest.fn().mockReturnValue(`Bearer ${token}`);

      await authMiddleware(mockContext, mockNext);

      expect(mockContext.json).toHaveBeenCalledWith({
        error: 'Invalid token',
        message: 'The provided token is invalid or expired',
        code: 'AUTH_INVALID_TOKEN',
      }, 401);
    });

    it('should handle Redis connection errors gracefully', async () => {
      const payload: JWTPayload = {
        sub: 'user-123',
        tenantId: 'tenant-456',
        email: 'test@example.com',
        roles: ['user'],
        permissions: ['read'],
        sessionId: 'session-abc',
        type: 'access',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 900,
      };

      const token = await sign(payload, 'test-secret');
      mockContext.req.header = jest.fn().mockReturnValue(`Bearer ${token}`);

      // Mock Redis error
      mockRedisClient.get.mockRejectedValue(new Error('Redis connection failed'));

      await authMiddleware(mockContext, mockNext);

      expect(mockContext.json).toHaveBeenCalledWith({
        error: 'Session expired',
        message: 'Your session has expired. Please log in again.',
        code: 'AUTH_SESSION_EXPIRED',
      }, 401);
    });
  });

  describe('optionalAuthMiddleware', () => {
    it('should continue without authentication when no header is provided', async () => {
      mockContext.req.header = jest.fn().mockReturnValue(undefined);

      await optionalAuthMiddleware(mockContext, mockNext);

      expect(mockContext.set).not.toHaveBeenCalled();
      expect(mockNext).toHaveBeenCalled();
    });

    it('should set user context when valid token is provided', async () => {
      const userContext: UserContext = {
        userId: 'user-123',
        tenantId: 'tenant-456',
        email: 'test@example.com',
        roles: ['user'],
        permissions: ['read'],
        sessionId: 'session-abc',
      };

      const payload: JWTPayload = {
        sub: userContext.userId,
        tenantId: userContext.tenantId,
        email: userContext.email,
        roles: userContext.roles,
        permissions: userContext.permissions,
        sessionId: userContext.sessionId,
        type: 'access',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 900,
      };

      const token = await sign(payload, 'test-secret');
      mockContext.req.header = jest.fn().mockReturnValue(`Bearer ${token}`);

      mockRedisClient.get.mockResolvedValue(JSON.stringify({
        userId: userContext.userId,
        active: true,
      }));

      await optionalAuthMiddleware(mockContext, mockNext);

      expect(mockContext.set).toHaveBeenCalledWith('user', userContext);
      expect(mockNext).toHaveBeenCalled();
    });

    it('should continue without authentication when token is invalid', async () => {
      mockContext.req.header = jest.fn().mockReturnValue('Bearer invalid.token');

      await optionalAuthMiddleware(mockContext, mockNext);

      expect(mockContext.set).not.toHaveBeenCalled();
      expect(mockNext).toHaveBeenCalled();
    });
  });

  describe('refreshTokenHandler', () => {
    it('should generate new tokens with valid refresh token', async () => {
      const userContext: UserContext = {
        userId: 'user-123',
        tenantId: 'tenant-456',
        email: 'test@example.com',
        roles: ['user'],
        permissions: ['read'],
        sessionId: 'session-abc',
      };

      const payload: JWTPayload = {
        sub: userContext.userId,
        tenantId: userContext.tenantId,
        email: userContext.email,
        roles: userContext.roles,
        permissions: userContext.permissions,
        sessionId: userContext.sessionId,
        type: 'refresh',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 86400 * 7, // 7 days
      };

      const refreshToken = await sign(payload, 'test-refresh-secret');
      mockContext.req.json = jest.fn().mockResolvedValue({ refreshToken });

      mockRedisClient.get.mockResolvedValue(JSON.stringify({
        userId: userContext.userId,
        active: true,
      }));

      await refreshTokenHandler(mockContext);

      expect(mockContext.json).toHaveBeenCalledWith(
        expect.objectContaining({
          accessToken: expect.any(String),
          refreshToken: expect.any(String),
          tokenType: 'Bearer',
          expiresIn: 900, // 15 minutes
        })
      );
    });

    it('should reject invalid refresh token', async () => {
      mockContext.req.json = jest.fn().mockResolvedValue({ 
        refreshToken: 'invalid.refresh.token' 
      });

      await refreshTokenHandler(mockContext);

      expect(mockContext.json).toHaveBeenCalledWith({
        error: 'Token refresh failed',
        message: 'Unable to refresh token. Please log in again.',
        code: 'AUTH_REFRESH_FAILED',
      }, 401);
    });

    it('should reject access token used as refresh token', async () => {
      const payload: JWTPayload = {
        sub: 'user-123',
        tenantId: 'tenant-456',
        email: 'test@example.com',
        roles: ['user'],
        permissions: ['read'],
        sessionId: 'session-abc',
        type: 'access', // Wrong type
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 900,
      };

      const token = await sign(payload, 'test-refresh-secret');
      mockContext.req.json = jest.fn().mockResolvedValue({ refreshToken: token });

      await refreshTokenHandler(mockContext);

      expect(mockContext.json).toHaveBeenCalledWith({
        error: 'Token refresh failed',
        message: 'Unable to refresh token. Please log in again.',
        code: 'AUTH_REFRESH_FAILED',
      }, 401);
    });
  });

  describe('logoutHandler', () => {
    it('should invalidate session on logout', async () => {
      const userContext: UserContext = {
        userId: 'user-123',
        tenantId: 'tenant-456',
        email: 'test@example.com',
        roles: ['user'],
        permissions: ['read'],
        sessionId: 'session-abc',
      };

      mockContext.get = jest.fn().mockReturnValue(userContext);

      await logoutHandler(mockContext);

      expect(mockRedisClient.del).toHaveBeenCalledWith('session:session-abc');
      expect(mockContext.json).toHaveBeenCalledWith({
        message: 'Logged out successfully',
      });
    });

    it('should handle logout without session gracefully', async () => {
      mockContext.get = jest.fn().mockReturnValue(null);

      await logoutHandler(mockContext);

      expect(mockRedisClient.del).not.toHaveBeenCalled();
      expect(mockContext.json).toHaveBeenCalledWith({
        message: 'Logged out successfully',
      });
    });
  });

  describe('Permission and Role Middlewares', () => {
    describe('requirePermission', () => {
      it('should allow access with required permission', async () => {
        const userContext: UserContext = {
          userId: 'user-123',
          tenantId: 'tenant-456',
          email: 'test@example.com',
          roles: ['user'],
          permissions: ['read', 'write'],
          sessionId: 'session-abc',
        };

        mockContext.get = jest.fn().mockReturnValue(userContext);

        const middleware = requirePermission('write');
        await middleware(mockContext, mockNext);

        expect(mockNext).toHaveBeenCalled();
      });

      it('should deny access without required permission', async () => {
        const userContext: UserContext = {
          userId: 'user-123',
          tenantId: 'tenant-456',
          email: 'test@example.com',
          roles: ['user'],
          permissions: ['read'],
          sessionId: 'session-abc',
        };

        mockContext.get = jest.fn().mockReturnValue(userContext);

        const middleware = requirePermission('write');
        await middleware(mockContext, mockNext);

        expect(mockContext.json).toHaveBeenCalledWith({
          error: 'Insufficient permissions',
          message: "You don't have the required permission: write",
          code: 'AUTH_INSUFFICIENT_PERMISSIONS',
        }, 403);
        expect(mockNext).not.toHaveBeenCalled();
      });

      it('should require authentication', async () => {
        mockContext.get = jest.fn().mockReturnValue(null);

        const middleware = requirePermission('write');
        await middleware(mockContext, mockNext);

        expect(mockContext.json).toHaveBeenCalledWith({
          error: 'Authentication required',
          message: 'You must be authenticated to access this resource',
          code: 'AUTH_REQUIRED',
        }, 401);
      });
    });

    describe('requireRole', () => {
      it('should allow access with required role', async () => {
        const userContext: UserContext = {
          userId: 'user-123',
          tenantId: 'tenant-456',
          email: 'test@example.com',
          roles: ['user', 'admin'],
          permissions: ['read'],
          sessionId: 'session-abc',
        };

        mockContext.get = jest.fn().mockReturnValue(userContext);

        const middleware = requireRole('admin');
        await middleware(mockContext, mockNext);

        expect(mockNext).toHaveBeenCalled();
      });

      it('should deny access without required role', async () => {
        const userContext: UserContext = {
          userId: 'user-123',
          tenantId: 'tenant-456',
          email: 'test@example.com',
          roles: ['user'],
          permissions: ['read'],
          sessionId: 'session-abc',
        };

        mockContext.get = jest.fn().mockReturnValue(userContext);

        const middleware = requireRole('admin');
        await middleware(mockContext, mockNext);

        expect(mockContext.json).toHaveBeenCalledWith({
          error: 'Insufficient role',
          message: "You don't have the required role: admin",
          code: 'AUTH_INSUFFICIENT_ROLE',
        }, 403);
      });
    });

    describe('requireAnyPermission', () => {
      it('should allow access with any of the required permissions', async () => {
        const userContext: UserContext = {
          userId: 'user-123',
          tenantId: 'tenant-456',
          email: 'test@example.com',
          roles: ['user'],
          permissions: ['read', 'list'],
          sessionId: 'session-abc',
        };

        mockContext.get = jest.fn().mockReturnValue(userContext);

        const middleware = requireAnyPermission(['write', 'delete', 'list']);
        await middleware(mockContext, mockNext);

        expect(mockNext).toHaveBeenCalled();
      });

      it('should deny access without any required permissions', async () => {
        const userContext: UserContext = {
          userId: 'user-123',
          tenantId: 'tenant-456',
          email: 'test@example.com',
          roles: ['user'],
          permissions: ['read'],
          sessionId: 'session-abc',
        };

        mockContext.get = jest.fn().mockReturnValue(userContext);

        const middleware = requireAnyPermission(['write', 'delete']);
        await middleware(mockContext, mockNext);

        expect(mockContext.json).toHaveBeenCalledWith({
          error: 'Insufficient permissions',
          message: 'You need one of these permissions: write, delete',
          code: 'AUTH_INSUFFICIENT_PERMISSIONS',
        }, 403);
      });
    });

    describe('requireAnyRole', () => {
      it('should allow access with any of the required roles', async () => {
        const userContext: UserContext = {
          userId: 'user-123',
          tenantId: 'tenant-456',
          email: 'test@example.com',
          roles: ['moderator'],
          permissions: ['read'],
          sessionId: 'session-abc',
        };

        mockContext.get = jest.fn().mockReturnValue(userContext);

        const middleware = requireAnyRole(['admin', 'moderator']);
        await middleware(mockContext, mockNext);

        expect(mockNext).toHaveBeenCalled();
      });
    });
  });

  describe('Tenant Middlewares', () => {
    describe('requireTenant', () => {
      it('should allow access with tenant context', async () => {
        const userContext: UserContext = {
          userId: 'user-123',
          tenantId: 'tenant-456',
          email: 'test@example.com',
          roles: ['user'],
          permissions: ['read'],
          sessionId: 'session-abc',
        };

        mockContext.get = jest.fn().mockReturnValue(userContext);

        await requireTenant(mockContext, mockNext);

        expect(mockNext).toHaveBeenCalled();
      });

      it('should deny access without tenant context', async () => {
        const userContext = {
          userId: 'user-123',
          email: 'test@example.com',
          roles: ['user'],
          permissions: ['read'],
          sessionId: 'session-abc',
        };

        mockContext.get = jest.fn().mockReturnValue(userContext);

        await requireTenant(mockContext, mockNext);

        expect(mockContext.json).toHaveBeenCalledWith({
          error: 'Tenant context required',
          message: 'A valid tenant context is required for this operation',
          code: 'AUTH_TENANT_REQUIRED',
        }, 400);
      });
    });

    describe('validateTenantAccess', () => {
      it('should allow access to correct tenant', async () => {
        const userContext: UserContext = {
          userId: 'user-123',
          tenantId: 'tenant-456',
          email: 'test@example.com',
          roles: ['user'],
          permissions: ['read'],
          sessionId: 'session-abc',
        };

        mockContext.get = jest.fn().mockReturnValue(userContext);

        const middleware = validateTenantAccess('tenant-456');
        await middleware(mockContext, mockNext);

        expect(mockNext).toHaveBeenCalled();
      });

      it('should deny access to different tenant', async () => {
        const userContext: UserContext = {
          userId: 'user-123',
          tenantId: 'tenant-456',
          email: 'test@example.com',
          roles: ['user'],
          permissions: ['read'],
          sessionId: 'session-abc',
        };

        mockContext.get = jest.fn().mockReturnValue(userContext);

        const middleware = validateTenantAccess('tenant-789');
        await middleware(mockContext, mockNext);

        expect(mockContext.json).toHaveBeenCalledWith({
          error: 'Tenant access denied',
          message: 'You do not have access to this tenant',
          code: 'AUTH_TENANT_ACCESS_DENIED',
        }, 403);
      });
    });
  });

  describe('Session Management Functions', () => {
    describe('validateSession', () => {
      it('should validate active session', async () => {
        mockRedisClient.get.mockResolvedValue(JSON.stringify({
          userId: 'user-123',
          active: true,
        }));

        const result = await validateSession('session-abc', 'user-123');
        expect(result).toBe(true);
      });

      it('should reject inactive session', async () => {
        mockRedisClient.get.mockResolvedValue(JSON.stringify({
          userId: 'user-123',
          active: false,
        }));

        const result = await validateSession('session-abc', 'user-123');
        expect(result).toBe(false);
      });

      it('should reject session with different user', async () => {
        mockRedisClient.get.mockResolvedValue(JSON.stringify({
          userId: 'user-456',
          active: true,
        }));

        const result = await validateSession('session-abc', 'user-123');
        expect(result).toBe(false);
      });

      it('should reject non-existent session', async () => {
        mockRedisClient.get.mockResolvedValue(null);

        const result = await validateSession('session-abc', 'user-123');
        expect(result).toBe(false);
      });
    });

    describe('createSession', () => {
      it('should create session in Redis', async () => {
        const userContext: UserContext = {
          userId: 'user-123',
          tenantId: 'tenant-456',
          organizationId: 'org-789',
          email: 'test@example.com',
          roles: ['user'],
          permissions: ['read'],
          sessionId: 'session-abc',
        };

        await createSession('session-abc', userContext);

        expect(mockRedisClient.setEx).toHaveBeenCalledWith(
          'session:session-abc',
          7 * 24 * 60 * 60, // 7 days
          expect.stringContaining('"userId":"user-123"')
        );
      });
    });

    describe('updateSessionAccess', () => {
      it('should update session last accessed time', async () => {
        const existingSession = {
          userId: 'user-123',
          active: true,
          lastAccessedAt: '2023-01-01T00:00:00.000Z',
        };

        mockRedisClient.get.mockResolvedValue(JSON.stringify(existingSession));

        await updateSessionAccess('session-abc');

        expect(mockRedisClient.setEx).toHaveBeenCalledWith(
          'session:session-abc',
          7 * 24 * 60 * 60,
          expect.stringMatching(/"lastAccessedAt":"202\d/)
        );
      });
    });

    describe('invalidateSession', () => {
      it('should delete session from Redis', async () => {
        await invalidateSession('session-abc');

        expect(mockRedisClient.del).toHaveBeenCalledWith('session:session-abc');
      });
    });

    describe('generateAccessToken', () => {
      it('should generate valid access token', async () => {
        const userContext: UserContext = {
          userId: 'user-123',
          tenantId: 'tenant-456',
          email: 'test@example.com',
          roles: ['user'],
          permissions: ['read'],
          sessionId: 'session-abc',
        };

        const token = await generateAccessToken(userContext);

        expect(token).toBeTruthy();
        expect(token.split('.')).toHaveLength(3); // JWT format
      });
    });

    describe('generateRefreshToken', () => {
      it('should generate valid refresh token', async () => {
        const userContext: UserContext = {
          userId: 'user-123',
          tenantId: 'tenant-456',
          email: 'test@example.com',
          roles: ['user'],
          permissions: ['read'],
          sessionId: 'session-abc',
        };

        const token = await generateRefreshToken(userContext);

        expect(token).toBeTruthy();
        expect(token.split('.')).toHaveLength(3); // JWT format
      });
    });
  });
});