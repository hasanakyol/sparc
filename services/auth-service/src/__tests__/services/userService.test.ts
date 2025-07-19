import { UserService, UserServiceConfig } from '../../services/userService';
import { mockPrisma, mockRedis, createTestUser, createTestTenant } from '../test-utils';
import winston from 'winston';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

// Create mock logger
const mockLogger = {
  info: jest.fn(),
  error: jest.fn(),
  warn: jest.fn(),
  debug: jest.fn(),
} as unknown as winston.Logger;

// Mock dependencies
jest.mock('@sparc/shared', () => ({
  generateUUID: jest.fn(() => 'test-uuid'),
  createError: jest.fn((code, message, status) => {
    const error = new Error(message);
    (error as any).status = status;
    (error as any).code = code;
    return error;
  }),
  ErrorCodes: {
    DUPLICATE_RESOURCE: 'DUPLICATE_RESOURCE',
    RESOURCE_NOT_FOUND: 'RESOURCE_NOT_FOUND',
    INVALID_CREDENTIALS: 'INVALID_CREDENTIALS',
    SERVICE_UNAVAILABLE: 'SERVICE_UNAVAILABLE',
  },
  validateInput: jest.fn((schema, data) => data),
  validateTenantAccess: jest.fn(),
  addTenantFilter: jest.fn((filter) => filter),
  logWithContext: jest.fn(),
  logAudit: jest.fn(),
  logError: jest.fn(),
  getCurrentTimestamp: jest.fn(() => new Date()),
  hashPassword: jest.fn(async (password) => `hashed_${password}`),
  verifyPassword: jest.fn(async (password, hash) => hash === `hashed_${password}`),
}));

jest.mock('bcrypt', () => ({
  compare: jest.fn(),
  hash: jest.fn(),
}));

jest.mock('jsonwebtoken', () => ({
  sign: jest.fn(() => 'test-token'),
  verify: jest.fn((token) => {
    if (token === 'invalid-token') throw new Error('Invalid token');
    return { sub: 'test-user-id', tenantId: 'test-tenant-id', sessionId: 'test-session-id' };
  }),
  decode: jest.fn(() => ({ exp: Math.floor(Date.now() / 1000) + 3600 })),
}));

describe('UserService', () => {
  let userService: UserService;
  const config: UserServiceConfig = {
    prisma: mockPrisma as any,
    redis: mockRedis as any,
    logger: mockLogger,
    jwtConfig: {
      accessTokenSecret: 'test-access-secret',
      refreshTokenSecret: 'test-refresh-secret',
      accessTokenExpiry: '15m',
      refreshTokenExpiry: '7d',
      issuer: 'test-issuer',
    },
    passwordOptions: {
      saltRounds: 10,
      minLength: 8,
    },
    bruteForceProtection: {
      maxAttempts: 5,
      windowMs: 900000,
      blockDurationMs: 1800000,
    },
    sessionConfig: {
      maxSessions: 5,
      sessionTimeoutMs: 86400000,
      extendOnActivity: true,
    },
    circuitBreaker: {
      enabled: true,
      failureThreshold: 5,
      resetTimeoutMs: 60000,
    },
  };

  const testContext = {
    tenantId: 'test-tenant-id',
    userId: 'test-user-id',
    organizationId: 'test-org-id',
  };

  const testLogContext = {
    requestId: 'test-request-id',
    userId: 'test-user-id',
    tenantId: 'test-tenant-id',
    ip: '127.0.0.1',
    userAgent: 'test-agent',
  };

  beforeEach(() => {
    jest.clearAllMocks();
    userService = new UserService(config);
  });

  describe('User CRUD Operations', () => {
    describe('createUser', () => {
      const createUserData = {
        email: 'newuser@example.com',
        username: 'newuser',
        password: 'Test123!@#',
        roles: ['VIEWER'],
        active: true,
      };

      it('should create a new user successfully', async () => {
        mockPrisma.user.findFirst.mockResolvedValue(null);
        mockPrisma.user.create.mockResolvedValue(createTestUser());
        mockPrisma.auditLog.create.mockResolvedValue({});

        const result = await userService.createUser(
          createUserData,
          testContext,
          testLogContext
        );

        expect(result).toBeDefined();
        expect(mockPrisma.user.create).toHaveBeenCalledWith({
          data: expect.objectContaining({
            email: createUserData.email,
            username: createUserData.username,
            passwordHash: `hashed_${createUserData.password}`,
          }),
        });
      });

      it('should reject duplicate email', async () => {
        mockPrisma.user.findFirst.mockResolvedValueOnce(createTestUser());

        await expect(
          userService.createUser(createUserData, testContext, testLogContext)
        ).rejects.toThrow('User with this email already exists');
      });

      it('should reject duplicate username', async () => {
        mockPrisma.user.findFirst
          .mockResolvedValueOnce(null) // Email check
          .mockResolvedValueOnce(createTestUser()); // Username check

        await expect(
          userService.createUser(createUserData, testContext, testLogContext)
        ).rejects.toThrow('User with this username already exists');
      });
    });

    describe('getUserById', () => {
      it('should return user when found', async () => {
        const testUser = createTestUser();
        mockPrisma.user.findFirst.mockResolvedValue(testUser);

        const result = await userService.getUserById(
          'test-user-id',
          'test-tenant-id',
          testLogContext
        );

        expect(result).toEqual(testUser);
        expect(mockPrisma.user.findFirst).toHaveBeenCalledWith({
          where: { id: 'test-user-id', tenantId: 'test-tenant-id' },
          include: { credentials: false },
        });
      });

      it('should return null when user not found', async () => {
        mockPrisma.user.findFirst.mockResolvedValue(null);

        const result = await userService.getUserById(
          'non-existent-id',
          'test-tenant-id',
          testLogContext
        );

        expect(result).toBeNull();
      });

      it('should include credentials when requested', async () => {
        const testUser = { ...createTestUser(), credentials: [] };
        mockPrisma.user.findFirst.mockResolvedValue(testUser);

        await userService.getUserById(
          'test-user-id',
          'test-tenant-id',
          testLogContext,
          true
        );

        expect(mockPrisma.user.findFirst).toHaveBeenCalledWith({
          where: { id: 'test-user-id', tenantId: 'test-tenant-id' },
          include: { credentials: true },
        });
      });
    });

    describe('updateUser', () => {
      it('should update user successfully', async () => {
        const testUser = createTestUser();
        mockPrisma.user.findFirst.mockResolvedValue(testUser);
        mockPrisma.user.update.mockResolvedValue({
          ...testUser,
          email: 'updated@example.com',
        });
        mockPrisma.auditLog.create.mockResolvedValue({});

        const result = await userService.updateUser(
          'test-user-id',
          { email: 'updated@example.com' },
          testContext,
          testLogContext
        );

        expect(result.email).toBe('updated@example.com');
        expect(mockPrisma.user.update).toHaveBeenCalled();
      });

      it('should hash password when updating', async () => {
        const testUser = createTestUser();
        mockPrisma.user.findFirst.mockResolvedValue(testUser);
        mockPrisma.user.update.mockResolvedValue(testUser);
        mockPrisma.auditLog.create.mockResolvedValue({});

        await userService.updateUser(
          'test-user-id',
          { password: 'NewPassword123!' },
          testContext,
          testLogContext
        );

        expect(mockPrisma.user.update).toHaveBeenCalledWith({
          where: { id: 'test-user-id', tenantId: 'test-tenant-id' },
          data: expect.objectContaining({
            passwordHash: 'hashed_NewPassword123!',
          }),
        });
      });

      it('should reject update with duplicate email', async () => {
        const testUser = createTestUser();
        const anotherUser = { ...createTestUser(), id: 'another-user-id' };
        
        mockPrisma.user.findFirst
          .mockResolvedValueOnce(testUser) // Get existing user
          .mockResolvedValueOnce(anotherUser); // Email conflict check

        await expect(
          userService.updateUser(
            'test-user-id',
            { email: 'existing@example.com' },
            testContext,
            testLogContext
          )
        ).rejects.toThrow('Email already in use by another user');
      });
    });

    describe('deleteUser', () => {
      it('should soft delete user by default', async () => {
        const testUser = createTestUser();
        mockPrisma.user.findFirst.mockResolvedValue(testUser);
        mockPrisma.user.update.mockResolvedValue({ ...testUser, active: false });
        mockPrisma.auditLog.create.mockResolvedValue({});

        await userService.deleteUser(
          'test-user-id',
          'test-tenant-id',
          testLogContext
        );

        expect(mockPrisma.user.update).toHaveBeenCalledWith({
          where: { id: 'test-user-id', tenantId: 'test-tenant-id' },
          data: { active: false, updatedAt: expect.any(Date) },
        });
      });

      it('should hard delete user when specified', async () => {
        const testUser = createTestUser();
        mockPrisma.user.findFirst.mockResolvedValue(testUser);
        mockPrisma.$transaction.mockImplementation(async (fn) => fn(mockPrisma));
        mockPrisma.credential.deleteMany.mockResolvedValue({});
        mockPrisma.mobileCredential.deleteMany.mockResolvedValue({});
        mockPrisma.user.delete.mockResolvedValue(testUser);
        mockPrisma.auditLog.create.mockResolvedValue({});

        await userService.deleteUser(
          'test-user-id',
          'test-tenant-id',
          testLogContext,
          false
        );

        expect(mockPrisma.user.delete).toHaveBeenCalled();
      });
    });

    describe('listUsers', () => {
      it('should list users with pagination', async () => {
        const users = [createTestUser()];
        mockPrisma.user.count.mockResolvedValue(1);
        mockPrisma.user.findMany.mockResolvedValue(users);

        const result = await userService.listUsers(
          'test-tenant-id',
          { page: 1, limit: 20 },
          testLogContext
        );

        expect(result).toEqual({
          users,
          total: 1,
          page: 1,
          limit: 20,
        });
      });

      it('should filter users by search term', async () => {
        mockPrisma.user.count.mockResolvedValue(0);
        mockPrisma.user.findMany.mockResolvedValue([]);

        await userService.listUsers(
          'test-tenant-id',
          { search: 'john' },
          testLogContext
        );

        expect(mockPrisma.user.findMany).toHaveBeenCalledWith({
          where: expect.objectContaining({
            OR: [
              { username: { contains: 'john', mode: 'insensitive' } },
              { email: { contains: 'john', mode: 'insensitive' } },
            ],
          }),
          skip: 0,
          take: 20,
          orderBy: { createdAt: 'desc' },
          select: expect.any(Object),
        });
      });
    });
  });

  describe('Authentication Methods', () => {
    describe('authenticateUser', () => {
      beforeEach(() => {
        mockRedis.get.mockResolvedValue(null);
        mockRedis.setex.mockResolvedValue('OK');
        mockRedis.exists.mockResolvedValue(0);
        mockRedis.del.mockResolvedValue(1);
        jest.spyOn(bcrypt, 'compare').mockResolvedValue(true as never);
      });

      it('should authenticate user successfully', async () => {
        const testUser = createTestUser();
        const testTenant = createTestTenant();
        mockPrisma.user.findFirst.mockResolvedValue({
          ...testUser,
          tenant: testTenant,
        });
        mockPrisma.user.update.mockResolvedValue(testUser);
        mockPrisma.auditLog.create.mockResolvedValue({});

        const result = await userService.authenticateUser(
          'testuser',
          'Test123!@#',
          'test-tenant-id',
          testLogContext
        );

        expect(result.isValid).toBe(true);
        expect(result.user).toBeDefined();
        expect(result.tokens).toBeDefined();
        expect(result.sessionId).toBeDefined();
      });

      it('should reject invalid credentials', async () => {
        const testUser = createTestUser();
        mockPrisma.user.findFirst.mockResolvedValue({
          ...testUser,
          tenant: createTestTenant(),
        });
        jest.spyOn(bcrypt, 'compare').mockResolvedValue(false as never);

        const result = await userService.authenticateUser(
          'testuser',
          'wrongpassword',
          'test-tenant-id',
          testLogContext
        );

        expect(result.isValid).toBe(false);
        expect(result.reason).toBe('Invalid credentials');
      });

      it('should reject non-existent user', async () => {
        mockPrisma.user.findFirst.mockResolvedValue(null);

        const result = await userService.authenticateUser(
          'nonexistent',
          'password',
          'test-tenant-id',
          testLogContext
        );

        expect(result.isValid).toBe(false);
        expect(result.reason).toBe('Invalid credentials');
      });

      it('should reject inactive user', async () => {
        const inactiveUser = { ...createTestUser(), active: false };
        mockPrisma.user.findFirst.mockResolvedValue({
          ...inactiveUser,
          tenant: createTestTenant(),
        });

        const result = await userService.authenticateUser(
          'testuser',
          'Test123!@#',
          'test-tenant-id',
          testLogContext
        );

        expect(result.isValid).toBe(false);
        expect(result.reason).toBe('Account is inactive');
      });

      it('should handle brute force protection', async () => {
        mockRedis.get.mockResolvedValue(
          JSON.stringify({
            attempts: 6,
            lastAttempt: Date.now(),
            blockedUntil: Date.now() + 300000,
          })
        );

        const result = await userService.authenticateUser(
          'testuser',
          'password',
          'test-tenant-id',
          testLogContext
        );

        expect(result.isValid).toBe(false);
        expect(result.reason).toContain('Account temporarily locked');
      });
    });

    describe('validateAccessToken', () => {
      it('should validate token successfully', async () => {
        mockRedis.exists.mockResolvedValue(0); // Not blacklisted
        mockRedis.get.mockResolvedValue(
          JSON.stringify({
            userId: 'test-user-id',
            tenantId: 'test-tenant-id',
            isActive: true,
            expiresAt: new Date(Date.now() + 3600000),
          })
        );
        mockPrisma.user.findFirst.mockResolvedValue(createTestUser());

        const result = await userService.validateAccessToken(
          'valid-token',
          testLogContext
        );

        expect(result).toBeDefined();
        expect(result?.sub).toBe('test-user-id');
      });

      it('should reject blacklisted token', async () => {
        mockRedis.exists.mockResolvedValue(1); // Blacklisted

        const result = await userService.validateAccessToken(
          'blacklisted-token',
          testLogContext
        );

        expect(result).toBeNull();
      });

      it('should reject invalid token', async () => {
        const result = await userService.validateAccessToken(
          'invalid-token',
          testLogContext
        );

        expect(result).toBeNull();
      });
    });

    describe('refreshTokens', () => {
      it('should refresh tokens successfully', async () => {
        mockRedis.get.mockResolvedValue('test-refresh-token');
        mockPrisma.user.findFirst.mockResolvedValue(createTestUser());
        mockPrisma.auditLog.create.mockResolvedValue({});

        const result = await userService.refreshTokens(
          'test-refresh-token',
          testLogContext
        );

        expect(result).toBeDefined();
        expect(result?.accessToken).toBeDefined();
        expect(result?.refreshToken).toBeDefined();
      });

      it('should reject invalid refresh token', async () => {
        mockRedis.get.mockResolvedValue(null);

        const result = await userService.refreshTokens(
          'invalid-refresh-token',
          testLogContext
        );

        expect(result).toBeNull();
      });
    });
  });

  describe('Password Management', () => {
    describe('changePassword', () => {
      it('should change password successfully', async () => {
        const testUser = createTestUser();
        mockPrisma.user.findFirst.mockResolvedValue(testUser);
        mockPrisma.user.update.mockResolvedValue(testUser);
        mockPrisma.auditLog.create.mockResolvedValue({});

        await userService.changePassword(
          'test-user-id',
          'Test123!@#',
          'NewPassword123!',
          'test-tenant-id',
          testLogContext
        );

        expect(mockPrisma.user.update).toHaveBeenCalledWith({
          where: { id: 'test-user-id', tenantId: 'test-tenant-id' },
          data: expect.objectContaining({
            passwordHash: 'hashed_NewPassword123!',
          }),
        });
      });

      it('should reject incorrect current password', async () => {
        const testUser = createTestUser();
        mockPrisma.user.findFirst.mockResolvedValue(testUser);
        const { verifyPassword } = require('@sparc/shared');
        verifyPassword.mockResolvedValue(false);

        await expect(
          userService.changePassword(
            'test-user-id',
            'wrongpassword',
            'NewPassword123!',
            'test-tenant-id',
            testLogContext
          )
        ).rejects.toThrow('Current password is incorrect');
      });
    });

    describe('resetPassword', () => {
      it('should reset password successfully', async () => {
        const testUser = createTestUser();
        mockPrisma.user.findFirst.mockResolvedValue(testUser);
        mockPrisma.user.update.mockResolvedValue(testUser);
        mockPrisma.auditLog.create.mockResolvedValue({});

        await userService.resetPassword(
          'test-user-id',
          'NewPassword123!',
          'test-tenant-id',
          testLogContext
        );

        expect(mockPrisma.user.update).toHaveBeenCalledWith({
          where: { id: 'test-user-id', tenantId: 'test-tenant-id' },
          data: expect.objectContaining({
            passwordHash: 'hashed_NewPassword123!',
          }),
        });
      });
    });
  });

  describe('Role and Permission Management', () => {
    describe('assignRoles', () => {
      it('should assign roles successfully', async () => {
        const testUser = createTestUser();
        const newRoles = ['ADMIN', 'VIEWER'];
        mockPrisma.user.findFirst.mockResolvedValue(testUser);
        mockPrisma.user.update.mockResolvedValue({
          ...testUser,
          roles: newRoles,
        });
        mockPrisma.auditLog.create.mockResolvedValue({});

        const result = await userService.assignRoles(
          'test-user-id',
          newRoles,
          'test-tenant-id',
          testLogContext
        );

        expect(result.roles).toEqual(newRoles);
      });
    });

    describe('checkPermission', () => {
      it('should return true for user with permission', async () => {
        const userWithPermission = {
          ...createTestUser(),
          permissions: { 'manage:users': true },
        };
        mockPrisma.user.findFirst.mockResolvedValue(userWithPermission);

        const result = await userService.checkPermission(
          'test-user-id',
          'manage:users',
          'test-tenant-id',
          testLogContext
        );

        expect(result).toBe(true);
      });

      it('should return true for admin roles', async () => {
        const adminUser = {
          ...createTestUser(),
          roles: ['super_admin'],
          permissions: {},
        };
        mockPrisma.user.findFirst.mockResolvedValue(adminUser);

        const result = await userService.checkPermission(
          'test-user-id',
          'any:permission',
          'test-tenant-id',
          testLogContext
        );

        expect(result).toBe(true);
      });

      it('should return false for inactive user', async () => {
        const inactiveUser = {
          ...createTestUser(),
          active: false,
        };
        mockPrisma.user.findFirst.mockResolvedValue(inactiveUser);

        const result = await userService.checkPermission(
          'test-user-id',
          'any:permission',
          'test-tenant-id',
          testLogContext
        );

        expect(result).toBe(false);
      });
    });
  });

  describe('Session Management', () => {
    describe('createUserSession', () => {
      it('should create session successfully', async () => {
        mockRedis.setex.mockResolvedValue('OK');
        mockRedis.keys.mockResolvedValue([]);

        const sessionId = await userService.createUserSession(
          createTestUser(),
          testLogContext,
          'device-fingerprint'
        );

        expect(sessionId).toBeDefined();
        expect(mockRedis.setex).toHaveBeenCalled();
      });

      it('should enforce session limits', async () => {
        const existingSessions = Array(6)
          .fill(null)
          .map((_, i) => `session:session-${i}`);
        
        mockRedis.keys.mockResolvedValue(existingSessions);
        mockRedis.get.mockImplementation(async (key) =>
          JSON.stringify({
            userId: 'test-user-id',
            tenantId: 'test-tenant-id',
            sessionId: key.replace('session:', ''),
            lastActivity: new Date(Date.now() - i * 1000),
            isActive: true,
            expiresAt: new Date(Date.now() + 3600000),
          })
        );
        mockRedis.setex.mockResolvedValue('OK');
        mockRedis.del.mockResolvedValue(1);

        await userService.createUserSession(
          createTestUser(),
          testLogContext
        );

        // Should delete oldest sessions
        expect(mockRedis.del).toHaveBeenCalled();
      });
    });

    describe('validateUserSession', () => {
      it('should validate active session', async () => {
        const session = {
          userId: 'test-user-id',
          tenantId: 'test-tenant-id',
          isActive: true,
          expiresAt: new Date(Date.now() + 3600000),
        };
        mockRedis.get.mockResolvedValue(JSON.stringify(session));
        mockPrisma.user.findFirst.mockResolvedValue(createTestUser());

        const result = await userService.validateUserSession(
          'test-session-id',
          'test-tenant-id',
          testLogContext
        );

        expect(result).toBeDefined();
        expect(result?.user).toBeDefined();
        expect(result?.session).toBeDefined();
      });

      it('should reject expired session', async () => {
        const session = {
          userId: 'test-user-id',
          tenantId: 'test-tenant-id',
          isActive: true,
          expiresAt: new Date(Date.now() - 3600000), // Expired
        };
        mockRedis.get.mockResolvedValue(JSON.stringify(session));

        const result = await userService.validateUserSession(
          'test-session-id',
          'test-tenant-id',
          testLogContext
        );

        expect(result).toBeNull();
        expect(mockRedis.del).toHaveBeenCalledWith('session:test-session-id');
      });
    });
  });

  describe('Service Health and Monitoring', () => {
    describe('getServiceHealth', () => {
      it('should report healthy status', async () => {
        mockPrisma.$queryRaw.mockResolvedValue([{ 1: 1 }]);
        mockRedis.ping.mockResolvedValue('PONG');

        const health = await userService.getServiceHealth();

        expect(health.status).toBe('healthy');
        expect(health.checks.database).toBe('healthy');
        expect(health.checks.redis).toBe('healthy');
      });

      it('should report degraded status with partial failures', async () => {
        mockPrisma.$queryRaw.mockResolvedValue([{ 1: 1 }]);
        mockRedis.ping.mockRejectedValue(new Error('Redis down'));

        const health = await userService.getServiceHealth();

        expect(health.status).toBe('degraded');
        expect(health.checks.database).toBe('healthy');
        expect(health.checks.redis).toBe('unhealthy');
      });

      it('should report unhealthy status with all failures', async () => {
        mockPrisma.$queryRaw.mockRejectedValue(new Error('DB down'));
        mockRedis.ping.mockRejectedValue(new Error('Redis down'));

        const health = await userService.getServiceHealth();

        expect(health.status).toBe('unhealthy');
        expect(health.checks.database).toBe('unhealthy');
        expect(health.checks.redis).toBe('unhealthy');
      });
    });

    describe('cleanupExpiredSessions', () => {
      it('should cleanup expired sessions', async () => {
        const sessions = ['session:1', 'session:2'];
        mockRedis.keys.mockResolvedValue(sessions);
        mockRedis.get.mockImplementation(async () =>
          JSON.stringify({
            sessionId: 'test-session',
            expiresAt: new Date(Date.now() - 3600000), // Expired
          })
        );
        mockRedis.del.mockResolvedValue(1);

        const result = await userService.cleanupExpiredSessions();

        expect(result.cleaned).toBe(2);
        expect(mockRedis.del).toHaveBeenCalledTimes(4); // 2 sessions + 2 refresh tokens
      });

      it('should handle cleanup errors gracefully', async () => {
        mockRedis.keys.mockRejectedValue(new Error('Redis error'));

        const result = await userService.cleanupExpiredSessions();

        expect(result.cleaned).toBe(0);
        expect(mockLogger.error).toHaveBeenCalled();
      });
    });
  });

  describe('Circuit Breaker', () => {
    it('should open circuit after failure threshold', async () => {
      // Force multiple failures
      mockPrisma.user.findFirst.mockRejectedValue(new Error('DB error'));

      for (let i = 0; i < 5; i++) {
        try {
          await userService.getUserById(
            'test-user-id',
            'test-tenant-id',
            testLogContext
          );
        } catch (error) {
          // Expected to fail
        }
      }

      // Next call should fail immediately due to open circuit
      await expect(
        userService.getUserById('test-user-id', 'test-tenant-id', testLogContext)
      ).rejects.toThrow('Service temporarily unavailable');
    });
  });

  describe('User Stats', () => {
    it('should return user statistics', async () => {
      mockPrisma.user.count
        .mockResolvedValueOnce(100) // Total
        .mockResolvedValueOnce(80) // Active
        .mockResolvedValueOnce(20); // Inactive

      mockPrisma.user.groupBy.mockResolvedValue([
        { roles: ['ADMIN'], _count: 5 },
        { roles: ['VIEWER'], _count: 95 },
      ]);

      mockPrisma.auditLog.count.mockResolvedValue(50);

      const stats = await userService.getUserStats(
        'test-tenant-id',
        testLogContext
      );

      expect(stats).toEqual({
        totalUsers: 100,
        activeUsers: 80,
        inactiveUsers: 20,
        usersByRole: {
          ADMIN: 5,
          VIEWER: 95,
        },
        recentLogins: 50,
      });
    });
  });
});