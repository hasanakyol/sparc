import { Hono } from 'hono';
import bcrypt from 'bcrypt';
import { sign } from 'hono/jwt';
import authRoutes from '../../routes/auth';
import { mockPrisma, mockRedis, createTestUser, createTestTenant } from '../test-utils';

// Mock dependencies
jest.mock('@prisma/client', () => ({
  PrismaClient: jest.fn(() => mockPrisma),
}));

jest.mock('ioredis', () => {
  return jest.fn(() => mockRedis);
});

jest.mock('@sparc/shared', () => ({
  config: {
    jwt: {
      accessTokenSecret: 'test-access-secret',
      refreshTokenSecret: 'test-refresh-secret',
      accessTokenExpiry: '15m',
      refreshTokenExpiry: '7d',
      issuer: 'test-issuer',
      audience: 'test-audience',
      algorithm: 'HS256',
    },
    security: {
      bcryptRounds: 10,
      sessionTimeout: 30,
      maxConcurrentSessions: 5,
      bruteForce: {
        maxAttempts: 5,
        windowMs: 900000,
        blockDuration: 900000,
      },
    },
    redis: {
      host: 'localhost',
      port: 6379,
      password: undefined,
      database: 0,
      keyPrefix: 'test:',
      connectTimeout: 5000,
      commandTimeout: 5000,
      retryDelay: 100,
      retryAttempts: 3,
    },
  },
  logger: {
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    debug: jest.fn(),
  },
  prisma: mockPrisma,
  withRetry: jest.fn((fn) => fn()),
}));

jest.mock('@sparc/shared/utils/jwt-blacklist', () => ({
  JWTBlacklistService: jest.fn().mockImplementation(() => ({
    add: jest.fn(),
    isBlacklisted: jest.fn().mockResolvedValue(false),
    cleanup: jest.fn(),
  })),
}));

jest.mock('@sparc/shared/services/email', () => ({
  sendVerificationEmail: jest.fn().mockResolvedValue(true),
  sendPasswordResetEmail: jest.fn().mockResolvedValue(true),
}));

jest.mock('@sparc/shared/services/mfa', () => ({
  MFAService: jest.fn().mockImplementation(() => ({
    generateSecret: jest.fn().mockReturnValue({
      secret: 'test-secret',
      qrCode: 'data:image/png;base64,test',
    }),
    verifyToken: jest.fn().mockReturnValue(true),
    generateBackupCodes: jest.fn().mockReturnValue(['code1', 'code2', 'code3']),
  })),
}));

jest.mock('@sparc/shared/utils/password-security', () => ({
  PasswordSecurityService: jest.fn().mockImplementation(() => ({
    validatePassword: jest.fn().mockResolvedValue({
      isValid: true,
      errors: [],
      score: 4,
    }),
    checkPasswordHistory: jest.fn().mockResolvedValue(true),
    addPasswordToHistory: jest.fn(),
  })),
}));

jest.mock('@sparc/shared/security/siem', () => ({
  logSecurityEvent: jest.fn(),
  SecurityEventType: {
    LOGIN_SUCCESS: 'LOGIN_SUCCESS',
    LOGIN_FAILURE: 'LOGIN_FAILURE',
    LOGOUT: 'LOGOUT',
    PASSWORD_CHANGE: 'PASSWORD_CHANGE',
    ACCOUNT_LOCKOUT: 'ACCOUNT_LOCKOUT',
  },
  SecuritySeverity: {
    LOW: 'LOW',
    MEDIUM: 'MEDIUM',
    HIGH: 'HIGH',
    CRITICAL: 'CRITICAL',
  },
}));

describe('Auth Routes', () => {
  let app: Hono;

  beforeEach(() => {
    jest.clearAllMocks();
    app = new Hono();
    app.route('/auth', authRoutes);
  });

  describe('POST /auth/signup', () => {
    const validSignupData = {
      email: 'newuser@example.com',
      username: 'newuser',
      password: 'Test123!@#',
      firstName: 'New',
      lastName: 'User',
      tenantId: 'test-tenant-id',
    };

    it('should create a new user successfully', async () => {
      mockPrisma.user.findFirst.mockResolvedValue(null);
      mockPrisma.tenant.findUnique.mockResolvedValue(createTestTenant());
      mockPrisma.user.create.mockResolvedValue({
        ...createTestUser(),
        email: validSignupData.email,
        username: validSignupData.username,
      });

      const res = await app.request('/auth/signup', {
        method: 'POST',
        body: JSON.stringify(validSignupData),
        headers: { 'Content-Type': 'application/json' },
      });

      expect(res.status).toBe(201);
      const body = await res.json();
      expect(body.success).toBe(true);
      expect(body.message).toBe('User created successfully. Please check your email to verify your account.');
    });

    it('should reject signup with existing email', async () => {
      mockPrisma.user.findFirst.mockResolvedValue(createTestUser());

      const res = await app.request('/auth/signup', {
        method: 'POST',
        body: JSON.stringify(validSignupData),
        headers: { 'Content-Type': 'application/json' },
      });

      expect(res.status).toBe(409);
      const body = await res.json();
      expect(body.error).toBe('User with this email or username already exists');
    });

    it('should reject signup with weak password', async () => {
      const res = await app.request('/auth/signup', {
        method: 'POST',
        body: JSON.stringify({ ...validSignupData, password: 'weak' }),
        headers: { 'Content-Type': 'application/json' },
      });

      expect(res.status).toBe(400);
    });

    it('should reject signup with invalid tenant', async () => {
      mockPrisma.user.findFirst.mockResolvedValue(null);
      mockPrisma.tenant.findUnique.mockResolvedValue(null);

      const res = await app.request('/auth/signup', {
        method: 'POST',
        body: JSON.stringify(validSignupData),
        headers: { 'Content-Type': 'application/json' },
      });

      expect(res.status).toBe(400);
      const body = await res.json();
      expect(body.error).toBe('Invalid tenant');
    });
  });

  describe('POST /auth/login', () => {
    const validLoginData = {
      email: 'test@example.com',
      password: 'Test123!@#',
      tenantId: 'test-tenant-id',
    };

    beforeEach(() => {
      mockRedis.zadd.mockResolvedValue(1);
      mockRedis.zcard.mockResolvedValue(1);
      mockRedis.expire.mockResolvedValue(1);
      mockRedis.ttl.mockResolvedValue(-1);
      mockRedis.setex.mockResolvedValue('OK');
    });

    it('should login successfully with valid credentials', async () => {
      const testUser = createTestUser();
      mockPrisma.user.findFirst.mockResolvedValue(testUser);
      mockPrisma.tenant.findUnique.mockResolvedValue(createTestTenant());
      jest.spyOn(bcrypt, 'compare').mockResolvedValue(true as never);

      const res = await app.request('/auth/login', {
        method: 'POST',
        body: JSON.stringify(validLoginData),
        headers: { 'Content-Type': 'application/json' },
      });

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.success).toBe(true);
      expect(body.data).toHaveProperty('accessToken');
      expect(body.data).toHaveProperty('refreshToken');
      expect(body.data).toHaveProperty('user');
    });

    it('should reject login with invalid credentials', async () => {
      mockPrisma.user.findFirst.mockResolvedValue(createTestUser());
      jest.spyOn(bcrypt, 'compare').mockResolvedValue(false as never);

      const res = await app.request('/auth/login', {
        method: 'POST',
        body: JSON.stringify(validLoginData),
        headers: { 'Content-Type': 'application/json' },
      });

      expect(res.status).toBe(401);
      const body = await res.json();
      expect(body.error).toBe('Invalid credentials');
    });

    it('should reject login for non-existent user', async () => {
      mockPrisma.user.findFirst.mockResolvedValue(null);

      const res = await app.request('/auth/login', {
        method: 'POST',
        body: JSON.stringify(validLoginData),
        headers: { 'Content-Type': 'application/json' },
      });

      expect(res.status).toBe(401);
      const body = await res.json();
      expect(body.error).toBe('Invalid credentials');
    });

    it('should reject login for inactive user', async () => {
      const inactiveUser = { ...createTestUser(), isActive: false };
      mockPrisma.user.findFirst.mockResolvedValue(inactiveUser);

      const res = await app.request('/auth/login', {
        method: 'POST',
        body: JSON.stringify(validLoginData),
        headers: { 'Content-Type': 'application/json' },
      });

      expect(res.status).toBe(403);
      const body = await res.json();
      expect(body.error).toBe('Account is disabled');
    });

    it('should handle brute force protection', async () => {
      mockRedis.zcard.mockResolvedValue(6); // Exceeds max attempts
      mockRedis.ttl.mockResolvedValue(300); // Still blocked

      const res = await app.request('/auth/login', {
        method: 'POST',
        body: JSON.stringify(validLoginData),
        headers: { 'Content-Type': 'application/json' },
      });

      expect(res.status).toBe(429);
      const body = await res.json();
      expect(body.error).toContain('Too many failed login attempts');
    });
  });

  describe('POST /auth/logout', () => {
    it('should logout successfully with valid token', async () => {
      const testUser = createTestUser();
      const token = await sign(
        { sub: testUser.id, tenantId: testUser.tenantId },
        'test-access-secret'
      );

      mockPrisma.user.findUnique.mockResolvedValue(testUser);
      mockRedis.del.mockResolvedValue(1);

      const res = await app.request('/auth/logout', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.success).toBe(true);
      expect(body.message).toBe('Logged out successfully');
    });

    it('should reject logout without token', async () => {
      const res = await app.request('/auth/logout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });

      expect(res.status).toBe(401);
    });
  });

  describe('POST /auth/refresh-token', () => {
    it('should refresh token successfully', async () => {
      const testUser = createTestUser();
      const refreshToken = await sign(
        { 
          sub: testUser.id, 
          tenantId: testUser.tenantId,
          type: 'refresh',
          sessionId: 'test-session-id'
        },
        'test-refresh-secret'
      );

      mockPrisma.user.findUnique.mockResolvedValue(testUser);
      mockRedis.get.mockResolvedValue(JSON.stringify({
        userId: testUser.id,
        tenantId: testUser.tenantId,
        createdAt: Date.now(),
      }));

      const res = await app.request('/auth/refresh-token', {
        method: 'POST',
        body: JSON.stringify({ refreshToken }),
        headers: { 'Content-Type': 'application/json' },
      });

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.success).toBe(true);
      expect(body.data).toHaveProperty('accessToken');
      expect(body.data).toHaveProperty('refreshToken');
    });

    it('should reject invalid refresh token', async () => {
      const res = await app.request('/auth/refresh-token', {
        method: 'POST',
        body: JSON.stringify({ refreshToken: 'invalid-token' }),
        headers: { 'Content-Type': 'application/json' },
      });

      expect(res.status).toBe(401);
      const body = await res.json();
      expect(body.error).toBe('Invalid refresh token');
    });
  });

  describe('GET /auth/me', () => {
    it('should return current user profile', async () => {
      const testUser = createTestUser();
      const token = await sign(
        { sub: testUser.id, tenantId: testUser.tenantId },
        'test-access-secret'
      );

      mockPrisma.user.findUnique.mockResolvedValue({
        ...testUser,
        tenant: createTestTenant(),
      });

      const res = await app.request('/auth/me', {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.success).toBe(true);
      expect(body.data.id).toBe(testUser.id);
      expect(body.data.email).toBe(testUser.email);
    });

    it('should reject request without authentication', async () => {
      const res = await app.request('/auth/me', {
        method: 'GET',
      });

      expect(res.status).toBe(401);
    });
  });

  describe('POST /auth/change-password', () => {
    it('should change password successfully', async () => {
      const testUser = createTestUser();
      const token = await sign(
        { sub: testUser.id, tenantId: testUser.tenantId },
        'test-access-secret'
      );

      mockPrisma.user.findUnique.mockResolvedValue(testUser);
      jest.spyOn(bcrypt, 'compare').mockResolvedValue(true as never);
      jest.spyOn(bcrypt, 'hash').mockResolvedValue('new-hash' as never);
      mockPrisma.user.update.mockResolvedValue(testUser);

      const res = await app.request('/auth/change-password', {
        method: 'POST',
        body: JSON.stringify({
          currentPassword: 'Test123!@#',
          newPassword: 'NewTest123!@#',
        }),
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.success).toBe(true);
      expect(body.message).toBe('Password changed successfully');
    });

    it('should reject change with incorrect current password', async () => {
      const testUser = createTestUser();
      const token = await sign(
        { sub: testUser.id, tenantId: testUser.tenantId },
        'test-access-secret'
      );

      mockPrisma.user.findUnique.mockResolvedValue(testUser);
      jest.spyOn(bcrypt, 'compare').mockResolvedValue(false as never);

      const res = await app.request('/auth/change-password', {
        method: 'POST',
        body: JSON.stringify({
          currentPassword: 'wrong-password',
          newPassword: 'NewTest123!@#',
        }),
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });

      expect(res.status).toBe(401);
      const body = await res.json();
      expect(body.error).toBe('Current password is incorrect');
    });
  });
});