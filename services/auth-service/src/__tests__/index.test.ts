import { Hono } from 'hono';
import supertest from 'supertest';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { 
  mockPrisma, 
  mockRedis, 
  createTestUser, 
  createTestTenant,
  setupTestEnv,
  cleanupTestEnv
} from './test-utils';

// Mock modules
jest.mock('@prisma/client', () => ({
  PrismaClient: jest.fn(() => mockPrisma)
}));

jest.mock('ioredis', () => {
  return jest.fn(() => mockRedis);
});

jest.mock('bcrypt');
jest.mock('jsonwebtoken');

// Import the app after mocks are set up
import createApp from '../app';

describe('Authentication Service', () => {
  let app: any;
  let request: any;

  beforeAll(() => {
    setupTestEnv();
    app = createApp();
    request = supertest(app.fetch);
  });

  afterAll(() => {
    cleanupTestEnv();
  });

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Health Endpoints', () => {
    test('GET /health should return service health status', async () => {
      const response = await request.get('/health');
      
      expect(response.status).toBe(200);
      expect(response.body).toMatchObject({
        status: 'healthy',
        service: 'auth-service',
        timestamp: expect.any(String),
      });
    });

    test('GET /ready should return readiness status', async () => {
      mockPrisma.$queryRaw.mockResolvedValue([{ result: 1 }]);
      mockRedis.ping.mockResolvedValue('PONG');

      const response = await request.get('/ready');
      
      expect(response.status).toBe(200);
      expect(response.body).toMatchObject({
        ready: true,
        checks: {
          database: true,
          redis: true,
        },
      });
    });

    test('GET /ready should return 503 when database is down', async () => {
      mockPrisma.$queryRaw.mockRejectedValue(new Error('Database connection failed'));
      mockRedis.ping.mockResolvedValue('PONG');

      const response = await request.get('/ready');
      
      expect(response.status).toBe(503);
      expect(response.body.ready).toBe(false);
      expect(response.body.checks.database).toBe(false);
    });
  });

  describe('Authentication Endpoints', () => {
    describe('POST /auth/signup', () => {
      test('should create new user successfully', async () => {
        const userData = {
          email: 'newuser@example.com',
          password: 'SecurePass123!',
          firstName: 'New',
          lastName: 'User',
          tenantId: 'test-tenant-id',
        };

        const hashedPassword = '$2b$12$hashedpassword';
        (bcrypt.hash as jest.Mock).mockResolvedValue(hashedPassword);

        mockPrisma.user.findFirst.mockResolvedValue(null);
        mockPrisma.tenant.findUnique.mockResolvedValue(createTestTenant());
        mockPrisma.user.create.mockResolvedValue({
          ...createTestUser(),
          email: userData.email,
          firstName: userData.firstName,
          lastName: userData.lastName,
        });

        const response = await request
          .post('/auth/signup')
          .send(userData);

        expect(response.status).toBe(201);
        expect(response.body.message).toBe('User created successfully');
        expect(response.body.user.email).toBe(userData.email);
        expect(response.body.user).not.toHaveProperty('passwordHash');
      });

      test('should return 409 for existing user', async () => {
        const userData = {
          email: 'existing@example.com',
          password: 'SecurePass123!',
          firstName: 'Existing',
          lastName: 'User',
          tenantId: 'test-tenant-id',
        };

        mockPrisma.user.findFirst.mockResolvedValue(createTestUser());

        const response = await request
          .post('/auth/signup')
          .send(userData);

        expect(response.status).toBe(409);
        expect(response.body.error).toBe('User already exists');
      });

      test('should return 400 for invalid tenant', async () => {
        const userData = {
          email: 'newuser@example.com',
          password: 'SecurePass123!',
          firstName: 'New',
          lastName: 'User',
          tenantId: 'invalid-tenant-id',
        };

        mockPrisma.user.findFirst.mockResolvedValue(null);
        mockPrisma.tenant.findUnique.mockResolvedValue(null);

        const response = await request
          .post('/auth/signup')
          .send(userData);

        expect(response.status).toBe(400);
        expect(response.body.error).toBe('Invalid tenant');
      });

      test('should validate password requirements', async () => {
        const userData = {
          email: 'newuser@example.com',
          password: 'weak',
          firstName: 'New',
          lastName: 'User',
          tenantId: 'test-tenant-id',
        };

        const response = await request
          .post('/auth/signup')
          .send(userData);

        expect(response.status).toBe(400);
        expect(response.body.error).toBe('Validation failed');
      });
    });

    describe('POST /auth/login', () => {
      test('should login user successfully', async () => {
        const loginData = {
          email: 'test@example.com',
          password: 'SecurePass123!',
          tenantId: 'test-tenant-id',
        };

        const user = {
          ...createTestUser(),
          tenant: createTestTenant(),
        };

        mockPrisma.user.findFirst.mockResolvedValue(user);
        mockPrisma.user.update.mockResolvedValue(user);
        mockRedis.setex.mockResolvedValue('OK');
        mockRedis.zadd.mockResolvedValue(1);
        mockRedis.zcard.mockResolvedValue(1);

        (bcrypt.compare as jest.Mock).mockResolvedValue(true);
        (jwt.sign as jest.Mock).mockReturnValue('mock-jwt-token');

        const response = await request
          .post('/auth/login')
          .send(loginData);

        expect(response.status).toBe(200);
        expect(response.body.message).toBe('Login successful');
        expect(response.body.user.email).toBe(loginData.email);
        expect(response.body.accessToken).toBeDefined();
        expect(response.body.refreshToken).toBeDefined();
        expect(response.headers['set-cookie']).toBeDefined();
      });

      test('should return 401 for invalid credentials', async () => {
        const loginData = {
          email: 'test@example.com',
          password: 'wrongpassword',
          tenantId: 'test-tenant-id',
        };

        mockPrisma.user.findFirst.mockResolvedValue(null);

        const response = await request
          .post('/auth/login')
          .send(loginData);

        expect(response.status).toBe(401);
        expect(response.body.error).toBe('Invalid credentials');
      });

      test('should return 401 for inactive user', async () => {
        const loginData = {
          email: 'test@example.com',
          password: 'SecurePass123!',
          tenantId: 'test-tenant-id',
        };

        const inactiveUser = {
          ...createTestUser(),
          isActive: false,
          tenant: createTestTenant(),
        };

        mockPrisma.user.findFirst.mockResolvedValue(inactiveUser);

        const response = await request
          .post('/auth/login')
          .send(loginData);

        expect(response.status).toBe(401);
        expect(response.body.error).toBe('Account is inactive');
      });

      test('should handle rate limiting', async () => {
        const loginData = {
          email: 'test@example.com',
          password: 'wrongpassword',
          tenantId: 'test-tenant-id',
        };

        // Simulate rate limit exceeded
        mockRedis.zadd.mockResolvedValue(1);
        mockRedis.zcard.mockResolvedValue(6); // Over limit
        mockRedis.zremrangebyscore.mockResolvedValue(0);

        const response = await request
          .post('/auth/login')
          .send(loginData);

        expect(response.status).toBe(429);
        expect(response.body.error).toBe('Too many login attempts');
      });
    });

    describe('POST /auth/logout', () => {
      test('should logout user successfully', async () => {
        const token = 'valid-jwt-token';
        (jwt.verify as jest.Mock).mockReturnValue({ 
          userId: 'test-user-id',
          exp: Math.floor(Date.now() / 1000) + 3600 
        });
        
        mockRedis.del.mockResolvedValue(1);
        mockRedis.setex.mockResolvedValue('OK');

        const response = await request
          .post('/auth/logout')
          .set('Authorization', `Bearer ${token}`);

        expect(response.status).toBe(200);
        expect(response.body.message).toBe('Logout successful');
        expect(mockRedis.setex).toHaveBeenCalled(); // Blacklist token
      });

      test('should return 401 for missing token', async () => {
        const response = await request
          .post('/auth/logout');

        expect(response.status).toBe(401);
        expect(response.body.error).toBe('Unauthorized');
      });
    });

    describe('POST /auth/refresh', () => {
      test('should refresh token successfully', async () => {
        const oldRefreshToken = 'old-refresh-token';
        const decodedToken = {
          userId: 'test-user-id',
          tenantId: 'test-tenant-id',
          type: 'refresh',
          exp: Math.floor(Date.now() / 1000) + 86400,
        };

        (jwt.verify as jest.Mock).mockReturnValue(decodedToken);
        (jwt.sign as jest.Mock).mockReturnValue('new-jwt-token');
        
        mockRedis.get.mockResolvedValue(oldRefreshToken);
        mockRedis.del.mockResolvedValue(1);
        mockRedis.setex.mockResolvedValue('OK');
        
        const user = createTestUser();
        mockPrisma.user.findUnique.mockResolvedValue(user);

        const response = await request
          .post('/auth/refresh')
          .send({ refreshToken: oldRefreshToken });

        expect(response.status).toBe(200);
        expect(response.body.accessToken).toBeDefined();
        expect(response.body.refreshToken).toBeDefined();
        expect(mockRedis.setex).toHaveBeenCalledTimes(2); // Blacklist old, store new
      });

      test('should return 401 for invalid refresh token', async () => {
        (jwt.verify as jest.Mock).mockImplementation(() => {
          throw new Error('Invalid token');
        });

        const response = await request
          .post('/auth/refresh')
          .send({ refreshToken: 'invalid-token' });

        expect(response.status).toBe(401);
        expect(response.body.error).toBe('Invalid refresh token');
      });
    });

    describe('GET /auth/me', () => {
      test('should return current user info', async () => {
        const token = 'valid-jwt-token';
        const decodedToken = {
          userId: 'test-user-id',
          tenantId: 'test-tenant-id',
          role: 'VIEWER',
        };

        (jwt.verify as jest.Mock).mockReturnValue(decodedToken);
        mockRedis.get.mockResolvedValue(null); // Not blacklisted
        
        const user = createTestUser();
        mockPrisma.user.findUnique.mockResolvedValue(user);

        const response = await request
          .get('/auth/me')
          .set('Authorization', `Bearer ${token}`);

        expect(response.status).toBe(200);
        expect(response.body.email).toBe(user.email);
        expect(response.body).not.toHaveProperty('passwordHash');
      });

      test('should return 401 for blacklisted token', async () => {
        const token = 'blacklisted-jwt-token';
        const decodedToken = {
          userId: 'test-user-id',
          tenantId: 'test-tenant-id',
        };

        (jwt.verify as jest.Mock).mockReturnValue(decodedToken);
        mockRedis.get.mockResolvedValue('blacklisted'); // Token is blacklisted

        const response = await request
          .get('/auth/me')
          .set('Authorization', `Bearer ${token}`);

        expect(response.status).toBe(401);
        expect(response.body.error).toBe('Token has been revoked');
      });
    });
  });

  describe('Password Management', () => {
    describe('POST /auth/forgot-password', () => {
      test('should initiate password reset', async () => {
        const resetData = {
          email: 'test@example.com',
          tenantId: 'test-tenant-id',
        };

        const user = createTestUser();
        mockPrisma.user.findFirst.mockResolvedValue(user);
        mockRedis.setex.mockResolvedValue('OK');

        const response = await request
          .post('/auth/forgot-password')
          .send(resetData);

        expect(response.status).toBe(200);
        expect(response.body.message).toBe('Password reset instructions sent');
        expect(mockRedis.setex).toHaveBeenCalled();
      });

      test('should return success even for non-existent user', async () => {
        const resetData = {
          email: 'nonexistent@example.com',
          tenantId: 'test-tenant-id',
        };

        mockPrisma.user.findFirst.mockResolvedValue(null);

        const response = await request
          .post('/auth/forgot-password')
          .send(resetData);

        expect(response.status).toBe(200);
        expect(response.body.message).toBe('Password reset instructions sent');
      });
    });

    describe('POST /auth/reset-password', () => {
      test('should reset password with valid token', async () => {
        const resetData = {
          token: 'valid-reset-token',
          newPassword: 'NewSecurePass123!',
        };

        const userId = 'test-user-id';
        mockRedis.get.mockResolvedValue(userId);
        mockRedis.del.mockResolvedValue(1);
        
        const hashedPassword = '$2b$12$newhashed';
        (bcrypt.hash as jest.Mock).mockResolvedValue(hashedPassword);
        
        const user = createTestUser();
        mockPrisma.user.update.mockResolvedValue(user);

        const response = await request
          .post('/auth/reset-password')
          .send(resetData);

        expect(response.status).toBe(200);
        expect(response.body.message).toBe('Password reset successfully');
        expect(mockPrisma.user.update).toHaveBeenCalledWith({
          where: { id: userId },
          data: { passwordHash: hashedPassword },
        });
      });

      test('should return 400 for invalid token', async () => {
        const resetData = {
          token: 'invalid-token',
          newPassword: 'NewSecurePass123!',
        };

        mockRedis.get.mockResolvedValue(null);

        const response = await request
          .post('/auth/reset-password')
          .send(resetData);

        expect(response.status).toBe(400);
        expect(response.body.error).toBe('Invalid or expired reset token');
      });
    });

    describe('POST /auth/change-password', () => {
      test('should change password for authenticated user', async () => {
        const token = 'valid-jwt-token';
        const decodedToken = {
          userId: 'test-user-id',
          tenantId: 'test-tenant-id',
        };

        (jwt.verify as jest.Mock).mockReturnValue(decodedToken);
        mockRedis.get.mockResolvedValue(null); // Not blacklisted

        const passwordData = {
          currentPassword: 'OldPass123!',
          newPassword: 'NewSecurePass123!',
        };

        const user = createTestUser();
        mockPrisma.user.findUnique.mockResolvedValue(user);
        
        (bcrypt.compare as jest.Mock).mockResolvedValue(true);
        (bcrypt.hash as jest.Mock).mockResolvedValue('$2b$12$newhashed');
        
        mockPrisma.user.update.mockResolvedValue(user);

        const response = await request
          .post('/auth/change-password')
          .set('Authorization', `Bearer ${token}`)
          .send(passwordData);

        expect(response.status).toBe(200);
        expect(response.body.message).toBe('Password changed successfully');
      });

      test('should return 401 for incorrect current password', async () => {
        const token = 'valid-jwt-token';
        const decodedToken = {
          userId: 'test-user-id',
          tenantId: 'test-tenant-id',
        };

        (jwt.verify as jest.Mock).mockReturnValue(decodedToken);
        mockRedis.get.mockResolvedValue(null);

        const passwordData = {
          currentPassword: 'WrongPass123!',
          newPassword: 'NewSecurePass123!',
        };

        const user = createTestUser();
        mockPrisma.user.findUnique.mockResolvedValue(user);
        
        (bcrypt.compare as jest.Mock).mockResolvedValue(false);

        const response = await request
          .post('/auth/change-password')
          .set('Authorization', `Bearer ${token}`)
          .send(passwordData);

        expect(response.status).toBe(401);
        expect(response.body.error).toBe('Current password is incorrect');
      });
    });
  });

  describe('Admin Endpoints', () => {
    describe('POST /auth/admin/revoke-sessions', () => {
      test('should revoke all user sessions', async () => {
        const adminToken = 'admin-jwt-token';
        const adminDecoded = {
          userId: 'admin-user-id',
          tenantId: 'test-tenant-id',
          role: 'ADMIN',
        };

        (jwt.verify as jest.Mock).mockReturnValue(adminDecoded);
        mockRedis.get.mockResolvedValue(null);
        
        mockRedis.keys.mockResolvedValue([
          'refresh:test-user-id:token1',
          'refresh:test-user-id:token2',
        ]);
        
        mockRedis.pipeline.mockReturnValue({
          del: jest.fn().mockReturnThis(),
          exec: jest.fn().mockResolvedValue([]),
        });

        const response = await request
          .post('/auth/admin/revoke-sessions')
          .set('Authorization', `Bearer ${adminToken}`)
          .send({ userId: 'test-user-id' });

        expect(response.status).toBe(200);
        expect(response.body.message).toBe('All sessions revoked successfully');
        expect(response.body.revokedCount).toBe(2);
      });

      test('should return 403 for non-admin user', async () => {
        const userToken = 'user-jwt-token';
        const userDecoded = {
          userId: 'regular-user-id',
          tenantId: 'test-tenant-id',
          role: 'VIEWER',
        };

        (jwt.verify as jest.Mock).mockReturnValue(userDecoded);
        mockRedis.get.mockResolvedValue(null);

        const response = await request
          .post('/auth/admin/revoke-sessions')
          .set('Authorization', `Bearer ${userToken}`)
          .send({ userId: 'test-user-id' });

        expect(response.status).toBe(403);
        expect(response.body.error).toBe('Admin access required');
      });
    });
  });

  describe('Error Handling', () => {
    test('should handle database errors gracefully', async () => {
      const loginData = {
        email: 'test@example.com',
        password: 'SecurePass123!',
        tenantId: 'test-tenant-id',
      };

      mockPrisma.user.findFirst.mockRejectedValue(new Error('Database connection failed'));

      const response = await request
        .post('/auth/login')
        .send(loginData);

      expect(response.status).toBe(500);
      expect(response.body.error).toBe('Internal server error');
    });

    test('should handle Redis errors gracefully', async () => {
      const token = 'valid-jwt-token';
      const decodedToken = {
        userId: 'test-user-id',
        tenantId: 'test-tenant-id',
      };

      (jwt.verify as jest.Mock).mockReturnValue(decodedToken);
      mockRedis.get.mockRejectedValue(new Error('Redis connection failed'));

      const response = await request
        .get('/auth/me')
        .set('Authorization', `Bearer ${token}`);

      expect(response.status).toBe(500);
      expect(response.body.error).toBe('Internal server error');
    });

    test('should validate request body', async () => {
      const response = await request
        .post('/auth/login')
        .send({}); // Empty body

      expect(response.status).toBe(400);
      expect(response.body.error).toBe('Validation failed');
    });

    test('should handle malformed JSON', async () => {
      const response = await request
        .post('/auth/login')
        .set('Content-Type', 'application/json')
        .send('{ invalid json');

      expect(response.status).toBe(400);
      expect(response.body.error).toBe('Invalid JSON');
    });
  });
});