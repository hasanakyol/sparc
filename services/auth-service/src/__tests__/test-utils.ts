import type { User, Tenant } from '@prisma/client';

// Mock implementations for testing
export const mockPrisma = {
  user: {
    create: jest.fn(),
    findFirst: jest.fn(),
    findUnique: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
    count: jest.fn(),
    findMany: jest.fn(),
    groupBy: jest.fn(),
  },
  tenant: {
    findUnique: jest.fn(),
  },
  auditLog: {
    create: jest.fn(),
    count: jest.fn(),
  },
  $transaction: jest.fn(),
  $queryRaw: jest.fn(),
  $disconnect: jest.fn(),
};

export const mockRedis = {
  setex: jest.fn(),
  get: jest.fn(),
  del: jest.fn(),
  exists: jest.fn(),
  expire: jest.fn(),
  keys: jest.fn(),
  ping: jest.fn(),
  quit: jest.fn(),
  zadd: jest.fn(),
  zcard: jest.fn(),
  zremrangebyscore: jest.fn(),
  pipeline: jest.fn(() => ({
    del: jest.fn().mockReturnThis(),
    exec: jest.fn().mockResolvedValue([]),
  })),
};

// Test data factories
export const createTestUser = (): User => ({
  id: 'test-user-id',
  email: 'test@example.com',
  username: 'testuser',
  firstName: 'Test',
  lastName: 'User',
  passwordHash: '$2b$12$hashedpassword',
  tenantId: 'test-tenant-id',
  role: 'VIEWER',
  isActive: true,
  createdAt: new Date(),
  updatedAt: new Date(),
  lastLoginAt: null,
  emailVerified: false,
  phoneNumber: null,
  phoneVerified: false,
  mfaEnabled: false,
  mfaSecret: null,
  metadata: {},
});

export const createTestTenant = (): Tenant => ({
  id: 'test-tenant-id',
  name: 'Test Tenant',
  isActive: true,
  createdAt: new Date(),
  updatedAt: new Date(),
  settings: {},
  features: [],
  subscriptionTier: 'BASIC',
  subscriptionExpiresAt: null,
});

// Helper to create test tokens
export const createTestToken = (userId: string, tenantId: string, role: string = 'VIEWER') => {
  return 'test-jwt-token';
};

// Helper to create mock request with auth
export const createAuthenticatedRequest = (overrides = {}) => {
  return {
    headers: {
      'authorization': 'Bearer test-jwt-token',
      'content-type': 'application/json',
    },
    ...overrides,
  };
};

// Mock environment variables for testing
export const setupTestEnv = () => {
  process.env.NODE_ENV = 'test';
  process.env.JWT_SECRET = 'test-secret';
  process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test';
  process.env.REDIS_URL = 'redis://localhost:6379';
  process.env.BCRYPT_ROUNDS = '10';
  process.env.JWT_EXPIRES_IN = '1h';
  process.env.REFRESH_TOKEN_EXPIRES_IN = '7d';
};

// Cleanup helper
export const cleanupTestEnv = () => {
  jest.clearAllMocks();
  jest.restoreAllMocks();
};