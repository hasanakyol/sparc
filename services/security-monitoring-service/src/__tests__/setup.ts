import { vi } from 'vitest';

// Mock environment variables
process.env.NODE_ENV = 'test';
process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test';
process.env.REDIS_URL = 'redis://localhost:6379';
process.env.JWT_SECRET = 'test-secret';

// Mock external modules
vi.mock('ioredis', () => {
  const Redis = vi.fn(() => ({
    get: vi.fn(),
    set: vi.fn(),
    del: vi.fn(),
    expire: vi.fn(),
    publish: vi.fn(),
    subscribe: vi.fn(),
    on: vi.fn(),
    quit: vi.fn()
  }));
  return { default: Redis };
});

vi.mock('@prisma/client', () => ({
  PrismaClient: vi.fn(() => ({
    $connect: vi.fn(),
    $disconnect: vi.fn(),
    $transaction: vi.fn()
  }))
}));

// Global test utilities
export const createMockContext = () => ({
  req: {
    header: vi.fn(),
    param: vi.fn(),
    query: vi.fn(),
    valid: vi.fn()
  },
  json: vi.fn(),
  status: vi.fn(),
  header: vi.fn(),
  get: vi.fn(),
  set: vi.fn()
});

export const createMockWebSocket = () => ({
  send: vi.fn(),
  close: vi.fn(),
  on: vi.fn(),
  emit: vi.fn()
});