import { jest } from '@jest/globals';

// Mock environment variables
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test-jwt-secret';
process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test_visitor_management';
process.env.REDIS_URL = 'redis://localhost:6379/2';
process.env.ENABLE_TRACING = 'false';

// Mock console to reduce noise
global.console = {
  ...console,
  log: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  // Keep error for debugging
  error: console.error,
};

// Mock timers for consistent test results
jest.useFakeTimers({
  doNotFake: ['nextTick', 'setImmediate'],
});

// Global test timeout
jest.setTimeout(30000);

// Clean up after all tests
afterAll(async () => {
  jest.useRealTimers();
});