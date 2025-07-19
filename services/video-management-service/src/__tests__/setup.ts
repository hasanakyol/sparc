// Test setup file for video-management-service
import { TextEncoder, TextDecoder } from 'util';

// Polyfill for TextEncoder/TextDecoder in Node.js test environment
global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder as any;

// Set up test environment variables
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test-secret';
process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test';
process.env.REDIS_URL = 'redis://localhost:6379';
process.env.VIDEO_STORAGE_PATH = '/tmp/test-recordings';
process.env.STREAM_BASE_URL = 'http://localhost:8080';

// Mock console methods to reduce noise in tests
global.console = {
  ...console,
  log: jest.fn(),
  error: jest.fn(),
  warn: jest.fn(),
  info: jest.fn(),
  debug: jest.fn(),
};

// Clean up after each test
afterEach(() => {
  jest.clearAllMocks();
});

// Global test timeout
jest.setTimeout(10000);
