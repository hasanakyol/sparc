// Test setup file
import { setupTestEnv } from './test-utils';

// Set up test environment before all tests
beforeAll(() => {
  setupTestEnv();
});

// Clean up after each test
afterEach(() => {
  jest.clearAllMocks();
});

// Global test timeout
jest.setTimeout(10000);