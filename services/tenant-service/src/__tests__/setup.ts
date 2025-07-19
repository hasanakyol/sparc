// Test setup file

// Set up test environment
process.env.NODE_ENV = 'test';
process.env.TEST_DATABASE_URL = 'postgresql://test:test@localhost:5432/sparc_test';
process.env.JWT_SECRET = 'test-secret';
process.env.LOG_LEVEL = 'error'; // Reduce log noise during tests

// Mock environment variables
beforeAll(() => {
  // Add any global test setup here
});

// Clean up after each test
afterEach(() => {
  jest.clearAllMocks();
});

// Global test timeout
jest.setTimeout(30000);