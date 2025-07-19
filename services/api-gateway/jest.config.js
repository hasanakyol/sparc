const baseConfig = require('../../jest.config.base');

module.exports = {
  ...baseConfig,
  displayName: 'api-gateway',
  testMatch: [
    '<rootDir>/src/**/__tests__/**/*.test.ts',
    '<rootDir>/src/**/*.test.ts',
    '<rootDir>/src/**/__tests__/**/*.integration.test.ts',
    '<rootDir>/src/**/*.integration.test.ts',
  ],
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/**/*.test.ts',
    '!src/**/*.integration.test.ts',
    '!src/**/__tests__/**',
    '!src/**/__mocks__/**',
    '!src/index.ts',
    '!src/types/**',
  ],
  coverageThreshold: {
    global: {
      branches: 90,
      functions: 90,
      lines: 90,
      statements: 90,
    },
  },
};