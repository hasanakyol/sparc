const baseConfig = require('../../jest.config.base');

module.exports = {
  ...baseConfig,
  displayName: 'access-control-service',
  testMatch: [
    '<rootDir>/src/**/__tests__/**/*.test.ts',
    '<rootDir>/src/**/*.test.ts',
  ],
  setupFilesAfterEnv: ['<rootDir>/src/__tests__/setup.ts'],
};