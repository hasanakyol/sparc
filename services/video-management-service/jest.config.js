const baseConfig = require('../../jest.config.base');

module.exports = {
  ...baseConfig,
  displayName: 'video-management-service',
  testMatch: [
    '<rootDir>/src/**/__tests__/**/*.test.ts',
    '<rootDir>/src/**/*.test.ts',
  ],
  setupFilesAfterEnv: ['<rootDir>/src/__tests__/setup.ts'],
};
