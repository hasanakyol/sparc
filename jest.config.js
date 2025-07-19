module.exports = {
  projects: [
    '<rootDir>/packages/*/jest.config.js',
    '<rootDir>/services/*/jest.config.js',
    '<rootDir>/web/jest.config.js',
  ],
  collectCoverage: true,
  coverageDirectory: '<rootDir>/coverage',
  coverageReporters: ['text', 'lcov', 'html', 'json', 'json-summary', 'cobertura'],
  coveragePathIgnorePatterns: [
    '/node_modules/',
    '/dist/',
    '/build/',
    '/.next/',
    '/coverage/',
    '/__tests__/',
    '/__mocks__/',
  ],
  // Merge coverage from all projects
  collectCoverageFrom: [
    'packages/*/src/**/*.{ts,tsx}',
    'services/*/src/**/*.{ts,tsx}',
    'web/app/**/*.{ts,tsx}',
    'web/components/**/*.{ts,tsx}',
    '!**/*.d.ts',
    '!**/*.test.{ts,tsx}',
    '!**/*.spec.{ts,tsx}',
    '!**/__tests__/**',
    '!**/__mocks__/**',
    '!**/node_modules/**',
    '!**/dist/**',
    '!**/build/**',
    '!**/.next/**',
  ],
  // Global coverage thresholds
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80,
    },
  },
  testPathIgnorePatterns: [
    '/node_modules/',
    '/dist/',
    '/build/',
    '/.next/',
  ],
  // Performance settings
  maxWorkers: '50%',
  cache: true,
  cacheDirectory: '<rootDir>/.jest-cache',
  // Test result processors for CI/CD
  testResultsProcessor: 'jest-junit',
  reporters: [
    'default',
    [
      'jest-junit',
      {
        outputDirectory: './test-results',
        outputName: 'junit.xml',
        classNameTemplate: '{classname} - {title}',
        titleTemplate: '{classname} - {title}',
        ancestorSeparator: ' › ',
        usePathForSuiteName: 'true',
      },
    ],
    [
      'jest-html-reporter',
      {
        pageTitle: 'SPARC Test Report',
        outputPath: './test-results/test-report.html',
        includeFailureMsg: true,
        includeConsoleLog: true,
      },
    ],
  ],
  // Timeout for all tests
  testTimeout: 30000,
  // Verbose output
  verbose: true,
};