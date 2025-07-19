module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src'],
  testMatch: ['**/__tests__/**/*.test.ts', '**/*.spec.ts'],
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/**/__tests__/**',
    '!src/**/index.ts'
  ],
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80
    }
  },
  moduleNameMapper: {
    '@/(.*)': '<rootDir>/src/$1',
    '@sparc/shared': '<rootDir>/../../packages/shared/src',
    '@sparc/database': '<rootDir>/../../packages/database/src'
  },
  setupFilesAfterEnv: ['<rootDir>/src/__tests__/setup.ts'],
  transform: {
    '^.+\\.ts$': ['ts-jest', {
      tsconfig: {
        allowJs: true,
        esModuleInterop: true,
        resolveJsonModule: true
      }
    }]
  }
};