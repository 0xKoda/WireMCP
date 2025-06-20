// jest.config.js - Jest configuration for WireMCP tests
module.exports = {
  testEnvironment: 'node',
  collectCoverageFrom: [
    'index.js',
    '!node_modules/**',
    '!test/**'
  ],
  coverageReporters: [
    'text',
    'lcov',
    'html'
  ],
  coverageDirectory: 'coverage',
  testMatch: [
    '**/test/**/*.test.js',
    '**/*.test.js'
  ],
  setupFilesAfterEnv: ['<rootDir>/test/setup.js'],
  collectCoverage: false, // Set to true when running coverage reports
  verbose: true,
  testTimeout: 10000, // 10 second timeout for tests
  maxWorkers: 4,
  clearMocks: true,
  restoreMocks: true
}; 