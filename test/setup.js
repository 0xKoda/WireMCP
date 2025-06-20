// test/setup.js - Global test setup for WireMCP tests

// Suppress console output during tests unless explicitly needed
const originalConsole = global.console;

global.console = {
  ...originalConsole,
  log: jest.fn(),
  error: jest.fn(),
  warn: jest.fn(),
  info: jest.fn(),
  debug: jest.fn()
};

// Add custom matchers if needed
expect.extend({
  toBeValidToolResponse(received) {
    const pass = received && 
                 received.content && 
                 Array.isArray(received.content) &&
                 received.content.length > 0 &&
                 received.content[0].type === 'text' &&
                 typeof received.content[0].text === 'string';

    if (pass) {
      return {
        message: () => `expected ${JSON.stringify(received)} not to be a valid tool response`,
        pass: true,
      };
    } else {
      return {
        message: () => `expected ${JSON.stringify(received)} to be a valid tool response`,
        pass: false,
      };
    }
  },

  toBeErrorResponse(received) {
    const pass = received && received.isError === true;

    if (pass) {
      return {
        message: () => `expected ${JSON.stringify(received)} not to be an error response`,
        pass: true,
      };
    } else {
      return {
        message: () => `expected ${JSON.stringify(received)} to be an error response`,
        pass: false,
      };
    }
  }
});

// Global timeout for async operations
jest.setTimeout(10000);

// Clean up after each test
afterEach(() => {
  jest.clearAllMocks();
});

// Clean up after all tests
afterAll(() => {
  global.console = originalConsole;
}); 