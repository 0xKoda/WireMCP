# WireMCP Test Suite

This directory contains comprehensive unit and integration tests for the WireMCP server.

## Test Structure

- `index.test.js` - Main unit tests covering all tools and utilities
- `integration.test.js` - Integration tests for complex workflows and server initialization  
- `test-helpers.js` - Shared test utilities, mock data, and helper functions
- `setup.js` - Global test configuration and custom Jest matchers

## Running Tests

```bash
# Run all tests
npm test

# Run tests in watch mode (reruns on file changes)
npm run test:watch

# Run tests with coverage report
npm run test:coverage

# Run specific test file
npx jest index.test.js

# Run specific test suite
npx jest --testNamePattern="capture_packets"
```

## Test Coverage

The test suite covers:

### Core Functionality
- ✅ All 7 MCP tools (`capture_packets`, `get_summary_stats`, `get_conversations`, `check_threats`, `check_ip_threats`, `analyze_pcap`, `extract_credentials`)
- ✅ `findTshark` utility function with fallback paths
- ✅ Server initialization and MCP tool/prompt registration
- ✅ Default parameter handling

### Error Scenarios
- ✅ tshark not found or permission denied
- ✅ Invalid network interfaces
- ✅ Missing PCAP files
- ✅ Malformed JSON responses from tshark
- ✅ URLhaus API failures
- ✅ Network timeouts and connectivity issues

### Security & Performance
- ✅ Input sanitization for potentially malicious interface names
- ✅ Large dataset handling and memory management
- ✅ Response size limiting (720k character limit)
- ✅ Concurrent tool execution
- ✅ Temporary file cleanup

### Data Processing
- ✅ HTTP Basic Auth credential extraction
- ✅ FTP credential extraction  
- ✅ Kerberos hash extraction
- ✅ Telnet credential detection
- ✅ Protocol hierarchy parsing
- ✅ Conversation statistics parsing
- ✅ IP threat detection against URLhaus blacklist

## Mock Data

The test suite uses realistic mock data including:
- Sample packet captures with various protocols (HTTP, HTTPS, DNS)
- URLhaus blacklist responses
- tshark output formats for all supported analysis types
- Various credential formats (Base64, plaintext, Kerberos hashes)

## Custom Jest Matchers

- `toBeValidToolResponse()` - Validates MCP tool response format
- `toBeErrorResponse()` - Validates error response format

## Test Philosophy

Tests follow these principles:
1. **Comprehensive mocking** - All external dependencies (tshark, axios, fs) are mocked
2. **Realistic scenarios** - Mock data mirrors real-world network captures
3. **Error resilience** - Every error path is tested
4. **Performance awareness** - Large dataset handling is validated
5. **Security conscious** - Malicious input scenarios are covered

## Adding New Tests

When adding new tools or modifying existing ones:

1. Add unit tests to `index.test.js` for the specific tool
2. Add integration tests to `integration.test.js` if the tool interacts with others
3. Update mock data in `test-helpers.js` if needed
4. Ensure both success and error paths are covered
5. Test with realistic data sizes and formats 