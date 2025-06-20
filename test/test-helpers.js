// test/test-helpers.js - Test utilities and mock data for WireMCP tests

const mockPacketData = [
  {
    _source: {
      layers: {
        'frame.number': ['1'],
        'ip.src': ['192.168.1.100'],
        'ip.dst': ['8.8.8.8'],
        'tcp.srcport': ['50234'],
        'tcp.dstport': ['443'],
        'tcp.flags': ['0x0018'],
        'frame.time': ['2024-01-01 12:00:00.000000'],
        'frame.protocols': ['eth:ethertype:ip:tcp:tls']
      }
    }
  },
  {
    _source: {
      layers: {
        'frame.number': ['2'],
        'ip.src': ['192.168.1.100'],
        'ip.dst': ['10.0.0.1'],
        'tcp.srcport': ['50235'],
        'tcp.dstport': ['80'],
        'http.request.method': ['GET'],
        'http.host': ['example.com'],
        'http.request.uri': ['/api/data'],
        'frame.protocols': ['eth:ethertype:ip:tcp:http']
      }
    }
  }
];

const mockProtocolStats = `
Protocol Hierarchy Statistics
Filter: 

eth                                      frames:142 bytes:18704 (100.00%)
  ip                                     frames:142 bytes:18704 (100.00%)
    tcp                                  frames:136 bytes:18104 (96.79%)
      tls                                frames:98  bytes:14280 (76.32%)
      http                               frames:38  bytes:3824 (20.44%)
    udp                                  frames:6   bytes:600 (3.21%)
      dns                                frames:6   bytes:600 (3.21%)
`;

const mockConversationStats = `
TCP Conversations
Filter:<No Filter>
                                               |       <-      | |       ->      | |     Total     |
                                               | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |
192.168.1.100:50234 <-> 8.8.8.8:443            45    8500      53    9750      98   18250
192.168.1.100:50235 <-> 10.0.0.1:80            18    1900      20    1924      38   3824
`;

const mockUrlhausBlacklist = `
# abuse.ch URLhaus Host Blacklist
# Generated on 2024-01-01 12:00:00 UTC
#
# Terms Of Use: https://urlhaus.abuse.ch/api/
# For questions please contact urlhaus [at] abuse.ch
#
192.168.1.200
10.0.0.100
malicious-domain.com
badactor.net/path
`;

const mockCredentialExtracts = {
  httpBasic: Buffer.from('testuser:testpass123').toString('base64'),
  ftpCommands: [
    '\tUSER\tftpadmin\t\t5',
    '\tPASS\tsecret123\t\t6'
  ],
  kerberos: 'krb_user\tEXAMPLE.COM\ta1b2c3d4e5f6\t23\t11\t10'
};

// Helper functions for test setup
const createMockExecAsync = (responses) => {
  let callCount = 0;
  return jest.fn().mockImplementation(() => {
    const response = responses[callCount] || responses[responses.length - 1];
    callCount++;
    if (response.error) {
      return Promise.reject(new Error(response.error));
    }
    return Promise.resolve(response);
  });
};

const setupTsharkMocks = (which, fs, execAsync) => {
  which.mockResolvedValue('/usr/bin/tshark');
  fs.access.mockResolvedValue();
  fs.unlink.mockResolvedValue();
  return execAsync;
};

const expectTsharkCommand = (execAsync, commandPattern, callIndex = 0) => {
  expect(execAsync).toHaveBeenNthCalledWith(
    callIndex + 1,
    expect.stringMatching(commandPattern),
    expect.objectContaining({
      env: expect.objectContaining({
        PATH: expect.stringContaining('/usr/bin:/usr/local/bin:/opt/homebrew/bin')
      })
    })
  );
};

// Mock response builders
const buildPacketResponse = (packets = mockPacketData) => ({
  stdout: JSON.stringify(packets),
  stderr: ''
});

const buildStatsResponse = (stats = mockProtocolStats) => ({
  stdout: stats,
  stderr: ''
});

const buildIPsResponse = (ips = ['192.168.1.100', '8.8.8.8']) => ({
  stdout: ips.map(ip => `${ip}\t${ip}`).join('\n'),
  stderr: ''
});

const buildCredentialResponse = (type = 'httpBasic') => ({
  stdout: type === 'httpBasic' ? 
    `${mockCredentialExtracts.httpBasic}\t\t\t\t1\n` :
    type === 'ftp' ?
    mockCredentialExtracts.ftpCommands.join('\n') + '\n' :
    type === 'kerberos' ?
    `${mockCredentialExtracts.kerberos}\n` :
    '',
  stderr: ''
});

// Error scenarios
const commonErrors = {
  tsharkNotFound: 'tshark not found. Please install Wireshark',
  permissionDenied: 'Permission denied',
  interfaceNotFound: 'Interface not found',
  fileNotFound: 'No such file or directory',
  invalidJSON: 'Unexpected token',
  networkTimeout: 'Network timeout'
};

// Validation helpers
const validateToolResponse = (response, shouldContain = []) => {
  expect(response).toBeDefined();
  expect(response.content).toBeDefined();
  expect(Array.isArray(response.content)).toBe(true);
  expect(response.content.length).toBeGreaterThan(0);
  expect(response.content[0].type).toBe('text');
  expect(response.content[0].text).toBeDefined();
  
  shouldContain.forEach(text => {
    expect(response.content[0].text).toContain(text);
  });
};

const validateErrorResponse = (response, errorMessage = null) => {
  expect(response.isError).toBe(true);
  if (errorMessage) {
    expect(response.content[0].text).toContain(errorMessage);
  }
};

module.exports = {
  mockPacketData,
  mockProtocolStats,
  mockConversationStats,
  mockUrlhausBlacklist,
  mockCredentialExtracts,
  createMockExecAsync,
  setupTsharkMocks,
  expectTsharkCommand,
  buildPacketResponse,
  buildStatsResponse,
  buildIPsResponse,
  buildCredentialResponse,
  commonErrors,
  validateToolResponse,
  validateErrorResponse
}; 