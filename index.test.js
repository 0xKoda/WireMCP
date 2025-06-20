// index.test.js - Unit tests for WireMCP Server

// Create a mock for execAsync that will be used in the promisify mock
const mockExecAsync = jest.fn();

// Mock all external dependencies first, before any requires
jest.mock('axios');
jest.mock('child_process');
jest.mock('which');
jest.mock('fs', () => ({
  promises: {
    access: jest.fn(),
    unlink: jest.fn(),
  }
}));

// Mock only the promisify function from util, not the entire module
jest.mock('util', () => {
  const originalUtil = jest.requireActual('util');
  return {
    ...originalUtil,
    promisify: jest.fn(() => mockExecAsync)
  };
});

// Mock MCP SDK
const mockMcpServer = {
  tool: jest.fn(),
  prompt: jest.fn(),
  connect: jest.fn().mockResolvedValue(undefined)
};

jest.mock('@modelcontextprotocol/sdk/server/mcp.js', () => ({
  McpServer: jest.fn().mockImplementation(() => mockMcpServer)
}));

jest.mock('@modelcontextprotocol/sdk/server/stdio.js', () => ({
  StdioServerTransport: jest.fn()
}));

// Now require modules after mocks are set up
const axios = require('axios');
const { exec } = require('child_process');
const { promisify } = require('util');
const which = require('which');
const fs = require('fs').promises;

const mockedAxios = axios;
const mockedExec = exec;
const mockedWhich = which;
const mockedFs = fs;

describe('WireMCP Server', () => {
  let findTshark;
  let server;
  let capturePacketsTool;
  let getSummaryStatsTool;
  let getConversationsTool;
  let checkThreatsTool;
  let checkIpThreatsTool;
  let analyzePcapTool;
  let extractCredentialsTool;

  beforeAll(() => {
    // Clear console.error mock
    console.error = jest.fn();
    
    // Import the module after setting up mocks
    delete require.cache[require.resolve('./index.js')];
    require('./index.js');
    
    // Extract the tool functions from the mocked server.tool calls
    const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
    const toolCalls = mockMcpServer.tool.mock.calls;
    
    // Extract tool implementations
    capturePacketsTool = toolCalls.find(call => call[0] === 'capture_packets')[3];
    getSummaryStatsTool = toolCalls.find(call => call[0] === 'get_summary_stats')[3];
    getConversationsTool = toolCalls.find(call => call[0] === 'get_conversations')[3];
    checkThreatsTool = toolCalls.find(call => call[0] === 'check_threats')[3];
    checkIpThreatsTool = toolCalls.find(call => call[0] === 'check_ip_threats')[3];
    analyzePcapTool = toolCalls.find(call => call[0] === 'analyze_pcap')[3];
    extractCredentialsTool = toolCalls.find(call => call[0] === 'extract_credentials')[3];
  });

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('findTshark utility', () => {
    test('should find tshark using which command', async () => {
      mockedWhich.mockResolvedValue('/usr/bin/tshark');
      
      // We need to test the findTshark function indirectly through a tool
      await capturePacketsTool({ interface: 'en0', duration: 1 });
      
      expect(mockedWhich).toHaveBeenCalledWith('tshark');
    });

    test('should fallback to common paths when which fails', async () => {
      mockedWhich.mockRejectedValue(new Error('not found'));
      mockExecAsync.mockResolvedValueOnce({ stdout: 'TShark 3.6.2', stderr: '' });
      
      await capturePacketsTool({ interface: 'en0', duration: 1 });
      
      expect(mockExecAsync).toHaveBeenCalledWith(expect.stringContaining('tshark -v'));
    });

    test('should throw error when tshark not found anywhere', async () => {
      mockedWhich.mockRejectedValue(new Error('not found'));
      mockExecAsync.mockRejectedValue(new Error('command not found'));
      
      const result = await capturePacketsTool({ interface: 'en0', duration: 1 });
      
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain('Error:');
    });
  });

  describe('capture_packets tool', () => {
    beforeEach(() => {
      mockedWhich.mockResolvedValue('/usr/bin/tshark');
      mockedFs.unlink.mockResolvedValue();
    });

    test('should capture packets successfully', async () => {
      const mockPackets = [
        {
          _source: {
            layers: {
              'frame.number': ['1'],
              'ip.src': ['192.168.1.1'],
              'ip.dst': ['192.168.1.2'],
              'tcp.srcport': ['80'],
              'tcp.dstport': ['8080']
            }
          }
        }
      ];

      mockExecAsync
        .mockResolvedValueOnce({ stdout: '', stderr: '' }) // tshark capture
        .mockResolvedValueOnce({ stdout: JSON.stringify(mockPackets), stderr: '' }); // tshark read

      const result = await capturePacketsTool({ interface: 'eth0', duration: 5 });

      expect(result.content[0].text).toContain('Captured packet data');
      expect(result.content[0].text).toContain('192.168.1.1');
      expect(mockExecAsync).toHaveBeenCalledWith(
        expect.stringContaining('tshark -i eth0 -w temp_capture.pcap -a duration:5'),
        expect.any(Object)
      );
    });

    test('should handle capture errors', async () => {
      mockedWhich.mockResolvedValue('/usr/bin/tshark');
      mockExecAsync.mockRejectedValue(new Error('Interface not found'));

      const result = await capturePacketsTool({ interface: 'invalid', duration: 1 });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain('Interface not found');
    });

    test('should trim packets when output is too large', async () => {
      // Create packets with enough data to exceed the 720k character limit
      const largePackets = Array(5000).fill(null).map((_, i) => ({
        _source: { 
          layers: { 
            'frame.number': [i.toString()], 
            'ip.src': [`192.168.${Math.floor(i/255)}.${i%255}`],
            'ip.dst': [`10.0.${Math.floor(i/255)}.${i%255}`],
            'tcp.srcport': [(50000 + i).toString()],
            'tcp.dstport': ['443'],
            'tcp.flags': ['0x00000018'],
            'frame.time': [`2024-01-01T12:00:${String(i % 60).padStart(2, '0')}.000000000Z`],
            'http.request.method': i % 10 === 0 ? ['GET'] : undefined,
            'http.response.code': i % 15 === 0 ? ['200'] : undefined,
            'http.request.uri': i % 20 === 0 ? [`/api/endpoint/${i}`] : undefined,
            'http.host': i % 25 === 0 ? [`example${i}.com`] : undefined,
            'frame.protocols': [`eth:ethertype:ip:tcp${i % 5 === 0 ? ':http' : ''}`]
          }
        }
      }));

      // Verify the JSON string would be large enough to trigger trimming
      const testJson = JSON.stringify(largePackets);
      expect(testJson.length).toBeGreaterThan(720000);

      mockExecAsync
        .mockResolvedValueOnce({ stdout: '', stderr: '' })
        .mockResolvedValueOnce({ stdout: testJson, stderr: '' });

      const result = await capturePacketsTool({ interface: 'en0', duration: 1 });

      expect(result.content[0].text).toContain('Captured packet data');
      // Should not contain the full 5000 packets due to trimming
      const resultData = JSON.parse(result.content[0].text.split(':\n')[1]);
      expect(resultData.length).toBeLessThan(5000);
    });
  });

  describe('get_summary_stats tool', () => {
    beforeEach(() => {
      mockedWhich.mockResolvedValue('/usr/bin/tshark');
      mockedFs.unlink.mockResolvedValue();
    });

    test('should get protocol hierarchy statistics', async () => {
      const mockStats = `
Protocol Hierarchy Statistics
eth                                      frames:100 bytes:50000
  ip                                     frames:90  bytes:45000
    tcp                                  frames:80  bytes:40000
      http                               frames:20  bytes:10000
`;

      mockExecAsync
        .mockResolvedValueOnce({ stdout: '', stderr: '' })
        .mockResolvedValueOnce({ stdout: mockStats, stderr: '' });

      const result = await getSummaryStatsTool({ interface: 'en0', duration: 3 });

      expect(result.content[0].text).toContain('Protocol hierarchy statistics');
      expect(result.content[0].text).toContain('tcp');
      expect(result.content[0].text).toContain('http');
    });
  });

  describe('get_conversations tool', () => {
    beforeEach(() => {
      mockedWhich.mockResolvedValue('/usr/bin/tshark');
      mockedFs.unlink.mockResolvedValue();
    });

    test('should get TCP conversation statistics', async () => {
      const mockConversations = `
TCP Conversations
Filter:<No Filter>
                                               |       <-      | |       ->      | |     Total     |
                                               | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |
192.168.1.1:80      <-> 192.168.1.2:8080        10    5000      15    7500      25   12500
`;

      mockExecAsync
        .mockResolvedValueOnce({ stdout: '', stderr: '' })
        .mockResolvedValueOnce({ stdout: mockConversations, stderr: '' });

      const result = await getConversationsTool({ interface: 'en0', duration: 2 });

      expect(result.content[0].text).toContain('TCP/UDP conversation statistics');
      expect(result.content[0].text).toContain('192.168.1.1');
    });
  });

  describe('check_threats tool', () => {
    beforeEach(() => {
      mockedWhich.mockResolvedValue('/usr/bin/tshark');
      mockedFs.unlink.mockResolvedValue();
    });

    test('should check IPs against URLhaus blacklist', async () => {
      const mockIPs = '192.168.1.1\t10.0.0.1\n192.168.1.2\t10.0.0.2\n';
      const mockBlacklist = `
# URLhaus blacklist
192.168.1.1
malicious.example.com
10.0.0.1
`;

      mockExecAsync
        .mockResolvedValueOnce({ stdout: '', stderr: '' }) // capture
        .mockResolvedValueOnce({ stdout: mockIPs, stderr: '' }); // extract IPs

      mockedAxios.get.mockResolvedValue({ 
        status: 200, 
        data: mockBlacklist 
      });

      const result = await checkThreatsTool({ interface: 'en0', duration: 1 });

      expect(result.content[0].text).toContain('Captured IPs:');
      expect(result.content[0].text).toContain('192.168.1.1');
      expect(result.content[0].text).toContain('Potential threats: 192.168.1.1, 10.0.0.1');
    });

    test('should handle URLhaus API failure gracefully', async () => {
      const mockIPs = '192.168.1.1\t10.0.0.1\n';

      mockExecAsync
        .mockResolvedValueOnce({ stdout: '', stderr: '' })
        .mockResolvedValueOnce({ stdout: mockIPs, stderr: '' });

      mockedAxios.get.mockRejectedValue(new Error('API unavailable'));

      const result = await checkThreatsTool({ interface: 'en0', duration: 1 });

      expect(result.content[0].text).toContain('No threats detected');
    });
  });

  describe('check_ip_threats tool', () => {
    test('should check single IP against URLhaus', async () => {
      const mockBlacklist = `
# URLhaus blacklist
192.168.1.100
malicious.example.com
`;

      mockedAxios.get.mockResolvedValue({ 
        status: 200, 
        data: mockBlacklist 
      });

      const result = await checkIpThreatsTool({ ip: '192.168.1.100' });

      expect(result.content[0].text).toContain('IP checked: 192.168.1.100');
      expect(result.content[0].text).toContain('Potential threat detected');
    });

    test('should report clean IP', async () => {
      const mockBlacklist = `
# URLhaus blacklist
192.168.1.100
`;

      mockedAxios.get.mockResolvedValue({ 
        status: 200, 
        data: mockBlacklist 
      });

      const result = await checkIpThreatsTool({ ip: '192.168.1.50' });

      expect(result.content[0].text).toContain('No threat detected');
    });
  });

  describe('analyze_pcap tool', () => {
    beforeEach(() => {
      mockedWhich.mockResolvedValue('/usr/bin/tshark');
      mockedFs.access.mockResolvedValue();
    });

    test('should analyze PCAP file successfully', async () => {
      const mockPackets = [
        {
          _source: {
            layers: {
              'frame.number': ['1'],
              'ip.src': ['192.168.1.1'],
              'ip.dst': ['192.168.1.2'],
              'http.host': ['example.com'],
              'http.request.uri': ['/api/test'],
              'frame.protocols': ['eth:ethertype:ip:tcp:http']
            }
          }
        }
      ];

      mockExecAsync.mockResolvedValue({ 
        stdout: JSON.stringify(mockPackets), 
        stderr: '' 
      });

      const result = await analyzePcapTool({ pcapPath: './test.pcap' });

      expect(result.content[0].text).toContain('Analyzed PCAP: ./test.pcap');
      expect(result.content[0].text).toContain('192.168.1.1');
      expect(result.content[0].text).toContain('http://example.com/api/test');
      expect(mockedFs.access).toHaveBeenCalledWith('./test.pcap');
    });

    test('should handle missing PCAP file', async () => {
      mockedFs.access.mockRejectedValue(new Error('File not found'));

      const result = await analyzePcapTool({ pcapPath: './missing.pcap' });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain('File not found');
    });
  });

  describe('extract_credentials tool', () => {
    beforeEach(() => {
      mockedWhich.mockResolvedValue('/usr/bin/tshark');
      mockedFs.access.mockResolvedValue();
    });

    test('should extract HTTP Basic Auth credentials', async () => {
      const base64Creds = Buffer.from('admin:password123').toString('base64');
      const mockPlaintextOutput = `${base64Creds}\t\t\t\t1\n`;
      const mockKerberosOutput = '\t\t\t\t\t\n';

      mockExecAsync
        .mockResolvedValueOnce({ stdout: mockPlaintextOutput, stderr: '' })
        .mockResolvedValueOnce({ stdout: mockKerberosOutput, stderr: '' });

      const result = await extractCredentialsTool({ pcapPath: './test.pcap' });

      expect(result.content[0].text).toContain('HTTP Basic Auth: admin:password123');
    });

    test('should extract FTP credentials', async () => {
      const mockPlaintextOutput = `\tUSER\tftpuser\t\t1\n\tPASS\tftppass\t\t2\n`;
      const mockKerberosOutput = '\t\t\t\t\t\n';

      mockExecAsync
        .mockResolvedValueOnce({ stdout: mockPlaintextOutput, stderr: '' })
        .mockResolvedValueOnce({ stdout: mockKerberosOutput, stderr: '' });

      const result = await extractCredentialsTool({ pcapPath: './test.pcap' });

      expect(result.content[0].text).toContain('FTP: ftpuser:ftppass');
    });

    test('should extract Kerberos hashes', async () => {
      const mockPlaintextOutput = '\t\t\t\t\t\n';
      const mockKerberosOutput = 'testuser\tTEST.REALM\thashdata123\t23\t11\t1\n';

      mockExecAsync
        .mockResolvedValueOnce({ stdout: mockPlaintextOutput, stderr: '' })
        .mockResolvedValueOnce({ stdout: mockKerberosOutput, stderr: '' });

      const result = await extractCredentialsTool({ pcapPath: './test.pcap' });

      expect(result.content[0].text).toContain('Kerberos: User=testuser Realm=TEST.REALM');
      expect(result.content[0].text).toContain('hashcat -m 18200');
    });

    test('should handle no credentials found', async () => {
      mockExecAsync
        .mockResolvedValueOnce({ stdout: '\n', stderr: '' })
        .mockResolvedValueOnce({ stdout: '\n', stderr: '' });

      const result = await extractCredentialsTool({ pcapPath: './test.pcap' });

      expect(result.content[0].text).toContain('Plaintext Credentials:\nNone');
      expect(result.content[0].text).toContain('Encrypted/Hashed Credentials:\nNone');
    });
  });

  describe('Error handling', () => {
    test('should handle tshark execution errors', async () => {
      mockedWhich.mockResolvedValue('/usr/bin/tshark');
      mockExecAsync.mockRejectedValue(new Error('Permission denied'));

      const result = await capturePacketsTool({ interface: 'en0', duration: 1 });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain('Permission denied');
    });

    test('should handle invalid JSON from tshark', async () => {
      mockedWhich.mockResolvedValue('/usr/bin/tshark');
      mockedFs.unlink.mockResolvedValue();
      
      mockExecAsync
        .mockResolvedValueOnce({ stdout: '', stderr: '' })
        .mockResolvedValueOnce({ stdout: 'invalid json', stderr: '' });

      const result = await capturePacketsTool({ interface: 'en0', duration: 1 });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain('Error:');
    });
  });

  describe('Default parameters', () => {
    test('should use default interface and duration', async () => {
      mockedWhich.mockResolvedValue('/usr/bin/tshark');
      mockedFs.unlink.mockResolvedValue();
      mockExecAsync
        .mockResolvedValueOnce({ stdout: '', stderr: '' })
        .mockResolvedValueOnce({ stdout: '[]', stderr: '' });

      await capturePacketsTool({});

      expect(mockExecAsync).toHaveBeenCalledWith(
        expect.stringContaining('tshark -i en0'),
        expect.any(Object)
      );
      expect(mockExecAsync).toHaveBeenCalledWith(
        expect.stringContaining('-a duration:5'),
        expect.any(Object)
      );
    });
  });
}); 