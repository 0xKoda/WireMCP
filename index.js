// index.js - WireMCP Server
const axios = require('axios');
const { exec } = require('child_process');
const { promisify } = require('util');
const which = require('which');
const fs = require('fs').promises;
const execAsync = promisify(exec);
const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');
const { z } = require('zod');

// Redirect console.log to stderr
const originalConsoleLog = console.log;
console.log = (...args) => console.error(...args);

// Dynamically locate tshark
async function findTshark() {
  try {
    const tsharkPath = await which('tshark');
    console.error(`Found tshark at: ${tsharkPath}`);
    return tsharkPath;
  } catch (err) {
    console.error('which failed to find tshark:', err.message);
    const fallbacks = process.platform === 'win32'
      ? ['C:\\Program Files\\Wireshark\\tshark.exe', 'C:\\Program Files (x86)\\Wireshark\\tshark.exe']
      : ['/usr/bin/tshark', '/usr/local/bin/tshark', '/opt/homebrew/bin/tshark', '/Applications/Wireshark.app/Contents/MacOS/tshark'];
    
    for (const path of fallbacks) {
      try {
        await execAsync(`"${path}" -v`);
        console.error(`Found tshark at fallback: ${path}`);
        return path;
      } catch (e) {
        console.error(`Fallback ${path} failed: ${e.message}`);
      }
    }
    throw new Error('tshark not found. Please install Wireshark (https://www.wireshark.org/download.html) and ensure tshark is in your PATH.');
  }
}

// Initialize MCP server
const server = new McpServer({
  name: 'wiremcp',
  version: '1.0.0',
});

// Tool 1: Capture live packet data
server.tool(
  'capture_packets',
  'Capture live traffic and provide raw packet data as JSON for LLM analysis',
  {
    interface: z.string().optional().default('en0').describe('Network interface to capture from (e.g., eth0, en0)'),
    duration: z.number().optional().default(5).describe('Capture duration in seconds'),
  },
  async (args) => {
    try {
      const tsharkPath = await findTshark();
      const { interface, duration } = args;
      const tempPcap = 'temp_capture.pcap';
      console.error(`Capturing packets on ${interface} for ${duration}s`);

      await execAsync(
        `"${tsharkPath}" -i "${interface}" -w "${tempPcap}" -a duration:${duration}`,
        { env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
      );

      const { stdout, stderr } = await execAsync(
        `"${tsharkPath}" -r "${tempPcap}" -T json -e frame.number -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e tcp.flags -e frame.time -e http.request.method -e http.response.code`,
        { env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
      );
      if (stderr) console.error(`tshark stderr: ${stderr}`);
      let packets = JSON.parse(stdout);

      const maxChars = 720000;
      let jsonString = JSON.stringify(packets);
      if (jsonString.length > maxChars) {
        const trimFactor = maxChars / jsonString.length;
        const trimCount = Math.floor(packets.length * trimFactor);
        packets = packets.slice(0, trimCount);
        jsonString = JSON.stringify(packets);
        console.error(`Trimmed packets from ${packets.length} to ${trimCount} to fit ${maxChars} chars`);
      }

      await fs.unlink(tempPcap).catch(err => console.error(`Failed to delete ${tempPcap}: ${err.message}`));

      return {
        content: [{
          type: 'text',
          text: `Captured packet data (JSON for LLM analysis):\n${jsonString}`,
        }],
      };
    } catch (error) {
      console.error(`Error in capture_packets: ${error.message}`);
      return { content: [{ type: 'text', text: `Error: ${error.message}` }], isError: true };
    }
  }
);

// Tool 2: Capture and provide summary statistics
server.tool(
  'get_summary_stats',
  'Capture live traffic and provide protocol hierarchy statistics for LLM analysis',
  {
    interface: z.string().optional().default('en0').describe('Network interface to capture from (e.g., eth0, en0)'),
    duration: z.number().optional().default(5).describe('Capture duration in seconds'),
  },
  async (args) => {
    try {
      const tsharkPath = await findTshark();
      const { interface, duration } = args;
      const tempPcap = 'temp_capture.pcap';
      console.error(`Capturing summary stats on ${interface} for ${duration}s`);

      await execAsync(
        `"${tsharkPath}" -i "${interface}" -w "${tempPcap}" -a duration:${duration}`,
        { env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
      );

      const { stdout, stderr } = await execAsync(
        `"${tsharkPath}" -r "${tempPcap}" -qz io,phs`,
        { env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
      );
      if (stderr) console.error(`tshark stderr: ${stderr}`);

      await fs.unlink(tempPcap).catch(err => console.error(`Failed to delete ${tempPcap}: ${err.message}`));

      return {
        content: [{
          type: 'text',
          text: `Protocol hierarchy statistics for LLM analysis:\n${stdout}`,
        }],
      };
    } catch (error) {
      console.error(`Error in get_summary_stats: ${error.message}`);
      return { content: [{ type: 'text', text: `Error: ${error.message}` }], isError: true };
    }
  }
);

// Tool 3: Capture and provide conversation stats
server.tool(
  'get_conversations',
  'Capture live traffic and provide TCP/UDP conversation statistics for LLM analysis',
  {
    interface: z.string().optional().default('en0').describe('Network interface to capture from (e.g., eth0, en0)'),
    duration: z.number().optional().default(5).describe('Capture duration in seconds'),
  },
  async (args) => {
    try {
      const tsharkPath = await findTshark();
      const { interface, duration } = args;
      const tempPcap = 'temp_capture.pcap';
      console.error(`Capturing conversations on ${interface} for ${duration}s`);

      await execAsync(
        `"${tsharkPath}" -i "${interface}" -w "${tempPcap}" -a duration:${duration}`,
        { env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
      );

      const { stdout, stderr } = await execAsync(
        `"${tsharkPath}" -r "${tempPcap}" -qz conv,tcp`,
        { env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
      );
      if (stderr) console.error(`tshark stderr: ${stderr}`);

      await fs.unlink(tempPcap).catch(err => console.error(`Failed to delete ${tempPcap}: ${err.message}`));

      return {
        content: [{
          type: 'text',
          text: `TCP/UDP conversation statistics for LLM analysis:\n${stdout}`,
        }],
      };
    } catch (error) {
      console.error(`Error in get_conversations: ${error.message}`);
      return { content: [{ type: 'text', text: `Error: ${error.message}` }], isError: true };
    }
  }
);

// Tool 4: Capture traffic and check threats against URLhaus
server.tool(
  'check_threats',
  'Capture live traffic and check IPs against URLhaus blacklist',
  {
    interface: z.string().optional().default('en0').describe('Network interface to capture from (e.g., eth0, en0)'),
    duration: z.number().optional().default(5).describe('Capture duration in seconds'),
  },
  async (args) => {
    try {
      const tsharkPath = await findTshark();
      const { interface, duration } = args;
      const tempPcap = 'temp_capture.pcap';
      console.error(`Capturing traffic on ${interface} for ${duration}s to check threats`);

      await execAsync(
        `"${tsharkPath}" -i "${interface}" -w "${tempPcap}" -a duration:${duration}`,
        { env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
      );

      const { stdout } = await execAsync(
        `"${tsharkPath}" -r "${tempPcap}" -T fields -e ip.src -e ip.dst`,
        { env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
      );
      const ips = [...new Set(stdout.split('\n').flatMap(line => line.split('\t')).filter(ip => ip && ip !== 'unknown'))];
      console.error(`Captured ${ips.length} unique IPs: ${ips.join(', ')}`);

      const urlhausUrl = 'https://urlhaus.abuse.ch/downloads/text/';
      console.error(`Fetching URLhaus blacklist from ${urlhausUrl}`);
      let urlhausData;
      let urlhausThreats = [];
      try {
        const response = await axios.get(urlhausUrl);
        console.error(`URLhaus response status: ${response.status}, length: ${response.data.length} chars`);
        console.error(`URLhaus raw data (first 200 chars): ${response.data.slice(0, 200)}`);
        const ipRegex = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/;
        urlhausData = [...new Set(response.data.split('\n')
          .map(line => {
            const match = line.match(ipRegex);
            return match ? match[0] : null;
          })
          .filter(ip => ip))];
        console.error(`URLhaus lookup successful: ${urlhausData.length} blacklist IPs fetched`);
        console.error(`Sample URLhaus IPs: ${urlhausData.slice(0, 5).join(', ') || 'None'}`);
        urlhausThreats = ips.filter(ip => urlhausData.includes(ip));
        console.error(`Checked IPs against URLhaus: ${urlhausThreats.length} threats found - ${urlhausThreats.join(', ') || 'None'}`);
      } catch (e) {
        console.error(`Failed to fetch URLhaus data: ${e.message}`);
        urlhausData = [];
      }

      const outputText = `Captured IPs:\n${ips.join('\n')}\n\n` +
        `Threat check against URLhaus blacklist:\n${
          urlhausThreats.length > 0 ? `Potential threats: ${urlhausThreats.join(', ')}` : 'No threats detected in URLhaus blacklist.'
        }`;

      await fs.unlink(tempPcap).catch(err => console.error(`Failed to delete ${tempPcap}: ${err.message}`));

      return {
        content: [{ type: 'text', text: outputText }],
      };
    } catch (error) {
      console.error(`Error in check_threats: ${error.message}`);
      return { content: [{ type: 'text', text: `Error: ${error.message}` }], isError: true };
    }
  }
);

// Tool 5: Check a specific IP against URLhaus IOCs
server.tool(
  'check_ip_threats',
  'Check a given IP address against URLhaus blacklist for IOCs',
  {
    ip: z.string().regex(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/).describe('IP address to check (e.g., 192.168.1.1)'),
  },
  async (args) => {
    try {
      const { ip } = args;
      console.error(`Checking IP ${ip} against URLhaus blacklist`);

      const urlhausUrl = 'https://urlhaus.abuse.ch/downloads/text/';
      console.error(`Fetching URLhaus blacklist from ${urlhausUrl}`);
      let urlhausData;
      let isThreat = false;
      try {
        const response = await axios.get(urlhausUrl);
        console.error(`URLhaus response status: ${response.status}, length: ${response.data.length} chars`);
        console.error(`URLhaus raw data (first 200 chars): ${response.data.slice(0, 200)}`);
        const ipRegex = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/;
        urlhausData = [...new Set(response.data.split('\n')
          .map(line => {
            const match = line.match(ipRegex);
            return match ? match[0] : null;
          })
          .filter(ip => ip))];
        console.error(`URLhaus lookup successful: ${urlhausData.length} blacklist IPs fetched`);
        console.error(`Sample URLhaus IPs: ${urlhausData.slice(0, 5).join(', ') || 'None'}`);
        isThreat = urlhausData.includes(ip);
        console.error(`IP ${ip} checked against URLhaus: ${isThreat ? 'Threat found' : 'No threat found'}`);
      } catch (e) {
        console.error(`Failed to fetch URLhaus data: ${e.message}`);
        urlhausData = [];
      }

      const outputText = `IP checked: ${ip}\n\n` +
        `Threat check against URLhaus blacklist:\n${
          isThreat ? 'Potential threat detected in URLhaus blacklist.' : 'No threat detected in URLhaus blacklist.'
        }`;

      return {
        content: [{ type: 'text', text: outputText }],
      };
    } catch (error) {
      console.error(`Error in check_ip_threats: ${error.message}`);
      return { content: [{ type: 'text', text: `Error: ${error.message}` }], isError: true };
    }
  }
);

// Tool 6: Analyze an existing PCAP file for general context
server.tool(
  'analyze_pcap',
  'Analyze a PCAP file and provide general packet data as JSON for LLM analysis',
  {
    pcapPath: z.string().describe('Path to the PCAP file to analyze (e.g., ./demo.pcap)'),
  },
  async (args) => {
    try {
      const tsharkPath = await findTshark();
      const { pcapPath } = args;
      console.error(`Analyzing PCAP file: ${pcapPath}`);

      // Check if file exists
      await fs.access(pcapPath);

      // Extract broad packet data
      const { stdout, stderr } = await execAsync(
        `"${tsharkPath}" -r "${pcapPath}" -T json -e frame.number -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e http.host -e http.request.uri -e frame.protocols`,
        { env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
      );
      if (stderr) console.error(`tshark stderr: ${stderr}`);
      const packets = JSON.parse(stdout);

      const ips = [...new Set(packets.flatMap(p => [
        p._source?.layers['ip.src']?.[0],
        p._source?.layers['ip.dst']?.[0]
      ]).filter(ip => ip))];
      console.error(`Found ${ips.length} unique IPs: ${ips.join(', ')}`);

      const urls = packets
        .filter(p => p._source?.layers['http.host'] && p._source?.layers['http.request.uri'])
        .map(p => `http://${p._source.layers['http.host'][0]}${p._source.layers['http.request.uri'][0]}`);
      console.error(`Found ${urls.length} URLs: ${urls.join(', ') || 'None'}`);

      const protocols = [...new Set(packets.map(p => p._source?.layers['frame.protocols']?.[0]))].filter(p => p);
      console.error(`Found protocols: ${protocols.join(', ') || 'None'}`);

      const maxChars = 720000;
      let jsonString = JSON.stringify(packets);
      if (jsonString.length > maxChars) {
        const trimFactor = maxChars / jsonString.length;
        const trimCount = Math.floor(packets.length * trimFactor);
        packets.splice(trimCount);
        jsonString = JSON.stringify(packets);
        console.error(`Trimmed packets from ${packets.length} to ${trimCount} to fit ${maxChars} chars`);
      }

      const outputText = `Analyzed PCAP: ${pcapPath}\n\n` +
        `Unique IPs:\n${ips.join('\n')}\n\n` +
        `URLs:\n${urls.length > 0 ? urls.join('\n') : 'None'}\n\n` +
        `Protocols:\n${protocols.join('\n') || 'None'}\n\n` +
        `Packet Data (JSON for LLM):\n${jsonString}`;

      return {
        content: [{ type: 'text', text: outputText }],
      };
    } catch (error) {
      console.error(`Error in analyze_pcap: ${error.message}`);
      return { content: [{ type: 'text', text: `Error: ${error.message}` }], isError: true };
    }
  }
);

// Tool 7: Extract credentials from a PCAP file
server.tool(
    'extract_credentials',
    'Extract potential credentials (HTTP Basic Auth, FTP, Telnet) from a PCAP file for LLM analysis',
    {
      pcapPath: z.string().describe('Path to the PCAP file to analyze (e.g., ./demo.pcap)'),
    },
    async (args) => {
      try {
        const tsharkPath = await findTshark();
        const { pcapPath } = args;
        console.error(`Extracting credentials from PCAP file: ${pcapPath}`);
  
        await fs.access(pcapPath);
  
        // Extract plaintext credentials
        const { stdout: plaintextOut } = await execAsync(
          `"${tsharkPath}" -r "${pcapPath}" -T fields -e http.authbasic -e ftp.request.command -e ftp.request.arg -e telnet.data -e frame.number`,
          { env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
        );

        // Extract Kerberos credentials
        const { stdout: kerberosOut } = await execAsync(
          `"${tsharkPath}" -r "${pcapPath}" -T fields -e kerberos.CNameString -e kerberos.realm -e kerberos.cipher -e kerberos.type -e kerberos.msg_type -e frame.number`,
          { env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
        );

        const lines = plaintextOut.split('\n').filter(line => line.trim());
        const packets = lines.map(line => {
          const [authBasic, ftpCmd, ftpArg, telnetData, frameNumber] = line.split('\t');
          return {
            authBasic: authBasic || '',
            ftpCmd: ftpCmd || '',
            ftpArg: ftpArg || '',
            telnetData: telnetData || '',
            frameNumber: frameNumber || ''
          };
        });
  
        const credentials = {
          plaintext: [],
          encrypted: []
        };
  
        // Process HTTP Basic Auth
        packets.forEach(p => {
          if (p.authBasic) {
            const [username, password] = Buffer.from(p.authBasic, 'base64').toString().split(':');
            credentials.plaintext.push({ type: 'HTTP Basic Auth', username, password, frame: p.frameNumber });
          }
        });
  
        // Process FTP
        packets.forEach(p => {
          if (p.ftpCmd === 'USER') {
            credentials.plaintext.push({ type: 'FTP', username: p.ftpArg, password: '', frame: p.frameNumber });
          }
          if (p.ftpCmd === 'PASS') {
            const lastUser = credentials.plaintext.findLast(c => c.type === 'FTP' && !c.password);
            if (lastUser) lastUser.password = p.ftpArg;
          }
        });
  
        // Process Telnet
        packets.forEach(p => {
          if (p.telnetData) {
            const telnetStr = p.telnetData.trim();
            if (telnetStr.toLowerCase().includes('login:') || telnetStr.toLowerCase().includes('password:')) {
              credentials.plaintext.push({ type: 'Telnet Prompt', data: telnetStr, frame: p.frameNumber });
            } else if (telnetStr && !telnetStr.match(/[A-Z][a-z]+:/) && !telnetStr.includes(' ')) {
              const lastPrompt = credentials.plaintext.findLast(c => c.type === 'Telnet Prompt');
              if (lastPrompt && lastPrompt.data.toLowerCase().includes('login:')) {
                credentials.plaintext.push({ type: 'Telnet', username: telnetStr, password: '', frame: p.frameNumber });
              } else if (lastPrompt && lastPrompt.data.toLowerCase().includes('password:')) {
                const lastUser = credentials.plaintext.findLast(c => c.type === 'Telnet' && !c.password);
                if (lastUser) lastUser.password = telnetStr;
                else credentials.plaintext.push({ type: 'Telnet', username: '', password: telnetStr, frame: p.frameNumber });
              }
            }
          }
        });

        // Process Kerberos credentials
        const kerberosLines = kerberosOut.split('\n').filter(line => line.trim());
        kerberosLines.forEach(line => {
          const [cname, realm, cipher, type, msgType, frameNumber] = line.split('\t');
          
          if (cipher && type) {
            let hashFormat = '';
            // Format hash based on message type
            if (msgType === '10' || msgType === '30') { // AS-REQ or TGS-REQ
              hashFormat = '$krb5pa$23$';
              if (cname) hashFormat += `${cname}$`;
              if (realm) hashFormat += `${realm}$`;
              hashFormat += cipher;
            } else if (msgType === '11') { // AS-REP
              hashFormat = '$krb5asrep$23$';
              if (cname) hashFormat += `${cname}@`;
              if (realm) hashFormat += `${realm}$`;
              hashFormat += cipher;
            }

            if (hashFormat) {
              credentials.encrypted.push({
                type: 'Kerberos',
                hash: hashFormat,
                username: cname || 'unknown',
                realm: realm || 'unknown',
                frame: frameNumber,
                crackingMode: msgType === '11' ? 'hashcat -m 18200' : 'hashcat -m 7500'
              });
            }
          }
        });

        console.error(`Found ${credentials.plaintext.length} plaintext and ${credentials.encrypted.length} encrypted credentials`);
  
        const outputText = `Analyzed PCAP: ${pcapPath}\n\n` +
          `Plaintext Credentials:\n${credentials.plaintext.length > 0 ? 
            credentials.plaintext.map(c => 
              c.type === 'Telnet Prompt' ? 
                `${c.type}: ${c.data} (Frame ${c.frame})` : 
                `${c.type}: ${c.username}:${c.password} (Frame ${c.frame})`
            ).join('\n') : 
            'None'}\n\n` +
          `Encrypted/Hashed Credentials:\n${credentials.encrypted.length > 0 ?
            credentials.encrypted.map(c =>
              `${c.type}: User=${c.username} Realm=${c.realm} (Frame ${c.frame})\n` +
              `Hash=${c.hash}\n` +
              `Cracking Command: ${c.crackingMode}\n`
            ).join('\n') :
            'None'}\n\n` +
          `Note: Encrypted credentials can be cracked using tools like John the Ripper or hashcat.\n` +
          `For Kerberos hashes:\n` +
          `- AS-REQ/TGS-REQ: hashcat -m 7500 or john --format=krb5pa-md5\n` +
          `- AS-REP: hashcat -m 18200 or john --format=krb5asrep`;
  
        return {
          content: [{ type: 'text', text: outputText }],
        };
      } catch (error) {
        console.error(`Error in extract_credentials: ${error.message}`);
        return { content: [{ type: 'text', text: `Error: ${error.message}` }], isError: true };
      }
    }
  );

// Add prompts for each tool
server.prompt(
  'capture_packets_prompt',
  {
    interface: z.string().optional().describe('Network interface to capture from'),
    duration: z.number().optional().describe('Duration in seconds to capture'),
  },
  ({ interface = 'en0', duration = 5 }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `Please analyze the network traffic on interface ${interface} for ${duration} seconds and provide insights about:
1. The types of traffic observed
2. Any notable patterns or anomalies
3. Key IP addresses and ports involved
4. Potential security concerns`
      }
    }]
  })
);

server.prompt(
  'summary_stats_prompt',
  {
    interface: z.string().optional().describe('Network interface to capture from'),
    duration: z.number().optional().describe('Duration in seconds to capture'),
  },
  ({ interface = 'en0', duration = 5 }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `Please provide a summary of network traffic statistics from interface ${interface} over ${duration} seconds, focusing on:
1. Protocol distribution
2. Traffic volume by protocol
3. Notable patterns in protocol usage
4. Potential network health indicators`
      }
    }]
  })
);

server.prompt(
  'conversations_prompt',
  {
    interface: z.string().optional().describe('Network interface to capture from'),
    duration: z.number().optional().describe('Duration in seconds to capture'),
  },
  ({ interface = 'en0', duration = 5 }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `Please analyze network conversations on interface ${interface} for ${duration} seconds and identify:
1. Most active IP pairs
2. Conversation durations and data volumes
3. Unusual communication patterns
4. Potential indicators of network issues`
      }
    }]
  })
);

server.prompt(
  'check_threats_prompt',
  {
    interface: z.string().optional().describe('Network interface to capture from'),
    duration: z.number().optional().describe('Duration in seconds to capture'),
  },
  ({ interface = 'en0', duration = 5 }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `Please analyze traffic on interface ${interface} for ${duration} seconds and check for security threats:
1. Compare captured IPs against URLhaus blacklist
2. Identify potential malicious activity
3. Highlight any concerning patterns
4. Provide security recommendations`
      }
    }]
  })
);

server.prompt(
  'check_ip_threats_prompt',
  {
    ip: z.string().describe('IP address to check'),
  },
  ({ ip }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `Please analyze the following IP address (${ip}) for potential security threats:
1. Check against URLhaus blacklist
2. Evaluate the IP's reputation
3. Identify any known malicious activity
4. Provide security recommendations`
      }
    }]
  })
);

server.prompt(
  'analyze_pcap_prompt',
  {
    pcapPath: z.string().describe('Path to the PCAP file'),
  },
  ({ pcapPath }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `Please analyze the PCAP file at ${pcapPath} and provide insights about:
1. Overall traffic patterns
2. Unique IPs and their interactions
3. Protocols and services used
4. Notable events or anomalies
5. Potential security concerns`
      }
    }]
  })
);

server.prompt(
  'extract_credentials_prompt',
  {
    pcapPath: z.string().describe('Path to the PCAP file'),
  },
  ({ pcapPath }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `Please analyze the PCAP file at ${pcapPath} for potential credential exposure:
1. Look for plaintext credentials (HTTP Basic Auth, FTP, Telnet)
2. Identify Kerberos authentication attempts
3. Extract any hashed credentials
4. Provide security recommendations for credential handling`
      }
    }]
  })
);

// Start the server
server.connect(new StdioServerTransport())
  .then(() => console.error('WireMCP Server is running...'))
  .catch(err => {
    console.error('Failed to start WireMCP:', err);
    process.exit(1);
  });