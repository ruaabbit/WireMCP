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
        await execAsync(`${path} -v`);
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
        `${tsharkPath} -i ${interface} -w ${tempPcap} -a duration:${duration}`,
        { env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
      );

      const { stdout, stderr } = await execAsync(
        `${tsharkPath} -r "${tempPcap}" -T json -e frame.number -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e tcp.flags -e frame.time -e http.request.method -e http.response.code`,
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
        `${tsharkPath} -i ${interface} -w ${tempPcap} -a duration:${duration}`,
        { env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
      );

      const { stdout, stderr } = await execAsync(
        `${tsharkPath} -r "${tempPcap}" -qz io,phs`,
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
        `${tsharkPath} -i ${interface} -w ${tempPcap} -a duration:${duration}`,
        { env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
      );

      const { stdout, stderr } = await execAsync(
        `${tsharkPath} -r "${tempPcap}" -qz conv,tcp`,
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

      // Capture live traffic
      await execAsync(
        `${tsharkPath} -i ${interface} -w ${tempPcap} -a duration:${duration}`,
        { env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
      );

      // Extract IPs
      const { stdout } = await execAsync(
        `${tsharkPath} -r "${tempPcap}" -T fields -e ip.src -e ip.dst`,
        { env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
      );
      const ips = [...new Set(stdout.split('\n').flatMap(line => line.split('\t')).filter(ip => ip && ip !== 'unknown'))];
      console.error(`Captured ${ips.length} unique IPs: ${ips.join(', ')}`);

      // Fetch URLhaus blacklist and extract IPs from URLs
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

      // Output results
      const outputText = `Captured IPs:\n${ips.join('\n')}\n\n` +
        `Threat check against URLhaus blacklist:\n${
          urlhausThreats.length > 0 ? `Potential threats: ${urlhausThreats.join(', ')}` : 'No threats detected in URLhaus blacklist.'
        }`;

      // Clean up
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

// Start the server
server.connect(new StdioServerTransport())
  .then(() => console.error('WireMCP Server is running...'))
  .catch(err => {
    console.error('Failed to start WireMCP:', err);
    process.exit(1);
  });