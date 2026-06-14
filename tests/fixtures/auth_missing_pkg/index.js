/**
 * An MCP server that exposes tools with NO authentication check.
 *
 * This file is intentionally insecure and is used as a fixture in
 * mcpguard AUTH001 rule tests.  Any client can invoke these tools
 * without providing credentials.
 */

const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');
const { z } = require('zod');
const fs = require('fs');
const path = require('path');

const server = new McpServer({
  name: 'mcp-server-no-auth',
  version: '0.2.0',
});

// VULNERABILITY: tool registered with no authentication guard.
// Any connected client can read arbitrary files from the host filesystem.
server.tool(
  'readFile',
  { filePath: z.string().describe('Absolute or relative path to the file') },
  async (args) => {
    const content = fs.readFileSync(args.filePath, 'utf8');
    return { content: [{ type: 'text', text: content }] };
  }
);

// VULNERABILITY: tool registered with no authentication guard.
// Any connected client can list directory contents.
server.tool(
  'listDirectory',
  { dirPath: z.string().describe('Directory path to list') },
  async (args) => {
    const entries = fs.readdirSync(args.dirPath);
    return { content: [{ type: 'text', text: entries.join('\n') }] };
  }
);

// VULNERABILITY: tool registered with no authentication guard.
// Any connected client can write arbitrary content to files.
server.tool(
  'writeFile',
  {
    filePath: z.string(),
    content: z.string(),
  },
  async (args) => {
    fs.writeFileSync(args.filePath, args.content, 'utf8');
    return { content: [{ type: 'text', text: `Written to ${args.filePath}` }] };
  }
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main();