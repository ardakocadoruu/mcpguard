/**
 * A completely benign MCP server stub.
 *
 * This file intentionally contains no security issues and is used as the
 * "all-clear" fixture in mcpguard rule tests.  All tools require an API
 * key passed via Bearer token, no secrets are hardcoded, and no subprocess
 * or outbound network calls are made.
 */

const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');
const { z } = require('zod');

const server = new McpServer({
  name: 'mcp-server-example-clean',
  version: '1.0.0',
});

/**
 * Verify the caller's Bearer token against the API_KEY environment variable.
 * Returns true when authenticated, false otherwise.
 */
function authenticate(context) {
  const apiKey = process.env.MCP_API_KEY;
  if (!apiKey) return false;
  const bearerToken = context?.authToken;
  return typeof bearerToken === 'string' && bearerToken === apiKey;
}

// A simple, harmless tool that echoes its input.
server.tool(
  'echo',
  { message: z.string().describe('The message to echo back') },
  async (args, context) => {
    if (!authenticate(context)) {
      return { content: [{ type: 'text', text: 'Unauthorized' }], isError: true };
    }
    return { content: [{ type: 'text', text: args.message }] };
  }
);

// A read-only tool that returns server info.
server.tool(
  'ping',
  {},
  async (_args, context) => {
    if (!authenticate(context)) {
      return { content: [{ type: 'text', text: 'Unauthorized' }], isError: true };
    }
    return { content: [{ type: 'text', text: 'pong' }] };
  }
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  process.stderr.write(`Fatal error: ${err.message}\n`);
  process.exit(1);
});