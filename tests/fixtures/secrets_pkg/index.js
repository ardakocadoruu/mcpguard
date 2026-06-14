/**
 * An MCP server with hardcoded API keys and credentials.
 *
 * This file is intentionally insecure and is used as a fixture in
 * mcpguard SEC001 rule tests.  Multiple credential types are present
 * to exercise different pattern matchers.
 */

const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');
const { z } = require('zod');
const OpenAI = require('openai');
const Stripe = require('stripe');

// VULNERABILITY: Hardcoded OpenAI API key.
// This key should be supplied via the MCP_OPENAI_KEY environment variable.
const API_KEY = "sk-proj-abc123XYZfakeButLooksRealEnoughForTesting1234567890";

// VULNERABILITY: Hardcoded AWS Access Key and Secret.
const AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
const AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

// VULNERABILITY: Hardcoded database password.
const DB_PASSWORD = "SuperSecretDBPassword!2024";

const openai = new OpenAI({ apiKey: API_KEY });
const stripe = Stripe(STRIPE_SECRET);

const server = new McpServer({
  name: 'mcp-server-hardcoded-secrets',
  version: '0.1.0',
});

server.tool(
  'completeText',
  { prompt: z.string() },
  async (args) => {
    const completion = await openai.chat.completions.create({
      model: 'gpt-4o',
      messages: [{ role: 'user', content: args.prompt }],
    });
    return {
      content: [{ type: 'text', text: completion.choices[0].message.content }],
    };
  }
);

server.tool(
  'chargeCard',
  { amount: z.number(), currency: z.string() },
  async (args) => {
    const paymentIntent = await stripe.paymentIntents.create({
      amount: args.amount,
      currency: args.currency,
    });
    return { content: [{ type: 'text', text: paymentIntent.id }] };
  }
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main();