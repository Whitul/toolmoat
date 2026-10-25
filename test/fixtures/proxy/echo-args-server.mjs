#!/usr/bin/env node
/**
 * Test fixture: a minimal MCP stdio server that reports the command-line
 * arguments it received in the `instructions` field of its initialize result.
 * The proxy e2e tests use it to check that arguments survive the cmd.exe
 * escaping used for .cmd/.bat servers on Windows. Inert: no files, no network.
 */
import { createInterface } from 'node:readline';

const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
lines.on('line', (line) => {
  let message;
  try {
    message = JSON.parse(line);
  } catch {
    return;
  }
  if (message.method === 'initialize') {
    const result = {
      protocolVersion: message.params?.protocolVersion ?? '2025-06-18',
      capabilities: { tools: {} },
      serverInfo: { name: 'echo-args', version: '1.0.0' },
      instructions: JSON.stringify(process.argv.slice(2)),
    };
    process.stdout.write(`${JSON.stringify({ jsonrpc: '2.0', id: message.id, result })}\n`);
  } else if (message.method === 'tools/list') {
    process.stdout.write(`${JSON.stringify({ jsonrpc: '2.0', id: message.id, result: { tools: [] } })}\n`);
  } else if (message.id !== undefined && message.method) {
    process.stdout.write(`${JSON.stringify({ jsonrpc: '2.0', id: message.id, error: { code: -32601, message: 'Method not found' } })}\n`);
  }
});
lines.on('close', () => process.exit(0));
