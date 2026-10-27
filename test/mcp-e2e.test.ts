import { spawn } from 'node:child_process';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { CLI, FIXTURES, ROOT, runCli, tempDir } from './helpers.js';

type Message = Record<string, any>;

/** An isolated environment: no real home directory, client config or toolmoat state is touched. */
function isolatedEnv(dir: string): NodeJS.ProcessEnv {
  return {
    ...process.env,
    NO_COLOR: '1',
    TOOLMOAT_HOME: path.join(dir, 'toolmoat-home'),
    TOOLMOAT_TEST_USER_HOME: path.join(dir, 'user-home'),
    APPDATA: path.join(dir, 'appdata'),
    XDG_CONFIG_HOME: path.join(dir, 'xdg'),
  };
}

interface Session {
  responses: Message[];
  stdout: string;
  stderr: string;
  code: number | null;
}

/** Writes the messages to `toolmoat mcp`, closes stdin and collects everything the process prints. */
function session(messages: Message[], env: NodeJS.ProcessEnv): Promise<Session> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, 'mcp'], { cwd: ROOT, env, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk: string) => {
      stdout += chunk;
    });
    child.stderr.on('data', (chunk: string) => {
      stderr += chunk;
    });
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`toolmoat mcp did not exit; stderr:\n${stderr}`));
    }, 15_000);
    child.once('exit', (code) => {
      clearTimeout(timer);
      const lines = stdout.split('\n').filter((line) => line !== '');
      resolve({ responses: lines.map((line) => JSON.parse(line) as Message), stdout, stderr, code });
    });
    for (const message of messages) child.stdin.write(`${JSON.stringify(message)}\n`);
    child.stdin.end();
  });
}

describe('toolmoat mcp end to end', () => {
  it('answers initialize, tools/list and tools/call over stdio and exits 0 when stdin closes', async () => {
    const dir = tempDir('toolmoat-mcp-e2e-');
    const result = await session(
      [
        { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'e2e', version: '0' } } },
        { jsonrpc: '2.0', method: 'notifications/initialized' },
        { jsonrpc: '2.0', id: 2, method: 'tools/list' },
        { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'scan_path', arguments: { path: path.join(FIXTURES, 'corpus', 'malicious', 'clawhavoc-skill') } } },
        { jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'list_pins', arguments: {} } },
      ],
      isolatedEnv(dir),
    );
    expect(result.code, result.stderr).toBe(0);
    expect(result.stderr).toBe('');
    // stdout carries nothing but JSON-RPC lines.
    for (const line of result.stdout.split('\n').filter((l) => l !== '')) expect(JSON.parse(line).jsonrpc).toBe('2.0');
    expect(result.stdout.endsWith('\n')).toBe(true);
    expect(result.responses.map((m) => m.id)).toEqual([1, 2, 3, 4]);

    const [init, list, scan, pins] = result.responses as [Message, Message, Message, Message];
    expect(init.result.protocolVersion).toBe('2025-06-18');
    expect(init.result.serverInfo.name).toBe('toolmoat');
    expect(list.result.tools.map((t: Message) => t.name).sort()).toEqual(['list_pins', 'list_rules', 'scan_installed', 'scan_path', 'scan_text']);
    expect(scan.result.structuredContent.counts.critical).toBeGreaterThan(0);
    expect(scan.result.content[0].text).toMatch(/^toolmoat \S+ scanned/);
    expect(pins.result.structuredContent.servers).toEqual([]);
    expect(pins.result.structuredContent.lockfile).toContain('toolmoat-home');
  });

  it('exits 0 on immediate end of input and rejects stray arguments', async () => {
    const dir = tempDir('toolmoat-mcp-e2e-');
    const empty = await session([], isolatedEnv(dir));
    expect(empty.code).toBe(0);
    expect(empty.stdout).toBe('');

    const extra = runCli(['mcp', '--port', '80'], { env: isolatedEnv(dir) });
    expect(extra.status).toBe(2);
    expect(extra.stdout).toBe('');

    const help = runCli(['mcp', '--help'], { env: isolatedEnv(dir) });
    expect(help.status).toBe(0);
    expect(help.stdout).toContain('Usage: toolmoat mcp');
  });
});
