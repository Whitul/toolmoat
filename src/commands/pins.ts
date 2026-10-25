import path from 'node:path';
import { parseArgs } from 'node:util';
import type { Lockfile } from '../proxy/lockfile.js';
import { defaultLockPath, readLockfile } from '../proxy/lockfile.js';
import { safeText } from '../proxy/names.js';
import { palette } from '../util/colors.js';

export const help = `Usage: toolmoat pins [--lock <file>] [--json]

Lists the MCP servers pinned by toolmoat proxy, with their tool counts and
any tool changes waiting for review.

Options:
  --lock <file>   Lockfile (default: <toolmoat home>/lock.json)
  --json          Machine-readable output`;

export interface ServerSummary {
  name: string;
  command: string;
  tools: number;
  pending: number;
  pendingTools: Array<{ tool: string; reason: string; detectedAt: string }>;
  firstSeen: string;
  updated: string;
}

/** One summary per server, sorted by name. */
export function summarizeServers(lock: Lockfile): ServerSummary[] {
  return Object.keys(lock.servers)
    .sort()
    .map((name) => {
      const entry = lock.servers[name]!;
      const pendingTools = Object.keys(entry.pending)
        .sort()
        .map((tool) => ({ tool, reason: entry.pending[tool]!.reason, detectedAt: entry.pending[tool]!.detectedAt }));
      return {
        name,
        command: entry.command,
        tools: Object.keys(entry.tools).length,
        pending: pendingTools.length,
        pendingTools,
        firstSeen: entry.firstSeen,
        updated: entry.updated,
      };
    });
}

export async function run(argv: string[]): Promise<number> {
  let values: { lock?: string; json?: boolean };
  try {
    ({ values } = parseArgs({ args: argv, options: { lock: { type: 'string' }, json: { type: 'boolean' } }, allowPositionals: false }));
  } catch (error) {
    process.stderr.write(`toolmoat pins: ${error instanceof Error ? error.message : String(error)}\n`);
    return 2;
  }
  const lockPath = path.resolve(values.lock ?? defaultLockPath());
  let lock: Lockfile;
  try {
    lock = readLockfile(lockPath);
  } catch (error) {
    process.stderr.write(`toolmoat pins: ${error instanceof Error ? error.message : String(error)}\n`);
    return 1;
  }
  const servers = summarizeServers(lock);
  if (values.json) {
    process.stdout.write(`${JSON.stringify({ lockfile: lockPath, servers }, null, 2)}\n`);
    return 0;
  }
  process.stdout.write(`${renderTable(servers, lockPath)}\n`);
  return 0;
}

function renderTable(servers: readonly ServerSummary[], lockPath: string): string {
  const c = palette(process.stdout);
  if (servers.length === 0) {
    return `No pinned MCP servers in ${lockPath}.\nServers are pinned the first time they run behind toolmoat proxy.`;
  }
  const rows = servers.map((s) => [safeText(s.name, 60), String(s.tools), String(s.pending), shortTime(s.updated)]);
  const header = ['SERVER', 'TOOLS', 'PENDING', 'UPDATED (UTC)'];
  const widths = header.map((h, i) => Math.max(h.length, ...rows.map((r) => r[i]!.length)));
  const line = (cells: string[]) => cells.map((cell, i) => cell.padEnd(widths[i]!)).join('  ').trimEnd();
  const out = [`Lockfile: ${lockPath}`, '', c.bold(line(header))];
  rows.forEach((row, index) => {
    const text = line(row);
    out.push(servers[index]!.pending > 0 ? c.yellow(text) : text);
  });
  const waiting = servers.filter((s) => s.pending > 0);
  if (waiting.length > 0) {
    out.push('');
    for (const s of waiting) {
      const tools = s.pendingTools.map((p) => `${safeText(p.tool, 60)} (${p.reason})`).join(', ');
      out.push(`${c.yellow('!')} ${safeText(s.name, 60)}: ${tools}`);
    }
    out.push('', `Review with ${c.cyan('toolmoat diff <server>')}, then ${c.cyan('toolmoat approve <server>')}.`);
  }
  return out.join('\n');
}

function shortTime(iso: string): string {
  const match = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})/.exec(iso);
  return match ? `${match[1]} ${match[2]}` : iso || '-';
}
