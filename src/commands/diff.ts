import path from 'node:path';
import { parseArgs } from 'node:util';
import { getOwn } from '../proxy/canonical.js';
import { diffLines, hunks, prettyDefinition } from '../proxy/diff.js';
import type { Lockfile, PendingTool, ServerEntry } from '../proxy/lockfile.js';
import { defaultLockPath, readLockfile } from '../proxy/lockfile.js';
import { safeText, shellQuote } from '../proxy/names.js';
import type { Palette } from '../util/colors.js';
import { palette } from '../util/colors.js';

export const help = `Usage: toolmoat diff <server> [--tool <tool>] [--lock <file>]

Shows the tool changes toolmoat proxy is holding for a server: why each tool
was held, what the scanner found, and a line diff between the pinned
definition and the new one (new or flagged tools are shown in full).

Options:
  --tool <tool>   Only this tool
  --lock <file>   Lockfile (default: <toolmoat home>/lock.json)`;

const REASON_TEXT: Record<PendingTool['reason'], string> = {
  changed: 'definition changed since it was pinned',
  new: 'tool appeared after the server was pinned',
  flagged: 'definition flagged by the scanner',
};

export async function run(argv: string[]): Promise<number> {
  let values: { tool?: string; lock?: string };
  let positionals: string[];
  try {
    ({ values, positionals } = parseArgs({ args: argv, options: { tool: { type: 'string' }, lock: { type: 'string' } }, allowPositionals: true }));
  } catch (error) {
    return usageError(error instanceof Error ? error.message : String(error));
  }
  const name = positionals[0];
  if (name === undefined || positionals.length > 1) return usageError('expected exactly one server name');
  const lockPath = path.resolve(values.lock ?? defaultLockPath());
  let lock: Lockfile;
  try {
    lock = readLockfile(lockPath);
  } catch (error) {
    process.stderr.write(`toolmoat diff: ${error instanceof Error ? error.message : String(error)}\n`);
    return 1;
  }
  const entry = getOwn(lock.servers, name);
  if (!entry) {
    process.stderr.write(`toolmoat diff: no server named '${safeText(name, 100)}' in ${lockPath}${knownServers(lock)}\n`);
    return 1;
  }
  const c = palette(process.stdout);
  let tools = Object.keys(entry.pending).sort();
  if (values.tool !== undefined) {
    if (!getOwn(entry.pending, values.tool)) {
      const pinned = getOwn(entry.tools, values.tool) ? ' (it is pinned and unchanged)' : '';
      process.stdout.write(`No pending change for tool '${safeText(values.tool, 100)}' on ${safeText(name, 100)}${pinned}.\n`);
      return 0;
    }
    tools = [values.tool];
  }
  if (tools.length === 0) {
    process.stdout.write(`No pending changes for ${safeText(name, 100)}: all ${Object.keys(entry.tools).length} tools match their pins.\n`);
    return 0;
  }
  const out = [c.bold(`${safeText(name, 100)}: ${tools.length} pending tool change${tools.length === 1 ? '' : 's'}`), c.dim(`lockfile: ${lockPath}`)];
  for (const tool of tools) out.push('', ...renderPending(entry, tool, c));
  out.push('', `Approve with: ${c.cyan(`toolmoat approve ${shellQuote(name)}${values.tool !== undefined ? ` --tool ${shellQuote(values.tool)}` : ''}`)}`);
  process.stdout.write(`${out.join('\n')}\n`);
  return 0;
}

/** The review block for one pending tool: reason, findings and a diff against the pin. */
export function renderPending(entry: ServerEntry, tool: string, c: Palette): string[] {
  const pending = getOwn(entry.pending, tool)!;
  const pinned = getOwn(entry.tools, tool);
  const launch = pending.launchChanged ? "; the server's command line had also changed" : '';
  const out = [`${c.bold(safeText(tool, 100))}  ${c.yellow(pending.reason)}  ${c.dim(`${REASON_TEXT[pending.reason]}${launch}, detected ${pending.detectedAt || 'unknown'}`)}`];
  if (pending.findings.length > 0) {
    out.push('  findings:');
    for (const f of pending.findings) {
      const severity = f.severity === 'critical' || f.severity === 'high' ? c.red(f.severity) : c.yellow(f.severity);
      out.push(`    ${severity} ${f.ruleId} ${safeText(f.message, 200)}`);
    }
  }
  const after = prettyDefinition(pending.definition).map((line) => safeText(line));
  if (!pinned) {
    out.push(`  ${c.dim('definition (not pinned before):')}`);
    for (const line of after) out.push(c.green(`  + ${line}`));
    return out;
  }
  const before = prettyDefinition(pinned.definition).map((line) => safeText(line));
  out.push(c.dim(`  --- pinned ${pinned.pinnedAt}`), c.dim(`  +++ pending ${pending.detectedAt}`));
  const changes = hunks(diffLines(before, after));
  if (changes.length === 0) out.push(c.dim('  (no visible difference; the definitions differ only in key order or encoding)'));
  changes.forEach((hunk, index) => {
    if (index > 0) out.push(c.dim('  ...'));
    for (const op of hunk.ops) {
      if (op.type === 'removed') out.push(c.red(`  - ${op.line}`));
      else if (op.type === 'added') out.push(c.green(`  + ${op.line}`));
      else out.push(c.dim(`    ${op.line}`));
    }
  });
  return out;
}

function knownServers(lock: Lockfile): string {
  const names = Object.keys(lock.servers).sort();
  return names.length > 0 ? ` (known: ${names.map((n) => safeText(n, 60)).join(', ')})` : '';
}

function usageError(message: string): number {
  process.stderr.write(`toolmoat diff: ${message}\nUsage: toolmoat diff <server> [--tool <tool>] [--lock <file>]\n`);
  return 2;
}
