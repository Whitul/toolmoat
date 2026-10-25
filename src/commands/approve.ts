import path from 'node:path';
import { parseArgs } from 'node:util';
import { getOwn, setOwn } from '../proxy/canonical.js';
import type { PendingTool, ServerEntry } from '../proxy/lockfile.js';
import { defaultLockPath, readLockfile, updateServer } from '../proxy/lockfile.js';
import { safeText } from '../proxy/names.js';
import { palette } from '../util/colors.js';

export const help = `Usage: toolmoat approve <server> [--tool <tool>]... [--all] [--reset] [--lock <file>]

Accepts tool changes that toolmoat proxy is holding for a server: the
pending definitions become the new pins. Without --tool every pending
change is approved. Review them first with toolmoat diff <server>.
A running proxy picks up the approval within a second and asks the client to
reload its tool list.

Options:
  --tool <tool>   Approve only this tool (repeatable)
  --all           Approve every pending change (the default without --tool)
  --reset         Forget the server entirely; its tools are pinned again on the next run
  --lock <file>   Lockfile (default: <toolmoat home>/lock.json)`;

interface ApproveValues {
  tool?: string[];
  all?: boolean;
  reset?: boolean;
  lock?: string;
}

export interface ApproveResult {
  approved: Array<{ tool: string; reason: PendingTool['reason'] }>;
  missing: string[];
}

/** Moves pending definitions into the pins. Pure: returns the new entry and what happened. */
export function approvePending(entry: ServerEntry, tools: readonly string[] | 'all', now: string): { entry: ServerEntry; result: ApproveResult } {
  const next: ServerEntry = { ...entry, tools: { ...entry.tools }, pending: { ...entry.pending } };
  const wanted = tools === 'all' ? Object.keys(entry.pending).sort() : [...new Set(tools)];
  const result: ApproveResult = { approved: [], missing: [] };
  for (const tool of wanted) {
    const pending = getOwn(next.pending, tool);
    if (!pending) {
      result.missing.push(tool);
      continue;
    }
    setOwn(next.tools, tool, { hash: pending.hash, definition: pending.definition, pinnedAt: now });
    delete next.pending[tool];
    result.approved.push({ tool, reason: pending.reason });
  }
  if (result.approved.length > 0) next.updated = now;
  return { entry: next, result };
}

export async function run(argv: string[]): Promise<number> {
  let values: ApproveValues;
  let positionals: string[];
  try {
    ({ values, positionals } = parseArgs({
      args: argv,
      options: { tool: { type: 'string', multiple: true }, all: { type: 'boolean' }, reset: { type: 'boolean' }, lock: { type: 'string' } },
      allowPositionals: true,
    }));
  } catch (error) {
    return usageError(error instanceof Error ? error.message : String(error));
  }
  const name = positionals[0];
  if (name === undefined || positionals.length > 1) return usageError('expected exactly one server name');
  if (values.reset && (values.all || values.tool)) return usageError('--reset cannot be combined with --tool or --all');
  if (values.all && values.tool) return usageError('use either --all or --tool, not both');
  const lockPath = path.resolve(values.lock ?? defaultLockPath());
  try {
    return values.reset ? reset(lockPath, name) : approve(lockPath, name, values.tool ?? 'all');
  } catch (error) {
    process.stderr.write(`toolmoat approve: ${error instanceof Error ? error.message : String(error)}\n`);
    return 1;
  }
}

function approve(lockPath: string, name: string, tools: readonly string[] | 'all'): number {
  const c = palette(process.stdout);
  const shownName = safeText(name, 100);
  let result = undefined as ApproveResult | undefined;
  let pendingBefore: string[] = [];
  updateServer(lockPath, name, (current) => {
    if (!current) return current;
    pendingBefore = Object.keys(current.pending).sort();
    const outcome = approvePending(current, tools, new Date().toISOString());
    result = outcome.result;
    return outcome.entry;
  });
  if (!result) {
    process.stderr.write(`toolmoat approve: no server named '${shownName}' in ${lockPath}${knownServers(lockPath)}\n`);
    return 1;
  }
  for (const tool of result.missing) {
    const others = pendingBefore.length > 0 ? ` (pending: ${pendingBefore.map((t) => safeText(t, 60)).join(', ')})` : '';
    process.stderr.write(`toolmoat approve: no pending change for tool '${safeText(tool, 100)}' on ${shownName}${others}\n`);
  }
  if (result.approved.length === 0) {
    if (result.missing.length === 0) process.stderr.write(`toolmoat approve: nothing to approve for ${shownName}; every tool matches its pin\n`);
    return 1;
  }
  const lines = [c.green(`Approved ${result.approved.length} tool change${result.approved.length === 1 ? '' : 's'} for ${shownName}:`)];
  for (const item of result.approved) lines.push(`  ${safeText(item.tool, 100)} (${item.reason})`);
  lines.push(c.dim(`Pins updated in ${lockPath}. A running proxy reloads them automatically; otherwise restart the MCP server.`));
  process.stdout.write(`${lines.join('\n')}\n`);
  return result.missing.length > 0 ? 1 : 0;
}

function reset(lockPath: string, name: string): number {
  let removed = undefined as ServerEntry | undefined;
  updateServer(lockPath, name, (current) => {
    removed = current;
    return undefined;
  });
  if (!removed) {
    process.stderr.write(`toolmoat approve: no server named '${safeText(name, 100)}' in ${lockPath}${knownServers(lockPath)}\n`);
    return 1;
  }
  const tools = Object.keys(removed.tools).length;
  const pending = Object.keys(removed.pending).length;
  process.stdout.write(
    `Forgot ${safeText(name, 100)} (${tools} pinned tool${tools === 1 ? '' : 's'}, ${pending} pending). Its tools will be pinned again the next time it runs.\n`,
  );
  return 0;
}

function knownServers(lockPath: string): string {
  try {
    const names = Object.keys(readLockfile(lockPath).servers).sort();
    return names.length > 0 ? ` (known: ${names.map((n) => safeText(n, 60)).join(', ')})` : '';
  } catch {
    return '';
  }
}

function usageError(message: string): number {
  process.stderr.write(`toolmoat approve: ${message}\nUsage: toolmoat approve <server> [--tool <tool>]... [--all] [--reset] [--lock <file>]\n`);
  return 2;
}
