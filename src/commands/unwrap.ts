import type { Launch, ServerEntry } from '../clients/configs.js';
import { originalLaunch, readLaunch, splitWrapped } from '../clients/configs.js';
import type { ParsedTargetArgs, Selection, ServerReport, ServerTransform } from './wrap.js';
import { formatLaunch, parseTargetArgs, processTargets, selectTargets, summarize, UsageError } from './wrap.js';

export const help = `Usage: toolmoat unwrap [options]

Undoes \`toolmoat wrap\`: every server whose command runs \`toolmoat proxy\` gets
back the command and args that follow the "--" in its wrapped command line.
Other keys (env, cwd, type, ...) are not touched.

Options:
  --client <id>    Only this client (repeatable), as for wrap
  --config <file>  Unwrap the servers in this config file (repeatable)
  --dry-run        Show what would change and write nothing
  --force          Rewrite JSON files that contain comments (the comments are lost)

Without --client or --config, every user-level config that exists is processed.
Codex's config.toml is never edited: unwrap prints the lines to paste.
Restart the client afterwards.`;

const NOTHING_AFTER_SEPARATOR = 'wrapped, but nothing follows "--" to restore; fix it by hand';

/**
 * Restores command and args in place. wrap puts a new args key before command
 * when the original entry had none, so that order plus an empty argument list
 * means the original had no args key at all.
 */
function applyUnwrapped(server: Record<string, unknown>, original: Launch): void {
  const keys = Object.keys(server);
  const argsFirst = keys.indexOf('args') < keys.indexOf('command');
  server.command = original.command;
  if (argsFirst && original.args.length === 0) delete server.args;
  else server.args = original.args;
}

/** What unwrap does with one command line: restore the original, or say why not. */
function planUnwrap(launch: Launch): Pick<ServerReport, 'status' | 'detail' | 'after'> {
  if (!splitWrapped(launch.command, launch.args)) return { status: 'unchanged', detail: 'not wrapped' };
  const original = originalLaunch(launch);
  if (!original) return { status: 'skipped', detail: NOTHING_AFTER_SEPARATOR };
  return { status: 'changed', detail: formatLaunch(original), after: original };
}

/** The unwrap transform for JSON configs. */
export const unwrapTransform: ServerTransform = (entry: ServerEntry): ServerReport => {
  const base = entry.project === undefined ? { name: entry.name } : { name: entry.name, project: entry.project };
  const launch = readLaunch(entry.server);
  if ('error' in launch) return { ...base, status: 'unchanged', detail: 'not wrapped' };
  const plan = planUnwrap(launch);
  if (plan.after) applyUnwrapped(entry.server, plan.after);
  return { ...base, ...plan };
};

export async function run(argv: string[]): Promise<number> {
  let args: ParsedTargetArgs;
  let selection: Selection;
  try {
    args = parseTargetArgs(argv, false);
    selection = selectTargets(args.clients, args.configs, process.cwd());
  } catch (error) {
    if (!(error instanceof UsageError)) throw error;
    process.stderr.write(`toolmoat unwrap: ${error.message}\n\n${help}\n`);
    return 2;
  }
  const unwrapToml = (name: string, launch: Launch): ServerReport => ({ name, ...planUnwrap(launch) });
  const reports = processTargets(selection.targets, unwrapTransform, unwrapToml, { dryRun: args.dryRun, force: args.force });
  return summarize(reports, selection, args.dryRun, 'unwrap');
}
