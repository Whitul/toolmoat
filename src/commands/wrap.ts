import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import type { ClientConfigLocation, ConfigFormat, Launch, ServerEntry, ServersKey } from '../clients/configs.js';
import {
  CLIENT_CONFIGS,
  clientChoices,
  findClientConfig,
  isRemoteServer,
  listServers,
  matchClientConfigs,
  pathKey,
  readJsonConfig,
  readLaunch,
  readTomlServers,
  splitWrapped,
  tomlString,
  writeJsonConfig,
} from '../clients/configs.js';
import { redactSecrets } from '../patterns/secrets.js';
import { deriveServerName } from '../proxy/names.js';
import { palette } from '../util/colors.js';
import { expandHome, homeDir } from '../util/paths.js';
import { printable, truncate } from '../util/text.js';
import { VERSION } from '../version.js';

export const help = `Usage: toolmoat wrap [options]

Routes the stdio MCP servers in your client configs through \`toolmoat proxy\`,
which pins tool definitions, guards outgoing secrets and keeps an audit log.

Options:
  --client <id>    Only this client (repeatable): claude-desktop, claude-code, cursor,
                   vscode, windsurf, codex, gemini, or one config id such as
                   claude-code-project, cursor-project, vscode-project, gemini-project
  --config <file>  Wrap the servers in this config file (repeatable)
  --lock <file>    Lockfile the proxy should use instead of its default
  --mode <mode>    Proxy mode: enforce or warn
  --dry-run        Show what would change and write nothing
  --force          Rewrite JSON files that contain comments (the comments are lost)

Without --client or --config, every user-level config that exists is wrapped:
Claude Desktop, Claude Code (~/.claude.json, including its per-project servers),
Cursor, VS Code, Windsurf, Gemini CLI and Codex. Project configs (.mcp.json,
.cursor/mcp.json, .vscode/mcp.json, .gemini/settings.json) are only wrapped when
named, because they are usually committed and the wrapped command holds paths
from this machine.

Each file is copied once to <file>.toolmoat.bak before its first change and is
replaced atomically. Remote (url) servers are left alone. Servers that are
already wrapped are left alone too, unless the node or cli.js path they start
no longer exists (say after switching Node versions): those are pointed at this
install. Codex's config.toml is never edited: wrap prints the lines to paste.
Restart the client afterwards. Undo with \`toolmoat unwrap\`.`;

/** Raised for bad command-line input; run() turns it into exit code 2. */
export class UsageError extends Error {}

/** The part of a wrapped command line that starts toolmoat, up to (not including) "proxy". */
export interface Launcher {
  command: string;
  prefix: string[];
}

export interface ProxyOptions {
  lock?: string;
  mode?: 'enforce' | 'warn';
}

/** Absolute path of the cli.js that is running this command. */
export function currentCliPath(): string {
  return fileURLToPath(new URL('../cli.js', import.meta.url));
}

/**
 * How a wrapped server starts toolmoat: the running node with the running
 * cli.js, or `npx -y toolmoat@<version>` when cli.js sits in the npx cache,
 * which npm may clean at any time.
 */
export function launcherFor(cliPath: string, nodePath: string = process.execPath): Launcher {
  if (/[\\/]_npx[\\/]/.test(cliPath)) return { command: 'npx', prefix: ['-y', `toolmoat@${VERSION}`] };
  return { command: nodePath, prefix: [cliPath] };
}

/** The wrapped command line for a server. */
export function wrapLaunch(name: string, original: Launch, launcher: Launcher, options: ProxyOptions = {}): Launch {
  return {
    command: launcher.command,
    args: [
      ...launcher.prefix,
      'proxy',
      '--name',
      name,
      ...(options.lock ? ['--lock', options.lock] : []),
      ...(options.mode ? ['--mode', options.mode] : []),
      '--',
      original.command,
      ...original.args,
    ],
  };
}

/** A config file that wrap or unwrap will process. */
export interface ConfigTarget {
  path: string;
  label: string;
  /** Short id that prefixes the proxy --name of servers wrapped in this file, e.g. "cursor-user". */
  scope: string;
  format: ConfigFormat;
  serversKeys: readonly ServersKey[];
  /** Project configs get a note that the file is usually committed. */
  project: boolean;
  /** Named on the command line, so a missing file is an error rather than silently skipped. */
  explicit: boolean;
}

export interface Selection {
  targets: ConfigTarget[];
  /** Project configs that exist but were left out because nothing named them. */
  projectHints: ConfigTarget[];
}

function fromLocation(location: ClientConfigLocation, cwd: string, explicit: boolean): ConfigTarget {
  return {
    path: location.resolve(cwd),
    label: location.label,
    scope: location.id,
    format: location.format,
    serversKeys: location.serversKeys,
    project: location.scope === 'project',
    explicit,
  };
}

function customTarget(file: string, cwd: string): ConfigTarget {
  const known = findClientConfig(file, cwd);
  if (known) return { ...fromLocation(known, cwd, true), path: file };
  const base = path.basename(file).toLowerCase();
  if (base.endsWith('.toml')) {
    return { path: file, label: 'Codex', scope: 'codex', format: 'toml', serversKeys: ['mcp_servers'], project: false, explicit: true };
  }
  const keys: ServersKey[] = base === '.claude.json' ? ['mcpServers', 'projects.*.mcpServers'] : ['mcpServers', 'servers'];
  return { path: file, label: path.basename(file), scope: path.basename(file, path.extname(file)), format: 'json', serversKeys: keys, project: false, explicit: true };
}

/** Resolves --client and --config into the config files to process. Throws UsageError for an unknown client. */
export function selectTargets(clients: readonly string[], configs: readonly string[], cwd: string): Selection {
  const targets: ConfigTarget[] = [];
  const seen = new Set<string>();
  const add = (target: ConfigTarget) => {
    const key = pathKey(target.path);
    if (seen.has(key)) return;
    seen.add(key);
    targets.push(target);
  };
  for (const query of clients) {
    const matches = matchClientConfigs(query);
    if (matches.length === 0) {
      throw new UsageError(`unknown client '${query}'. Known clients: ${clientChoices().join(', ')}`);
    }
    for (const location of matches) add(fromLocation(location, cwd, true));
  }
  for (const file of configs) add(customTarget(path.resolve(cwd, expandHome(file)), cwd));
  if (clients.length > 0 || configs.length > 0) return { targets, projectHints: [] };

  const projectHints: ConfigTarget[] = [];
  for (const location of CLIENT_CONFIGS) {
    const target = fromLocation(location, cwd, false);
    if (!fs.existsSync(target.path)) continue;
    if (location.scope === 'project') projectHints.push(target);
    else add(target);
  }
  return { targets, projectHints };
}

export type ServerStatus = 'changed' | 'unchanged' | 'skipped';

export interface ServerReport {
  name: string;
  project?: string;
  status: ServerStatus;
  /** For changed servers, the original command line; otherwise why nothing changed. */
  detail: string;
  /** The command line after the change. */
  after?: Launch;
  /** For servers wrap newly wraps: the command line it had. */
  original?: Launch;
}

export interface ConfigReport {
  target: ConfigTarget;
  servers: ServerReport[];
  /** Why the file could not be read or written. Changed servers in it were not saved. */
  error?: string;
  written: boolean;
  /** Backup created by this run. */
  backup?: string;
  /** For TOML configs: the lines the user should paste, because toolmoat never edits TOML. */
  pasteLines?: string[];
}

/** Decides what happens to one server. It changes entry.server in place when the status is 'changed'. */
export type ServerTransform = (entry: ServerEntry) => ServerReport;

/** Reads a JSON config, applies the transform to every server and writes the file when something changed. */
export function processJsonTarget(
  target: ConfigTarget,
  transform: ServerTransform,
  options: { dryRun: boolean; force: boolean },
): ConfigReport {
  let config;
  try {
    config = readJsonConfig(target.path);
  } catch (error) {
    return { target, servers: [], written: false, error: readError(error) };
  }
  const servers = listServers(config.data, target.serversKeys).map(transform);
  const report: ConfigReport = { target, servers, written: false };
  if (!servers.some((s) => s.status === 'changed')) return report;
  if (config.hasComments && !options.force) {
    report.error = 'the file contains comments, which rewriting it would drop. Re-run with --force to rewrite it anyway, or edit it by hand';
    return report;
  }
  if (config.lossyNumber !== null) {
    report.error = `the file contains the number ${truncate(config.lossyNumber, 40)}, which rewriting it would change because JSON cannot hold it exactly. Edit the file by hand`;
    return report;
  }
  if (options.dryRun) return report;
  try {
    const { backup } = writeJsonConfig(config);
    report.written = true;
    if (backup) report.backup = backup;
  } catch (error) {
    report.error = `could not write the file: ${error instanceof Error ? error.message : String(error)}`;
  }
  return report;
}

function readError(error: unknown): string {
  const code = (error as NodeJS.ErrnoException).code;
  if (code === 'ENOENT') return 'file not found';
  if (code === 'EACCES' || code === 'EPERM') return 'permission denied';
  return error instanceof Error ? error.message : String(error);
}

/**
 * The node or cli.js path of a wrapped command line that no longer exists on
 * this machine (after a Node version switch, a reinstall or a config synced
 * from another machine), or null when the launcher is fine or not path-based.
 */
export function missingLauncherPath(launch: Launch): string | null {
  if (launch.args.indexOf('proxy') !== 1 || !/(?:^|[\\/])cli\.js$/i.test(launch.args[0]!)) return null;
  return [launch.command, launch.args[0]!].find((p) => path.isAbsolute(p) && !fs.existsSync(p)) ?? null;
}

/** Whether `toolmoat proxy --name` accepts the name: it refuses an empty one, control characters and more than 200 characters. */
export function isProxyName(name: string): boolean {
  return name !== '' && name.length <= 200 && !/[\u0000-\u001f\u007f]/.test(name);
}

/** What wrap does with one stdio command line: wrap it, point a stale wrapped one at this install, or leave it. */
export function planWrap(name: string, launch: Launch, launcher: Launcher, options: ProxyOptions): Pick<ServerReport, 'status' | 'detail' | 'after' | 'original'> {
  if (!splitWrapped(launch.command, launch.args)) {
    if (!isProxyName(name)) {
      return { status: 'skipped', detail: 'its name is empty, longer than 200 characters or has control characters, which the proxy rejects; rename the server first' };
    }
    return { status: 'changed', detail: formatLaunch(launch), after: wrapLaunch(name, launch, launcher, options), original: launch };
  }
  const missing = missingLauncherPath(launch);
  if (missing === null) return { status: 'unchanged', detail: 'already wrapped' };
  const after = { command: launcher.command, args: [...launcher.prefix, ...launch.args.slice(1)] };
  return { status: 'changed', detail: `already wrapped, but ${formatLaunch({ command: missing, args: [] })} no longer exists; launcher updated`, after };
}

/** Lowercase letters, digits and dashes only. */
function slug(text: string): string {
  return text.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
}

/**
 * The --name a wrapped server gets: the client, the project for per-project
 * servers, then the server's own name ("cursor.github", "claude-code-user.my-app.db").
 * The lockfile keys pins by name, so two clients that both call a server
 * "github" must not share one entry, or each would hide the other's tools.
 */
export function scopedName(scope: string, name: string, project?: string): string {
  const parts = [slug(scope) || 'mcp'];
  if (project !== undefined) parts.push(slug(path.basename(project)) || 'project');
  parts.push(name);
  return parts.join('.');
}

/** The wrap transform: replaces command and args of each stdio server with the proxy launch. */
export function wrapTransform(launcher: Launcher, options: ProxyOptions, scope?: string): ServerTransform {
  return (entry) => {
    const base = entry.project === undefined ? { name: entry.name } : { name: entry.name, project: entry.project };
    if (isRemoteServer(entry.server)) {
      return { ...base, status: 'skipped', detail: 'remote (url) server: the stdio proxy cannot wrap it' };
    }
    const launch = readLaunch(entry.server);
    if ('error' in launch) return { ...base, status: 'skipped', detail: launch.error };
    const proxyName = scope === undefined ? entry.name : scopedName(scope, entry.name, entry.project);
    const plan = planWrap(proxyName, launch, launcher, options);
    if (plan.after) applyWrapped(entry.server, plan.after);
    return { ...base, ...plan };
  };
}

/**
 * Sets the wrapped command and args in place, so every other key keeps its
 * position. When the entry had no args key, the new one is put before command:
 * unwrap reads that order to drop args again and restore the entry exactly.
 */
function applyWrapped(server: Record<string, unknown>, after: Launch): void {
  if (Object.hasOwn(server, 'args')) {
    server.command = after.command;
    server.args = after.args;
    return;
  }
  const rest = Object.entries(server).map(([key, value]): [string, unknown] => [key, key === 'command' ? after.command : value]);
  for (const key of Object.keys(server)) delete server[key];
  server.args = after.args;
  for (const [key, value] of rest) server[key] = value;
}

/** Wrap's view of a Codex config.toml: never edited, so changed servers come with lines to paste. */
export function processTomlTarget(target: ConfigTarget, transform: (name: string, launch: Launch) => ServerReport): ConfigReport {
  let text: string;
  try {
    text = fs.readFileSync(target.path, 'utf8');
  } catch (error) {
    return { target, servers: [], written: false, error: readError(error) };
  }
  const servers: ServerReport[] = [];
  const pasteLines: string[] = [];
  for (const server of readTomlServers(text)) {
    if (server.url !== undefined && server.command === undefined) {
      servers.push({ name: server.name, status: 'skipped', detail: 'remote (url) server: the stdio proxy cannot wrap it' });
      continue;
    }
    if (server.unparsed) {
      servers.push({ name: server.name, status: 'skipped', detail: `${server.unparsed}; edit it by hand` });
      continue;
    }
    if (server.command === undefined) {
      servers.push({ name: server.name, status: 'skipped', detail: 'no command (not a stdio server)' });
      continue;
    }
    const report = transform(server.name, { command: server.command, args: server.args ?? [] });
    servers.push(report);
    if (report.status === 'changed' && report.after) {
      pasteLines.push(
        server.header,
        `command = ${tomlString(report.after.command)}`,
        `args = [${report.after.args.map(tomlString).join(', ')}]`,
        '',
      );
    }
  }
  const report: ConfigReport = { target, servers, written: false };
  if (pasteLines.length > 0) report.pasteLines = pasteLines.slice(0, -1);
  return report;
}

function quoteArg(arg: string): string {
  return /^[\w@%+=:,./\\-]+$/.test(arg) ? arg : `"${arg.replace(/"/g, '\\"')}"`;
}

/** A command line for display: quoted where needed, secrets redacted, invisible characters escaped. */
export function formatLaunch(launch: Launch, max = 120): string {
  const text = [launch.command, ...launch.args].map(quoteArg).join(' ');
  return truncate(printable(redactSecrets(text)), max);
}

function inside(base: string, file: string): string | null {
  const rel = path.relative(base, file);
  if (!rel || rel === '..' || rel.startsWith(`..${path.sep}`) || path.isAbsolute(rel)) return null;
  return rel.split(path.sep).join('/');
}

/** Relative to the working directory when inside it, '~/...' inside the home directory, else absolute; forward slashes. */
export function shownPath(file: string): string {
  const inCwd = inside(process.cwd(), file);
  if (inCwd !== null) return inCwd;
  const inHome = inside(homeDir(), file);
  return inHome !== null ? `~/${inHome}` : file.split(path.sep).join('/');
}

/** Client names to restart, from the labels of the configs that were written. */
export function clientsToRestart(reports: readonly ConfigReport[]): string[] {
  const names = reports.filter((r) => r.written).map((r) => r.target.label.replace(/\s*\(.*\)$/, ''));
  return [...new Set(names)];
}

function joinNames(names: readonly string[]): string {
  if (names.length <= 1) return names.join('');
  return `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}`;
}

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? '' : 's'}`;
}

export interface ParsedTargetArgs {
  clients: string[];
  configs: string[];
  dryRun: boolean;
  force: boolean;
  lock?: string;
  mode?: string;
}

/** Parses the options wrap and unwrap share (plus wrap's --lock and --mode when allowed). Throws UsageError. */
export function parseTargetArgs(argv: string[], withProxyOptions: boolean): ParsedTargetArgs {
  const options = {
    client: { type: 'string', multiple: true },
    config: { type: 'string', multiple: true },
    'dry-run': { type: 'boolean' },
    force: { type: 'boolean' },
    lock: { type: 'string' },
    mode: { type: 'string' },
  } as const;
  let values;
  try {
    ({ values } = parseArgs({ args: argv, options, strict: true, allowPositionals: false }));
  } catch (error) {
    throw new UsageError(error instanceof Error ? error.message : String(error));
  }
  if (!withProxyOptions) {
    const extra = (['lock', 'mode'] as const).find((key) => values[key] !== undefined);
    if (extra) throw new UsageError(`Unknown option '--${extra}'`);
  }
  const parsed: ParsedTargetArgs = {
    clients: values.client ?? [],
    configs: values.config ?? [],
    dryRun: values['dry-run'] === true,
    force: values.force === true,
  };
  if (typeof values.lock === 'string') parsed.lock = values.lock;
  if (typeof values.mode === 'string') parsed.mode = values.mode;
  return parsed;
}

/** Prints the per-config report shared by wrap and unwrap. */
export function printReports(reports: readonly ConfigReport[], verbs: { done: string; planned: string }, dryRun: boolean): void {
  const c = palette();
  const out = (line = '') => process.stdout.write(`${line}\n`);
  for (const report of reports) {
    const { target } = report;
    out(`${c.bold(target.label)}  ${c.dim(shownPath(target.path))}`);
    if (report.servers.length === 0 && !report.error) out(`  ${c.dim('no servers')}`);
    const width = Math.min(28, Math.max(4, ...report.servers.map((s) => printable(s.name).length)));
    for (const server of report.servers) {
      const name = printable(server.name).padEnd(width);
      const where = server.project !== undefined ? c.dim(` (project ${printable(server.project)})`) : '';
      if (server.status === 'changed') {
        const saved = report.written || (dryRun && !report.error) || target.format === 'toml';
        const verb = target.format === 'toml' ? 'paste' : saved ? (report.written ? verbs.done : verbs.planned) : 'not saved';
        const color = saved ? c.green : c.yellow;
        out(`  ${color(verb.padEnd(10))} ${name} ${server.detail}${where}`);
      } else {
        const label = server.status === 'unchanged' ? c.dim('unchanged'.padEnd(10)) : c.yellow('skipped'.padEnd(10));
        out(`  ${label} ${name} ${c.dim(server.detail)}${where}`);
      }
    }
    if (report.error) out(`  ${c.red('error')}      ${report.error}`);
    if (report.backup) out(`  ${c.dim(`backup: ${shownPath(report.backup)}`)}`);
    if (report.written && target.project) {
      out(`  ${c.yellow('note')}       this project file is usually committed; the new command holds paths from this machine`);
    }
    if (report.pasteLines) {
      out(`  ${c.yellow('not edited')} toolmoat never rewrites TOML. Replace the command and args lines of these tables:`);
      for (const line of report.pasteLines) out(line ? `    ${line}` : '');
    }
    out();
  }
}

/** Counts the JSON-config servers that were (or, in a dry run, would be) changed. TOML changes are only printed. */
export function countChanged(reports: readonly ConfigReport[], dryRun: boolean): number {
  let count = 0;
  for (const report of reports) {
    if (report.target.format !== 'json' || !(report.written || (dryRun && !report.error))) continue;
    count += report.servers.filter((s) => s.status === 'changed').length;
  }
  return count;
}

/** Processes the selected targets; missing explicit files become error reports, missing default ones are dropped. */
export function processTargets(
  targets: readonly ConfigTarget[],
  jsonTransform: ServerTransform,
  tomlTransform: (name: string, launch: Launch) => ServerReport,
  options: { dryRun: boolean; force: boolean },
): ConfigReport[] {
  const reports: ConfigReport[] = [];
  for (const target of targets) {
    if (!fs.existsSync(target.path)) {
      if (target.explicit) reports.push({ target, servers: [], written: false, error: 'file not found' });
      continue;
    }
    reports.push(target.format === 'toml' ? processTomlTarget(target, tomlTransform) : processJsonTarget(target, jsonTransform, options));
  }
  return reports;
}

export async function run(argv: string[]): Promise<number> {
  let args: ParsedTargetArgs;
  let selection: Selection;
  const cwd = process.cwd();
  try {
    args = parseTargetArgs(argv, true);
    if (args.mode !== undefined && args.mode !== 'enforce' && args.mode !== 'warn') {
      throw new UsageError(`--mode must be enforce or warn, not '${args.mode}'`);
    }
    selection = selectTargets(args.clients, args.configs, cwd);
  } catch (error) {
    if (!(error instanceof UsageError)) throw error;
    process.stderr.write(`toolmoat wrap: ${error.message}\n\n${help}\n`);
    return 2;
  }

  const cliPath = currentCliPath();
  if (!fs.existsSync(cliPath)) {
    process.stderr.write(`toolmoat wrap: cannot find toolmoat's cli.js at ${cliPath}; run wrap from the installed package\n`);
    return 1;
  }
  const launcher = launcherFor(cliPath);
  const proxyOptions: ProxyOptions = {};
  if (args.lock) proxyOptions.lock = path.resolve(cwd, expandHome(args.lock));
  if (args.mode === 'enforce' || args.mode === 'warn') proxyOptions.mode = args.mode;

  const reports = selection.targets.flatMap((target) =>
    processTargets(
      [target],
      wrapTransform(launcher, proxyOptions, target.scope),
      (name, launch) => ({ name, ...planWrap(scopedName(target.scope, name), launch, launcher, proxyOptions) }),
      { dryRun: args.dryRun, force: args.force },
    ),
  );
  if (reports.some((r) => r.servers.some((s) => s.status === 'changed'))) {
    const shape = wrapLaunch('<server>', { command: '<original command>', args: [] }, launcher, proxyOptions);
    const text = [shape.command, ...shape.args].map((arg) => (arg.startsWith('<') ? arg : quoteArg(arg))).join(' ');
    process.stdout.write(`${palette().dim(`Wrapped servers start as: ${text}`)}\n\n`);
  }
  const code = summarize(reports, selection, args.dryRun, 'wrap');
  for (const clash of nameClashes(reports)) {
    const programs = clash.programs.map((p) => truncate(printable(p), 60)).join(', ');
    process.stdout.write(
      `${palette().yellow('note')} '${truncate(printable(clash.name), 60)}' names servers that run different programs (${programs}). The proxy keeps one lockfile entry per name, so they would hide each other's tools: change the value after --name in all but one of them.\n`,
    );
  }
  return code;
}

/** Names shared by newly wrapped servers that run different programs, with those programs. */
export function nameClashes(reports: readonly ConfigReport[]): { name: string; programs: string[] }[] {
  const byName = new Map<string, Set<string>>();
  for (const report of reports) {
    if (report.error) continue;
    for (const server of report.servers) {
      if (server.status !== 'changed' || !server.original || !server.after) continue;
      // Compare the --name the proxy will actually use, which carries the client and project scope.
      const proxyName = server.after.args[server.after.args.indexOf('--name') + 1] ?? server.name;
      const programs = byName.get(proxyName) ?? new Set<string>();
      programs.add(deriveServerName(server.original.command, server.original.args));
      byName.set(proxyName, programs);
    }
  }
  return [...byName].filter(([, programs]) => programs.size > 1).map(([name, programs]) => ({ name, programs: [...programs] }));
}

/** Prints the reports and the closing summary, and returns the exit code. */
export function summarize(reports: readonly ConfigReport[], selection: Selection, dryRun: boolean, verb: 'wrap' | 'unwrap'): number {
  const c = palette();
  const out = (line = '') => process.stdout.write(`${line}\n`);
  const words = verb === 'wrap' ? { done: 'wrapped', planned: 'would wrap' } : { done: 'unwrapped', planned: 'would unwrap' };
  printReports(reports, words, dryRun);

  if (selection.projectHints.length > 0) {
    out(c.dim(`Project configs left alone (name them with --config or --client to ${verb} them):`));
    for (const hint of selection.projectHints) out(c.dim(`  ${hint.label}  ${shownPath(hint.path)}`));
    out();
  }
  if (reports.length === 0) {
    out(selection.projectHints.length > 0 ? `No user-level MCP client configs found.` : 'No MCP client configs found.');
    return selection.projectHints.length > 0 ? 0 : 1;
  }

  const changed = countChanged(reports, dryRun);
  const errors = reports.filter((r) => r.error).length;
  const written = reports.filter((r) => r.written).length;
  const configsTouched = dryRun ? reports.filter((r) => !r.error && r.target.format === 'json' && r.servers.some((s) => s.status === 'changed')).length : written;
  const pasted = reports.filter((r) => r.pasteLines).length;
  const pastedServers = reports.reduce((n, r) => n + (r.pasteLines ? r.servers.filter((s) => s.status === 'changed').length : 0), 0);
  if (dryRun) {
    out(`Dry run: would ${verb} ${plural(changed, 'server')} in ${plural(configsTouched, 'config')}. Nothing was written.`);
  } else if (written > 0) {
    out(`${verb === 'wrap' ? 'Wrapped' : 'Unwrapped'} ${plural(changed, 'server')} in ${plural(written, 'config')}.`);
  } else {
    out(pasted === 0 ? `Nothing to ${verb}.` : `Nothing to ${verb} in the JSON configs.`);
  }
  if (pasted > 0) {
    out(`Codex: ${plural(pastedServers, 'server')} to ${verb} by hand; paste the lines shown above into ${pasted === 1 ? 'its config.toml' : 'those config.toml files'}.`);
  }
  const restart = clientsToRestart(reports);
  if (restart.length > 0) out(`Restart ${joinNames(restart)} so ${restart.length === 1 ? 'it starts' : 'they start'} the servers ${verb === 'wrap' ? 'through toolmoat' : 'directly again'}.`);
  if (errors > 0) out(c.red(`${plural(errors, 'config')} could not be processed; see the errors above.`));
  return errors > 0 && changed === 0 && pastedServers === 0 ? 1 : 0;
}
