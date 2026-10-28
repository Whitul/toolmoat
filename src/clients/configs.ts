import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { isRecord, parseJsonc, stripComments } from '../util/jsonc.js';
import { appDataDir, homeDir } from '../util/paths.js';
import { joinKeyPath, parseToml } from '../util/toml-lite.js';

export type ConfigScope = 'user' | 'project';
export type ConfigFormat = 'json' | 'toml';
/** Where a config keeps its servers. "projects.*.mcpServers" is ~/.claude.json's per-project map. */
export type ServersKey = 'mcpServers' | 'servers' | 'projects.*.mcpServers' | 'mcp_servers';

/** A file where an MCP client keeps its server list. Discovery scans these and wrap rewrites them. */
export interface ClientConfigLocation {
  /** Stable id accepted by --client, e.g. "claude-desktop". */
  id: string;
  /** Client family, e.g. "cursor". As a --client value it selects the family's user-level configs. */
  client: string;
  /** Readable name used as the report target, e.g. "Claude Code (user)". */
  label: string;
  scope: ConfigScope;
  format: ConfigFormat;
  serversKeys: readonly ServersKey[];
  /** Size limit for discovery when the file is known to grow large. */
  maxBytes?: number;
  /** Absolute path of the file on this machine; project configs live under cwd. */
  resolve(cwd: string): string;
}

const MIB = 1024 * 1024;

export const CLIENT_CONFIGS: readonly ClientConfigLocation[] = [
  {
    id: 'claude-desktop',
    client: 'claude-desktop',
    label: 'Claude Desktop',
    scope: 'user',
    format: 'json',
    serversKeys: ['mcpServers'],
    resolve: () => path.join(appDataDir(), 'Claude', 'claude_desktop_config.json'),
  },
  {
    id: 'claude-code-user',
    client: 'claude-code',
    label: 'Claude Code (user)',
    scope: 'user',
    format: 'json',
    serversKeys: ['mcpServers', 'projects.*.mcpServers'],
    maxBytes: 20 * MIB,
    resolve: () => path.join(homeDir(), '.claude.json'),
  },
  {
    id: 'claude-code-project',
    client: 'claude-code',
    label: 'Claude Code (project .mcp.json)',
    scope: 'project',
    format: 'json',
    serversKeys: ['mcpServers'],
    resolve: (cwd) => path.join(cwd, '.mcp.json'),
  },
  {
    id: 'cursor-user',
    client: 'cursor',
    label: 'Cursor',
    scope: 'user',
    format: 'json',
    serversKeys: ['mcpServers'],
    resolve: () => path.join(homeDir(), '.cursor', 'mcp.json'),
  },
  {
    id: 'cursor-project',
    client: 'cursor',
    label: 'Cursor (project)',
    scope: 'project',
    format: 'json',
    serversKeys: ['mcpServers'],
    resolve: (cwd) => path.join(cwd, '.cursor', 'mcp.json'),
  },
  {
    id: 'vscode-user',
    client: 'vscode',
    label: 'VS Code',
    scope: 'user',
    format: 'json',
    serversKeys: ['servers'],
    resolve: () => path.join(appDataDir(), 'Code', 'User', 'mcp.json'),
  },
  {
    id: 'vscode-project',
    client: 'vscode',
    label: 'VS Code (project)',
    scope: 'project',
    format: 'json',
    serversKeys: ['servers'],
    resolve: (cwd) => path.join(cwd, '.vscode', 'mcp.json'),
  },
  {
    id: 'windsurf',
    client: 'windsurf',
    label: 'Windsurf',
    scope: 'user',
    format: 'json',
    serversKeys: ['mcpServers'],
    resolve: () => path.join(homeDir(), '.codeium', 'windsurf', 'mcp_config.json'),
  },
  {
    id: 'codex',
    client: 'codex',
    label: 'Codex',
    scope: 'user',
    format: 'toml',
    serversKeys: ['mcp_servers'],
    resolve: () => path.join(homeDir(), '.codex', 'config.toml'),
  },
  {
    id: 'gemini-user',
    client: 'gemini',
    label: 'Gemini CLI',
    scope: 'user',
    format: 'json',
    serversKeys: ['mcpServers'],
    resolve: () => path.join(homeDir(), '.gemini', 'settings.json'),
  },
  {
    id: 'gemini-project',
    client: 'gemini',
    label: 'Gemini CLI (project)',
    scope: 'project',
    format: 'json',
    serversKeys: ['mcpServers'],
    resolve: (cwd) => path.join(cwd, '.gemini', 'settings.json'),
  },
];

/** Normalised form of a path for equality checks and dedupe: resolved, and lower-cased on Windows. */
export function pathKey(p: string): string {
  const resolved = path.resolve(p);
  return process.platform === 'win32' ? resolved.toLowerCase() : resolved;
}

/** The known client config at exactly this path, if any. */
export function findClientConfig(absPath: string, cwd: string): ClientConfigLocation | undefined {
  const key = pathKey(absPath);
  return CLIENT_CONFIGS.find((location) => pathKey(location.resolve(cwd)) === key);
}

function compact(text: string): string {
  return text.toLowerCase().replace(/[^a-z0-9]/g, '');
}

/**
 * Configs selected by one --client value. An exact id or label picks that one
 * config; a client family such as "cursor" picks the family's user-level configs.
 */
export function matchClientConfigs(query: string): ClientConfigLocation[] {
  const q = compact(query);
  if (!q) return [];
  const exact = CLIENT_CONFIGS.filter((l) => compact(l.id) === q || compact(l.label) === q);
  if (exact.length > 0) return exact;
  return CLIENT_CONFIGS.filter((l) => compact(l.client) === q && l.scope === 'user');
}

/** Values --client accepts, for usage messages. */
export function clientChoices(): string[] {
  return [...new Set([...CLIENT_CONFIGS.map((l) => l.client), ...CLIENT_CONFIGS.map((l) => l.id)])];
}

/** A parsed JSON config plus what is needed to write it back faithfully. */
export interface JsonConfigFile {
  path: string;
  /** The exact text read from disk. */
  text: string;
  data: Record<string, unknown>;
  /** True when the file has // or /* comments, which a rewrite would drop. */
  hasComments: boolean;
  /** A number in the file that JSON.parse cannot hold exactly, so a rewrite would change it; null when there is none. */
  lossyNumber: string | null;
}

/** Reads and parses a JSON or JSONC config. Throws an Error with a readable message. */
export function readJsonConfig(file: string): JsonConfigFile {
  const text = fs.readFileSync(file, 'utf8');
  const source = text.startsWith('﻿') ? text.slice(1) : text;
  const data = source.trim() === '' ? {} : parseJsonc(source);
  if (!isRecord(data)) throw new Error(`${file} is not valid JSON (or not a JSON object)`);
  const stripped = stripComments(source);
  return { path: file, text, data, hasComments: stripped !== source, lossyNumber: findLossyNumber(stripped) };
}

/** The first integer literal longer than 15 digits that a parse and re-serialise would round, or a number that overflows to null. */
function findLossyNumber(text: string): string | null {
  for (const match of text.matchAll(/"(?:[^"\\]|\\.)*"|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g)) {
    const token = match[0];
    if (token.startsWith('"')) continue;
    if (!Number.isFinite(Number(token))) return token;
    if (/^-?\d{16,}$/.test(token) && String(Number(token)) !== token) return token;
  }
  return null;
}

/** One server entry inside a config. */
export interface ServerEntry {
  name: string;
  /** Where the entry lives, for messages: "mcpServers", "servers" or projects["/path"].mcpServers. */
  section: string;
  /** Project path for ~/.claude.json project-scoped servers. */
  project?: string;
  /** The live object inside the parsed config: changing it changes what writeJsonConfig writes. */
  server: Record<string, unknown>;
}

/** Every server entry under the given keys, in file order. */
export function listServers(data: Record<string, unknown>, keys: readonly ServersKey[]): ServerEntry[] {
  const out: ServerEntry[] = [];
  const collect = (servers: unknown, section: string, project?: string) => {
    if (!isRecord(servers)) return;
    for (const [name, server] of Object.entries(servers)) {
      if (!isRecord(server)) continue;
      out.push(project === undefined ? { name, section, server } : { name, section, project, server });
    }
  };
  for (const key of keys) {
    if (key !== 'projects.*.mcpServers') {
      collect(data[key], key);
      continue;
    }
    const projects = data.projects;
    if (!isRecord(projects)) continue;
    for (const [project, value] of Object.entries(projects)) {
      if (isRecord(value)) collect(value.mcpServers, `projects[${JSON.stringify(project)}].mcpServers`, project);
    }
  }
  return out;
}

const REMOTE_TYPES = new Set(['http', 'sse', 'streamable-http', 'streamablehttp', 'ws', 'websocket']);

/** True for servers reached over the network (url, serverUrl, httpUrl or an http/sse type). */
export function isRemoteServer(server: Record<string, unknown>): boolean {
  if (typeof server.url === 'string' || typeof server.serverUrl === 'string' || typeof server.httpUrl === 'string') return true;
  return typeof server.type === 'string' && REMOTE_TYPES.has(server.type.toLowerCase()) && typeof server.command !== 'string';
}

export interface Launch {
  command: string;
  args: string[];
}

/** The command line of a stdio server, or a reason it cannot be read as one. */
export function readLaunch(server: Record<string, unknown>): Launch | { error: string } {
  const { command, args } = server;
  if (typeof command !== 'string' || command.trim() === '') return { error: 'no command (not a stdio server)' };
  if (args === undefined) return { command, args: [] };
  if (!Array.isArray(args) || !args.every((a): a is string => typeof a === 'string')) {
    return { error: 'args is not a list of strings' };
  }
  return { command, args: [...args] };
}

/**
 * Options of `toolmoat proxy` that take a value, so a value such as "--" is
 * not read as the separator. The proxy's own parser uses these sets too, so
 * a new option cannot make wrapped entries unrecognisable.
 */
export const PROXY_VALUE_FLAGS: ReadonlySet<string> = new Set(['--name', '--lock', '--mode', '--on-new', '--allow-new', '--audit-log', '--allow-secret']);
export const PROXY_BOOLEAN_FLAGS: ReadonlySet<string> = new Set(['--no-audit', '--log-args']);

function commandName(command: string): string {
  return path.basename(command.replace(/\\/g, '/')).toLowerCase().replace(/\.(cmd|exe|ps1|bat)$/, '');
}

/**
 * The original command line inside an toolmoat-wrapped one ([command, ...args]
 * after the "--"), or null when the command line was not written by wrap. An
 * empty array means the entry is wrapped but has nothing after "--".
 * Recognised launchers: <node> <.../cli.js> proxy, npx -y toolmoat@<version> proxy, toolmoat proxy.
 * Only options of `toolmoat proxy` may stand between "proxy" and "--", so
 * another program's `node tool/cli.js proxy --stdio -- upstream` is not taken
 * for a wrapped server (unwrap would otherwise rewrite it).
 */
export function splitWrapped(command: string, args: readonly string[]): string[] | null {
  const at = args.indexOf('proxy');
  if (at === -1) return null;
  const viaCli = at === 1 && /(?:^|[\\/])cli\.js$/i.test(args[0]!);
  const viaPackage = args.slice(0, at).some((arg) => /^toolmoat(?:@[^\s]{1,64})?$/.test(arg));
  const viaBin = at === 0 && commandName(command) === 'toolmoat';
  if (!viaCli && !viaPackage && !viaBin) return null;
  for (let i = at + 1; i < args.length; i++) {
    const arg = args[i]!;
    if (arg === '--') return args.slice(i + 1);
    if (PROXY_VALUE_FLAGS.has(arg)) i++;
    else if (!PROXY_BOOLEAN_FLAGS.has(arg) && !PROXY_VALUE_FLAGS.has(arg.split('=')[0]!)) return null;
  }
  return null;
}

/**
 * The command line a wrapped server really runs, or null when the launch is
 * not wrapped by toolmoat (or wraps nothing). Rules that judge a server's
 * command should look at this rather than at the toolmoat launcher.
 */
export function originalLaunch(launch: Launch): Launch | null {
  const inner = splitWrapped(launch.command, launch.args);
  if (!inner || inner.length === 0) return null;
  return { command: inner[0]!, args: inner.slice(1) };
}

/** The stdio servers of a parsed JSON config with their command lines. */
export function stdioServers(data: Record<string, unknown>, keys: readonly ServersKey[]): (ServerEntry & { launch: Launch })[] {
  const out: (ServerEntry & { launch: Launch })[] = [];
  for (const entry of listServers(data, keys)) {
    if (isRemoteServer(entry.server)) continue;
    const launch = readLaunch(entry.server);
    if (!('error' in launch)) out.push({ ...entry, launch });
  }
  return out;
}

/** Path of the one-time backup kept next to a config before toolmoat first changes it. */
export function backupPath(file: string): string {
  return `${file}.toolmoat.bak`;
}

/**
 * Writes config.data back to config.path, keeping the original indentation,
 * line endings, BOM and trailing newline. Creates "<file>.toolmoat.bak" the
 * first time, writes a temp file in the same directory and renames it over the
 * original, so a crash never leaves a half-written config. Refuses when the
 * file changed on disk since it was read (clients rewrite their configs).
 * Returns the backup path when this call created it.
 */
export function writeJsonConfig(config: JsonConfigFile): { backup: string | null } {
  const target = realTarget(config.path);
  const current = fs.readFileSync(target, 'utf8');
  if (current !== config.text) {
    throw new Error(`${config.path} changed on disk while toolmoat was editing it; run the command again`);
  }
  const backup = backupPath(target);
  let created: string | null = null;
  if (!fs.existsSync(backup)) {
    fs.copyFileSync(target, backup, fs.constants.COPYFILE_EXCL);
    created = backup;
  }
  atomicWrite(target, serializeLike(config.data, config.text));
  return { backup: created };
}

function realTarget(file: string): string {
  try {
    return fs.realpathSync(file);
  } catch {
    return file;
  }
}

/** JSON.stringify with the indentation, line endings, BOM and final newline of the original text. */
export function serializeLike(data: unknown, original: string): string {
  const bom = original.startsWith('﻿') ? '﻿' : '';
  const eol = original.includes('\r\n') ? '\r\n' : '\n';
  const trailing = /\n[ \t]*$/.test(original) || original.trim() === '' ? eol : '';
  let json = JSON.stringify(data, null, detectIndent(original));
  if (eol !== '\n') json = json.replace(/\n/g, eol);
  return `${bom}${json}${trailing}`;
}

function detectIndent(text: string): string | number {
  const body = text.trim();
  if (body !== '' && !body.includes('\n')) return 0;
  const match = /\n([ \t]{1,16})\S/.exec(text);
  if (!match) return 2;
  const indent = match[1]!;
  return indent.startsWith('\t') ? '\t' : indent.length;
}

function atomicWrite(target: string, content: string): void {
  const mode = fs.statSync(target).mode & 0o777;
  const temp = path.join(path.dirname(target), `.${path.basename(target)}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`);
  try {
    const fd = fs.openSync(temp, 'wx', mode);
    try {
      fs.writeFileSync(fd, content, 'utf8');
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    if (process.platform !== 'win32') fs.chmodSync(temp, mode);
    renameWithRetry(temp, target);
  } catch (error) {
    fs.rmSync(temp, { force: true });
    throw error;
  }
}

/** Windows briefly locks files that editors, antivirus or the client itself have open. */
function renameWithRetry(from: string, to: string): void {
  for (let attempt = 0; ; attempt++) {
    try {
      fs.renameSync(from, to);
      return;
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      const transient = code === 'EPERM' || code === 'EACCES' || code === 'EBUSY';
      if (process.platform !== 'win32' || !transient || attempt >= 5) throw error;
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 50 * (attempt + 1));
    }
  }
}

/** A [mcp_servers.<name>] table from a Codex config.toml. */
export interface TomlServer {
  name: string;
  /** The header line exactly as written, e.g. [mcp_servers.github]. */
  header: string;
  /** 1-based line of the header. */
  line: number;
  command?: string;
  args?: string[];
  url?: string;
  /** Set when the server cannot be wrapped by pasting a replacement for its table; says why. */
  unparsed?: string;
}

/**
 * Reads the servers of a Codex config.toml with toml-lite. wrap prints
 * replacement lines for a server's own [mcp_servers.<name>] table, so servers
 * defined inline or with dotted keys are marked unparsed. It never rewrites
 * the file.
 */
export function readTomlServers(text: string): TomlServer[] {
  const doc = parseToml(text);
  const table = doc.data.mcp_servers;
  if (!isRecord(table)) return [];
  const lines = text.split(/\r?\n/);
  const servers: TomlServer[] = [];
  for (const [name, value] of Object.entries(table)) {
    if (!isRecord(value)) continue;
    const line = doc.lines.get(joinKeyPath(['mcp_servers', name])) ?? 0;
    const source = (lines[line - 1] ?? '').trim();
    const server: TomlServer = { name, header: source, line };
    const { command, args, url } = value;
    if (typeof command === 'string') server.command = command;
    else if (command !== undefined) server.unparsed = 'command is not a string';
    if (Array.isArray(args) && args.every((a): a is string => typeof a === 'string')) server.args = [...args];
    else if (args !== undefined) server.unparsed = 'args is not a list of strings';
    if (typeof url === 'string') server.url = url;
    if (!source.startsWith('[')) server.unparsed = 'it is defined inline or with dotted keys rather than in its own [mcp_servers.<name>] table';
    else if (command === undefined && url === undefined && doc.errors.length > 0) {
      server.unparsed = `config.toml has syntax toolmoat could not read (line ${doc.errors[0]!.line})`;
    }
    servers.push(server);
  }
  return servers;
}

/** Formats a string as a TOML value: a literal string when that is safe, else a basic string. */
export function tomlString(value: string): string {
  if (!/['\u0000-\u001f\u007f]/.test(value)) return `'${value}'`;
  return JSON.stringify(value);
}
