/**
 * Structure-aware rules for MCP client configs, agent harness settings and
 * hooks, plugin manifests, package manifests and skill frontmatter.
 *
 * Each file is parsed once (JSONC or TOML) into a small model: the MCP
 * servers it declares, the hook commands it registers and its permission
 * grants. Rules read that model and point findings at the exact key, using a
 * position map built from the raw text. Command strings found inside configs
 * (hook commands, inline server scripts, install scripts) are also run
 * through the dangerous-code rules as synthetic 'script' files, and hits are
 * reported under this module's rule ids so the config file gets the finding.
 *
 * Malformed input never throws: a file that does not parse gives no matches.
 */
import { Buffer } from 'node:buffer';
import path from 'node:path';
import { findSecrets, redactSecrets } from '../patterns/secrets.js';
import type { FileKind, Rule, RuleMatch, ScanFile, Severity } from '../types.js';
import { SEVERITY_RANK } from '../types.js';
import { asList, parseFrontmatter } from '../util/frontmatter.js';
import { indexOfJsonString, isRecord, parseJsonc } from '../util/jsonc.js';
import { homeDir } from '../util/paths.js';
import { findAll, lineStartIndex, printable, truncate } from '../util/text.js';
import { joinKeyPath, parseToml } from '../util/toml-lite.js';
import { codeRules } from './code.js';

const SERVER_KINDS: readonly FileKind[] = ['mcp-config', 'plugin-manifest', 'agent-settings'];
const HOOK_KINDS: readonly FileKind[] = ['agent-settings', 'plugin-manifest', 'mcp-config'];
const LAUNCH_KINDS: readonly FileKind[] = ['mcp-config', 'plugin-manifest', 'agent-settings'];

const MAX_SERVERS = 500;
const MAX_HOOKS = 500;
const MAX_SCRIPT = 20_000;
const MAX_WORDS = 400;
const MAX_INNER_HITS = 10;
const MAX_JSON_DEPTH = 10;

// ===========================================================================
// Parsed documents
// ===========================================================================

type Seg = string | number;
type Where = { index: number } | { line: number };

interface ConfigDoc {
  file: ScanFile;
  format: 'json' | 'toml' | 'text';
  data: Record<string, unknown> | undefined;
  /** Position of a key path in the raw text, falling back to the nearest ancestor that was found. */
  where(segments: readonly Seg[]): Where;
  servers?: McpServer[];
  hooks?: HookCommand[];
}

/** One-entry memo: every rule in this module parses the same file in turn. */
let lastDoc: ConfigDoc | undefined;

function loadDoc(file: ScanFile): ConfigDoc {
  const prev = lastDoc;
  if (
    prev &&
    prev.file.path === file.path &&
    prev.file.displayPath === file.displayPath &&
    prev.file.kind === file.kind &&
    prev.file.content === file.content
  ) {
    return prev;
  }
  const doc = isTomlFile(file) ? tomlDoc(file) : jsonDoc(file);
  lastDoc = doc;
  return doc;
}

function isTomlFile(file: ScanFile): boolean {
  return /\.toml$/i.test(file.path) || /\.toml$/i.test(file.displayPath);
}

function jsonDoc(file: ScanFile): ConfigDoc {
  const parsed = file.content.trim() ? parseJsonc(file.content) : undefined;
  const data = isRecord(parsed) ? parsed : undefined;
  let offsets: Map<string, number> | undefined;
  return {
    file,
    format: data ? 'json' : 'text',
    data,
    where(segments) {
      offsets ??= locateJson(file.content);
      for (let n = segments.length; n > 0; n--) {
        const hit = offsets.get(pathKey(segments.slice(0, n)));
        if (hit !== undefined) return { index: hit };
      }
      const last = segments[segments.length - 1];
      const guess = typeof last === 'string' ? indexOfJsonString(file.content, last) : -1;
      return { index: Math.max(0, guess) };
    },
  };
}

function tomlDoc(file: ScanFile): ConfigDoc {
  const { data, lines } = parseToml(file.content);
  return {
    file,
    format: 'toml',
    data,
    where(segments) {
      for (let n = segments.length; n > 0; n--) {
        const line = lines.get(joinKeyPath(segments.slice(0, n)));
        if (line !== undefined) return { line };
      }
      return { line: 1 };
    },
  };
}

const PATH_SEP = '\u0000';

function pathKey(segments: readonly Seg[]): string {
  return segments.join(PATH_SEP);
}

interface JsonFrame {
  array: boolean;
  /** Path key of this container plus a trailing separator ('' for the root). */
  prefix: string;
  index: number;
  elementSeen: boolean;
  expectKey: boolean;
  pendingKey: string;
}

/**
 * Maps the path of every object key and array element in JSONC text to its
 * offset (the key's opening quote, or the element's first character). Single
 * linear pass, tolerant of comments and trailing commas; stops quietly on
 * anything malformed. Paths deeper than MAX_JSON_DEPTH are not recorded.
 */
function locateJson(text: string): Map<string, number> {
  const out = new Map<string, number>();
  const stack: JsonFrame[] = [];
  const n = text.length;
  let i = 0;

  const childPrefix = (): string | undefined => {
    const top = stack[stack.length - 1];
    if (!top) return '';
    if (stack.length > MAX_JSON_DEPTH) return undefined;
    if (top.array) {
      const key = top.prefix + String(top.index);
      if (!top.elementSeen) {
        top.elementSeen = true;
        out.set(key, i);
      }
      return key + PATH_SEP;
    }
    return top.prefix + top.pendingKey + PATH_SEP;
  };

  while (i < n) {
    const ch = text[i]!;
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r' || ch === '\ufeff' || ch === ':') {
      i++;
      continue;
    }
    if (ch === '/' && text[i + 1] === '/') {
      const nl = text.indexOf('\n', i);
      i = nl === -1 ? n : nl;
      continue;
    }
    if (ch === '/' && text[i + 1] === '*') {
      const end = text.indexOf('*/', i + 2);
      i = end === -1 ? n : end + 2;
      continue;
    }
    const top = stack[stack.length - 1];
    if (ch === '"') {
      const end = endOfJsonString(text, i);
      if (end === -1) break;
      if (top && !top.array && top.expectKey) {
        let key: unknown;
        try {
          key = JSON.parse(text.slice(i, end));
        } catch {
          break;
        }
        top.pendingKey = String(key);
        top.expectKey = false;
        if (stack.length <= MAX_JSON_DEPTH) out.set(top.prefix + top.pendingKey, i);
      } else {
        childPrefix();
      }
      i = end;
      continue;
    }
    if (ch === '{' || ch === '[') {
      const prefix = childPrefix();
      stack.push({ array: ch === '[', prefix: prefix ?? `${PATH_SEP}deep${PATH_SEP}`, index: 0, elementSeen: false, expectKey: ch === '{', pendingKey: '' });
      i++;
      continue;
    }
    if (ch === '}' || ch === ']') {
      stack.pop();
      i++;
      continue;
    }
    if (ch === ',') {
      if (top?.array) {
        top.index++;
        top.elementSeen = false;
      } else if (top) {
        top.expectKey = true;
      }
      i++;
      continue;
    }
    childPrefix();
    while (i < n && !' \t\r\n,:{}[]"/'.includes(text[i]!)) i++;
    if (i < n && text[i] === '/' && text[i + 1] !== '/' && text[i + 1] !== '*') i++;
  }
  return out;
}

/** Index just past the closing quote of the JSON string starting at `start`, or -1. */
function endOfJsonString(text: string, start: number): number {
  for (let j = start + 1; j < text.length; j++) {
    const ch = text[j];
    if (ch === '\\') j++;
    else if (ch === '"') return j + 1;
    else if (ch === '\n') return -1;
  }
  return -1;
}

// ===========================================================================
// Model: MCP servers, hooks
// ===========================================================================

interface Located {
  value: string;
  path: Seg[];
}

interface KeyedValues {
  path: Seg[];
  values: Record<string, unknown>;
}

interface McpServer {
  name: string;
  path: Seg[];
  raw: Record<string, unknown>;
  command?: Located;
  args: Located[];
  env?: KeyedValues;
  headers: KeyedValues[];
  urls: Located[];
  disabled: boolean;
}

interface HookCommand {
  event: string;
  matcher?: string;
  command: string;
  path: Seg[];
  /** True for a settings command such as statusLine or apiKeyHelper rather than an event hook. */
  setting?: boolean;
}

/** Every MCP server the file declares, in any of the shapes the major clients use. */
function servers(doc: ConfigDoc): McpServer[] {
  if (doc.servers) return doc.servers;
  const out: McpServer[] = [];
  const data = doc.data;
  if (data) {
    addServerMap(out, data.mcpServers, ['mcpServers']);
    addServerMap(out, data.servers, ['servers']);
    addServerMap(out, data.mcp_servers, ['mcp_servers']);
    addServerMap(out, data.context_servers, ['context_servers']);
    if (isRecord(data.mcp)) addServerMap(out, data.mcp.servers, ['mcp', 'servers']);
    if (isRecord(data.projects)) {
      for (const [project, settings] of Object.entries(data.projects)) {
        if (isRecord(settings)) addServerMap(out, settings.mcpServers, ['projects', project, 'mcpServers']);
      }
    }
    if (Array.isArray(data.plugins)) {
      data.plugins.forEach((plugin: unknown, i) => {
        if (isRecord(plugin)) addServerMap(out, plugin.mcpServers, ['plugins', i, 'mcpServers']);
      });
    }
  }
  doc.servers = out;
  return out;
}

function activeServers(doc: ConfigDoc): McpServer[] {
  return servers(doc).filter((s) => !s.disabled);
}

function addServerMap(out: McpServer[], map: unknown, base: Seg[]): void {
  if (!isRecord(map)) return;
  for (const [name, raw] of Object.entries(map)) {
    if (out.length >= MAX_SERVERS) return;
    if (!isRecord(raw)) continue;
    const server = toServer(name, raw, [...base, name]);
    if (server) out.push(server);
  }
}

function toServer(name: string, raw: Record<string, unknown>, at: Seg[]): McpServer | undefined {
  let command: Located | undefined;
  let args: Located[] = [];
  let env: KeyedValues | undefined;
  if (typeof raw.command === 'string') {
    command = { value: raw.command, path: [...at, 'command'] };
  } else if (isRecord(raw.command) && typeof raw.command.path === 'string') {
    // Zed: "command": { "path": ..., "args": [...], "env": {...} }
    const base = [...at, 'command'];
    command = { value: raw.command.path, path: [...base, 'path'] };
    args = stringArgs(raw.command.args, [...base, 'args']);
    env = keyed(raw.command.env, [...base, 'env']);
  }
  if (Array.isArray(raw.args)) args = stringArgs(raw.args, [...at, 'args']);
  env ??= keyed(raw.env, [...at, 'env']);
  const headers = [keyed(raw.headers, [...at, 'headers']), keyed(raw.http_headers, [...at, 'http_headers'])].filter(
    (h): h is KeyedValues => h !== undefined,
  );
  if (typeof raw.bearer_token === 'string') headers.push({ path: at, values: { bearer_token: raw.bearer_token } });
  const urls: Located[] = [];
  for (const key of ['url', 'serverUrl', 'httpUrl']) {
    const value = raw[key];
    if (typeof value === 'string') urls.push({ value, path: [...at, key] });
  }
  if (!command && urls.length === 0) return undefined;
  const disabled = raw.disabled === true || raw.enabled === false;
  return { name, path: at, raw, args, headers, urls, disabled, ...(command ? { command } : {}), ...(env ? { env } : {}) };
}

function stringArgs(value: unknown, base: Seg[]): Located[] {
  if (!Array.isArray(value)) return [];
  const out: Located[] = [];
  value.forEach((arg: unknown, i) => {
    if (typeof arg === 'string') out.push({ value: arg, path: [...base, i] });
  });
  return out;
}

function keyed(value: unknown, at: Seg[]): KeyedValues | undefined {
  return isRecord(value) ? { path: at, values: value } : undefined;
}

/** Claude Code settings whose string value is a shell command the harness runs on its own, like a hook. */
const COMMAND_SETTINGS = ['apiKeyHelper', 'awsAuthRefresh', 'awsCredentialExport', 'otelHeadersHelper'] as const;

/**
 * Hook commands from settings.json ("hooks": {...}), plugin hooks.json (wrapped
 * or not) and marketplace entries, plus the statusLine and helper commands of
 * Claude Code settings, which also run automatically.
 */
function hooks(doc: ConfigDoc): HookCommand[] {
  if (doc.hooks) return doc.hooks;
  const out: HookCommand[] = [];
  const data = doc.data;
  if (data) {
    addHookMap(out, data.hooks, ['hooks']);
    addHookMap(out, data, []);
    if (Array.isArray(data.plugins)) {
      data.plugins.forEach((plugin: unknown, i) => {
        if (isRecord(plugin)) addHookMap(out, plugin.hooks, ['plugins', i, 'hooks']);
      });
    }
    if (doc.file.kind === 'agent-settings') addCommandSettings(out, data);
  }
  doc.hooks = out;
  return out;
}

function addCommandSettings(out: HookCommand[], data: Record<string, unknown>): void {
  const status = data.statusLine;
  if (isRecord(status) && (status.type === undefined || status.type === 'command') && typeof status.command === 'string' && status.command.trim()) {
    out.push({ event: 'statusLine', setting: true, command: status.command, path: ['statusLine', 'command'] });
  }
  for (const key of COMMAND_SETTINGS) {
    const command = data[key];
    if (typeof command === 'string' && command.trim()) out.push({ event: key, setting: true, command, path: [key] });
  }
}

function addHookMap(out: HookCommand[], map: unknown, base: Seg[]): void {
  if (!isRecord(map)) return;
  for (const [event, groups] of Object.entries(map)) {
    if (!Array.isArray(groups)) continue;
    groups.forEach((group: unknown, i) => {
      if (!isRecord(group) || !Array.isArray(group.hooks)) return;
      const matcher = typeof group.matcher === 'string' ? group.matcher : undefined;
      group.hooks.forEach((hook: unknown, j) => {
        if (out.length >= MAX_HOOKS || !isRecord(hook) || typeof hook.command !== 'string') return;
        if (hook.type !== undefined && hook.type !== 'command') return;
        out.push({ event, command: hook.command, path: [...base, event, i, 'hooks', j, 'command'], ...(matcher !== undefined ? { matcher } : {}) });
      });
    });
  }
}

function hookLabel(hook: HookCommand): string {
  const event = show(hook.event, 40);
  if (hook.setting) return `${event} setting`;
  return hook.matcher ? `${event} hook (matcher '${show(hook.matcher, 60)}')` : `${event} hook`;
}

function serverLabel(server: McpServer): string {
  return `Server '${show(server.name, 60)}'`;
}

// ===========================================================================
// Shell command helpers
// ===========================================================================

/** A word of a command line plus where it came from: -1 for the server's command, otherwise an index into its args. */
interface Tok {
  text: string;
  origin: number;
}

const ESCAPABLE = ' \t"\'\\$`|&;()<>';

/**
 * Splits a shell command into words and operators (|, &&, ;, $(, `, >, ...).
 * Handles quotes and backslash escapes, but keeps a backslash that does not
 * escape anything, so Windows paths survive. Bounded in input and output.
 */
function shellWords(command: string): string[] {
  const text = command.length > MAX_SCRIPT ? command.slice(0, MAX_SCRIPT) : command;
  const words: string[] = [];
  let word = '';
  let inWord = false;
  let quote = '';
  const flush = () => {
    if (inWord) words.push(word);
    word = '';
    inWord = false;
  };
  for (let i = 0; i < text.length && words.length < MAX_WORDS; i++) {
    const ch = text[i]!;
    const next = text[i + 1] ?? '';
    if (quote) {
      if (ch === quote) quote = '';
      else if (ch === '\\' && quote === '"' && next !== '' && '"\\$`'.includes(next)) {
        word += next;
        i++;
      } else word += ch;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      inWord = true;
    } else if (ch === '\\' && next !== '' && ESCAPABLE.includes(next)) {
      word += next;
      inWord = true;
      i++;
    } else if (ch === ' ' || ch === '\t' || ch === '\r') {
      flush();
    } else if (ch === '\n') {
      flush();
      words.push(';');
    } else if (ch === '$' && next === '(') {
      flush();
      words.push('$(');
      i++;
    } else if ('|&;()<>`'.includes(ch)) {
      flush();
      const pair = ch + next;
      if (pair === '||' || pair === '&&' || pair === '>>' || pair === '|&' || pair === '<(') {
        words.push(pair);
        i++;
      } else words.push(ch);
    } else {
      word += ch;
      inWord = true;
    }
  }
  flush();
  return words;
}

function splitTok(tok: Tok): Tok[] {
  return shellWords(tok.text).map((text) => ({ text, origin: tok.origin }));
}

/** Lowercased executable name without directory or Windows extension: "C:\\nodejs\\npx.cmd" -> "npx". */
function programName(token: string): string {
  const slash = Math.max(token.lastIndexOf('/'), token.lastIndexOf('\\'));
  return token
    .slice(slash + 1)
    .toLowerCase()
    .replace(/\.(?:exe|cmd|bat|com|ps1)$/, '');
}

const POSIX_SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'fish', 'ash']);
const PS_VALUE_FLAGS = new Set([
  'executionpolicy', 'ex', 'ep', 'windowstyle', 'w', 'workingdirectory', 'wd', 'configurationname', 'config',
  'settingsfile', 'settings', 'inputformat', 'inp', 'if', 'outputformat', 'o', 'of', 'version', 'v', 'psconsolefile', 'custompipename',
]);
/** A path to a Windows executable that contains spaces, used as a whole command. */
const WINDOWS_EXE_PATH = /^[A-Za-z]:[\\/][^"'\n]{0,500}\.(?:exe|cmd|bat|com)$/i;

interface InlineScript {
  shell: string;
  script: string;
  origin: number;
  encoded: boolean;
  /** The inline script split into words, for further analysis. Empty when it could not be decoded. */
  words: Tok[];
}

/** Recognises `bash -c '...'`, `cmd /c ...`, `powershell -Command ...` and `-EncodedCommand`. */
function inlineScript(toks: readonly Tok[]): InlineScript | undefined {
  const head = toks[0];
  if (!head) return undefined;
  const shell = programName(head.text);
  if (POSIX_SHELLS.has(shell)) return posixInline(shell, toks);
  if (shell === 'cmd') return cmdInline(toks);
  if (shell === 'powershell' || shell === 'pwsh') return powershellInline(shell, toks);
  return undefined;
}

function posixInline(shell: string, toks: readonly Tok[]): InlineScript | undefined {
  for (let i = 1; i < toks.length; i++) {
    const t = toks[i]!.text;
    if (t.startsWith('--')) continue;
    if (!t.startsWith('-') && !t.startsWith('+')) return undefined;
    if (/^-[A-Za-z]{0,10}c[A-Za-z]{0,10}$/.test(t)) {
      const body = toks[i + 1];
      return body ? { shell, script: body.text, origin: body.origin, encoded: false, words: splitTok(body) } : undefined;
    }
    if (t === '-o' || t === '+o') i++;
  }
  return undefined;
}

function cmdInline(toks: readonly Tok[]): InlineScript | undefined {
  for (let i = 1; i < toks.length; i++) {
    const t = toks[i]!.text;
    if (/^\/[ck]$/i.test(t)) {
      const rest = toks.slice(i + 1);
      const first = rest[0];
      if (!first) return undefined;
      return { shell: 'cmd', script: rest.map((r) => r.text).join(' '), origin: first.origin, encoded: false, words: rest.flatMap(splitTok) };
    }
    if (!t.startsWith('/')) return undefined;
  }
  return undefined;
}

function powershellInline(shell: string, toks: readonly Tok[]): InlineScript | undefined {
  for (let i = 1; i < toks.length; i++) {
    const t = toks[i]!.text;
    if (!/^[-/]/.test(t)) return undefined;
    const name = t.slice(1).toLowerCase();
    if (name === 'e' || name === 'ec' || (name.length >= 3 && 'encodedcommand'.startsWith(name))) {
      const body = toks[i + 1];
      if (!body) return undefined;
      const decoded = decodePowerShell(body.text);
      return {
        shell,
        script: decoded ?? body.text,
        origin: body.origin,
        encoded: true,
        words: decoded ? shellWords(decoded).map((text) => ({ text, origin: body.origin })) : [],
      };
    }
    if (name === 'c' || (name.length >= 3 && 'command'.startsWith(name))) {
      const rest = toks.slice(i + 1);
      const first = rest[0];
      if (!first) return undefined;
      return { shell, script: rest.map((r) => r.text).join(' '), origin: first.origin, encoded: false, words: rest.flatMap(splitTok) };
    }
    if (name === 'f' || (name.length >= 2 && 'file'.startsWith(name))) return undefined;
    if (PS_VALUE_FLAGS.has(name)) i++;
  }
  return undefined;
}

/** PowerShell -EncodedCommand is base64 of UTF-16LE text. */
function decodePowerShell(b64: string): string | undefined {
  if (b64.length > MAX_SCRIPT * 3 || !/^[A-Za-z0-9+/]{8,}={0,2}$/.test(b64)) return undefined;
  const decoded = Buffer.from(b64, 'base64').toString('utf16le');
  return decoded.includes('\u0000') || !decoded.trim() ? undefined : decoded;
}

/** True when an inline script is a single plain command with no pipes, chaining, redirection or substitution. */
function isSimpleScript(script: string): boolean {
  return !/[|&;<>`\n\r]|\$\(/.test(script);
}

/** The server's command line as words. Splits "command": "npx -y pkg" when there are no args. */
function baseTokens(server: McpServer): Tok[] {
  if (!server.command) return [];
  const command = server.command.value;
  if (server.args.length === 0 && /\s/.test(command.trim()) && !WINDOWS_EXE_PATH.test(command.trim())) {
    return shellWords(command).map((text) => ({ text, origin: -1 }));
  }
  return [{ text: command, origin: -1 }, ...server.args.map((a, i) => ({ text: a.value, origin: i }))];
}

const ENV_ASSIGN = /^[A-Za-z_][A-Za-z0-9_]{0,100}=/;

/** Drops a leading `env [-i] [VAR=value ...]` so the real program comes first. */
function stripEnv(toks: Tok[]): Tok[] {
  if (programName(toks[0]?.text ?? '') !== 'env') return toks;
  let i = 1;
  while (i < toks.length && (toks[i]!.text.startsWith('-') || ENV_ASSIGN.test(toks[i]!.text))) i++;
  return toks.slice(i);
}

/** Strips wrappers that just launch another program: env VAR=x, cmd /c, and simple `sh -c` one-liners. */
function unwrap(toks: Tok[], depth = 0): Tok[] {
  if (toks.length === 0 || depth > 3) return toks;
  const stripped = stripEnv(toks);
  if (stripped !== toks) return unwrap(stripped, depth + 1);
  const inline = inlineScript(toks);
  if (inline && !inline.encoded && isSimpleScript(inline.script) && inline.words.length > 0) return unwrap(inline.words, depth + 1);
  return toks;
}

/** The effective launch command, plus the words of any non-trivial inline script it runs. */
function launchLines(server: McpServer): Tok[][] {
  const base = unwrap(baseTokens(server));
  const lines = [base];
  const inline = inlineScript(base);
  if (inline && inline.words.length > 0) lines.push(inline.words);
  return lines;
}

function tokPath(server: McpServer, tok: Tok): Seg[] {
  if (tok.origin < 0) return server.command?.path ?? server.path;
  return server.args[tok.origin]?.path ?? server.path;
}

const SEPARATORS = new Set(['|', '||', '&', '&&', ';', '(', ')', '$(', '`', '<(', '|&']);
const REDIRECTS = new Set(['>', '>>', '<']);
const PREFIX_COMMANDS = new Set(['sudo', 'exec', 'nohup', 'time', 'env', 'command', 'xargs', 'nice', 'doas', 'start']);
const INTERPRETERS = new Set([
  'bash', 'sh', 'zsh', 'dash', 'ksh', 'fish', 'ash', 'python', 'python3', 'python2', 'py', 'pythonw', 'node', 'nodejs', 'deno', 'bun',
  'tsx', 'ts-node', 'ruby', 'perl', 'php', 'pwsh', 'powershell', 'source', '.', 'osascript', 'cscript', 'wscript', 'java',
]);
const INLINE_CODE_FLAGS = new Set(['-c', '-e', '-m', '--eval', '-p', '--print', '-r', '--require']);

/** Words that name a program or script being executed: the head of each command, and the script handed to an interpreter. */
function executedWords(words: readonly Tok[]): Tok[] {
  const out: Tok[] = [];
  let expectCommand = true;
  let interpreter = '';
  for (let i = 0; i < words.length; i++) {
    const w = words[i]!;
    const t = w.text;
    if (SEPARATORS.has(t)) {
      expectCommand = true;
      interpreter = '';
      continue;
    }
    if (REDIRECTS.has(t)) {
      i++;
      continue;
    }
    if (expectCommand) {
      if (PREFIX_COMMANDS.has(t) || ENV_ASSIGN.test(t)) continue;
      out.push(w);
      expectCommand = false;
      const prog = programName(t);
      interpreter = INTERPRETERS.has(prog) ? prog : '';
      continue;
    }
    if (!interpreter) continue;
    if (interpreter === 'pwsh' || interpreter === 'powershell') {
      if (/^[-/]f(?:ile)?$/i.test(t)) {
        const next = words[i + 1];
        if (next) out.push(next);
        interpreter = '';
        i++;
      } else if (/^[-/](?:c|com|comm|comma|comman|command|e|ec|enc[a-z]{0,11})$/i.test(t)) {
        interpreter = '';
      }
      continue;
    }
    if (t === 'run' && (interpreter === 'deno' || interpreter === 'bun')) continue;
    if (INLINE_CODE_FLAGS.has(t)) {
      interpreter = '';
      continue;
    }
    if (t.startsWith('-')) continue;
    out.push(w);
    interpreter = '';
  }
  return out;
}

// ===========================================================================
// Package runners (TM-SUP-001)
// ===========================================================================

interface PackageRun {
  runner: string;
  ecosystem: 'npm' | 'pypi' | 'docker';
  tok: Tok;
  spec: string;
}

type PinProblem =
  | { kind: 'missing'; name: string }
  | { kind: 'loose'; name: string; version: string }
  | { kind: 'git' }
  | { kind: 'url' }
  | { kind: 'latest'; name: string };

/** Finds packages fetched by npx, pnpm/yarn dlx, bunx, npm exec, uvx, pipx run and docker run. */
function packageRuns(toks: readonly Tok[]): PackageRun[] {
  const head = toks[0];
  if (!head) return [];
  const prog = programName(head.text);
  const rest = toks.slice(1);
  const sub = rest[0]?.text;
  switch (prog) {
    case 'npx':
      return npmLike('npx', rest);
    case 'pnpx':
      return npmLike('pnpm dlx', rest);
    case 'bunx':
      return npmLike('bunx', rest);
    case 'pnpm':
      return sub === 'dlx' ? npmLike('pnpm dlx', rest.slice(1)) : [];
    case 'yarn':
      return sub === 'dlx' ? npmLike('yarn dlx', rest.slice(1)) : [];
    case 'bun':
      return sub === 'x' ? npmLike('bunx', rest.slice(1)) : [];
    case 'npm':
      return sub === 'exec' || sub === 'x' ? npmLike('npm exec', rest.slice(1)) : [];
    case 'uvx':
      return pyLike('uvx', rest);
    case 'uv':
      return sub === 'tool' && rest[1]?.text === 'run' ? pyLike('uvx', rest.slice(2)) : [];
    case 'pipx':
      return sub === 'run' ? pyLike('pipx run', rest.slice(1)) : [];
    case 'docker':
    case 'podman':
    case 'nerdctl': {
      if (sub === 'run') return dockerRun(prog, rest.slice(1));
      if (sub === 'container' && rest[1]?.text === 'run') return dockerRun(prog, rest.slice(2));
      return [];
    }
    default:
      return [];
  }
}

const NPM_VALUE_FLAGS = new Set(['--registry', '--cache', '--prefix', '--userconfig', '--node-options', '-w', '--workspace', '--node-arg', '-n']);

function npmLike(runner: string, toks: readonly Tok[]): PackageRun[] {
  const packages: Tok[] = [];
  for (let i = 0; i < toks.length; i++) {
    const tok = toks[i]!;
    const t = tok.text;
    if (t === '--') {
      const next = toks[i + 1];
      if (next && packages.length === 0) packages.push(next);
      break;
    }
    if (t.startsWith('--package=')) {
      packages.push({ text: t.slice('--package='.length), origin: tok.origin });
      continue;
    }
    if (t === '-p' || t === '--package') {
      const next = toks[++i];
      if (next) packages.push(next);
      continue;
    }
    if (t === '-c' || t === '--call') return packages.map((p) => ({ runner, ecosystem: 'npm', tok: p, spec: p.text }));
    if (t.startsWith('-')) {
      if (NPM_VALUE_FLAGS.has(t)) i++;
      continue;
    }
    if (packages.length === 0) packages.push(tok);
    break;
  }
  return packages.map((p) => ({ runner, ecosystem: 'npm', tok: p, spec: p.text }));
}

const PY_VALUE_FLAGS = new Set([
  '--with', '--with-editable', '--with-requirements', '--python', '-p', '--index-url', '--extra-index-url', '--index', '--default-index',
  '--directory', '--env-file', '--constraints', '--overrides', '--pip-args', '--cache-dir', '--find-links', '-f', '-i',
]);

function pyLike(runner: string, toks: readonly Tok[]): PackageRun[] {
  let from: Tok | undefined;
  for (let i = 0; i < toks.length; i++) {
    const tok = toks[i]!;
    const t = tok.text;
    if (t === '--from' || t === '--spec') {
      from = toks[++i];
      continue;
    }
    const eq = /^--(?:from|spec)=(.{1,2000})$/.exec(t);
    if (eq) {
      from = { text: eq[1]!, origin: tok.origin };
      continue;
    }
    if (t === '--') continue;
    if (t.startsWith('-')) {
      if (PY_VALUE_FLAGS.has(t)) i++;
      continue;
    }
    const spec = from ?? tok;
    return [{ runner, ecosystem: 'pypi', tok: spec, spec: spec.text }];
  }
  return from ? [{ runner, ecosystem: 'pypi', tok: from, spec: from.text }] : [];
}

const DOCKER_VALUE_LONG = new Set([
  '--env', '--env-file', '--volume', '--mount', '--name', '--network', '--net', '--publish', '--workdir', '--user', '--entrypoint',
  '--platform', '--label', '--label-file', '--memory', '--memory-swap', '--memory-reservation', '--cpus', '--cpu-shares', '--cpuset-cpus',
  '--add-host', '--cap-add', '--cap-drop', '--device', '--dns', '--dns-search', '--dns-option', '--hostname', '--ipc', '--pid',
  '--restart', '--runtime', '--security-opt', '--shm-size', '--tmpfs', '--ulimit', '--log-driver', '--log-opt', '--pull', '--gpus',
  '--expose', '--stop-signal', '--stop-timeout', '--health-cmd', '--health-interval', '--health-retries', '--health-timeout',
  '--cidfile', '--volumes-from', '--link', '--group-add', '--attach', '--cgroupns', '--userns', '--uts', '--isolation',
  '--network-alias', '--ip', '--ip6', '--mac-address', '--annotation', '--detach-keys', '--domainname', '--storage-opt', '--sysctl',
  '--device-cgroup-rule', '--blkio-weight', '--oom-score-adj', '--pids-limit', '--cgroup-parent',
]);
const DOCKER_VALUE_SHORT = new Set(['e', 'v', 'p', 'w', 'u', 'l', 'm', 'h', 'a', 'c']);

function dockerRun(prog: string, toks: readonly Tok[]): PackageRun[] {
  for (let i = 0; i < toks.length; i++) {
    const tok = toks[i]!;
    const t = tok.text;
    if (t.startsWith('--')) {
      if (!t.includes('=') && DOCKER_VALUE_LONG.has(t)) i++;
      continue;
    }
    if (t.startsWith('-') && t.length > 1) {
      if (!t.includes('=') && DOCKER_VALUE_SHORT.has(t[t.length - 1]!)) i++;
      continue;
    }
    return [{ runner: `${prog} run`, ecosystem: 'docker', tok, spec: t }];
  }
  return [];
}

const EXACT_SEMVER = /^[=v]?\d{1,9}\.\d{1,9}\.\d{1,9}(?:-[0-9A-Za-z.-]{1,64})?(?:\+[0-9A-Za-z.-]{1,64})?$/;
const LOCAL_SPEC = /^(?:\.{1,2}(?:[\\/]|$)|[\\/]|~|[A-Za-z]:[\\/]|file:|link:|workspace:)/i;
const COMMIT_REF = /^[0-9a-f]{7,40}$/i;

function pinProblem(run: PackageRun): PinProblem | undefined {
  const spec = run.spec.trim();
  if (!spec || isPlaceholder(spec) || LOCAL_SPEC.test(spec)) return undefined;
  if (run.ecosystem === 'npm') return npmPinProblem(spec);
  if (run.ecosystem === 'pypi') return pyPinProblem(spec);
  return dockerPinProblem(spec);
}

function npmPinProblem(spec: string): PinProblem | undefined {
  if (/^(?:git\+|git:|github:|gitlab:|bitbucket:|gist:)/i.test(spec) || /^[A-Za-z0-9][\w.-]{0,100}\/[\w.-]{1,100}(?:#\S{0,200})?$/.test(spec)) {
    const hash = spec.lastIndexOf('#');
    return hash !== -1 && COMMIT_REF.test(spec.slice(hash + 1)) ? undefined : { kind: 'git' };
  }
  if (/^https?:\/\//i.test(spec)) return { kind: 'url' };
  if (/^npm:/i.test(spec)) return npmPinProblem(spec.slice(4));
  const at = spec.indexOf('@', spec.startsWith('@') ? 1 : 0);
  if (at <= 0) return { kind: 'missing', name: spec };
  const name = spec.slice(0, at);
  const version = spec.slice(at + 1);
  if (EXACT_SEMVER.test(version)) return undefined;
  return version ? { kind: 'loose', name, version } : { kind: 'missing', name };
}

function pyPinProblem(spec: string): PinProblem | undefined {
  if (/^git\+/i.test(spec)) {
    const ref = /@([0-9A-Za-z._-]{1,100})(?:#\S{0,200})?$/.exec(spec.replace(/^git\+[a-z]{1,10}:\/\/[^@/]{0,200}@/i, ''));
    return ref && COMMIT_REF.test(ref[1]!) ? undefined : { kind: 'git' };
  }
  if (/^https?:\/\//i.test(spec)) return { kind: 'url' };
  const name = /^[A-Za-z0-9][A-Za-z0-9._-]{0,200}(?:\[[^\]]{0,200}\])?/.exec(spec)?.[0];
  if (!name) return undefined;
  const rest = spec.slice(name.length).trim();
  if (!rest) return { kind: 'missing', name };
  if (/^(?:===?|@)\s{0,3}v?\d[0-9A-Za-z.+!-]{0,64}$/.test(rest) && !rest.includes('*')) return undefined;
  return { kind: 'loose', name, version: rest.replace(/^@/, '') };
}

function dockerPinProblem(image: string): PinProblem | undefined {
  if (/@sha256:[0-9a-f]{64}$/i.test(image)) return undefined;
  const lastSlash = image.lastIndexOf('/');
  const colon = image.indexOf(':', lastSlash + 1);
  if (colon === -1) return { kind: 'missing', name: image };
  if (image.slice(colon + 1) === 'latest') return { kind: 'latest', name: image };
  return undefined;
}

function pinMessage(server: McpServer, run: PackageRun, problem: PinProblem): string {
  const who = serverLabel(server);
  const tail = 'a malicious update would run on next start.';
  const what = run.ecosystem === 'docker' ? `${run.runner.split(' ')[0]} image` : `${run.runner} package`;
  switch (problem.kind) {
    case 'missing':
      return run.ecosystem === 'docker'
        ? `${who} runs ${what} '${show(problem.name)}' without a tag or digest; ${tail}`
        : `${who} runs ${what} '${show(problem.name)}' without a pinned version; ${tail}`;
    case 'loose':
      return `${who} runs ${what} '${show(problem.name)}' at '${show(problem.version, 40)}', which is not an exact version; ${tail}`;
    case 'latest':
      return `${who} runs ${what} '${show(problem.name)}' with the moving ':latest' tag and no digest; ${tail}`;
    case 'git':
      return `${who} runs ${what} from git '${show(run.spec)}' without a pinned commit; ${tail}`;
    case 'url':
      return `${who} runs ${what} from the URL '${show(maskUrlString(run.spec))}', whose content can change at any time; ${tail}`;
  }
}

// ===========================================================================
// Paths, URLs, secrets
// ===========================================================================

/** Forward slashes, no trailing slash, lowercased for Windows drive paths. */
function normPath(p: string): string {
  let out = p.replace(/\\/g, '/').replace(/\/{2,}/g, '/');
  if (out.length > 1 && out.endsWith('/')) out = out.slice(0, -1);
  if (/^[A-Za-z]:/.test(out)) out = out.toLowerCase();
  return out;
}

function samePath(a: string, b: string): boolean {
  return isUnder(a, b) && isUnder(b, a);
}

function isUnder(p: string, root: string): boolean {
  const a = /^[a-z]:/i.test(p) ? p.toLowerCase() : p;
  const b = /^[a-z]:/i.test(root) ? root.toLowerCase() : root;
  return a === b || a.startsWith(b.endsWith('/') ? b : `${b}/`);
}

function home(): string {
  return normPath(homeDir());
}

/** Expands ~, $HOME, ${HOME}, %USERPROFILE% and $env:USERPROFILE at the start of a path. */
function expandHomeVars(p: string): string {
  const m = /^(?:~|\$HOME|\$\{HOME\}|%USERPROFILE%|\$env:USERPROFILE)(?=$|[\\/])/i.exec(p);
  return m ? home() + p.slice(m[0].length) : p;
}

const TEMP_PATTERNS: readonly RegExp[] = [
  /^(?:\/private)?(?:\/var)?\/tmp\//i,
  /^\/dev\/shm\//,
  /^(?:\/private)?\/var\/folders\/[^/]{1,10}\/[^/]{1,64}\/T\//,
  /^(?:\$\{?TMPDIR\}?|\$\{?TMP\}?|\$\{?TEMP\}?|%TEMP%|%TMP%|\$env:TEMP|\$env:TMP)\//i,
  /\/appdata\/local\/temp\//i,
  /^[a-z]:\/windows\/temp\//i,
];
const DOWNLOAD_PATTERNS: readonly RegExp[] = [
  /^(?:~|\$\{?HOME\}?|%USERPROFILE%|\$env:USERPROFILE)\/downloads\//i,
  /^\/(?:users|home)\/[^/]{1,64}\/downloads\//i,
  /^[a-z]:\/users\/[^/]{1,64}\/downloads\//i,
];

/** 'temp' or 'downloads' when an executable path lives in a scratch folder. */
function scratchFolder(token: string): 'temp' | 'downloads' | undefined {
  const p = token.replace(/\\/g, '/');
  if (TEMP_PATTERNS.some((re) => re.test(p))) return 'temp';
  if (DOWNLOAD_PATTERNS.some((re) => re.test(p))) return 'downloads';
  const h = home();
  if (h.length > 1 && isUnder(normPath(p), `${h}/Downloads`)) return 'downloads';
  return undefined;
}

function isPlaceholder(s: string): boolean {
  return (
    /\$\{[^}\n]{1,200}\}/.test(s) ||
    /^\$[A-Za-z_][A-Za-z0-9_]{0,100}$/.test(s) ||
    /%[A-Za-z_][A-Za-z0-9_]{0,100}%/.test(s) ||
    /\{\{[^}\n]{1,200}\}\}/.test(s) ||
    /^\$env:[A-Za-z_]/i.test(s) ||
    /^<[^>\n]{1,200}>$/.test(s)
  );
}

type HostClass = 'loopback' | 'private' | 'public';

function ipv4(host: string): number[] | undefined {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!m) return undefined;
  const parts = m.slice(1).map(Number);
  return parts.every((p) => p <= 255) ? parts : undefined;
}

function hostClass(hostname: string): HostClass {
  const h = hostname.toLowerCase().replace(/^\[/, '').replace(/\]$/, '');
  if (h === 'localhost' || h.endsWith('.localhost') || h === '::1' || h === '0.0.0.0' || h === 'host.docker.internal') return 'loopback';
  const v4 = ipv4(h);
  if (v4) {
    const [a = 0, b = 0] = v4;
    if (a === 127) return 'loopback';
    if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127)) {
      return 'private';
    }
    return 'public';
  }
  if (h.includes(':')) return /^(?:f[cd]|fe80)/.test(h) ? 'private' : 'public';
  if (!h.includes('.') || /\.(?:local|lan|internal|intranet|home\.arpa|corp|home)$/.test(h)) return 'private';
  return 'public';
}

const TUNNEL_HOSTS: readonly (readonly [string, string])[] = [
  ['ngrok.io', 'ngrok'], ['ngrok-free.app', 'ngrok'], ['ngrok.app', 'ngrok'], ['ngrok-free.dev', 'ngrok'], ['ngrok.dev', 'ngrok'],
  ['trycloudflare.com', 'Cloudflare quick tunnel'], ['loca.lt', 'localtunnel'], ['localtunnel.me', 'localtunnel'],
  ['serveo.net', 'Serveo'], ['serveousercontent.com', 'Serveo'], ['localhost.run', 'localhost.run'], ['lhr.life', 'localhost.run'],
  ['lhr.rocks', 'localhost.run'], ['pinggy.io', 'Pinggy'], ['pinggy.link', 'Pinggy'], ['pinggy.online', 'Pinggy'], ['bore.pub', 'bore'],
  ['devtunnels.ms', 'Dev Tunnels'], ['tunnelto.dev', 'tunnelto'], ['localxpose.io', 'LocalXpose'], ['loclx.io', 'LocalXpose'],
  ['telebit.io', 'Telebit'], ['telebit.cloud', 'Telebit'],
];

function tunnelProvider(hostname: string): string | undefined {
  const h = hostname.toLowerCase();
  return TUNNEL_HOSTS.find(([suffix]) => h === suffix || h.endsWith(`.${suffix}`))?.[1];
}

function parseUrl(raw: string): URL | undefined {
  try {
    const url = new URL(raw.trim());
    return /[${}%]/.test(url.hostname) ? undefined : url;
  } catch {
    return undefined;
  }
}

/** Scheme, host and path only: never userinfo or query, which may carry credentials. */
function shownUrl(url: URL): string {
  return truncate(`${url.protocol}//${url.host}${url.pathname === '/' ? '' : url.pathname}`, 100);
}

/** A URL or URL-like spec safe to show: userinfo and query masked. Shorthands such as github:user/repo stay as written. */
function maskUrlString(raw: string): string {
  const url = /^[a-z][a-z0-9+.-]{0,20}:\/\//i.test(raw) ? parseUrl(raw) : undefined;
  return url ? shownUrl(url) : raw.replace(/\/\/[^/@\s]{1,200}@/, '//****@').replace(/\?[^\n]{0,2000}$/, '?…');
}

const CREDENTIAL_PARAMS = new Set([
  'token', 'accesstoken', 'authtoken', 'auth', 'key', 'apikey', 'xapikey', 'secret', 'clientsecret', 'password', 'passwd', 'pwd',
  'pass', 'sig', 'signature', 'sessiontoken', 'bearertoken', 'privatekey',
]);

function isCredentialParam(name: string): boolean {
  const n = name.toLowerCase().replace(/[-_.]/g, '');
  return CREDENTIAL_PARAMS.has(n) || n.endsWith('token') || n.endsWith('apikey') || n.endsWith('secret') || n.endsWith('password');
}

/** Remote endpoints a server talks to: its url fields, plus URL arguments such as those given to mcp-remote. */
function endpoints(server: McpServer): Located[] {
  const out = [...server.urls];
  for (const arg of server.args) {
    if (/^(?:https?|wss?):\/\//i.test(arg.value)) out.push(arg);
    else {
      const m = /^--?[A-Za-z][\w-]{0,40}=((?:https?|wss?):\/\/\S{1,2000})$/i.exec(arg.value);
      if (m) out.push({ value: m[1]!, path: arg.path });
    }
  }
  return out;
}

const SECRET_WORDS = new Set([
  'KEY', 'APIKEY', 'TOKEN', 'SECRET', 'PASSWORD', 'PASSWD', 'PASSPHRASE', 'PWD', 'PAT', 'AUTH', 'AUTHORIZATION', 'CREDENTIAL',
  'CREDENTIALS', 'BEARER', 'COOKIE', 'PASS',
]);
const NOT_SECRET_WORDS = new Set([
  'FILE', 'PATH', 'DIR', 'URL', 'URI', 'ENDPOINT', 'HOST', 'NAME', 'ID', 'TYPE', 'MODE', 'LIMIT', 'COUNT', 'TIMEOUT', 'TTL', 'EXPIRY',
  'EXPIRES', 'VAR', 'ENV', 'PREFIX', 'FORMAT', 'REGION', 'LENGTH', 'SIZE', 'MAX', 'MIN', 'PORT', 'USER', 'USERNAME', 'EMAIL', 'ACCOUNT',
  'PROJECT', 'ORG', 'DOMAIN', 'SCOPE', 'SCOPES', 'METHOD', 'PROVIDER', 'STRATEGY', 'ENABLED', 'DISABLED', 'REQUIRED', 'LOCATION',
  'ALGORITHM', 'ALG', 'PUBLIC', 'PUBLISHABLE', 'ISSUER', 'AUDIENCE', 'HEADER', 'FIELD', 'ROTATION', 'THROUGH',
]);

function keyWords(key: string): string[] {
  return key
    .slice(0, 200)
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .toUpperCase()
    .split(/[^A-Z0-9]+/)
    .filter(Boolean);
}

function isSecretName(key: string): boolean {
  const words = keyWords(key);
  return words.some((w) => SECRET_WORDS.has(w)) && !words.some((w) => NOT_SECRET_WORDS.has(w));
}

const DUMMY_VALUES: readonly RegExp[] = [
  /^(?:changeme|placeholder|replace[_-]?me|example|sample|dummy|test(?:ing)?|todo|tbd|secret|password|token|api[_-]?key|redacted|none|null|undefined|true|false)$/i,
  /^your[\w.-]{0,80}$/i,
  /your[_-](?:api[_-])?(?:key|token|secret|password)/i,
  /[_-]here$/i,
  /^x{3}/i,
  /^\*{3}/,
];

/** A literal that could plausibly be a credential: long enough, no spaces, not a reference, path, URL, number or obvious dummy. */
function looksLikeLiteralSecret(value: string): boolean {
  const s = value.trim();
  if (s.length < 8 || s.length > 4096 || /\s/.test(s) || isPlaceholder(s)) return false;
  if (/^(?:[~./\\]|[A-Za-z]:[\\/])/.test(s) || /^[a-z][a-z0-9+.-]{1,20}:\/\//i.test(s) || /^\d+$/.test(s)) return false;
  if (/^(.)\1+$/.test(s)) return false;
  return !DUMMY_VALUES.some((re) => re.test(s));
}

function stripAuthScheme(value: string): string {
  return value.replace(/^(?:Bearer|Basic|Token|Bot|ApiKey)\s{1,10}/i, '');
}

function maskValue(value: string): string {
  return value.length <= 6 ? '****' : `${value.slice(0, 2)}****`;
}

// ===========================================================================
// Scripts inside configs, checked with the dangerous-code rules
// ===========================================================================

interface ScriptHit {
  ruleId?: string;
  title?: string;
  message: string;
  severity: Severity;
}

/** Fallback signals for when the dangerous-code rules report nothing (or are not loaded). */
const RED_FLAGS: readonly { regex: RegExp; severity: Severity; message: string }[] = [
  {
    regex: /\b(?:curl|wget)\b[^|\n]{0,300}\|\s{0,10}(?:sudo\s{1,10})?(?:ba|z|da|k)?sh\b/i,
    severity: 'high',
    message: 'pipes a download straight into a shell',
  },
  {
    regex: /\b(?:irm|iwr|Invoke-RestMethod|Invoke-WebRequest)\b[^|\n]{0,300}\|\s{0,10}(?:iex|Invoke-Expression)\b/i,
    severity: 'high',
    message: 'pipes a download into Invoke-Expression',
  },
  {
    regex: /\b(?:iex|Invoke-Expression)\b[^\n]{0,40}\b(?:irm|iwr|Invoke-RestMethod|Invoke-WebRequest|DownloadString)\b/i,
    severity: 'high',
    message: 'runs downloaded code with Invoke-Expression',
  },
  {
    regex: /\bbase64\s{1,10}(?:-d|--decode|-D)\b|\batob\s{0,5}\(|\bBuffer\.from\s{0,5}\([^)\n]{0,2000}['"]base64['"]|FromBase64String|\bb64decode\b/i,
    severity: 'high',
    message: 'decodes base64 data, a common way to hide a payload',
  },
  {
    regex: /\bxattr\b[^\n]{0,60}com\.apple\.quarantine/i,
    severity: 'high',
    message: 'removes the macOS quarantine flag so a downloaded binary runs unchecked',
  },
];

function analyzeScript(script: string, file: ScanFile, label: string, ext: string): ScriptHit[] {
  const content = script.length > MAX_SCRIPT ? script.slice(0, MAX_SCRIPT) : script;
  const synthetic: ScanFile = {
    path: `${file.path}#${label}${ext}`,
    displayPath: `${file.displayPath}#${label}${ext}`,
    kind: 'script',
    content,
    ...(file.target !== undefined ? { target: file.target } : {}),
  };
  const hits: ScriptHit[] = [];
  const seen = new Set<string>();
  for (const rule of codeRules) {
    if (!rule.kinds.includes('script')) continue;
    let matches: RuleMatch[];
    try {
      matches = rule.check(synthetic);
    } catch {
      continue;
    }
    for (const m of matches) {
      const key = `${rule.id}|${m.message}`;
      if (seen.has(key)) continue;
      seen.add(key);
      hits.push({ ruleId: rule.id, title: rule.title, message: m.message, severity: m.severity ?? rule.severity });
      if (hits.length >= MAX_INNER_HITS) return hits;
    }
  }
  if (hits.length > 0) return hits;
  for (const flag of RED_FLAGS) {
    if (flag.regex.test(content)) hits.push({ message: flag.message, severity: flag.severity });
  }
  return hits;
}

/** "<context> triggers TM-EXEC-001 (Title): inner message" or, for built-in signals, "<context> <signal>". */
function hitMessage(context: string, hit: ScriptHit): string {
  return hit.ruleId ? `${context} triggers ${hit.ruleId} (${hit.title ?? ''}): ${show(hit.message, 160)}` : `${context} ${hit.message}`;
}

function maxSeverity(a: Severity, b: Severity): Severity {
  return SEVERITY_RANK[a] >= SEVERITY_RANK[b] ? a : b;
}

// ===========================================================================
// Settings scope and misc helpers
// ===========================================================================

type SettingsScope = 'project' | 'local' | 'user' | 'managed' | 'other';

/**
 * Project settings live in <repo>/.claude/settings.json and arrive with a
 * clone. <repo>/.claude/settings.local.json is personal: Claude Code writes the
 * user's own approvals there and keeps it out of git. User settings live in
 * ~/.claude/.
 */
function settingsScope(file: ScanFile): SettingsScope {
  const p = normPath(file.path);
  const base = path.posix.basename(p).toLowerCase();
  const dir = path.posix.dirname(p);
  if (base.startsWith('managed-settings')) return 'managed';
  if (!base.startsWith('settings')) return 'other';
  if (samePath(dir, `${home()}/.claude`)) return 'user';
  if (path.posix.basename(dir).toLowerCase() !== '.claude') return 'other';
  return base === 'settings.local.json' ? 'local' : 'project';
}

const PROJECT_SUFFIX = '; this is a project settings file, so a cloned repository can grant itself these permissions';

/** Directories whose scripts count as part of what is being scanned: the scan root and the config's own project or plugin. */
function knownRoots(file: ScanFile): string[] {
  const roots: string[] = [];
  const abs = normPath(file.path);
  const shown = normPath(file.displayPath);
  if (!/^(?:\/|[a-z]:)/i.test(shown) && abs.toLowerCase().endsWith(`/${shown.toLowerCase()}`)) {
    roots.push(abs.slice(0, abs.length - shown.length - 1));
  }
  let dir = path.posix.dirname(abs);
  if (!samePath(dir, `${home()}/.claude`) && /^(?:\.claude|hooks|\.claude-plugin|\.codex|\.gemini|\.cursor|\.vscode)$/i.test(path.posix.basename(dir))) {
    dir = path.posix.dirname(dir);
  }
  roots.push(dir);
  return roots.filter((r) => r.length > 1);
}

const SYSTEM_DIRS: readonly RegExp[] = [
  /^\/(?:usr|bin|sbin|opt\/homebrew|nix|snap|system|library\/apple)(?:\/|$)/i,
  /^[a-z]:\/(?:windows|program files|program files \(x86\)|programdata\/chocolatey)\//i,
];

/** Absolute path outside the scanned roots, after expanding ~ and $HOME; undefined when unknown or inside. */
function outsidePath(token: string, roots: readonly string[]): string | undefined {
  if (/CLAUDE_PLUGIN_ROOT|CLAUDE_PROJECT_DIR/.test(token)) return undefined;
  const expanded = normPath(expandHomeVars(token));
  if (!/^(?:\/|[a-z]:\/)/i.test(expanded) || /[$%]/.test(expanded)) return undefined;
  if (SYSTEM_DIRS.some((re) => re.test(expanded))) return undefined;
  if (roots.some((root) => isUnder(expanded, root))) return undefined;
  return expanded;
}

function show(text: string, max = 80): string {
  return truncate(printable(text.length > max * 4 ? text.slice(0, max * 4) : text), max);
}

function showCommand(command: string, max = 120): string {
  return show(redactSecrets(command.length > MAX_SCRIPT ? command.slice(0, MAX_SCRIPT) : command).replace(/\s+/g, ' ').trim(), max);
}

function hookWords(hook: HookCommand): Tok[][] {
  const words = shellWords(hook.command).map((text) => ({ text, origin: 0 }));
  const lines = [words];
  const inline = inlineScript(words);
  if (inline && inline.words.length > 0) lines.push(inline.words);
  return lines;
}

// ===========================================================================
// Rules: supply chain
// ===========================================================================

const unpinnedRunner: Rule = {
  id: 'TM-SUP-001',
  title: 'Unpinned package runner',
  description:
    'An MCP server is launched through npx, pnpm/yarn dlx, bunx, uvx, pipx run or docker run without an exact version, so every start fetches whatever the registry serves at that moment. A hijacked maintainer account or malicious release then runs with your privileges.',
  category: 'supply-chain',
  severity: 'medium',
  kinds: SERVER_KINDS,
  remediation: 'Pin an exact version (npx -y pkg@1.2.3, uvx pkg==1.2.3, image@sha256:<digest>) and update deliberately after reviewing the changes.',
  check(file) {
    const doc = loadDoc(file);
    const out: RuleMatch[] = [];
    for (const server of activeServers(doc)) {
      for (const run of packageRuns(unwrap(baseTokens(server)))) {
        const problem = pinProblem(run);
        if (problem) out.push({ ...doc.where(tokPath(server, run.tok)), message: pinMessage(server, run, problem) });
      }
    }
    return out;
  },
};

const INSTALL_SCRIPTS: Readonly<Record<string, Severity>> = {
  preinstall: 'medium',
  install: 'medium',
  postinstall: 'medium',
  prepare: 'low',
  preprepare: 'low',
  postprepare: 'low',
  prepublish: 'low',
};

const installScript: Rule = {
  id: 'TM-SUP-002',
  title: 'Install-time script in a package manifest',
  description:
    'The package runs a lifecycle script (preinstall, install, postinstall, prepare) automatically when it is installed. Install scripts are the most common way malicious packages execute code before anyone looks at them.',
  category: 'supply-chain',
  severity: 'medium',
  kinds: ['package-manifest'],
  remediation: 'Review what the script does; install with --ignore-scripts when you do not need it, and prefer packages that need no install step.',
  check(file) {
    const doc = loadDoc(file);
    const scripts = doc.format === 'json' ? doc.data?.scripts : undefined;
    if (!isRecord(scripts)) return [];
    const out: RuleMatch[] = [];
    for (const [name, base] of Object.entries(INSTALL_SCRIPTS)) {
      const script = scripts[name];
      if (typeof script !== 'string' || !script.trim()) continue;
      const where = doc.where(['scripts', name]);
      const hits = analyzeScript(script, file, `scripts.${name}`, '.sh');
      if (hits.length === 0) {
        out.push({ ...where, severity: base, message: `'${name}' script runs automatically on install: ${showCommand(script)}` });
        continue;
      }
      for (const hit of hits) {
        out.push({ ...where, severity: maxSeverity(base, hit.severity), message: hitMessage(`'${name}' install script`, hit) });
      }
    }
    return out;
  },
};

interface SourceProblem {
  severity: Severity;
  message: string;
}

/** npm dependency specs that bypass the registry: git, GitHub shorthand, URLs. */
function npmSourceProblem(spec: string): SourceProblem | undefined {
  const s = spec.trim();
  if (!s || /^(?:file:|link:|workspace:|portal:|patch:|npm:|catalog:)/i.test(s) || /^\.{0,2}\//.test(s)) return undefined;
  if (/^(?:git\+)?http:\/\//i.test(s) || /^git:\/\//i.test(s)) {
    return { severity: 'medium', message: `over an unencrypted connection (${show(maskUrlString(s))}); anyone on the network path can swap the code` };
  }
  const gitLike = /^(?:git\+|git@|github:|gitlab:|bitbucket:|gist:)/i.test(s) || /^https:\/\/[^\s]{1,2000}\.git(?:#|$)/i.test(s);
  if (gitLike || /^[A-Za-z0-9][\w.-]{0,100}\/[\w.-]{1,100}(?:#\S{0,200})?$/.test(s)) {
    const hash = s.lastIndexOf('#');
    const ref = hash === -1 ? '' : s.slice(hash + 1).replace(/^commit=/, '');
    if (COMMIT_REF.test(ref)) return undefined;
    return { severity: 'low', message: `from git (${show(maskUrlString(s))}) without a pinned commit; the branch or tag can change under you` };
  }
  if (/^https:\/\//i.test(s)) {
    return { severity: 'medium', message: `from a raw URL (${show(maskUrlString(s))}); the file can change without a version bump and skips registry integrity checks` };
  }
  return undefined;
}

/** Python direct references: git+..., http(s):// archives. */
function pySourceProblem(url: string): SourceProblem | undefined {
  const s = url.trim();
  if (!s || /^file:/i.test(s)) return undefined;
  if (/^(?:git\+)?http:\/\//i.test(s) || /^git:\/\//i.test(s)) {
    return { severity: 'medium', message: `over an unencrypted connection (${show(maskUrlString(s))}); anyone on the network path can swap the code` };
  }
  if (/^git\+/i.test(s)) {
    const ref = /@([0-9A-Za-z._-]{1,100})(?:#\S{0,200})?$/.exec(s.replace(/^git\+[a-z]{1,10}:\/\/[^@/]{0,200}@/i, ''));
    if (ref && COMMIT_REF.test(ref[1]!)) return undefined;
    return { severity: 'low', message: `from git (${show(maskUrlString(s))}) without a pinned commit; the branch or tag can change under you` };
  }
  if (/^https:\/\//i.test(s)) {
    return { severity: 'medium', message: `from a raw URL (${show(maskUrlString(s))}); the file can change without a version bump` };
  }
  return undefined;
}

const PEP508_DIRECT = /^\s{0,10}([A-Za-z0-9][A-Za-z0-9._-]{0,200})(?:\[[^\]]{0,200}\])?\s{0,10}@\s{0,10}(\S{1,2000})/;

function pyprojectDeps(doc: ConfigDoc): { name: string; problem: SourceProblem; at: Seg[] }[] {
  const data = doc.data;
  if (!data) return [];
  const out: { name: string; problem: SourceProblem; at: Seg[] }[] = [];
  const fromList = (list: unknown, at: Seg[]) => {
    if (!Array.isArray(list)) return;
    list.forEach((dep: unknown, i) => {
      if (typeof dep !== 'string') return;
      const m = PEP508_DIRECT.exec(dep);
      const problem = m ? pySourceProblem(m[2]!) : undefined;
      if (m && problem) out.push({ name: m[1]!, problem, at: [...at, i] });
    });
  };
  const fromTable = (table: unknown, at: Seg[]) => {
    if (!isRecord(table)) return;
    for (const [name, spec] of Object.entries(table)) {
      const entries = Array.isArray(spec) ? spec : [spec];
      for (const entry of entries) {
        if (!isRecord(entry)) continue;
        let problem: SourceProblem | undefined;
        if (typeof entry.git === 'string') {
          const rev = typeof entry.rev === 'string' ? entry.rev : '';
          problem = pySourceProblem(`git+${entry.git.replace(/^git\+/i, '')}${rev ? `@${rev}` : ''}`);
        } else if (typeof entry.url === 'string') {
          problem = pySourceProblem(entry.url);
        }
        if (problem) out.push({ name, problem, at: [...at, name] });
      }
    }
  };
  const project = data.project;
  if (isRecord(project)) {
    fromList(project.dependencies, ['project', 'dependencies']);
    if (isRecord(project['optional-dependencies'])) {
      for (const [group, list] of Object.entries(project['optional-dependencies'])) fromList(list, ['project', 'optional-dependencies', group]);
    }
  }
  if (isRecord(data['dependency-groups'])) {
    for (const [group, list] of Object.entries(data['dependency-groups'])) fromList(list, ['dependency-groups', group]);
  }
  const tool = isRecord(data.tool) ? data.tool : undefined;
  if (tool && isRecord(tool.poetry)) {
    fromTable(tool.poetry.dependencies, ['tool', 'poetry', 'dependencies']);
    fromTable(tool.poetry['dev-dependencies'], ['tool', 'poetry', 'dev-dependencies']);
    if (isRecord(tool.poetry.group)) {
      for (const [group, body] of Object.entries(tool.poetry.group)) {
        if (isRecord(body)) fromTable(body.dependencies, ['tool', 'poetry', 'group', group, 'dependencies']);
      }
    }
  }
  if (tool && isRecord(tool.uv)) fromTable(tool.uv.sources, ['tool', 'uv', 'sources']);
  return out;
}

/** requirements.txt lines that install from git, a URL or a plain-HTTP index. */
function requirementsDeps(content: string): (SourceProblem & { line: number })[] {
  const out: (SourceProblem & { line: number })[] = [];
  const lines = content.split('\n');
  for (let i = 0; i < lines.length && out.length < 50; i++) {
    const raw = lines[i]!;
    const comment = raw.search(/(?:^|\s)#/);
    const line = (comment === -1 ? raw : raw.slice(0, comment)).trim();
    if (!line) continue;
    const index = /^(?:--index-url|--extra-index-url|-i)[\s=]{1,10}(\S{1,2000})/.exec(line);
    if (index) {
      const url = index[1]!;
      if (/^http:\/\//i.test(url) && hostClass(parseUrl(url)?.hostname ?? '') === 'public') {
        out.push({ line: i + 1, severity: 'medium', message: `Package index ${show(maskUrlString(url))} is used over plain HTTP; anyone on the network path can serve different packages` });
      } else if (line.startsWith('--extra-index-url')) {
        out.push({ line: i + 1, severity: 'low', message: `Extra package index ${show(maskUrlString(url))} is consulted alongside PyPI, which allows dependency-confusion attacks` });
      }
      continue;
    }
    const spec = line.replace(/^(?:-e|--editable)\s{1,10}/, '');
    const direct = PEP508_DIRECT.exec(spec);
    const url = direct ? direct[2]! : spec;
    if (!/^(?:git\+|https?:\/\/|git:\/\/)/i.test(url)) continue;
    const problem = pySourceProblem(url.split(/\s/)[0]!);
    if (problem) {
      const name = direct?.[1] ?? /#egg=([\w.-]{1,100})/.exec(url)?.[1] ?? 'package';
      out.push({ line: i + 1, severity: problem.severity, message: `Dependency '${show(name, 60)}' is fetched ${problem.message}` });
    }
  }
  return out;
}

const NPM_DEP_FIELDS = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies', 'resolutions'] as const;

const dependencySource: Rule = {
  id: 'TM-SUP-003',
  title: 'Dependency fetched from a URL or git',
  description:
    'A dependency is installed straight from a git repository or URL instead of a registry release. It bypasses registry integrity checks and can change without a version bump, and plain-HTTP sources can be swapped in transit.',
  category: 'supply-chain',
  severity: 'low',
  kinds: ['package-manifest'],
  remediation: 'Depend on a published registry version, or pin git dependencies to a full commit hash and serve everything over HTTPS.',
  check(file) {
    const doc = loadDoc(file);
    const out: RuleMatch[] = [];
    if (doc.format === 'json' && doc.data) {
      for (const field of NPM_DEP_FIELDS) {
        const deps = doc.data[field];
        if (!isRecord(deps)) continue;
        for (const [name, spec] of Object.entries(deps)) {
          if (typeof spec !== 'string' || out.length >= 100) continue;
          const problem = npmSourceProblem(spec);
          if (problem) {
            out.push({ ...doc.where([field, name]), severity: problem.severity, message: `Dependency '${show(name, 60)}' is fetched ${problem.message}` });
          }
        }
      }
    } else if (doc.format === 'toml') {
      for (const dep of pyprojectDeps(doc)) {
        out.push({ ...doc.where(dep.at), severity: dep.problem.severity, message: `Dependency '${show(dep.name, 60)}' is fetched ${dep.problem.message}` });
      }
    } else if (/\.(?:txt|in)$/i.test(file.path)) {
      for (const dep of requirementsDeps(file.content)) out.push({ line: dep.line, severity: dep.severity, message: dep.message });
    }
    return out;
  },
};

const scratchBinary: Rule = {
  id: 'TM-SUP-004',
  title: 'Runs a binary from a temp or downloads folder',
  description:
    'An MCP server or hook executes a program or script that lives in /tmp, %TEMP% or ~/Downloads. Those folders hold unreviewed, unversioned files written by browsers and other programs, which is exactly where droppers stage payloads.',
  category: 'supply-chain',
  severity: 'medium',
  kinds: LAUNCH_KINDS,
  remediation: 'Install the tool to a stable location (or reference it from the project or plugin) and verify where it came from.',
  check(file) {
    const doc = loadDoc(file);
    const out: RuleMatch[] = [];
    for (const server of activeServers(doc)) {
      for (const line of launchLines(server)) {
        for (const tok of executedWords(line)) {
          const folder = scratchFolder(tok.text);
          if (folder) out.push({ ...doc.where(tokPath(server, tok)), message: `${serverLabel(server)} runs ${show(tok.text)} from ${folderName(folder)}; files there are not reviewed or versioned.` });
        }
      }
    }
    for (const hook of hooks(doc)) {
      for (const line of hookWords(hook)) {
        for (const tok of executedWords(line)) {
          const folder = scratchFolder(tok.text);
          if (folder) out.push({ ...doc.where(hook.path), message: `${hookLabel(hook)} runs ${show(tok.text)} from ${folderName(folder)}; files there are not reviewed or versioned.` });
        }
      }
    }
    return out;
  },
};

function folderName(folder: 'temp' | 'downloads'): string {
  return folder === 'temp' ? 'a temporary folder' : 'the Downloads folder';
}

// ===========================================================================
// Rules: transport
// ===========================================================================

const plainHttp: Rule = {
  id: 'TM-NET-001',
  title: 'Remote MCP server over plain HTTP',
  description:
    'A remote MCP server is reached over unencrypted HTTP. Anyone on the network path can read tool calls and results, steal bearer tokens and inject tool descriptions or responses.',
  category: 'insecure-transport',
  severity: 'high',
  kinds: SERVER_KINDS,
  remediation: 'Use an https:// URL. Plain HTTP is only acceptable for localhost.',
  check(file) {
    const doc = loadDoc(file);
    const out: RuleMatch[] = [];
    for (const server of activeServers(doc)) {
      for (const endpoint of endpoints(server)) {
        const url = parseUrl(endpoint.value);
        if (!url || (url.protocol !== 'http:' && url.protocol !== 'ws:')) continue;
        const cls = hostClass(url.hostname);
        if (cls === 'loopback') continue;
        out.push({
          ...doc.where(endpoint.path),
          severity: cls === 'private' ? 'medium' : 'high',
          message: `${serverLabel(server)} connects to ${show(shownUrl(url), 100)} over plain HTTP; tool calls, results and tokens can be read or altered on the ${cls === 'private' ? 'local network' : 'network'}.`,
        });
      }
    }
    return out;
  },
};

const urlCredentials: Rule = {
  id: 'TM-NET-002',
  title: 'Credentials in a remote MCP URL',
  description:
    'A remote MCP server URL carries a credential in its query string or user:password part. URLs are logged by proxies and servers, shown in UIs and copied into bug reports, so the credential leaks easily.',
  category: 'insecure-transport',
  severity: 'high',
  kinds: SERVER_KINDS,
  remediation: "Send the credential in a header backed by an environment variable or the client's secret store (for example ${input:token} in VS Code), then rotate it.",
  check(file) {
    const doc = loadDoc(file);
    const out: RuleMatch[] = [];
    for (const server of activeServers(doc)) {
      for (const endpoint of endpoints(server)) {
        const url = parseUrl(endpoint.value);
        if (!url) continue;
        const where = doc.where(endpoint.path);
        const params = [...url.searchParams.entries()]
          .filter(([name, value]) => isCredentialParam(name) && value.length >= 6 && !isPlaceholder(value))
          .map(([name]) => name);
        if (params.length > 0) {
          out.push({
            ...where,
            snippet: maskedUrl(url),
            message: `${serverLabel(server)} URL carries a credential in query parameter '${show(params[0]!, 40)}'; URLs end up in logs, proxies and screenshots.`,
          });
        }
        const password = decodeURIComponentSafe(url.password);
        const username = decodeURIComponentSafe(url.username);
        if ((password && !isPlaceholder(password)) || (!password && username.length >= 20 && !isPlaceholder(username))) {
          out.push({
            ...where,
            snippet: maskedUrl(url),
            message: `${serverLabel(server)} URL embeds ${password ? 'a username and password' : 'a token as the username'} before the host; URLs end up in logs, proxies and screenshots.`,
          });
        }
      }
    }
    return out;
  },
};

function decodeURIComponentSafe(text: string): string {
  try {
    return decodeURIComponent(text);
  } catch {
    return text;
  }
}

function maskedUrl(url: URL): string {
  const copy = new URL(url.href);
  if (copy.password) copy.password = '****';
  else if (copy.username.length >= 20) copy.username = '****';
  for (const name of [...copy.searchParams.keys()]) if (isCredentialParam(name)) copy.searchParams.set(name, '****');
  return truncate(copy.href, 160);
}

const tunnelEndpoint: Rule = {
  id: 'TM-NET-003',
  title: 'Remote MCP server on a tunnel or raw IP',
  description:
    'A remote MCP server is reached through a public tunnelling service (ngrok, Cloudflare quick tunnels, localtunnel, serveo...) or a bare public IP address. Anyone can create these in seconds, they rotate freely and usually front a personal machine, so there is no stable identity behind the server.',
  category: 'insecure-transport',
  severity: 'medium',
  kinds: SERVER_KINDS,
  remediation: 'Only connect to MCP servers on domains you can attribute to their operator, over HTTPS.',
  check(file) {
    const doc = loadDoc(file);
    const out: RuleMatch[] = [];
    for (const server of activeServers(doc)) {
      for (const endpoint of endpoints(server)) {
        const url = parseUrl(endpoint.value);
        if (!url) continue;
        const host = url.hostname.toLowerCase();
        const provider = tunnelProvider(host);
        if (provider) {
          out.push({ ...doc.where(endpoint.path), message: `${serverLabel(server)} connects to ${show(host, 80)}, a public ${provider} tunnel that anyone can stand up and that usually fronts a personal machine.` });
        } else if ((ipv4(host) || host.startsWith('[')) && hostClass(host) === 'public') {
          out.push({ ...doc.where(endpoint.path), message: `${serverLabel(server)} connects to the raw IP address ${show(host, 60)}; there is no domain name to tell you who operates it.` });
        }
      }
    }
    return out;
  },
};

// ===========================================================================
// Rules: config hygiene
// ===========================================================================

function secretMatches(doc: ConfigDoc, server: McpServer): RuleMatch[] {
  const out: RuleMatch[] = [];
  const who = serverLabel(server);
  const tail = 'anyone or anything that can read this file, including a malicious skill or plugin, can copy it.';
  const checkValue = (label: string, key: string, value: unknown, at: Seg[]) => {
    if (typeof value !== 'string') return;
    const hit = findSecrets(value, 1)[0];
    const snippet = `${key}: ${maskValue(value)}`;
    if (hit) {
      out.push({ ...doc.where(at), snippet, severity: 'high', message: `${who} ${label} '${show(key, 60)}' holds a plaintext ${hit.name}; ${tail}` });
    } else if (isSecretName(key) && looksLikeLiteralSecret(stripAuthScheme(value))) {
      out.push({ ...doc.where(at), snippet, severity: 'medium', message: `${who} ${label} '${show(key, 60)}' holds a literal value that looks like a credential; ${tail}` });
    }
  };
  if (server.env) for (const [key, value] of Object.entries(server.env.values)) checkValue('env var', key, value, [...server.env.path, key]);
  for (const headers of server.headers) {
    for (const [key, value] of Object.entries(headers.values)) checkValue('header', key, value, [...headers.path, key]);
  }
  server.args.forEach((arg, i) => {
    const snippet = `argument ${i + 1}: ${maskValue(arg.value)}`;
    const hit = findSecrets(arg.value, 1)[0];
    if (hit) {
      out.push({ ...doc.where(arg.path), snippet, severity: 'high', message: `${who} passes a plaintext ${hit.name} on its command line (argument ${i + 1}); command lines are visible to other local processes and end up in logs.` });
      return;
    }
    const assign = /^(?:--?)?([A-Za-z_][\w-]{0,100})=([^\n]{1,4096})$/.exec(arg.value);
    const prev = server.args[i - 1]?.value ?? '';
    const flag = /^--?([A-Za-z][\w-]{0,60})$/.exec(prev);
    const name = assign ? assign[1]! : flag && !arg.value.startsWith('-') ? flag[1]! : undefined;
    const value = assign ? assign[2]! : arg.value;
    if (name && isSecretName(name) && looksLikeLiteralSecret(stripAuthScheme(value))) {
      out.push({ ...doc.where(arg.path), snippet, severity: 'medium', message: `${who} passes a literal value for '${show(name, 60)}' on its command line; ${tail}` });
    }
  });
  return out;
}

const plaintextSecret: Rule = {
  id: 'TM-CFG-001',
  title: 'Plaintext secret in MCP server config',
  description:
    'An MCP server env var, header or argument holds a literal credential. Client configs are read by every tool, skill and plugin running as you, are synced and backed up, and are a prime target for infostealers; secrets there leak easily.',
  category: 'secrets',
  severity: 'high',
  kinds: SERVER_KINDS,
  remediation: "Move the secret to the environment or the client's input/secret store (${input:...} in VS Code, ${env:VAR} or bearer_token_env_var), then rotate it.",
  check(file) {
    const doc = loadDoc(file);
    return servers(doc).flatMap((server) => secretMatches(doc, server));
  },
};

const inlineShell: Rule = {
  id: 'TM-CFG-002',
  title: 'Server command runs an inline shell script',
  description:
    'An MCP server is launched as bash -c, cmd /c or powershell -Command with a script written into the config. Inline scripts hide arbitrary logic (downloads, decoding, chained commands) behind what looks like a server entry; encoded PowerShell hides it completely.',
  category: 'dangerous-execution',
  severity: 'medium',
  kinds: SERVER_KINDS,
  remediation: 'Point the server at a real executable with plain arguments; move any setup into a reviewed script file.',
  check(file) {
    const doc = loadDoc(file);
    const out: RuleMatch[] = [];
    for (const server of activeServers(doc)) {
      const inline = findInline(baseTokens(server));
      if (!inline) continue;
      const at = doc.where(tokPath(server, { text: '', origin: inline.origin }));
      const base: Severity = inline.encoded ? 'high' : 'medium';
      const ext = inline.shell === 'cmd' ? '.cmd' : inline.shell === 'powershell' || inline.shell === 'pwsh' ? '.ps1' : '.sh';
      const hits = analyzeScript(inline.script, file, `${server.name}.command`, ext);
      const who = serverLabel(server);
      for (const hit of hits) {
        out.push({ ...at, severity: maxSeverity(base, hit.severity), message: hitMessage(`${who} inline ${inline.shell} script`, hit) });
      }
      if (hits.length > 0) continue;
      if (inline.encoded) {
        out.push({ ...at, severity: base, message: `${who} runs a base64-encoded PowerShell command, which hides what it does${inline.words.length ? `; decoded: ${showCommand(inline.script, 100)}` : ''}.` });
      } else if (!isSimpleScript(inline.script)) {
        out.push({ ...at, severity: base, message: `${who} runs an inline ${inline.shell} script instead of a program: ${showCommand(inline.script, 100)}` });
      }
    }
    return out;
  },
};

function enableAllMessage(scope: SettingsScope): { message: string; severity?: Severity } {
  if (scope === 'user') {
    return {
      message:
        "enableAllProjectMcpServers is true in your user settings: the MCP servers in any repository's .mcp.json start without asking, so cloning a repository is enough to run its servers.",
    };
  }
  if (scope === 'local') {
    return {
      severity: 'low',
      message:
        'enableAllProjectMcpServers is true in local project settings: every server this project adds to .mcp.json later, for example in a pulled commit, starts without asking you.',
    };
  }
  return { message: 'enableAllProjectMcpServers is true in project settings: a cloned repository can switch on the MCP servers it ships in .mcp.json without asking you.' };
}

function enabledListMessage(scope: SettingsScope, names: string): { message: string; severity?: Severity } {
  if (scope === 'user') {
    return {
      severity: 'low',
      message: `User settings pre-approve project MCP servers named ${names}; any repository whose .mcp.json reuses one of these names gets that server started without asking.`,
    };
  }
  if (scope === 'local') {
    return {
      severity: 'info',
      message: `Local project settings pre-approve the .mcp.json servers ${names}; if a pulled commit changes what one of them runs, it starts without asking you again.`,
    };
  }
  return { message: `Project settings pre-approve the .mcp.json servers ${names}: a cloned repository can switch on its own MCP servers without asking you.` };
}

/** The innermost interesting inline script: simple one-liners that just launch another wrapper are followed. */
function findInline(toks: Tok[], depth = 0): InlineScript | undefined {
  if (depth > 3) return undefined;
  const inline = inlineScript(stripEnv(toks));
  if (!inline) return undefined;
  if (!inline.encoded && isSimpleScript(inline.script)) return findInline(inline.words, depth + 1) ?? inline;
  return inline;
}

const autoEnableServers: Rule = {
  id: 'TM-CFG-003',
  title: 'Settings auto-enable project MCP servers',
  description:
    "Claude Code settings turn on the MCP servers from a project's .mcp.json without the usual approval prompt (enableAllProjectMcpServers or enabledMcpjsonServers). When the setting ships inside a repository, cloning it is enough to start whatever servers it defines.",
  category: 'excessive-permissions',
  severity: 'medium',
  kinds: ['agent-settings'],
  remediation: 'Remove the setting from project settings and approve project MCP servers interactively after reviewing .mcp.json.',
  check(file) {
    const doc = loadDoc(file);
    const data = doc.data;
    if (!data) return [];
    const scope = settingsScope(file);
    if (scope === 'managed') return [];
    const out: RuleMatch[] = [];
    if (data.enableAllProjectMcpServers === true) {
      out.push({ ...doc.where(['enableAllProjectMcpServers']), ...enableAllMessage(scope) });
    }
    const enabled = Array.isArray(data.enabledMcpjsonServers) ? data.enabledMcpjsonServers.filter((n): n is string => typeof n === 'string') : [];
    if (enabled.length > 0) {
      const names = enabled.slice(0, 5).map((n) => `'${show(n, 40)}'`).join(', ') + (enabled.length > 5 ? ', ...' : '');
      out.push({ ...doc.where(['enabledMcpjsonServers']), ...enabledListMessage(scope, names) });
    }
    return out;
  },
};

// ===========================================================================
// Rules: permissions
// ===========================================================================

const CODE_RUNNERS = new Set([
  'bash', 'sh', 'zsh', 'dash', 'fish', 'ksh', 'pwsh', 'powershell', 'cmd', 'python', 'python3', 'py', 'node', 'deno', 'bun', 'ruby',
  'perl', 'php', 'eval', 'exec', 'sudo', 'su', 'doas', 'env', 'xargs', 'npx', 'uvx', 'bunx', 'pnpx', 'osascript',
]);
const NETWORK_RUNNERS = new Set(['curl', 'wget', 'nc', 'ncat', 'netcat', 'socat', 'ssh', 'scp', 'iwr', 'irm', 'invoke-webrequest', 'invoke-restmethod']);

interface Grant {
  severity: Severity;
  effect: string;
}

/** What a permissions.allow or allowed-tools entry effectively grants, when that is broad. */
function classifyGrant(entry: string): Grant | undefined {
  const t = entry.trim();
  if (t === '*') return { severity: 'high', effect: 'which allows every tool without asking' };
  const shell = /^(Bash|PowerShell)(?:\(([^)\n]{0,500})\))?$/i.exec(t);
  if (shell) {
    const spec = (shell[2] ?? '').trim();
    if (spec === '' || spec.startsWith('*') || spec === ':*') {
      return { severity: 'high', effect: 'which lets the agent run any shell command without asking' };
    }
    const first = programName(spec.split(/[\s:]/)[0] ?? '');
    if (CODE_RUNNERS.has(first)) return { severity: 'medium', effect: `which lets the agent run arbitrary code through ${first} without asking` };
    if (NETWORK_RUNNERS.has(first)) return { severity: 'medium', effect: `which lets the agent send data anywhere with ${first} without asking` };
    return undefined;
  }
  if (/^WebFetch(?:\(\s{0,5}(?:\*|domain:\*)?\s{0,5}\))?$/i.test(t)) {
    return { severity: 'medium', effect: 'which lets the agent fetch any URL without asking, an easy exfiltration channel for injected instructions' };
  }
  if (/^WebSearch(?:\(\s{0,5}\*?\s{0,5}\))?$/i.test(t)) {
    return { severity: 'low', effect: 'which lets the agent send search queries (and whatever it puts in them) without asking' };
  }
  if (/^mcp__\*/i.test(t)) return { severity: 'medium', effect: 'which pre-approves every tool of every MCP server' };
  return undefined;
}

const BYPASS_FLAG = /^(?:skipDangerousModePermissionPrompt|dangerouslySkipPermissions|dangerously[A-Z][A-Za-z]{0,60}|skip[A-Z][A-Za-z]{0,40}Permission[A-Za-z]{0,40})$/;

function codexGrants(doc: ConfigDoc, table: Record<string, unknown>, at: Seg[]): RuleMatch[] {
  if (table.sandbox_mode !== 'danger-full-access') return [];
  const never = table.approval_policy === 'never';
  return [
    {
      ...doc.where([...at, 'sandbox_mode']),
      severity: never ? 'high' : 'medium',
      message: never
        ? "Codex runs with sandbox_mode 'danger-full-access' and approval_policy 'never': every command runs unsandboxed and without asking."
        : "Codex sandbox_mode is 'danger-full-access': commands run without the sandbox, limited only by approval prompts.",
    },
  ];
}

const broadPermissions: Rule = {
  id: 'TM-PERM-001',
  title: 'Overly broad agent permissions',
  description:
    'Agent settings pre-approve dangerous capabilities: bypassPermissions mode, unrestricted Bash, any URL fetch, every MCP tool, or sandbox-free execution. A single prompt injection then turns into code execution or data theft with no human in the loop.',
  category: 'excessive-permissions',
  severity: 'high',
  kinds: ['agent-settings', 'mcp-config'],
  remediation: 'Allow narrow, specific commands (Bash(git status:*), WebFetch(domain:docs.example.com)) and keep the default permission mode.',
  check(file) {
    const doc = loadDoc(file);
    const data = doc.data;
    if (!data) return [];
    const suffix = settingsScope(file) === 'project' ? PROJECT_SUFFIX : '';
    const out: RuleMatch[] = [];
    const perms = isRecord(data.permissions) ? data.permissions : undefined;
    if (perms?.defaultMode === 'bypassPermissions') {
      out.push({
        ...doc.where(['permissions', 'defaultMode']),
        severity: 'high',
        message: `permissions.defaultMode is 'bypassPermissions': every tool call, including shell commands and file writes, runs without asking${suffix}.`,
      });
    }
    if (perms && Array.isArray(perms.allow)) {
      perms.allow.forEach((entry: unknown, i) => {
        if (typeof entry !== 'string') return;
        const grant = classifyGrant(entry);
        if (grant) out.push({ ...doc.where(['permissions', 'allow', i]), severity: grant.severity, message: `permissions.allow grants '${show(entry, 60)}', ${grant.effect}${suffix}.` });
      });
    }
    const flagTables: [Seg[], Record<string, unknown> | undefined][] = [[[], data], [['permissions'], perms]];
    for (const [at, table] of flagTables) {
      for (const [key, value] of Object.entries(table ?? {})) {
        if (value === true && BYPASS_FLAG.test(key)) {
          out.push({ ...doc.where([...at, key]), severity: 'medium', message: `${show(key, 60)} is true, which skips the safety prompt for dangerous permission modes${suffix}.` });
        }
      }
    }
    for (const server of servers(doc)) {
      if (server.raw.trust === true) {
        out.push({ ...doc.where([...server.path, 'trust']), severity: 'medium', message: `${serverLabel(server)} is marked trust: true, so its tool calls run without confirmation.` });
      }
    }
    if (doc.format === 'toml') {
      out.push(...codexGrants(doc, data, []));
      if (isRecord(data.profiles)) {
        for (const [name, profile] of Object.entries(data.profiles)) if (isRecord(profile)) out.push(...codexGrants(doc, profile, ['profiles', name]));
      }
    }
    return out;
  },
};

const skillShell: Rule = {
  id: 'TM-PERM-002',
  title: 'Skill or command grants unrestricted shell',
  description:
    'A skill, slash command or agent pre-approves unrestricted shell access in its allowed-tools frontmatter. While it is active the agent can run any command without asking, so instructions hidden in the skill or in content it reads go straight to your shell.',
  category: 'excessive-permissions',
  severity: 'medium',
  kinds: ['skill', 'instructions'],
  remediation: 'List only the commands the skill needs, for example "Bash(git status:*), Bash(npm test:*)".',
  check(file) {
    const fm = parseFrontmatter(file.content);
    if (!fm) return [];
    const key = ['allowed-tools', 'allowed_tools', 'allowedTools'].find((k) => fm.data[k] !== undefined);
    if (!key) return [];
    const line = fm.lines[key] ?? 1;
    const owner = ownerLabel(file, fm.data.name);
    const out: RuleMatch[] = [];
    for (const tool of asList(fm.data[key]).slice(0, 100)) {
      const grant = classifyGrant(tool);
      if (!grant || /^Web|^mcp__/i.test(tool.trim())) continue;
      const severity: Severity = grant.severity === 'high' ? 'medium' : 'low';
      out.push({ line, severity, message: `${owner} pre-approves '${show(tool, 60)}' in ${key}, ${grant.effect} while it is active.` });
    }
    return out;
  },
};

function ownerLabel(file: ScanFile, name: unknown): string {
  const p = normPath(file.displayPath);
  const label = typeof name === 'string' && name.trim() ? name.trim() : path.posix.basename(p).replace(/\.md$/i, '');
  const what = file.kind === 'skill' ? 'Skill' : /(?:^|\/)agents\//.test(p) ? 'Agent' : /(?:^|\/)commands\//.test(p) ? 'Command' : 'File';
  return `${what} '${show(label, 60)}'`;
}

const SENSITIVE_DIRS = /\/(?:\.ssh|\.aws|\.gnupg|\.kube|\.docker|\.config|\.azure|\.gcloud|\.password-store|library\/keychains)$/i;

/** Why an additional directory is too broad, or undefined when it is fine. */
function broadDirectory(dir: string): string | undefined {
  const raw = dir.trim();
  if (!raw) return undefined;
  const p = normPath(expandHomeVars(raw));
  const h = home();
  if (p === '/' || /^[a-z]:\/?$/i.test(p)) return 'the whole filesystem';
  if ((h.length > 1 && p === h) || /^(?:~|\$HOME|%USERPROFILE%)$/i.test(raw)) return 'your entire home directory';
  if (/^\/(?:users|home)(?:\/[^/]{1,64})?$/i.test(p) || /^[a-z]:\/users(?:\/[^/]{1,64})?$/i.test(p)) return 'a whole home directory';
  if (SENSITIVE_DIRS.test(p)) return 'a directory that holds credentials';
  return undefined;
}

const outsideProject: Rule = {
  id: 'TM-PERM-003',
  title: 'Agent access outside the project',
  description:
    'permissions.additionalDirectories extends the agent beyond the project to the home directory, a drive root or a credentials folder. Any prompt injection can then read SSH keys, cloud tokens and browser data that have nothing to do with the task.',
  category: 'excessive-permissions',
  severity: 'medium',
  kinds: ['agent-settings'],
  remediation: 'Add only the specific sibling directories the work needs.',
  check(file) {
    const doc = loadDoc(file);
    const permissions = doc.data?.permissions;
    const dirs = isRecord(permissions) ? permissions.additionalDirectories : undefined;
    if (!Array.isArray(dirs)) return [];
    const suffix = settingsScope(file) === 'project' ? PROJECT_SUFFIX : '';
    const out: RuleMatch[] = [];
    dirs.forEach((dir: unknown, i) => {
      if (typeof dir !== 'string') return;
      const why = broadDirectory(dir);
      if (why) out.push({ ...doc.where(['permissions', 'additionalDirectories', i]), message: `permissions.additionalDirectories grants the agent access to '${show(dir, 60)}', ${why}${suffix}.` });
    });
    return out;
  },
};

// ===========================================================================
// Rules: hooks
// ===========================================================================

const hookInventory: Rule = {
  id: 'TM-HOOK-001',
  title: 'Hook inventory',
  description:
    'Lists every hook command, plus the statusLine and helper commands (apiKeyHelper, awsAuthRefresh...) in Claude Code settings. These run automatically on agent events (every prompt, every tool call, session start) without asking each time, so you should know exactly what each one executes.',
  category: 'persistence',
  severity: 'info',
  kinds: HOOK_KINDS,
  check(file) {
    const doc = loadDoc(file);
    return hooks(doc).map((hook) => ({ ...doc.where(hook.path), message: `${hookLabel(hook)} runs: ${showCommand(hook.command)}` }));
  },
};

const dangerousHook: Rule = {
  id: 'TM-HOOK-002',
  title: 'Dangerous hook command',
  description:
    'A hook command matches a dangerous-code pattern such as download-and-execute, decoding hidden payloads, credential access or destructive deletion. Hooks fire automatically, so this runs every time the event happens.',
  category: 'dangerous-execution',
  severity: 'high',
  kinds: HOOK_KINDS,
  remediation: 'Remove the hook, or replace it with a reviewed script that is part of the project or plugin.',
  check(file) {
    const doc = loadDoc(file);
    const out: RuleMatch[] = [];
    hooks(doc).forEach((hook, i) => {
      for (const hit of analyzeScript(hook.command, file, `hook${i}`, '.sh')) {
        out.push({ ...doc.where(hook.path), severity: hit.severity, message: hitMessage(`${hookLabel(hook)} command`, hit) });
      }
    });
    return out;
  },
};

const NETWORK_TOOL = /(?:^|[\s;&|(`'"]|\$\()(curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|nc|ncat|netcat|socat|Start-BitsTransfer)(?=$|[\s;&|)`'"]|\.exe\b)/gi;
const URL_IN_TEXT = /\bhttps?:\/\/[^\s'"`<>|;&()]{1,500}/gi;

const hookNetwork: Rule = {
  id: 'TM-HOOK-003',
  title: 'Hook makes network requests',
  description:
    'A hook command calls curl, wget, Invoke-WebRequest, nc or a similar tool. Hooks see prompts, tool inputs and outputs, so a hook that phones home can leak code, files and tokens on every run without any prompt.',
  category: 'exfiltration',
  severity: 'medium',
  kinds: HOOK_KINDS,
  remediation: 'Check where the hook sends data and what it includes; keep notifications local or send only fixed messages.',
  check(file) {
    const doc = loadDoc(file);
    const out: RuleMatch[] = [];
    for (const hook of hooks(doc)) {
      const tools = [...new Set(findAll(NETWORK_TOOL, hook.command, 10).map((h) => (h.groups[0] ?? '').toLowerCase()))].filter(Boolean);
      if (tools.length === 0) continue;
      const hosts = [...new Set(findAll(URL_IN_TEXT, hook.command, 10).map((h) => parseUrl(h.text)?.hostname).filter((h): h is string => Boolean(h)))];
      const localOnly = hosts.length > 0 && hosts.every((h) => hostClass(h) === 'loopback');
      const target = hosts.length > 0 ? ` to ${hosts.slice(0, 3).map((h) => show(h, 60)).join(', ')}` : '';
      out.push({
        ...doc.where(hook.path),
        severity: localOnly ? 'low' : 'medium',
        message: `${hookLabel(hook)} makes network requests with ${tools.join(', ')}${target}; a hook that phones home can leak prompts, files or tokens on every run.`,
      });
    }
    return out;
  },
};

const SCRIPT_URL_EXT = /\.(?:sh|bash|zsh|py|js|mjs|cjs|ts|ps1|psm1|rb|pl|bat|cmd)$/i;
const RUNS_FETCHED = /\|\s{0,10}(?:sudo\s{1,10})?(?:ba|z|da|k)?sh\b|\|\s{0,10}(?:python3?|node|perl|ruby|iex|Invoke-Expression)\b|<\(|\$\(\s{0,10}(?:curl|wget)|\bdeno\s{1,10}run\b|\b(?:iex|Invoke-Expression)\b/i;

const externalHookScript: Rule = {
  id: 'TM-HOOK-004',
  title: 'Hook runs a script outside the project or plugin',
  description:
    'A hook executes a script by absolute path outside the scanned project or plugin, or fetches one from a URL. That code is not covered by this scan or by code review, and can change without the hook changing.',
  category: 'dangerous-execution',
  severity: 'low',
  kinds: HOOK_KINDS,
  remediation: 'Keep hook scripts inside the project or plugin (for example ${CLAUDE_PLUGIN_ROOT}/hooks/...) and scan them too.',
  check(file) {
    const doc = loadDoc(file);
    const roots = knownRoots(file);
    const out: RuleMatch[] = [];
    for (const hook of hooks(doc)) {
      const where = doc.where(hook.path);
      for (const line of hookWords(hook)) {
        for (const tok of executedWords(line)) {
          if (scratchFolder(tok.text)) continue;
          const outside = outsidePath(tok.text, roots);
          if (outside) out.push({ ...where, message: `${hookLabel(hook)} runs ${show(tok.text)}, which is outside the scanned project or plugin; that script is not covered by this scan.` });
        }
      }
      if (RUNS_FETCHED.test(hook.command)) {
        for (const h of findAll(URL_IN_TEXT, hook.command, 5)) {
          const url = parseUrl(h.text);
          if (url && SCRIPT_URL_EXT.test(url.pathname)) {
            out.push({ ...where, message: `${hookLabel(hook)} fetches and runs the remote script ${show(shownUrl(url), 100)}; whatever is served there runs on every trigger.` });
          }
        }
      }
    }
    return out;
  },
};

// ===========================================================================
// Snippet masking
// ===========================================================================

type Range = readonly [start: number, end: number];

const MAX_MASK_LINE = 100_000;
const MAX_MASKS_PER_PATTERN = 1000;
const SNIPPET_WIDTH = 150;

const URL_USERINFO = /\/\/([^/@\s"'<>]{1,200})@/g;
const QUERY_PARAM = /[?&]([A-Za-z0-9_.-]{1,60})=([^&\s"'#<>]{1,2000})/g;
const JSON_PAIR = /"([A-Za-z_][\w.-]{0,100})"\s{0,5}:\s{0,5}"([^"\\\n]{1,4096})"/g;
const TOML_BASIC_PAIR = /(?:^|[\s{,])([A-Za-z_][\w-]{0,100})\s{0,5}=\s{0,5}"([^"\\\n]{1,4096})"/g;
const TOML_LITERAL_PAIR = /(?:^|[\s{,])([A-Za-z_][\w-]{0,100})\s{0,5}=\s{0,5}'([^'\n]{1,4096})'/g;
const FLAG_PAIR = /--?([A-Za-z][\w-]{0,60})=([^\s"',&]{1,4096})/g;

/** One-entry memo: the rules of this module report on the same file in turn, often on the same lines. */
let maskMemo: { content: string; lines: Map<number, Range[]> } | undefined;

function isLiteralCredential(key: string, value: string): boolean {
  return isSecretName(key) && looksLikeLiteralSecret(stripAuthScheme(value));
}

/**
 * Offsets of credential-looking values on one line: URL passwords and
 * query-string credentials, and literals under secret-like keys in JSON,
 * TOML and --flag=value form. The generic secret patterns redact known token
 * formats; these cover the rest, which config files are full of.
 */
function secretRanges(content: string, start: number, end: number): Range[] {
  const line = content.slice(start, Math.min(end, start + MAX_MASK_LINE));
  const out: Range[] = [];
  /** Masks the value captured last in the match, which always ends `tail` characters before the match ends. */
  const add = (hit: { index: number; text: string }, value: string, tail: number) => {
    const valueEnd = hit.index + hit.text.length - tail;
    out.push([start + valueEnd - value.length, start + valueEnd]);
  };
  for (const hit of findAll(URL_USERINFO, line, MAX_MASKS_PER_PATTERN)) {
    const userinfo = hit.groups[0] ?? '';
    const colon = userinfo.indexOf(':');
    if (colon !== -1 && colon < userinfo.length - 1) add(hit, userinfo.slice(colon + 1), 1);
    else if (userinfo.length >= 20 && !isPlaceholder(userinfo)) add(hit, userinfo, 1);
  }
  for (const hit of findAll(QUERY_PARAM, line, MAX_MASKS_PER_PATTERN)) {
    const value = hit.groups[1] ?? '';
    if (isCredentialParam(hit.groups[0] ?? '') && !isPlaceholder(value)) add(hit, value, 0);
  }
  for (const [regex, tail] of [[JSON_PAIR, 1], [TOML_BASIC_PAIR, 1], [TOML_LITERAL_PAIR, 1], [FLAG_PAIR, 0]] as const) {
    for (const hit of findAll(regex, line, MAX_MASKS_PER_PATTERN)) {
      const value = hit.groups[1] ?? '';
      if (isLiteralCredential(hit.groups[0] ?? '', value)) add(hit, value, tail);
    }
  }
  return mergeRanges(out);
}

function mergeRanges(ranges: Range[]): Range[] {
  ranges.sort((a, b) => a[0] - b[0]);
  const out: [number, number][] = [];
  for (const [s, e] of ranges) {
    const last = out[out.length - 1];
    if (last && s <= last[1]) last[1] = Math.max(last[1], e);
    else out.push([s, e]);
  }
  return out;
}

function lineMasks(content: string, lineStart: number, lineEnd: number): Range[] {
  if (maskMemo?.content !== content) maskMemo = { content, lines: new Map() };
  let ranges = maskMemo.lines.get(lineStart);
  if (!ranges) {
    ranges = secretRanges(content, lineStart, lineEnd);
    maskMemo.lines.set(lineStart, ranges);
  }
  return ranges;
}

/**
 * Gives a match an explicit snippet with credentials masked when its line
 * holds any. The snippet is a window around the match, built from the raw
 * line, so a value cut by the window edge is still masked.
 */
function maskSnippet(content: string, match: RuleMatch): RuleMatch {
  if (match.snippet !== undefined) return match;
  let at: number;
  if (match.index !== undefined) at = Math.max(0, Math.min(match.index, content.length));
  else if (match.line !== undefined) at = lineStartIndex(content, match.line);
  else return match;
  if (at < 0) return match;
  const lineStart = content.lastIndexOf('\n', at - 1) + 1;
  const newline = content.indexOf('\n', at);
  const lineEnd = newline === -1 ? content.length : content[newline - 1] === '\r' ? newline - 1 : newline;
  const ranges = lineMasks(content, lineStart, lineEnd);
  if (ranges.length === 0) return match;

  const width = lineEnd - lineStart;
  const from = width <= SNIPPET_WIDTH ? lineStart : lineStart + Math.max(0, Math.min(at - lineStart - 40, width - SNIPPET_WIDTH));
  const to = Math.min(lineEnd, from + SNIPPET_WIDTH);
  let snippet = from > lineStart ? '…' : '';
  let cursor = from;
  for (const [s, e] of ranges) {
    if (e <= cursor || s >= to) continue;
    snippet += `${content.slice(cursor, Math.max(cursor, s))}****`;
    cursor = Math.min(to, e);
  }
  snippet += content.slice(cursor, to) + (to < lineEnd ? '…' : '');
  return { ...match, snippet };
}

/** Wraps a rule so every match it returns passes through maskSnippet. */
function withMaskedSnippets(rule: Rule): Rule {
  const check = rule.check;
  return { ...rule, check: (file) => check(file).map((match) => maskSnippet(file.content, match)) };
}

/** Structure-aware rules for MCP configs, agent settings, hooks and manifests (TM-SUP-*, TM-PERM-*, TM-HOOK-*, TM-NET-*, TM-CFG-*). */
export const configRules: readonly Rule[] = [
  unpinnedRunner,
  installScript,
  dependencySource,
  scratchBinary,
  plainHttp,
  urlCredentials,
  tunnelEndpoint,
  plaintextSecret,
  inlineShell,
  autoEnableServers,
  broadPermissions,
  skillShell,
  outsideProject,
  hookInventory,
  dangerousHook,
  hookNetwork,
  externalHookScript,
].map(withMaskedSnippets);
