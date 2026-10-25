import fs from 'node:fs';
import path from 'node:path';
import type { ClientConfigLocation } from '../clients/configs.js';
import { CLIENT_CONFIGS, pathKey } from '../clients/configs.js';
import type { FileKind, ScanFile, SkippedFile } from '../types.js';
import { isRecord, parseJsonc } from '../util/jsonc.js';
import { expandHome, homeDir } from '../util/paths.js';
import { printable, truncate } from '../util/text.js';
import type { IgnoreConfig } from './ignore.js';
import { isPathIgnored } from './ignore.js';

export interface DiscoverOptions {
  /** Files or directories to scan; a leading ~ is expanded. */
  paths: string[];
  /** Also scan the known agent locations (skills, plugins, hooks, MCP client configs) that exist. */
  useDefaults: boolean;
  cwd: string;
  /** Walk into node_modules, virtualenvs and caches too. .git is always skipped. */
  deep?: boolean;
  /** Files larger than this are reported as skipped. Default 2 MiB. */
  maxFileBytes?: number;
  ignore?: IgnoreConfig;
  /** Stop after this many files. Default 20000. */
  maxFiles?: number;
}

export interface DiscoverResult {
  files: ScanFile[];
  skipped: SkippedFile[];
  /** What was actually scanned, as display paths, for the report header. */
  roots: string[];
}

const MIB = 1024 * 1024;
const DEFAULT_MAX_FILE_BYTES = 2 * MIB;
const DEFAULT_MAX_FILES = 20_000;
const READ_CONCURRENCY = 16;
const BINARY_SNIFF_BYTES = 8192;

const SKIP_DIRS = new Set(['.git', 'node_modules', '.venv', 'venv', '__pycache__', '.tox', '.mypy_cache', '.pytest_cache', '.next', '.turbo', '.cache']);
const PROMPT_DIRS = new Set(['commands', 'agents', 'rules', 'prompts']);
const MARKDOWN_EXTS = new Set(['.md', '.mdx', '.markdown', '.mdc']);
const SCRIPT_EXTS = new Set([
  '.sh', '.bash', '.zsh', '.fish', '.ps1', '.psm1', '.bat', '.cmd', '.py', '.js', '.mjs', '.cjs',
  '.ts', '.mts', '.cts', '.jsx', '.tsx', '.rb', '.pl', '.php', '.lua',
]);
const AGENT_MARKDOWN = new Set(['claude.md', 'claude.local.md', 'agents.md', 'gemini.md']);
const DOC_STEMS = new Set(['readme', 'changelog', 'contributing', 'license', 'security', 'code_of_conduct']);
const RULE_FILES = new Set(['.cursorrules', '.windsurfrules']);
const MCP_CONFIG_NAMES = new Set(['.mcp.json', 'mcp.json', 'claude_desktop_config.json', 'mcp_config.json', '.claude.json']);

/** Agent locations other than MCP client configs. Client configs come from src/clients/configs.ts. */
interface AgentLocation {
  segments: string[];
  /** Report target for user-level files that are not in a skill or plugin. Project files use the project's name. */
  label?: string;
  /** A skills directory: symlinked skill folders directly inside it are followed, since that is how people install them. */
  skills?: boolean;
}

const CLAUDE_USER = 'Claude Code (user)';

const USER_LOCATIONS: readonly AgentLocation[] = [
  { segments: ['.claude', 'skills'], label: CLAUDE_USER, skills: true },
  { segments: ['.claude', 'plugins'], label: CLAUDE_USER },
  { segments: ['.claude', 'commands'], label: CLAUDE_USER },
  { segments: ['.claude', 'agents'], label: CLAUDE_USER },
  { segments: ['.claude', 'hooks'], label: CLAUDE_USER },
  { segments: ['.claude', 'CLAUDE.md'], label: CLAUDE_USER },
  { segments: ['.claude', 'settings.json'], label: CLAUDE_USER },
  { segments: ['.claude', 'settings.local.json'], label: CLAUDE_USER },
  { segments: ['.codex', 'skills'], label: 'Codex', skills: true },
  { segments: ['.agents', 'skills'], label: 'Agent skills (user)', skills: true },
  { segments: ['.gemini', 'extensions'], label: 'Gemini CLI' },
];

const PROJECT_LOCATIONS: readonly AgentLocation[] = [
  { segments: ['.claude', 'settings.json'] },
  { segments: ['.claude', 'settings.local.json'] },
  { segments: ['.claude', 'skills'], skills: true },
  { segments: ['.claude', 'commands'] },
  { segments: ['.claude', 'agents'] },
  { segments: ['.claude', 'hooks'] },
  { segments: ['.claude', 'CLAUDE.md'] },
  { segments: ['CLAUDE.md'] },
  { segments: ['CLAUDE.local.md'] },
  { segments: ['AGENTS.md'] },
  { segments: ['GEMINI.md'] },
  { segments: ['.agents', 'skills'], skills: true },
];

/** What a file inherits from the directories above it. */
interface DirContext {
  /** Name of the nearest enclosing skill directory (one that holds SKILL.md). */
  skill?: string;
  /** Name of the nearest enclosing plugin (a directory with .claude-plugin/plugin.json). */
  plugin?: string;
  /** Somewhere under a commands/, agents/, rules/ or prompts/ directory. */
  inPromptDir: boolean;
}

interface Root {
  abs: string;
  /** Target for files that are not in a skill or plugin and are not a known client config. */
  label: string;
  skills: boolean;
  explicit: boolean;
}

/** The result of looking at a file name: a kind, or 'content' when only the content can tell. */
type NameKind = FileKind | 'content';

interface Candidate {
  abs: string;
  displayPath: string;
  ctx: DirContext;
  root: Root;
  nameKind: NameKind | null;
  /** The file was named on the command line, so it is scanned even when its kind is unknown. */
  explicitFile: boolean;
}

interface State {
  cwd: string;
  home: string;
  deep: boolean;
  maxFileBytes: number;
  maxFiles: number;
  ignore: IgnoreConfig | undefined;
  configs: Map<string, ClientConfigLocation>;
  candidates: Candidate[];
  skipped: SkippedFile[];
  roots: string[];
  seenFiles: Set<string>;
  seenDirs: Set<string>;
  capped: boolean;
}

/**
 * Finds the files to scan: the explicit paths, plus the known agent locations
 * when useDefaults is set. Walks iteratively, never follows directory symlinks
 * found during the walk (except symlinked skill folders directly inside a known
 * skills directory), skips vendored and cache directories unless deep is set,
 * and reports large, binary and unreadable files as skipped.
 */
export async function discover(options: DiscoverOptions): Promise<DiscoverResult> {
  const cwd = path.resolve(options.cwd);
  const state: State = {
    cwd,
    home: homeDir(),
    deep: options.deep ?? false,
    maxFileBytes: options.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES,
    maxFiles: options.maxFiles ?? DEFAULT_MAX_FILES,
    ignore: options.ignore,
    configs: new Map(CLIENT_CONFIGS.map((location) => [pathKey(location.resolve(cwd)), location])),
    candidates: [],
    skipped: [],
    roots: [],
    seenFiles: new Set(),
    seenDirs: new Set(),
    capped: false,
  };

  for (const raw of options.paths) {
    const abs = path.resolve(cwd, expandHome(raw));
    collectRoot({ abs, label: rootLabel(abs), skills: false, explicit: true }, state);
  }
  if (options.useDefaults) {
    for (const root of defaultRoots(cwd, state.home)) collectRoot(root, state);
  }

  const loaded = await mapPool(state.candidates, READ_CONCURRENCY, (candidate) => load(candidate, state));
  const files: ScanFile[] = [];
  const skipped = [...state.skipped];
  for (const item of loaded) {
    if (!item) continue;
    if ('reason' in item) skipped.push(item);
    else files.push(item);
  }
  return { files, skipped, roots: state.roots };
}

function defaultRoots(cwd: string, home: string): Root[] {
  const project = path.basename(cwd) || 'project';
  const roots: Root[] = [];
  for (const location of USER_LOCATIONS) {
    roots.push({ abs: path.join(home, ...location.segments), label: location.label ?? CLAUDE_USER, skills: location.skills ?? false, explicit: false });
  }
  for (const location of CLIENT_CONFIGS) {
    const label = location.scope === 'user' ? location.label : project;
    roots.push({ abs: location.resolve(cwd), label, skills: false, explicit: false });
  }
  for (const location of PROJECT_LOCATIONS) {
    roots.push({ abs: path.join(cwd, ...location.segments), label: project, skills: location.skills ?? false, explicit: false });
  }
  return roots;
}

function rootLabel(abs: string): string {
  return path.basename(abs) || toForwardSlashes(abs);
}

function collectRoot(root: Root, state: State): void {
  if (state.capped) return;
  let stat: fs.Stats;
  try {
    stat = fs.statSync(root.abs);
  } catch {
    if (root.explicit) state.skipped.push({ path: displayPathFor(root.abs, state), reason: 'not found' });
    return;
  }
  const display = displayPathFor(root.abs, state);
  if (stat.isDirectory()) {
    if (state.seenDirs.has(pathKey(root.abs)) || isDirIgnored(root.abs, state)) return;
    state.roots.push(display);
    const ctx = contextAbove(root.abs, 0);
    walk(root, { ...ctx, inPromptDir: ctx.inPromptDir || PROMPT_DIRS.has(path.basename(root.abs).toLowerCase()) }, state);
  } else if (stat.isFile()) {
    if (state.seenFiles.has(pathKey(root.abs)) || (state.ignore && isPathIgnored(display, state.ignore))) return;
    state.roots.push(display);
    const fileRoot = root.explicit ? { ...root, label: rootLabel(path.dirname(root.abs)) } : root;
    addCandidate(root.abs, contextAbove(path.dirname(root.abs), 3, true), fileRoot, state);
  } else if (root.explicit) {
    state.skipped.push({ path: display, reason: 'not a regular file or directory' });
  }
}

interface PendingDir {
  dir: string;
  ctx: DirContext;
  depth: number;
}

function walk(root: Root, base: DirContext, state: State): void {
  const stack: PendingDir[] = [{ dir: root.abs, ctx: base, depth: 0 }];
  while (stack.length > 0 && !state.capped) {
    const { dir, ctx: inherited, depth } = stack.pop()!;
    const key = pathKey(dir);
    if (state.seenDirs.has(key)) continue;
    state.seenDirs.add(key);
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch (error) {
      state.skipped.push({ path: displayPathFor(dir, state), reason: `unreadable directory (${errorCode(error)})` });
      continue;
    }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    const ctx = enterDir(dir, entries, inherited);
    const subdirs: PendingDir[] = [];
    for (const entry of entries) {
      if (state.capped) break;
      const abs = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!skipDirName(entry.name, state.deep) && !isDirIgnored(abs, state)) {
          subdirs.push({ dir: abs, ctx: childContext(ctx, entry.name), depth: depth + 1 });
        }
      } else if (entry.isSymbolicLink()) {
        visitLink(abs, entry.name, ctx, root, depth, subdirs, state);
      } else if (entry.isFile()) {
        addCandidate(abs, ctx, root, state);
      }
    }
    for (let i = subdirs.length - 1; i >= 0; i--) stack.push(subdirs[i]!);
  }
}

function visitLink(abs: string, name: string, ctx: DirContext, root: Root, depth: number, subdirs: PendingDir[], state: State): void {
  let stat: fs.Stats;
  try {
    stat = fs.statSync(abs);
  } catch {
    if (kindFromName(abs, ctx) !== null) state.skipped.push({ path: displayPathFor(abs, state), reason: 'broken symbolic link' });
    return;
  }
  if (stat.isFile()) {
    addCandidate(abs, ctx, root, state);
    return;
  }
  if (!stat.isDirectory() || skipDirName(name, state.deep) || isDirIgnored(abs, state)) return;
  if (root.skills && depth === 0) {
    subdirs.push({ dir: abs, ctx: childContext(ctx, name), depth: depth + 1 });
    return;
  }
  state.skipped.push({ path: displayPathFor(abs, state), reason: 'symbolic link to a directory, not followed (scan its target directly)' });
}

function skipDirName(name: string, deep: boolean): boolean {
  return deep ? name === '.git' : SKIP_DIRS.has(name);
}

function isDirIgnored(abs: string, state: State): boolean {
  if (!state.ignore || state.ignore.paths.length === 0) return false;
  const display = displayPathFor(abs, state);
  return isPathIgnored(display, state.ignore) || isPathIgnored(`${display}/`, state.ignore);
}

/** Context for the files of a directory, given its entries: does it hold SKILL.md or a plugin manifest? */
function enterDir(dir: string, entries: readonly fs.Dirent[], inherited: DirContext): DirContext {
  let ctx = inherited;
  if (entries.some((e) => e.name.toLowerCase() === 'skill.md' && !e.isDirectory())) ctx = { ...ctx, skill: path.basename(dir) };
  if (entries.some((e) => e.name === '.claude-plugin' && e.isDirectory())) {
    const plugin = pluginName(dir);
    if (plugin !== null) ctx = { ...ctx, plugin };
  }
  return ctx;
}

function childContext(ctx: DirContext, name: string): DirContext {
  if (ctx.inPromptDir || !PROMPT_DIRS.has(name.toLowerCase())) return ctx;
  return { ...ctx, inPromptDir: true };
}

/** The plugin name from dir/.claude-plugin/plugin.json, the directory name when it has none, or null when there is no manifest. */
function pluginName(dir: string): string | null {
  const manifest = path.join(dir, '.claude-plugin', 'plugin.json');
  let text: string;
  try {
    if (fs.statSync(manifest).size > MIB) return path.basename(dir);
    text = fs.readFileSync(manifest, 'utf8');
  } catch {
    return null;
  }
  const data = parseJsonc(text);
  const name = isRecord(data) && typeof data.name === 'string' ? truncate(printable(data.name.trim()), 80) : '';
  return name || path.basename(dir);
}

/**
 * Skill, plugin and prompt-directory context from the directories above a
 * scan root (dir itself included when includeSelf is set), so that scanning
 * one file or subfolder of a skill still attributes it to the skill. Looks at
 * most six levels up and never at or above the home directory.
 */
function contextAbove(dir: string, promptLevels: number, includeSelf = false): DirContext {
  const ctx: DirContext = { inPromptDir: false };
  const home = pathKey(homeDir());
  let current = path.resolve(includeSelf ? dir : path.dirname(dir));
  if (!includeSelf && current === path.resolve(dir)) return ctx;
  for (let level = 0; level < 6; level++) {
    if (pathKey(current) === home) break;
    const name = path.basename(current).toLowerCase();
    if (level < promptLevels && PROMPT_DIRS.has(name)) ctx.inPromptDir = true;
    if (ctx.skill === undefined && hasSkillFile(current)) ctx.skill = path.basename(current);
    if (ctx.plugin === undefined) {
      const plugin = pluginName(current);
      if (plugin !== null) ctx.plugin = plugin;
    }
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return ctx;
}

function hasSkillFile(dir: string): boolean {
  return fs.existsSync(path.join(dir, 'SKILL.md')) || fs.existsSync(path.join(dir, 'skill.md'));
}

function addCandidate(abs: string, ctx: DirContext, root: Root, state: State): void {
  const key = pathKey(abs);
  if (state.seenFiles.has(key)) return;
  const nameKind = kindFromName(abs, ctx);
  const explicitFile = root.explicit && pathKey(root.abs) === key;
  if (nameKind === null && !explicitFile) return;
  const displayPath = displayPathFor(abs, state);
  if (state.ignore && isPathIgnored(displayPath, state.ignore)) return;
  state.seenFiles.add(key);
  if (state.candidates.length >= state.maxFiles) {
    state.capped = true;
    state.skipped.push({
      path: displayPathFor(root.abs, state),
      reason: `stopped after ${state.maxFiles} files (file limit); files after this point were not scanned`,
    });
    return;
  }
  state.candidates.push({ abs, displayPath, ctx, root, nameKind, explicitFile });
}

async function load(candidate: Candidate, state: State): Promise<ScanFile | SkippedFile | null> {
  const { abs, displayPath } = candidate;
  const skip = (reason: string): SkippedFile => ({ path: displayPath, reason });
  const known = state.configs.get(pathKey(abs));
  const limit = Math.max(state.maxFileBytes, known?.maxBytes ?? 0);
  const byContent = candidate.nameKind === 'content' && !candidate.explicitFile;
  const extensionless = path.extname(abs) === '';

  let handle: fs.promises.FileHandle;
  try {
    handle = await fs.promises.open(abs, 'r');
  } catch (error) {
    return skip(`unreadable (${errorCode(error)})`);
  }
  let buffer: Buffer;
  try {
    const { size } = await handle.stat();
    // Extensionless files are only scripts with a shebang; most are licences, Makefiles or binaries.
    if (byContent && extensionless && (await readHead(handle, 2)) !== '#!') return null;
    if (size > limit) {
      // Oversized generic JSON is data, not something an agent loads by that name.
      if (byContent && !extensionless) return null;
      return skip(`larger than ${formatBytes(limit)}`);
    }
    buffer = await handle.readFile();
  } catch (error) {
    return skip(`unreadable (${errorCode(error)})`);
  } finally {
    await handle.close().catch(() => undefined);
  }
  const content = decodeText(buffer);
  if (content === null) return skip('binary file');

  let kind: FileKind | null = candidate.nameKind === 'content' ? kindFromContent(abs, content) : candidate.nameKind;
  if (kind === null) {
    if (!candidate.explicitFile) return null;
    kind = 'instructions';
  }
  const rootRelPath = path.relative(candidate.root.abs, abs).split(path.sep).join('/') || path.basename(abs);
  return { path: abs, displayPath, kind, content, target: targetFor(candidate, known), rootRelPath };
}

function targetFor(candidate: Candidate, known: ClientConfigLocation | undefined): string {
  if (known) return known.label;
  if (candidate.ctx.skill !== undefined) return `skill:${candidate.ctx.skill}`;
  if (candidate.ctx.plugin !== undefined) return `plugin:${candidate.ctx.plugin}`;
  return candidate.root.label;
}

/** The first bytes of an open file, read by position so a later readFile still starts at offset 0. */
async function readHead(handle: fs.promises.FileHandle, bytes: number): Promise<string> {
  const buffer = Buffer.alloc(bytes);
  const { bytesRead } = await handle.read(buffer, 0, bytes, 0);
  return buffer.subarray(0, bytesRead).toString('latin1');
}

/**
 * Decodes UTF-8, or UTF-16 when the file starts with a byte-order mark (as
 * Windows PowerShell writes scripts), and drops a leading BOM. Returns null for
 * binary content: a NUL byte in the first 8 KiB of a file without a UTF-16 BOM.
 */
function decodeText(buffer: Buffer): string | null {
  if (buffer.length >= 2 && buffer[0] === 0xff && buffer[1] === 0xfe) {
    return new TextDecoder('utf-16le').decode(buffer.subarray(2));
  }
  if (buffer.length >= 2 && buffer[0] === 0xfe && buffer[1] === 0xff) {
    const body = Buffer.from(buffer.subarray(2, 2 + ((buffer.length - 2) & ~1)));
    return new TextDecoder('utf-16le').decode(body.swap16());
  }
  if (buffer.subarray(0, BINARY_SNIFF_BYTES).includes(0)) return null;
  const text = buffer.toString('utf8');
  return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}

function formatBytes(bytes: number): string {
  if (bytes >= MIB && bytes % MIB === 0) return `${bytes / MIB} MiB`;
  if (bytes >= MIB) return `${(bytes / MIB).toFixed(1)} MiB`;
  if (bytes >= 1024) return `${Math.round(bytes / 1024)} KiB`;
  return `${bytes} bytes`;
}

function errorCode(error: unknown): string {
  return (error as NodeJS.ErrnoException).code ?? (error instanceof Error ? error.message : String(error));
}

function toForwardSlashes(p: string): string {
  return p.split(path.sep).join('/');
}

/** Relative path with forward slashes when abs is inside base ('' for base itself), otherwise null. */
function relativeInside(base: string, abs: string): string | null {
  const rel = path.relative(base, abs);
  if (rel === '') return '';
  if (rel === '..' || rel.startsWith(`..${path.sep}`) || path.isAbsolute(rel)) return null;
  return toForwardSlashes(rel);
}

/** Relative to cwd when inside it, '~/...' when inside the home directory, otherwise absolute; always forward slashes. */
function displayPathFor(abs: string, state: Pick<State, 'cwd' | 'home'>): string {
  const inCwd = relativeInside(state.cwd, abs);
  if (inCwd !== null) return inCwd || '.';
  const inHome = relativeInside(state.home, abs);
  if (inHome !== null) return inHome ? `~/${inHome}` : '~';
  return toForwardSlashes(abs);
}

/**
 * What a file is to an agent, from its path and (for generic JSON and
 * extensionless files) its content. Returns null for files toolmoat does not
 * scan. Skill and plugin membership is looked up on disk in the directories
 * above the file; content is read from disk when it is needed and not given.
 */
export function classifyFile(absPath: string, content?: string): FileKind | null {
  const ctx = contextAbove(path.dirname(absPath), 3, true);
  const kind = kindFromName(absPath, ctx);
  if (kind !== 'content') return kind;
  const text = content ?? readSmallText(absPath);
  return text === null ? null : kindFromContent(absPath, text);
}

function readSmallText(file: string): string | null {
  try {
    if (fs.statSync(file).size > DEFAULT_MAX_FILE_BYTES) return null;
    return decodeText(fs.readFileSync(file));
  } catch {
    return null;
  }
}

function kindFromName(absPath: string, ctx: DirContext): NameKind | null {
  const lower = path.basename(absPath).toLowerCase();
  const ext = path.extname(lower);
  const parent = path.basename(path.dirname(absPath)).toLowerCase();
  if (lower === 'skill.md') return 'skill';
  if (MARKDOWN_EXTS.has(ext)) return markdownKind(lower, ctx);
  if (RULE_FILES.has(lower)) return 'instructions';
  if (SCRIPT_EXTS.has(ext)) return 'script';
  if (ext === '.json') return jsonKind(lower, parent);
  if (ext === '.toml') {
    if (lower === 'pyproject.toml') return 'package-manifest';
    return lower === 'config.toml' && parent === '.codex' ? 'mcp-config' : null;
  }
  if (lower === 'requirements.txt') return 'package-manifest';
  if (ext === '') return 'content';
  return null;
}

function markdownKind(lower: string, ctx: DirContext): FileKind {
  if (AGENT_MARKDOWN.has(lower) || ctx.inPromptDir) return 'instructions';
  const stem = lower.slice(0, lower.indexOf('.') === -1 ? lower.length : lower.indexOf('.'));
  if (DOC_STEMS.has(stem)) return 'docs';
  return ctx.skill !== undefined || ctx.plugin !== undefined ? 'instructions' : 'docs';
}

function jsonKind(lower: string, parent: string): NameKind {
  if (lower === 'package.json') return 'package-manifest';
  if (parent === '.claude-plugin' && (lower === 'plugin.json' || lower === 'marketplace.json')) return 'plugin-manifest';
  if (parent === '.claude' && (lower === 'settings.json' || lower === 'settings.local.json')) return 'agent-settings';
  if (lower === 'hooks.json') return 'agent-settings';
  if (MCP_CONFIG_NAMES.has(lower)) return 'mcp-config';
  if (parent === '.gemini' && lower === 'settings.json') return 'mcp-config';
  return 'content';
}

/**
 * Generic JSON is an MCP config when it has top-level mcpServers, and agent
 * settings when it has Claude-style hooks (event names such as PreToolUse) or
 * a permissions block. Extensionless files are scripts when they start with #!.
 */
function kindFromContent(absPath: string, content: string): FileKind | null {
  const ext = path.extname(absPath).toLowerCase();
  if (ext === '') return content.startsWith('#!') ? 'script' : null;
  if (ext !== '.json') return null;
  const data = parseJsonc(content);
  if (!isRecord(data)) return null;
  if (data.mcpServers !== undefined) return 'mcp-config';
  if (isRecord(data.hooks) && Object.keys(data.hooks).some((key) => /^[A-Z][A-Za-z]{2,40}$/.test(key))) return 'agent-settings';
  if (isRecord(data.permissions) && ['allow', 'deny', 'ask', 'defaultMode'].some((key) => key in (data.permissions as object))) {
    return 'agent-settings';
  }
  return null;
}

async function mapPool<T, R>(items: readonly T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const index = next++;
      results[index] = await fn(items[index]!);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}
