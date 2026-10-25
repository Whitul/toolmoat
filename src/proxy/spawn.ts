import { spawnSync } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

/** How to start the MCP server: the file to execute and its exact arguments. */
export interface SpawnPlan {
  file: string;
  args: string[];
  /** Set when args are a pre-escaped cmd.exe command line that Node must not quote again. */
  windowsVerbatimArguments: boolean;
  /** The server runs under cmd.exe, so stopping it means stopping a process tree. */
  viaShell: boolean;
}

export interface PlanContext {
  platform: NodeJS.Platform;
  env: NodeJS.ProcessEnv;
  cwd: string;
  /** Whether a path is a regular file. Defaults to the real file system; tests inject one to plan for Windows anywhere. */
  isFile?: (candidate: string) => boolean;
}

/**
 * Works out how to launch a server command. Elsewhere Node resolves PATH
 * itself. On Windows the command is resolved through PATH and PATHEXT here,
 * because most MCP servers start through .cmd shims (npx.cmd, pnpm.cmd...)
 * that Node refuses to spawn without a shell since the CVE-2024-27980 fix;
 * those run through cmd.exe with every argument escaped for it.
 */
export function planSpawn(command: string, args: readonly string[], ctx: PlanContext): SpawnPlan | { error: string } {
  if (ctx.platform !== 'win32') return { file: command, args: [...args], windowsVerbatimArguments: false, viaShell: false };
  const resolved = resolveWindowsCommand(command, ctx.env, ctx.cwd, ctx.isFile);
  if (!resolved) return { error: `command not found: ${command} (searched PATH with PATHEXT)` };
  if (!/\.(?:cmd|bat)$/i.test(resolved)) return { file: resolved, args: [...args], windowsVerbatimArguments: false, viaShell: false };
  const unsafe = [resolved, ...args].find((arg) => /[\r\n\0]/.test(arg));
  if (unsafe !== undefined) return { error: 'cannot pass an argument containing a line break or NUL to a .cmd/.bat server through cmd.exe' };
  const line = [escapeCmdCommand(resolved), ...args.map(escapeCmdArgument)].join(' ');
  return {
    file: envValue(ctx.env, 'ComSpec') ?? 'cmd.exe',
    args: ['/d', '/s', '/c', `"${line}"`],
    windowsVerbatimArguments: true,
    viaShell: true,
  };
}

/** Case-insensitive environment lookup, as Windows itself does. */
export function envValue(env: NodeJS.ProcessEnv, name: string): string | undefined {
  const upper = name.toUpperCase();
  for (const [key, value] of Object.entries(env)) if (key.toUpperCase() === upper && value !== undefined) return value;
  return undefined;
}

/**
 * Finds the file Windows would run for a command, trying each PATHEXT
 * extension in each PATH directory. Paths containing a separator resolve
 * against cwd. Unlike cmd.exe, a bare name is never looked up in the current
 * directory, so a planted npx.cmd in a project cannot hijack the server.
 */
export function resolveWindowsCommand(command: string, env: NodeJS.ProcessEnv, cwd: string, exists: (candidate: string) => boolean = isFile): string | undefined {
  const win = path.win32;
  const exts = (envValue(env, 'PATHEXT') ?? '.COM;.EXE;.BAT;.CMD').split(';').map((e) => e.trim()).filter(Boolean);
  const ext = win.extname(command);
  const hasKnownExt = ext !== '' && exts.some((e) => e.toLowerCase() === ext.toLowerCase());
  const names = hasKnownExt ? [command] : [...exts.map((e) => command + e.toLowerCase()), ...(ext ? [command] : [])];
  const hasSeparator = /[\\/]/.test(command) || win.isAbsolute(command);
  const dirs = hasSeparator
    ? [cwd]
    : (envValue(env, 'PATH') ?? '').split(';').map((d) => d.trim().replace(/^"(.*)"$/, '$1')).filter(Boolean);
  for (const dir of dirs) {
    for (const name of names) {
      const candidate = win.resolve(dir, name);
      if (exists(candidate)) return candidate;
    }
  }
  return undefined;
}

function isFile(p: string): boolean {
  try {
    return fs.statSync(p).isFile();
  } catch {
    return false;
  }
}

const CMD_META = /([()\][%!^"`<>&|;, *?])/g;

/** Escapes the program path of a cmd.exe command line by putting a caret before every metacharacter (as cross-spawn does). */
export function escapeCmdCommand(command: string): string {
  return path.win32.normalize(command).replace(CMD_META, '^$1');
}

/**
 * Escapes one argument for `cmd.exe /d /s /c "<line>"` when the target is a
 * batch file: quote it the way CommandLineToArgvW expects
 * (https://qntm.org/cmd), then caret-escape metacharacters twice, because
 * cmd.exe parses the line once to start the batch file and again when the
 * batch file expands %* (npx.cmd, npm and pnpm shims all do). Escaping only
 * once lets an argument such as `say "hi" & calc` run calc.
 */
export function escapeCmdArgument(arg: string): string {
  return quoteForArgv(arg).replace(CMD_META, '^$1').replace(CMD_META, '^$1');
}

/** Quotes an argument so CommandLineToArgvW reads it back unchanged: backslashes before a quote or the end are doubled. */
export function quoteForArgv(arg: string): string {
  let out = '"';
  let slashes = 0;
  for (const ch of arg) {
    if (ch === '\\') {
      slashes++;
      continue;
    }
    out += ch === '"' ? `${'\\'.repeat(slashes * 2 + 1)}"` : `${'\\'.repeat(slashes)}${ch}`;
    slashes = 0;
  }
  return `${out}${'\\'.repeat(slashes * 2)}"`;
}

/** Stops the server. On Windows the whole tree goes, since killing cmd.exe alone would orphan the real server. */
export function killServer(child: ChildProcess, platform: NodeJS.Platform = process.platform): void {
  if (child.exitCode !== null || child.signalCode !== null) return;
  if (platform === 'win32' && child.pid !== undefined) {
    spawnSync('taskkill', ['/pid', String(child.pid), '/T', '/F'], { stdio: 'ignore', windowsHide: true });
    return;
  }
  child.kill('SIGTERM');
}
