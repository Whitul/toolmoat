import path from 'node:path';
import { redactSecrets } from '../patterns/secrets.js';
import { printable, truncate } from '../util/text.js';

/** Package runners whose first positional argument names the package that is the server. */
const PACKAGE_RUNNERS = new Set(['npx', 'bunx', 'uvx', 'pnpx']);
/** Runners that take a subcommand first: `pnpm dlx pkg`, `npm exec pkg`, `pipx run pkg`. */
const SUBCOMMAND_RUNNERS: Record<string, readonly string[]> = {
  pnpm: ['dlx', 'exec'],
  yarn: ['dlx', 'exec'],
  npm: ['exec', 'x'],
  pipx: ['run'],
  bun: ['x', 'run'],
  uv: ['run', 'tool'],
};
/** Interpreters whose first positional argument is the server script. */
const INTERPRETERS = new Set(['node', 'nodejs', 'python', 'python3', 'py', 'deno', 'tsx', 'ts-node', 'bun', 'ruby', 'php', 'java']);
/** Options of runners and interpreters that consume the next argument. */
const VALUE_OPTIONS = new Set([
  '-p', '--package', '--from', '--with', '--python', '--directory', '--project', '--index-url', '--spec', '--registry',
  '--cache', '--userconfig', '-r', '--require', '--import', '--loader', '--env-file', '-c', '--config', '--cwd',
  '-e', '--env', '-v', '--volume', '--name', '--network', '-w', '--workdir', '-u', '--user', '--mount', '--entrypoint',
  '--platform', '-l', '--label', '--publish', '--add-host', '--cpus', '-m', '--memory',
]);
/** Script names too generic to identify a server; the closest meaningful directory is used instead. */
const GENERIC_SCRIPTS = new Set(['index', 'main', 'server', 'cli', 'app', 'run', 'start', '__main__', 'mod', 'bin']);
const BUILD_DIRS = new Set(['dist', 'build', 'out', 'lib', 'src', 'bin', 'build-output', '.']);

/**
 * Derives a stable lockfile id from a server command: the npm/PyPI package
 * for package runners (npx -y @scope/pkg@1.2 -> @scope/pkg), the script name
 * for interpreters (node path/to/weather-server.js -> weather-server), the
 * image for docker run, otherwise the executable's base name.
 */
export function deriveServerName(command: string, args: readonly string[]): string {
  const base = executableName(command);
  let rest = [...args];
  const subcommands = SUBCOMMAND_RUNNERS[base];
  if (subcommands && rest[0] !== undefined && subcommands.includes(rest[0])) {
    rest = rest.slice(1);
    const target = firstPositional(rest);
    if (target !== undefined && looksLikeScript(target)) return cleanName(scriptName(rest) ?? base);
    return cleanName(packageName(rest) ?? base);
  }
  if (PACKAGE_RUNNERS.has(base)) return cleanName(packageName(rest) ?? base);
  if (base === 'docker' || base === 'podman') return cleanName(imageName(rest) ?? base);
  if (INTERPRETERS.has(base)) return cleanName(scriptName(rest) ?? base);
  return cleanName(base);
}

function executableName(command: string): string {
  const name = path.win32.basename(path.posix.basename(command));
  return name.replace(/\.(?:exe|cmd|bat|com|ps1|sh)$/i, '').toLowerCase();
}

function packageName(args: readonly string[]): string | undefined {
  const explicit = optionValue(args, ['-p', '--package', '--from']);
  const spec = explicit ?? firstPositional(args);
  return spec === undefined ? undefined : stripVersion(spec);
}

function stripVersion(spec: string): string {
  const scoped = spec.startsWith('@');
  const at = spec.indexOf('@', scoped ? 1 : 0);
  let name = at > 0 ? spec.slice(0, at) : spec;
  name = name.replace(/(?:==|>=|<=|~=|!=)[^\s]{0,100}$/, '').replace(/\[[^\]]{0,100}\]$/, '');
  return name || spec;
}

function imageName(args: readonly string[]): string | undefined {
  const runIndex = args.findIndex((a) => a === 'run');
  const image = firstPositional(runIndex === -1 ? args : args.slice(runIndex + 1));
  if (!image) return undefined;
  const last = image.split('/').pop() ?? image;
  return last.replace(/[:@][^/]{0,200}$/, '') || last;
}

function scriptName(args: readonly string[]): string | undefined {
  const moduleName = optionValue(args, ['-m']);
  if (moduleName) return moduleName;
  const script = firstPositional(args);
  if (!script) return undefined;
  const parts = script.split(/[\\/]+/).filter(Boolean);
  const file = parts.pop() ?? script;
  const stem = file.replace(/\.(?:[cm]?[jt]s|py|rb|php|jar)$/i, '');
  if (!GENERIC_SCRIPTS.has(stem.toLowerCase())) return stem;
  for (let i = parts.length - 1; i >= 0; i--) {
    const dir = parts[i]!;
    if (!BUILD_DIRS.has(dir.toLowerCase()) && !/^[a-z]:$/i.test(dir)) return dir;
  }
  return stem;
}

function looksLikeScript(arg: string): boolean {
  if (arg.startsWith('@')) return false;
  return /[\\/]/.test(arg) || /\.(?:[cm]?[jt]s|py|rb|php|jar)$/i.test(arg);
}

function firstPositional(args: readonly string[]): string | undefined {
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (arg === '--') return args[i + 1];
    if (!arg.startsWith('-')) return arg;
    if (!arg.includes('=') && VALUE_OPTIONS.has(arg)) i++;
  }
  return undefined;
}

function optionValue(args: readonly string[], names: readonly string[]): string | undefined {
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (arg === '--') return undefined;
    for (const name of names) {
      if (arg === name) return args[i + 1];
      if (arg.startsWith(`${name}=`)) return arg.slice(name.length + 1);
    }
  }
  return undefined;
}

function cleanName(name: string): string {
  const cleaned = name.replace(/[^A-Za-z0-9@/._-]+/g, '-').replace(/^-+|-+$/g, '');
  return cleaned.slice(0, 120) || 'mcp-server';
}

/** A file name for the server's audit log: no separators or characters Windows rejects. */
export function fileSafeName(name: string): string {
  const safe = name.replace(/[^A-Za-z0-9._@-]+/g, '_').replace(/^[.]+/, '');
  return safe.slice(0, 120) || 'server';
}

/** Quotes an argument for display in a copy-pasteable command when it needs it. */
export function shellQuote(arg: string): string {
  if (arg !== '' && /^[A-Za-z0-9@%+=:,./_~-]+$/.test(arg)) return arg;
  return `"${arg.replace(/(["\\$`])/g, '\\$1')}"`;
}

/** The command line as stored in the lockfile and shown to users. */
export function formatCommand(command: string, args: readonly string[]): string {
  return [command, ...args].map(shellQuote).join(' ');
}

const SECRET_NAME = '(?<![a-z])(?:token|secret|passw(?:or)?d|pwd|api[-_]?key|credential|auth(?:orization)?)s?(?![a-z])';
const SECRET_VALUE = `("[^"]*"|'[^']*'|[^\\s"'&-][^\\s"'&]*)`;
/** name=value, as in KEY=..., --key=... and ?key=... */
const SECRET_ASSIGNMENT = new RegExp(`((?:^|[\\s"'?&;])[\\w.-]*${SECRET_NAME}[\\w.-]*)(=)${SECRET_VALUE}`, 'gi');
/** --key value: only for options, since a bare name followed by a word is usually a variable passed by name (docker -e TOKEN image). */
const SECRET_OPTION = new RegExp(`((?:^|\\s)--?[\\w.-]*${SECRET_NAME}[\\w.-]*)(\\s+)${SECRET_VALUE}`, 'gi');

/**
 * Masks credentials in a command line before it is stored in the lockfile (meant to be
 * reviewed and committed) or the audit log: known token formats, passwords inside URLs,
 * bearer and basic credentials, and the values of options and variables whose names say
 * token, secret, password, key or auth.
 */
export function redactCommandLine(line: string): string {
  return redactSecrets(line)
    .replace(/\b([a-z][a-z0-9+.-]*:\/\/[^\s:/@"']+:)[^\s@/"']+@/gi, '$1[redacted]@')
    .replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}/gi, '$1 [redacted]')
    .replace(SECRET_ASSIGNMENT, '$1$2[redacted]')
    .replace(SECRET_OPTION, '$1$2[redacted]');
}

/**
 * Makes attacker-controlled text (tool names, descriptions, rule messages)
 * safe for a terminal: control, C1, bidi, zero-width and tag characters
 * become visible escapes, so nothing can move the cursor, recolor output or
 * hide inside a line. Optionally truncates.
 */
export function safeText(text: string, max?: number): string {
  let out = printable(text).replace(/[\u0080-\u009f]/g, (ch) => `\\u${ch.charCodeAt(0).toString(16).padStart(4, '0')}`);
  if (max !== undefined) out = truncate(out, max);
  return out;
}
