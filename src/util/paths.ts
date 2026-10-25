import os from 'node:os';
import path from 'node:path';

export function homeDir(): string {
  return process.env.TOOLMOAT_TEST_USER_HOME ?? os.homedir();
}

/** Expands a leading ~ to the user's home directory. */
export function expandHome(p: string): string {
  if (p === '~') return homeDir();
  if (p.startsWith('~/') || p.startsWith('~\\')) return path.join(homeDir(), p.slice(2));
  return p;
}

/** Where toolmoat keeps its lockfile and audit logs. Override with TOOLMOAT_HOME. */
export function toolmoatHome(): string {
  return process.env.TOOLMOAT_HOME ?? path.join(homeDir(), '.toolmoat');
}

/** Forward-slash path relative to root when the file is inside it, otherwise the absolute path. */
export function toDisplayPath(absPath: string, root?: string): string {
  if (absPath.includes('://')) return absPath;
  let shown = absPath;
  if (root) {
    const rel = path.relative(root, absPath);
    if (rel && !rel.startsWith('..') && !path.isAbsolute(rel)) shown = rel;
  }
  return shown.split(path.sep).join('/');
}

/** Platform-specific application-data directory (APPDATA on Windows, ~/Library/Application Support on macOS, XDG_CONFIG_HOME elsewhere). */
export function appDataDir(): string {
  if (process.platform === 'win32') return process.env.APPDATA ?? path.join(homeDir(), 'AppData', 'Roaming');
  if (process.platform === 'darwin') return path.join(homeDir(), 'Library', 'Application Support');
  return process.env.XDG_CONFIG_HOME ?? path.join(homeDir(), '.config');
}
