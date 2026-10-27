import fs from 'node:fs';
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

/**
 * On Windows, a UNC path (\\host\share, //host/share, \\?\UNC\...) or a
 * device-namespace path (\\.\pipe\x, \\?\...). Touching one can open an SMB
 * connection that sends the user's credentials, or connect to a named pipe,
 * so code that must stay offline checks the string before any fs call.
 */
export function isRemoteOrDevicePath(p: string, platform: NodeJS.Platform = process.platform): boolean {
  if (platform !== 'win32') return false;
  return /^[\\/]{2}/.test(p);
}

/** Symbolic links followed before linksOffMachine gives up and treats the path as unsafe. */
const MAX_LINK_HOPS = 16;

/**
 * True when abs, or a directory on the way to it, is a symbolic link that
 * leads (directly or through other links) to a UNC or device path. Only lstat
 * and readlink are used, which never follow a link, so the check itself stays
 * on this machine. Always false outside Windows.
 */
export function linksOffMachine(abs: string, hops = 0): boolean {
  if (process.platform !== 'win32') return false;
  if (isRemoteOrDevicePath(abs)) return true;
  const resolved = path.resolve(abs);
  const root = path.parse(resolved).root;
  const parts = resolved.slice(root.length).split(path.sep).filter(Boolean);
  let current = root;
  for (let i = 0; i < parts.length; i++) {
    current = path.join(current, parts[i]!);
    let target: string;
    try {
      if (!fs.lstatSync(current).isSymbolicLink()) continue;
      target = fs.readlinkSync(current);
    } catch {
      return false;
    }
    if (isRemoteOrDevicePath(target) || hops >= MAX_LINK_HOPS) return true;
    return linksOffMachine(path.resolve(path.dirname(current), target, ...parts.slice(i + 1)), hops + 1);
  }
  return false;
}
