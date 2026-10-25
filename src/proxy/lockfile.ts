import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type { Severity } from '../types.js';
import { toolmoatHome } from '../util/paths.js';
import { canonicalJson, getOwn, setOwn } from './canonical.js';
import type { ToolDefinition } from './fingerprint.js';

/**
 * The lockfile pins every MCP tool definition the proxy has accepted, and
 * holds definitions waiting for a human decision. It is plain, sorted JSON so
 * it can be reviewed and committed.
 */

export interface PinnedTool {
  hash: string;
  definition: ToolDefinition;
  pinnedAt: string;
}

export type PendingReason = 'changed' | 'new' | 'flagged';

export interface FindingSummary {
  ruleId: string;
  severity: Severity;
  message: string;
}

export interface PendingTool {
  hash: string;
  definition: ToolDefinition;
  detectedAt: string;
  reason: PendingReason;
  findings: FindingSummary[];
}

export interface ServerEntry {
  command: string;
  firstSeen: string;
  updated: string;
  tools: Record<string, PinnedTool>;
  pending: Record<string, PendingTool>;
}

export interface Lockfile {
  version: 1;
  servers: Record<string, ServerEntry>;
}

export class LockfileError extends Error {
  override name = 'LockfileError';
}

/** <toolmoat home>/lock.json */
export function defaultLockPath(): string {
  return path.join(toolmoatHome(), 'lock.json');
}

export function emptyLockfile(): Lockfile {
  return { version: 1, servers: {} };
}

/** Reads and validates a lockfile. A missing file is an empty lockfile; a corrupt one throws LockfileError. */
export function readLockfile(file: string): Lockfile {
  let text: string;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (error) {
    if (errorCode(error) === 'ENOENT') return emptyLockfile();
    throw new LockfileError(`cannot read lockfile ${file}: ${errorMessage(error)}`);
  }
  if (text.trim() === '') return emptyLockfile();
  let data: unknown;
  try {
    data = JSON.parse(text.replace(/^﻿/, ''));
  } catch (error) {
    throw new LockfileError(`lockfile ${file} is not valid JSON: ${errorMessage(error)}`);
  }
  return validateLockfile(data, file);
}

function validateLockfile(data: unknown, file: string): Lockfile {
  if (!isObject(data)) throw new LockfileError(`lockfile ${file} must contain a JSON object`);
  if (data.version !== 1) throw new LockfileError(`lockfile ${file} has unsupported version ${JSON.stringify(data.version)} (expected 1)`);
  const servers = data.servers ?? {};
  if (!isObject(servers)) throw new LockfileError(`lockfile ${file}: "servers" must be an object`);
  const out: Lockfile = emptyLockfile();
  for (const [name, entry] of Object.entries(servers)) {
    if (!isObject(entry)) throw new LockfileError(`lockfile ${file}: server "${name}" must be an object`);
    setOwn(out.servers, name, normalizeEntry(entry));
  }
  return out;
}

function normalizeEntry(entry: Record<string, unknown>): ServerEntry {
  return {
    command: typeof entry.command === 'string' ? entry.command : '',
    firstSeen: typeof entry.firstSeen === 'string' ? entry.firstSeen : '',
    updated: typeof entry.updated === 'string' ? entry.updated : '',
    tools: recordOf(entry.tools, normalizePinned),
    pending: recordOf(entry.pending, normalizePending),
  };
}

function recordOf<T>(value: unknown, normalize: (item: Record<string, unknown>) => T | undefined): Record<string, T> {
  const out: Record<string, T> = {};
  if (!isObject(value)) return out;
  for (const [key, item] of Object.entries(value)) {
    const normalized = isObject(item) ? normalize(item) : undefined;
    if (normalized !== undefined) setOwn(out, key, normalized);
  }
  return out;
}

function normalizePinned(item: Record<string, unknown>): PinnedTool | undefined {
  if (typeof item.hash !== 'string' || !isObject(item.definition)) return undefined;
  return { hash: item.hash, definition: item.definition, pinnedAt: typeof item.pinnedAt === 'string' ? item.pinnedAt : '' };
}

function normalizePending(item: Record<string, unknown>): PendingTool | undefined {
  if (typeof item.hash !== 'string' || !isObject(item.definition)) return undefined;
  if (item.reason !== 'changed' && item.reason !== 'new' && item.reason !== 'flagged') return undefined;
  return {
    hash: item.hash,
    definition: item.definition,
    detectedAt: typeof item.detectedAt === 'string' ? item.detectedAt : '',
    reason: item.reason,
    findings: Array.isArray(item.findings) ? (item.findings.filter(isObject) as unknown as FindingSummary[]) : [],
  };
}

/** Serializes with stable key order so the file diffs cleanly in version control. */
export function serializeLockfile(lock: Lockfile): string {
  const servers: Record<string, ServerEntry> = {};
  for (const name of Object.keys(lock.servers).sort()) {
    const entry = lock.servers[name]!;
    setOwn(servers, name, {
      command: entry.command,
      firstSeen: entry.firstSeen,
      updated: entry.updated,
      tools: sortedRecord(entry.tools),
      pending: sortedRecord(entry.pending),
    });
  }
  return `${JSON.stringify({ version: 1, servers }, null, 2)}\n`;
}

function sortedRecord<T>(record: Record<string, T>): Record<string, T> {
  const out: Record<string, T> = {};
  for (const key of Object.keys(record).sort()) setOwn(out, key, JSON.parse(canonicalJson(record[key])) as T);
  return out;
}

/** Writes the whole lockfile atomically: temp file in the same directory, fsync, rename. */
export function writeLockfile(file: string, lock: Lockfile): void {
  atomicWrite(file, serializeLockfile(lock));
}

/**
 * Read-modify-write of one server's entry under an advisory lock. The file is
 * re-read inside the lock and only this server's entry is replaced, so
 * several proxies (and `toolmoat approve`) can share one lockfile. `mutate`
 * gets a private copy of the current entry and returns the new one, or
 * undefined to remove the server. Returns the entry that was written.
 */
export function updateServer(
  file: string,
  name: string,
  mutate: (current: ServerEntry | undefined) => ServerEntry | undefined,
): ServerEntry | undefined {
  return withFileLock(file, () => {
    const lock = readLockfile(file);
    const before = getOwn(lock.servers, name);
    const next = mutate(before === undefined ? undefined : structuredClone(before));
    if (canonicalJson(next ?? null) === canonicalJson(before ?? null)) return before;
    if (next === undefined) delete lock.servers[name];
    else setOwn(lock.servers, name, next);
    writeLockfile(file, lock);
    return next;
  });
}

const RETRYABLE = new Set(['EPERM', 'EBUSY', 'EACCES']);

function atomicWrite(file: string, data: string): void {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`;
  const fd = fs.openSync(tmp, 'w');
  try {
    fs.writeSync(fd, data);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  for (let attempt = 0; ; attempt++) {
    try {
      fs.renameSync(tmp, file);
      return;
    } catch (error) {
      if (attempt < 10 && RETRYABLE.has(errorCode(error) ?? '')) {
        sleepSync(Math.min(10 * 2 ** attempt, 200));
        continue;
      }
      try {
        fs.unlinkSync(tmp);
      } catch {
        // The temp file may already be gone; the original error is what matters.
      }
      throw error;
    }
  }
}

const LOCK_TIMEOUT_MS = 3000;
const STALE_LOCK_MS = 10_000;

/** Runs fn while holding <file>.lock, created with O_EXCL. Locks left by dead processes are broken. */
export function withFileLock<T>(file: string, fn: () => T): T {
  const lockPath = `${file}.lock`;
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const deadline = Date.now() + LOCK_TIMEOUT_MS;
  for (let attempt = 0; ; attempt++) {
    try {
      const fd = fs.openSync(lockPath, 'wx');
      fs.writeSync(fd, String(process.pid));
      fs.closeSync(fd);
      break;
    } catch (error) {
      const code = errorCode(error);
      if (code !== 'EEXIST' && !RETRYABLE.has(code ?? '')) throw error;
      if (code === 'EEXIST' && isStaleLock(lockPath)) {
        try {
          fs.unlinkSync(lockPath);
        } catch {
          // Another process broke the stale lock first.
        }
        continue;
      }
      if (Date.now() > deadline) throw new LockfileError(`lockfile ${file} is locked by another process (${lockPath})`);
      sleepSync(Math.min(5 + attempt * 2, 25));
    }
  }
  try {
    return fn();
  } finally {
    try {
      fs.unlinkSync(lockPath);
    } catch {
      // Nothing useful to do if the lock vanished.
    }
  }
}

/**
 * A lock is stale when it is too old or its owner process is gone. The file is
 * checked again after the liveness probe: the owner may have released the lock
 * and exited while we looked, and the path may now hold another process's
 * live lock, which must not be broken.
 */
function isStaleLock(lockPath: string): boolean {
  try {
    const before = fs.statSync(lockPath);
    const owner = fs.readFileSync(lockPath, 'utf8');
    const pid = Number.parseInt(owner, 10);
    const expired = Date.now() - before.mtimeMs > STALE_LOCK_MS;
    const orphaned = Number.isInteger(pid) && pid > 0 && pid !== process.pid && !processAlive(pid);
    if (!expired && !orphaned) return false;
    const after = fs.statSync(lockPath);
    return after.ino === before.ino && after.mtimeMs === before.mtimeMs && fs.readFileSync(lockPath, 'utf8') === owner;
  } catch {
    return false;
  }
}

function processAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return errorCode(error) === 'EPERM';
  }
}

const sleepCell = new Int32Array(new SharedArrayBuffer(4));

function sleepSync(ms: number): void {
  Atomics.wait(sleepCell, 0, 0, ms);
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function errorCode(error: unknown): string | undefined {
  return isObject(error) && typeof error.code === 'string' ? error.code : undefined;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
