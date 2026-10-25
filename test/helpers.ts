import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { scanFile } from '../src/scan/engine.js';
import type { FileKind, Finding, Rule, ScanFile } from '../src/types.js';

export const ROOT = path.resolve(import.meta.dirname, '..');
export const CLI = path.join(ROOT, 'dist', 'cli.js');
export const FIXTURES = path.join(ROOT, 'test', 'fixtures');

export function file(content: string, kind: FileKind, displayPath = `sample.${kind}`): ScanFile {
  return { path: path.join(ROOT, displayPath), displayPath, kind, content, target: 'sample' };
}

/** Runs the given rules (default: all) over one in-memory file. */
export function scan(content: string, kind: FileKind, rules?: readonly Rule[]): Finding[] {
  return scanFile(file(content, kind), rules ? { rules } : {});
}

export function ruleIds(findings: readonly Finding[]): string[] {
  return [...new Set(findings.map((f) => f.ruleId))].sort();
}

export function tempDir(prefix = 'toolmoat-'): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

export interface CliResult {
  status: number | null;
  stdout: string;
  stderr: string;
}

/** Runs the built CLI with an isolated TOOLMOAT_HOME unless the caller passes one. */
export function runCli(args: string[], options: { cwd?: string; env?: NodeJS.ProcessEnv; input?: string } = {}): CliResult {
  const result = spawnSync(process.execPath, [CLI, ...args], {
    cwd: options.cwd ?? ROOT,
    env: { ...process.env, NO_COLOR: '1', TOOLMOAT_HOME: tempDir('toolmoat-home-'), ...options.env },
    input: options.input,
    encoding: 'utf8',
    timeout: 30_000,
  });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}
