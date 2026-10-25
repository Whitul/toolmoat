import { matchesGlob } from '../util/glob.js';

/**
 * User-controlled suppressions, read from .toolmoatignore in the directory
 * toolmoat runs from (or --ignore-file). Ignore files and comments inside a
 * scanned artifact are never honoured: the artifact is the thing under
 * suspicion, so it must not be able to switch the scanner off.
 */
export interface IgnoreConfig {
  /** Rule ids suppressed everywhere. */
  rules: Set<string>;
  /** Globs for files skipped entirely. */
  paths: string[];
  /** Rule ids suppressed only for files matching the glob. */
  pathRules: { pattern: string; ruleId: string }[];
}

export function emptyIgnore(): IgnoreConfig {
  return { rules: new Set(), paths: [], pathRules: [] };
}

const RULE_ID = /^TM-[A-Z]+-\d{3}$/;

/**
 * Format, one entry per line, # for comments:
 *   TM-PI-001              suppress a rule everywhere
 *   test/fixtures/**       skip matching files
 *   docs/*.md:TM-PI-001    suppress a rule for matching files only
 */
export function parseIgnoreFile(text: string): IgnoreConfig {
  const config = emptyIgnore();
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    if (RULE_ID.test(line)) {
      config.rules.add(line);
      continue;
    }
    const scoped = /^(.+):(TM-[A-Z]+-\d{3})$/.exec(line);
    if (scoped) config.pathRules.push({ pattern: scoped[1]!, ruleId: scoped[2]! });
    else config.paths.push(line);
  }
  return config;
}

export function mergeIgnore(a: IgnoreConfig, b: IgnoreConfig): IgnoreConfig {
  return {
    rules: new Set([...a.rules, ...b.rules]),
    paths: [...a.paths, ...b.paths],
    pathRules: [...a.pathRules, ...b.pathRules],
  };
}

export function isPathIgnored(displayPath: string, ignore: IgnoreConfig): boolean {
  return ignore.paths.some((pattern) => matchesGlob(displayPath, pattern));
}

export function isFindingIgnored(ruleId: string, displayPath: string, ignore: IgnoreConfig): boolean {
  if (ignore.rules.has(ruleId)) return true;
  if (isPathIgnored(displayPath, ignore)) return true;
  return ignore.pathRules.some((entry) => entry.ruleId === ruleId && matchesGlob(displayPath, entry.pattern));
}
