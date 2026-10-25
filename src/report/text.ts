import path from 'node:path';
import { countBySeverity } from '../scan/engine.js';
import type { Finding, ScanResult, Severity } from '../types.js';
import { SEVERITIES } from '../types.js';
import type { Palette } from '../util/colors.js';
import { palette } from '../util/colors.js';
import { homeDir } from '../util/paths.js';
import { printable } from '../util/text.js';
import { VERSION } from '../version.js';
import type { ReportOptions } from './index.js';

const BADGE_WIDTH = 'CRITICAL'.length;
const WRAP_WIDTH = 100;
const MAX_HEADER_ROOTS = 4;

/**
 * Renders findings for a terminal or a CI log: grouped by target, then file,
 * with remediation once per rule at the end. Output is ASCII apart from the
 * ellipsis in truncated snippets, and every attacker-influenced string goes
 * through printable() so a scanned file cannot inject terminal escapes.
 */
export function renderText(result: ScanResult, options: ReportOptions = {}): string {
  const c = palette(process.stdout, options.color ?? false);
  const cwd = options.cwd ?? process.cwd();
  const lines: string[] = [];

  if (!options.quiet) {
    lines.push(header(result, options, cwd));
    if (result.filesScanned === 0) lines.push('No agent skills, plugins, hooks or MCP configs were found.');
    if (options.ignoreFile) lines.push(c.gray(`Ignore file: ${printable(options.ignoreFile)}`));
    lines.push('');
  }

  for (const group of groupByTarget(result.findings)) {
    lines.push(`${c.bold(group.label)} ${c.gray(`(${plural(group.findings.length, 'finding')})`)}`);
    for (const finding of group.findings) lines.push(...findingBlock(finding, c), '');
  }

  if (!options.quiet) {
    lines.push(...remediationSection(result.findings, c));
    lines.push(...footer(result, options, c));
  }

  while (lines.length > 0 && lines[lines.length - 1] === '') lines.pop();
  return lines.length === 0 ? '' : `${lines.join('\n')}\n`;
}

function header(result: ScanResult, options: ReportOptions, cwd: string): string {
  const version = options.version ?? VERSION;
  let text = `toolmoat ${version} scanned ${plural(result.filesScanned, 'file')} in ${plural(result.targets.length, 'target')}`;
  const roots = (options.roots ?? []).map((root) => printable(shortPath(root, cwd)));
  if (roots.length > 0) {
    const shown = options.verbose || roots.length <= MAX_HEADER_ROOTS ? roots : [...roots.slice(0, MAX_HEADER_ROOTS - 1), `+${roots.length - MAX_HEADER_ROOTS + 1} more`];
    text += ` (${shown.join(', ')})`;
  }
  return `${text} in ${formatDuration(result.durationMs)}`;
}

function findingBlock(finding: Finding, c: Palette): string[] {
  const lines = [
    `  ${badge(finding.severity, c)}  ${c.cyan(finding.ruleId)}  ${c.bold(printable(finding.title))}`,
    `    ${location(finding)}  ${printable(finding.message)}`,
  ];
  if (finding.snippet) lines.push(`    ${c.gray(`> ${printable(finding.snippet)}`)}`);
  return lines;
}

function remediationSection(findings: readonly Finding[], c: Palette): string[] {
  const seen = new Set<string>();
  const lines: string[] = [];
  for (const finding of findings) {
    if (!finding.remediation || seen.has(finding.ruleId)) continue;
    seen.add(finding.ruleId);
    lines.push(`  ${c.cyan(finding.ruleId)}  ${c.bold(printable(finding.title))}`);
    lines.push(...wrapText(finding.remediation, WRAP_WIDTH, '    '));
  }
  return lines.length === 0 ? [] : [c.bold('How to fix'), ...lines, ''];
}

function footer(result: ScanResult, options: ReportOptions, c: Palette): string[] {
  const lines: string[] = [];
  const total = result.findings.length;
  if (total === 0) {
    lines.push(c.green('No issues found.'));
  } else {
    const counts = countBySeverity(result.findings);
    const parts = SEVERITIES.filter((s) => counts[s] > 0).map((s) => colorFor(s, c)(`${counts[s]} ${s}`));
    lines.push(`${c.bold(plural(total, 'finding'))}: ${parts.join(', ')}`);
  }
  if (options.hidden) {
    const below = options.minSeverity ?? 'low';
    lines.push(c.gray(`${plural(options.hidden, 'finding')} below ${below} not shown (use --min-severity info to include them).`));
  }
  if (options.suppressed) {
    lines.push(c.gray(`${plural(options.suppressed, 'finding')} suppressed by ${printable(options.ignoreFile ?? 'the ignore file')}.`));
  }
  if (result.skipped.length > 0) {
    if (options.verbose) {
      lines.push(`Skipped ${plural(result.skipped.length, 'file')}:`);
      for (const skip of result.skipped) lines.push(`  ${printable(skip.path)}  ${c.gray(printable(skip.reason))}`);
    } else {
      lines.push(c.gray(`Skipped ${plural(result.skipped.length, 'file')} (use --verbose to list them).`));
    }
  }
  return lines;
}

interface TargetGroup {
  label: string;
  findings: Finding[];
}

/** Groups findings by target in order of first appearance, then by file within each target, keeping the incoming order otherwise. */
function groupByTarget(findings: readonly Finding[]): TargetGroup[] {
  const groups = new Map<string, Finding[]>();
  for (const finding of findings) {
    const key = finding.target ?? '';
    const list = groups.get(key);
    if (list) list.push(finding);
    else groups.set(key, [finding]);
  }
  return [...groups].map(([target, list]) => {
    const fileOrder = new Map<string, number>();
    for (const f of list) if (!fileOrder.has(f.file)) fileOrder.set(f.file, fileOrder.size);
    const sorted = [...list].sort((a, b) => fileOrder.get(a.file)! - fileOrder.get(b.file)!);
    return { label: target ? printable(target) : 'Other files', findings: sorted };
  });
}

function location(finding: Finding): string {
  let text = printable(finding.file);
  if (finding.line !== undefined) text += `:${finding.line}`;
  if (finding.line !== undefined && finding.column !== undefined) text += `:${finding.column}`;
  return text;
}

function badge(severity: Severity, c: Palette): string {
  return colorFor(severity, c)(severity.toUpperCase().padEnd(BADGE_WIDTH));
}

function colorFor(severity: Severity, c: Palette): (s: string) => string {
  switch (severity) {
    case 'critical':
      return (s) => c.bold(c.magenta(s));
    case 'high':
      return (s) => c.bold(c.red(s));
    case 'medium':
      return c.yellow;
    case 'low':
      return c.blue;
    case 'info':
      return c.gray;
  }
}

/**
 * Short form of a path for headers. Display paths (relative, "~/..." or
 * synthetic ids) pass through; absolute paths become "." or a path relative
 * to cwd when inside it, "~/..." inside the home directory, otherwise stay
 * absolute. Always with forward slashes.
 */
export function shortPath(p: string, cwd: string = process.cwd()): string {
  if (p.includes('://')) return p;
  if (!path.isAbsolute(p)) return toSlash(p) || '.';
  const abs = path.resolve(p);
  const home = homeDir();
  const fromCwd = path.relative(cwd, abs);
  if (fromCwd === '') return '.';
  if (path.resolve(cwd) !== path.resolve(home) && isInside(fromCwd)) return toSlash(fromCwd);
  const fromHome = path.relative(home, abs);
  if (fromHome === '') return '~';
  if (isInside(fromHome)) return `~/${toSlash(fromHome)}`;
  return toSlash(abs);
}

function isInside(relative: string): boolean {
  return relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

function toSlash(p: string): string {
  return p.split(path.sep).join('/');
}

function plural(n: number, noun: string): string {
  return `${n} ${noun}${n === 1 ? '' : 's'}`;
}

function formatDuration(ms: number): string {
  return ms < 1000 ? `${Math.max(0, Math.round(ms))} ms` : `${(ms / 1000).toFixed(1)} s`;
}

/** Word-wraps each paragraph of text to width columns, prefixing every line with indent. */
function wrapText(text: string, width: number, indent: string): string[] {
  const out: string[] = [];
  const room = Math.max(20, width - indent.length);
  for (const paragraph of text.split(/\r?\n/)) {
    let line = '';
    for (const word of printable(paragraph).split(/\s+/)) {
      if (!word) continue;
      if (line && line.length + 1 + word.length > room) {
        out.push(indent + line);
        line = word;
      } else {
        line = line ? `${line} ${word}` : word;
      }
    }
    if (line) out.push(indent + line);
  }
  return out;
}
