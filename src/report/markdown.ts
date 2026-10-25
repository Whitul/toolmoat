import { countBySeverity } from '../scan/engine.js';
import type { Finding, ScanResult, Severity } from '../types.js';
import { SEVERITIES } from '../types.js';
import { printable, truncate } from '../util/text.js';
import { VERSION } from '../version.js';
import type { ReportOptions } from './index.js';

/** GitHub caps step summaries at 1 MiB and PR comments at 64 KiB, so long reports are cut. */
export const MAX_MARKDOWN_ROWS = 200;
const MAX_CELL = 300;
const MAX_REMEDIATIONS = 50;

/** Report for GitHub step summaries and PR comments: severity counts, then one table row per finding. */
export function renderMarkdown(result: ScanResult, options: ReportOptions = {}): string {
  const version = options.version ?? VERSION;
  const findings = result.findings;
  const out: string[] = ['## toolmoat scan results', ''];
  out.push(`Scanned ${plural(result.filesScanned, 'file')} in ${plural(result.targets.length, 'target')} with toolmoat ${escapeCell(version)}.`, '');

  if (findings.length === 0) {
    out.push('**No issues found.**', '');
  } else {
    const counts = countBySeverity(findings);
    out.push('| Severity | Findings |', '| --- | ---: |');
    for (const severity of SEVERITIES) out.push(`| ${label(severity)} | ${counts[severity]} |`);
    out.push('', '### Findings', '', '| Severity | Rule | Location | Message |', '| --- | --- | --- | --- |');
    for (const finding of findings.slice(0, MAX_MARKDOWN_ROWS)) out.push(row(finding));
    out.push('');
    if (findings.length > MAX_MARKDOWN_ROWS) {
      out.push(`Showing the first ${MAX_MARKDOWN_ROWS} of ${findings.length} findings. Run \`toolmoat scan\` locally or use \`--format sarif\` for the full list.`, '');
    }
    out.push(...remediations(findings));
  }

  const notes = footnotes(result, options);
  if (notes.length > 0) out.push(...notes, '');
  return `${out.join('\n').trimEnd()}\n`;
}

function row(finding: Finding): string {
  const severity = finding.severity === 'critical' || finding.severity === 'high' ? `**${label(finding.severity)}**` : label(finding.severity);
  const rule = `\`${finding.ruleId}\` ${escapeCell(finding.title)}`;
  return `| ${severity} | ${rule} | ${escapeCell(locationOf(finding))} | ${escapeCell(finding.message)} |`;
}

function remediations(findings: readonly Finding[]): string[] {
  const seen = new Set<string>();
  const items: string[] = [];
  for (const finding of findings) {
    if (!finding.remediation || seen.has(finding.ruleId)) continue;
    seen.add(finding.ruleId);
    if (items.length < MAX_REMEDIATIONS) items.push(`- \`${finding.ruleId}\` ${escapeCell(finding.title)}: ${escapeCell(finding.remediation, 600)}`);
  }
  return items.length === 0 ? [] : ['### How to fix', '', ...items, ''];
}

function footnotes(result: ScanResult, options: ReportOptions): string[] {
  const notes: string[] = [];
  if (options.hidden) notes.push(`${plural(options.hidden, 'finding')} below ${options.minSeverity ?? 'low'} not shown.`);
  if (options.suppressed) notes.push(`${plural(options.suppressed, 'finding')} suppressed by ${escapeCell(options.ignoreFile ?? 'the ignore file')}.`);
  if (result.skipped.length > 0) notes.push(`${plural(result.skipped.length, 'file')} skipped.`);
  return notes.length === 0 ? [] : [notes.join(' ')];
}

function locationOf(finding: Finding): string {
  if (finding.line === undefined) return finding.file;
  return finding.column === undefined ? `${finding.file}:${finding.line}` : `${finding.file}:${finding.line}:${finding.column}`;
}

/**
 * Makes untrusted text safe inside a GitHub table cell: one line, no
 * invisible characters, no raw HTML, and markdown punctuation (including
 * pipes and backticks) escaped so it renders literally.
 */
export function escapeCell(text: string, max = MAX_CELL): string {
  const flat = truncate(printable(text.replace(/\r?\n/g, ' ')).trim(), max);
  return flat
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/[\\`*_[\]|~]/g, (ch) => `\\${ch}`);
}

function label(severity: Severity): string {
  return severity.charAt(0).toUpperCase() + severity.slice(1);
}

function plural(n: number, noun: string): string {
  return `${n} ${noun}${n === 1 ? '' : 's'}`;
}
