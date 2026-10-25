import { redactSecrets } from '../patterns/secrets.js';
import { allRules } from '../rules/index.js';
import type { Finding, Rule, RuleMatch, ScanFile, Severity } from '../types.js';
import { atLeast, SEVERITY_RANK } from '../types.js';
import { lineAt, lineColAt, printable, truncate } from '../util/text.js';
import type { IgnoreConfig } from './ignore.js';
import { emptyIgnore, isFindingIgnored } from './ignore.js';

export interface EngineOptions {
  rules?: readonly Rule[];
  ignore?: IgnoreConfig;
  /** Drop findings below this severity. */
  minSeverity?: Severity;
  /** Called when a rule throws. The scan carries on without that rule's output for the file. */
  onRuleError?: (rule: Rule, file: ScanFile, error: unknown) => void;
}

const SNIPPET_MAX = 160;

const LOWER: Record<Severity, Severity> = { critical: 'high', high: 'medium', medium: 'low', low: 'info', info: 'info' };

/**
 * Test code in plugins and MCP servers is full of deliberately hostile strings
 * and is not what the agent runs, so its findings drop one level (critical
 * still shows as high). Judged on the path inside the scanned root, so scanning
 * a directory that itself lives under test/ is not affected.
 */
export function isTestPath(relPath: string): boolean {
  return (
    /(?:^|\/)(?:tests?|__tests__|spec|specs|testdata|__fixtures__)\//i.test(relPath) ||
    /(?:^|\/)(?:test_[^/]*\.py|[^/]*_test\.(?:py|go)|[^/]*\.(?:test|spec)\.[cm]?[jt]sx?)$/i.test(relPath)
  );
}

export function scanFile(file: ScanFile, options: EngineOptions = {}): Finding[] {
  const rules = options.rules ?? allRules;
  const ignore = options.ignore ?? emptyIgnore();
  const findings: Finding[] = [];
  const seen = new Set<string>();

  for (const rule of rules) {
    if (!rule.kinds.includes(file.kind)) continue;
    if (isFindingIgnored(rule.id, file.displayPath, ignore)) continue;
    let matches: RuleMatch[];
    try {
      matches = rule.check(file);
    } catch (error) {
      options.onRuleError?.(rule, file, error);
      continue;
    }
    const inTests = file.kind === 'script' && isTestPath(file.rootRelPath ?? file.displayPath);
    for (const match of matches) {
      const finding = toFinding(rule, file, match);
      if (inTests && finding.severity !== 'info') {
        finding.severity = LOWER[finding.severity];
        finding.message += ' (in a test file, so severity is lowered one level)';
      }
      if (options.minSeverity && !atLeast(finding.severity, options.minSeverity)) continue;
      const key = `${finding.ruleId}|${finding.line ?? 0}|${finding.message}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push(finding);
    }
  }
  return findings;
}

export function scanFiles(files: readonly ScanFile[], options: EngineOptions = {}): Finding[] {
  return sortFindings(files.flatMap((file) => scanFile(file, options)));
}

export function toFinding(rule: Rule, file: ScanFile, match: RuleMatch): Finding {
  let line = match.line;
  let column: number | undefined;
  if (match.index !== undefined) {
    const pos = lineColAt(file.content, match.index);
    line = pos.line;
    column = pos.column;
  }
  const finding: Finding = {
    ruleId: rule.id,
    severity: match.severity ?? rule.severity,
    category: rule.category,
    title: rule.title,
    message: match.message,
    file: file.displayPath,
  };
  if (line !== undefined) finding.line = line;
  if (column !== undefined) finding.column = column;
  const snippet = makeSnippet(match.snippet ?? (line !== undefined ? lineAt(file.content, line) : undefined), column);
  if (snippet) finding.snippet = snippet;
  if (file.target) finding.target = file.target;
  if (rule.remediation) finding.remediation = rule.remediation;
  return finding;
}

/** Redacts secrets, escapes invisible characters and trims long lines to a window around the column. */
export function makeSnippet(raw: string | undefined, column?: number): string | undefined {
  if (raw === undefined) return undefined;
  let text = redactSecrets(raw);
  text = printable(text).trim();
  if (!text) return undefined;
  if (text.length > SNIPPET_MAX && column !== undefined && column > 60) {
    const start = Math.min(column - 40, text.length - SNIPPET_MAX + 1);
    text = `…${text.slice(Math.max(0, start))}`;
  }
  return truncate(text, SNIPPET_MAX);
}

export function sortFindings(findings: Finding[]): Finding[] {
  return findings.sort(
    (a, b) =>
      SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
      a.file.localeCompare(b.file) ||
      (a.line ?? 0) - (b.line ?? 0) ||
      a.ruleId.localeCompare(b.ruleId),
  );
}

export function countBySeverity(findings: readonly Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;
  return counts;
}
