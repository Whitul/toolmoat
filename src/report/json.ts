import { countBySeverity } from '../scan/engine.js';
import type { Finding, ScanResult, Severity } from '../types.js';
import { VERSION } from '../version.js';
import type { ReportOptions } from './index.js';

export interface JsonReport {
  tool: 'toolmoat';
  version: string;
  summary: {
    filesScanned: number;
    /** Names of the distinct targets (skills, plugins, servers) that were scanned. */
    targets: string[];
    durationMs: number;
    counts: Record<Severity, number>;
  };
  findings: Finding[];
  skipped: { path: string; reason: string }[];
}

/** Machine-readable report with a stable key order and 2-space indentation. */
export function renderJson(result: ScanResult, options: ReportOptions = {}): string {
  const report: JsonReport = {
    tool: 'toolmoat',
    version: options.version ?? VERSION,
    summary: {
      filesScanned: result.filesScanned,
      targets: [...result.targets],
      durationMs: Math.round(result.durationMs),
      counts: countBySeverity(result.findings),
    },
    findings: result.findings.map(toJsonFinding),
    skipped: result.skipped.map((skip) => ({ path: skip.path, reason: skip.reason })),
  };
  return `${JSON.stringify(report, null, 2)}\n`;
}

/** Copies a finding with its keys in a fixed order, leaving out absent optional fields. */
export function toJsonFinding(finding: Finding): Finding {
  const out: Finding = {
    ruleId: finding.ruleId,
    severity: finding.severity,
    category: finding.category,
    title: finding.title,
    message: finding.message,
    file: finding.file,
  };
  if (finding.line !== undefined) out.line = finding.line;
  if (finding.column !== undefined) out.column = finding.column;
  if (finding.snippet !== undefined) out.snippet = finding.snippet;
  if (finding.target !== undefined) out.target = finding.target;
  if (finding.remediation !== undefined) out.remediation = finding.remediation;
  return out;
}
