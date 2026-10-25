import path from 'node:path';
import { describe, expect, it } from 'vitest';
import type { Finding } from '../src/types.js';
import { FIXTURES, runCli } from './helpers.js';

const CORPUS = path.join(FIXTURES, 'corpus');

interface JsonReport {
  summary: { filesScanned: number; counts: Record<string, number> };
  findings: Finding[];
}

function scanJson(...paths: string[]): { status: number | null; report: JsonReport } {
  const result = runCli(['scan', ...paths, '--format', 'json']);
  return { status: result.status, report: JSON.parse(result.stdout) as JsonReport };
}

function rulesIn(report: JsonReport, dir: string, minRank = 0): Set<string> {
  const rank: Record<string, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  return new Set(
    report.findings.filter((f) => f.file.includes(`/${dir}/`) && rank[f.severity]! >= minRank).map((f) => f.ruleId),
  );
}

describe('end-to-end scan of the corpus', () => {
  it('keeps the benign corpus free of medium-or-higher findings', () => {
    const { status, report } = scanJson(path.join(CORPUS, 'benign'));
    expect(status).toBe(0);
    expect(report.summary.filesScanned).toBeGreaterThan(10);
    const serious = report.findings.filter((f) => ['medium', 'high', 'critical'].includes(f.severity));
    expect(serious, JSON.stringify(serious, null, 2)).toEqual([]);
  });

  it('catches every malicious sample', () => {
    const { status, report } = scanJson(path.join(CORPUS, 'malicious'), path.join(CORPUS, 'configs'));
    expect(status).toBe(1);

    const expectations: Record<string, string[]> = {
      'clawhavoc-skill': ['TM-EXEC-001', 'TM-OBF-001', 'TM-EXEC-004'],
      'poisoned-mcp-server': ['TM-PI-002', 'TM-PI-003', 'TM-PI-005', 'TM-CRED-001'],
      'hidden-skill': ['TM-HID-001', 'TM-HID-004'],
      'backdoor-plugin': ['TM-HOOK-002', 'TM-PERM-002'],
      'stealer-script': ['TM-CRED-002', 'TM-CRED-003', 'TM-EXFIL-001'],
      configs: ['TM-SUP-001', 'TM-CFG-001', 'TM-NET-001'],
    };
    for (const [dir, rules] of Object.entries(expectations)) {
      const found = rulesIn(report, dir);
      for (const rule of rules) expect(found, `${rule} in ${dir}`).toContain(rule);
    }
    // Each malicious skill, plugin and script must produce at least one high or critical finding.
    for (const dir of ['clawhavoc-skill', 'poisoned-mcp-server', 'hidden-skill', 'backdoor-plugin', 'stealer-script']) {
      expect(rulesIn(report, dir, 3).size, `high+ findings in ${dir}`).toBeGreaterThan(0);
    }
  });

  it('emits valid SARIF with results for the malicious corpus', () => {
    const result = runCli(['scan', path.join(CORPUS, 'malicious'), '--format', 'sarif']);
    expect(result.status).toBe(1);
    const sarif = JSON.parse(result.stdout) as { version: string; runs: { results: unknown[]; tool: { driver: { rules: unknown[] } } }[] };
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs[0]!.results.length).toBeGreaterThan(10);
    expect(sarif.runs[0]!.tool.driver.rules.length).toBeGreaterThan(10);
  });
});
