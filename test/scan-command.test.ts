import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { renderRules, run as runRules } from '../src/commands/rules.js';
import type { ScanDeps, ScanIo, ScanOptions } from '../src/commands/scan.js';
import { run, runScan } from '../src/commands/scan.js';
import { parseIgnoreFile } from '../src/scan/ignore.js';
import type { Rule, ScanFile, SkippedFile } from '../src/types.js';
import { FIXTURES, ROOT, runCli, tempDir } from './helpers.js';

type DiscoverOptions = Parameters<ScanDeps['discover']>[0];

/** EVIL is high, MEH low, NOTE info, and BOOM makes the rule throw. */
const markerRule: Rule = {
  id: 'TM-PI-990',
  title: 'Test marker',
  description: 'Flags EVIL, MEH and NOTE markers so the scan command can be tested on its own.',
  category: 'prompt-injection',
  severity: 'high',
  kinds: ['skill'],
  remediation: 'Remove the marker.',
  check(file) {
    if (file.content.includes('BOOM')) throw new Error('boom');
    const hits = (word: string) => [...file.content.matchAll(new RegExp(word, 'g'))].map((m) => m.index);
    return [
      ...hits('EVIL').map((index) => ({ message: 'Found the EVIL marker', index })),
      ...hits('MEH').map((index) => ({ message: 'Found the MEH marker', index, severity: 'low' as const })),
      ...hits('NOTE').map((index) => ({ message: 'Found the NOTE marker', index, severity: 'info' as const })),
    ];
  },
};

function skill(content: string, dir: string, name = 'demo'): ScanFile {
  return { path: path.join(dir, 'skills', name, 'SKILL.md'), displayPath: `skills/${name}/SKILL.md`, kind: 'skill', content, target: name };
}

function fakeDiscover(files: ScanFile[], skipped: SkippedFile[] = []) {
  const calls: DiscoverOptions[] = [];
  const discover: ScanDeps['discover'] = async (options) => {
    calls.push(options);
    return { files, skipped, roots: options.paths.map((p: string) => path.resolve(options.cwd, p)) };
  };
  return { discover, calls };
}

function harness(content: string | ScanFile[], options: { cwd?: string; color?: boolean } = {}) {
  const cwd = options.cwd ?? tempDir('toolmoat-scan-');
  const files = typeof content === 'string' ? [skill(content, cwd)] : content;
  const fake = fakeDiscover(files, [{ path: 'skills/demo/blob.bin', reason: 'binary file' }]);
  const out = { stdout: '', stderr: '' };
  const io: Partial<ScanIo> = {
    cwd,
    color: options.color ?? false,
    stdout: (text) => {
      out.stdout += text;
    },
    stderr: (text) => {
      out.stderr += text;
    },
    deps: { discover: fake.discover, rules: [markerRule] },
  };
  return { cwd, out, calls: fake.calls, exec: (argv: string[]) => run(argv, io) };
}

async function scanOf(content: string, options: Partial<ScanOptions> = {}) {
  const cwd = tempDir('toolmoat-scan-');
  const fake = fakeDiscover([skill(content, cwd)]);
  const outcome = await runScan({ paths: ['.'], useDefaults: false, cwd, ...options }, { discover: fake.discover, rules: [markerRule] });
  return { outcome, calls: fake.calls, cwd };
}

describe('runScan', () => {
  it('exits 1 only for findings at or above --fail-on', async () => {
    expect((await scanOf('EVIL')).outcome.exitCode).toBe(1);
    expect((await scanOf('EVIL', { failOn: 'high' })).outcome.exitCode).toBe(1);
    expect((await scanOf('EVIL', { failOn: 'medium' })).outcome.exitCode).toBe(1);
    expect((await scanOf('EVIL', { failOn: 'critical' })).outcome.exitCode).toBe(0);
    expect((await scanOf('EVIL', { failOn: 'none' })).outcome.exitCode).toBe(0);
    expect((await scanOf('MEH')).outcome.exitCode).toBe(0);
    expect((await scanOf('clean text', { failOn: 'info' })).outcome.exitCode).toBe(0);
  });

  it('filters by --min-severity and counts what it hid', async () => {
    const content = 'EVIL\nMEH\nNOTE\n';
    const byDefault = (await scanOf(content)).outcome;
    expect(byDefault.result.findings.map((f) => f.severity)).toEqual(['high', 'low']);
    expect(byDefault.hidden).toBe(1);
    const all = (await scanOf(content, { minSeverity: 'info' })).outcome;
    expect(all.result.findings).toHaveLength(3);
    expect(all.hidden).toBe(0);
    const high = (await scanOf(content, { minSeverity: 'high' })).outcome;
    expect(high.result.findings.map((f) => f.message)).toEqual(['Found the EVIL marker']);
    expect(high.hidden).toBe(2);
  });

  it('still fails on findings hidden by --min-severity', async () => {
    const { outcome } = await scanOf('MEH', { minSeverity: 'high', failOn: 'low' });
    expect(outcome.result.findings).toEqual([]);
    expect(outcome.exitCode).toBe(1);
  });

  it('drops suppressed findings from the result and from the exit code', async () => {
    const { outcome } = await scanOf('EVIL', { ignore: parseIgnoreFile('TM-PI-990') });
    expect(outcome.result.findings).toEqual([]);
    expect(outcome.suppressed).toBe(1);
    expect(outcome.exitCode).toBe(0);
    const scoped = (await scanOf('EVIL', { ignore: parseIgnoreFile('other/**:TM-PI-990') })).outcome;
    expect(scoped.result.findings).toHaveLength(1);
    expect(scoped.suppressed).toBe(0);
  });

  it('passes its options to discovery and fills in the result', async () => {
    const ignore = parseIgnoreFile('vendor/**');
    const { outcome, calls, cwd } = await scanOf('EVIL', { paths: ['skills'], deep: true, maxFileBytes: 1024, ignore, useDefaults: true });
    expect(calls).toEqual([{ paths: ['skills'], useDefaults: true, cwd, deep: true, maxFileBytes: 1024, ignore }]);
    expect(outcome.result.filesScanned).toBe(1);
    expect(outcome.result.targets).toEqual(['demo']);
    expect(outcome.result.rules).toEqual([markerRule]);
    expect(outcome.result.durationMs).toBeGreaterThanOrEqual(0);
    expect(outcome.roots).toEqual([path.resolve(cwd, 'skills')]);
    expect(outcome.filePaths.get('skills/demo/SKILL.md')).toBe(path.join(cwd, 'skills', 'demo', 'SKILL.md'));
    expect(outcome.result.findings[0]).toMatchObject({ ruleId: 'TM-PI-990', file: 'skills/demo/SKILL.md', line: 1, column: 1, target: 'demo' });
  });

  it('collects rule errors instead of failing the scan', async () => {
    const cwd = tempDir();
    const fake = fakeDiscover([skill('BOOM', cwd, 'broken'), skill('EVIL', cwd, 'fine')]);
    const outcome = await runScan({ paths: ['.'], useDefaults: false, cwd }, { discover: fake.discover, rules: [markerRule] });
    expect(outcome.ruleErrors).toEqual([{ ruleId: 'TM-PI-990', file: 'skills/broken/SKILL.md', message: 'boom' }]);
    expect(outcome.result.findings).toHaveLength(1);
  });
});

describe('scan command', () => {
  it('prints a text report and returns the exit code', async () => {
    const h = harness('EVIL');
    expect(await h.exec(['.'])).toBe(1);
    expect(h.out.stdout).toMatch(/^toolmoat \S+ scanned 1 file in 1 target \(\.\) in \d+ ms\n/);
    expect(h.out.stdout).toContain('  HIGH      TM-PI-990  Test marker\n    skills/demo/SKILL.md:1:1  Found the EVIL marker\n    > EVIL\n');
    expect(h.out.stdout).toContain('How to fix');
    expect(h.out.stdout).not.toContain('\u001b[');
    expect(h.out.stderr).toBe('');
  });

  it('returns 0 for a clean scan', async () => {
    const h = harness('nothing to see');
    expect(await h.exec(['.', '--fail-on', 'info'])).toBe(0);
    expect(h.out.stdout).toContain('No issues found.');
  });

  it('scans the default locations only when no paths are given or --defaults is set', async () => {
    const withDirs = (...names: string[]) => {
      const h = harness('x');
      for (const name of names) fs.mkdirSync(path.join(h.cwd, name));
      return h;
    };
    const a = harness('x');
    await a.exec([]);
    expect(a.calls[0]).toMatchObject({ paths: [], useDefaults: true, deep: false });
    const b = withDirs('one', 'two');
    await b.exec(['one', 'two']);
    expect(b.calls[0]).toMatchObject({ paths: ['one', 'two'], useDefaults: false });
    const c = withDirs('one');
    await c.exec(['one', '--defaults', '--deep', '--max-file-size', '0.5']);
    expect(c.calls[0]).toMatchObject({ paths: ['one'], useDefaults: true, deep: true, maxFileBytes: 512 * 1024 });
  });

  it('fails with exit code 2 when a path does not exist', async () => {
    const h = harness('EVIL');
    expect(await h.exec(['.', 'typo-dir', 'also-missing.md'])).toBe(2);
    expect(h.out.stderr).toBe('toolmoat scan: path not found: typo-dir, also-missing.md\n');
    expect(h.out.stdout).toBe('');
    expect(h.calls).toHaveLength(0);
  });

  it('writes json, sarif and markdown', async () => {
    const json = harness('EVIL');
    expect(await json.exec(['.', '--format', 'json'])).toBe(1);
    const report = JSON.parse(json.out.stdout);
    expect(report.summary).toMatchObject({ filesScanned: 1, targets: ['demo'], counts: { high: 1 } });
    expect(report.skipped).toEqual([{ path: 'skills/demo/blob.bin', reason: 'binary file' }]);

    const sarif = harness('EVIL');
    await sarif.exec(['.', '-f', 'sarif']);
    const log = JSON.parse(sarif.out.stdout);
    expect(log.runs[0].results[0]).toMatchObject({ ruleId: 'TM-PI-990', level: 'error' });
    expect(log.runs[0].results[0].locations[0].physicalLocation.artifactLocation).toEqual({ uri: 'skills/demo/SKILL.md', uriBaseId: '%SRCROOT%' });

    const md = harness('EVIL');
    await md.exec(['.', '--format', 'markdown']);
    expect(md.out.stdout.startsWith('## toolmoat scan results\n')).toBe(true);
  });

  it('writes the report to --output and prints a one-line summary instead', async () => {
    const h = harness('EVIL');
    expect(await h.exec(['.', '--format', 'json', '--output', 'reports/toolmoat.json', '--color'])).toBe(1);
    const written = fs.readFileSync(path.join(h.cwd, 'reports', 'toolmoat.json'), 'utf8');
    expect(JSON.parse(written).findings).toHaveLength(1);
    expect(h.out.stdout).toMatch(/^toolmoat \S+: 1 finding \(1 high\) in 1 file; json report written to reports\/toolmoat\.json\n$/);

    const text = harness('EVIL');
    await text.exec(['.', '-o', 'out.txt', '--color']);
    expect(fs.readFileSync(path.join(text.cwd, 'out.txt'), 'utf8')).not.toContain('\u001b[');

    const quiet = harness('EVIL');
    expect(await quiet.exec(['.', '-o', 'out.sarif', '-f', 'sarif', '--quiet'])).toBe(1);
    expect(quiet.out.stdout).toBe('');
    expect(fs.existsSync(path.join(quiet.cwd, 'out.sarif'))).toBe(true);
  });

  it('prints only findings with --quiet, and nothing when clean', async () => {
    const noisy = harness('EVIL');
    await noisy.exec(['.', '--quiet']);
    expect(noisy.out.stdout.startsWith('demo (1 finding)\n')).toBe(true);
    const clean = harness('fine');
    expect(await clean.exec(['.', '-q'])).toBe(0);
    expect(clean.out.stdout).toBe('');
  });

  it('honours .toolmoatignore in the cwd', async () => {
    const h = harness('EVIL');
    fs.writeFileSync(path.join(h.cwd, '.toolmoatignore'), '# accepted risk\nTM-PI-990\n');
    expect(await h.exec(['.'])).toBe(0);
    expect(h.out.stdout).toContain('No issues found.');
    expect(h.out.stdout).toContain('1 finding suppressed by .toolmoatignore.');
  });

  it('honours --ignore-file over the cwd ignore file', async () => {
    const h = harness('EVIL');
    fs.writeFileSync(path.join(h.cwd, '.toolmoatignore'), 'TM-PI-990\n');
    fs.writeFileSync(path.join(h.cwd, 'strict.ignore'), 'docs/**\n');
    expect(await h.exec(['.', '--ignore-file', 'strict.ignore'])).toBe(1);
    expect(h.out.stdout).toContain('Ignore file: strict.ignore');
  });

  it('applies no ignore file with --no-ignore', async () => {
    const h = harness('EVIL');
    fs.writeFileSync(path.join(h.cwd, '.toolmoatignore'), 'TM-PI-990\n');
    expect(await h.exec(['.', '--no-ignore'])).toBe(1);
    expect(h.out.stdout).not.toContain('Ignore file:');
    expect(h.calls[0]!.ignore).toEqual(parseIgnoreFile(''));
  });

  it('never reads ignore files from inside the scanned targets', async () => {
    const target = tempDir('toolmoat-target-');
    fs.writeFileSync(path.join(target, '.toolmoatignore'), '**\nTM-PI-990\n');
    const h = harness([skill('EVIL', target)]);
    expect(await h.exec([target])).toBe(1);
    expect(h.out.stdout).toContain('Found the EVIL marker');
    expect(h.out.stdout).not.toContain('suppressed');
  });

  it('fails with exit code 2 when --ignore-file cannot be read', async () => {
    const h = harness('EVIL');
    expect(await h.exec(['.', '--ignore-file', 'missing.ignore'])).toBe(2);
    expect(h.out.stderr).toContain('cannot read ignore file missing.ignore');
    expect(h.calls).toHaveLength(0);
  });

  it.each([
    [['--bogus'], "unknown option '--bogus'"],
    [['--format', 'xml'], "unknown format 'xml'"],
    [['--format'], '--format'],
    [['--fail-on', 'urgent'], "invalid --fail-on 'urgent'"],
    [['--min-severity', 'none'], "invalid --min-severity 'none'"],
    [['--max-file-size', 'lots'], "invalid --max-file-size 'lots'"],
    [['--max-file-size=0'], "invalid --max-file-size '0'"],
    [['--output='], '--output needs a file name'],
    [['--no-ignore', '--ignore-file', 'x'], 'cannot be combined'],
  ])('rejects %j with exit code 2', async (argv, message) => {
    const h = harness('EVIL');
    expect(await h.exec(argv)).toBe(2);
    expect(h.out.stderr).toContain(message);
    expect(h.out.stderr).toContain("Run 'toolmoat scan --help' for usage.");
    expect(h.out.stdout).toBe('');
    expect(h.calls).toHaveLength(0);
  });

  it('returns 2 with a clear message when discovery fails', async () => {
    const out = { stderr: '' };
    const code = await run(['.'], {
      cwd: tempDir(),
      stdout: () => undefined,
      stderr: (t) => {
        out.stderr += t;
      },
      deps: {
        discover: async () => {
          throw new Error('EACCES: permission denied, scandir');
        },
      },
    });
    expect(code).toBe(2);
    expect(out.stderr).toBe('toolmoat scan: EACCES: permission denied, scandir\n');
  });

  it('shows info findings, skipped files and rule errors with --verbose', async () => {
    const cwd = tempDir();
    const files = [skill('EVIL NOTE', cwd), skill('BOOM', cwd, 'broken')];
    const quiet = harness(files, { cwd });
    await quiet.exec(['.']);
    expect(quiet.out.stdout).not.toContain('NOTE marker');
    expect(quiet.out.stdout).toContain('1 finding below low not shown');
    expect(quiet.out.stdout).toContain('Skipped 1 file (use --verbose to list them).');
    expect(quiet.out.stderr).toBe('toolmoat scan: 1 rule error while scanning (run with --verbose for details)\n');

    const verbose = harness(files, { cwd });
    await verbose.exec(['.', '--verbose']);
    expect(verbose.out.stdout).toContain('INFO      TM-PI-990  Test marker');
    expect(verbose.out.stdout).toContain('Skipped 1 file:\n  skills/demo/blob.bin  binary file');
    expect(verbose.out.stderr).toBe('toolmoat scan: rule TM-PI-990 failed on skills/broken/SKILL.md: boom\n');

    const explicit = harness(files, { cwd });
    await explicit.exec(['.', '-v', '--min-severity', 'high']);
    expect(explicit.out.stdout).not.toContain('NOTE marker');
  });

  it('colors text output with --color and never with --no-color', async () => {
    const on = harness('EVIL');
    await on.exec(['.', '--color']);
    expect(on.out.stdout).toContain('\u001b[');
    const auto = harness('EVIL', { color: true });
    await auto.exec(['.']);
    expect(auto.out.stdout).toContain('\u001b[');
    const off = harness('EVIL', { color: true });
    await off.exec(['.', '--no-color']);
    expect(off.out.stdout).not.toContain('\u001b[');
    const json = harness('EVIL');
    await json.exec(['.', '--format', 'json', '--color']);
    expect(json.out.stdout).not.toContain('\u001b[');
  });

  it('prints help', async () => {
    const h = harness('EVIL');
    expect(await h.exec(['--help'])).toBe(0);
    expect(h.out.stdout).toContain('Usage: toolmoat scan [paths...] [options]');
    expect(h.out.stdout).toContain('--fail-on');
  });
});

describe('rules command', () => {
  const rules: Rule[] = [
    { ...markerRule, id: 'TM-SUP-002', title: 'Second | rule', severity: 'medium', category: 'supply-chain', kinds: ['package-manifest', 'mcp-config'] },
    { ...markerRule, id: 'TM-EXEC-001', title: 'First rule', severity: 'critical', category: 'dangerous-execution', kinds: ['skill', 'script'] },
    { ...markerRule, id: 'TM-PI-003', title: 'Third rule', severity: 'low' },
  ];

  function rulesHarness() {
    const out = { stdout: '', stderr: '' };
    const io = {
      color: false,
      rules,
      stdout: (t: string) => {
        out.stdout += t;
      },
      stderr: (t: string) => {
        out.stderr += t;
      },
    };
    return { out, exec: (argv: string[]) => runRules(argv, io) };
  }

  it('renders a README table sorted by id with escaped cells', () => {
    const lines = renderRules(rules, 'markdown').trimEnd().split('\n');
    expect(lines[0]).toBe('| ID | Title | Severity | Category | Applies to | Description |');
    expect(lines[1]).toBe('| --- | --- | --- | --- | --- | --- |');
    expect(lines.slice(2).map((l) => l.split(' | ')[0])).toEqual(['| `TM-EXEC-001`', '| `TM-PI-003`', '| `TM-SUP-002`']);
    expect(lines[4]).toContain('| Second \\| rule | medium | supply-chain | package-manifest, mcp-config |');
  });

  it('lists rules as text with id, severity, category, kinds and description', () => {
    const out = renderRules(rules, 'text');
    expect(out).toContain('TM-EXEC-001  CRITICAL  dangerous-execution    First rule\n  Applies to: skill, script\n  Flags EVIL');
    expect(out.indexOf('TM-EXEC-001')).toBeLessThan(out.indexOf('TM-PI-003'));
    expect(out).toContain('3 rules: 1 critical, 1 medium, 1 low\n');
  });

  it('prints json and filters by --severity', async () => {
    const h = rulesHarness();
    expect(await h.exec(['--format', 'json', '--severity', 'medium'])).toBe(0);
    const parsed = JSON.parse(h.out.stdout);
    expect(parsed.tool).toBe('toolmoat');
    expect(parsed.rules.map((r: { id: string }) => r.id)).toEqual(['TM-EXEC-001', 'TM-SUP-002']);
    expect(Object.keys(parsed.rules[0])).toEqual(['id', 'title', 'severity', 'category', 'kinds', 'description', 'remediation']);
  });

  it.each([[['--severity', 'urgent']], [['--format', 'sarif']], [['--nope']], [['extra']]])('rejects %j with exit code 2', async (argv) => {
    const h = rulesHarness();
    expect(await h.exec(argv)).toBe(2);
    expect(h.out.stderr).toContain("Run 'toolmoat rules --help' for usage.");
    expect(h.out.stdout).toBe('');
  });
});

describe('cli', () => {
  it('rejects unknown scan options with exit code 2', () => {
    const res = runCli(['scan', '--definitely-not-an-option']);
    expect(res.status).toBe(2);
    expect(res.stderr).toContain("unknown option '--definitely-not-an-option'");
  });

  it('lists the built-in rules as json', () => {
    const res = runCli(['rules', '--format', 'json']);
    expect(res.status).toBe(0);
    expect(Array.isArray(JSON.parse(res.stdout).rules)).toBe(true);
  });

  const hasDiscovery = fs.existsSync(path.join(ROOT, 'src', 'scan', 'discover.ts'));

  it.skipIf(!hasDiscovery)('scans a fixture directory with exit codes that match the findings', () => {
    const home = tempDir('toolmoat-user-home-');
    const env = { TOOLMOAT_TEST_USER_HOME: home, APPDATA: path.join(home, 'AppData'), XDG_CONFIG_HOME: path.join(home, '.config') };
    const cwd = tempDir('toolmoat-cli-cwd-');
    const malicious = path.join(FIXTURES, 'scan', 'malicious');
    const clean = path.join(FIXTURES, 'scan', 'clean');

    const none = runCli(['scan', malicious, '--format', 'json', '--fail-on', 'none'], { cwd, env });
    expect(none.status, none.stderr).toBe(0);
    const report = JSON.parse(none.stdout);
    expect(report.tool).toBe('toolmoat');
    expect(report.summary.filesScanned).toBeGreaterThanOrEqual(1);

    const strict = runCli(['scan', malicious, '--format', 'json', '--min-severity', 'info', '--fail-on', 'info'], { cwd, env });
    expect(strict.status, strict.stderr).toBe(JSON.parse(strict.stdout).findings.length > 0 ? 1 : 0);

    const benign = runCli(['scan', clean, '--format', 'json', '--min-severity', 'info'], { cwd, env });
    const benignReport = JSON.parse(benign.stdout);
    const atOrAboveHigh = benignReport.findings.some((f: { severity: string }) => f.severity === 'high' || f.severity === 'critical');
    expect(benign.status, benign.stderr).toBe(atOrAboveHigh ? 1 : 0);
  });
});
