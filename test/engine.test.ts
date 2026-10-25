import { describe, expect, it } from 'vitest';
import { findSecrets, redactSecrets } from '../src/patterns/secrets.js';
import { parseIgnoreFile } from '../src/scan/ignore.js';
import { scanFile, scanFiles } from '../src/scan/engine.js';
import type { Rule } from '../src/types.js';
import { file } from './helpers.js';

const evilRule: Rule = {
  id: 'TM-PI-999',
  title: 'Test rule',
  description: 'Flags the word EVIL so the engine can be tested on its own.',
  category: 'prompt-injection',
  severity: 'high',
  kinds: ['skill'],
  check: (f) => [...f.content.matchAll(/EVIL/g)].map((m) => ({ message: 'found EVIL', index: m.index })),
};

describe('engine', () => {
  it('maps offsets to 1-based line and column', () => {
    const [finding] = scanFile(file('first\n  EVIL here\n', 'skill'), { rules: [evilRule] });
    expect(finding).toMatchObject({ ruleId: 'TM-PI-999', line: 2, column: 3, severity: 'high', snippet: 'EVIL here' });
  });

  it('only runs rules on the kinds they declare', () => {
    expect(scanFile(file('EVIL', 'script'), { rules: [evilRule] })).toEqual([]);
  });

  it('redacts secrets and escapes invisible characters in snippets', () => {
    const key = `ghp_${'a'.repeat(36)}`;
    const [finding] = scanFile(file(`EVIL ${key} ​`, 'skill'), { rules: [evilRule] });
    expect(finding!.snippet).not.toContain(key);
    expect(finding!.snippet).toContain('[redacted]');
    expect(finding!.snippet).toContain('\\u200b');
  });

  it('honours user ignore files', () => {
    const f = file('EVIL', 'skill', 'skills/demo/SKILL.md');
    expect(scanFile(f, { rules: [evilRule], ignore: parseIgnoreFile('TM-PI-999') })).toEqual([]);
    expect(scanFile(f, { rules: [evilRule], ignore: parseIgnoreFile('skills/**') })).toEqual([]);
    expect(scanFile(f, { rules: [evilRule], ignore: parseIgnoreFile('skills/demo/*.md:TM-PI-999') })).toEqual([]);
    expect(scanFile(f, { rules: [evilRule], ignore: parseIgnoreFile('other/**') })).toHaveLength(1);
  });

  it('keeps scanning when a rule throws', () => {
    const broken: Rule = { ...evilRule, id: 'TM-PI-998', check: () => { throw new Error('boom'); } };
    const errors: string[] = [];
    const findings = scanFile(file('EVIL', 'skill'), { rules: [broken, evilRule], onRuleError: (r) => errors.push(r.id) });
    expect(errors).toEqual(['TM-PI-998']);
    expect(findings).toHaveLength(1);
  });

  it('sorts by severity, then file and line', () => {
    const low: Rule = { ...evilRule, id: 'TM-PI-997', severity: 'low' };
    const findings = scanFiles([file('x\nEVIL', 'skill', 'b.md'), file('EVIL', 'skill', 'a.md')], { rules: [low, evilRule] });
    expect(findings.map((f) => `${f.severity}:${f.file}:${f.line}`)).toEqual(['high:a.md:1', 'high:b.md:2', 'low:a.md:1', 'low:b.md:2']);
  });
});

describe('secret patterns', () => {
  it('finds and redacts common credentials', () => {
    // Built at runtime so the repository itself holds no secret-shaped literals.
    const text = `aws=${'AKIA'}${'ABCDEFGHIJKLMNOP'} anthropic=sk-ant-api03-${'x'.repeat(90)}`;
    expect(findSecrets(text).map((h) => h.patternId)).toEqual(['aws-access-key', 'anthropic-key']);
    expect(redactSecrets(text)).not.toContain('ABCDEFGHIJKLMNOP');
  });
});
