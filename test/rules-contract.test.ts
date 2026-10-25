import { describe, expect, it } from 'vitest';
import { SECRET_PATTERNS } from '../src/patterns/secrets.js';
import { allRules } from '../src/rules/index.js';
import { FILE_KINDS, SEVERITIES } from '../src/types.js';
import { file } from './helpers.js';

const PREFIX_CATEGORY: Record<string, string[]> = {
  PI: ['prompt-injection'],
  HID: ['hidden-content'],
  EXEC: ['dangerous-execution'],
  OBF: ['obfuscation'],
  CRED: ['credential-access'],
  EXFIL: ['exfiltration'],
  PERSIST: ['persistence'],
  DESTRUCT: ['destructive'],
  SEC: ['secrets'],
  SUP: ['supply-chain'],
  PERM: ['excessive-permissions'],
  HOOK: ['dangerous-execution', 'persistence', 'excessive-permissions', 'exfiltration'],
  NET: ['insecure-transport'],
  CFG: ['excessive-permissions', 'supply-chain', 'insecure-transport', 'secrets', 'dangerous-execution'],
};

describe('rule registry contract', () => {
  it('has unique, well-formed ids whose prefix matches the category', () => {
    const ids = new Set<string>();
    for (const rule of allRules) {
      expect(rule.id).toMatch(/^TM-[A-Z]+-\d{3}$/);
      expect(ids.has(rule.id), `duplicate id ${rule.id}`).toBe(false);
      ids.add(rule.id);
      const prefix = rule.id.split('-')[1]!;
      expect(PREFIX_CATEGORY[prefix], `unknown prefix in ${rule.id}`).toBeDefined();
      expect(PREFIX_CATEGORY[prefix]).toContain(rule.category);
    }
  });

  it('describes every rule and declares valid kinds and severity', () => {
    for (const rule of allRules) {
      expect(rule.title.length, rule.id).toBeGreaterThan(3);
      expect(rule.description.length, rule.id).toBeGreaterThan(20);
      expect(SEVERITIES).toContain(rule.severity);
      expect(rule.kinds.length, rule.id).toBeGreaterThan(0);
      for (const kind of rule.kinds) expect(FILE_KINDS).toContain(kind);
    }
  });

  it('returns no matches for empty files', () => {
    for (const rule of allRules) {
      for (const kind of rule.kinds) expect(rule.check(file('', kind)), rule.id).toEqual([]);
    }
  });
});

/**
 * Rules run on attacker-controlled text, so a regex with catastrophic
 * backtracking would let a malicious skill hang the scanner (and the proxy).
 * Every rule must stay fast on long, repetitive, adversarial input.
 */
describe('rules are linear-time on adversarial input', () => {
  const N = 40_000;
  const inputs: Record<string, string> = {
    'letters': 'a'.repeat(N),
    'spaces': ' '.repeat(N),
    'newlines': '\n'.repeat(N),
    'slashes': '/'.repeat(N),
    'backslashes': '\\'.repeat(N),
    'quotes': '"'.repeat(N),
    'base64-ish': 'QUJD'.repeat(N / 4),
    'url-ish': 'http://a.b/'.repeat(N / 11),
    'curl-ish': 'curl -s '.repeat(N / 8),
    'pipes': '| '.repeat(N / 2),
    'ignore-ish': 'ignore previous '.repeat(N / 16),
    'html-comment-ish': '<!-- '.repeat(N / 5),
    'json-ish': '{"a":'.repeat(N / 5),
    'dots': 'a.'.repeat(N / 2),
    'zero-width': '​'.repeat(N),
    'tags': String.fromCodePoint(0xe0041).repeat(N / 2),
    'env-ish': 'process.env.'.repeat(N / 12),
    'path-ish': '~/.ssh/'.repeat(N / 7),
    'eval-ish': 'eval(atob('.repeat(N / 10),
    'mixed-unicode': 'ж‮я‍'.repeat(N / 4),
  };

  for (const rule of allRules) {
    it(`${rule.id} stays under 300ms per input`, () => {
      for (const [label, content] of Object.entries(inputs)) {
        for (const kind of rule.kinds) {
          const started = performance.now();
          rule.check(file(content, kind));
          const elapsed = performance.now() - started;
          expect(elapsed, `${rule.id} on ${label} (${kind}) took ${elapsed.toFixed(0)}ms`).toBeLessThan(300);
        }
      }
    });
  }

  it('secret patterns stay fast too', () => {
    for (const pattern of SECRET_PATTERNS) {
      for (const content of Object.values(inputs)) {
        const started = performance.now();
        new RegExp(pattern.regex.source, 'g').test(content);
        expect(performance.now() - started, pattern.id).toBeLessThan(300);
      }
    }
  });
});
