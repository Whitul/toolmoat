import { describe, expect, it } from 'vitest';
import { findSecrets, redactSecrets, SECRET_PATTERNS } from '../src/patterns/secrets.js';
import { secretRules } from '../src/rules/secrets.js';
import type { Finding } from '../src/types.js';
import { scan } from './helpers.js';

/** Build fake secrets at runtime so the repo never contains a real-looking literal. */
const B = 'B'; // break up vendor prefixes a little in source
const fakeGithub = 'ghp_' + 'a'.repeat(36);
const fakeStripe = 'sk_live_' + 'c'.repeat(28);
const fakeGroq = 'gsk_' + 'd'.repeat(52);
const fakeXai = 'xai-' + 'e'.repeat(80);
const fakeGocspx = 'GOCSPX-' + 'f'.repeat(28);
const fakeSendgrid = 'SG.' + 'g'.repeat(22) + '.' + 'h'.repeat(43);
const fakeShopify = 'shpat_' + 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6';
const fakeDiscord = 'M' + 'Tk4'.repeat(8) + '.Gh' + 'JkLm' + '.' + 'z'.repeat(30);

function s(content: string, kind: Parameters<typeof scan>[1] = 'script'): Finding[] {
  return scan(content, kind, secretRules);
}
function has(findings: Finding[], id: string): boolean {
  return findings.some((f) => f.ruleId === id);
}

describe('TM-SEC-001 hardcoded credential', () => {
  it('flags a GitHub token and marks a private key critical', () => {
    const gh = s('const token = "' + fakeGithub + '"');
    expect(has(gh, 'TM-SEC-001')).toBe(true);
    expect(gh.find((f) => f.ruleId === 'TM-SEC-001')?.message).toContain('GitHub');

    const body = 'MIIE' + 'pAIBAAKCAQEA'.repeat(8);
    const pk = s('-----' + B.replace('B', 'BEGIN') + ' RSA PRIVATE KEY-----\n' + body + '\n-----END RSA PRIVATE KEY-----');
    expect(pk.find((f) => f.ruleId === 'TM-SEC-001')?.severity).toBe('critical');

    // A bare header with no key material (a test fixture or a detection pattern) is not a leak.
    const header = s('-----' + B.replace('B', 'BEGIN') + ' OPENSSH PRIVATE KEY-----\n');
    expect(has(header, 'TM-SEC-001')).toBe(false);
  });

  it('never leaks the secret value in the message or snippet', () => {
    const f = s('api="' + fakeStripe + '"').find((x) => x.ruleId === 'TM-SEC-001');
    expect(f?.message).not.toContain(fakeStripe);
    expect(f?.snippet ?? '').not.toContain(fakeStripe);
  });

  it('skips documented placeholders and examples', () => {
    expect(has(s('key = "AKIAIOSFODNN7EXAMPLE"'), 'TM-SEC-001')).toBe(false);
    expect(has(s('token = "your_api_key_here"'), 'TM-SEC-001')).toBe(false);
    expect(has(s('token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"'), 'TM-SEC-001')).toBe(false);
  });
});

describe('TM-SEC-002 secret-like assignment', () => {
  it('flags a high-entropy value on a secret-looking name', () => {
    const val = 'aZ3kQ9mX1pV7wL2rT6yB8nC4dF0gH5jK';
    expect(has(s('password = "' + val + '"'), 'TM-SEC-002')).toBe(true);
    expect(has(s('client_secret: "' + val + '"', 'mcp-config'), 'TM-SEC-002')).toBe(true);
  });

  it('ignores env references, placeholders, low-entropy and prose values', () => {
    expect(has(s('api_key = process.env.API_KEY'), 'TM-SEC-002')).toBe(false);
    expect(has(s('password = "${DB_PASSWORD}"'), 'TM-SEC-002')).toBe(false);
    expect(has(s('password = "changemechangeme"'), 'TM-SEC-002')).toBe(false);
    expect(has(s('password = "aaaaaaaaaaaaaaaaaaaa"'), 'TM-SEC-002')).toBe(false);
    expect(has(s('token = "the quick brown fox jumps"'), 'TM-SEC-002')).toBe(false);
  });

  it('does not run on tool definitions', () => {
    for (const r of secretRules) expect(r.kinds).not.toContain('tool-definition');
  });
});

describe('hardened secret patterns', () => {
  it('detects the newly added providers', () => {
    const cases: [string, string][] = [
      [fakeGroq, 'groq-key'],
      [fakeXai, 'xai-key'],
      [fakeGocspx, 'google-oauth-secret'],
      [fakeSendgrid, 'sendgrid-key'],
      [fakeShopify, 'shopify-token'],
      [fakeDiscord, 'discord-bot-token'],
    ];
    for (const [value, id] of cases) {
      const hits = findSecrets('x = ' + value).map((h) => h.patternId);
      expect(hits, id).toContain(id);
    }
  });

  it('redacts a detected secret, keeping a short recognisable prefix', () => {
    const red = redactSecrets('token=' + fakeGithub);
    expect(red).not.toContain(fakeGithub);
    expect(red).toContain('ghp_');
    expect(red).toContain('[redacted]');
  });

  it('keeps every pattern linear on repetitive input', () => {
    const inputs = ['a'.repeat(40_000), 'QUJD'.repeat(10_000), 'A1b2'.repeat(10_000), '.'.repeat(40_000)];
    for (const p of SECRET_PATTERNS) {
      for (const input of inputs) {
        const started = performance.now();
        new RegExp(p.regex.source, 'g').test(input);
        expect(performance.now() - started, p.id).toBeLessThan(200);
      }
    }
  });
});
