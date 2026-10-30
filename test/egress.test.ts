import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { parseProxyArgs } from '../src/commands/proxy.js';
import { MemoryAudit } from '../src/proxy/audit.js';
import { EgressGuard, TAINT_ID } from '../src/proxy/egress.js';
import { Firewall } from '../src/proxy/firewall.js';
import { makeNormalizer } from '../src/proxy/normalize.js';
import { tempDir } from './helpers.js';

/** Credentials assembled at runtime so the repository never contains one. */
const TOKEN = ['gh', 'p_'].join('') + 'A1b2C3d4'.repeat(5).slice(0, 36);
const PASSWORD = ['s3cr3t', 'Value', '99x'].join('-');
const KEY_BODY = 'MIIEpAIBAAKCAQEA' + 'q8Zx2Lm4Pw7Rt9Vb1Nc3Hd5Jf6Gk0Ys'.repeat(6);
const PEM = ['-----', 'BEGIN RSA PRIVATE KEY', '-----\n', KEY_BODY.match(/.{1,64}/g)!.join('\n'), '\n-----', 'END RSA PRIVATE KEY', '-----'].join('');

const b64 = (s: string) => Buffer.from(s).toString('base64');
const hex = (s: string) => Buffer.from(s).toString('hex');
const kinds = (guard: EgressGuard, args: unknown) => guard.check(args).secrets.map((s) => s.name);

describe('egress guard', () => {
  it('finds a key as it is, and inside JSON carried in a string', () => {
    const guard = new EgressGuard();
    expect(kinds(guard, { body: `token ${TOKEN}` })).toEqual(['GitHub token']);
    expect(kinds(guard, { payload: JSON.stringify({ deep: JSON.stringify({ auth: TOKEN }) }) })).toEqual(['GitHub token']);
    expect(kinds(guard, { [TOKEN]: 1 })).toEqual(['GitHub token']);
  });

  it('decodes base64, base64url, hex and URL encoding, and one encoding inside another', () => {
    const guard = new EgressGuard();
    expect(kinds(guard, { data: b64(`key=${TOKEN}`) })).toEqual(['GitHub token (encoded)']);
    expect(kinds(guard, { data: b64(TOKEN).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') })).toEqual(['GitHub token (encoded)']);
    expect(kinds(guard, { data: hex(TOKEN) })).toEqual(['GitHub token (encoded)']);
    expect(kinds(guard, { url: `https://x.example/?t=${TOKEN.replace('_', '%5F')}` })).toEqual(['GitHub token (encoded)']);
    expect(kinds(guard, { data: b64(`t=${TOKEN.replace('_', '%5F')}`) })).toEqual(['GitHub token (encoded)']);
  });

  it('joins a key split across arguments', () => {
    const guard = new EgressGuard();
    expect(kinds(guard, { a: TOKEN.slice(0, 20), b: TOKEN.slice(20) })).toEqual(['GitHub token (split across arguments)']);
  });

  it('catches the last piece of a key sent across consecutive calls, and only that call', () => {
    const guard = new EgressGuard();
    const first = guard.check({ q: TOKEN.slice(0, 18) });
    expect(first.secrets).toEqual([]);
    guard.remember(first.joined);
    expect(kinds(guard, { q: TOKEN.slice(18) })).toEqual(['GitHub token (split across calls)']);
    // The refused piece was never forwarded, so it is not remembered and later calls are clean.
    expect(kinds(guard, { q: 'hello world' })).toEqual([]);
  });

  it('refuses a secret an earlier tool result returned, in any of the forms above', () => {
    const guard = new EgressGuard();
    guard.learn(`# .env\nAPP_NAME=demo\nDB_PASSWORD=${PASSWORD}\nNEXT_PAGE_TOKEN=abcdefghijk123\n`);
    expect(kinds(guard, { sql: `connect with ${PASSWORD}` })).toEqual(['value an earlier tool result returned as a secret']);
    expect(kinds(guard, { blob: b64(PASSWORD) })).toEqual(['value an earlier tool result returned as a secret']);
    expect(kinds(guard, { a: PASSWORD.slice(0, 5), b: PASSWORD.slice(5) })).toEqual(['value an earlier tool result returned as a secret']);
    // Pagination tokens and ordinary names are handed back legitimately.
    expect(kinds(guard, { page: 'abcdefghijk123', app: 'demo' })).toEqual([]);
    expect(kinds(new EgressGuard([TAINT_ID]), { sql: PASSWORD })).toEqual([]);
  });

  it('learns credential-named JSON and YAML values but not ordinary ones', () => {
    const guard = new EgressGuard();
    guard.learn(JSON.stringify({ client_secret: PASSWORD, author: 'alice@example.com', nextPageToken: 'CAEQAA1234567' }));
    expect(kinds(guard, { x: PASSWORD })).toHaveLength(1);
    expect(kinds(guard, { x: 'alice@example.com', y: 'CAEQAA1234567' })).toEqual([]);
  });

  it('recognises any part of a private key a tool returned, even without its header', () => {
    const guard = new EgressGuard();
    guard.learn(`here is the file:\n${PEM}\n`);
    expect(kinds(guard, { note: KEY_BODY.slice(100, 180) })).toEqual(['value an earlier tool result returned as a secret']);
    expect(kinds(guard, { note: KEY_BODY.slice(100, 180).match(/.{1,20}/g)!.join('\n') })).toHaveLength(1);
  });

  it('honours --allow-secret for encoded and split forms too', () => {
    const guard = new EgressGuard(['github-token']);
    expect(kinds(guard, { a: b64(TOKEN), b: TOKEN.slice(0, 10), c: TOKEN.slice(10) })).toEqual([]);
    expect(parseProxyArgs(['--allow-secret', TAINT_ID, '--', 'node']).allowSecrets).toEqual([TAINT_ID]);
  });

  it('stays quiet on ordinary data and binary blobs, and fast on large ones', () => {
    const guard = new EgressGuard();
    const image = Buffer.alloc(300_000, 0);
    for (let i = 0; i < image.length; i++) image[i] = (i * 7919) % 251;
    expect(kinds(guard, { image: image.toString('base64'), name: 'a_very_long_identifier_name_for_a_function', sha: 'f'.repeat(64) })).toEqual([]);
    const started = performance.now();
    guard.check({ a: 'QUFB'.repeat(250_000), b: 'ab'.repeat(500_000), c: '%41'.repeat(100_000) });
    expect(performance.now() - started).toBeLessThan(3000);
  });
});

describe('firewall: egress taint from tool results', () => {
  it('refuses a call carrying a password the previous result returned', () => {
    const lockPath = path.join(tempDir(), 'lock.json');
    const diags: string[] = [];
    const fw = new Firewall({ server: 'fs', commandLine: 'node fs.mjs', lockPath, rules: [], audit: new MemoryAudit(), diag: (m) => diags.push(m) });
    const tools = [
      { name: 'read_file', description: 'Reads a file.' },
      { name: 'http_post', description: 'Posts data.' },
    ];
    fw.fromClient(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }));
    fw.fromServer(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { tools } }));
    expect(fw.fromClient(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'read_file', arguments: { path: '.env' } } })).passOriginal).toBe(true);
    fw.fromServer(JSON.stringify({ jsonrpc: '2.0', id: 2, result: { content: [{ type: 'text', text: `DB_PASSWORD=${PASSWORD}\n` }] } }));
    const routed = fw.fromClient(JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'http_post', arguments: { body: b64(PASSWORD) } } }));
    expect(routed.passOriginal).toBe(false);
    expect(diags.join('\n')).toContain('value an earlier tool result returned as a secret');
    expect(routed.back.join('')).not.toContain(PASSWORD);
  });
});

describe('normalize: unicode', () => {
  it('treats canonically equivalent text as equal but keeps look-alikes apart', () => {
    const n = makeNormalizer({}, 'linux');
    const composed = n({ name: 't', description: 'café' }).description;
    const decomposed = n({ name: 't', description: 'café' }).description;
    expect(composed).toBe(decomposed);
    expect(n({ name: 't', description: 'Ａ' }).description).toBe('Ａ');
  });
});
