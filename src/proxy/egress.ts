import { findSecrets } from '../patterns/secrets.js';
import type { SecretSummary } from './audit.js';

/**
 * The egress guard: finds credentials in tool-call arguments before they
 * reach the server. Beyond the plain JSON of the arguments it looks at
 * values that are URL-, base64- or hex-encoded, JSON carried inside a string,
 * a key split across several arguments or across consecutive calls, and
 * values an earlier tool result returned as a secret (taint). It is a speed
 * bump against careless or scripted leaks, not a control: deliberate
 * encodings beyond these, or a key read through one server and sent through
 * another, still get past it.
 */

/** Pseudo pattern id for values first seen in a tool result. --allow-secret accepts it. */
export const TAINT_ID = 'tool-result';

type Via = 'plain' | 'encoded' | 'split' | 'calls' | 'taint';

const MAX_LEAVES = 10_000;
/** JSON carried inside a string, inside a string... */
const MAX_JSON_DEPTH = 3;
/** Base64 of URL-encoded text and similar. */
const MAX_DECODE_DEPTH = 2;
const MAX_DECODED_CHARS = 1024 * 1024;
const MAX_JSON_STRING = 1024 * 1024;
/** Arguments of this many earlier calls are kept to catch a key sent in pieces. */
const WINDOW_CALLS = 4;
const WINDOW_CHARS_PER_CALL = 16 * 1024;
const MAX_TAINTED = 300;
const MIN_TAINTED = 8;
const MAX_TAINTED_LENGTH = 512;
/** Private key material is remembered in chunks of this size, so any part of it is recognised. */
const KEY_CHUNK = 40;
const MAX_LEARN_CHARS = 2 * 1024 * 1024;

/** 16 characters is 12 bytes, the shortest secret worth decoding. */
const BASE64_RUN = /[A-Za-z0-9+/_-]{16,}={0,2}/g;
const HEX_RUN = /(?<![0-9A-Fa-f])[0-9A-Fa-f]{24,}(?![0-9A-Fa-f])/g;
const PERCENT_RUN = /(?:%[0-9A-Fa-f]{2})+/g;
const PRIVATE_KEY_BLOCK = /-----BEGIN [A-Z ]{0,40}PRIVATE KEY(?: BLOCK)?-----([\s\S]{1,16384}?)-----END [A-Z ]{0,40}PRIVATE KEY(?: BLOCK)?-----/g;
/** NAME=value lines of .env files and shell configs. */
const ENV_ASSIGNMENT = /^[ \t]*(?:export[ \t]+)?([A-Z][A-Z0-9_]{1,63})[ \t]*=[ \t]*["']?([^\s"'`]{1,512})/gm;
/** "key": "value" and key: value in JSON, YAML and TOML. */
const KEY_ASSIGNMENT = /(?<![A-Za-z0-9_])["']?([A-Za-z][A-Za-z0-9_.-]{1,63})["']?[ \t]{0,4}[:=][ \t]{0,4}["']([^"'\n]{1,512})["']/g;
/** Names whose values are credentials. Pagination, CSRF and state tokens are left out on purpose: tools hand those back legitimately. */
const SECRET_ENV_NAME = /PASSWORD|PASSWD|PASSPHRASE|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIAL/;
const SECRET_KEY_NAME = /^(?:password|passwd|passphrase|secret|client_?secret|api_?key|apikey|private_?key|access_?key|secret_?key|access_?token|refresh_?token|auth_?token|bearer_?token)$/i;
const NOT_A_SECRET_NAME = /PAGE|CURSOR|NEXT|SYNC|CSRF|STATE|NONCE|TYPE|URL|PATH|FILE|NAME|ID$/i;
const PLACEHOLDER = /^(?:\$\{.*\}|\$\(.*\)|<.*>|%.*%|x{4,}|\*{3,}|your[_-]|changeme|example|placeholder|dummy|redacted|null|undefined|true|false)/i;

export interface EgressCheck {
  secrets: SecretSummary[];
  /** The call's strings joined, to hand to remember() if the call is forwarded. */
  joined: string;
}

export class EgressGuard {
  private readonly allow: ReadonlySet<string>;
  private window: string[] = [];
  private readonly tainted = new Set<string>();
  private readonly keyChunks = new Set<string>();

  constructor(allow: Iterable<string> = []) {
    this.allow = new Set(allow);
  }

  /** The credentials found in one call's arguments, plain ones first, at most one per kind. */
  check(args: unknown): EgressCheck {
    const { values: parts, keys } = collectLeaves(args);
    // Values only: a key name between two pieces would break a split key apart.
    const joined = parts.join('');
    const candidates: Array<{ text: string; via: Via; from?: number }> = keys.map((text) => ({ text, via: 'plain' as const }));
    const budget = { chars: MAX_DECODED_CHARS };
    for (const part of parts) {
      candidates.push({ text: part, via: 'plain' });
      let layer = [part];
      for (let depth = 0; depth < MAX_DECODE_DEPTH && layer.length > 0 && budget.chars > 0; depth++) {
        layer = layer.flatMap((text) => decodedVariants(text, budget));
        for (const text of layer) candidates.push({ text, via: 'encoded' });
      }
    }
    if (parts.length > 1) candidates.push({ text: joined, via: 'split' });
    if (this.window.length > 0) {
      const earlier = this.window.join('');
      // Only a key that reaches into this call counts; one wholly inside earlier calls was judged then.
      candidates.push({ text: earlier + joined.slice(0, WINDOW_CHARS_PER_CALL), via: 'calls', from: earlier.length });
    }

    const found = new Map<string, SecretSummary & { via: Via }>();
    const add = (patternId: string, name: string, via: Via): void => {
      if (this.allow.has(patternId) || found.has(patternId)) return;
      found.set(patternId, { patternId, name: describe(name, via), via });
    };
    for (const { text, via, from } of candidates) {
      for (const hit of findSecrets(text)) {
        if (from !== undefined && hit.index + hit.length <= from) continue;
        add(hit.patternId, hit.name, via);
      }
    }
    if (!this.allow.has(TAINT_ID) && (this.tainted.size > 0 || this.keyChunks.size > 0) && candidates.some((c) => this.carriesTaint(c.text, c.from))) {
      add(TAINT_ID, 'value an earlier tool result returned as a secret', 'taint');
    }
    const order: Via[] = ['plain', 'encoded', 'split', 'calls', 'taint'];
    const secrets = [...found.values()].sort((a, b) => order.indexOf(a.via) - order.indexOf(b.via)).map(({ patternId, name }) => ({ patternId, name }));
    return { secrets, joined };
  }

  /** Records the strings of a forwarded call, so a key sent in pieces is recognised when its last piece goes out. */
  remember(joined: string): void {
    this.window.push(joined.slice(-WINDOW_CHARS_PER_CALL));
    if (this.window.length > WINDOW_CALLS) this.window.shift();
  }

  /**
   * Remembers the secrets a tool result carries, so they are refused if a
   * later call tries to send them out again: known credential formats,
   * private key material, and the values of credential-named entries in
   * .env, JSON, YAML or TOML text.
   */
  learn(text: string): void {
    if (!text) return;
    const source = text.length > MAX_LEARN_CHARS ? text.slice(0, MAX_LEARN_CHARS) : text;
    for (const hit of findSecrets(source, 200)) {
      if (hit.patternId !== 'private-key' && !this.allow.has(hit.patternId)) this.taint(source.slice(hit.index, hit.index + hit.length));
    }
    for (const match of source.matchAll(PRIVATE_KEY_BLOCK)) {
      const body = (match[1] ?? '').replace(/\\[nr]|\s/g, '');
      for (let i = 0; i + KEY_CHUNK <= body.length && this.keyChunks.size < MAX_TAINTED * 4; i += KEY_CHUNK) this.keyChunks.add(body.slice(i, i + KEY_CHUNK));
    }
    for (const match of source.matchAll(ENV_ASSIGNMENT)) {
      const [, name = '', value = ''] = match;
      if (SECRET_ENV_NAME.test(name) && !NOT_A_SECRET_NAME.test(name)) this.taint(value);
    }
    for (const match of source.matchAll(KEY_ASSIGNMENT)) {
      const [, name = '', value = ''] = match;
      if (SECRET_KEY_NAME.test(name)) this.taint(value);
    }
  }

  private taint(value: string): void {
    const trimmed = value.trim();
    if (trimmed.length < MIN_TAINTED || trimmed.length > MAX_TAINTED_LENGTH) return;
    if (PLACEHOLDER.test(trimmed) || /^[\d.]+$/.test(trimmed) || new Set(trimmed).size <= 3) return;
    if (this.tainted.size >= MAX_TAINTED) {
      const oldest = this.tainted.values().next().value;
      if (oldest !== undefined) this.tainted.delete(oldest);
    }
    this.tainted.add(trimmed);
  }

  /** Whether text holds a tainted value that reaches past `from` (the start of this call in a window of earlier calls). */
  private carriesTaint(text: string, from = 0): boolean {
    const reaches = (haystack: string, needle: string, start: number): boolean => {
      const at = haystack.indexOf(needle, Math.max(0, start - needle.length + 1));
      return at !== -1;
    };
    for (const value of this.tainted) if (reaches(text, value, from)) return true;
    if (this.keyChunks.size > 0) {
      // Whitespace is dropped from both sides, so the window offset is only approximate here: count the whole text.
      const compact = text.replace(/\\[nr]|\s/g, '');
      const start = from === 0 ? 0 : compact.length - text.slice(from).replace(/\\[nr]|\s/g, '').length;
      for (const chunk of this.keyChunks) if (reaches(compact, chunk, start)) return true;
    }
    return false;
  }
}

function describe(name: string, via: Via): string {
  switch (via) {
    case 'plain':
    case 'taint':
      return name;
    case 'encoded':
      return `${name} (encoded)`;
    case 'split':
      return `${name} (split across arguments)`;
    case 'calls':
      return `${name} (split across calls)`;
  }
}

/**
 * Every string value in the arguments, in order, and separately every key,
 * including those of JSON carried inside a string. Iterative and bounded.
 */
function collectLeaves(args: unknown): { values: string[]; keys: string[] } {
  const out: string[] = [];
  const keys: string[] = [];
  const stack: Array<{ value: unknown; depth: number }> = [{ value: args, depth: 0 }];
  while (stack.length > 0 && out.length + keys.length < MAX_LEAVES) {
    const { value, depth } = stack.pop()!;
    if (typeof value === 'string') {
      out.push(value);
      const trimmed = value.trimStart();
      if (depth < MAX_JSON_DEPTH && value.length <= MAX_JSON_STRING && (trimmed.startsWith('{') || trimmed.startsWith('['))) {
        try {
          stack.push({ value: JSON.parse(value) as unknown, depth: depth + 1 });
        } catch {
          // Not JSON after all.
        }
      }
    } else if (Array.isArray(value)) {
      for (let i = value.length - 1; i >= 0; i--) stack.push({ value: value[i], depth });
    } else if (value !== null && typeof value === 'object') {
      const entries = Object.entries(value as Record<string, unknown>);
      for (let i = entries.length - 1; i >= 0; i--) {
        const [key, child] = entries[i]!;
        keys.push(key);
        stack.push({ value: child, depth });
      }
    }
  }
  return { values: out, keys };
}

/** Readable texts hidden in one string: URL-decoded, and each long base64 or hex run decoded. */
function decodedVariants(text: string, budget: { chars: number }): string[] {
  const out: string[] = [];
  const keep = (decoded: string | null): void => {
    if (decoded === null || budget.chars <= 0) return;
    budget.chars -= decoded.length;
    out.push(decoded);
  };
  if (text.includes('%')) {
    const decoded = text.replace(PERCENT_RUN, (run) => {
      try {
        return decodeURIComponent(run);
      } catch {
        return run;
      }
    });
    if (decoded !== text) keep(decoded);
  }
  for (const match of text.matchAll(BASE64_RUN)) {
    if (budget.chars <= 0) break;
    keep(readable(Buffer.from(match[0].replace(/-/g, '+').replace(/_/g, '/'), 'base64')));
  }
  for (const match of text.matchAll(HEX_RUN)) {
    if (budget.chars <= 0) break;
    const hex = match[0].length % 2 === 0 ? match[0] : match[0].slice(0, -1);
    keep(readable(Buffer.from(hex, 'hex')));
  }
  return out;
}

/** The bytes as text when they decode to mostly printable UTF-8, otherwise null (images, compressed data). */
function readable(bytes: Buffer): string | null {
  if (bytes.length < 12) return null;
  const text = bytes.toString('utf8');
  let printable = 0;
  for (const ch of text) {
    const code = ch.codePointAt(0) ?? 0;
    if (code !== 0xfffd && (code === 9 || code === 10 || code === 13 || (code >= 0x20 && code !== 0x7f))) printable++;
  }
  return printable >= text.length * 0.9 ? text : null;
}
