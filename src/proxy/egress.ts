import { findSecrets, SECRET_PATTERNS } from '../patterns/secrets.js';
import type { SecretSummary } from './audit.js';

/**
 * The egress guard: finds credentials in tool-call arguments before they
 * reach the server. Besides credential formats anywhere in the arguments, it
 * looks at URL-, base64- and hex-encoded values, JSON carried inside a
 * string, a key split across arguments or across the last few calls, and
 * secrets an earlier result of the same server returned (taint). It is a
 * speed bump against careless or scripted leaks, not a control: deliberate
 * transformations beyond these, or a key read through one server and sent
 * through another, still get past it.
 */

/** Pseudo pattern id for values first seen in a tool result. --allow-secret accepts it. */
export const TAINT_ID = 'tool-result';

type Via = 'plain' | 'encoded' | 'split' | 'calls' | 'taint';

/** Strings looked at individually for decoding and splits. The plain pass always covers the whole arguments. */
const MAX_LEAVES = 10_000;
/** JSON carried inside a string, inside a string... */
const MAX_JSON_DEPTH = 3;
const MAX_JSON_STRING = 1024 * 1024;
/** Base64 of URL-encoded text and similar. */
const MAX_DECODE_DEPTH = 2;
/** Decoded text kept per string, so one big decoy cannot use up the budget of the strings after it. */
const LEAF_DECODE_CHARS = 256 * 1024;
const TOTAL_DECODE_CHARS = 4 * 1024 * 1024;
/** At most this much of one base64 or hex run is decoded. */
const RUN_WINDOW = 64 * 1024;
/** Only strings up to this length are treated as possible pieces of a split key. */
const MAX_PIECE = 512;
const MAX_PIECES_TEXT = 1024 * 1024;
/** Short strings of this many earlier forwarded calls are kept, so a key sent in two pieces is recognised. */
const WINDOW_CALLS = 2;
/** Strings per call that are paired with each other and with those of the earlier calls. */
const MAX_PAIRED = 32;
const MAX_TAINTED = 300;
const MAX_KEY_CHUNKS = 1200;
const MIN_TAINTED = 10;
const MAX_TAINTED_LENGTH = 512;
/** Private key material is remembered in chunks of this size, so any part of it is recognised. */
const KEY_CHUNK = 40;
const MAX_KEY_BLOCK = 16 * 1024;
const MAX_KEY_BLOCKS = 50;
const LEARN_HEAD = 2 * 1024 * 1024;
const LEARN_TAIL = 256 * 1024;

/** The credential patterns without word boundaries, for text glued together from several pieces. */
const LOOSE_PATTERNS = SECRET_PATTERNS.map((p) => ({ id: p.id, name: p.name, regex: new RegExp(p.regex.source.replace(/\\b/g, ''), 'g') }));

/** NAME=value, NAME: value and "name": "value" at the start of a line (.env, ini, YAML, TOML, docker-compose lists). */
const LINE_ASSIGNMENT =
  /^[ \t]*(?:-[ \t]+)?(?:export[ \t]+)?["']?([A-Za-z_][A-Za-z0-9_.-]{0,63})["']?[ \t]*[:=][ \t]*(?:"((?:[^"\\\n]|\\.){1,512})"|'([^'\n]{1,512})'|([^\s"'#;,][^\s#;,]{0,511}))/gm;
/** "name": "value" anywhere, for minified JSON. */
const JSON_ASSIGNMENT = /"([A-Za-z_][A-Za-z0-9_.-]{0,63})"[ \t]*:[ \t]*"((?:[^"\\\n]|\\.){1,512})"/g;
/** Credential names, matched on the last segments of the name in SNAKE_CASE. */
const SECRET_NAME = /(?:^|_)(?:PASSWORD|PASSWD|PASSPHRASE|PWD|SECRET|SECRET_KEY|SECRET_ACCESS_KEY|CLIENT_SECRET|TOKEN|ACCESS_TOKEN|REFRESH_TOKEN|AUTH_TOKEN|BEARER_TOKEN|API_KEY|APIKEY|ACCESS_KEY|PRIVATE_KEY)$/;
/** Tokens that tools hand back legitimately: pagination, CSRF, state. */
const NOT_SECRET_NAME = /(?:^|_)(?:PAGE|NEXT|CURSOR|SYNC|CSRF|XSRF|STATE|NONCE|CONTINUATION)(?:_|$)/;
const PLACEHOLDER = /^(?:\$\{.*\}|\$\(.*\)|<.*>|%.*%|x{4,}|\*{3,}|your[_-]|changeme|example|placeholder|dummy|redacted|null|undefined|none|true|false)/i;

export interface EgressCheck {
  secrets: SecretSummary[];
  /** The call's short strings, to hand to remember() if the call is forwarded. */
  pieces: string[];
}

interface Candidate {
  text: string;
  via: Via;
  /** For text glued from pieces: where each piece starts, so a match must span two of them. */
  pieceStarts?: number[];
}

export class EgressGuard {
  private readonly allow: ReadonlySet<string>;
  private window: string[][] = [];
  private readonly tainted = new Set<string>();
  private readonly keyChunks = new Set<string>();

  constructor(allow: Iterable<string> = []) {
    this.allow = new Set(allow);
  }

  /** The credentials found in one call's arguments, plain ones first, at most one per kind. */
  check(args: unknown): EgressCheck {
    const found = new Map<string, SecretSummary & { via: Via }>();
    const add = (patternId: string, name: string, via: Via): void => {
      if (this.allow.has(patternId) || found.has(patternId)) return;
      found.set(patternId, { patternId, name: describe(name, via), via });
    };

    // The whole arguments as JSON, as before: no cap, so padding cannot push a key out of sight.
    const plain = jsonText(args);
    for (const hit of findSecrets(plain)) add(hit.patternId, hit.name, 'plain');

    const { values, keys } = collectLeaves(args);
    const candidates: Candidate[] = [];
    // Strings of JSON carried inside a string (their escapes are undone only here), and every string
    // when the arguments are nested too deeply to serialize.
    for (const leaf of values) if (leaf.depth > 0 || plain === '') candidates.push({ text: leaf.text, via: 'plain' });
    if (plain === '') for (const key of keys) candidates.push({ text: key, via: 'plain' });

    // Pieces of a split key: all short strings in order, and every pair of them in either order,
    // within this call and with the strings of the last calls, so other arguments in between do not matter.
    const pieces = values.map((leaf) => leaf.text).filter((text) => text.length > 0 && text.length <= MAX_PIECE);
    const joined = joinPieces(pieces);
    if (pieces.length > 1) candidates.push({ text: joined.text, via: 'split', pieceStarts: joined.starts });
    const paired = pieces.slice(0, MAX_PAIRED);
    for (let i = 0; i < paired.length; i++) {
      for (let j = 0; j < paired.length; j++) {
        if (i !== j) candidates.push({ text: paired[i]! + paired[j]!, via: 'split', pieceStarts: [0, paired[i]!.length] });
      }
    }
    for (const earlier of this.window) {
      for (const before of earlier) {
        for (const piece of paired) candidates.push({ text: before + piece, via: 'calls', pieceStarts: [0, before.length] });
      }
    }

    // Decoding, smallest strings first, each with its own share of the budget. The window of earlier
    // calls is not decoded: what decodes there was judged when it was sent.
    const budget = { total: TOTAL_DECODE_CHARS };
    const toDecode = [...values.map((leaf) => leaf.text), ...keys, ...(pieces.length > 1 ? [joined.text] : [])];
    toDecode.sort((a, b) => a.length - b.length);
    for (const text of toDecode) {
      if (budget.total <= 0) break;
      const leafBudget = { chars: Math.min(LEAF_DECODE_CHARS, budget.total) };
      let layer = [text];
      for (let depth = 0; depth < MAX_DECODE_DEPTH && layer.length > 0 && leafBudget.chars > 0; depth++) {
        layer = layer.flatMap((t) => decodedVariants(t, leafBudget));
        for (const decoded of layer) candidates.push({ text: decoded, via: 'encoded' });
      }
      budget.total -= Math.min(LEAF_DECODE_CHARS, budget.total) - leafBudget.chars;
    }

    for (const candidate of candidates) {
      if (candidate.pieceStarts !== undefined) {
        for (const hit of looseSecrets(candidate.text)) if (spansPieces(hit, candidate.pieceStarts)) add(hit.id, hit.name, candidate.via);
      } else {
        for (const hit of findSecrets(candidate.text)) add(hit.patternId, hit.name, candidate.via);
      }
    }

    if (!this.allow.has(TAINT_ID) && (this.tainted.size > 0 || this.keyChunks.size > 0)) {
      const taintTexts: Candidate[] = [...values.map((leaf) => ({ text: leaf.text, via: 'plain' as const })), ...keys.map((text) => ({ text, via: 'plain' as const })), ...candidates];
      if (taintTexts.some((c) => this.carriesTaint(c))) add(TAINT_ID, 'value an earlier tool result returned as a secret', 'taint');
    }

    const order: Via[] = ['plain', 'encoded', 'split', 'calls', 'taint'];
    const secrets = [...found.values()].sort((a, b) => order.indexOf(a.via) - order.indexOf(b.via)).map(({ patternId, name }) => ({ patternId, name }));
    return { secrets, pieces: paired };
  }

  /** Records the short strings of a forwarded call, so a key sent in two pieces is recognised when the second goes out. */
  remember(pieces: readonly string[]): void {
    this.window.push(pieces.slice(0, MAX_PAIRED).map(detach));
    if (this.window.length > WINDOW_CALLS) this.window.shift();
  }

  /**
   * Remembers the secrets a tool result carries, so a later call that sends
   * one out again is refused: credential formats, private key material, and
   * secret-looking values of credential-named entries (.env, ini, YAML, TOML,
   * JSON). Only the head and tail of a very large result are read.
   */
  learn(text: string): void {
    if (!text) return;
    const source = text.length > LEARN_HEAD + LEARN_TAIL ? `${text.slice(0, LEARN_HEAD)}\n${text.slice(-LEARN_TAIL)}` : text;
    for (const hit of findSecrets(source, 200)) {
      if (hit.patternId !== 'private-key' && !this.allow.has(hit.patternId)) this.addTaint(source.slice(hit.index, hit.index + hit.length));
    }
    this.learnKeyBlocks(source);
    for (const match of source.matchAll(LINE_ASSIGNMENT)) {
      const value = match[2] !== undefined ? unescapeJson(match[2]) : (match[3] ?? match[4] ?? '');
      if (isSecretName(match[1] ?? '') && looksSecret(value)) this.addTaint(value);
    }
    for (const match of source.matchAll(JSON_ASSIGNMENT)) {
      const value = unescapeJson(match[2] ?? '');
      if (isSecretName(match[1] ?? '') && looksSecret(value)) this.addTaint(value);
    }
  }

  /** Bodies of PEM private key blocks, in chunks. Linear: each END marker is searched for once. */
  private learnKeyBlocks(source: string): void {
    let pos = 0;
    let nextEnd = -2;
    for (let blocks = 0; blocks < MAX_KEY_BLOCKS; ) {
      const begin = source.indexOf('-----BEGIN ', pos);
      if (begin === -1) return;
      const headerEnd = source.indexOf('-----', begin + 11);
      if (headerEnd === -1 || headerEnd - begin > 80) return;
      pos = headerEnd + 5;
      if (!source.slice(begin, headerEnd).includes('PRIVATE KEY')) continue;
      if (nextEnd < pos) nextEnd = source.indexOf('-----END ', pos);
      if (nextEnd === -1) return;
      if (nextEnd - pos > MAX_KEY_BLOCK) continue;
      const body = source.slice(pos, nextEnd).replace(/\\[nr]|\s/g, '');
      for (let i = 0; i + KEY_CHUNK <= body.length; i += KEY_CHUNK) {
        if (this.keyChunks.size >= MAX_KEY_CHUNKS) this.keyChunks.delete(this.keyChunks.values().next().value as string);
        this.keyChunks.add(detach(body.slice(i, i + KEY_CHUNK)));
      }
      pos = nextEnd + 9;
      blocks++;
    }
  }

  private addTaint(value: string): void {
    const trimmed = value.trim();
    if (trimmed.length < MIN_TAINTED || trimmed.length > MAX_TAINTED_LENGTH || PLACEHOLDER.test(trimmed)) return;
    if (this.tainted.size >= MAX_TAINTED) this.tainted.delete(this.tainted.values().next().value as string);
    this.tainted.add(detach(trimmed));
  }

  /**
   * Whether a candidate holds a tainted value: as a whole token in a single
   * string, or, in text glued from pieces or calls, spanning two of them.
   */
  private carriesTaint({ text, pieceStarts }: Candidate): boolean {
    const glued = pieceStarts !== undefined;
    const spans = (at: number, length: number): boolean => pieceStarts?.some((start) => start > at && start < at + length) ?? false;
    for (const value of this.tainted) {
      if (!glued) {
        if (containsToken(text, value)) return true;
        continue;
      }
      for (let at = text.indexOf(value); at !== -1; at = text.indexOf(value, at + 1)) if (spans(at, value.length)) return true;
    }
    if (this.keyChunks.size > 0 && !glued) {
      const compact = text.replace(/\\[nr]|\s/g, '');
      for (const chunk of this.keyChunks) if (compact.includes(chunk)) return true;
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

function jsonText(value: unknown): string {
  try {
    return JSON.stringify(value) ?? '';
  } catch {
    return '';
  }
}

/** A flat copy, so a remembered piece does not keep the whole string it was cut from alive. */
function detach(text: string): string {
  return Buffer.from(text, 'utf8').toString('utf8');
}

function unescapeJson(raw: string): string {
  if (!raw.includes('\\')) return raw;
  try {
    return JSON.parse(`"${raw}"`) as string;
  } catch {
    return raw;
  }
}

/** A credential-like name: PASSWORD, DB_PASSWORD, secretAccessKey, api-key... but not NEXT_PAGE_TOKEN or TOKENIZER. */
export function isSecretName(name: string): boolean {
  const snake = name.replace(/([a-z0-9])([A-Z])/g, '$1_$2').replace(/[-.\s]+/g, '_').toUpperCase();
  return SECRET_NAME.test(snake) && !NOT_SECRET_NAME.test(snake);
}

/**
 * Whether a value under a credential name looks like a real secret rather
 * than a word, a code fragment or a path: at least 10 characters, two kinds
 * of character, no brackets, $ or URL scheme, and not a plain word.
 */
export function looksSecret(value: string): boolean {
  const v = value.trim();
  if (v.length < MIN_TAINTED || v.length > MAX_TAINTED_LENGTH || PLACEHOLDER.test(v)) return false;
  // Code, paths, URLs and variable references; a strong password may still hold any of these characters elsewhere.
  if (/^[[{$/~.]|\$\{|\$\(|\w\(|:\/\//.test(v)) return false;
  if (/^[A-Za-z]+$/.test(v) || /^[\d.]+$/.test(v)) return false;
  if (/\s/.test(v) && v.length < 16) return false;
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z\d\s]/].filter((re) => re.test(v)).length;
  return classes >= 2 && new Set(v).size >= 6;
}

/** text includes value not glued to letters or digits on either side. */
function containsToken(text: string, value: string): boolean {
  let at = text.indexOf(value);
  while (at !== -1) {
    const before = at > 0 ? text[at - 1]! : '';
    const after = text[at + value.length] ?? '';
    if (!/[A-Za-z0-9]/.test(before) && !/[A-Za-z0-9]/.test(after)) return true;
    at = text.indexOf(value, at + 1);
  }
  return false;
}

interface Leaf {
  text: string;
  /** 0 for strings of the arguments themselves, more for strings of JSON parsed out of a string. */
  depth: number;
}

/** Every string value in the arguments, in order, and separately every key. Iterative and bounded. */
function collectLeaves(args: unknown): { values: Leaf[]; keys: string[] } {
  const values: Leaf[] = [];
  const keys: string[] = [];
  const stack: Array<{ value: unknown; depth: number }> = [{ value: args, depth: 0 }];
  while (stack.length > 0 && values.length + keys.length < MAX_LEAVES) {
    const { value, depth } = stack.pop()!;
    if (typeof value === 'string') {
      values.push({ text: value, depth });
      const trimmed = value.trimStart();
      if (depth < MAX_JSON_DEPTH && value.length <= MAX_JSON_STRING && /^["{[]/.test(trimmed)) {
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
  return { values, keys };
}

function joinPieces(pieces: readonly string[]): { text: string; starts: number[] } {
  const starts: number[] = [];
  let text = '';
  for (const piece of pieces) {
    if (text.length + piece.length > MAX_PIECES_TEXT) break;
    starts.push(text.length);
    text += piece;
  }
  return { text, starts };
}

function looseSecrets(text: string): Array<{ id: string; name: string; index: number; length: number }> {
  const hits: Array<{ id: string; name: string; index: number; length: number }> = [];
  for (const pattern of LOOSE_PATTERNS) {
    pattern.regex.lastIndex = 0;
    let match: RegExpExecArray | null;
    while (hits.length < 50 && (match = pattern.regex.exec(text)) !== null) {
      hits.push({ id: pattern.id, name: pattern.name, index: match.index, length: match[0].length });
      if (match[0].length === 0) pattern.regex.lastIndex++;
    }
  }
  return hits;
}

/** A match that starts in one piece and ends in a later one. */
function spansPieces(hit: { index: number; length: number }, starts: readonly number[]): boolean {
  const end = hit.index + hit.length;
  return starts.some((start) => start > hit.index && start < end);
}

const isAlnum = (c: number): boolean => (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122);
/** A-Z a-z 0-9 + / - _ */
const BASE64_CHAR = (c: number): boolean => isAlnum(c) || c === 43 || c === 47 || c === 45 || c === 95;
const HEX_CHAR = (c: number): boolean => (c >= 48 && c <= 57) || (c >= 65 && c <= 70) || (c >= 97 && c <= 102);

/**
 * Readable texts hidden in one string: URL-decoded, each base64 run decoded
 * at all four alignments (a run can start mid-word, as in a URL path), each
 * hex run decoded, and base64 wrapped over several lines joined first.
 * Runs are found with a plain loop, never a backtracking regex over the
 * whole string, and only the first RUN_WINDOW characters of a run are used.
 */
function decodedVariants(text: string, budget: { chars: number }): string[] {
  const out: string[] = [];
  const keep = (decoded: string | null): void => {
    if (decoded === null || budget.chars <= 0) return;
    budget.chars -= decoded.length;
    out.push(decoded);
  };
  if (text.includes('%')) {
    const decoded = text.replace(/(?:%[0-9A-Fa-f]{2}){1,4096}/g, (run) => {
      try {
        return decodeURIComponent(run);
      } catch {
        return run;
      }
    });
    if (decoded !== text) keep(decoded);
  }
  const sources = [text];
  if (/[A-Za-z0-9+/=]{16,}\r?\n[A-Za-z0-9+/=]/.test(text.slice(0, 4096))) sources.push(text.replace(/\r?\n/g, ''));
  for (const source of sources) {
    for (const run of runs(source, BASE64_CHAR, 16)) {
      if (budget.chars <= 0) return out;
      const std = run.replace(/-/g, '+').replace(/_/g, '/');
      for (let offset = 0; offset < 4 && offset + 16 <= std.length; offset++) keep(readable(Buffer.from(std.slice(offset), 'base64')));
    }
  }
  for (const run of runs(text, HEX_CHAR, 24)) {
    if (budget.chars <= 0) return out;
    for (let offset = 0; offset < 2; offset++) {
      const hex = run.slice(offset);
      keep(readable(Buffer.from(hex.length % 2 === 0 ? hex : hex.slice(0, -1), 'hex')));
    }
  }
  return out;
}

/** Maximal runs of characters matching `char`, at least `min` long, each cut to RUN_WINDOW. */
function runs(text: string, char: (code: number) => boolean, min: number): string[] {
  const out: string[] = [];
  let start = -1;
  for (let i = 0; i <= text.length; i++) {
    const inside = i < text.length && char(text.charCodeAt(i));
    if (inside && start === -1) start = i;
    else if (!inside && start !== -1) {
      if (i - start >= min) out.push(text.slice(start, Math.min(i, start + RUN_WINDOW)));
      start = -1;
    }
  }
  return out;
}

/** The bytes as text when they decode to mostly printable UTF-8, otherwise null (images, compressed data). */
function readable(bytes: Buffer): string | null {
  if (bytes.length < 12) return null;
  const text = bytes.toString('utf8');
  let printable = 0;
  let total = 0;
  for (const ch of text) {
    total++;
    const code = ch.codePointAt(0) ?? 0;
    if (code !== 0xfffd && (code === 9 || code === 10 || code === 13 || (code >= 0x20 && code !== 0x7f))) printable++;
  }
  return printable >= total * 0.9 ? text : null;
}
