import os from 'node:os';
import path from 'node:path';
import { homeDir } from '../util/paths.js';
import type { ToolDefinition } from './fingerprint.js';

/**
 * Values that differ from one machine, container or checkout to the next and
 * that some servers write into their tool definitions: a hostname in a
 * description, a home directory as a default path. They are replaced with
 * placeholders before a definition is pinned or compared, so the same server
 * pins the same everywhere and a shared lockfile raises no false alarms.
 *
 * Hostnames and paths are replaced only where they are this machine's own
 * values, so a definition cannot use them to slip other text past a pin. The
 * one pattern-based rule, container ids, applies only to descriptions and
 * titles of servers started by a container runtime, where at most a 12-digit
 * hex id can change unnoticed.
 */
export interface VolatileValues {
  hostname?: string;
  home?: string;
  cwd?: string;
  tmp?: string;
  /** The server runs in a container, whose hostname is its 12-character id. */
  container?: boolean;
}

export type Normalizer = (definition: ToolDefinition) => ToolDefinition;

/** Paths shorter than this are too generic to replace. */
const MIN_PATH = 4;
/** Longer values are not real hostnames or paths, and would only make huge patterns. */
const MAX_VALUE = 4096;
const CONTAINER_RUNTIMES = new Set(['docker', 'podman', 'nerdctl']);
/** Schema keywords whose strings are structure, pinned exactly (the same set the scanner skips). */
const STRUCTURAL_KEYS = new Set([
  'type', 'required', 'format', 'pattern', 'contentEncoding', 'contentMediaType',
  '$schema', '$ref', '$id', '$anchor', '$dynamicRef', '$dynamicAnchor',
]);
/** Prose fields, the only place container ids are normalized. */
const PROSE_KEYS = new Set(['description', 'title']);
/** Characters that continue a name or path segment, so a match must not touch them on either side. */
const WORD = 'A-Za-z0-9_\\-';
const CONTAINER_ID = /(?<![A-Za-z0-9])[0-9a-f]{12}(?![A-Za-z0-9])/g;
/** A placeholder followed by path segments; only the separators between segments are rewritten. */
const PLACEHOLDER_PATH = /\{\{(?:home|cwd|tmp)\}\}(?:[\\/]+[A-Za-z0-9._~@%+=,-]*)*/g;
/** file:///C:/Users/x on Windows is file:///home/x on POSIX: one slash belongs to the path there. */
const FILE_URL = /file:\/{3}(?=\{\{(?:home|cwd|tmp)\}\})/gi;

/** The volatile values of this machine. command is the server executable, used to recognise container runtimes. */
export function localVolatileValues(command?: string): VolatileValues {
  let hostname: string | undefined;
  try {
    hostname = os.hostname();
  } catch {
    hostname = undefined;
  }
  return { hostname, home: homeDir(), cwd: process.cwd(), tmp: os.tmpdir(), container: command !== undefined && isContainerRuntime(command) };
}

/** docker, podman or nerdctl, by any path and with or without a Windows extension. */
export function isContainerRuntime(command: string): boolean {
  const base = path.posix.basename(command.replace(/\\/g, '/')).toLowerCase().replace(/\.(?:exe|cmd|bat)$/, '');
  return CONTAINER_RUNTIMES.has(base);
}

interface Replacement {
  re: RegExp;
  placeholder: string;
}

/**
 * Builds the normalizer for one set of values. It rewrites the strings of a
 * definition except the tool's own name and schema keywords such as type,
 * required and pattern; keys are never touched and the input is not mutated.
 * Line endings become \n, and longer paths are replaced before shorter ones,
 * so a temp directory under the home directory stays {{tmp}}.
 */
export function makeNormalizer(values: VolatileValues, platform: NodeJS.Platform = process.platform): Normalizer {
  const replacements = [...pathReplacements(values, platform), ...hostnameReplacements(values.hostname)];
  const normalize = (text: string, key: string): string => {
    if (STRUCTURAL_KEYS.has(key)) return text;
    // NFC only folds canonically equivalent sequences, which render identically; NFKC would fold look-alikes too.
    const nfc = text.normalize('NFC');
    let out = nfc.includes('\r') ? nfc.replace(/\r\n?/g, '\n') : nfc;
    for (const { re, placeholder } of replacements) out = out.replace(re, placeholder);
    if (values.container && PROSE_KEYS.has(key)) out = out.replace(CONTAINER_ID, (id) => (/[a-f]/.test(id) ? '{{container}}' : id));
    if (!out.includes('{{')) return out;
    // Separators after a placeholder differ between Windows and POSIX checkouts of the same lockfile.
    return out.replace(FILE_URL, 'file://').replace(PLACEHOLDER_PATH, (p) => p.replace(/[\\/]+/g, '/'));
  };
  return (definition) => {
    const out = mapStrings(definition, normalize);
    if (definition.name !== undefined) out.name = definition.name;
    return out;
  };
}

/**
 * Copies a JSON value, passing every string through fn with the key it sits
 * under (an array's strings get the array's key). Iterative, so nesting depth
 * is no limit, and own "__proto__" keys stay plain properties.
 */
function mapStrings(root: ToolDefinition, fn: (text: string, key: string) => string): ToolDefinition {
  const out: ToolDefinition = {};
  const stack: Array<{ src: object; dst: Record<string, unknown> | unknown[]; arrayKey: string }> = [{ src: root, dst: out, arrayKey: '' }];
  while (stack.length > 0) {
    const { src, dst, arrayKey } = stack.pop()!;
    const inArray = Array.isArray(src);
    for (const key of Object.keys(src)) {
      const value = (src as Record<string, unknown>)[key];
      const context = inArray ? arrayKey : key;
      let copy: unknown = value;
      if (typeof value === 'string') {
        copy = fn(value, context);
      } else if (value !== null && typeof value === 'object') {
        copy = Array.isArray(value) ? [] : {};
        stack.push({ src: value, dst: copy as Record<string, unknown> | unknown[], arrayKey: context });
      }
      if (Array.isArray(dst)) dst[Number(key)] = copy;
      else Object.defineProperty(dst, key, { value: copy, enumerable: true, writable: true, configurable: true });
    }
  }
  return out;
}

function pathReplacements(values: VolatileValues, platform: NodeJS.Platform): Replacement[] {
  const pathApi = platform === 'win32' ? path.win32 : path.posix;
  const candidates: Array<[string, string | undefined]> = [
    ['home', values.home],
    ['cwd', values.cwd],
    ['tmp', values.tmp],
  ];
  const seen = new Set<string>();
  const usable: Array<{ name: string; value: string }> = [];
  for (const [name, raw] of candidates) {
    if (!raw || raw.length > MAX_VALUE) continue;
    const value = raw.replace(/[\\/]+$/, '');
    if (value.length < MIN_PATH || pathApi.parse(raw).root === raw) continue;
    const key = platform === 'win32' ? value.toLowerCase().replace(/\\/g, '/') : value;
    if (seen.has(key)) continue;
    seen.add(key);
    usable.push({ name, value });
  }
  usable.sort((a, b) => b.value.length - a.value.length);
  const flags = platform === 'win32' ? 'gi' : 'g';
  return usable.map(({ name, value }) => {
    // macOS reports /var/... and /tmp, while servers that resolve symlinks print /private/var/...
    const prefix = platform === 'darwin' && /^\/(?:var|tmp)(?:\/|$)/.test(value) ? '(?:/private)?' : '';
    return { re: new RegExp(`(?<![${WORD}.])${prefix}${pathPattern(value)}(?![${WORD}])`, flags), placeholder: `{{${name}}}` };
  });
}

/**
 * The path as a pattern in which any separator matches /, \ or an escaped \\.
 * A leading separator matches exactly one, so the slashes of file:/// stay put.
 */
function pathPattern(value: string): string {
  return [...value].map((ch, i) => (ch === '/' || ch === '\\' ? (i === 0 ? '[\\\\/]' : '[\\\\/]{1,2}') : escapeRegExp(ch))).join('');
}

/**
 * The full and short hostname. A name made only of letters (ubuntu, server)
 * could be an ordinary word in a description, and replacing it on one machine
 * but not another would cause the very mismatch this avoids, so only names
 * with a digit, hyphen or dot are replaced.
 */
function hostnameReplacements(hostname: string | undefined): Replacement[] {
  if (!hostname || hostname.length > MAX_VALUE) return [];
  const names = [...new Set([hostname, hostname.split('.')[0] ?? ''])].filter((n) => n.length >= 3 && /[\d.-]/.test(n));
  names.sort((a, b) => b.length - a.length);
  return names.map((n) => ({ re: new RegExp(`(?<![${WORD}.])${escapeRegExp(n)}(?![${WORD}])`, 'gi'), placeholder: '{{hostname}}' }));
}

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
}
