/**
 * Hardcoded-credential rules. TM-SEC-001 reports known credential formats
 * (via the shared secret patterns); TM-SEC-002 catches generic high-entropy
 * values assigned to secret-looking names. Both skip obvious placeholders and
 * documented examples so they stay quiet on templates and READMEs.
 *
 * Messages never contain the secret itself; the engine redacts snippets, and
 * these rules name only the credential type.
 */
import path from 'node:path';
import { pathKey } from '../clients/configs.js';
import { findSecrets } from '../patterns/secrets.js';
import type { FileKind, Rule, RuleMatch, ScanFile } from '../types.js';
import { isRecord, parseJsonc } from '../util/jsonc.js';
import { homeDir } from '../util/paths.js';
import { findAll } from '../util/text.js';

/** Secret rules apply to every kind except live tool definitions (the proxy guards those). */
const SECRET_KINDS: readonly FileKind[] = [
  'skill',
  'instructions',
  'docs',
  'script',
  'mcp-config',
  'agent-settings',
  'plugin-manifest',
  'package-manifest',
];

/** Signals that a literal is a placeholder, example or environment reference rather than a real secret. */
const PLACEHOLDER =
  /example|your[_-]?|changeme|change[_-]?this|placeholder|dummy|sample|redacted|insert[_-]?|replace[_-]?|token[_-]?here|key[_-]?here|xxxxx|\.\.\.|\$\{|\$\(|<[^>]{1,40}>|%[a-z_]+%|os\.environ|process\.env|getenv/i;

/** True when a secret literal looks like a template value, not a live credential. */
function isPlaceholder(value: string): boolean {
  if (PLACEHOLDER.test(value)) return true;
  if (/^[x0*.\-_]+$/i.test(value)) return true;
  const alnum = value.replace(/[^A-Za-z0-9]/g, '');
  if (alnum.length > 0 && new Set(alnum.toLowerCase()).size <= 3) return true;
  return false;
}

/**
 * True when a BEGIN PRIVATE KEY header is followed by actual key material.
 * A bare header (a test fixture, a detection pattern, docs) is not a leak.
 */
function hasKeyBody(content: string, from: number): boolean {
  const after = content.slice(from, from + 400).replace(/\\n|\\r|\s/g, '');
  return /[A-Za-z0-9+/=]{60}/.test(after);
}

/** The key name right before a JSON string value that starts at the end of the text. */
const PRIMARY_API_KEY_BEFORE = /"primaryApiKey"\s*:\s*"$/;

/**
 * True when the secret at index is the top-level primaryApiKey of the user's
 * own ~/.claude.json, where Claude Code itself stores the key it signs in
 * with. The same value anywhere else, or in any other file, is a leak, and so
 * is content passed in by name only (scan_text), which never has an absolute path.
 */
function isClaudeCodeOwnKey(file: ScanFile, index: number, value: string): boolean {
  if (!path.isAbsolute(file.path) || pathKey(file.path) !== pathKey(path.join(homeDir(), '.claude.json'))) return false;
  if (!PRIMARY_API_KEY_BEFORE.test(file.content.slice(Math.max(0, index - 64), index))) return false;
  if (jsonDepthAt(file.content, index) !== 1) return false;
  const data = parseJsonc(file.content);
  return isRecord(data) && typeof data.primaryApiKey === 'string' && data.primaryApiKey.includes(value);
}

/** How many objects and arrays are open at index, counting only brackets outside strings. */
function jsonDepthAt(text: string, index: number): number {
  let depth = 0;
  let inString = false;
  for (let i = 0; i < index; i++) {
    const ch = text[i];
    if (inString) {
      if (ch === '\\') i++;
      else if (ch === '"') inString = false;
    } else if (ch === '"') inString = true;
    else if (ch === '{' || ch === '[') depth++;
    else if (ch === '}' || ch === ']') depth--;
  }
  return inString ? depth : -1;
}

/** Shannon entropy in bits per character. */
function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let bits = 0;
  for (const count of freq.values()) {
    const p = count / s.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

const secHardcoded: Rule = {
  id: 'TM-SEC-001',
  title: 'Hardcoded credential',
  description:
    'A live-looking credential (API key, token or private key block) is embedded in the file. Committed secrets leak to anyone who reads the skill or its repository.',
  category: 'secrets',
  severity: 'high',
  kinds: SECRET_KINDS,
  remediation: 'Move the secret to an environment variable or secret manager and rotate the exposed value.',
  check(file) {
    const matches: RuleMatch[] = [];
    for (const hit of findSecrets(file.content, 50)) {
      const value = file.content.slice(hit.index, hit.index + hit.length);
      if (hit.patternId === 'private-key' && !hasKeyBody(file.content, hit.index + hit.length)) continue;
      if (hit.patternId !== 'private-key' && isPlaceholder(value)) continue;
      if (hit.patternId === 'anthropic-key' && isClaudeCodeOwnKey(file, hit.index, value)) {
        matches.push({
          index: hit.index,
          severity: 'low',
          message:
            'Claude Code keeps the API key it signs in with here, in plaintext (primaryApiKey). That is expected, but every skill, plugin and MCP server you run can read this file, so keep it private and never share or commit it',
        });
        continue;
      }
      matches.push({
        index: hit.index,
        severity: hit.patternId === 'private-key' ? 'critical' : 'high',
        message: `Hardcoded credential: ${hit.name}`,
      });
    }
    return matches;
  },
};

const ASSIGN =
  /\b(api[_-]?key|apikey|secret|client[_-]?secret|access[_-]?token|auth[_-]?token|refresh[_-]?token|bearer[_-]?token|token|password|passwd|pwd|passphrase|private[_-]?key)\b\s*[:=]{1,2}\s*["'`]([A-Za-z0-9_\-+./=~]{16,200})["'`]/i;

const secAssignment: Rule = {
  id: 'TM-SEC-002',
  title: 'Secret-like assignment',
  description:
    'A secret-looking name (password, api_key, token) is assigned a long, high-entropy literal. Even without a known vendor prefix this is very likely a hardcoded credential.',
  category: 'secrets',
  severity: 'medium',
  kinds: SECRET_KINDS,
  remediation: 'Load the value from the environment or a secret manager instead of hardcoding it.',
  check(file) {
    const matches: RuleMatch[] = [];
    for (const h of findAll(ASSIGN, file.content, 50)) {
      const value = h.groups[1];
      if (!value) continue;
      if (isPlaceholder(value)) continue;
      if (shannonEntropy(value) <= 3.5) continue;
      const name = (h.groups[0] ?? 'secret').toLowerCase();
      matches.push({ index: h.index, message: `High-entropy value assigned to "${name}" (likely a hardcoded secret)` });
    }
    return matches;
  },
};

export const secretRules: readonly Rule[] = [secHardcoded, secAssignment];
