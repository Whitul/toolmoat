/**
 * Parses JSON that may contain // and /* *\/ comments and trailing commas, as
 * VS Code style config files do. Returns undefined instead of throwing.
 */
export function parseJsonc(text: string): unknown {
  const source = text.startsWith('﻿') ? text.slice(1) : text;
  try {
    return JSON.parse(source);
  } catch {
    // fall through to the lenient path
  }
  try {
    return JSON.parse(stripTrailingCommas(stripComments(source)));
  } catch {
    return undefined;
  }
}

/** Replaces comments with spaces so character offsets stay the same. */
export function stripComments(text: string): string {
  let out = '';
  let inString = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    const next = text[i + 1];
    if (inString) {
      out += ch;
      if (ch === '\\') {
        out += next ?? '';
        i++;
      } else if (ch === '"') {
        inString = false;
      }
    } else if (ch === '"') {
      inString = true;
      out += ch;
    } else if (ch === '/' && next === '/') {
      while (i < text.length && text[i] !== '\n') {
        out += ' ';
        i++;
      }
      if (i < text.length) out += '\n';
    } else if (ch === '/' && next === '*') {
      out += '  ';
      i += 2;
      while (i < text.length && !(text[i] === '*' && text[i + 1] === '/')) {
        out += text[i] === '\n' ? '\n' : ' ';
        i++;
      }
      out += '  ';
      i++;
    } else {
      out += ch;
    }
  }
  return out;
}

function stripTrailingCommas(text: string): string {
  let out = '';
  let inString = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    if (inString) {
      out += ch;
      if (ch === '\\') {
        out += text[i + 1] ?? '';
        i++;
      } else if (ch === '"') {
        inString = false;
      }
      continue;
    }
    if (ch === '"') {
      inString = true;
      out += ch;
      continue;
    }
    if (ch === ',') {
      let j = i + 1;
      while (j < text.length && /\s/.test(text[j]!)) j++;
      if (text[j] === '}' || text[j] === ']') {
        out += ' ';
        continue;
      }
    }
    out += ch;
  }
  return out;
}

/**
 * Best-effort offset of a JSON string value (or key) in the raw text, used to
 * point findings at the right line. Searches for the JSON-encoded form first,
 * then the raw value. Returns -1 when not found.
 */
export function indexOfJsonString(text: string, value: string, from = 0): number {
  const encoded = JSON.stringify(value);
  const exact = text.indexOf(encoded, from);
  if (exact !== -1) return exact;
  return text.indexOf(value, from);
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
