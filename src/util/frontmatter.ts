export type FrontmatterValue = string | string[];

export interface Frontmatter {
  /** Parsed top-level keys. Nested maps are kept as raw text under their key. */
  data: Record<string, FrontmatterValue>;
  /** 1-based line of each top-level key, for pointing findings at it. */
  lines: Record<string, number>;
  /** Markdown after the closing fence. */
  body: string;
  /** 1-based line where the body starts. */
  bodyLine: number;
}

/**
 * Parses the YAML frontmatter of a SKILL.md or command file. Handles the
 * subset these files use in practice: scalars, quoted strings, inline [a, b]
 * lists, "- item" lists and | or > block scalars. Returns null when the file
 * has no frontmatter. Never throws.
 */
export function parseFrontmatter(content: string): Frontmatter | null {
  const text = content.startsWith('﻿') ? content.slice(1) : content;
  const lines = text.split(/\r?\n/);
  if (lines[0]?.trim() !== '---') return null;
  let end = -1;
  for (let i = 1; i < lines.length; i++) {
    if (lines[i]!.trim() === '---') {
      end = i;
      break;
    }
  }
  if (end === -1) return null;

  const data: Record<string, FrontmatterValue> = {};
  const keyLines: Record<string, number> = {};
  let i = 1;
  while (i < end) {
    const line = lines[i]!;
    const m = /^([A-Za-z0-9_-]+)\s*:\s*(.*)$/.exec(line);
    if (!m) {
      i++;
      continue;
    }
    const key = m[1]!;
    const rest = m[2]!.trim();
    keyLines[key] = i + 1;
    i++;

    if (rest === '|' || rest === '>' || rest === '|-' || rest === '>-' || rest === '|+' || rest === '>+') {
      const block: string[] = [];
      while (i < end && (lines[i]!.startsWith(' ') || lines[i]!.startsWith('\t') || lines[i]!.trim() === '')) {
        block.push(lines[i]!.trim());
        i++;
      }
      data[key] = rest.startsWith('>') ? block.join(' ').replace(/\s+/g, ' ').trim() : block.join('\n').trim();
    } else if (rest === '') {
      const items: string[] = [];
      const raw: string[] = [];
      while (i < end && (lines[i]!.startsWith(' ') || lines[i]!.startsWith('\t') || lines[i]!.trim() === '')) {
        const item = /^\s*-\s+(.*)$/.exec(lines[i]!);
        if (item) items.push(unquote(item[1]!.trim()));
        raw.push(lines[i]!);
        i++;
      }
      data[key] = items.length > 0 ? items : raw.join('\n').trim();
    } else if (rest.startsWith('[') && rest.endsWith(']')) {
      data[key] = splitInlineList(rest.slice(1, -1));
    } else {
      data[key] = unquote(rest);
    }
  }

  return { data, lines: keyLines, body: lines.slice(end + 1).join('\n'), bodyLine: end + 2 };
}

function unquote(value: string): string {
  if (value.length >= 2 && ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'")))) {
    return value.slice(1, -1);
  }
  return value;
}

function splitInlineList(inner: string): string[] {
  const out: string[] = [];
  let current = '';
  let quote: string | null = null;
  let depth = 0;
  for (const ch of inner) {
    if (quote) {
      if (ch === quote) quote = null;
      current += ch;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
      current += ch;
    } else if (ch === '(') {
      depth++;
      current += ch;
    } else if (ch === ')') {
      depth = Math.max(0, depth - 1);
      current += ch;
    } else if (ch === ',' && depth === 0) {
      if (current.trim()) out.push(unquote(current.trim()));
      current = '';
    } else {
      current += ch;
    }
  }
  if (current.trim()) out.push(unquote(current.trim()));
  return out;
}

/** Reads a frontmatter value as a list: inline lists, "- item" lists and comma- or space-separated strings. */
export function asList(value: FrontmatterValue | undefined): string[] {
  if (value === undefined) return [];
  if (Array.isArray(value)) return value;
  return splitInlineList(value).flatMap(splitOutsideParens).filter(Boolean);
}

/** Splits on whitespace that is not inside parentheses, so "Read Bash(git status:*)" gives two tools. */
function splitOutsideParens(text: string): string[] {
  const out: string[] = [];
  let current = '';
  let depth = 0;
  for (const ch of text) {
    if (ch === '(') depth++;
    else if (ch === ')') depth = Math.max(0, depth - 1);
    if (/\s/.test(ch) && depth === 0) {
      if (current) out.push(current);
      current = '';
    } else {
      current += ch;
    }
  }
  if (current) out.push(current);
  return out;
}
