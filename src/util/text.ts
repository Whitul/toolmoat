/** Converts a character offset into 1-based line and column numbers. */
export function lineColAt(content: string, index: number): { line: number; column: number } {
  const clamped = Math.max(0, Math.min(index, content.length));
  let line = 1;
  let lastNewline = -1;
  for (let i = content.indexOf('\n'); i !== -1 && i < clamped; i = content.indexOf('\n', i + 1)) {
    line++;
    lastNewline = i;
  }
  return { line, column: clamped - lastNewline };
}

/** Returns the text of a 1-based line without its line terminator, or '' when out of range. */
export function lineAt(content: string, line: number): string {
  if (line < 1) return '';
  let start = 0;
  for (let current = 1; current < line; current++) {
    const next = content.indexOf('\n', start);
    if (next === -1) return '';
    start = next + 1;
  }
  const end = content.indexOf('\n', start);
  return content.slice(start, end === -1 ? content.length : end).replace(/\r$/, '');
}

/** Offset of the first character of a 1-based line, or -1 when out of range. */
export function lineStartIndex(content: string, line: number): number {
  if (line < 1) return -1;
  let start = 0;
  for (let current = 1; current < line; current++) {
    const next = content.indexOf('\n', start);
    if (next === -1) return -1;
    start = next + 1;
  }
  return start;
}

export function truncate(text: string, max = 160): string {
  return text.length <= max ? text : `${text.slice(0, max - 1)}…`;
}

/**
 * Makes text safe to print on one terminal line: control and invisible
 * characters become visible escapes such as ​, so hidden payloads show up
 * in reports instead of being smuggled into them.
 */
export function printable(text: string): string {
  let out = '';
  for (const ch of text) {
    const code = ch.codePointAt(0) ?? 0;
    if (ch === '\t') out += ' ';
    else if (isInvisible(code) || code < 0x20 || code === 0x7f) {
      out += code > 0xffff ? `\\u{${code.toString(16)}}` : `\\u${code.toString(16).padStart(4, '0')}`;
    } else out += ch;
  }
  return out;
}

/** Zero-width, bidi-control, tag and other format characters that render as nothing. */
export function isInvisible(code: number): boolean {
  return (
    (code >= 0x200b && code <= 0x200f) ||
    (code >= 0x202a && code <= 0x202e) ||
    (code >= 0x2060 && code <= 0x2064) ||
    (code >= 0x2066 && code <= 0x2069) ||
    code === 0x00ad ||
    code === 0x034f ||
    code === 0x061c ||
    code === 0x115f ||
    code === 0x1160 ||
    code === 0x180e ||
    code === 0x3164 ||
    code === 0xfeff ||
    code === 0xffa0 ||
    (code >= 0xfe00 && code <= 0xfe0f) ||
    (code >= 0xe0000 && code <= 0xe007f) ||
    (code >= 0xe0100 && code <= 0xe01ef)
  );
}

export interface RegexHit {
  index: number;
  text: string;
  groups: (string | undefined)[];
}

/**
 * Runs a regex over content and returns every hit. The regex is copied with the
 * global flag added, so callers can pass literals without worrying about lastIndex.
 * Stops after `limit` hits so one noisy file cannot flood a report.
 */
export function findAll(regex: RegExp, content: string, limit = 50): RegexHit[] {
  const flags = regex.flags.includes('g') ? regex.flags : `${regex.flags}g`;
  const re = new RegExp(regex.source, flags);
  const hits: RegexHit[] = [];
  let match: RegExpExecArray | null;
  while (hits.length < limit && (match = re.exec(content)) !== null) {
    hits.push({ index: match.index, text: match[0], groups: match.slice(1) });
    if (match[0].length === 0) re.lastIndex++;
  }
  return hits;
}
