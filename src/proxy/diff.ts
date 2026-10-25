import { canonicalJson } from './canonical.js';

export type DiffOp = { type: 'same' | 'removed' | 'added'; line: string };

/** Above this many LCS cells the middle of the diff is shown as a plain replace, keeping memory bounded. */
const MAX_LCS_CELLS = 4_000_000;

/**
 * Line diff based on a longest common subsequence. Common prefix and suffix
 * are stripped first, so typical edits (an appended block in a description)
 * cost almost nothing.
 */
export function diffLines(before: readonly string[], after: readonly string[]): DiffOp[] {
  let start = 0;
  while (start < before.length && start < after.length && before[start] === after[start]) start++;
  let endA = before.length;
  let endB = after.length;
  while (endA > start && endB > start && before[endA - 1] === after[endB - 1]) {
    endA--;
    endB--;
  }
  const ops: DiffOp[] = before.slice(0, start).map((line) => ({ type: 'same', line }));
  ops.push(...diffMiddle(before.slice(start, endA), after.slice(start, endB)));
  ops.push(...before.slice(endA).map((line): DiffOp => ({ type: 'same', line })));
  return ops;
}

function diffMiddle(a: readonly string[], b: readonly string[]): DiffOp[] {
  const n = a.length;
  const m = b.length;
  if (n === 0 || m === 0 || (n + 1) * (m + 1) > MAX_LCS_CELLS) {
    return [...a.map((line): DiffOp => ({ type: 'removed', line })), ...b.map((line): DiffOp => ({ type: 'added', line }))];
  }
  const width = m + 1;
  const table = new Uint32Array((n + 1) * width);
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      table[i * width + j] = a[i] === b[j] ? table[(i + 1) * width + j + 1]! + 1 : Math.max(table[(i + 1) * width + j]!, table[i * width + j + 1]!);
    }
  }
  const ops: DiffOp[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      ops.push({ type: 'same', line: a[i]! });
      i++;
      j++;
    } else if (table[(i + 1) * width + j]! >= table[i * width + j + 1]!) {
      ops.push({ type: 'removed', line: a[i++]! });
    } else {
      ops.push({ type: 'added', line: b[j++]! });
    }
  }
  while (i < n) ops.push({ type: 'removed', line: a[i++]! });
  while (j < m) ops.push({ type: 'added', line: b[j++]! });
  return ops;
}

export interface Hunk {
  ops: DiffOp[];
}

/** Groups a diff into hunks of changes with `context` unchanged lines around each. */
export function hunks(ops: readonly DiffOp[], context = 3): Hunk[] {
  const changed = ops.map((op, index) => (op.type === 'same' ? -1 : index)).filter((index) => index !== -1);
  const out: Hunk[] = [];
  let current: { from: number; to: number } | undefined;
  for (const index of changed) {
    const from = Math.max(0, index - context);
    const to = Math.min(ops.length - 1, index + context);
    if (current && from <= current.to + 1) current.to = to;
    else {
      if (current) out.push({ ops: ops.slice(current.from, current.to + 1) });
      current = { from, to };
    }
  }
  if (current) out.push({ ops: ops.slice(current.from, current.to + 1) });
  return out;
}

/**
 * Pretty-prints a tool definition for review: canonical key order, two-space
 * indent, and strings that contain newlines spread over several lines so a
 * diff shows exactly which lines of a description were added. The output is
 * for humans and is not meant to be parsed back as JSON.
 */
export function prettyDefinition(value: unknown): string[] {
  const normalized = value === undefined ? null : (JSON.parse(canonicalJson(value)) as unknown);
  const lines: string[] = [];
  emit(normalized, '', '', '', lines);
  return lines;
}

function emit(value: unknown, indent: string, prefix: string, suffix: string, lines: string[]): void {
  if (Array.isArray(value)) {
    if (value.length === 0) {
      lines.push(`${indent}${prefix}[]${suffix}`);
      return;
    }
    lines.push(`${indent}${prefix}[`);
    value.forEach((item, index) => emit(item, `${indent}  `, '', index < value.length - 1 ? ',' : '', lines));
    lines.push(`${indent}]${suffix}`);
    return;
  }
  if (value !== null && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length === 0) {
      lines.push(`${indent}${prefix}{}${suffix}`);
      return;
    }
    lines.push(`${indent}${prefix}{`);
    entries.forEach(([key, child], index) => emit(child, `${indent}  `, `${JSON.stringify(key)}: `, index < entries.length - 1 ? ',' : '', lines));
    lines.push(`${indent}}${suffix}`);
    return;
  }
  if (typeof value === 'string' && value.includes('\n')) {
    const parts = value.split('\n');
    parts.forEach((part, index) => {
      const body = JSON.stringify(part).slice(1, -1);
      const open = index === 0 ? `${indent}${prefix}"` : `${indent}  `;
      const close = index === parts.length - 1 ? `"${suffix}` : '\\n';
      lines.push(`${open}${body}${close}`);
    });
    return;
  }
  lines.push(`${indent}${prefix}${JSON.stringify(value)}${suffix}`);
}
