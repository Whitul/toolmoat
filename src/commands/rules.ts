import { parseArgs } from 'node:util';
import { escapeCell } from '../report/markdown.js';
import { allRules } from '../rules/index.js';
import type { Rule, Severity } from '../types.js';
import { atLeast, isSeverity, SEVERITIES } from '../types.js';
import type { Palette } from '../util/colors.js';
import { palette } from '../util/colors.js';
import { VERSION } from '../version.js';

export const help = `Usage: toolmoat rules [options]

List every detection rule with its id, severity, category, the file kinds it
applies to and what it detects.

Options:
  -f, --format <format>    text (default), json or markdown (a README table)
      --severity <sev>     Only list rules at or above this severity
                           (critical, high, medium, low or info)
      --color, --no-color  Force or disable colors (NO_COLOR is honoured)`;

export type RulesFormat = 'text' | 'json' | 'markdown';

const RULES_FORMATS: readonly RulesFormat[] = ['text', 'json', 'markdown'];
const WRAP_WIDTH = 100;

export interface RulesIo {
  stdout(text: string): void;
  stderr(text: string): void;
  /** Whether stdout takes colors when neither --color nor --no-color is given. */
  color: boolean;
  rules: readonly Rule[];
}

export async function run(argv: string[], io: Partial<RulesIo> = {}): Promise<number> {
  const env: RulesIo = {
    stdout: (text) => process.stdout.write(text),
    stderr: (text) => process.stderr.write(text),
    color: palette(process.stdout).bold('x') !== 'x',
    rules: allRules,
    ...io,
  };
  let values: ReturnType<typeof parseRulesArgs>;
  try {
    values = parseRulesArgs(argv);
  } catch (error) {
    return usage(env, parseError(error));
  }
  if (values.help) {
    env.stdout(`${help}\n`);
    return 0;
  }
  const format = values.format ?? 'text';
  if (!isRulesFormat(format)) return usage(env, `unknown format '${format}' (expected ${RULES_FORMATS.join(', ')})`);
  const severity = values.severity;
  if (severity !== undefined && !isSeverity(severity)) return usage(env, `invalid --severity '${severity}' (expected ${SEVERITIES.join(', ')})`);

  const color = format === 'text' && (values['no-color'] ? false : values.color ? true : env.color);
  const selected = env.rules.filter((rule) => severity === undefined || atLeast(rule.severity, severity));
  env.stdout(renderRules(selected, format, { color }));
  return 0;
}

function parseRulesArgs(argv: string[]) {
  return parseArgs({
    args: argv,
    strict: true,
    allowPositionals: false,
    options: {
      format: { type: 'string', short: 'f' },
      severity: { type: 'string' },
      color: { type: 'boolean' },
      'no-color': { type: 'boolean' },
      help: { type: 'boolean', short: 'h' },
    },
  }).values;
}

/** Renders a rule list sorted by id. The result ends with a newline. */
export function renderRules(rules: readonly Rule[], format: RulesFormat, options: { color?: boolean } = {}): string {
  const sorted = [...rules].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  switch (format) {
    case 'json':
      return rulesJson(sorted);
    case 'markdown':
      return rulesMarkdown(sorted);
    case 'text':
      return rulesText(sorted, palette(process.stdout, options.color ?? false));
  }
}

function rulesJson(rules: readonly Rule[]): string {
  const out = {
    tool: 'toolmoat',
    version: VERSION,
    rules: rules.map((rule) => {
      const entry: Record<string, unknown> = {
        id: rule.id,
        title: rule.title,
        severity: rule.severity,
        category: rule.category,
        kinds: [...rule.kinds],
        description: rule.description,
      };
      if (rule.remediation) entry.remediation = rule.remediation;
      return entry;
    }),
  };
  return `${JSON.stringify(out, null, 2)}\n`;
}

function rulesMarkdown(rules: readonly Rule[]): string {
  const lines = ['| ID | Title | Severity | Category | Applies to | Description |', '| --- | --- | --- | --- | --- | --- |'];
  for (const rule of rules) {
    const cells = [`\`${rule.id}\``, escapeCell(rule.title), rule.severity, rule.category, escapeCell(rule.kinds.join(', ')), escapeCell(rule.description, 1000)];
    lines.push(`| ${cells.join(' | ')} |`);
  }
  return `${lines.join('\n')}\n`;
}

function rulesText(rules: readonly Rule[], c: Palette): string {
  if (rules.length === 0) return 'No rules match.\n';
  const idWidth = Math.max(...rules.map((rule) => rule.id.length));
  const lines: string[] = [];
  for (const rule of rules) {
    lines.push(`${c.cyan(rule.id.padEnd(idWidth))}  ${severityBadge(rule.severity, c)}  ${rule.category.padEnd(21)}  ${c.bold(rule.title)}`);
    lines.push(...wrap(`Applies to: ${rule.kinds.join(', ')}`, '  ').map(c.gray));
    lines.push(...wrap(rule.description, '  '));
    lines.push('');
  }
  const counts = SEVERITIES.map((s) => [s, rules.filter((rule) => rule.severity === s).length] as const)
    .filter(([, n]) => n > 0)
    .map(([s, n]) => `${n} ${s}`);
  lines.push(`${rules.length} rule${rules.length === 1 ? '' : 's'}: ${counts.join(', ')}`);
  return `${lines.join('\n')}\n`;
}

function severityBadge(severity: Severity, c: Palette): string {
  const text = severity.toUpperCase().padEnd('CRITICAL'.length);
  switch (severity) {
    case 'critical':
      return c.bold(c.magenta(text));
    case 'high':
      return c.bold(c.red(text));
    case 'medium':
      return c.yellow(text);
    case 'low':
      return c.blue(text);
    case 'info':
      return c.gray(text);
  }
}

function wrap(text: string, indent: string): string[] {
  const out: string[] = [];
  let line = '';
  for (const word of text.split(/\s+/)) {
    if (!word) continue;
    if (line && indent.length + line.length + 1 + word.length > WRAP_WIDTH) {
      out.push(indent + line);
      line = word;
    } else {
      line = line ? `${line} ${word}` : word;
    }
  }
  if (line) out.push(indent + line);
  return out;
}

function isRulesFormat(value: string): value is RulesFormat {
  return (RULES_FORMATS as readonly string[]).includes(value);
}

function usage(io: RulesIo, message: string): number {
  io.stderr(`toolmoat rules: ${message}\nRun 'toolmoat rules --help' for usage.\n`);
  return 2;
}

function parseError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  if ((error as { code?: unknown } | null)?.code === 'ERR_PARSE_ARGS_UNKNOWN_OPTION') {
    const option = /'([^']{1,200})'/.exec(message)?.[1];
    if (option) return `unknown option '${option}'`;
  }
  if ((error as { code?: unknown } | null)?.code === 'ERR_PARSE_ARGS_UNEXPECTED_POSITIONAL') {
    const arg = /'([^']{1,200})'/.exec(message)?.[1];
    if (arg) return `unexpected argument '${arg}'`;
  }
  return message;
}
