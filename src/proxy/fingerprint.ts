import type { EngineOptions } from '../scan/engine.js';
import { scanFile } from '../scan/engine.js';
import type { Finding, Rule, ScanFile } from '../types.js';
import { sha256 } from '../util/hash.js';
import { canonicalJson } from './canonical.js';

/** The parts of an MCP tool that shape what the model sees and does. Only these are pinned. */
export const FINGERPRINT_FIELDS = ['name', 'title', 'description', 'inputSchema', 'outputSchema', 'annotations'] as const;

/** A tool definition reduced to the pinned fields, with keys in canonical order. */
export type ToolDefinition = Record<string, unknown>;

/** Picks the pinned fields of a raw tool object and normalizes key order so equal tools compare equal. */
export function toolDefinition(tool: Record<string, unknown>): ToolDefinition {
  const picked: Record<string, unknown> = {};
  for (const field of FINGERPRINT_FIELDS) {
    if (tool[field] !== undefined) picked[field] = tool[field];
  }
  return JSON.parse(canonicalJson(picked)) as ToolDefinition;
}

/** sha256 of the canonical JSON of the pinned fields: stable under key reordering, sensitive to any other change. */
export function fingerprint(definition: ToolDefinition): string {
  return sha256(canonicalJson(definition));
}

/** Visiting more values than this means the definition cannot be read completely; see scanTool. */
const MAX_NODES = 500_000;
/** Keywords whose value is data the model reads as it is: every string below one counts. */
const VALUE_KEYS = new Set(['default', 'const', 'enum', 'examples']);
/** Schema keywords whose string is structure rather than prose. Every other string in a definition reaches the model. */
const STRUCTURAL_KEYS = new Set([
  'type', 'required', 'format', 'pattern', 'contentEncoding', 'contentMediaType',
  '$schema', '$ref', '$id', '$anchor', '$dynamicRef', '$dynamicAnchor',
]);
/** Keywords whose object value maps names to schemas, so its keys are parameter names and not keywords. */
const NAME_MAPS = new Set(['properties', 'patternProperties', '$defs', 'definitions', 'dependentSchemas']);

export interface ModelText {
  text: string;
  /** True when the definition was too big to read to the end. */
  truncated: boolean;
}

interface Frame {
  value: unknown;
  /** Inside a default, const, enum or examples value. */
  data: boolean;
  /** An object whose keys are names rather than keywords. */
  names: boolean;
}

/**
 * Collects every string of a tool definition that ends up in the model's
 * context: name, title, description, annotation titles and, inside the input
 * and output schemas, every string except structural keywords (type, format,
 * pattern, $ref...): descriptions, titles, comments, vendor extensions,
 * parameter names, defaults, enums and examples, at any depth. Each piece goes
 * on its own paragraph.
 */
export function modelVisibleText(definition: ToolDefinition): string {
  return collectModelText(definition).text;
}

/** Like modelVisibleText, and says when the definition was too big to read completely. Walks iteratively, so depth is no limit. */
export function collectModelText(definition: ToolDefinition): ModelText {
  const parts: string[] = [];
  for (const key of ['name', 'title', 'description'] as const) {
    const value = definition[key];
    if (typeof value === 'string' && value) parts.push(value);
  }
  let nodes = 0;
  let truncated = false;
  const stack: Frame[] = [definition.outputSchema, definition.inputSchema, definition.annotations].map((value) => ({ value, data: false, names: false }));
  while (stack.length > 0) {
    const { value, data, names } = stack.pop()!;
    if (++nodes > MAX_NODES) {
      truncated = true;
      break;
    }
    if (typeof value === 'string') {
      if (value) parts.push(value);
      continue;
    }
    if (value === null || typeof value !== 'object') continue;
    if (Array.isArray(value)) {
      for (let i = value.length - 1; i >= 0; i--) stack.push({ value: value[i], data, names: false });
      continue;
    }
    const record = value as Record<string, unknown>;
    const entries = Object.entries(record);
    if (!names && !data && isPlainObject(record.properties)) {
      const propertyNames = Object.keys(record.properties as object);
      if (propertyNames.length > 0) parts.push(`Parameters: ${propertyNames.join(', ')}`);
    }
    for (let i = entries.length - 1; i >= 0; i--) {
      const [key, child] = entries[i]!;
      if (names) {
        stack.push({ value: child, data: false, names: false });
      } else if (typeof child === 'string') {
        if (data || !STRUCTURAL_KEYS.has(key)) stack.push({ value: child, data, names: false });
      } else if (Array.isArray(child) && child.every((item) => typeof item === 'string')) {
        const strings = child.filter((item): item is string => item.length > 0);
        if ((data || !STRUCTURAL_KEYS.has(key)) && strings.length > 0) parts.push(strings.join('\n'));
      } else {
        stack.push({ value: child, data: data || VALUE_KEYS.has(key), names: !data && NAME_MAPS.has(key) && isPlainObject(child) });
      }
    }
  }
  return { text: parts.join('\n\n'), truncated };
}

function isPlainObject(value: unknown): boolean {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/** Synthetic path under which a live tool is reported, e.g. mcp://github/create_issue. */
export function toolPath(server: string, tool: string): string {
  return `mcp://${server}/${tool}`;
}

/** Runs the scanner's tool-definition rules over a tool's model-visible text. */
export function scanTool(server: string, definition: ToolDefinition, rules: readonly Rule[], onRuleError?: EngineOptions['onRuleError']): Finding[] {
  const name = typeof definition.name === 'string' ? definition.name : '';
  const path = toolPath(server, name);
  const { text, truncated } = collectModelText(definition);
  const file: ScanFile = { kind: 'tool-definition', path, displayPath: path, target: server, content: text };
  const findings = scanFile(file, onRuleError ? { rules, onRuleError } : { rules });
  if (truncated) findings.push(unreadableFinding(server, path));
  return findings;
}

/** A definition the scanner could not read to the end may hide text in the part it skipped, so it is treated as flagged. */
function unreadableFinding(server: string, path: string): Finding {
  return {
    ruleId: 'TM-PROXY-001',
    severity: 'high',
    category: 'obfuscation',
    title: 'Tool definition too large to inspect',
    message: `The definition has more than ${MAX_NODES} values, so toolmoat cannot check all of it for hidden instructions`,
    file: path,
    target: server,
    remediation: 'Review the definition with toolmoat diff and approve it only if the server is trusted.',
  };
}

/** Runs the same rules over text a tool returned, which can carry injected instructions too. */
export function scanToolOutput(server: string, tool: string, text: string, rules: readonly Rule[], onRuleError?: EngineOptions['onRuleError']): Finding[] {
  return scanText(server, `${toolPath(server, tool)}#output`, text, rules, onRuleError);
}

/** Scans the `instructions` of a server's initialize result, which many clients add to the model's context. */
export function scanServerInstructions(server: string, text: string, rules: readonly Rule[], onRuleError?: EngineOptions['onRuleError']): Finding[] {
  return scanText(server, `mcp://${server}#instructions`, text, rules, onRuleError);
}

function scanText(server: string, path: string, text: string, rules: readonly Rule[], onRuleError?: EngineOptions['onRuleError']): Finding[] {
  const file: ScanFile = { kind: 'tool-definition', path, displayPath: path, target: server, content: text };
  return scanFile(file, onRuleError ? { rules, onRuleError } : { rules });
}
