import path from 'node:path';
import { pathToFileURL } from 'node:url';
import type { Category, Finding, Rule, ScanResult, Severity } from '../types.js';
import { sha256 } from '../util/hash.js';
import { expandHome } from '../util/paths.js';
import { printable } from '../util/text.js';
import { VERSION } from '../version.js';
import type { ReportOptions } from './index.js';

export const SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';
export const INFORMATION_URI = 'https://github.com/Whitul/toolmoat';
const SRCROOT = '%SRCROOT%';

type SarifLevel = 'error' | 'warning' | 'note';

const LEVEL: Record<Severity, SarifLevel> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
};

/** GitHub code scanning maps these to its critical/high/medium/low buckets. */
const SECURITY_SEVERITY: Record<Severity, string> = {
  critical: '9.5',
  high: '8.0',
  medium: '5.5',
  low: '3.0',
  info: '0.0',
};

export interface SarifArtifactLocation {
  uri: string;
  uriBaseId?: string;
}

export interface SarifReportingDescriptor {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  help: { text: string; markdown: string };
  defaultConfiguration: { level: SarifLevel };
  properties: { tags: string[]; precision: 'high' | 'medium'; 'security-severity': string };
}

export interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  level: SarifLevel;
  message: { text: string };
  locations: {
    physicalLocation: {
      artifactLocation: SarifArtifactLocation;
      region: { startLine: number; startColumn?: number; snippet?: { text: string } };
    };
  }[];
  partialFingerprints: { primaryLocationLineHash: string };
  properties: { severity: Severity; category: Category; target?: string };
}

export interface SarifLog {
  $schema: string;
  version: '2.1.0';
  runs: {
    tool: { driver: { name: string; version: string; semanticVersion: string; informationUri: string; rules: SarifReportingDescriptor[] } };
    originalUriBaseIds: Record<string, { uri: string }>;
    columnKind: 'utf16CodeUnits';
    results: SarifResult[];
  }[];
}

/** SARIF 2.1.0 for GitHub code scanning and other SARIF viewers. */
export function renderSarif(result: ScanResult, options: ReportOptions = {}): string {
  return `${JSON.stringify(buildSarif(result, options), null, 2)}\n`;
}

export function buildSarif(result: ScanResult, options: ReportOptions = {}): SarifLog {
  const version = options.version ?? VERSION;
  const cwd = path.resolve(options.cwd ?? process.cwd());
  const descriptors: SarifReportingDescriptor[] = [];
  const indexById = new Map<string, number>();
  const addDescriptor = (descriptor: SarifReportingDescriptor): number => {
    const existing = indexById.get(descriptor.id);
    if (existing !== undefined) return existing;
    indexById.set(descriptor.id, descriptors.length);
    descriptors.push(descriptor);
    return descriptors.length - 1;
  };
  for (const rule of result.rules) addDescriptor(ruleDescriptor(rule));

  const occurrences = new Map<string, number>();
  const results = result.findings.map((finding): SarifResult => {
    const ruleIndex = indexById.get(finding.ruleId) ?? addDescriptor(findingDescriptor(finding));
    const hash = sha256(`${finding.ruleId}\n${finding.file}\n${finding.snippet ?? ''}`).slice('sha256:'.length);
    const occurrence = (occurrences.get(hash) ?? 0) + 1;
    occurrences.set(hash, occurrence);
    const region: SarifResult['locations'][number]['physicalLocation']['region'] = { startLine: Math.max(1, finding.line ?? 1) };
    if (finding.line !== undefined && finding.column !== undefined) region.startColumn = Math.max(1, finding.column);
    if (finding.snippet) region.snippet = { text: finding.snippet };
    const properties: SarifResult['properties'] = { severity: finding.severity, category: finding.category };
    if (finding.target !== undefined) properties.target = finding.target;
    return {
      ruleId: finding.ruleId,
      ruleIndex,
      level: LEVEL[finding.severity],
      message: { text: printable(finding.message) },
      locations: [{ physicalLocation: { artifactLocation: sarifArtifactLocation(finding.file, cwd, options.filePaths), region } }],
      partialFingerprints: { primaryLocationLineHash: `${hash.slice(0, 32)}:${occurrence}` },
      properties,
    };
  });

  return {
    $schema: SARIF_SCHEMA,
    version: '2.1.0',
    runs: [
      {
        tool: { driver: { name: 'toolmoat', version, semanticVersion: version, informationUri: INFORMATION_URI, rules: descriptors } },
        originalUriBaseIds: { [SRCROOT]: { uri: directoryUri(cwd) } },
        columnKind: 'utf16CodeUnits',
        results,
      },
    ],
  };
}

/**
 * Where a finding lives, as SARIF wants it: a forward-slash path relative to
 * %SRCROOT% (the cwd) when the file is inside it, a file:/// URI for files
 * elsewhere such as ~/.claude, and synthetic ids like mcp://server/tool as is.
 */
export function sarifArtifactLocation(file: string, cwd: string, filePaths?: ReadonlyMap<string, string>): SarifArtifactLocation {
  if (file.includes('://')) return { uri: file };
  const absolute = filePaths?.get(file) ?? absoluteFromDisplay(file);
  if (absolute === undefined) return { uri: encodePath(file), uriBaseId: SRCROOT };
  const relative = path.relative(cwd, absolute);
  if (relative && relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative)) {
    return { uri: encodePath(relative.split(path.sep).join('/')), uriBaseId: SRCROOT };
  }
  return { uri: pathToFileURL(absolute).href };
}

function absoluteFromDisplay(file: string): string | undefined {
  if (file === '~' || file.startsWith('~/') || file.startsWith('~\\')) return expandHome(file);
  return path.isAbsolute(file) ? file : undefined;
}

function encodePath(relative: string): string {
  return relative.replace(/\\/g, '/').split('/').map(encodeURIComponent).join('/');
}

function directoryUri(dir: string): string {
  const href = pathToFileURL(dir).href;
  return href.endsWith('/') ? href : `${href}/`;
}

function ruleDescriptor(rule: Rule): SarifReportingDescriptor {
  return descriptor(rule.id, rule.title, rule.description, rule.severity, rule.category, rule.remediation, rule.kinds);
}

/** Fallback for a finding whose rule is not in the active rule list, so ruleIndex always resolves. */
function findingDescriptor(finding: Finding): SarifReportingDescriptor {
  return descriptor(finding.ruleId, finding.title, finding.title, finding.severity, finding.category, finding.remediation, []);
}

function descriptor(
  id: string,
  title: string,
  description: string,
  severity: Severity,
  category: Category,
  remediation: string | undefined,
  kinds: readonly string[],
): SarifReportingDescriptor {
  const facts = `Severity: ${severity}. Category: ${category}.${kinds.length > 0 ? ` Applies to: ${kinds.join(', ')}.` : ''}`;
  const text = [description, remediation ? `How to fix: ${remediation}` : '', facts].filter(Boolean).join('\n\n');
  const markdown = [`**${title}**`, description, remediation ? `**How to fix:** ${remediation}` : '', facts].filter(Boolean).join('\n\n');
  return {
    id,
    name: pascalCase(title) || id.replace(/-/g, ''),
    shortDescription: { text: title },
    fullDescription: { text: description },
    help: { text, markdown },
    defaultConfiguration: { level: LEVEL[severity] },
    properties: {
      tags: ['security', category],
      precision: severity === 'critical' || severity === 'high' ? 'high' : 'medium',
      'security-severity': SECURITY_SEVERITY[severity],
    },
  };
}

/** "Download piped into a shell" -> "DownloadPipedIntoAShell". */
function pascalCase(title: string): string {
  return title
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join('');
}
