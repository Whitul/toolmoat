import type { ScanResult, Severity } from '../types.js';
import { renderJson } from './json.js';
import { renderMarkdown } from './markdown.js';
import { renderSarif } from './sarif.js';
import { renderText } from './text.js';

export type ReportFormat = 'text' | 'json' | 'sarif' | 'markdown';

export const REPORT_FORMATS: readonly ReportFormat[] = ['text', 'json', 'sarif', 'markdown'];

export function isReportFormat(value: string): value is ReportFormat {
  return (REPORT_FORMATS as readonly string[]).includes(value);
}

/** Context shared by every reporter. Reporters are pure: everything they print comes from the result and these options. */
export interface ReportOptions {
  /** Version printed in the report. Defaults to the running toolmoat version. */
  version?: string;
  /** Scan roots shown in the text header: display paths, or absolute paths that get shortened. */
  roots?: readonly string[];
  /** Directory paths are shown relative to, and the SARIF %SRCROOT%. Defaults to process.cwd(). */
  cwd?: string;
  /** Text only: emit ANSI colors. */
  color?: boolean;
  /** Text only: list skipped files and every scan root. */
  verbose?: boolean;
  /** Text only: print findings and nothing else, and nothing at all when clean. */
  quiet?: boolean;
  /** The --min-severity the result was filtered with. */
  minSeverity?: Severity;
  /** How many findings were dropped for being below minSeverity. */
  hidden?: number;
  /** How many findings the user's ignore file suppressed. */
  suppressed?: number;
  /** Display path of the ignore file that was applied, if any. */
  ignoreFile?: string;
  /** Maps a finding's display path to its absolute path, so SARIF can emit exact URIs. */
  filePaths?: ReadonlyMap<string, string>;
}

/** Renders a scan result in the requested format. The returned string ends with a newline unless it is empty. */
export function renderReport(format: ReportFormat, result: ScanResult, options: ReportOptions = {}): string {
  switch (format) {
    case 'text':
      return renderText(result, options);
    case 'json':
      return renderJson(result, options);
    case 'sarif':
      return renderSarif(result, options);
    case 'markdown':
      return renderMarkdown(result, options);
  }
}

export { renderJson, toJsonFinding } from './json.js';
export { escapeCell, renderMarkdown } from './markdown.js';
export { buildSarif, renderSarif, sarifArtifactLocation } from './sarif.js';
export { renderText, shortPath } from './text.js';
