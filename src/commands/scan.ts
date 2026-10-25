import fs from 'node:fs';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { parseArgs } from 'node:util';
import type { ReportFormat } from '../report/index.js';
import { isReportFormat, REPORT_FORMATS, renderReport } from '../report/index.js';
import { allRules } from '../rules/index.js';
import type { DiscoverOptions, DiscoverResult } from '../scan/discover.js';
import { countBySeverity, scanFiles } from '../scan/engine.js';
import type { IgnoreConfig } from '../scan/ignore.js';
import { emptyIgnore, isFindingIgnored, parseIgnoreFile } from '../scan/ignore.js';
import type { Rule, ScanResult, Severity } from '../types.js';
import { atLeast, isSeverity, SEVERITIES } from '../types.js';
import { palette } from '../util/colors.js';
import { expandHome, toDisplayPath } from '../util/paths.js';
import { VERSION } from '../version.js';

export const help = `Usage: toolmoat scan [paths...] [options]

Scan agent skills, plugins, hooks and MCP server configs for malicious or
risky content. Runs fully offline. With no paths, scans the default agent
locations (Claude Code, Claude Desktop, Cursor, Windsurf, VS Code, Codex...).

Options:
  -f, --format <format>      text (default), json, sarif or markdown
  -o, --output <file>        Write the report to a file and print a one-line summary
      --fail-on <severity>   Exit 1 when a finding is at or above this severity:
                             critical, high (default), medium, low, info or none
      --min-severity <sev>   Hide findings below this severity (default: low,
                             or info with --verbose)
      --ignore-file <file>   Suppressions to apply (default: ./.toolmoatignore
                             if present; never read from scanned targets)
      --no-ignore            Apply no ignore file at all, e.g. when the current
                             directory is itself an untrusted download
      --defaults             Also scan the default agent locations when paths are given
      --deep                 Look further: deeper directory levels and bundled files
      --max-file-size <MiB>  Skip files larger than this many MiB
  -q, --quiet                Only print findings (nothing when clean); with
                             --output, print nothing to stdout
  -v, --verbose              Show info findings, skipped files and rule errors
      --color, --no-color    Force or disable colors (NO_COLOR is honoured)

--fail-on also counts findings hidden by --min-severity, but never findings
suppressed by the ignore file.

Exit codes:
  0  no findings at or above --fail-on
  1  findings at or above --fail-on
  2  usage or runtime error, including a path that does not exist

Examples:
  toolmoat scan
  toolmoat scan ./skills --format sarif --output toolmoat.sarif
  toolmoat scan . --fail-on medium --format markdown >> "$GITHUB_STEP_SUMMARY"`;

export type FailOn = Severity | 'none';

/** Input to the scan core. Paths are resolved by discovery against cwd. */
export interface ScanOptions {
  paths: string[];
  useDefaults: boolean;
  cwd: string;
  deep?: boolean;
  maxFileBytes?: number;
  /** The user's suppressions. Never loaded from inside a scanned target. */
  ignore?: IgnoreConfig;
  /** Findings below this severity are left out of the result. Default low. */
  minSeverity?: Severity;
  /** Default high. */
  failOn?: FailOn;
}

export interface ScanDeps {
  discover(options: DiscoverOptions): Promise<DiscoverResult>;
  /** Defaults to every built-in rule. */
  rules?: readonly Rule[];
}

export interface RuleError {
  ruleId: string;
  file: string;
  message: string;
}

export interface ScanOutcome {
  /** Findings at or above minSeverity, not suppressed by the ignore config. */
  result: ScanResult;
  exitCode: 0 | 1;
  roots: string[];
  /** Findings below minSeverity that were left out of the result. */
  hidden: number;
  /** Findings dropped by the ignore config. */
  suppressed: number;
  ruleErrors: RuleError[];
  /** Display path to absolute path of every scanned file. */
  filePaths: Map<string, string>;
}

/** Loaded on first use, so the scan core can be driven with in-memory files and no filesystem walker. */
async function lazyDiscover(options: DiscoverOptions): Promise<DiscoverResult> {
  const mod = await import('../scan/discover.js');
  return mod.discover(options);
}

/** The scan pipeline without any I/O of its own: discover, run the rules, filter, decide the exit code. */
export async function runScan(options: ScanOptions, deps: ScanDeps = { discover: lazyDiscover }): Promise<ScanOutcome> {
  const started = performance.now();
  const ignore = options.ignore ?? emptyIgnore();
  const minSeverity = options.minSeverity ?? 'low';
  const failOn = options.failOn ?? 'high';
  const rules = deps.rules ?? allRules;

  const discovered = await deps.discover({
    paths: options.paths,
    useDefaults: options.useDefaults,
    cwd: options.cwd,
    deep: options.deep,
    maxFileBytes: options.maxFileBytes,
    ignore,
  });

  const ruleErrors: RuleError[] = [];
  const all = scanFiles(discovered.files, {
    rules,
    onRuleError: (rule, file, error) => {
      ruleErrors.push({ ruleId: rule.id, file: file.displayPath, message: error instanceof Error ? error.message : String(error) });
    },
  });
  const active = all.filter((finding) => !isFindingIgnored(finding.ruleId, finding.file, ignore));
  const shown = active.filter((finding) => atLeast(finding.severity, minSeverity));
  const failed = failOn !== 'none' && active.some((finding) => atLeast(finding.severity, failOn));

  const targets = new Set<string>();
  const filePaths = new Map<string, string>();
  for (const file of discovered.files) {
    if (file.target) targets.add(file.target);
    if (!filePaths.has(file.displayPath)) filePaths.set(file.displayPath, file.path);
  }

  return {
    result: {
      findings: shown,
      filesScanned: discovered.files.length,
      targets: [...targets].sort(),
      skipped: discovered.skipped,
      rules,
      durationMs: performance.now() - started,
    },
    exitCode: failed ? 1 : 0,
    roots: discovered.roots,
    hidden: active.length - shown.length,
    suppressed: all.length - active.length,
    ruleErrors,
    filePaths,
  };
}

/** Process boundary for the command, injectable for tests. */
export interface ScanIo {
  cwd: string;
  stdout(text: string): void;
  stderr(text: string): void;
  /** Whether stdout takes colors when neither --color nor --no-color is given. */
  color: boolean;
  deps: ScanDeps;
}

interface CliOptions {
  help: boolean;
  paths: string[];
  useDefaults: boolean;
  format: ReportFormat;
  output?: string;
  failOn: FailOn;
  minSeverity: Severity;
  ignoreFile?: string;
  noIgnore: boolean;
  deep: boolean;
  maxFileBytes?: number;
  quiet: boolean;
  verbose: boolean;
  color?: boolean;
}

class UsageError extends Error {}

export async function run(argv: string[], io: Partial<ScanIo> = {}): Promise<number> {
  const env: ScanIo = { ...defaultIo(), ...io };
  let cli: CliOptions;
  try {
    cli = parseCli(argv);
  } catch (error) {
    env.stderr(`toolmoat scan: ${usageMessage(error)}\nRun 'toolmoat scan --help' for usage.\n`);
    return 2;
  }
  if (cli.help) {
    env.stdout(`${help}\n`);
    return 0;
  }

  // A mistyped path in CI must not turn into a silent, green "0 files scanned".
  const missing = cli.paths.filter((p) => !fs.existsSync(path.resolve(env.cwd, expandHome(p))));
  if (missing.length > 0) {
    env.stderr(`toolmoat scan: path not found: ${missing.join(', ')}\n`);
    return 2;
  }

  let ignore: { config: IgnoreConfig; display?: string };
  try {
    ignore = cli.noIgnore ? { config: emptyIgnore() } : loadIgnore(cli.ignoreFile, env.cwd);
  } catch (error) {
    env.stderr(`toolmoat scan: ${errorMessage(error)}\n`);
    return 2;
  }

  let outcome: ScanOutcome;
  try {
    outcome = await runScan(
      {
        paths: cli.paths,
        useDefaults: cli.useDefaults,
        cwd: env.cwd,
        deep: cli.deep,
        maxFileBytes: cli.maxFileBytes,
        ignore: ignore.config,
        minSeverity: cli.minSeverity,
        failOn: cli.failOn,
      },
      env.deps,
    );
  } catch (error) {
    env.stderr(`toolmoat scan: ${errorMessage(error)}\n`);
    return 2;
  }

  reportRuleErrors(outcome.ruleErrors, cli.verbose, env);

  const toFile = cli.output !== undefined;
  const report = renderReport(cli.format, outcome.result, {
    roots: outcome.roots,
    cwd: env.cwd,
    color: !toFile && cli.format === 'text' && (cli.color ?? env.color),
    verbose: cli.verbose,
    quiet: cli.quiet && !toFile,
    minSeverity: cli.minSeverity,
    hidden: outcome.hidden,
    suppressed: outcome.suppressed,
    ignoreFile: ignore.display,
    filePaths: outcome.filePaths,
  });

  if (cli.output === undefined) {
    env.stdout(report);
    return outcome.exitCode;
  }
  const target = path.resolve(env.cwd, cli.output);
  try {
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, report, 'utf8');
  } catch (error) {
    env.stderr(`toolmoat scan: cannot write ${cli.output}: ${errorMessage(error)}\n`);
    return 2;
  }
  if (!cli.quiet) env.stdout(`${summaryLine(outcome, cli.format, toDisplayPath(target, env.cwd))}\n`);
  return outcome.exitCode;
}

function defaultIo(): ScanIo {
  return {
    cwd: process.cwd(),
    stdout: (text) => process.stdout.write(text),
    stderr: (text) => process.stderr.write(text),
    // Probe the shared palette so TTY, NO_COLOR and FORCE_COLOR are decided in one place.
    color: palette(process.stdout).bold('x') !== 'x',
    deps: { discover: lazyDiscover },
  };
}

function parseCli(argv: string[]): CliOptions {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    strict: true,
    options: {
      format: { type: 'string', short: 'f' },
      output: { type: 'string', short: 'o' },
      'fail-on': { type: 'string' },
      'min-severity': { type: 'string' },
      'ignore-file': { type: 'string' },
      'no-ignore': { type: 'boolean' },
      defaults: { type: 'boolean' },
      deep: { type: 'boolean' },
      'max-file-size': { type: 'string' },
      quiet: { type: 'boolean', short: 'q' },
      verbose: { type: 'boolean', short: 'v' },
      color: { type: 'boolean' },
      'no-color': { type: 'boolean' },
      help: { type: 'boolean', short: 'h' },
    },
  });

  const format = values.format ?? 'text';
  if (!isReportFormat(format)) throw new UsageError(`unknown format '${format}' (expected ${REPORT_FORMATS.join(', ')})`);
  const failOn = values['fail-on'] ?? 'high';
  if (failOn !== 'none' && !isSeverity(failOn)) {
    throw new UsageError(`invalid --fail-on '${failOn}' (expected ${SEVERITIES.join(', ')} or none)`);
  }
  const verbose = values.verbose ?? false;
  const minSeverity = values['min-severity'] ?? (verbose ? 'info' : 'low');
  if (!isSeverity(minSeverity)) throw new UsageError(`invalid --min-severity '${minSeverity}' (expected ${SEVERITIES.join(', ')})`);
  if (values.output === '') throw new UsageError('--output needs a file name');
  if (values['no-ignore'] && values['ignore-file'] !== undefined) throw new UsageError('--ignore-file and --no-ignore cannot be combined');

  const cli: CliOptions = {
    help: values.help ?? false,
    paths: positionals,
    useDefaults: positionals.length === 0 || (values.defaults ?? false),
    format,
    failOn,
    minSeverity,
    noIgnore: values['no-ignore'] ?? false,
    deep: values.deep ?? false,
    quiet: values.quiet ?? false,
    verbose,
  };
  if (values.output !== undefined) cli.output = values.output;
  if (values['ignore-file'] !== undefined) cli.ignoreFile = values['ignore-file'];
  if (values['max-file-size'] !== undefined) cli.maxFileBytes = parseMiB(values['max-file-size']);
  if (values['no-color']) cli.color = false;
  else if (values.color) cli.color = true;
  return cli;
}

function parseMiB(value: string): number {
  const mib = /^\d{1,6}(?:\.\d{1,6})?$/.test(value.trim()) ? Number(value) : Number.NaN;
  if (!Number.isFinite(mib) || mib <= 0) throw new UsageError(`invalid --max-file-size '${value}' (expected a positive number of MiB)`);
  return Math.max(1, Math.round(mib * 1024 * 1024));
}

/**
 * The user's suppressions: --ignore-file when given (it must exist), else
 * .toolmoatignore in the cwd when present. Ignore files inside scanned
 * targets are never consulted.
 */
function loadIgnore(ignoreFile: string | undefined, cwd: string): { config: IgnoreConfig; display?: string } {
  if (ignoreFile !== undefined) {
    const file = path.resolve(cwd, ignoreFile);
    let text: string;
    try {
      text = fs.readFileSync(file, 'utf8');
    } catch (error) {
      throw new Error(`cannot read ignore file ${ignoreFile}: ${errorMessage(error)}`);
    }
    return { config: parseIgnoreFile(text), display: toDisplayPath(file, cwd) };
  }
  const local = path.join(cwd, '.toolmoatignore');
  let text: string;
  try {
    text = fs.readFileSync(local, 'utf8');
  } catch {
    return { config: emptyIgnore() };
  }
  return { config: parseIgnoreFile(text), display: '.toolmoatignore' };
}

function reportRuleErrors(errors: readonly RuleError[], verbose: boolean, io: ScanIo): void {
  if (errors.length === 0) return;
  if (verbose) {
    for (const e of errors) io.stderr(`toolmoat scan: rule ${e.ruleId} failed on ${e.file}: ${e.message}\n`);
    return;
  }
  const noun = errors.length === 1 ? 'error' : 'errors';
  io.stderr(`toolmoat scan: ${errors.length} rule ${noun} while scanning (run with --verbose for details)\n`);
}

/** One line for stdout when the report itself went to a file. */
export function summaryLine(outcome: ScanOutcome, format: ReportFormat, written: string): string {
  const { result } = outcome;
  const files = `${result.filesScanned} file${result.filesScanned === 1 ? '' : 's'}`;
  let status = 'no issues found';
  if (result.findings.length > 0) {
    const counts = countBySeverity(result.findings);
    const parts = SEVERITIES.filter((s) => counts[s] > 0).map((s) => `${counts[s]} ${s}`);
    status = `${result.findings.length} finding${result.findings.length === 1 ? '' : 's'} (${parts.join(', ')})`;
  }
  return `toolmoat ${VERSION}: ${status} in ${files}; ${format} report written to ${written}`;
}

function usageMessage(error: unknown): string {
  if (error instanceof UsageError) return error.message;
  const code = (error as { code?: unknown } | null)?.code;
  const message = errorMessage(error);
  if (code === 'ERR_PARSE_ARGS_UNKNOWN_OPTION') {
    const option = /'([^']{1,200})'/.exec(message)?.[1];
    return option ? `unknown option '${option}'` : message;
  }
  return message;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
