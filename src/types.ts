export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export const SEVERITIES: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

export function isSeverity(value: string): value is Severity {
  return (SEVERITIES as readonly string[]).includes(value);
}

export function atLeast(severity: Severity, threshold: Severity): boolean {
  return SEVERITY_RANK[severity] >= SEVERITY_RANK[threshold];
}

export type Category =
  | 'prompt-injection'
  | 'hidden-content'
  | 'exfiltration'
  | 'credential-access'
  | 'dangerous-execution'
  | 'obfuscation'
  | 'persistence'
  | 'destructive'
  | 'excessive-permissions'
  | 'supply-chain'
  | 'secrets'
  | 'insecure-transport';

/**
 * What a file is to the agent. Rules declare the kinds they apply to, and
 * discovery assigns exactly one kind per file.
 */
export type FileKind =
  /** SKILL.md: frontmatter plus instructions loaded straight into the agent's context. */
  | 'skill'
  /** Other markdown an agent reads: CLAUDE.md, AGENTS.md, commands/*.md, agents/*.md, reference files inside a skill. */
  | 'instructions'
  /** Human-facing docs the agent normally does not load: README, CHANGELOG, CONTRIBUTING. */
  | 'docs'
  /** Executable code shipped with a skill, plugin, hook or MCP server (.sh, .ps1, .py, .js, .ts, ...). */
  | 'script'
  /** MCP client config: claude_desktop_config.json, .mcp.json, ~/.claude.json, Cursor, Windsurf, VS Code, Codex TOML. */
  | 'mcp-config'
  /** Agent harness settings holding hooks and permissions: .claude/settings*.json, hooks/hooks.json. */
  | 'agent-settings'
  /** Plugin and marketplace manifests: .claude-plugin/plugin.json, marketplace.json. */
  | 'plugin-manifest'
  /** Dependency manifests: package.json, pyproject.toml, requirements.txt. */
  | 'package-manifest'
  /** A live MCP tool definition (name, description, schema) observed by the runtime proxy. */
  | 'tool-definition';

export const FILE_KINDS: readonly FileKind[] = [
  'skill',
  'instructions',
  'docs',
  'script',
  'mcp-config',
  'agent-settings',
  'plugin-manifest',
  'package-manifest',
  'tool-definition',
];

export interface ScanFile {
  /** Absolute path on disk, or a synthetic id such as "mcp://server/tool" for live tool definitions. */
  path: string;
  /** Path shown in reports: relative to the scan root when possible, always with forward slashes. */
  displayPath: string;
  kind: FileKind;
  content: string;
  /** Logical owner shown in reports: a skill name, plugin name or MCP server name. */
  target?: string;
  /** Path relative to the scan root the file was found under, with forward slashes. */
  rootRelPath?: string;
}

/** What a rule returns for each problem it sees. The engine turns matches into findings. */
export interface RuleMatch {
  message: string;
  /** Character offset into file.content where the problem starts. The engine derives line and column from it. */
  index?: number;
  /** Explicit 1-based line, used when there is no meaningful offset. Ignored when index is set. */
  line?: number;
  /** Override the computed snippet, for example to show decoded hidden text. Redacted by the engine. */
  snippet?: string;
  /** Override the rule's default severity for this match, for example to escalate inside a tool definition. */
  severity?: Severity;
}

export interface Rule {
  /** Stable id such as "TM-PI-001". Never reuse or renumber an id. */
  id: string;
  title: string;
  /** One or two sentences explaining the threat, shown by `toolmoat rules` and in SARIF help. */
  description: string;
  category: Category;
  severity: Severity;
  kinds: readonly FileKind[];
  remediation?: string;
  /** Must be synchronous, side-effect free and linear-time on attacker-controlled input. */
  check(file: ScanFile): RuleMatch[];
}

export interface Finding {
  ruleId: string;
  severity: Severity;
  category: Category;
  title: string;
  message: string;
  /** The file's displayPath. */
  file: string;
  /** 1-based. */
  line?: number;
  /** 1-based. */
  column?: number;
  /** Single-line excerpt with secrets redacted, at most ~160 characters. */
  snippet?: string;
  target?: string;
  remediation?: string;
}

export interface SkippedFile {
  path: string;
  reason: string;
}

export interface ScanResult {
  findings: Finding[];
  filesScanned: number;
  /** Distinct targets (skills, plugins, servers) that were scanned. */
  targets: string[];
  skipped: SkippedFile[];
  /** The rules that were active, so reporters such as SARIF can describe them. */
  rules: readonly Rule[];
  durationMs: number;
}
