import type { Finding } from '../types.js';
import { atLeast } from '../types.js';
import { getOwn, setOwn } from './canonical.js';
import type { ToolDefinition } from './fingerprint.js';
import type { FindingSummary, PendingReason, PinnedTool, ServerEntry } from './lockfile.js';

/** enforce hides and blocks; warn only reports and records. */
export type Mode = 'enforce' | 'warn';
/** What happens to a tool that shows up on a server that is already pinned. */
export type OnNew = 'block' | 'allow';

export interface ToolInput {
  name: string;
  hash: string;
  definition: ToolDefinition;
  /** The pinned definition for this tool name, if there is one. */
  pinned?: PinnedTool;
  /** True while the server is being seen for the first time (trust on first use). */
  firstUse: boolean;
  onNew: OnNew;
  /** Scans the definition. Called only when the tool does not match its pin. */
  scan: () => Finding[];
}

interface DecisionBase {
  name: string;
  hash: string;
  definition: ToolDefinition;
}

export type ToolDecision =
  /** The definition matches its pin. */
  | (DecisionBase & { action: 'allow' })
  /** Not pinned yet and accepted: trust on first use, or --on-new allow. */
  | (DecisionBase & { action: 'pin'; why: 'first-use' | 'on-new-allow'; warnings: FindingSummary[] })
  /** Held for human review. */
  | (DecisionBase & { action: 'block'; reason: PendingReason; findings: FindingSummary[] });

/**
 * Decides one tool. A tool that matches its pin is allowed without
 * rescanning (a human or first use already accepted exactly this
 * definition). A changed definition is always held. An unpinned tool with a
 * high or critical finding is held as flagged even on first use or with
 * --on-new allow; otherwise first use pins it and later arrivals follow onNew.
 */
export function decideTool(input: ToolInput): ToolDecision {
  const base: DecisionBase = { name: input.name, hash: input.hash, definition: input.definition };
  if (input.pinned && input.pinned.hash === input.hash) return { ...base, action: 'allow' };
  const findings = summarize(input.scan());
  if (input.pinned) return { ...base, action: 'block', reason: 'changed', findings };
  if (findings.some((f) => isBlocking(f))) return { ...base, action: 'block', reason: 'flagged', findings };
  if (input.firstUse) return { ...base, action: 'pin', why: 'first-use', warnings: findings.filter(isWarning) };
  if (input.onNew === 'allow') return { ...base, action: 'pin', why: 'on-new-allow', warnings: findings.filter(isWarning) };
  return { ...base, action: 'block', reason: 'new', findings };
}

/** High and critical findings keep an unpinned tool away from the model. */
export function isBlocking(finding: { severity: Finding['severity'] }): boolean {
  return atLeast(finding.severity, 'high');
}

/** Medium findings let the tool through with a warning. */
export function isWarning(finding: { severity: Finding['severity'] }): boolean {
  return atLeast(finding.severity, 'medium') && !isBlocking(finding);
}

/** Findings worth keeping in the lockfile: everything above info. */
export function summarize(findings: readonly Finding[]): FindingSummary[] {
  return findings
    .filter((f) => atLeast(f.severity, 'low'))
    .map((f) => ({ ruleId: f.ruleId, severity: f.severity, message: f.message }));
}

export interface ApplyContext {
  command: string;
  now: string;
}

/**
 * Folds a list of decisions into a server's lock entry: pins accepted tools
 * and records held ones as pending. A pending entry that already holds the
 * same definition keeps its original detection time. Pure: returns a new entry.
 */
export function applyDecisions(current: ServerEntry | undefined, decisions: readonly ToolDecision[], ctx: ApplyContext): ServerEntry {
  const entry: ServerEntry = current
    ? { ...current, tools: { ...current.tools }, pending: { ...current.pending } }
    : { command: ctx.command, firstSeen: ctx.now, updated: ctx.now, tools: {}, pending: {} };
  let dirty = current === undefined || current.command !== ctx.command;
  entry.command = ctx.command;
  for (const decision of decisions) {
    if (decision.action === 'pin') {
      setOwn(entry.tools, decision.name, { hash: decision.hash, definition: decision.definition, pinnedAt: ctx.now });
      delete entry.pending[decision.name];
      dirty = true;
    } else if (decision.action === 'allow') {
      // The server serves the pinned definition again, so a change recorded earlier is obsolete.
      if (getOwn(entry.pending, decision.name) !== undefined) {
        delete entry.pending[decision.name];
        dirty = true;
      }
    } else {
      const existing = getOwn(entry.pending, decision.name);
      if (existing && existing.hash === decision.hash && existing.reason === decision.reason) continue;
      setOwn(entry.pending, decision.name, {
        hash: decision.hash,
        definition: decision.definition,
        detectedAt: existing?.hash === decision.hash ? existing.detectedAt : ctx.now,
        reason: decision.reason,
        findings: decision.findings,
      });
      dirty = true;
    }
  }
  if (dirty) entry.updated = ctx.now;
  return dirty ? entry : (current as ServerEntry);
}

/** Pinned tools that a complete listing no longer contains. */
export function removedTools(entry: ServerEntry | undefined, listed: ReadonlySet<string>): string[] {
  if (!entry) return [];
  return Object.keys(entry.tools).filter((name) => !listed.has(name)).sort();
}
