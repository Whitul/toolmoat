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
  /** Fingerprint of the normalized definition (see normalize.ts). */
  hash: string;
  /** Fingerprint of the definition exactly as served, which is what toolmoat 0.2 and earlier pinned. */
  legacyHash?: string;
  /** The normalized definition, as it is stored in the lockfile. */
  definition: ToolDefinition;
  /** The pinned definition for this tool name, if there is one. */
  pinned?: PinnedTool;
  /** The server's command line differs from the one recorded in the lockfile. Only noted on new tools. */
  launchChanged?: boolean;
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
  /**
   * Accepted and (re)pinned: trust on first use, --on-new allow, or "repin"
   * for a pin made from the exact same definition by a version that did not
   * normalize yet, which only rewrites the pin in the current form.
   */
  | (DecisionBase & { action: 'pin'; why: 'first-use' | 'on-new-allow' | 'repin'; warnings: FindingSummary[] })
  /** Held for human review. legacyHash lets a pending entry from an older version keep its detection time. */
  | (DecisionBase & { action: 'block'; reason: PendingReason; findings: FindingSummary[]; launchChanged?: boolean; legacyHash?: string });

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
  if (input.pinned && input.legacyHash !== undefined && input.pinned.hash === input.legacyHash) return { ...base, action: 'pin', why: 'repin', warnings: [] };
  const findings = summarize(input.scan());
  const legacy = input.legacyHash !== undefined ? { legacyHash: input.legacyHash } : {};
  if (input.pinned) return { ...base, action: 'block', reason: 'changed', findings, ...legacy };
  if (findings.some((f) => isBlocking(f))) return { ...base, action: 'block', reason: 'flagged', findings, ...legacy };
  if (input.firstUse) return { ...base, action: 'pin', why: 'first-use', warnings: findings.filter(isWarning) };
  if (input.onNew === 'allow') return { ...base, action: 'pin', why: 'on-new-allow', warnings: findings.filter(isWarning) };
  // Only new tools get the note: a changed command line can add tools, but it rarely explains a rewritten description.
  return { ...base, action: 'block', reason: 'new', findings, ...legacy, ...(input.launchChanged ? { launchChanged: true } : {}) };
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
      // A repin keeps the time the definition was first accepted.
      const pinnedAt = decision.why === 'repin' ? (getOwn(entry.tools, decision.name)?.pinnedAt ?? ctx.now) : ctx.now;
      setOwn(entry.tools, decision.name, { hash: decision.hash, definition: decision.definition, pinnedAt });
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
      // An entry an older version recorded under the raw hash is the same definition: rewrite it, keep its time.
      const same = existing !== undefined && (existing.hash === decision.hash || existing.hash === decision.legacyHash);
      setOwn(entry.pending, decision.name, {
        hash: decision.hash,
        definition: decision.definition,
        detectedAt: same ? existing.detectedAt : ctx.now,
        reason: decision.reason,
        findings: decision.findings,
        ...(decision.launchChanged ? { launchChanged: true } : {}),
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
