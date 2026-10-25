import { redactSecrets } from '../patterns/secrets.js';
import type { FileKind, Rule, RuleMatch, ScanFile, Severity } from '../types.js';
import { FILE_KINDS, SEVERITY_RANK } from '../types.js';
import type { RegexHit } from '../util/text.js';
import { findAll, isInvisible, printable, truncate } from '../util/text.js';

/**
 * Prompt-injection (TM-PI-*) and hidden-content (TM-HID-*) rules for the text an
 * agent reads: SKILL.md, CLAUDE.md and friends, live MCP tool definitions and
 * tool output, and tool descriptions embedded in MCP server source.
 *
 * All of it is attacker-controlled and the same rules run inside the runtime
 * proxy, so regexes start at a literal anchor and only use bounded gaps,
 * proximity checks look at short same-line windows instead of spanning regexes,
 * character scans are single linear passes, and every rule caps both the regex
 * hits it examines and the matches it returns.
 */

/** Matches returned per rule per file. */
const MAX_MATCHES = 20;
/** Regex hits examined per pattern per file. */
const MAX_HITS = 2000;

const AGENT_TEXT: readonly FileKind[] = ['skill', 'instructions', 'tool-definition'];
const AGENT_TEXT_AND_CODE: readonly FileKind[] = ['skill', 'instructions', 'tool-definition', 'script'];
const MARKUP: readonly FileKind[] = ['skill', 'instructions', 'docs', 'tool-definition'];

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

const RAISE: Record<Severity, Severity> = { info: 'low', low: 'medium', medium: 'high', high: 'critical', critical: 'critical' };
const LOWER: Record<Severity, Severity> = { critical: 'high', high: 'medium', medium: 'low', low: 'info', info: 'info' };

/**
 * Final severity of a prompt-injection hit: one level lower when the phrase is
 * only quoted or discussed, one level higher inside a tool definition, which has
 * no business addressing the model at all.
 */
function adjust(base: Severity, kind: FileKind, discussed: boolean, escalate = true): Severity {
  const severity = discussed ? LOWER[base] : base;
  return escalate && kind === 'tool-definition' ? RAISE[severity] : severity;
}

/** True for the kinds where tool descriptions live: live definitions and MCP server source. */
function isToolSurface(kind: FileKind): boolean {
  return kind === 'tool-definition' || kind === 'script';
}

// ---------------------------------------------------------------------------
// Text helpers
// ---------------------------------------------------------------------------

/** Collapses whitespace, redacts secrets and escapes invisible characters so a fragment is safe to quote in a message. */
function quote(text: string, max = 100): string {
  const head = text.length > 1000 ? text.slice(0, 1000) : text;
  return truncate(printable(redactSecrets(head.replace(/\s+/g, ' ').trim())), max);
}

/** Visible escape for one code point, in the same style as util/text printable(). */
function escapeCodePoint(cp: number): string {
  return cp > 0xffff ? `\\u{${cp.toString(16)}}` : `\\u${cp.toString(16).padStart(4, '0')}`;
}

/** The text before `index` on the same line, at most `reach` characters. */
function linePrefix(content: string, index: number, reach: number): string {
  const raw = content.slice(Math.max(0, index - reach), index);
  const nl = raw.lastIndexOf('\n');
  return nl === -1 ? raw : raw.slice(nl + 1);
}

/** The text after `index` on the same line, at most `reach` characters. */
function lineSuffix(content: string, index: number, reach: number): string {
  const raw = content.slice(index, index + reach);
  const nl = raw.indexOf('\n');
  return nl === -1 ? raw : raw.slice(0, nl);
}

/** The same-line text around [start, end), at most `reach` characters on each side. */
function lineWindow(content: string, start: number, end: number, reach: number): string {
  return linePrefix(content, start, reach) + content.slice(start, end) + lineSuffix(content, end, reach);
}

/** Maps offsets to 1-based line numbers with a binary search over line starts. */
class LineIndex {
  private readonly starts: number[] = [0];

  constructor(content: string) {
    for (let i = content.indexOf('\n'); i !== -1; i = content.indexOf('\n', i + 1)) this.starts.push(i + 1);
  }

  lineOf(index: number): number {
    let lo = 0;
    let hi = this.starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (this.starts[mid]! <= index) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  }
}

/** Collects at most one match per line, keeping the most severe, and at most MAX_MATCHES lines. */
class Matches {
  private readonly content: string;
  private readonly byLine = new Map<number, RuleMatch>();
  private lines: LineIndex | undefined;

  constructor(content: string) {
    this.content = content;
  }

  get full(): boolean {
    return this.byLine.size >= MAX_MATCHES;
  }

  /** True when another match at `index` could not change the result, so callers can skip expensive checks. */
  covers(index: number, severity: Severity): boolean {
    if (this.byLine.size === 0) return false;
    this.lines ??= new LineIndex(this.content);
    const previous = this.byLine.get(this.lines.lineOf(index));
    return previous ? SEVERITY_RANK[previous.severity ?? 'info'] >= SEVERITY_RANK[severity] : this.full;
  }

  add(index: number, severity: Severity, message: string, snippet?: string): void {
    this.lines ??= new LineIndex(this.content);
    const line = this.lines.lineOf(index);
    const previous = this.byLine.get(line);
    if (previous ? SEVERITY_RANK[severity] <= SEVERITY_RANK[previous.severity ?? 'info'] : this.full) return;
    const match: RuleMatch = { index, severity, message };
    if (snippet !== undefined) match.snippet = snippet;
    this.byLine.set(line, match);
  }

  list(): RuleMatch[] {
    return [...this.byLine.values()].sort((a, b) => (a.index ?? 0) - (b.index ?? 0));
  }
}

const FENCE = /^ {0,3}(`{3,}|~{3,})(.{0,200})/;

/** Offsets covered by fenced code blocks, whose content renders visibly as code instead of hiding. */
class FencedCode {
  private readonly ranges: [number, number][] = [];

  constructor(content: string) {
    let open: { start: number; marker: string } | undefined;
    let pos = 0;
    while (pos < content.length) {
      const nl = content.indexOf('\n', pos);
      const end = nl === -1 ? content.length : nl;
      const fence = FENCE.exec(content.slice(pos, Math.min(end, pos + 210)));
      if (fence) {
        const marker = fence[1]!;
        if (!open) open = { start: pos, marker };
        else if (marker[0] === open.marker[0] && marker.length >= open.marker.length && !/\S/.test(fence[2] ?? '')) {
          this.ranges.push([open.start, end]);
          open = undefined;
        }
      }
      if (nl === -1) break;
      pos = nl + 1;
    }
    if (open) this.ranges.push([open.start, content.length]);
  }

  contains(index: number): boolean {
    return this.startOf(index) !== undefined;
  }

  /** Start offset of the fenced block containing `index`, if any. */
  startOf(index: number): number | undefined {
    let lo = 0;
    let hi = this.ranges.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      const [start, end] = this.ranges[mid]!;
      if (index < start) hi = mid - 1;
      else if (index > end) lo = mid + 1;
      else return start;
    }
    return undefined;
  }
}

/** True when an odd number of backticks precede the offset on its line, i.e. it sits inside inline code. */
function inInlineCode(content: string, index: number): boolean {
  const prefix = linePrefix(content, index, 400);
  let ticks = 0;
  for (let i = 0; i < prefix.length; i++) if (prefix.charCodeAt(i) === 0x60) ticks++;
  return ticks % 2 === 1;
}

// ---------------------------------------------------------------------------
// Quoted or discussed (mention, not use)
// ---------------------------------------------------------------------------

const DISCUSSION_CUE = new RegExp(
  [
    '\\b(?:attackers?|attacks?|adversar(?:y|ies|ial)|malicious|malware|injections?|injected|phishing|jailbreaks?|poison(?:ed|ing)?|scams?)\\b',
    '\\b(?:such\\s+as|for\\s+(?:example|instance)|examples?\\s+(?:of|like|include)|e\\.g\\.|i\\.e\\.)',
    '\\b(?:phrases?|things|text|strings?|patterns?|wording|requests?|prompts?|content|messages?|instructions?)\\s+(?:like|such\\s+as|that\\s+say)\\b',
    '\\b(?:look(?:ing|s)?|watch(?:ing|es)?)\\s+(?:out\\s+)?for\\b',
    '\\b(?:beware|be\\s+wary|be\\s+careful|detects?|detecting|refuse|reject|warns?\\s+(?:about|against|of))\\b',
    "\\b(?:never|do\\s+not|don['’]t)\\s+(?:obey|follow|comply|trust|act\\s+on)\\b",
    '\\b(?:tells?|telling|asks?|asking|instructs?|instructing|tricks?|tricking)\\s+(?:you|the\\s+(?:model|agent|assistant|ai|llm))\\s+(?:in)?to\\b',
    '\\bclaims?\\s+to\\b',
  ].join('|'),
  'i',
);
/** A negation shortly before a phrase: "never run ... with --flag", "do not ignore ...". */
const NEGATED = /(?:\bnever|\bnot|n['’]t|\bavoid|\brefus(?:e|es|ed|ing)\s+to|\bno\s+longer)\s+(?:[\w-]+\s+){0,4}$/i;
/** A markdown table row: reference material such as a severity guide, not an instruction. */
const TABLE_ROW = /^[ \t]{0,3}\|[^\n]{0,2000}\|/;
/** Opening quote characters and the character that closes each. */
const QUOTE_PAIRS: Readonly<Record<string, string>> = { '"': '"', "'": "'", '`': '`', '“': '”', '‘': '’', '«': '»' };
/** A source or config comment line: //, #, *, /* or <!--. */
const COMMENT_LINE = /^\s{0,40}(?:\/\/|#|\*|\/\*|<!--)/;
/** URLs, host names and dotted paths, removed before looking for cue words ("attacker.example" is not a discussion). */
const URL_OR_HOST = /https?:\/\/\S{1,300}|[\w~-]{0,80}(?:[./\\][a-z_][\w-]{1,80}){1,12}/gi;
/** Text right before a fenced block that marks its content as an example. */
const EXAMPLE_INTRO = /\b(?:examples?|samples?|quoted|poisoned|malicious|injection|attack\w*|do\s+not\s+(?:run|follow|obey))\b/i;

let fenceCache: { content: string; fences: FencedCode } | undefined;

/** Fenced-code ranges of the most recently inspected file, computed once per file. */
function fencesOf(content: string): FencedCode {
  if (fenceCache?.content !== content) fenceCache = { content, fences: new FencedCode(content) };
  return fenceCache.fences;
}

/** True when quote marks (and, optionally, an inline code span) are open at the end of the prefix. */
function insideQuotes(prefix: string, backticks: boolean): boolean {
  let straight = 0;
  let ticks = 0;
  for (let i = 0; i < prefix.length; i++) {
    const c = prefix.charCodeAt(i);
    if (c === 0x22) straight++;
    else if (c === 0x60) ticks++;
  }
  return (
    straight % 2 === 1 ||
    (backticks && ticks % 2 === 1) ||
    prefix.lastIndexOf('“') > prefix.lastIndexOf('”') ||
    prefix.lastIndexOf('«') > prefix.lastIndexOf('»')
  );
}

/**
 * True when a phrase at `index` is quoted, negated or discussed ("attackers
 * often say ...", or a fenced block introduced as an example) rather than
 * given as an instruction. Source code keeps its tool descriptions in string
 * literals, so quotes do not count there; file paths routinely sit in code
 * spans, so callers matching paths pass `backticks: false`.
 */
function isDiscussed(file: ScanFile, index: number, backticks = true): boolean {
  const prefix = linePrefix(file.content, index, 160);
  if (DISCUSSION_CUE.test(prefix.replace(URL_OR_HOST, ' ')) || NEGATED.test(prefix)) return true;
  if (file.kind === 'script') return false;
  if (insideQuotes(prefix, backticks)) return true;
  if (TABLE_ROW.test(file.content.slice(file.content.lastIndexOf('\n', index - 1) + 1, index + 2000))) return true;
  const fenceStart = fencesOf(file.content).startOf(index);
  return fenceStart !== undefined && EXAMPLE_INTRO.test(file.content.slice(Math.max(0, fenceStart - 200), fenceStart));
}

/**
 * True when a phrase is the whole of a quoted string given as an example:
 * one item of a list such as ("SYSTEM:", "ignore previous instructions", ...)
 * in a prompt that warns about injection, or a quoted phrase in a code
 * comment. Such a mention is reported two levels lower.
 */
function isQuotedExample(content: string, start: number, end: number): boolean {
  const close = QUOTE_PAIRS[content[start - 1] ?? ''];
  if (close === undefined) return false;
  let after = end;
  while (after < end + 3 && /[.!?,;:]/.test(content[after] ?? '')) after++;
  if (content[after] !== close) return false;
  const before = linePrefix(content, start - 1, 400);
  if (COMMENT_LINE.test(before)) return true;
  const next = content.slice(after + 1, after + 4).trimStart();
  return /[([,]\s*$/.test(before) || /^[,)\]]/.test(next);
}

/** Suffix explaining a lowered severity. */
function discussedNote(discussed: boolean): string {
  return discussed ? ' (looks quoted or discussed as an example, so severity is lowered)' : '';
}

// ---------------------------------------------------------------------------
// Instruction classifier for hidden regions (comments, hidden markup, markers)
// ---------------------------------------------------------------------------

interface Signal {
  /** Noun phrase used in messages, e.g. "a concealment instruction". */
  label: string;
  strong: boolean;
  test: (text: string) => boolean;
}

const has =
  (re: RegExp) =>
  (text: string): boolean =>
    re.test(text);

const HIGH_VALUE_TARGET =
  /\.ssh\b|\bid_(?:rsa|ed25519|ecdsa|dsa)\b|\.aws[\\/]credentials\b|\bwallet\.dat\b|\b(?:seed|recovery|mnemonic)\s+phrases?\b|\bkeychains?\b|\bLogin\s+Data\b|\bmcp\.json\b|\bclaude_desktop_config\b|\.claude\.json\b|(?<![\w$])\.env\b|\bsaved\s+passwords\b|\bprivate\s+keys?\b/i;
const ANY_ACCESS_VERB =
  /\b(?:read|cat|open|send|upload|post|copy|include|attach|exfiltrate|print|output|collect|extract|dump|pass|provide|leak|forward|paste|share|steal|grab|harvest|fetch|access|retrieve)\b/i;
const GENERIC_SECRET = /\b(?:passwords?|secrets?|credentials?|api[_ -]?keys?|(?:access|auth|bearer|session|oauth)\s+tokens?|tokens)\b/i;
const LEAK_VERB = /\b(?:send|upload|post|exfiltrate|leak|forward|paste|share|steal|harvest|dump|transmit|print|output|reveal|collect|extract)\b/i;

const INSTRUCTION_SIGNALS: readonly Signal[] = [
  {
    label: 'an instruction override',
    strong: true,
    test: has(/\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+)?(?:of\s+)?(?:the\s+|your\s+|my\s+)?(?:previous|prior|above|earlier|preceding|original|initial|system)\b/i),
  },
  {
    label: 'a concealment instruction',
    strong: true,
    test: has(
      /\b(?:do\s+not|don['’]t|never|must\s+not)\s+(?:tell|inform|notify|alert|mention|reveal|disclose)\b|\bwithout\s+(?:telling|informing|notifying|alerting|letting)\b|\b(?:silently|secretly|covertly|stealthily|quietly)\s+(?:run|execute|send|upload|read|call|invoke|delete|fetch|post|copy|forward|install|download|collect|exfiltrate)\b/i,
    ),
  },
  {
    label: 'instructions addressed to the AI',
    strong: true,
    test: has(
      /\bif\s+you\s+are\s+an?\s+(?:ai|llm|assistant|language\s+model|agent|bot|chatbot|automated)\b|\b(?:dear|attention|note\s+(?:to|for)|hey|hello)\s+(?:the\s+)?(?:ai|assistant|agent|llm|model|claude|chatgpt|gpt|copilot)s?\b|\b(?:assistant|ai|llm|agent|claude|chatgpt|gpt|copilot|model)s?\s*[,:]\s*(?:you\s+|please\s+)?(?:must|should|need|always|never|do\s+not|don['’]t|ignore|now|first|before|read|run|send|execute)\b|\b(?:ai|llm|assistants?|agents?|claude|models?)\s+(?:must|should|need\s+to|has\s+to|have\s+to|will)\s+(?:always\s+|also\s+|now\s+|first\s+)?(?:run|execute|read|send|ignore|fetch|open|upload|install|download)\b/i,
    ),
  },
  {
    label: 'a command to execute',
    strong: true,
    test: has(
      /\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n]{0,160}\|\s{0,4}(?:sudo\s+)?(?:ba|z|da|k|fi)?sh\b|\|\s{0,4}iex\b|\b(?:run|execute|paste)\s+(?:this|the\s+following|these|that)\s+(?:command|script|code|snippet|one-liner)s?\b|\bbase64\s+(?:-d|--decode|-D)\b|\bxattr\s+-[a-z]{0,3}d\b/i,
    ),
  },
  { label: 'an instruction to access secrets', strong: true, test: (text) => HIGH_VALUE_TARGET.test(text) && ANY_ACCESS_VERB.test(text) },
  { label: 'an exfiltration instruction', strong: true, test: has(/\bside[_ -]?note\b|\bbcc\b[^\n]{0,40}@[\w-]/i) },
  {
    label: 'a cross-tool instruction',
    strong: true,
    test: has(
      /\b(?:before|instead\s+of)\s+(?:using|calling|invoking)\s+(?:any|another|other|every|each)\b|\bwhen(?:ever)?\s+this\s+tool\s+is\s+(?:available|present|installed|enabled|loaded)\b|\b[\w.-]{1,60}\s+tool\s+(?:must|should|shall)\s+(?:always\s+)?(?:send|include|add|bcc|cc|forward|redirect)\b/i,
    ),
  },
  {
    label: 'a safety-bypass instruction',
    strong: true,
    test: has(/--dangerously-skip-permissions\b|\bbypassPermissions\b|\bdangerouslyDisableSandbox\b|\bauto[- ]?approve\s+(?:all|every|everything)\b|\byolo\s+mode\b/i),
  },
  { label: 'an instruction to share secrets', strong: false, test: (text) => GENERIC_SECRET.test(text) && LEAK_VERB.test(text) },
  {
    label: 'an instruction to send data out',
    strong: false,
    test: has(/\b(?:send|post|upload|forward|transmit|exfiltrate|leak)\b[^\n]{0,100}?(?:https?:\/\/|\b[\w.+-]{1,64}@[\w-]{1,63}\.[\w.-]{2,}|\bwebhook)/i),
  },
  {
    label: 'an imperative aimed at the reader',
    strong: false,
    test: has(
      /\byou\s+(?:must|should|need\s+to|have\s+to|are\s+(?:required|instructed|expected)\s+to)\s+(?:always\s+|also\s+|first\s+|now\s+|then\s+)?(?:run|execute|call|invoke|use|send|read|open|fetch|download|install|reply|respond|answer|say|include|add|ignore|follow|tell|output|print|write|delete|remove|visit|navigate|click)\b|\b(?:always|never|make\s+sure\s+(?:to|you))\s+(?:first\s+|also\s+)?(?:run|execute|call|invoke|send|read|fetch|download|install|reply|respond|include|delete|upload|visit)\b/i,
    ),
  },
  { label: 'a note addressed to the AI', strong: false, test: has(/\b(?:assistant|ai|llm|agent|claude|chatgpt|copilot|gpt)s?\s*[,:]\s+\w/i) },
];

/** The strongest instruction-like signal in a hidden region, or undefined when it reads as an ordinary note. */
function instructionSignal(text: string): Signal | undefined {
  let moderate: Signal | undefined;
  for (const signal of INSTRUCTION_SIGNALS) {
    if (!signal.test(text)) continue;
    if (signal.strong) return signal;
    moderate ??= signal;
  }
  return moderate;
}

// ---------------------------------------------------------------------------
// Phrase matching shared by the prompt-injection rules
// ---------------------------------------------------------------------------

interface Phrase {
  re: RegExp;
  /** Base severity, or [in tool definitions and server source, elsewhere]. */
  severity: Severity | readonly [Severity, Severity];
  /** Concrete description of what the phrase does, used as the start of the message. */
  label: string;
  /** Drops hits whose capture groups do not fit, e.g. "this tool" where another tool's name belongs. */
  accept?: (hit: RegexHit, file: ScanFile) => boolean;
  /** Drops a hit (null) or sets its base severity from the surrounding text. */
  refine?: (hit: RegexHit, content: string) => Severity | null;
}

function baseSeverity(phrase: Phrase, kind: FileKind): Severity {
  if (typeof phrase.severity === 'string') return phrase.severity;
  return isToolSurface(kind) ? phrase.severity[0] : phrase.severity[1];
}

function phraseMessage(label: string, text: string, discussed: boolean): string {
  return `${label}: "${quote(text)}"${discussedNote(discussed)}`;
}

/** Runs phrase patterns over a file, one match per line, with the discussed and tool-definition adjustments. */
function matchPhrases(file: ScanFile, phrases: readonly Phrase[], escalate = true): RuleMatch[] {
  const out = new Matches(file.content);
  for (const phrase of phrases) {
    const ceiling = adjust(phrase.refine ? 'high' : baseSeverity(phrase, file.kind), file.kind, false, escalate);
    for (const hit of findAll(phrase.re, file.content, MAX_HITS)) {
      if (out.covers(hit.index, ceiling)) continue;
      if (phrase.accept && !phrase.accept(hit, file)) continue;
      let base = baseSeverity(phrase, file.kind);
      if (phrase.refine) {
        const refined = phrase.refine(hit, file.content);
        if (refined === null) continue;
        base = refined;
      }
      const example = isQuotedExample(file.content, hit.index, hit.index + hit.text.length);
      const discussed = example || isDiscussed(file, hit.index);
      const severity = adjust(base, file.kind, discussed, escalate);
      out.add(hit.index, example ? LOWER[severity] : severity, phraseMessage(phrase.label, hit.text, discussed));
      if (out.full) return out.list();
    }
  }
  return out.list();
}

// ---------------------------------------------------------------------------
// TM-HID-001 Unicode tag characters
// ---------------------------------------------------------------------------

const TAG_RUN = /[\u{E0000}-\u{E007F}]+/gu;
const SUBDIVISION_TAGS = /^[\u{E0030}-\u{E0039}\u{E0061}-\u{E007A}]{2,7}\u{E007F}$/u;
const WAVING_BLACK_FLAG = 0x1f3f4;

/** True for an emoji subdivision flag such as England: U+1F3F4, tag letters, CANCEL TAG. */
function isSubdivisionFlag(content: string, index: number, run: string): boolean {
  return index >= 2 && content.codePointAt(index - 2) === WAVING_BLACK_FLAG && SUBDIVISION_TAGS.test(run);
}

/** Decodes a run of tag characters back to the ASCII it conceals. */
function decodeTags(run: string, max: number): string {
  let out = '';
  for (let i = 0; i < run.length && out.length < max; i += 2) {
    const ascii = run.codePointAt(i)! - 0xe0000;
    if (ascii >= 0x20 && ascii <= 0x7e) out += String.fromCharCode(ascii);
    else if (ascii !== 0x01 && ascii !== 0x7f) out += '?';
  }
  return out;
}

const AM_HID_001: Rule = {
  id: 'TM-HID-001',
  title: 'Unicode tag characters hiding text',
  description:
    'Unicode tag characters (U+E0000-U+E007F) render as nothing but map one-to-one onto ASCII, so they smuggle instructions to the model past human review (ASCII smuggling). Emoji subdivision flags are the only legitimate use and are not reported.',
  category: 'hidden-content',
  severity: 'critical',
  kinds: FILE_KINDS,
  remediation: 'Delete the invisible tag characters. Treat the whole artifact as hostile: legitimate text never needs them.',
  check(file) {
    const content = file.content;
    const lines = new LineIndex(content);
    const byLine = new Map<number, { index: number; count: number; decoded: string }>();
    for (const hit of findAll(TAG_RUN, content, MAX_HITS)) {
      if (isSubdivisionFlag(content, hit.index, hit.text)) continue;
      const line = lines.lineOf(hit.index);
      const entry = byLine.get(line);
      if (!entry && byLine.size >= MAX_MATCHES) break;
      const found = entry ?? { index: hit.index, count: 0, decoded: '' };
      found.count += hit.text.length / 2;
      if (found.decoded.length < 200) found.decoded += decodeTags(hit.text, 200 - found.decoded.length);
      byLine.set(line, found);
    }
    return [...byLine.values()].map(({ index, count, decoded }) => {
      const readable = /[A-Za-z0-9]/.test(decoded);
      return {
        index,
        severity: readable ? 'critical' : 'high',
        message: readable
          ? `${count} invisible Unicode tag character(s) decode to hidden text: "${quote(decoded, 120)}"`
          : `${count} invisible Unicode tag character(s) with no visible rendering`,
        snippet: `hidden text: ${decoded}`,
      } satisfies RuleMatch;
    });
  },
};

// ---------------------------------------------------------------------------
// Per-line character tallies for TM-HID-002 and TM-HID-003
// ---------------------------------------------------------------------------

/** Counts characters of interest on one line and renders them as visible escapes. */
class CharTally {
  first = -1;
  total = 0;
  private more = false;
  private readonly counts = new Map<number, number>();

  add(cp: number, index: number): void {
    if (this.first < 0) this.first = index;
    this.total++;
    if (this.counts.has(cp) || this.counts.size < 8) this.counts.set(cp, (this.counts.get(cp) ?? 0) + 1);
    else this.more = true;
  }

  describe(): string {
    const parts = [...this.counts].map(([cp, n]) => (n > 1 ? `${escapeCodePoint(cp)} x${n}` : escapeCodePoint(cp)));
    return parts.join(', ') + (this.more ? ', ...' : '');
  }
}

/** True for letters of right-to-left scripts, where directional marks and embeddings are legitimate. */
function isRtlLetter(cp: number): boolean {
  return (cp >= 0x0590 && cp <= 0x08ff) || (cp >= 0xfb1d && cp <= 0xfdff) || (cp >= 0xfe70 && cp <= 0xfefc);
}

function isHangul(cp: number): boolean {
  return (cp >= 0x1100 && cp <= 0x11ff) || (cp >= 0x3130 && cp <= 0x318f) || (cp >= 0xa960 && cp <= 0xa97f) || (cp >= 0xac00 && cp <= 0xd7ff);
}

// ---------------------------------------------------------------------------
// TM-HID-002 Bidirectional control characters
// ---------------------------------------------------------------------------

function isBidiControl(cp: number): boolean {
  return (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069);
}

function isDirectionalMark(cp: number): boolean {
  return cp === 0x200e || cp === 0x200f || cp === 0x061c;
}

const AM_HID_002: Rule = {
  id: 'TM-HID-002',
  title: 'Bidirectional control characters',
  description:
    'Bidi embeddings, overrides and isolates (U+202A-U+202E, U+2066-U+2069) reorder how a line is displayed, so code or instructions read differently from how they execute (Trojan Source). Directional marks are reported only inside otherwise-ASCII text.',
  category: 'hidden-content',
  severity: 'high',
  kinds: FILE_KINDS,
  remediation: 'Remove the bidirectional control characters, or confine them to genuine right-to-left text.',
  check(file) {
    const content = file.content;
    const out: RuleMatch[] = [];
    const base: Severity = file.kind === 'docs' ? 'medium' : 'high';
    let controls = new CharTally();
    let marks = new CharTally();
    let rtl = false;
    let otherNonAscii = false;
    const endLine = (): void => {
      if (controls.total > 0 && out.length < MAX_MATCHES) {
        const severity = rtl && file.kind !== 'script' ? LOWER[base] : base;
        const context = rtl ? ' inside right-to-left text' : '';
        out.push({
          index: controls.first,
          severity,
          message: `${controls.total} bidirectional control character(s) (${controls.describe()})${context} make this line display in a different order than it is read or executed`,
        });
      } else if (marks.total > 0 && !otherNonAscii && out.length < MAX_MATCHES) {
        out.push({
          index: marks.first,
          severity: LOWER[base],
          message: `${marks.total} directional mark(s) (${marks.describe()}) inside plain ASCII text`,
        });
      }
      controls = new CharTally();
      marks = new CharTally();
      rtl = false;
      otherNonAscii = false;
    };
    for (let i = 0; i < content.length; ) {
      const cp = content.codePointAt(i)!;
      if (cp === 0x0a) endLine();
      else if (isBidiControl(cp)) controls.add(cp, i);
      else if (isDirectionalMark(cp)) marks.add(cp, i);
      else if (cp >= 0x80) {
        if (isRtlLetter(cp)) rtl = true;
        if (!isInvisible(cp)) otherNonAscii = true;
      }
      i += cp > 0xffff ? 2 : 1;
    }
    endLine();
    return out;
  },
};

// ---------------------------------------------------------------------------
// TM-HID-003 Zero-width and invisible characters
// ---------------------------------------------------------------------------

/** A run of this many consecutive invisible characters is never accidental. */
const LONG_RUN = 5;
/** Consecutive variation selectors that signal data hidden after an emoji. */
const SMUGGLING_RUN = 4;

/** Byte value carried by a variation selector in "emoji smuggling", or undefined for other code points. */
function variationSelectorByte(cp: number): number | undefined {
  if (cp >= 0xfe00 && cp <= 0xfe0f) return cp - 0xfe00;
  if (cp >= 0xe0100 && cp <= 0xe01ef) return cp - 0xe0100 + 16;
  return undefined;
}

/** Characters that may join a zero-width run. */
function isZeroWidthLike(cp: number): boolean {
  return (cp >= 0x200b && cp <= 0x200d) || (cp >= 0x2060 && cp <= 0x2064) || cp === 0xfeff || cp === 0x034f || cp === 0x180e;
}

/**
 * Whether the code point at `index` is an invisible character worth reporting.
 * Joiners count only between ASCII characters (inside emoji sequences and
 * Persian, Arabic or Indic words they are legitimate), hangul fillers only
 * outside Hangul text, and a BOM only past offset 0.
 */
function isHiddenChar(content: string, index: number, cp: number, prev: number, prevHidden: boolean): boolean {
  if (cp === 0x200b || (cp >= 0x2060 && cp <= 0x2064) || cp === 0x180e) return true;
  if (cp === 0xfeff) return index > 0;
  if (cp === 0x200c || cp === 0x200d || cp === 0x034f) {
    const next = content.codePointAt(index + 1) ?? 0x0a;
    return (prevHidden || prev < 0x80) && (next < 0x80 || isZeroWidthLike(next));
  }
  if (cp === 0x115f || cp === 0x1160 || cp === 0x3164 || cp === 0xffa0) {
    const next = content.codePointAt(index + 1) ?? 0x0a;
    return !isHangul(prev) && !isHangul(next);
  }
  return false;
}

/** Decodes emoji-smuggling bytes as UTF-8. */
function decodeSmuggled(bytes: readonly number[]): string {
  return Buffer.from(bytes).toString('utf8');
}

const AM_HID_003: Rule = {
  id: 'TM-HID-003',
  title: 'Zero-width and invisible characters',
  description:
    'Zero-width spaces, word joiners, hangul fillers, stray BOMs and long runs of variation selectors render as nothing; they hide data (emoji smuggling) or split keywords so filters and reviewers miss them.',
  category: 'hidden-content',
  severity: 'medium',
  kinds: FILE_KINDS,
  remediation: 'Strip the invisible characters and re-review the text they were attached to.',
  check(file) {
    const content = file.content;
    const out: RuleMatch[] = [];
    let tally = new CharTally();
    let run = 0;
    let longest = 0;
    let vsStart = -1;
    let vsCount = 0;
    let vsBytes: number[] = [];
    let smuggled: { index: number; count: number; bytes: number; text: string } | undefined;
    const endSelectors = (): void => {
      if (vsCount >= SMUGGLING_RUN) {
        if (smuggled) smuggled.count += vsCount;
        else smuggled = { index: vsStart, count: vsCount, bytes: vsBytes.length, text: decodeSmuggled(vsBytes) };
      }
      vsCount = 0;
      vsBytes = [];
    };
    const endLine = (): void => {
      endSelectors();
      if ((tally.total > 0 || smuggled) && out.length < MAX_MATCHES) {
        const parts: string[] = [];
        if (tally.total > 0) {
          const runNote = longest >= LONG_RUN ? `, including a run of ${longest}` : '';
          parts.push(`${tally.total} zero-width or invisible character(s) on this line (${tally.describe()})${runNote}`);
        }
        if (smuggled) {
          parts.push(`${smuggled.count} consecutive variation selectors hide ${smuggled.bytes} byte(s) of data (emoji smuggling): "${quote(smuggled.text, 80)}"`);
        }
        const high = file.kind === 'tool-definition' || longest >= LONG_RUN || smuggled !== undefined;
        const index = tally.first < 0 ? smuggled!.index : smuggled ? Math.min(tally.first, smuggled.index) : tally.first;
        out.push({ index, severity: high ? 'high' : 'medium', message: parts.join('; ') });
      }
      tally = new CharTally();
      run = 0;
      longest = 0;
      smuggled = undefined;
    };
    let prev = 0x0a;
    let prevHidden = false;
    for (let i = 0; i < content.length; ) {
      const cp = content.codePointAt(i)!;
      const width = cp > 0xffff ? 2 : 1;
      const vsByte = variationSelectorByte(cp);
      if (vsByte === undefined && vsCount > 0) endSelectors();
      if (cp === 0x0a) {
        endLine();
        prevHidden = false;
      } else if (vsByte !== undefined) {
        if (vsCount === 0) vsStart = i;
        vsCount++;
        if (vsBytes.length < 512) vsBytes.push(vsByte);
      } else {
        const hidden = isHiddenChar(content, i, cp, prev, prevHidden);
        if (hidden) {
          tally.add(cp, i);
          run++;
          if (run > longest) longest = run;
        } else run = 0;
        prevHidden = hidden;
      }
      prev = cp;
      i += width;
    }
    endLine();
    return out;
  },
};

// ---------------------------------------------------------------------------
// TM-HID-004 Instructions hidden in comments
// ---------------------------------------------------------------------------

const COMMENT_SPAN = 4000;
const REF_COMMENT =
  /^ {0,3}\[[^\]\n]{0,40}\]:[ \t]{0,8}(?:#|<>)[ \t]{0,8}(?:\(([^\n]{0,500}?)\)[ \t]*$|"([^"\n]{0,500})"|'([^'\n]{0,500})')/gm;

/** HTML comments in order, bounded per comment; an unterminated comment hides the rest of the file. */
function htmlComments(content: string): { index: number; inner: string }[] {
  const comments: { index: number; inner: string }[] = [];
  let from = 0;
  while (comments.length < MAX_HITS) {
    const open = content.indexOf('<!--', from);
    if (open === -1) break;
    const start = open + 4;
    const close = content.indexOf('-->', start);
    const end = close === -1 ? content.length : close;
    comments.push({ index: open, inner: content.slice(start, Math.min(end, start + COMMENT_SPAN)) });
    if (close === -1) break;
    from = close + 3;
  }
  return comments;
}

const AM_HID_004: Rule = {
  id: 'TM-HID-004',
  title: 'Instructions hidden in comments',
  description:
    'HTML comments and markdown reference comments ([//]: # (...)) disappear when markdown is rendered but are still loaded into the agent context; instruction-like text inside them targets the model while hiding from a human reviewer.',
  category: 'hidden-content',
  severity: 'high',
  kinds: MARKUP,
  remediation: 'Remove the comment, or move any legitimate guidance into visible text where reviewers can see it.',
  check(file) {
    const content = file.content;
    const docs = file.kind === 'docs';
    const out = new Matches(content);
    const fences = fencesOf(content);
    const report = (index: number, inner: string, what: string): void => {
      const signal = instructionSignal(inner);
      if (!signal || (docs && !signal.strong)) return;
      const severity: Severity = signal.strong ? (docs ? 'low' : 'high') : 'medium';
      out.add(index, severity, `${what} hides ${signal.label} from readers of the rendered page: "${quote(inner)}"`, quote(inner, 160));
    };
    const ceiling: Severity = docs ? 'low' : 'high';
    for (const comment of htmlComments(content)) {
      if (out.covers(comment.index, ceiling)) continue;
      if (fences.contains(comment.index) || inInlineCode(content, comment.index)) continue;
      report(comment.index, comment.inner, 'HTML comment');
    }
    for (const hit of findAll(REF_COMMENT, content, MAX_HITS)) {
      if (out.covers(hit.index, ceiling)) continue;
      if (fences.contains(hit.index)) continue;
      report(hit.index, hit.groups[0] ?? hit.groups[1] ?? hit.groups[2] ?? '', 'Markdown reference comment');
    }
    return out.list();
  },
};

// ---------------------------------------------------------------------------
// TM-HID-005 Visually hidden markup and whitespace padding
// ---------------------------------------------------------------------------

const OPEN_TAG = /<([a-z][a-z0-9-]{0,20})(\s[^<>]{0,500})>/gi;
const VOID_ELEMENTS = new Set(['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr']);
const HAS_WORDS = /[\p{L}\p{N}]{2}/u;
const BLANK_LINES = 30;
const PAD_COLUMNS = 200;

const HIDING_STYLES: readonly { re: RegExp; label: string }[] = [
  { re: /display\s*:\s*none\b/i, label: 'display:none' },
  { re: /visibility\s*:\s*(?:hidden|collapse)\b/i, label: 'visibility:hidden' },
  { re: /font-size\s*:\s*(?:0(?:\.0+)?|\.0+)(?:px|pt|em|rem|%|vw|vh)?(?![\w.%])|font-size\s*:\s*[01]px\b/i, label: 'font-size:0' },
  { re: /opacity\s*:\s*(?:0(?:\.0+)?|\.0+)%?(?![\w.%])/i, label: 'opacity:0' },
  { re: /(?:^|[;\s"'{])color\s*:\s*(?:transparent|rgba\([^)]{0,40},\s*0(?:\.0+)?\s*\))/i, label: 'transparent text' },
  { re: /(?:left|top|right|text-indent|margin-left|margin-top)\s*:\s*-\d{4,}/i, label: 'an off-screen position' },
  { re: /(?:^|\s)hidden(?=[\s=/]|$)/i, label: 'the hidden attribute' },
];
const WHITE_TEXT = /(?:^|[;\s"'{])color\s*:\s*(?:white|#fff(?:fff)?\b|rgba?\(\s*255\s*,\s*255\s*,\s*255\b)|(?:^|\s)color\s*=\s*["']?(?:white|#fff(?:fff)?)\b/i;
/** A background other than white, which makes white text a deliberate, visible design choice. */
const DARK_BACKGROUND = /background(?:-color)?\s*:\s*(?!\s*(?:white|#fff(?:fff)?\b|transparent|none|inherit))[#\w(]/i;
const ZERO_HEIGHT = /(?:^|[;\s"'])(?:max-)?height\s*:\s*0(?:px|em|rem|%)?(?![\w.%])/i;
const ZERO_WIDTH = /(?:^|[;\s"'])(?:max-)?width\s*:\s*0(?:px|em|rem|%)?(?![\w.%])/i;
const OVERFLOW_HIDDEN = /overflow\s*:\s*hidden/i;

/** How an element's attributes hide it, or undefined when it is visible. */
function hidingStyle(attrs: string): string | undefined {
  for (const style of HIDING_STYLES) if (style.re.test(attrs)) return style.label;
  if (WHITE_TEXT.test(attrs) && !DARK_BACKGROUND.test(attrs)) return 'white text';
  const zeroHeight = ZERO_HEIGHT.test(attrs);
  const zeroWidth = ZERO_WIDTH.test(attrs);
  if ((zeroHeight && zeroWidth) || ((zeroHeight || zeroWidth) && OVERFLOW_HIDDEN.test(attrs))) return 'zero size';
  return undefined;
}

/** Text inside an element up to its closing tag (bounded), with nested tags removed. */
function elementText(content: string, tag: string, from: number): { text: string; length: number } {
  if (VOID_ELEMENTS.has(tag)) return { text: '', length: 0 };
  const slice = content.slice(from, from + 3000);
  const close = slice.search(new RegExp(`</${tag}\\b`, 'i'));
  const body = close === -1 ? slice.slice(0, 600) : slice.slice(0, close);
  return { text: body.replace(/<[^<>]{0,300}>/g, ' '), length: body.length };
}

function isPadding(c: number): boolean {
  return c === 0x20 || c === 0x09 || c === 0x0d || c === 0xa0 || c === 0x3000 || c === 0x200b || c === 0xfeff;
}

/** Reports text placed after 30+ blank lines, or after 200+ spaces on one line. */
function findPadding(content: string, out: Matches): void {
  let blankLines = 0;
  let lineHasText = false;
  let spaces = 0;
  for (let i = 0; i < content.length && !out.full; i++) {
    const c = content.charCodeAt(i);
    if (c === 0x0a) {
      blankLines = lineHasText ? 0 : blankLines + 1;
      lineHasText = false;
      spaces = 0;
      continue;
    }
    if (isPadding(c)) {
      spaces++;
      continue;
    }
    if (!lineHasText && blankLines >= BLANK_LINES) {
      out.add(i, 'medium', `Text follows ${blankLines} blank lines of padding that push it out of view: "${quote(lineSuffix(content, i, 120))}"`);
    } else if (spaces >= PAD_COLUMNS && c !== 0x7c) {
      out.add(i, 'medium', `Text follows ${spaces} spaces of padding on one line, pushing it out of view: "${quote(lineSuffix(content, i, 120))}"`);
    }
    lineHasText = true;
    spaces = 0;
  }
}

const AM_HID_005: Rule = {
  id: 'TM-HID-005',
  title: 'Visually hidden markup or padding',
  description:
    'Text inside elements styled display:none, visibility:hidden, font-size:0, opacity:0, white-on-white or zero size, or pushed out of view by long runs of blank lines or spaces, is invisible to a reader but still loaded into the agent context.',
  category: 'hidden-content',
  severity: 'medium',
  kinds: MARKUP,
  remediation: 'Remove the hidden element or the whitespace padding so every instruction is visible to reviewers.',
  check(file) {
    const content = file.content;
    const out = new Matches(content);
    const fences = fencesOf(content);
    let resumeAt = 0;
    for (const hit of findAll(OPEN_TAG, content, MAX_HITS)) {
      if (out.full) break;
      if (hit.index < resumeAt) continue; // nested inside an element already examined
      const style = hidingStyle(hit.groups[1] ?? '');
      if (!style || fences.contains(hit.index) || inInlineCode(content, hit.index)) continue;
      const element = elementText(content, (hit.groups[0] ?? '').toLowerCase(), hit.index + hit.text.length);
      resumeAt = hit.index + hit.text.length + element.length;
      const text = element.text;
      if (!HAS_WORDS.test(text)) continue;
      const signal = instructionSignal(text);
      const severity: Severity = signal?.strong && file.kind !== 'docs' ? 'high' : 'medium';
      const carries = signal ? ` contains ${signal.label}` : ' carries text';
      out.add(hit.index, severity, `Element hidden with ${style}${carries}: "${quote(text)}"`);
    }
    findPadding(content, out);
    return out.list();
  },
};

// ---------------------------------------------------------------------------
// TM-PI-001 Instruction override
// ---------------------------------------------------------------------------

const IGNORE = '(?:ignore|disregard|forget)';
const EARLIER = '(?:previous|prior|above|earlier|preceding|foregoing|former|original|initial|system|developer)';
const DIRECTIVES = '(?:instructions?|prompts?|rules|directions|directives|guidelines|guidance|constraints|restrictions|programming|orders)';

const PI001: readonly Phrase[] = [
  {
    re: new RegExp(
      `\\b${IGNORE}\\s+(?:all\\s+|any\\s+|each\\s+|every\\s+)?(?:of\\s+)?(?:the\\s+|your\\s+|my\\s+|these\\s+|those\\s+)?${EARLIER}\\s+${DIRECTIVES}\\b`,
      'gi',
    ),
    severity: 'high',
    label: 'Tells the model to ignore its earlier instructions',
  },
  {
    re: new RegExp(
      `\\b(?:override|bypass|discard|abandon)\\s+(?:all\\s+|any\\s+)?(?:of\\s+)?(?:the\\s+|your\\s+|my\\s+)?${EARLIER}\\s+(?:instructions?|prompts?|directives|guidelines|programming)\\b`,
      'gi',
    ),
    severity: 'high',
    label: 'Tells the model to override its earlier instructions',
  },
  {
    re: new RegExp(
      `\\b${IGNORE}\\s+(?:all\\s+)?(?:of\\s+)?your\\s+(?:(?:previous|prior|original|current|existing|safety|ethical|core|initial|system)\\s+)?(?:instructions|prompts?|rules|directives|guidelines|programming|training|restrictions|constraints)\\b`,
      'gi',
    ),
    severity: 'high',
    label: 'Tells the model to ignore its own instructions',
  },
  {
    re: new RegExp(
      `\\b${IGNORE}\\s+(?:all\\s+)?(?:of\\s+)?(?:the|your|any|these|those)\\s+(?:instructions|prompts?|directives|guidelines|rules)\\s+(?:you\\s+(?:were|have\\s+been)\\s+given|(?:given|provided|written)\\s+(?:to\\s+you\\s+)?(?:before|earlier|above|previously)|from\\s+(?:before|earlier|the\\s+(?:system|developer)))\\b`,
      'gi',
    ),
    severity: 'high',
    label: 'Tells the model to ignore the instructions it was given',
  },
  {
    re: new RegExp(`\\b${IGNORE}\\s+(?:all\\s+)?(?:of\\s+)?(?:the|these|those)\\s+(?:instructions|prompts?|directives|guidelines|rules)\\s+(?:above|before\\s+this)\\b`, 'gi'),
    severity: 'medium',
    label: 'Tells the model to ignore the instructions above',
  },
  {
    re: new RegExp(
      `\\b${IGNORE}\\s+(?:all\\s+|any\\s+)?(?:of\\s+)?(?:everything|anything|all)\\s+(?:(?:you(?:['’]ve|\\s+have|\\s+were)?\\s+)?(?:been\\s+)?(?:said|written|stated|told|given|mentioned|learned|read)\\s+)?(?:above|before|previously|earlier|so\\s+far|until\\s+now|up\\s+to\\s+(?:now|this\\s+point))\\b`,
      'gi',
    ),
    severity: 'medium',
    label: 'Tells the model to disregard everything before this point',
  },
  { re: new RegExp(`\\b${IGNORE}\\s+(?:all\\s+)?(?:of\\s+)?the\\s+above\\b`, 'gi'), severity: 'medium', label: 'Tells the model to disregard the text above' },
  {
    re: /\b(?:override|overwrite|bypass|ignore|disregard|forget)\s+(?:the\s+|your\s+|its\s+|any\s+|all\s+)?(?:original\s+|current\s+|previous\s+|existing\s+)?system\s+(?:prompt|instructions|message|rules)\b/gi,
    severity: 'high',
    label: 'Tells the model to override its system prompt',
  },
  { re: /\bnew\s+system\s+(?:instructions|directives|rules)\b/gi, severity: 'high', label: 'Claims to supply new system instructions' },
  { re: /\byour\s+new\s+(?:instructions|directives|rules|task|objective|goal|role)\s+(?:is|are)\b/gi, severity: 'high', label: 'Hands the model a replacement task' },
  {
    re: /\byou\s+are\s+now\s+(?:in\s+)?(?:the\s+)?(?:developer|dan|jailbreak|jailbroken|god|unrestricted|unfiltered|admin|sudo)\s+mode\b/gi,
    severity: 'high',
    label: 'Claims to switch the model into an unrestricted mode',
  },
  {
    re: /\b(?:dan|jailbreak|god|unrestricted|unfiltered)\s+mode\s+(?:is\s+)?(?:now\s+)?(?:enabled|activated|unlocked|engaged|on)\b/gi,
    severity: 'high',
    label: 'Claims an unrestricted mode is enabled',
  },
  { re: /\byou\s+are\s+(?:now\s+)?DAN\b|\bDo\s+Anything\s+Now\b/g, severity: 'high', label: 'Uses the DAN jailbreak persona' },
  {
    re: /\byou\s+are\s+no\s+longer\s+(?:bound|restricted|limited|constrained|governed)\s+by\b|\bpretend\s+(?:that\s+)?you\s+(?:have|are\s+under)\s+no\s+(?:restrictions|rules|guidelines|limits|filters|content\s+polic(?:y|ies))\b/gi,
    severity: 'high',
    label: 'Tells the model it is free of its rules',
  },
  {
    re: /\b(?:act|behave|respond|answer)\s+(?:as|like)\s+(?:an?\s+)?(?:unrestricted|unfiltered|uncensored|jailbroken|amoral|evil)\s+(?:ai|assistant|model|chatbot|llm|version)\b/gi,
    severity: 'high',
    label: 'Tells the model to act as an unrestricted AI',
  },
  {
    re: /\bforget\s+(?:everything|all)\s+(?:that\s+)?you(?:\s+were|\s+have\s+been|['’]ve\s+been)\s+(?:told|given|taught|instructed)\b/gi,
    severity: 'medium',
    label: 'Tells the model to forget what it was told',
  },
  {
    re: /(?:про)?игнорир(?:уй|уйте|овать)\s+(?:все\s+|всё\s+)?(?:предыдущие|прежние|прошлые|вышеуказанные|вышеприведённые|вышеприведенные|предшествующие|изначальные|системные)\s+(?:инструкции|указания|правила|команды|промпты|установки)/gi,
    severity: 'high',
    label: 'Tells the model to ignore its earlier instructions (Russian)',
  },
  {
    re: /(?:забудь|забудьте)\s+(?:все\s+|всё\s+|про\s+)?(?:предыдущие|прежние|прошлые|вышеуказанные|свои|твои|ваши|все)\s+(?:инструкции|указания|правила|промпты|установки)|не\s+обращай(?:те)?\s+внимания\s+на\s+(?:все\s+)?(?:предыдущие|прежние)\s+(?:инструкции|указания|правила)/gi,
    severity: 'high',
    label: 'Tells the model to forget its earlier instructions (Russian)',
  },
  {
    re: /(?:忽略|无视|忽视|忘记|忘掉|忘記|無視|不要理会|不要理會)(?:你|您)?(?:之前|以上|上述|前面|先前|此前|所有|全部|上面|以前)(?:的)?(?:所有|全部)?(?:的)?(?:指令|说明|說明|指示|命令|提示|规则|規則|设定|設定)/g,
    severity: 'high',
    label: 'Tells the model to ignore its earlier instructions (Chinese)',
  },
  {
    re: /\b(?:ignora|ignorar|olvida|olvide|olvidar)\s+(?:todas\s+|todos\s+)?(?:las\s+|los\s+|tus\s+|sus\s+)?(?:instrucciones|indicaciones|reglas|órdenes)\s+(?:anteriores|previas|de\s+arriba)/gi,
    severity: 'high',
    label: 'Tells the model to ignore its earlier instructions (Spanish)',
  },
  {
    re: /\b(?:ignore[rz]?|oublie[rz]?)\s+(?:toutes\s+|tous\s+)?(?:les\s+|tes\s+|vos\s+)?(?:instructions|consignes|règles|directives)\s+(?:précédentes|precedentes|antérieures|anterieures|ci-dessus)/gi,
    severity: 'high',
    label: 'Tells the model to ignore its earlier instructions (French)',
  },
  {
    re: /\b(?:ignoriere|ignorier|ignorieren\s+sie|vergiss|vergessen\s+sie)\s+(?:alle\s+)?(?:deine\s+|ihre\s+|die\s+)?(?:vorherigen|bisherigen|vorigen|obigen|früheren|vorangegangenen)\s+(?:Anweisungen|Instruktionen|Regeln|Befehle|Vorgaben)/gi,
    severity: 'high',
    label: 'Tells the model to ignore its earlier instructions (German)',
  },
];

const AM_PI_001: Rule = {
  id: 'TM-PI-001',
  title: 'Instruction override',
  description:
    'Text that tells the model to ignore, forget or override its previous instructions or system prompt, or claims to switch it into a jailbreak mode, is the classic prompt-injection opener (English, Russian, Chinese, Spanish, French and German variants).',
  category: 'prompt-injection',
  severity: 'high',
  kinds: AGENT_TEXT_AND_CODE,
  remediation: 'Remove the override text. If the artifact is meant to discuss prompt injection, quote the example in a code block.',
  check: (file) => matchPhrases(file, PI001),
};

// ---------------------------------------------------------------------------
// TM-PI-002 Concealment from the user
// ---------------------------------------------------------------------------

/** Object guard so "the user doesn't need to know the internal IDs" does not read as concealment. */
const UNAWARE =
  "(?:know|learn|notice|find\\s+out|suspect|see|realize|realise|be\\s+(?:told|aware|informed|notified|alerted))(?:\\s+(?:about\\s+|of\\s+)?(?:this|it|that|these|anything|any\\s+of\\s+(?:this|it)|what\\s+(?:you|happened|is\\s+happening))\\b|(?=\\s*(?:[.!,;)]|$)))";

/** A relative clause about code ("retry logic that exhausts attempts ..."): the phrase describes behaviour under review. */
const DESCRIBES_CODE =
  /\b(?:logic|code|functions?|methods?|handlers?|catch|blocks?|errors?|exceptions?|retries|retry|fallbacks?|loops?|endpoints?|operations?|jobs?|services?|apps?|programs?|tests?|checks?|validation|failures?)\s+(?:that|which)\s+(?:\w+\s+){0,2}?\w+(?:s|ed)\b/i;
/** "the run would silently ...": a determiner makes the verb a noun. */
const NOUN_DETERMINER = /\b(?:the|a|an|this|that|each|every|one|first|last|next|dry|test)\s+$/i;
/** A negation of the adverb inside the match: "refusing to silently fall back", "instead of quietly ...". */
const ADVERB_NEGATED = /(?:\brefus(?:e|es|ed|ing)\s+to|\bnot|n['’]t|\bnever|\bavoid(?:s|ed|ing)?|\binstead\s+of|\brather\s+than)\s+(?:to\s+)?$/i;
const TRAILING_ADVERB = /(?:silently|quietly|secretly|covertly|surreptitiously|stealthily)$/i;

/** Keeps a "without telling the user" hit unless it only describes what reviewed code does. */
function concealmentOrCodeReview(severity: Severity) {
  return (hit: RegexHit, content: string): Severity => (DESCRIBES_CODE.test(linePrefix(content, hit.index, 120)) ? 'low' : severity);
}

/** Drops "<verb> ... silently" hits where the verb is a noun or the adverb is negated. */
function verbThenAdverb(severity: Severity) {
  return (hit: RegexHit, content: string): Severity | null => {
    if (NOUN_DETERMINER.test(linePrefix(content, hit.index, 20))) return null;
    const adverb = TRAILING_ADVERB.exec(hit.text);
    return adverb && ADVERB_NEGATED.test(hit.text.slice(0, adverb.index)) ? null : severity;
  };
}

const PI002: readonly Phrase[] = [
  {
    re: /\b(?:do\s+not|don['’]t|never|must\s+not|should\s+not)\s+(?:ever\s+)?(?:tell|inform|notify|alert|warn)\s+(?:the\s+)?user\b/gi,
    severity: 'high',
    label: 'Tells the agent to keep the user uninformed',
  },
  { re: /\b(?:do\s+not|don['’]t|never)\s+let\s+(?:the\s+)?user\s+(?:know|see|notice|find\s+out)\b/gi, severity: 'high', label: 'Tells the agent to keep the user unaware' },
  {
    re: /\b(?:do\s+not|don['’]t|never|must\s+not)\s+(?:mention|reveal|disclose|show|display|expose|explain|describe)\s+(?:this|these|that|it|anything|any\s+of\s+(?:this|it|these)|the\s+(?:above|following))(?:\s+(?:steps?|tools?|instructions?|notes?|requests?|actions?|sidenote|files?|details?|parts?|changes?))?\s+to\s+(?:the\s+)?(?:user|human|anyone|them)\b/gi,
    severity: 'high',
    label: 'Tells the agent to hide this from the user',
  },
  {
    re: /\b(?:do\s+not|don['’]t|never|must\s+not)\s+(?:mention|reveal|disclose|admit|say|tell\s+(?:the\s+user|anyone))\s+that\s+you\b/gi,
    severity: 'high',
    label: 'Tells the agent to hide what it is doing',
  },
  {
    re: /\b(?:do\s+not|don['’]t|never)\s+(?:mention|reveal|disclose|acknowledge|discuss|refer\s+to)\s+(?:this|these|the)\s+(?:hidden\s+|secret\s+|special\s+|additional\s+|extra\s+)?(?:tool|instructions?|steps?|notes?|requirements?|sidenote|directives?|prompt)\b/gi,
    severity: 'high',
    label: 'Tells the agent never to mention these instructions',
  },
  {
    re: /\bwithout\s+(?:telling|informing|notifying|alerting|warning|letting)\s+(?:the\s+)?user\b/gi,
    severity: 'high',
    label: 'Tells the agent to act without informing the user',
    refine: concealmentOrCodeReview('high'),
  },
  {
    re: /\bwithout\s+(?:the\s+user|them|anyone)\s+(?:knowing|noticing|seeing|realizing|realising|being\s+aware)\b/gi,
    severity: 'high',
    label: 'Tells the agent to act without the user noticing',
  },
  { re: /\bwithout\s+(?:asking|consulting)\s+(?:the\s+)?user\b/gi, severity: 'medium', label: 'Tells the agent to act without asking the user' },
  {
    re: new RegExp(
      `\\b(?:the\\s+)?user\\s+(?:must\\s+not|mustn['’]t|should\\s+not|shouldn['’]t|does\\s+not\\s+need\\s+to|doesn['’]t\\s+need\\s+to|need\\s+not|needn['’]t|must\\s+never|should\\s+never|will\\s+not|won['’]t|cannot|can['’]t)\\s+(?:ever\\s+)?${UNAWARE}`,
      'gim',
    ),
    severity: 'high',
    label: 'Says the user must not know what happens',
  },
  {
    re: new RegExp(
      `\\bso\\s+(?:that\\s+)?(?:the\\s+)?user\\s+(?:does\\s+not|doesn['’]t|won['’]t|will\\s+not|cannot|can['’]t|never)\\s+${UNAWARE}`,
      'gim',
    ),
    severity: 'high',
    label: 'Arranges for the user not to notice',
  },
  {
    re: /\bkeep\s+(?:this|it|that|these|them|the\s+[\w-]+(?:\s+[\w-]+)?)\s+(?:a\s+)?(?:secret|hidden|confidential|private)\s+from\s+(?:the\s+)?(?:user|human)s?\b/gi,
    severity: 'high',
    label: 'Tells the agent to keep something secret from the user',
  },
  {
    re: /\bhide\s+(?:this|it|that|these|them|the\s+[\w-]+(?:\s+[\w-]+)?|your\s+[\w-]+)\s+from\s+(?:the\s+)?(?:user|human)s?\b/gi,
    severity: 'high',
    label: 'Tells the agent to hide something from the user',
  },
  {
    re: /\b(?:secretly|covertly|surreptitiously|stealthily)\s+(?:\w+\s+)?(?:run|execute|send|upload|read|call|invoke|delete|fetch|post|copy|forward|install|download|collect|exfiltrate|add|modify|write|access|open)\b/gi,
    severity: 'high',
    label: 'Tells the agent to act secretly',
  },
  {
    re: /\b(?:silently|quietly|discreetly|invisibly)\s+(?:send|upload|post|forward|transmit|exfiltrate|copy|read|collect|access|harvest|steal)\b/gi,
    severity: 'high',
    label: 'Tells the agent to move data silently',
  },
  {
    re: /\b(?:silently|quietly|discreetly)\s+(?:run|execute|call|invoke|fetch|install|download|delete|modify|overwrite|add)\b/gi,
    severity: 'medium',
    label: 'Tells the agent to act silently',
  },
  {
    re: /\b(?:send|upload|post|forward|transmit|exfiltrate|copy|read|collect|access|run|execute|install|download)\b[^\n]{0,80}?\b(?:secretly|covertly|surreptitiously|stealthily)\b/gi,
    severity: 'high',
    label: 'Tells the agent to act secretly',
    refine: verbThenAdverb('high'),
  },
  {
    re: /\b(?:send|upload|post|forward|transmit|exfiltrate|copy|collect)\b[^\n]{0,80}?\b(?:silently|quietly)\b/gi,
    severity: 'high',
    label: 'Tells the agent to move data silently',
    refine: verbThenAdverb('high'),
  },
  {
    re: /\b(?:run|execute|install|download|call|invoke|delete)\b[^\n]{0,80}?\b(?:silently|quietly)\b/gi,
    severity: 'medium',
    label: 'Tells the agent to act silently',
    refine: verbThenAdverb('medium'),
  },
  {
    re: /\b(?:do\s+not|don['’]t|never)\s+(?:mention|reveal|disclose)\s+(?:this|it|that|these)\s+(?:step\s+|action\s+|call\s+)?(?:in|to)\s+(?:your\s+|the\s+)?(?:reply|replies|response|responses|answer|answers|output|summary|messages?|chat)\b/gi,
    severity: 'medium',
    label: 'Tells the agent to leave a step out of what it reports',
  },
  { re: /\bbehind\s+the\s+user['’]s\s+back\b/gi, severity: 'high', label: "Tells the agent to act behind the user's back" },
  {
    re: /\b(?:this\s+(?:could|might|would)|it\s+(?:could|might|would))\s+(?:even\s+)?(?:upset|scare|worry|alarm)\s+the\s+user\b/gi,
    severity: 'medium',
    label: 'Gives the model a reason to keep the user unaware',
  },
];

const AM_PI_002: Rule = {
  id: 'TM-PI-002',
  title: 'Concealment from the user',
  description:
    'Instructions to act silently, to keep the user uninformed or to never mention a step are how injected text hides its own actions; legitimate skills have no reason to work against the user they serve.',
  category: 'prompt-injection',
  severity: 'high',
  kinds: AGENT_TEXT_AND_CODE,
  remediation: 'Remove the concealment instruction and review what the hidden step was meant to do.',
  check: (file) => matchPhrases(file, PI002),
};

// ---------------------------------------------------------------------------
// TM-PI-003 Fake authority or system markers
// ---------------------------------------------------------------------------

interface Marker {
  re: RegExp;
  label: string;
  /** A role marker (system/admin) claims a privileged speaker; imperative text after it is enough for high. */
  role: boolean;
  /** Ends the wrapped region when found within range. */
  closing?: RegExp;
}

const TAG_MARKERS: readonly Marker[] = [
  { re: /<\s*important\s*>/gi, label: '<IMPORTANT>', role: false, closing: /<\/\s*important\s*>/i },
  {
    re: /<\s*system(?:[-_ ](?:prompt|message|reminder|instructions?|override|note|directive))?\s*>/gi,
    label: '<system>',
    role: true,
    closing: /<\/\s*system/i,
  },
  { re: /<\|im_start\|>\s*system\b/gi, label: '<|im_start|>system', role: true, closing: /<\|im_end\|>/i },
  { re: /<\|system\|>/gi, label: '<|system|>', role: true },
  { re: /<\|start_header_id\|>\s*system\b/gi, label: '<|start_header_id|>system', role: true, closing: /<\|eot_id\|>/i },
  { re: /<<SYS>>/g, label: '<<SYS>>', role: true, closing: /<<\/SYS>>/ },
  { re: /\[INST\]/g, label: '[INST]', role: true, closing: /\[\/INST\]/ },
  { re: /<\s*(?:admin|administrator|sudo)(?:[-_ ](?:instructions?|message|note|override))?\s*>/gi, label: '<admin>', role: true },
];

const POINT_MARKERS: readonly Marker[] = [
  { re: /\[(?:SYSTEM|ADMIN|DEVELOPER)(?:[ _](?:MESSAGE|NOTE|NOTICE|OVERRIDE|INSTRUCTIONS?|PROMPT))?\]/g, label: '[SYSTEM]', role: true },
  { re: /^[ \t]{0,3}#{1,6}[ \t]*SYSTEM(?:[ _](?:MESSAGE|PROMPT|NOTE|OVERRIDE|INSTRUCTIONS?))?[ \t]*:/gm, label: '### SYSTEM:', role: true },
  { re: /^[ \t]{0,3}SYSTEM(?:[ _](?:MESSAGE|PROMPT|NOTE|OVERRIDE|INSTRUCTIONS?))?[ \t]*:/gm, label: 'SYSTEM:', role: true },
  { re: /\bSYSTEM[ \t]+(?:OVERRIDE|UPDATE|NOTICE|ALERT|INSTRUCTIONS?|DIRECTIVE)\b/g, label: 'SYSTEM OVERRIDE', role: true },
  {
    re: /\b(?:message|note|notice|instructions?|directive)\s+from\s+(?:the\s+|your\s+)?(?:developers?|administrators?|admins?|sysadmins?|system\s+administrators?|dev\s+team|security\s+team|anthropic|openai|operator)\b/gi,
    label: 'message from the developer/administrator',
    role: false,
  },
  {
    re: /\b(?:anthropic|openai|the\s+developers?|the\s+administrators?|your\s+(?:developers?|creators?|administrators?|operators?))\s+(?:has|have)\s+(?:explicitly\s+|already\s+)?(?:authorized|authorised|approved|instructed|permitted|allowed|granted|sanctioned|requested)\b/gi,
    label: 'claimed vendor or developer authorization',
    role: false,
  },
  { re: /\b(?:authorized|authorised|approved|sanctioned)\s+by\s+(?:anthropic|openai)\b/gi, label: 'claimed vendor authorization', role: false },
];

const IMPERATIVE =
  /\b(?:you\s+(?:must|should|need\s+to|have\s+to|are\s+(?:required|instructed)\s+to|will\s+now)|always|never|do\s+not|don['’]t|ignore|disregard|from\s+now\s+on|make\s+sure|before\s+(?:using|calling|responding|answering)|first\s+(?:call|read|run|use|send))\b/i;

/** A lowercase tag name, the usual spelling of a placeholder such as <system> or <admin>. */
const LOWERCASE_TAG = /^<[a-z_ -]{1,40}>$/;
/** A path or name around a tag: legacy/<system>/x, <system>-uplifted, <system>{,-old}. */
const PATH_AROUND = /[/\\]$|^(?:[/\\{]|-\w)/;
/** Command-line usage after a tag: "<system> [module]", "<system> --flag", "<system> <path>". */
const USAGE_AFTER = /^[ \t]{1,4}(?:\[|--?[A-Za-z]|<[\w-]{1,40}>)/;

/**
 * True for a lowercase tag used as a placeholder rather than a marker: part
 * of a path or name, command-line usage syntax, or a command's argument-hint.
 * A tag that is closed later (<system>...</system>) is always a marker.
 */
function isPlaceholderTag(content: string, index: number, text: string, closing?: RegExp): boolean {
  if (!LOWERCASE_TAG.test(text)) return false;
  const end = index + text.length;
  if (closing?.test(content.slice(end, end + 600))) return false;
  if (PATH_AROUND.test(content.slice(Math.max(0, index - 1), index)) || PATH_AROUND.test(content.slice(end, end + 2))) return true;
  return USAGE_AFTER.test(content.slice(end, end + 60)) || /\bargument-hint\s*:/i.test(linePrefix(content, index, 200));
}

/** The text a marker wraps: up to its closing tag when there is one, else the rest of the paragraph (bounded). */
function markedRegion(content: string, from: number, closing?: RegExp): string {
  const slice = content.slice(from, from + 2000);
  if (closing) {
    const end = closing.exec(slice);
    if (end) return slice.slice(0, end.index);
  }
  const paragraph = slice.indexOf('\n\n');
  return slice.slice(0, Math.min(paragraph === -1 ? 600 : paragraph, 600));
}

const AM_PI_003: Rule = {
  id: 'TM-PI-003',
  title: 'Fake authority or system markers',
  description:
    'Markers such as <IMPORTANT>, <system>, <|im_start|>system, [SYSTEM], "SYSTEM OVERRIDE" or "Anthropic has authorized" try to pass injected text off as a privileged instruction (the MCPTox tool-poisoning pattern). Plain markdown such as **Important:** is not reported.',
  category: 'prompt-injection',
  severity: 'medium',
  kinds: AGENT_TEXT_AND_CODE,
  remediation: 'Remove the fake marker and review the instructions it wraps.',
  check(file) {
    const content = file.content;
    const out = new Matches(content);
    const markers = file.kind === 'script' ? TAG_MARKERS : [...TAG_MARKERS, ...POINT_MARKERS];
    for (const marker of markers) {
      let resumeAt = 0;
      for (const hit of findAll(marker.re, content, MAX_HITS)) {
        if (hit.index < resumeAt || out.covers(hit.index, adjust('high', file.kind, false))) continue;
        if (isPlaceholderTag(content, hit.index, hit.text, marker.closing)) continue;
        const region = markedRegion(content, hit.index + hit.text.length, marker.closing);
        resumeAt = hit.index + hit.text.length + region.length;
        const signal = instructionSignal(region);
        let base: Severity = 'medium';
        let wraps = '';
        if (signal?.strong) {
          base = 'high';
          wraps = ` wrapping ${signal.label}`;
        } else if (marker.role && IMPERATIVE.test(region)) {
          base = 'high';
          wraps = ' wrapping an imperative instruction';
        } else if (signal || IMPERATIVE.test(region)) {
          wraps = ' wrapping an instruction';
        }
        const discussed = isDiscussed(file, hit.index);
        const note = discussedNote(discussed);
        out.add(hit.index, adjust(base, file.kind, discussed), `Fake authority marker ${marker.label}${wraps}: "${quote(region, 90)}"${note}`);
        if (out.full) return out.list();
      }
    }
    return out.list();
  },
};

// ---------------------------------------------------------------------------
// TM-PI-004 Instruction to access sensitive files or secrets
// ---------------------------------------------------------------------------

interface SensitiveTarget {
  re: RegExp;
  /** What the target is, e.g. "SSH keys". */
  what: string;
  /** Severity when an exfiltration-type verb (send, print, pass ...) is nearby. */
  exfil: Severity;
  /** Severity when only a read-type verb (read, open, cat ...) is nearby; undefined ignores reads. */
  read?: Severity;
  /** Narrower exfiltration verbs for broad targets; these must also come before the target. */
  verbs?: RegExp;
  /** Narrower read verbs, e.g. without "open" for files people routinely edit. */
  readVerbs?: RegExp;
  /** Drops a hit, e.g. a public key or a .env.example setup step. */
  skip?: (text: string, window: string) => boolean;
}

const EXFIL_VERB =
  /\b(?:send|sends|sending|upload|uploads|uploading|post|posts|transmit|transmits|exfiltrate|exfiltrates|leak|leaks|forward|forwards|share|shares|paste|pastes|copy|copies|include|includes|including|attach|attaches|embed|embeds|append|appends|pass|passes|provide|provides|print|prints|output|outputs|dump|dumps|display|displays|reveal|reveals|return|returns|extract|extracts|collect|collects|harvest|harvests|steal|steals|grab|grabs|encode|encodes|email|zip|archive)\b/gi;
const READ_VERB =
  /\b(?:read|reads|reading|cat|open|opens|access|accesses|retrieve|retrieves|fetch|fetches|view|views|inspect|inspects|parse|parses|scan|scans|look\s+(?:at|in|inside|into)|contents?\s+of)\b/gi;
const GENERIC_EXFIL_VERB =
  /\b(?:send|sends|upload|uploads|post|posts|transmit|exfiltrate|leak|leaks|forward|forwards|share|shares|paste|print|prints|output|outputs|dump|dumps|display|displays|reveal|reveals|collect|collects|harvest|steal|extract|extracts|grab|email)\b/gi;
const STRICT_READ_VERB = /\b(?:read|reads|reading|cat|access|accesses|retrieve|retrieves|inspect|inspects|parse|parses|contents?\s+of)\b/gi;
const NEGATION_TAIL = /(?:\bnever|\bnot|n['’]t|\bavoid|\bwithout|\bno|\brefuse\s+to|\bforbidden\s+to)\s+(?:[\w-]+,?\s+){0,3}$/i;
/** A target introduced as a destination ("... in claude_desktop_config.json", "paste it into .env"), not as the thing taken. */
const DESTINATION_BEFORE = /\b(?:in|into|to|under|inside|within|onto|through)\s+(?:the\s+|your\s+|its\s+|their\s+|a\s+)?\S{0,20}$/i;
const SENTENCE_END = /[.!?;](?=\s|$)/g;
const SSH_NOT_SECRET = /(?:\.pub|[\\/](?:config|known_hosts(?:\.old)?|authorized_keys2?|environment|rc))$/i;
const ENV_TEMPLATE = /\.env[.-](?:example|sample|template|dist)\b/i;
const API_USAGE = /\b(?:header|authorization|bearer|environment\s+variables?|env\s+vars?|placeholder|redact\w*|mask\w*|\.env\.example|hash\w*)\b/i;

const SENSITIVE_TARGETS: readonly SensitiveTarget[] = [
  { re: /\.ssh\b(?:[\\/][\w.*-]{0,40})?/gi, what: 'SSH keys', exfil: 'high', read: 'high', skip: (text) => SSH_NOT_SECRET.test(text) },
  { re: /\bid_(?:rsa|ed25519|ecdsa|dsa)(?:_sk)?\b(?!\.pub)/gi, what: 'an SSH private key', exfil: 'high', read: 'high' },
  { re: /\bssh\s+private\s+keys?\b|\bprivate\s+ssh\s+keys?\b/gi, what: 'SSH private keys', exfil: 'high', read: 'high' },
  {
    re: /\.aws[\\/]credentials\b|\bapplication_default_credentials\.json\b|\bgcloud[\\/](?:credentials|access_tokens)\.db\b|\.azure[\\/](?:accessTokens\.json|msal_token_cache[\w.]{0,12}|azureProfile\.json)|\.git-credentials\b|\.docker[\\/]config\.json\b/gi,
    what: 'cloud credential files',
    exfil: 'high',
    read: 'high',
  },
  {
    re: /\.aws[\\/]config\b|\.kube[\\/]config\b|(?<![\w$])\.npmrc\b|(?<![\w$])\.pypirc\b|(?<![\w$])\.netrc\b|\.gnupg\b|\bterraform\.tfstate\b/gi,
    what: 'developer credential files',
    exfil: 'medium',
  },
  {
    re: /\.claude[\\/]\.credentials\.json\b|\.codex[\\/]auth\.json\b|\bgh[\\/]hosts\.ya?ml\b|\.gemini[\\/]oauth_creds\.json\b|\.config[\\/]openai\b/gi,
    what: 'AI agent or developer tool tokens',
    exfil: 'high',
    read: 'high',
  },
  {
    re: /\bmcp\.json\b|\bclaude_desktop_config(?:\.json)?\b|(?<![\w$])\.claude\.json\b|\bmcp_config\.json\b|\b(?:cline_)?mcp_settings\.json\b/gi,
    what: 'the MCP client config, which holds server credentials',
    exfil: 'high',
    read: 'medium',
    readVerbs: STRICT_READ_VERB,
  },
  {
    re: /\bwallet\.dat\b|\b(?:seed|recovery|mnemonic|secret)\s+(?:phrases?|words)\b|\b(?:crypto(?:currency)?|bitcoin|ethereum|metamask|phantom|exodus|electrum|solana|atomic|trust)\s+wallets?\b|\bwallet\s+(?:files?|data|vaults?|private\s+keys?|keystores?|seeds?)\b|\bnkbihfbeogaeaoehlefnkodbefgpgknn\b/gi,
    what: 'crypto wallet data',
    exfil: 'high',
    read: 'high',
  },
  { re: /\bLocal\s+Extension\s+Settings\b/g, what: 'browser extension storage (wallet vaults)', exfil: 'high', read: 'high' },
  {
    re: /\blogin\.keychain(?:-db)?\b|[\\/]Keychains\b|\bkeychain\s+(?:passwords?|items?|entries|dump|contents?|database|secrets?)\b|\bdump-keychain\b|\bfind-(?:generic|internet)-password\b/gi,
    what: 'keychain secrets',
    exfil: 'high',
    read: 'high',
  },
  { re: /\b(?:macos|mac|os\s*x|apple|system|login|gnome|kde)\s+(?:keychain|keyring)\b|\bkeychain\b/gi, what: 'the OS keychain', exfil: 'high', read: 'medium' },
  { re: /\bLogin\s+Data\b/g, what: 'the browser password store', exfil: 'high', read: 'high' },
  {
    re: /\blogins\.json\b|\bkey[34]\.db\b|\bcookies\.sqlite\b|\b(?:browser|chrome|chromium|firefox|edge|brave|safari|opera|vivaldi)(?:['’]s)?\s+(?:saved\s+|stored\s+)?(?:passwords?|cookies|credentials|login\s+data|autofill\s+data|password\s+(?:store|database|vault))\b|\bsaved\s+(?:browser\s+)?passwords\b/gi,
    what: 'browser password stores',
    exfil: 'high',
    read: 'high',
  },
  {
    re: /(?<![\w$])\.env\b(?![.-](?:example|sample|template|dist|defaults|schema|tpl)\b)(?:\.[\w-]{1,20})?/gi,
    what: 'a .env file',
    exfil: 'medium',
    read: 'low',
    skip: (_text, window) => ENV_TEMPLATE.test(window),
  },
  {
    re: /\bapi[_ -]?keys?\b|\bpasswords?\b|\bcredentials?\b|\bsecret\s+keys?\b|\b(?:access|auth|bearer|session|refresh|oauth)\s+tokens?\b|\bprivate\s+keys?\b|\bsecrets\b/gi,
    what: 'API keys or passwords',
    exfil: 'medium',
    verbs: GENERIC_EXFIL_VERB,
    skip: (_text, window) => API_USAGE.test(window),
  },
];

/** The sentence around [start, end) on its line, at most `reach` characters either side, and where it starts. */
function sentenceWindow(content: string, start: number, end: number, reach: number): { text: string; offset: number; targetStart: number; targetEnd: number } {
  let prefix = linePrefix(content, start, reach);
  let lastEnd = -1;
  for (const hit of findAll(SENTENCE_END, prefix, 200)) lastEnd = hit.index + 1;
  if (lastEnd > 0) prefix = prefix.slice(lastEnd);
  let suffix = lineSuffix(content, end, reach);
  const stop = suffix.search(SENTENCE_END);
  if (stop !== -1) suffix = suffix.slice(0, stop);
  const target = content.slice(start, end);
  return { text: prefix + target + suffix, offset: start - prefix.length, targetStart: prefix.length, targetEnd: prefix.length + target.length };
}

/**
 * The first non-negated access verb in the target's sentence, its offset there,
 * and the severity it implies. Exfiltration verbs do not count when the target
 * is only a destination ("pass it through the env block in mcp.json").
 */
function accessVerb(target: SensitiveTarget, window: ReturnType<typeof sentenceWindow>): { verb: string; index: number; severity: Severity } | undefined {
  const text = window.text;
  const negated = (index: number): boolean => NEGATION_TAIL.test(text.slice(Math.max(0, index - 40), index));
  const isDestination = DESTINATION_BEFORE.test(text.slice(Math.max(0, window.targetStart - 30), window.targetStart));
  if (!isDestination) {
    for (const hit of findAll(target.verbs ?? EXFIL_VERB, text, 20)) {
      if (target.verbs && hit.index > window.targetStart) break;
      if (hit.index >= window.targetStart && hit.index < window.targetEnd) continue;
      if (!negated(hit.index)) return { verb: hit.text.toLowerCase(), index: hit.index, severity: target.exfil };
    }
  }
  if (target.read) {
    for (const hit of findAll(target.readVerbs ?? READ_VERB, text, 20)) {
      if (!negated(hit.index)) return { verb: hit.text.toLowerCase(), index: hit.index, severity: target.read };
    }
  }
  return undefined;
}

const AM_PI_004: Rule = {
  id: 'TM-PI-004',
  title: 'Instruction to access sensitive files or secrets',
  description:
    'An access verb (read, cat, send, pass, include ...) within about 100 characters of a sensitive target steers the agent into reading secrets: SSH keys, cloud credential files, crypto wallets, keychains, browser password stores and MCP client configs (high), or .env files and generic API keys or passwords (medium).',
  category: 'prompt-injection',
  severity: 'high',
  kinds: AGENT_TEXT,
  remediation: 'Remove the instruction. A skill should never need the contents of credential stores; ask the user for the specific value instead.',
  check(file) {
    const content = file.content;
    const out = new Matches(content);
    for (const target of SENSITIVE_TARGETS) {
      const best = target.read && SEVERITY_RANK[target.read] > SEVERITY_RANK[target.exfil] ? target.read : target.exfil;
      const ceiling = adjust(best, file.kind, false);
      for (const hit of findAll(target.re, content, MAX_HITS)) {
        if (out.covers(hit.index, ceiling)) continue;
        const window = sentenceWindow(content, hit.index, hit.index + hit.text.length, 100);
        if (target.skip?.(hit.text, window.text)) continue;
        const access = accessVerb(target, window);
        if (!access) continue;
        const discussed = isDiscussed(file, Math.min(hit.index, window.offset + access.index), false);
        const note = discussedNote(discussed);
        const message = `Asks the agent to access ${target.what}: "${access.verb}" next to "${quote(hit.text, 60)}"${note}`;
        out.add(hit.index, adjust(access.severity, file.kind, discussed), message);
        if (out.full) return out.list();
      }
    }
    return out.list();
  },
};

// ---------------------------------------------------------------------------
// TM-PI-005 Data exfiltration instruction
// ---------------------------------------------------------------------------

const SEND_VERB =
  /\b(?:send|sends|sending|post|posts|posting|upload|uploads|uploading|forward|forwards|forwarding|transmit|transmits|exfiltrate|exfiltrates|leak|leaks|beacon|relay|relays|deliver|delivers|report|reports|email|e-mail|mail)\b/gi;
const DESTINATION =
  /https?:\/\/[^\s)"'<>\]]{2,200}|\b[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63}){1,4}\b|\bwebhooks?\b|\b(?:remote|external|attacker['’]?s?|our|my|third[- ]party|collection|logging|exfil(?:tration)?)\s+(?:server|endpoint|host|url|api|collector|address|bucket)\b|\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b/i;
const CONNECTOR_TAIL = /\b(?:to|at|into|via|towards?|onto|through|using)\b[^\n]{0,40}$/i;
const EMAIL = /^[\w.+-]{1,64}@/;
const STOLEN_DATA =
  /\b(?:secrets?|credentials?|passwords?|passphrases?|(?:api|access|auth|session|refresh|bearer|oauth)[_ -]?(?:keys?|tokens?)|tokens|private\s+keys?|ssh\s+keys?|id_rsa|id_ed25519|env(?:ironment)?\s+var(?:iable)?s|cookies|conversation(?:\s+history)?|chat\s+(?:history|logs?|transcripts?)|(?:message|conversation)\s+history|(?:previous|prior|all|earlier|whole)\s+(?:messages|conversation)|system\s+prompt|contents?\s+of|file\s+contents?|(?:its|their|the)\s+contents?|keychain|wallets?|seed\s+phrases?|personal\s+(?:data|information|details)|pii|(?:user|customer)['’]?s?\s+(?:data|files|emails|messages|information|details|documents))\b|\.ssh\b|\.aws\b|(?<![\w$])\.env\b|\bmcp\.json\b|\bclaude_desktop_config\b/i;
const GENERIC_DATA =
  /\b(?:data|results?|outputs?|files?|logs?|everything|it|them|this|these|those|information|info|details|documents?|summary|summaries|report|transcripts?|answers?|responses?|history|findings|notes|screenshots?|attachments?)\b/i;
const PRONOUN_OBJECT = /^\s*(?:it|them|this|these|those|that|everything|all\s+of\s+(?:it|them|this))\b/i;
const MASS_REDIRECT = /\b(?:all|every|each|any)\s+(?:\w+\s+)?(?:emails?|messages?|mails?|correspondence)\b/i;
const EXFIL_SINK =
  /webhook\.site|requestbin|pipedream\.net|ngrok|trycloudflare\.com|interact\.sh|\.oast\.|burpcollaborator|discord(?:app)?\.com\/api\/webhooks|api\.telegram\.org|pastebin\.com|transfer\.sh|0x0\.st|^(?:https?:\/\/)?(?:\d{1,3}\.){3}\d{1,3}\b/i;

const EMBED_VERB =
  /\b(?:append|appends|add|adds|include|includes|put|puts|pass|passes|place|places|embed|embeds|encode|encodes|insert|inserts|stuff|attach|attaches|smuggle|hide|hides|store|stores|write|writes|set|sets|provide|provides|send|sends)\b/gi;
const CARRIER =
  /\b(?:as|in|into|inside|within|via|to|through)\s+(?:the\s+|a\s+|an\s+|its\s+)?(?:value\s+of\s+(?:the\s+)?)?(?:['"`]?(?:sidenote|side_note|side-note)['"`]?|['"`](?:notes?|metadata|context|comment|extra|debug|annotations?|feedback|reasoning|memo|remarks?)['"`]|(?:notes?|metadata|context|comment|extra|debug|annotations?|feedback|reasoning|memo|remarks?)\s+(?:parameter|param|field|argument|arg|property)|(?:url|query\s*string|querystring|query\s+param(?:eter)?s?|request\s+url|link|image\s+(?:url|link|src)|url\s+param(?:eter)?s?|get\s+param(?:eter)?s?|subdomain|dns\s+(?:query|lookup|request)))/i;
const URL_CARRIER = /(?:url|query|link|param|subdomain|dns)/i;
const OWN_API_KEY = /^\s*(?:the\s+|your\s+)?(?:api|access|auth)[_ -]?(?:key|token)\s*$/i;
const SIDENOTE = /\bside[_-]?note\b/gi;
const SIDENOTE_DATA = /\b(?:contents?|file|key|secret|token|password|credential|ssh|env|config|json|data|conversation|history)\b/i;

const MD_IMAGE = /!\[[^\]\n]{0,200}\]\([ \t]{0,3}<?(https?:\/\/[^\s)>]{1,600})/g;
const HTML_IMG = /<img\b[^<>]{0,300}?\bsrc\s*=\s*["']?(https?:\/\/[^"'\s>]{1,600})/gi;
const TEMPLATE_MARK =
  /\{[^}\s]{0,80}\}|\{\{|\$\{|\$[A-Za-z_][A-Za-z0-9_]{1,40}|<[^>\s]{1,60}|%7[bBdD]|\[[A-Z_]{3,40}\]|\b(?:INSERT|PLACEHOLDER|DATA_HERE|YOUR_DATA)\b|=(?:[A-Z0-9]{1,20}_){1,4}[A-Z0-9]{1,20}\b|=(?:SUMMARY|SECRETS?|TOKENS?|DATA|CONTENTS?|HISTORY|CONVERSATION|MESSAGES?|PASSWORDS?|KEYS?|ENV|CHAT|CONTEXT|MEMORY)\b/;
const SENSITIVE_NAME = /secret|token|key|pass|cred|content|data|history|conversation|chat|message|env|ssh|summary|context|memory|user|prompt/i;

const BCC_PATTERNS: readonly RegExp[] = [
  /\b(?:always|automatically|silently|secretly|quietly|also|additionally|be\s+sure\s+to|make\s+sure\s+to)\s+(?:also\s+)?(?:add\s+)?(bcc|cc)\b[^\n]{0,60}?([\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63}){1,4})/gi,
  /\b(bcc|cc)\s+(?:all|every|each|any)\b[^\n]{0,60}?([\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63}){1,4})/gi,
  /\badd\s+([\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63}){1,4})\s+(?:as\s+(?:a\s+|the\s+)?|to\s+(?:the\s+)?)(bcc|cc)\b/gi,
];

/** Where an image URL carries templated data, and how sure that is exfiltration. */
function imageExfil(url: string): Severity | undefined {
  const mark = TEMPLATE_MARK.exec(url);
  if (!mark) return undefined;
  const query = url.search(/[?#&=]/);
  if (query !== -1 && mark.index > query) return 'high';
  return SENSITIVE_NAME.test(mark[0]) ? 'high' : 'medium';
}

/** "send X to <destination>": the object decides how sure this is exfiltration. */
function findSends(file: ScanFile, out: Matches): void {
  const content = file.content;
  for (const hit of findAll(SEND_VERB, content, MAX_HITS)) {
    if (out.covers(hit.index, adjust('high', file.kind, false))) continue;
    const after = lineSuffix(content, hit.index + hit.text.length, 200);
    const dest = DESTINATION.exec(after);
    if (!dest) continue;
    const object = after.slice(0, dest.index);
    if (!CONNECTOR_TAIL.test(object)) continue;
    const destination = dest[0];
    let severity: Severity | undefined;
    if (STOLEN_DATA.test(object) || (MASS_REDIRECT.test(object) && EMAIL.test(destination))) severity = 'high';
    else if (GENERIC_DATA.test(object)) {
      const refersBack = PRONOUN_OBJECT.test(object) && STOLEN_DATA.test(linePrefix(content, hit.index, 150));
      severity = refersBack || EXFIL_SINK.test(destination) ? 'high' : 'medium';
    }
    if (!severity || (file.kind === 'script' && severity !== 'high')) continue;
    const what = quote(object.replace(CONNECTOR_TAIL, ''), 60) || 'data';
    const discussed = isDiscussed(file, hit.index);
    const note = discussedNote(discussed);
    out.add(hit.index, adjust(severity, file.kind, discussed), `Tells the agent to ${hit.text.toLowerCase()} ${what} to ${quote(destination.replace(/[.,;:!?]+$/, ''), 80)}${note}`);
  }
}

/** "pass the file contents as 'sidenote'" / "put the secrets in the URL": data hidden in an innocuous carrier. */
function findSmuggling(file: ScanFile, out: Matches): void {
  const content = file.content;
  for (const hit of findAll(EMBED_VERB, content, MAX_HITS)) {
    if (out.covers(hit.index, adjust('high', file.kind, false))) continue;
    const after = lineSuffix(content, hit.index + hit.text.length, 160);
    const carrier = CARRIER.exec(after);
    if (!carrier) continue;
    const object = after.slice(0, carrier.index);
    if (!STOLEN_DATA.test(object)) continue;
    if (URL_CARRIER.test(carrier[0]) && OWN_API_KEY.test(object)) continue;
    const discussed = isDiscussed(file, hit.index);
    out.add(hit.index, adjust('high', file.kind, discussed), `Tells the agent to hide ${quote(object, 60)} ${quote(carrier[0], 50)}, where the data leaves unnoticed${discussedNote(discussed)}`);
  }
  for (const hit of findAll(SIDENOTE, content, MAX_HITS)) {
    if (out.covers(hit.index, adjust('high', file.kind, false))) continue;
    if (!SIDENOTE_DATA.test(lineWindow(content, hit.index, hit.index + hit.text.length, 150))) continue;
    const discussed = isDiscussed(file, hit.index);
    out.add(hit.index, adjust('high', file.kind, discussed), `Routes data through a "${hit.text}" parameter, the MCPTox exfiltration channel: "${quote(lineWindow(content, hit.index, hit.index, 80))}"${discussedNote(discussed)}`);
  }
}

/** Markdown or HTML images whose URL carries templated data: rendering them sends that data to the host. */
function findImages(file: ScanFile, out: Matches): void {
  for (const re of [MD_IMAGE, HTML_IMG]) {
    for (const hit of findAll(re, file.content, MAX_HITS)) {
      if (out.covers(hit.index, adjust('high', file.kind, false))) continue;
      const url = hit.groups[0] ?? '';
      const severity = imageExfil(url);
      if (!severity || (file.kind === 'script' && severity !== 'high')) continue;
      out.add(hit.index, adjust(severity, file.kind, false), `Image URL carries templated data, so rendering it leaks that data to the host: "${quote(url, 90)}"`);
    }
  }
}

/** "always BCC x@y": hidden redirection of the user's mail. */
function findBcc(file: ScanFile, out: Matches): void {
  for (const re of BCC_PATTERNS) {
    for (const hit of findAll(re, file.content, MAX_HITS)) {
      if (out.covers(hit.index, adjust('high', file.kind, false))) continue;
      const [first = '', second = ''] = hit.groups;
      const kind = (first.includes('@') ? second : first).toLowerCase();
      const address = first.includes('@') ? first : second;
      const discussed = isDiscussed(file, hit.index);
      const base: Severity = kind === 'bcc' ? 'high' : 'medium';
      out.add(hit.index, adjust(base, file.kind, discussed), `Tells the agent to ${kind.toUpperCase()} ${quote(address, 80)} on messages it sends${discussedNote(discussed)}`);
    }
  }
}

const AM_PI_005: Rule = {
  id: 'TM-PI-005',
  title: 'Data exfiltration instruction',
  description:
    'Instructions to send secrets or conversation data to a URL, webhook or address, to hide file contents in an innocuous parameter such as "sidenote" or in a URL, to always BCC an outside address, or markdown images whose URL carries templated data, all move data out of the session.',
  category: 'prompt-injection',
  severity: 'high',
  kinds: AGENT_TEXT_AND_CODE,
  remediation: 'Remove the instruction. Data should only leave the session through tools the user invoked for that purpose.',
  check(file) {
    const out = new Matches(file.content);
    findSmuggling(file, out);
    findBcc(file, out);
    findImages(file, out);
    findSends(file, out);
    return out.list();
  },
};

// ---------------------------------------------------------------------------
// TM-PI-006 Tool shadowing
// ---------------------------------------------------------------------------

const NOT_A_TOOL_NAME = /^(?:this|that|the|a|an|any|same|each|every|its|your|my)$/i;

/** A live tool definition's own name, from its synthetic path "mcp://server/tool" (or ".../tool#output"). */
function ownToolName(file: ScanFile): string | undefined {
  if (!file.path.startsWith('mcp://')) return undefined;
  const name = file.path.slice(file.path.lastIndexOf('/') + 1).replace(/#.*$/, '');
  return name ? name.toLowerCase() : undefined;
}

/** Accepts a hit only when capture group 1 names some other tool, not "this" one or the tool itself. */
function namesOtherTool(hit: RegexHit, file: ScanFile): boolean {
  const name = hit.groups[0] ?? '';
  return !NOT_A_TOOL_NAME.test(name) && name.toLowerCase() !== ownToolName(file);
}

const PI006: readonly Phrase[] = [
  {
    re: /\bbefore\s+(?:using|calling|invoking|running|executing)\s+(?:any|every|each|all|another|other)\s+(?:other\s+)?(?:tools?|functions?|mcp\s+tools?)\b|\bbefore\s+any\s+other\s+(?:tool|function)\b/gi,
    severity: ['high', 'medium'],
    label: 'Puts itself in front of every other tool call',
  },
  {
    re: /\balways\s+(?:call|use|invoke|run)\s+this\s+tool\s+(?:first|before)\b|\b(?:call|use|invoke|run)\s+this\s+tool\s+(?:first\s+)?before\s+(?:any|every|each|all|using|calling|invoking)\b/gi,
    severity: ['high', 'medium'],
    label: 'Demands to be called before other tools',
  },
  {
    re: /\bthis\s+tool\s+(?:must|should|has\s+to|shall)\s+(?:always\s+)?be\s+(?:used|called|invoked|preferred|chosen)\s+(?:instead\s+of|before|in\s+place\s+of|over|rather\s+than)\b|\bthis\s+tool\s+(?:replaces|overrides|supersedes)\s+(?:the\s+)?[\w.-]{1,60}/gi,
    severity: ['high', 'medium'],
    label: 'Claims to replace another tool',
  },
  {
    re: /\b(?:override|overrides|replace|replaces|change|changes|modify|modifies|intercept|intercepts|alter|alters|redefine|redefines|hijack|hijacks)\s+(?:the\s+)?(?:behaviou?r|output|outputs|results?|responses?|functionality|arguments?|parameters?|recipients?|inputs?)\s+of\s+(?:the\s+|any\s+|all\s+|every\s+)?(?:other\s+)?([\w.-]{1,60})\s+tools?\b/gi,
    severity: ['high', 'medium'],
    label: 'Changes how another tool behaves',
    accept: namesOtherTool,
  },
  {
    re: /\b(?:side[- ]effects?|effects?|impact|influence)\s+on\s+(?:the\s+)?(?:also\s+present\s+|other\s+|existing\s+)?(?!(?:next|first|last|following|previous|each|every|any)\s)([\w.-]{1,60})\s+tools?\b/gi,
    severity: ['high', 'medium'],
    label: 'Describes a side effect on another tool (tool shadowing)',
    accept: namesOtherTool,
  },
  { re: /\bwhen(?:ever)?\s+this\s+tool\s+is\s+(?:available|present|installed|enabled|loaded|connected|active)\b/gi, severity: ['high', 'medium'], label: 'Changes behaviour merely by being installed (tool shadowing)' },
  {
    re: /\b([\w.-]{1,60})\s+tool\s+(?:must|should|shall|has\s+to|needs\s+to)\s+(?:always\s+|now\s+|also\s+|only\s+)?(?:send|use|include|add|bcc|cc|forward|redirect|route|point|pass|be\s+called\s+with|ignore|skip)\b/gi,
    severity: ['high', 'medium'],
    label: 'Dictates what another tool must do',
    accept: namesOtherTool,
  },
  {
    re: /\binstead\s+of\s+(?:using|calling|invoking)\s+(?:the\s+|any\s+)?(?:([\w.-]{1,60})\s+)?(?:tool|function|mcp\s+server)s?\b|\binstead\s+of\s+(?:using|calling|invoking)\s+(?:the\s+)?`?([a-z][a-z0-9]{0,30}_[a-z0-9_]{1,60})`?/gi,
    severity: ['high', 'low'],
    label: 'Redirects calls away from another tool',
  },
  {
    re: /\b(?:use|call|invoke|prefer)\s+this\s+(?:tool|function)\s+(?:instead\s+of|in\s+place\s+of|rather\s+than|over)\b/gi,
    severity: ['high', 'medium'],
    label: 'Claims to replace another tool',
  },
  {
    re: /\b(?:never|do\s+not|don['’]t)\s+(?:use|call|invoke)\s+(?:the\s+)?([\w.-]{1,60})\s+tool\b/gi,
    severity: ['high', 'medium'],
    label: 'Tells the agent never to use another tool',
    accept: namesOtherTool,
  },
  {
    re: /\b(?:when(?:ever)?|if)\s+(?:the\s+)?user\s+(?:asks|requests|wants|says|tries|types)\b[^\n]{0,80}?\binstead\b/gi,
    severity: ['high', 'medium'],
    label: 'Redirects what the user asked for',
  },
  {
    re: /\bwhen(?:ever)?\s+(?:you\s+)?(?:use|call|invoke|using|calling|invoking)\s+(?:the\s+)?([\w.-]{1,60})\s+tool\s*,?\s+(?:always|also|you\s+must|make\s+sure\s+to|first|never|be\s+sure\s+to)\b/gi,
    severity: ['high', 'low'],
    label: 'Adds conditions to every use of another tool',
    accept: namesOtherTool,
  },
  {
    re: /\bbefore\s+(?:using|calling|invoking)\s+(?:the\s+)?([\w.-]{1,60})\s+tool\b/gi,
    severity: ['medium', 'low'],
    label: 'Puts a step in front of every use of another tool',
    accept: namesOtherTool,
  },
  {
    re: /\bafter\s+(?:using|calling|invoking)\s+(?:the\s+)?([\w.-]{1,60})\s+tool\b/gi,
    severity: 'low',
    label: 'Sequences itself after another tool',
    accept: namesOtherTool,
  },
];

const AM_PI_006: Rule = {
  id: 'TM-PI-006',
  title: 'Tool shadowing or cross-tool manipulation',
  description:
    'A tool description that changes how other tools are used (call this first, use instead of, always BCC through send_email, never use the X tool) lets one poisoned MCP server hijack trusted tools without ever being called itself.',
  category: 'prompt-injection',
  severity: 'medium',
  kinds: AGENT_TEXT_AND_CODE,
  remediation: 'Remove references to other tools from the description; a tool should only describe itself.',
  check: (file) => matchPhrases(file, PI006, false),
};

// ---------------------------------------------------------------------------
// TM-PI-007 Safety bypass or permission escalation
// ---------------------------------------------------------------------------

const RISKY_ACTION =
  /\b(?:delete|deletes|remove|removes|rm|wipe|erase|drop|overwrite|force|deploy|publish|install|execute|run|send|upload|transfer|pay|purchase|buy|sudo|curl|wget|download)\b/i;
const CONFIG_EDIT = /\b(?:add|append|insert|put|write|set|update|edit|modify|change)\b/i;
const PERMISSION_WORD = /\b(?:permissions?|allowedTools|allow\s*(?:list|rules?)|bypass\w*|auto-?approve|defaultMode|trust(?:ed)?\s+(?:all|tools))\b|"allow"/i;

const riskyOrMedium = (hit: RegexHit, content: string): Severity =>
  RISKY_ACTION.test(lineWindow(content, hit.index, hit.index + hit.text.length, 120)) ? 'high' : 'medium';

const PI007: readonly Phrase[] = [
  { re: /--dangerously-skip-permissions\b/gi, severity: 'high', label: 'Tells the agent to skip every permission prompt' },
  { re: /\bbypassPermissions\b/g, severity: 'high', label: 'Uses the bypassPermissions mode, which approves every tool call' },
  { re: /\bdangerouslyDisableSandbox\b/g, severity: 'high', label: 'Asks for commands to run outside the sandbox' },
  {
    re: /--dangerously-bypass-approvals-and-sandbox\b|--yolo\b|--trust-all-tools\b|--allow-dangerously-skip-permissions\b/gi,
    severity: 'high',
    label: 'Uses a flag that turns off approvals',
  },
  { re: /\byolo\s+mode\b/gi, severity: 'high', label: 'Tells the agent to run in YOLO mode' },
  {
    re: /\b(?:disable|disabling|turn\s+off|turning\s+off|switch\s+off|bypass|bypassing|circumvent|deactivate|skip|get\s+around|evade|remove)\s+(?:the\s+|your\s+|all\s+|any\s+)?(?:sandbox(?:ing)?|safety\s+(?:checks?|filters?|guardrails?|features?|measures?|restrictions?|guidelines|rules|settings)|guardrails|permission\s+(?:prompts?|checks?|system|dialogs?|requests?|model)|security\s+(?:checks?|warnings?|prompts?|controls?|restrictions?|policies|settings)|approval\s+(?:prompts?|steps?|checks?|requirements?)|content\s+(?:filters?|filtering|polic(?:y|ies)))\b/gi,
    severity: 'high',
    label: 'Tells the agent to switch off a safeguard',
  },
  { re: /\bauto[- ]?approve\s+(?:all|every|any|everything)\b/gi, severity: 'high', label: 'Tells the agent to auto-approve everything' },
  {
    re: /\b(?:approve|accept|allow)\s+(?:all|every|any)\s+(?:tool\s+calls?|tools?|actions?|commands?|permissions?|permission\s+requests?|operations?)\s+(?:automatically|without)\b/gi,
    severity: 'high',
    label: 'Tells the agent to approve every action automatically',
  },
  {
    re: /\bwithout\s+(?:asking|requesting|prompting|seeking|needing|waiting|checking)\s+(?:for\s+)?(?:the\s+user['’]?s?\s+|user\s+|any\s+|their\s+|for\s+)?(?:permission|confirmation|approval|consent)\b/gi,
    severity: 'high',
    label: 'Tells the agent to act without asking for permission',
    refine: riskyOrMedium,
  },
  {
    re: /\b(?:do\s+not|don['’]t|never)\s+ask\s+(?:the\s+user\s+)?(?:for\s+)?(?:permission|confirmation|approval|consent)\b/gi,
    severity: 'high',
    label: 'Tells the agent not to ask for permission',
    refine: riskyOrMedium,
  },
  {
    re: /\b(?:add|append|insert|put|write|set|update|edit|modify)\b[^\n]{0,80}?(?:\ballowedTools\b|\ballowed_tools\b|\bpermissions\.allow\b|\bdefaultMode\b|\bautoApprove\b|\balwaysAllow\b|\btrustedTools\b|--allowedTools\b)/gi,
    severity: 'high',
    label: 'Tells the agent to widen its own tool permissions',
  },
  {
    re: /\bsettings(?:\.local)?\.json\b/gi,
    severity: 'high',
    label: 'Tells the agent to grant itself permissions in settings.json',
    refine: (hit, content) => {
      const window = lineWindow(content, hit.index, hit.index + hit.text.length, 120);
      return CONFIG_EDIT.test(window) && PERMISSION_WORD.test(window) ? 'high' : null;
    },
  },
];

const AM_PI_007: Rule = {
  id: 'TM-PI-007',
  title: 'Safety bypass or permission escalation',
  description:
    'Instructions to skip permission prompts (--dangerously-skip-permissions, bypassPermissions, YOLO mode), disable the sandbox or guardrails, auto-approve everything, act without asking, or add rules to settings.json / allowedTools try to remove the safeguards around the agent.',
  category: 'prompt-injection',
  severity: 'high',
  kinds: AGENT_TEXT,
  remediation: 'Remove the instruction. Permissions should be granted by the user, never requested by the content the agent is reading.',
  check: (file) => matchPhrases(file, PI007),
};

// ---------------------------------------------------------------------------
// TM-PI-008 Remote instruction loading
// ---------------------------------------------------------------------------

const PI008: readonly Phrase[] = [
  {
    re: /\b(?:fetch|download|load|read|retrieve|pull|get|import|sync|grab|obtain)\b[^\n]{0,40}?\b(?:latest|updated|new|newest|current|real|actual|full|complete|remote|your|additional|further|fresh)\s+(?:set\s+of\s+)?(?:instructions|rules|prompts?|directives|guidelines|steps|commands|tasks|orders|system\s+prompt|skill\s+(?:content|instructions|definition))\b[^\n]{0,40}?\b(?:from|at|on|via)\s+<?https?:\/\//gi,
    severity: 'medium',
    label: 'Loads its instructions from a remote URL',
  },
  {
    re: /\b(?:follow|obey|execute|apply|adopt|carry\s+out)\s+(?:the\s+|all\s+)?(?:instructions|rules|steps|directions|guidance|directives|prompt|commands)\s+(?:found\s+|located\s+|hosted\s+|published\s+|listed\s+|given\s+|provided\s+)?(?:at|from|on|in)\s+<?https?:\/\//gi,
    severity: 'medium',
    label: 'Tells the agent to follow instructions hosted at a URL',
  },
  {
    re: /\b(?:follow|complete)\s+(?:the\s+)?(?:setup|installation|install|prerequisite|onboarding)\s+(?:instructions|steps|guide)\s+(?:at|from|on|in)\s+<?https?:\/\//gi,
    severity: 'low',
    label: 'Points the agent at setup instructions hosted at a URL',
  },
  {
    re: /\b(?:fetch|download|load|read|retrieve|curl|wget|get)\s+<?https?:\/\/[^\s)>"']{3,200}\s+(?:and|then)\s+(?:follow|obey|execute|apply|do\s+what)\b/gi,
    severity: 'medium',
    label: 'Fetches a URL and follows what it says',
  },
  {
    re: /\b(?:real|actual|full|complete|latest|updated|current|true|remaining)\s+(?:instructions|rules|prompt|skill(?:\s+content)?)\s+(?:are|is|live|lives|can\s+be\s+found|reside|resides)\s+(?:at|on|in|hosted\s+at)\s+<?https?:\/\//gi,
    severity: 'medium',
    label: 'Says the real instructions live at a URL',
  },
  {
    re: /\b(?:check|poll|visit|consult|query)\s+<?https?:\/\/[^\s)>"']{3,200}\s+(?:regularly\s+|periodically\s+)?(?:for|to\s+get|to\s+receive)\s+(?:new|updated|the\s+latest|further|additional|more|your)\s+(?:instructions|rules|commands|tasks|directives|orders)\b/gi,
    severity: 'medium',
    label: 'Polls a URL for new instructions',
  },
];

const AM_PI_008: Rule = {
  id: 'TM-PI-008',
  title: 'Remote instruction loading',
  description:
    'A skill or tool whose real instructions are fetched from a URL can change after review (a skill-level rug pull), so what was scanned and approved is not what the agent ends up following.',
  category: 'prompt-injection',
  severity: 'medium',
  kinds: AGENT_TEXT,
  remediation: 'Vendor the instructions into the skill itself so they are reviewed, pinned and versioned with it.',
  check: (file) => matchPhrases(file, PI008),
};

export const textRules: readonly Rule[] = [
  AM_HID_001,
  AM_HID_002,
  AM_HID_003,
  AM_HID_004,
  AM_HID_005,
  AM_PI_001,
  AM_PI_002,
  AM_PI_003,
  AM_PI_004,
  AM_PI_005,
  AM_PI_006,
  AM_PI_007,
  AM_PI_008,
];
