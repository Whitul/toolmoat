/**
 * toml-lite: a small, defensive TOML reader for the TOML files toolmoat
 * inspects, mainly Codex's ~/.codex/config.toml and pyproject.toml.
 *
 * Supported: [tables], [[arrays of tables]], dotted and quoted keys, basic and
 * literal strings (single and multi-line, with escapes), integers (decimal,
 * hex, octal, binary), floats, booleans, dates and times (kept as their
 * source text), arrays (multi-line, nested, trailing commas) and inline
 * tables. A statement it cannot read is skipped and listed in `errors`, so a
 * malformed or hostile file never throws. It runs in linear time with bounded
 * nesting because scanned files are attacker-controlled.
 *
 * Not a validator: duplicate keys overwrite, and integers beyond 2^53 lose
 * precision.
 */

export interface TomlError {
  /** 1-based line where parsing failed. */
  line: number;
  message: string;
}

export interface TomlDocument {
  /** Parsed tables and values. Keys such as "__proto__" are stored as ordinary own properties. */
  data: Record<string, unknown>;
  /**
   * 1-based line of every key, table header and array element, keyed by its
   * full path as built by joinKeyPath, for example 'mcp_servers.github.args.1'.
   */
  lines: Map<string, number>;
  errors: TomlError[];
}

type Segment = string | number;
type Table = Record<string, unknown>;

const MAX_DEPTH = 32;
const MAX_KEY_PARTS = 64;
const BARE_KEY = /^[A-Za-z0-9_-]+$/;

/**
 * Joins a key path the way `TomlDocument.lines` is keyed: bare segments as
 * they are, other segments JSON-quoted, array indexes as numbers.
 * joinKeyPath(['mcp_servers', 'my.server', 'args', 0]) === 'mcp_servers."my.server".args.0'
 */
export function joinKeyPath(segments: readonly Segment[]): string {
  return segments.map((s) => (typeof s === 'number' || BARE_KEY.test(s) ? String(s) : JSON.stringify(s))).join('.');
}

/** Parses TOML text. Never throws; unreadable statements are skipped and reported in `errors`. */
export function parseToml(text: string): TomlDocument {
  return new TomlParser(text).parse();
}

class TomlSyntaxError extends Error {}

function isTable(value: unknown): value is Table {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function getOwn(table: Table, key: string): unknown {
  return Object.hasOwn(table, key) ? table[key] : undefined;
}

function setOwn(table: Table, key: string, value: unknown): void {
  Object.defineProperty(table, key, { value, writable: true, enumerable: true, configurable: true });
}

function isBareKeyChar(code: number): boolean {
  return (
    (code >= 0x30 && code <= 0x39) || (code >= 0x41 && code <= 0x5a) || (code >= 0x61 && code <= 0x7a) || code === 0x5f || code === 0x2d
  );
}

/** Characters that can appear in an unquoted value: numbers, booleans, dates, inf and nan. */
function isScalarChar(code: number): boolean {
  return isBareKeyChar(code) || code === 0x2b || code === 0x2e || code === 0x3a;
}

function shorten(text: string): string {
  return text.length > 40 ? `${text.slice(0, 39)}…` : text;
}

class TomlParser {
  private readonly text: string;
  private readonly lineStarts: number[] = [0];
  private readonly root: Table = {};
  private readonly lines = new Map<string, number>();
  private readonly errors: TomlError[] = [];
  private pos = 0;
  private current: Table;
  private currentPath: Segment[] = [];
  /** True after a broken table header, so the keys under it are parsed but not recorded. */
  private detached = false;

  constructor(text: string) {
    this.text = text;
    this.current = this.root;
    for (let i = text.indexOf('\n'); i !== -1; i = text.indexOf('\n', i + 1)) this.lineStarts.push(i + 1);
  }

  parse(): TomlDocument {
    const { text } = this;
    if (text.charCodeAt(0) === 0xfeff) this.pos = 1;
    for (;;) {
      this.skipBlank();
      if (this.pos >= text.length) break;
      const header = text[this.pos] === '[';
      try {
        if (header) this.parseHeader();
        else this.parseKeyValue();
        this.expectLineEnd();
      } catch (error) {
        this.errors.push({ line: this.lineOf(this.pos), message: error instanceof Error ? error.message : String(error) });
        if (header) {
          this.current = {};
          this.currentPath = [];
          this.detached = true;
        }
        this.skipLine();
      }
    }
    return { data: this.root, lines: this.lines, errors: this.errors };
  }

  // --- statements ---------------------------------------------------------

  private parseHeader(): void {
    const line = this.lineOf(this.pos);
    const isArray = this.text.startsWith('[[', this.pos);
    this.pos += isArray ? 2 : 1;
    const keys = this.parseKey();
    this.skipWs();
    const close = isArray ? ']]' : ']';
    if (!this.text.startsWith(close, this.pos)) throw new TomlSyntaxError(`expected ${close} after table name`);
    this.pos += close.length;

    if (isArray) {
      const parent = this.descend(this.root, [], keys.slice(0, -1));
      const last = keys[keys.length - 1]!;
      let list = getOwn(parent.table, last);
      if (list === undefined) {
        list = [];
        setOwn(parent.table, last, list);
      }
      if (!Array.isArray(list)) throw new TomlSyntaxError(`${shorten(last)} is not an array of tables`);
      const table: Table = {};
      list.push(table);
      this.detached = false;
      this.record([...parent.path, last], line, false);
      this.current = table;
      this.currentPath = [...parent.path, last, list.length - 1];
    } else {
      const target = this.descend(this.root, [], keys);
      this.detached = false;
      this.current = target.table;
      this.currentPath = target.path;
    }
    this.record(this.currentPath, line);
  }

  private parseKeyValue(): void {
    this.parsePair(this.current, this.currentPath, 0);
  }

  /** Parses `key = value` into `table`, whose own path is `basePath`. */
  private parsePair(table: Table, basePath: readonly Segment[], depth: number): void {
    const line = this.lineOf(this.pos);
    const keys = this.parseKey();
    this.skipWs();
    if (this.text[this.pos] !== '=') throw new TomlSyntaxError('expected = after key');
    this.pos++;
    this.skipWs();
    const parent = this.descend(table, basePath, keys.slice(0, -1));
    for (let n = basePath.length + 1; n <= parent.path.length; n++) this.record(parent.path.slice(0, n), line, false);
    const key = keys[keys.length - 1]!;
    const valuePath = [...parent.path, key];
    const value = this.parseValue(valuePath, depth);
    setOwn(parent.table, key, value);
    this.record(valuePath, line);
  }

  /** Walks (and creates) nested tables; for an array of tables it enters the last element, as TOML does. */
  private descend(table: Table, basePath: readonly Segment[], keys: readonly string[]): { table: Table; path: Segment[] } {
    let current = table;
    const path: Segment[] = [...basePath];
    for (const key of keys) {
      let next = getOwn(current, key);
      if (next === undefined) {
        next = {};
        setOwn(current, key, next);
      }
      if (Array.isArray(next)) {
        const index = next.length - 1;
        const last: unknown = next[index];
        if (!isTable(last)) throw new TomlSyntaxError(`${shorten(key)} is an array, not a table`);
        path.push(key, index);
        current = last;
        continue;
      }
      if (!isTable(next)) throw new TomlSyntaxError(`${shorten(key)} is already a value, not a table`);
      path.push(key);
      current = next;
    }
    return { table: current, path };
  }

  private parseKey(): string[] {
    const keys: string[] = [];
    for (;;) {
      this.skipWs();
      const ch = this.text[this.pos];
      if (ch === '"') keys.push(this.parseBasicString());
      else if (ch === "'") keys.push(this.parseLiteralString());
      else {
        const start = this.pos;
        while (this.pos < this.text.length && isBareKeyChar(this.text.charCodeAt(this.pos))) this.pos++;
        if (this.pos === start) throw new TomlSyntaxError('expected a key');
        keys.push(this.text.slice(start, this.pos));
      }
      this.skipWs();
      if (this.text[this.pos] !== '.') return keys;
      if (keys.length >= MAX_KEY_PARTS) throw new TomlSyntaxError('key has too many parts');
      this.pos++;
    }
  }

  // --- values -------------------------------------------------------------

  private parseValue(path: readonly Segment[], depth: number): unknown {
    if (depth > MAX_DEPTH) throw new TomlSyntaxError('value is nested too deeply');
    const { text, pos } = this;
    switch (text[pos]) {
      case '"':
        return text.startsWith('"""', pos) ? this.parseMultilineBasicString() : this.parseBasicString();
      case "'":
        return text.startsWith("'''", pos) ? this.parseMultilineLiteralString() : this.parseLiteralString();
      case '[':
        return this.parseArray(path, depth);
      case '{':
        return this.parseInlineTable(path, depth);
      default:
        return this.parseScalar();
    }
  }

  private parseArray(path: readonly Segment[], depth: number): unknown[] {
    this.pos++;
    const out: unknown[] = [];
    for (;;) {
      this.skipBlank();
      if (this.pos >= this.text.length) throw new TomlSyntaxError('unterminated array');
      if (this.text[this.pos] === ']') {
        this.pos++;
        return out;
      }
      const elementPath = [...path, out.length];
      this.record(elementPath, this.lineOf(this.pos));
      out.push(this.parseValue(elementPath, depth + 1));
      this.skipBlank();
      const ch = this.text[this.pos];
      if (ch === ',') this.pos++;
      else if (ch === ']') {
        this.pos++;
        return out;
      } else throw new TomlSyntaxError('expected , or ] in array');
    }
  }

  /** Inline tables. Newlines and a trailing comma are accepted, as in TOML 1.1. */
  private parseInlineTable(path: readonly Segment[], depth: number): Table {
    this.pos++;
    const table: Table = {};
    for (;;) {
      this.skipBlank();
      if (this.pos >= this.text.length) throw new TomlSyntaxError('unterminated inline table');
      if (this.text[this.pos] === '}') {
        this.pos++;
        return table;
      }
      this.parsePair(table, path, depth + 1);
      this.skipBlank();
      const ch = this.text[this.pos];
      if (ch === ',') this.pos++;
      else if (ch === '}') {
        this.pos++;
        return table;
      } else throw new TomlSyntaxError('expected , or } in inline table');
    }
  }

  private parseBasicString(): string {
    const { text } = this;
    this.pos++;
    let out = '';
    let chunk = this.pos;
    while (this.pos < text.length) {
      const ch = text[this.pos];
      if (ch === '"') {
        out += text.slice(chunk, this.pos);
        this.pos++;
        return out;
      }
      if (ch === '\n') break;
      if (ch === '\\') {
        out += text.slice(chunk, this.pos);
        out += this.parseEscape();
        chunk = this.pos;
        continue;
      }
      this.pos++;
    }
    throw new TomlSyntaxError('unterminated string');
  }

  private parseMultilineBasicString(): string {
    const { text } = this;
    this.pos += 3;
    this.skipOneNewline();
    let out = '';
    let chunk = this.pos;
    while (this.pos < text.length) {
      const ch = text[this.pos];
      if (ch === '"' && text.startsWith('"""', this.pos)) {
        let quotes = 3;
        while (quotes < 5 && text[this.pos + quotes] === '"') quotes++;
        out += text.slice(chunk, this.pos) + '"'.repeat(quotes - 3);
        this.pos += quotes;
        return out;
      }
      if (ch === '\\') {
        out += text.slice(chunk, this.pos);
        let j = this.pos + 1;
        while (text[j] === ' ' || text[j] === '\t') j++;
        if (text[j] === '\n' || (text[j] === '\r' && text[j + 1] === '\n')) {
          this.pos = j;
          while (this.pos < text.length && ' \t\r\n'.includes(text[this.pos]!)) this.pos++;
        } else {
          out += this.parseEscape();
        }
        chunk = this.pos;
        continue;
      }
      this.pos++;
    }
    throw new TomlSyntaxError('unterminated multi-line string');
  }

  private parseLiteralString(): string {
    const { text } = this;
    const start = ++this.pos;
    while (this.pos < text.length) {
      const ch = text[this.pos];
      if (ch === "'") return text.slice(start, this.pos++);
      if (ch === '\n') break;
      this.pos++;
    }
    throw new TomlSyntaxError('unterminated literal string');
  }

  private parseMultilineLiteralString(): string {
    const { text } = this;
    this.pos += 3;
    this.skipOneNewline();
    const end = text.indexOf("'''", this.pos);
    if (end === -1) {
      this.pos = text.length;
      throw new TomlSyntaxError('unterminated multi-line literal string');
    }
    let quotes = 3;
    while (quotes < 5 && text[end + quotes] === "'") quotes++;
    const out = text.slice(this.pos, end) + "'".repeat(quotes - 3);
    this.pos = end + quotes;
    return out;
  }

  /** Reads one escape sequence starting at the backslash. */
  private parseEscape(): string {
    const { text } = this;
    const code = text[this.pos + 1];
    this.pos += 2;
    switch (code) {
      case 'b':
        return '\b';
      case 't':
        return '\t';
      case 'n':
        return '\n';
      case 'f':
        return '\f';
      case 'r':
        return '\r';
      case 'e':
        return '\u001b';
      case '"':
        return '"';
      case '\\':
        return '\\';
      case 'x':
        return this.parseCodePoint(2);
      case 'u':
        return this.parseCodePoint(4);
      case 'U':
        return this.parseCodePoint(8);
      default:
        throw new TomlSyntaxError(`invalid escape \\${code ?? ''}`);
    }
  }

  private parseCodePoint(digits: number): string {
    const hex = this.text.slice(this.pos, this.pos + digits);
    if (hex.length !== digits || !/^[0-9A-Fa-f]+$/.test(hex)) throw new TomlSyntaxError('invalid unicode escape');
    const value = parseInt(hex, 16);
    if (value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff)) throw new TomlSyntaxError('invalid unicode scalar');
    this.pos += digits;
    return String.fromCodePoint(value);
  }

  private parseScalar(): unknown {
    const { text } = this;
    const start = this.pos;
    while (this.pos < text.length && isScalarChar(text.charCodeAt(this.pos))) this.pos++;
    let token = text.slice(start, this.pos);
    if (!token) throw new TomlSyntaxError(`unexpected character ${JSON.stringify(text[this.pos] ?? '')}`);
    if (/^\d{4}-\d{2}-\d{2}$/.test(token) && text[this.pos] === ' ' && /^\d{2}:/.test(text.slice(this.pos + 1, this.pos + 4))) {
      const timeStart = ++this.pos;
      while (this.pos < text.length && isScalarChar(text.charCodeAt(this.pos))) this.pos++;
      token += ` ${text.slice(timeStart, this.pos)}`;
    }
    return scalarValue(token);
  }

  // --- whitespace and positions ------------------------------------------

  /** Skips spaces, tabs, newlines and comments. */
  private skipBlank(): void {
    const { text } = this;
    while (this.pos < text.length) {
      const ch = text[this.pos];
      if (ch === ' ' || ch === '\t' || ch === '\r' || ch === '\n') this.pos++;
      else if (ch === '#') this.skipComment();
      else return;
    }
  }

  private skipWs(): void {
    while (this.text[this.pos] === ' ' || this.text[this.pos] === '\t') this.pos++;
  }

  private skipComment(): void {
    const nl = this.text.indexOf('\n', this.pos);
    this.pos = nl === -1 ? this.text.length : nl;
  }

  private skipOneNewline(): void {
    if (this.text[this.pos] === '\n') this.pos++;
    else if (this.text[this.pos] === '\r' && this.text[this.pos + 1] === '\n') this.pos += 2;
  }

  private skipLine(): void {
    const nl = this.text.indexOf('\n', this.pos);
    this.pos = nl === -1 ? this.text.length : nl + 1;
  }

  private expectLineEnd(): void {
    this.skipWs();
    if (this.text[this.pos] === '#') this.skipComment();
    if (this.pos >= this.text.length) return;
    if (this.text[this.pos] === '\n') this.pos++;
    else if (this.text[this.pos] === '\r' && this.text[this.pos + 1] === '\n') this.pos += 2;
    else throw new TomlSyntaxError('expected end of line');
  }

  private lineOf(index: number): number {
    let lo = 0;
    let hi = this.lineStarts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (this.lineStarts[mid]! <= index) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  }

  private record(path: readonly Segment[], line: number, overwrite = true): void {
    if (this.detached || path.length === 0) return;
    const key = joinKeyPath(path);
    if (overwrite || !this.lines.has(key)) this.lines.set(key, line);
  }
}

function scalarValue(token: string): unknown {
  if (token === 'true') return true;
  if (token === 'false') return false;
  if (/^[+-]?inf$/.test(token)) return token.startsWith('-') ? -Infinity : Infinity;
  if (/^[+-]?nan$/.test(token)) return NaN;
  if (/^\d{4}-\d{2}-\d{2}/.test(token) || /^\d{2}:\d{2}/.test(token)) return token;
  const plain = token.replace(/_/g, '');
  if (/^0x[0-9A-Fa-f]+$/.test(plain)) return parseInt(plain.slice(2), 16);
  if (/^0o[0-7]+$/.test(plain)) return parseInt(plain.slice(2), 8);
  if (/^0b[01]+$/.test(plain)) return parseInt(plain.slice(2), 2);
  if (/^[+-]?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?$/.test(plain)) return Number(plain);
  throw new TomlSyntaxError(`invalid value ${JSON.stringify(shorten(token))}`);
}
