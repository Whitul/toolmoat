/**
 * Framing for the MCP stdio transport: newline-delimited JSON-RPC 2.0
 * messages. Lines are split on raw bytes, so chunks may break a line or a
 * multi-byte character anywhere, and lines may end with \n or \r\n.
 */

const NEWLINE = 0x0a;

export interface Line {
  /** The line's bytes without the terminating \n (a trailing \r is kept, so the line can be forwarded byte for byte). */
  raw: Buffer;
  /** The line decoded as UTF-8, without its \n or \r\n terminator. */
  text: string;
}

/** Splits a byte stream into lines without quadratic copying, however the stream is chunked. */
export class LineDecoder {
  private pending: Buffer[] = [];

  /** Feeds one chunk and returns every line it completed. */
  push(chunk: Buffer): Line[] {
    const lines: Line[] = [];
    let start = 0;
    let newline = chunk.indexOf(NEWLINE, start);
    while (newline !== -1) {
      const piece = chunk.subarray(start, newline);
      if (this.pending.length > 0) {
        this.pending.push(piece);
        lines.push(toLine(Buffer.concat(this.pending)));
        this.pending = [];
      } else {
        lines.push(toLine(piece));
      }
      start = newline + 1;
      newline = chunk.indexOf(NEWLINE, start);
    }
    if (start < chunk.length) this.pending.push(chunk.subarray(start));
    return lines;
  }

  /** Returns the unterminated last line at end of stream, if there is one. */
  flush(): Line | undefined {
    if (this.pending.length === 0) return undefined;
    const raw = Buffer.concat(this.pending);
    this.pending = [];
    return raw.length > 0 ? toLine(raw) : undefined;
  }
}

function toLine(raw: Buffer): Line {
  const text = raw.toString('utf8');
  return { raw, text: text.endsWith('\r') ? text.slice(0, -1) : text };
}

export type JsonRpcId = string | number;

/** A JSON-RPC message as parsed from the wire. Fields are unvalidated: the peer may be hostile. */
export type JsonRpcMessage = Record<string, unknown>;

export type ParsedLine =
  | { kind: 'message'; message: JsonRpcMessage }
  | { kind: 'batch'; items: unknown[] }
  /** Starts like JSON but does not parse. A lenient reader at the other end might still accept it. */
  | { kind: 'invalid' }
  | { kind: 'raw' };

/** Anything that begins, after any whitespace, with an object or array opener. JSON.parse allows less whitespace than other parsers do, so this is deliberately wide. */
const JSON_LIKE = /^\s*[{[]/;

/** Classifies a line as a JSON-RPC message, a batch (JSON array), JSON-looking garbage, or anything else (logs, blank lines). */
export function parseLine(text: string): ParsedLine {
  // .NET and PowerShell servers can start their output with a byte order mark; clients that tolerate it must keep working.
  const body = text.startsWith('﻿') ? text.replace(/^﻿+/, '') : text;
  if (!JSON_LIKE.test(body)) return { kind: 'raw' };
  let value: unknown;
  try {
    value = JSON.parse(body);
  } catch {
    return { kind: 'invalid' };
  }
  if (Array.isArray(value)) return { kind: 'batch', items: value };
  if (value !== null && typeof value === 'object') return { kind: 'message', message: value as JsonRpcMessage };
  return { kind: 'invalid' };
}

/** Serializes one message for the wire. JSON.stringify never emits a raw newline, so the framing stays intact. */
export function encodeMessage(value: unknown): string {
  return JSON.stringify(value);
}

function hasId(message: JsonRpcMessage): boolean {
  return typeof message.id === 'string' || typeof message.id === 'number';
}

/** A request expects a response: it has a method and a string or numeric id. */
export function isRequest(message: JsonRpcMessage): boolean {
  return typeof message.method === 'string' && hasId(message);
}

export function isNotification(message: JsonRpcMessage): boolean {
  return typeof message.method === 'string' && !('id' in message);
}

export function isResponse(message: JsonRpcMessage): boolean {
  return message.method === undefined && hasId(message) && ('result' in message || 'error' in message);
}

/** Map key for a request id that keeps 1 and "1" apart. */
export function idKey(id: unknown): string {
  return typeof id === 'number' ? `n:${id}` : `s:${String(id)}`;
}
