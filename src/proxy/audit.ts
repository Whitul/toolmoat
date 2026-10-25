import fs from 'node:fs';
import path from 'node:path';
import { redactSecrets } from '../patterns/secrets.js';
import type { FindingSummary } from './lockfile.js';

export type AuditEventName =
  | 'start'
  | 'tools/list'
  | 'pinned'
  | 'blocked'
  | 'changed'
  | 'new'
  | 'flagged'
  | 'call'
  | 'secret'
  | 'injection'
  | 'server-request'
  | 'exit';

export interface SecretSummary {
  patternId: string;
  name: string;
}

/** One JSONL line of the audit log. Argument values appear only with --log-args, and then redacted. */
export interface AuditEvent {
  ts: string;
  server: string;
  event: AuditEventName;
  tool?: string;
  decision?: string;
  findings?: Array<FindingSummary | SecretSummary>;
  /** Size of the JSON-encoded tool arguments. */
  argBytes?: number;
  args?: unknown;
  /** Method of a server-to-client request. */
  method?: string;
  /** Short human-readable context, such as a block reason or a tool count. */
  detail?: string;
  /** Exit code of the server process. */
  code?: number;
}

export type AuditInput = Omit<AuditEvent, 'ts' | 'server'>;

/** Where the firewall reports events. Implementations must never throw. */
export interface AuditSink {
  write(event: AuditInput): void;
}

const MAX_LOGGED_ARGS = 16 * 1024;

/**
 * Append-only JSONL audit log written through a non-blocking stream. Any
 * failure (unwritable directory, full disk) disables logging with one
 * warning instead of disturbing the proxy.
 */
export class AuditLog implements AuditSink {
  private stream: fs.WriteStream | undefined;
  private failed = false;

  constructor(
    readonly file: string,
    private readonly server: string,
    private readonly warn: (message: string) => void = () => {},
  ) {
    try {
      fs.mkdirSync(path.dirname(file), { recursive: true });
      this.stream = fs.createWriteStream(file, { flags: 'a' });
      this.stream.on('error', (error) => this.fail(error));
    } catch (error) {
      this.fail(error);
    }
  }

  write(event: AuditInput): void {
    if (this.failed || !this.stream) return;
    try {
      this.stream.write(`${JSON.stringify({ ts: new Date().toISOString(), server: this.server, ...event })}\n`);
    } catch (error) {
      this.fail(error);
    }
  }

  /** Flushes and closes the stream. Resolves even when the log is broken or slow. */
  close(timeoutMs = 2000): Promise<void> {
    const stream = this.stream;
    this.stream = undefined;
    if (!stream || this.failed) return Promise.resolve();
    return new Promise((resolve) => {
      const timer = setTimeout(resolve, timeoutMs);
      timer.unref();
      stream.end(() => {
        clearTimeout(timer);
        resolve();
      });
    });
  }

  private fail(error: unknown): void {
    if (this.failed) return;
    this.failed = true;
    this.warn(`audit log disabled, cannot write ${this.file}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/** An audit sink that keeps events in memory, for tests and embedding. */
export class MemoryAudit implements AuditSink {
  readonly events: AuditInput[] = [];

  write(event: AuditInput): void {
    this.events.push(event);
  }
}

/** Arguments as they may appear in the log with --log-args: secrets redacted, size capped. */
export function loggableArgs(argsJson: string): unknown {
  const redacted = redactSecrets(argsJson);
  if (redacted.length > MAX_LOGGED_ARGS) return `${redacted.slice(0, MAX_LOGGED_ARGS)}…[truncated]`;
  try {
    return JSON.parse(redacted) as unknown;
  } catch {
    return redacted;
  }
}
