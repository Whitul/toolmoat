import { spawn } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import { AuditLog } from './audit.js';
import type { ProxyOptions, Routed } from './firewall.js';
import { Firewall } from './firewall.js';
import type { Line } from './framing.js';
import { LineDecoder } from './framing.js';
import { redactCommandLine } from './names.js';
import { killServer, planSpawn } from './spawn.js';

export type { ProxyOptions } from './firewall.js';

export interface RunProxyOptions extends ProxyOptions {
  /** The server executable as written in the client config, e.g. "npx". */
  command: string;
  args: readonly string[];
  /** JSONL audit log; undefined disables auditing. */
  auditPath?: string;
}

const NEWLINE = Buffer.from('\n');
/** How long the server may keep running after the client closed stdin. */
const STDIN_EOF_GRACE_MS = 5000;
/** How long to wait for the server's last output after it exited. */
const DRAIN_AFTER_EXIT_MS = 1500;
const LOCK_POLL_MS = 1000;

/** Writes one prefixed diagnostic line to stderr, the only place toolmoat may talk while proxying. */
export function stderrDiag(message: string): void {
  try {
    process.stderr.write(`[toolmoat] ${message}\n`);
  } catch {
    // stderr is gone; nothing else to try.
  }
}

/**
 * Runs an MCP stdio server behind the firewall: spawns it, pumps
 * newline-delimited JSON-RPC between this process's stdio and the server's,
 * and resolves with the exit code to use (the server's own, or 1 when it
 * could not start). stdout carries protocol messages only.
 */
export async function runProxy(options: RunProxyOptions): Promise<number> {
  const diag = options.diag ?? stderrDiag;
  const audit = options.auditPath ? new AuditLog(options.auditPath, options.server, diag) : undefined;
  let firewall: Firewall;
  try {
    firewall = new Firewall({ ...options, diag, audit });
  } catch (error) {
    diag(`${errorMessage(error)}. Fix or delete the lockfile; refusing to start '${options.server}' unverified.`);
    await audit?.close();
    return 1;
  }
  const plan = planSpawn(options.command, options.args, { platform: process.platform, env: process.env, cwd: process.cwd() });
  if ('error' in plan) {
    diag(`could not start MCP server '${options.server}': ${plan.error}`);
    await audit?.close();
    return 1;
  }
  audit?.write({ event: 'start', decision: options.mode ?? 'enforce', detail: redactCommandLine(options.commandLine) });
  let child: ChildProcess;
  try {
    child = spawn(plan.file, plan.args, {
      stdio: ['pipe', 'pipe', 'inherit'],
      env: process.env,
      windowsHide: true,
      windowsVerbatimArguments: plan.windowsVerbatimArguments,
    });
  } catch (error) {
    diag(`could not start MCP server '${options.server}': ${errorMessage(error)}`);
    await audit?.close();
    return 1;
  }
  return supervise(child, firewall, audit, diag, options);
}

function supervise(child: ChildProcess, firewall: Firewall, audit: AuditLog | undefined, diag: (m: string) => void, options: RunProxyOptions): Promise<number> {
  const clientIn = process.stdin;
  const clientOut = process.stdout;
  const serverIn = child.stdin!;
  const serverOut = child.stdout!;
  const fromClient = new LineDecoder();
  const fromServer = new LineDecoder();

  return new Promise<number>((resolve) => {
    let finished = false;
    let signals = 0;
    let graceTimer: NodeJS.Timeout | undefined;
    let clientPaused = false;
    let serverPaused = false;

    const toServer = (chunks: Buffer[]): void => {
      if (chunks.length === 0 || serverIn.destroyed || serverIn.writableEnded) return;
      if (!serverIn.write(Buffer.concat(chunks)) && !clientPaused) {
        clientPaused = true;
        clientIn.pause();
        serverIn.once('drain', () => {
          clientPaused = false;
          clientIn.resume();
        });
      }
    };

    const toClient = (chunks: Buffer[]): void => {
      if (chunks.length === 0 || clientOut.destroyed) return;
      if (!clientOut.write(Buffer.concat(chunks)) && !serverPaused) {
        serverPaused = true;
        serverOut.pause();
        clientOut.once('drain', () => {
          serverPaused = false;
          serverOut.resume();
        });
      }
    };

    const route = (lines: Line[], from: 'client' | 'server'): void => {
      const onward: Buffer[] = [];
      const back: Buffer[] = [];
      for (const line of lines) {
        const routed = safeRoute(firewall, line.text, from, options.mode ?? 'enforce', diag);
        if (routed.passOriginal) onward.push(line.raw, NEWLINE);
        for (const text of routed.onward) onward.push(Buffer.from(`${text}\n`, 'utf8'));
        for (const text of routed.back) back.push(Buffer.from(`${text}\n`, 'utf8'));
      }
      if (from === 'client') {
        toServer(onward);
        toClient(back);
      } else {
        toClient(onward);
        toServer(back);
      }
    };

    const onClientData = (chunk: Buffer): void => route(fromClient.push(chunk), 'client');
    const onClientEnd = (): void => {
      const last = fromClient.flush();
      if (last) route([last], 'client');
      if (!serverIn.destroyed) serverIn.end();
      graceTimer ??= setTimeout(() => killServer(child), STDIN_EOF_GRACE_MS);
    };
    clientIn.on('data', onClientData);
    clientIn.once('end', onClientEnd);
    clientIn.once('error', onClientEnd);

    serverOut.on('data', (chunk: Buffer) => route(fromServer.push(chunk), 'server'));
    serverOut.once('end', () => {
      const last = fromServer.flush();
      if (last) route([last], 'server');
    });
    serverIn.on('error', () => {
      // EPIPE once the server has exited; its exit is handled below.
    });
    clientOut.on('error', () => {
      diag('the MCP client closed stdout; stopping the server');
      killServer(child);
    });

    const onLockChange = (current: fs.Stats, previous: fs.Stats): void => {
      if (current.mtimeMs === previous.mtimeMs && current.size === previous.size) return;
      const lines = firewall.lockChanged();
      toClient(lines.map((text) => Buffer.from(`${text}\n`, 'utf8')));
    };
    fs.watchFile(options.lockPath, { interval: LOCK_POLL_MS, persistent: false }, onLockChange);

    const onSignal = (signal: NodeJS.Signals): void => {
      signals++;
      if (process.platform === 'win32' || signals > 1) killServer(child);
      else child.kill(signal);
    };
    const signalNames: NodeJS.Signals[] = process.platform === 'win32' ? ['SIGINT', 'SIGTERM'] : ['SIGINT', 'SIGTERM', 'SIGHUP'];
    for (const name of signalNames) process.on(name, onSignal);
    const onProcessExit = (): void => killServer(child);
    process.on('exit', onProcessExit);

    const finish = async (code: number): Promise<void> => {
      if (finished) return;
      finished = true;
      if (graceTimer) clearTimeout(graceTimer);
      fs.unwatchFile(options.lockPath, onLockChange);
      for (const name of signalNames) process.off(name, onSignal);
      clientIn.off('data', onClientData);
      clientIn.pause();
      clientIn.destroy();
      audit?.write({ event: 'exit', code });
      await withTimeout(firewall.idle(), 1000);
      await audit?.close();
      await withTimeout(new Promise<void>((done) => clientOut.write('', () => done())), 1000);
      process.off('exit', onProcessExit);
      resolve(code);
    };

    child.once('error', (error) => {
      if (child.pid !== undefined) return;
      diag(`could not start MCP server '${options.server}': ${errorMessage(error)}`);
      void finish(1);
    });
    child.once('exit', (code, signal) => {
      const exitCode = code ?? signalExitCode(signal);
      if (serverOut.readableEnded || serverOut.destroyed) {
        void finish(exitCode);
        return;
      }
      const timer = setTimeout(() => void finish(exitCode), DRAIN_AFTER_EXIT_MS);
      serverOut.once('close', () => {
        clearTimeout(timer);
        void finish(exitCode);
      });
    });
  });
}

/** Routes one line, failing closed in enforce mode if the firewall itself throws. */
function safeRoute(firewall: Firewall, text: string, from: 'client' | 'server', mode: string, diag: (m: string) => void): Routed {
  try {
    return from === 'client' ? firewall.fromClient(text) : firewall.fromServer(text);
  } catch (error) {
    diag(`internal error while checking a message from the ${from}: ${errorMessage(error)}; ${mode === 'enforce' ? 'dropping it' : 'forwarding it'}`);
    return { passOriginal: mode !== 'enforce', onward: [], back: [] };
  }
}

function signalExitCode(signal: NodeJS.Signals | null): number {
  if (!signal) return 1;
  const number = os.constants.signals[signal];
  return typeof number === 'number' ? 128 + number : 1;
}

function withTimeout(promise: Promise<void>, ms: number): Promise<void> {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, ms);
    timer.unref();
    promise.then(
      () => {
        clearTimeout(timer);
        resolve();
      },
      () => {
        clearTimeout(timer);
        resolve();
      },
    );
  });
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
