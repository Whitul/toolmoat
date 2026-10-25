#!/usr/bin/env node
import { VERSION } from './version.js';

interface CommandModule {
  run(argv: string[]): Promise<number>;
  help: string;
}

interface CommandEntry {
  summary: string;
  load: () => Promise<CommandModule>;
}

const COMMANDS: Record<string, CommandEntry> = {
  scan: {
    summary: 'Scan skills, plugins, hooks and MCP configs for malicious or risky content',
    load: () => import('./commands/scan.js'),
  },
  proxy: {
    summary: 'Run an MCP server behind the runtime firewall (tool pinning, egress guard, audit log)',
    load: () => import('./commands/proxy.js'),
  },
  wrap: {
    summary: 'Route the stdio MCP servers in your client configs through the proxy',
    load: () => import('./commands/wrap.js'),
  },
  unwrap: {
    summary: 'Undo wrap and restore the original server commands',
    load: () => import('./commands/unwrap.js'),
  },
  pins: {
    summary: 'List pinned MCP servers and any pending tool changes',
    load: () => import('./commands/pins.js'),
  },
  diff: {
    summary: 'Show what changed in a server\'s tools since they were pinned',
    load: () => import('./commands/diff.js'),
  },
  approve: {
    summary: 'Accept pending tool changes for a server and update its pins',
    load: () => import('./commands/approve.js'),
  },
  rules: {
    summary: 'List every detection rule',
    load: () => import('./commands/rules.js'),
  },
};

function usage(): string {
  const width = Math.max(...Object.keys(COMMANDS).map((name) => name.length));
  const lines = Object.entries(COMMANDS).map(([name, entry]) => `  ${name.padEnd(width)}  ${entry.summary}`);
  return [
    `toolmoat ${VERSION} - local-first security for AI agent skills, plugins, hooks and MCP servers`,
    '',
    'Usage: toolmoat <command> [options]',
    '',
    'Commands:',
    ...lines,
    '',
    'Run `toolmoat <command> --help` for command options.',
  ].join('\n');
}

export async function main(argv: string[]): Promise<number> {
  const [name, ...rest] = argv;
  if (name === undefined || name === '-h' || name === '--help' || name === 'help') {
    process.stdout.write(`${usage()}\n`);
    return 0;
  }
  if (name === '-v' || name === '--version') {
    process.stdout.write(`${VERSION}\n`);
    return 0;
  }
  const entry = COMMANDS[name];
  if (!entry) {
    process.stderr.write(`toolmoat: unknown command '${name}'\n\n${usage()}\n`);
    return 2;
  }
  const command = await entry.load();
  if (name !== 'proxy' && (rest.includes('-h') || rest.includes('--help'))) {
    process.stdout.write(`${command.help}\n`);
    return 0;
  }
  return command.run(rest);
}

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (error: unknown) => {
    process.stderr.write(`toolmoat: ${error instanceof Error ? error.message : String(error)}\n`);
    if (process.env.TOOLMOAT_DEBUG) console.error(error);
    process.exitCode = 2;
  },
);
