import { runMcpServer } from '../mcp/server.js';
import { VERSION } from '../version.js';

export const help = `Usage: toolmoat mcp

Runs toolmoat as an MCP server on stdin/stdout, so an agent can scan skills,
plugins, hooks and MCP configs itself before installing or enabling them.

Tools: scan_path, scan_installed, scan_text, list_rules, list_pins.

Everything is read-only and offline: the server never writes files, never
makes network requests and never runs scanned code. No .toolmoatignore is
applied, because the working directory may itself be an untrusted download.
There is no tool to approve pinned tool changes; that stays with you, in a
terminal, via toolmoat approve.

Set TOOLMOAT_DEBUG=1 to log diagnostics to stderr.

Add it to Claude Code:
  claude mcp add toolmoat -- npx -y toolmoat@${VERSION} mcp`;

export async function run(argv: string[]): Promise<number> {
  const extra = argv.find((arg) => arg !== '-h' && arg !== '--help');
  if (extra !== undefined) {
    process.stderr.write(`toolmoat mcp: unexpected argument '${extra}'\nRun 'toolmoat mcp --help' for usage.\n`);
    return 2;
  }
  return runMcpServer();
}
