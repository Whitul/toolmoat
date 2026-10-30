import path from 'node:path';
import { PROXY_BOOLEAN_FLAGS, PROXY_VALUE_FLAGS } from '../clients/configs.js';
import { SECRET_PATTERNS } from '../patterns/secrets.js';
import { TAINT_ID } from '../proxy/egress.js';
import { defaultLockPath } from '../proxy/lockfile.js';
import { deriveServerName, fileSafeName, formatCommand } from '../proxy/names.js';
import type { Mode, OnNew } from '../proxy/policy.js';
import { runProxy } from '../proxy/proxy.js';
import { toolmoatHome } from '../util/paths.js';

/** What --allow-secret accepts: every credential pattern, plus values tainted by a tool result. */
const ALLOWABLE_SECRETS: readonly string[] = [...SECRET_PATTERNS.map((p) => p.id), TAINT_ID];

export const help = `Usage: toolmoat proxy [options] -- <command> [args...]

Runs an MCP stdio server behind toolmoat's runtime firewall. Use it in your
MCP client config in place of the server command (toolmoat wrap does that).

  - Pins every tool definition (sha256) on first run and hides tools whose
    definition later changes (rug pulls) or that appear later, until you
    approve them.
  - Hides tools whose descriptions contain high or critical findings (tool
    poisoning, hidden instructions) from the model.
  - Blocks tool calls whose arguments contain credentials (egress guard).
  - Warns when a tool's output looks like prompt injection.
  - Keeps a JSONL audit log; argument values are not logged by default.

Options:
  --name <id>            Server id in the lockfile (default: derived from the command)
  --lock <file>          Lockfile (default: <toolmoat home>/lock.json, ~/.toolmoat or TOOLMOAT_HOME)
  --mode enforce|warn    enforce hides and blocks; warn only reports (default: enforce)
  --on-new block|allow   Tools that appear on an already pinned server (default: block)
  --allow-new <tool>     Pin this tool without holding it when it appears later, e.g.
                         one a server only lists once a token is set (repeatable;
                         whole name, case-sensitive; * matches any run of
                         characters, ? one character). Flagged tools are still held.
  --audit-log <file>     Audit log (default: <toolmoat home>/audit/<name>.jsonl)
  --no-audit             Do not write an audit log
  --log-args             Also log tool-call arguments, with secrets redacted
  --allow-secret <id>    Let one credential type through the egress guard (repeatable).
                         Ids: ${ALLOWABLE_SECRETS.join(', ')}
                         (${TAINT_ID}: values an earlier tool result returned as a secret)
  -h, --help             Show this help (only before --)

Examples:
  toolmoat proxy -- npx -y @modelcontextprotocol/server-filesystem ~/projects
  toolmoat proxy --name demo -- node examples/rugpull-server.mjs

Held tools: toolmoat pins, toolmoat diff <name>, toolmoat approve <name>`;

export class UsageError extends Error {
  override name = 'UsageError';
}

export interface ProxyArgs {
  help: boolean;
  name?: string;
  lock?: string;
  mode: Mode;
  onNew: OnNew;
  auditLog?: string;
  noAudit: boolean;
  logArgs: boolean;
  allowSecrets: string[];
  /** Tool names or * ? patterns that may appear later without being held. */
  allowNew: string[];
  command?: string;
  args: string[];
}

const VALUE_FLAGS = PROXY_VALUE_FLAGS;
const BOOLEAN_FLAGS = new Set([...PROXY_BOOLEAN_FLAGS, '--help', '-h']);

/**
 * Parses proxy options up to `--` (or up to the first non-option word);
 * everything after belongs to the server command and is never interpreted.
 */
export function parseProxyArgs(argv: readonly string[]): ProxyArgs {
  const out: ProxyArgs = { help: false, mode: 'enforce', onNew: 'block', noAudit: false, logArgs: false, allowSecrets: [], allowNew: [], args: [] };
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i]!;
    if (token === '--' || !token.startsWith('-') || token === '-') {
      const start = token === '--' ? i + 1 : i;
      out.command = argv[start];
      out.args = argv.slice(start + 1);
      break;
    }
    const eq = token.startsWith('--') ? token.indexOf('=') : -1;
    const flag = eq === -1 ? token : token.slice(0, eq);
    if (BOOLEAN_FLAGS.has(flag)) {
      if (eq !== -1) throw new UsageError(`${flag} does not take a value`);
      if (flag === '--help' || flag === '-h') out.help = true;
      else if (flag === '--no-audit') out.noAudit = true;
      else out.logArgs = true;
      continue;
    }
    if (!VALUE_FLAGS.has(flag)) throw new UsageError(`unknown option ${flag}`);
    const value = eq === -1 ? argv[++i] : token.slice(eq + 1);
    if (value === undefined || value === '') throw new UsageError(`${flag} needs a value`);
    applyValue(out, flag, value);
  }
  return out;
}

function applyValue(out: ProxyArgs, flag: string, value: string): void {
  switch (flag) {
    case '--name':
      if (/[\u0000-\u001f\u007f]/.test(value) || value.length > 200) throw new UsageError('--name must be at most 200 printable characters');
      out.name = value;
      break;
    case '--lock':
      out.lock = value;
      break;
    case '--mode':
      if (value !== 'enforce' && value !== 'warn') throw new UsageError(`--mode must be enforce or warn, not ${value}`);
      out.mode = value;
      break;
    case '--on-new':
      if (value !== 'block' && value !== 'allow') throw new UsageError(`--on-new must be block or allow, not ${value}`);
      out.onNew = value;
      break;
    case '--allow-new':
      if (/[\u0000-\u001f\u007f]/.test(value) || value.length > 200) throw new UsageError('--allow-new must be at most 200 printable characters');
      out.allowNew.push(value);
      break;
    case '--audit-log':
      out.auditLog = value;
      break;
    case '--allow-secret':
      if (!ALLOWABLE_SECRETS.includes(value)) {
        throw new UsageError(`unknown secret pattern '${value}' for --allow-secret; known ids: ${ALLOWABLE_SECRETS.join(', ')}`);
      }
      out.allowSecrets.push(value);
      break;
  }
}

export async function run(argv: string[]): Promise<number> {
  let parsed: ProxyArgs;
  try {
    parsed = parseProxyArgs(argv);
  } catch (error) {
    process.stderr.write(`toolmoat proxy: ${error instanceof Error ? error.message : String(error)}\nRun toolmoat proxy --help for usage.\n`);
    return 2;
  }
  if (parsed.help) {
    process.stdout.write(`${help}\n`);
    return 0;
  }
  if (parsed.command === undefined || parsed.command === '') {
    process.stderr.write('toolmoat proxy: missing the server command, e.g. toolmoat proxy -- npx -y some-mcp-server\n');
    return 2;
  }
  const name = parsed.name ?? deriveServerName(parsed.command, parsed.args);
  const auditPath = parsed.noAudit ? undefined : path.resolve(parsed.auditLog ?? path.join(toolmoatHome(), 'audit', `${fileSafeName(name)}.jsonl`));
  const code = await runProxy({
    server: name,
    commandLine: formatCommand(parsed.command, parsed.args),
    lockPath: path.resolve(parsed.lock ?? defaultLockPath()),
    mode: parsed.mode,
    onNew: parsed.onNew,
    allowNew: parsed.allowNew,
    allowSecrets: parsed.allowSecrets,
    logArgs: parsed.logArgs,
    command: parsed.command,
    args: parsed.args,
    ...(auditPath ? { auditPath } : {}),
  });
  // A grandchild that inherited a handle must not keep the proxy alive after the server is gone.
  setTimeout(() => process.exit(code), 500).unref();
  return code;
}
