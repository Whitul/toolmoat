import fs from 'node:fs';
import path from 'node:path';
import { afterAll, describe, expect, it, vi } from 'vitest';
import { backupPath, originalLaunch, readJsonConfig, readTomlServers, serializeLike, splitWrapped, writeJsonConfig } from '../src/clients/configs.js';
import { isProxyName, launcherFor, scopedName, wrapLaunch } from '../src/commands/wrap.js';
import { VERSION } from '../src/version.js';
import { CLI, FIXTURES, runCli, tempDir } from './helpers.js';

const temps: string[] = [];

afterAll(() => {
  for (const dir of temps) fs.rmSync(dir, { recursive: true, force: true });
});

/** A private copy of the fixture home and project, with env vars pointing every client path at it. */
function sandbox() {
  // The real path: wrap resolves relative options against process.cwd(), which the OS reports without
  // symlinks (macOS keeps os.tmpdir() under the /var -> /private/var link).
  const tmp = fs.realpathSync(tempDir('toolmoat-wrap-'));
  temps.push(tmp);
  const home = path.join(tmp, 'home');
  const project = path.join(tmp, 'project');
  fs.cpSync(path.join(FIXTURES, 'discover', 'home'), home, { recursive: true });
  fs.cpSync(path.join(FIXTURES, 'discover', 'project'), project, { recursive: true });
  const appdata = path.join(home, 'appdata');
  const appRoot = process.platform === 'darwin' ? path.join(home, 'Library', 'Application Support') : appdata;
  if (appRoot !== appdata) fs.cpSync(appdata, appRoot, { recursive: true });
  const env = { TOOLMOAT_TEST_USER_HOME: home, APPDATA: appdata, XDG_CONFIG_HOME: appdata, TOOLMOAT_HOME: path.join(tmp, 'toolmoat') };
  const paths = {
    desktop: path.join(appRoot, 'Claude', 'claude_desktop_config.json'),
    vscode: path.join(appRoot, 'Code', 'User', 'mcp.json'),
    claude: path.join(home, '.claude.json'),
    cursor: path.join(home, '.cursor', 'mcp.json'),
    windsurf: path.join(home, '.codeium', 'windsurf', 'mcp_config.json'),
    gemini: path.join(home, '.gemini', 'settings.json'),
    codex: path.join(home, '.codex', 'config.toml'),
    projectMcp: path.join(project, '.mcp.json'),
  };
  const original = Object.fromEntries(Object.entries(paths).map(([key, file]) => [key, fs.readFileSync(file, 'utf8')])) as Record<keyof typeof paths, string>;
  const cli = (...args: string[]) => runCli(args, { cwd: project, env });
  return { tmp, home, project, paths, original, cli };
}

type Json = Record<string, any>;

function readJson(file: string): Json {
  return JSON.parse(fs.readFileSync(file, 'utf8')) as Json;
}

const sameFile = (a: string, b: string) => (process.platform === 'win32' ? a.toLowerCase() === b.toLowerCase() : a === b);

/** Checks a wrapped entry: node + the built cli.js, proxy, --name, then the original command line after --. */
function expectWrapped(server: Json, name: string, original: string[]): void {
  expect(server.command).toBe(process.execPath);
  expect(sameFile(server.args[0], CLI), `${server.args[0]} vs ${CLI}`).toBe(true);
  expect(server.args.slice(1)).toEqual(['proxy', '--name', name, '--', ...original]);
}

describe('wrap helpers', () => {
  it('launches through node and the running cli.js, or through npx from the npx cache', () => {
    expect(launcherFor('/usr/lib/node_modules/toolmoat/dist/cli.js', '/usr/bin/node')).toEqual({
      command: '/usr/bin/node',
      prefix: ['/usr/lib/node_modules/toolmoat/dist/cli.js'],
    });
    const npx = { command: 'npx', prefix: ['-y', `toolmoat@${VERSION}`] };
    expect(launcherFor('/home/u/.npm/_npx/0a1b/node_modules/toolmoat/dist/cli.js', '/usr/bin/node')).toEqual(npx);
    expect(launcherFor('C:\\Users\\u\\AppData\\Local\\npm-cache\\_npx\\0a1b\\node_modules\\toolmoat\\dist\\cli.js', 'node.exe')).toEqual(npx);
  });

  it('builds the wrapped command line with proxy options before --', () => {
    const launch = wrapLaunch('db', { command: 'uvx', args: ['mcp-db'] }, { command: 'node', prefix: ['/x/cli.js'] }, { lock: '/l.lock', mode: 'warn' });
    expect(launch).toEqual({ command: 'node', args: ['/x/cli.js', 'proxy', '--name', 'db', '--lock', '/l.lock', '--mode', 'warn', '--', 'uvx', 'mcp-db'] });
  });

  it('recognises only command lines written by wrap', () => {
    expect(splitWrapped('node', ['/x/dist/cli.js', 'proxy', '--name', 'a', '--', 'npx', '-y', 'pkg'])).toEqual(['npx', '-y', 'pkg']);
    expect(splitWrapped('npx', ['-y', 'toolmoat@1.2.3', 'proxy', '--name', 'a', '--mode', 'warn', '--', 'uvx', 'x'])).toEqual(['uvx', 'x']);
    expect(splitWrapped('C:\\bin\\toolmoat.cmd', ['proxy', '--name', 'a', '--', 'srv'])).toEqual(['srv']);
    expect(splitWrapped('node', ['/x/cli.js', 'proxy', '--name', '--', '--', 'srv'])).toEqual(['srv']);
    expect(splitWrapped('node', ['/x/cli.js', 'serve', '--', 'srv'])).toBeNull();
    expect(splitWrapped('npx', ['-y', 'http-proxy', 'proxy', '--', 'srv'])).toBeNull();
    expect(splitWrapped('node', ['/x/cli.js', 'proxy', '--name', 'a'])).toBeNull();
    expect(splitWrapped('node', ['/x/cli.js', 'proxy', '--audit-log', '--', '--', 'srv'])).toEqual(['srv']);
    // Only toolmoat proxy options may stand between "proxy" and "--": another tool's own cli.js is not a wrapped server.
    expect(splitWrapped('node', ['tool/cli.js', 'proxy', '--stdio', '--', 'upstream'])).toBeNull();
    expect(splitWrapped('node', ['tool/cli.js', 'proxy', 'extra', '--', 'upstream'])).toBeNull();
    expect(splitWrapped('npx', ['-y', 'toolmoat', 'proxy', '--bogus', '--', 'srv'])).toBeNull();
    expect(splitWrapped('node', ['/x/cli.js', 'proxy', '--name=a', '--no-audit', '--log-args', '--allow-secret', 'aws-access-key', '--', 'srv'])).toEqual(['srv']);
    expect(originalLaunch({ command: 'node', args: ['/x/cli.js', 'proxy', '--'] })).toBeNull();
    expect(originalLaunch({ command: 'npx', args: ['-y', 'toolmoat@0.0.9', 'proxy', '--name', 'a', '--', 'srv', '--flag'] })).toEqual({
      command: 'srv',
      args: ['--flag'],
    });
  });

  it('reads Codex server tables, including quoted names and multi-line arrays', () => {
    const servers = readTomlServers(fs.readFileSync(path.join(FIXTURES, 'discover', 'home', '.codex', 'config.toml'), 'utf8'));
    expect(servers.map(({ name, command, args, url }) => ({ name, command, args, url }))).toEqual([
      { name: 'context7', command: 'npx', args: ['-y', '@upstash/context7-mcp'], url: undefined },
      { name: 'local tools', command: 'C:\\tools\\mcp.exe', args: ['--stdio', '--verbose'], url: undefined },
      { name: 'remote-docs', command: undefined, args: undefined, url: 'https://docs.example.invalid/mcp' },
    ]);
    expect(servers.map((s) => s.header)).toEqual(['[mcp_servers.context7]', '[mcp_servers."local tools"]', '[mcp_servers.remote-docs]']);
    expect(servers.every((s) => s.unparsed === undefined)).toBe(true);
  });

  it('marks Codex servers it cannot replace by pasting a table', () => {
    const text = [
      '[mcp_servers]',
      'dotted.command = "npx"',
      'inline = { command = "uvx", args = ["tool"] }',
      '',
      '[mcp_servers.numbers]',
      'command = "srv"',
      'args = [1, 2]',
      '',
    ].join('\n');
    const byName = new Map(readTomlServers(text).map((s) => [s.name, s]));
    expect(byName.get('dotted')!.unparsed).toMatch(/inline or with dotted keys/);
    expect(byName.get('inline')!.unparsed).toMatch(/inline or with dotted keys/);
    expect(byName.get('numbers')).toMatchObject({ header: '[mcp_servers.numbers]', line: 5, command: 'srv', unparsed: 'args is not a list of strings' });
  });

  it('accepts only the server names the proxy accepts', () => {
    expect(['filesystem', 'my server', 'café 😀', 'x'.repeat(200)].map(isProxyName)).toEqual([true, true, true, true]);
    expect(['', 'x'.repeat(201), 'a\u0001b', 'a\nb', 'a\u007fb'].map(isProxyName)).toEqual([false, false, false, false, false]);
  });

  it('serializes with the original formatting', () => {
    expect(serializeLike({ a: [1] }, '{\r\n\t"a": []\r\n}\r\n')).toBe('{\r\n\t"a": [\r\n\t\t1\r\n\t]\r\n}\r\n');
    expect(serializeLike({ a: 1 }, '\uFEFF{"a":0}')).toBe('\uFEFF{"a":1}');
    expect(serializeLike({ a: 1 }, '{\n    "a": 0\n}')).toBe('{\n    "a": 1\n}');
  });
});

describe('toolmoat wrap and unwrap', () => {
  it('wraps every stdio server in the user-level configs and leaves everything else alone', () => {
    const box = sandbox();
    const result = box.cli('wrap');
    expect(result.status, result.stderr + result.stdout).toBe(0);

    const desktop = readJson(box.paths.desktop);
    expectWrapped(desktop.mcpServers.filesystem, 'claude-desktop.filesystem', ['npx', '-y', '@modelcontextprotocol/server-filesystem', '/home/dev/Documents']);
    expectWrapped(desktop.mcpServers['local-binary'], 'claude-desktop.local-binary', ['/opt/mcp/bin/local-mcp']);
    expect(desktop.mcpServers['local-binary'].env).toEqual({ LOG_LEVEL: 'info' });
    expectWrapped(desktop.mcpServers['empty-args'], 'claude-desktop.empty-args', ['local-tool']);
    expect(desktop.mcpServers['remote-notes']).toEqual({ url: 'https://notes.example.invalid/sse' });
    expect(desktop.globalShortcut).toBe('Ctrl+Space');

    const claude = readJson(box.paths.claude);
    const originalClaude = JSON.parse(box.original.claude) as Json;
    expectWrapped(claude.mcpServers.memory, 'claude-code-user.memory', ['npx', '-y', '@modelcontextprotocol/server-memory']);
    expect(claude.mcpServers.memory).toMatchObject({ type: 'stdio', env: {} });
    expect(claude.mcpServers['docs-search']).toEqual(originalClaude.mcpServers['docs-search']);
    const sqlite = claude.projects['/home/dev/app'].mcpServers.sqlite;
    expectWrapped(sqlite, 'claude-code-user.app.sqlite', ['uvx', 'mcp-server-sqlite', '--db-path', '/home/dev/app/data.db']);
    expect(claude.projects['/home/dev/app'].hasTrustDialogAccepted).toBe(true);
    expect(claude.numStartups).toBe(12);

    const cursor = readJson(box.paths.cursor);
    expectWrapped(cursor.mcpServers.github, 'cursor-user.github', ['docker', 'run', '-i', '--rm', '-e', 'GITHUB_PERSONAL_ACCESS_TOKEN', 'ghcr.io/github/github-mcp-server']);
    expect(cursor.mcpServers.github.env).toEqual({ GITHUB_PERSONAL_ACCESS_TOKEN: '${env:GITHUB_TOKEN}' });

    const vscode = readJson(box.paths.vscode);
    expectWrapped(vscode.servers.fetch, 'vscode-user.fetch', ['uvx', 'mcp-server-fetch']);
    expect(vscode.servers.fetch.type).toBe('stdio');
    expect(vscode.servers['remote-api']).toEqual({ type: 'http', url: 'https://api.example.invalid/mcp' });
    expect(vscode.inputs).toHaveLength(1);

    expectWrapped(readJson(box.paths.windsurf).mcpServers.time, 'windsurf.time', ['uvx', 'mcp-server-time']);
    const gemini = readJson(box.paths.gemini).mcpServers.weather;
    expectWrapped(gemini, 'gemini-user.weather', ['node', '/home/dev/weather/index.js']);
    expect(gemini.cwd).toBe('/home/dev/weather');

    expect(fs.readFileSync(box.paths.projectMcp, 'utf8')).toBe(box.original.projectMcp);
    expect(fs.readFileSync(box.paths.codex, 'utf8')).toBe(box.original.codex);
    expect(result.stdout).toContain('Project configs left alone');
    expect(result.stdout).toContain('[mcp_servers.context7]');
    expect(result.stdout).toContain(`'proxy', '--name', 'codex.context7', '--', 'npx', '-y', '@upstash/context7-mcp'`);
    expect(result.stdout).toContain('remote (url) server');
    expect(result.stdout).toMatch(/Wrapped 9 servers in 6 configs/);
    expect(result.stdout).toMatch(/Restart .*Claude Desktop/);

    for (const key of ['desktop', 'claude', 'cursor', 'vscode', 'windsurf', 'gemini'] as const) {
      expect(fs.readFileSync(`${box.paths[key]}.toolmoat.bak`, 'utf8'), key).toBe(box.original[key]);
    }
    expect(fs.existsSync(`${box.paths.projectMcp}.toolmoat.bak`)).toBe(false);
  });

  it('is idempotent and unwrap restores every config byte for byte', () => {
    const box = sandbox();
    expect(box.cli('wrap').status).toBe(0);
    const keys = ['desktop', 'claude', 'cursor', 'vscode', 'windsurf', 'gemini'] as const;
    const afterFirst = keys.map((key) => fs.readFileSync(box.paths[key], 'utf8'));

    const second = box.cli('wrap');
    expect(second.status).toBe(0);
    expect(second.stdout).toContain('already wrapped');
    expect(second.stdout).toContain('Nothing to wrap in the JSON configs.');
    expect(second.stdout).toContain('Project configs left alone');
    expect(second.stdout).toMatch(/^ {2}Claude Code \(project \.mcp\.json\) {2}\.mcp\.json$/m);
    expect(keys.map((key) => fs.readFileSync(box.paths[key], 'utf8'))).toEqual(afterFirst);

    const unwrap = box.cli('unwrap');
    expect(unwrap.status, unwrap.stderr + unwrap.stdout).toBe(0);
    expect(unwrap.stdout).toMatch(/Unwrapped 9 servers in 6 configs/);
    for (const key of keys) {
      expect(fs.readFileSync(box.paths[key], 'utf8'), key).toBe(box.original[key]);
      expect(fs.readFileSync(`${box.paths[key]}.toolmoat.bak`, 'utf8'), key).toBe(box.original[key]);
    }
    expect(box.cli('unwrap').stdout).toContain('Nothing to unwrap.');
  });

  it('writes nothing with --dry-run', () => {
    const box = sandbox();
    const result = box.cli('wrap', '--dry-run');
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('would wrap');
    expect(result.stdout).toMatch(/Dry run: would wrap 9 servers in 6 configs\. Nothing was written\./);
    for (const [key, file] of Object.entries(box.paths)) {
      expect(fs.readFileSync(file, 'utf8'), key).toBe(box.original[key as keyof typeof box.original]);
      expect(fs.existsSync(`${file}.toolmoat.bak`), key).toBe(false);
    }
  });

  it('refuses to rewrite a config with comments unless --force is given', () => {
    const box = sandbox();
    const withComment = box.original.vscode.replace('{\n', '{\n  // my servers\n');
    fs.writeFileSync(box.paths.vscode, withComment);

    const refused = box.cli('wrap', '--client', 'vscode');
    expect(refused.status).toBe(1);
    expect(refused.stdout).toMatch(/comments.*--force/);
    expect(fs.readFileSync(box.paths.vscode, 'utf8')).toBe(withComment);
    expect(fs.existsSync(`${box.paths.vscode}.toolmoat.bak`)).toBe(false);

    const forced = box.cli('wrap', '--client', 'VS Code', '--force');
    expect(forced.status).toBe(0);
    expectWrapped(readJson(box.paths.vscode).servers.fetch, 'vscode-user.fetch', ['uvx', 'mcp-server-fetch']);
    expect(fs.readFileSync(`${box.paths.vscode}.toolmoat.bak`, 'utf8')).toBe(withComment);
    expect(fs.readFileSync(box.paths.desktop, 'utf8')).toBe(box.original.desktop);
  });

  it('passes --lock and --mode to the proxy and wraps a project config named with --config', () => {
    const box = sandbox();
    const result = box.cli('wrap', '--config', '.mcp.json', '--lock', 'pins.lock', '--mode', 'warn');
    expect(result.status, result.stderr + result.stdout).toBe(0);
    expect(result.stdout).toContain('usually committed');
    const server = readJson(box.paths.projectMcp).mcpServers['project-db'];
    expect(server.command).toBe(process.execPath);
    expect(server.args.slice(1)).toEqual(['proxy', '--name', 'claude-code-project.project-db', '--lock', path.join(box.project, 'pins.lock'), '--mode', 'warn', '--', 'npx', '-y', '@example/db-mcp']);
    expect(fs.readFileSync(box.paths.cursor, 'utf8')).toBe(box.original.cursor);

    expect(box.cli('unwrap', '--config', '.mcp.json').status).toBe(0);
    expect(fs.readFileSync(box.paths.projectMcp, 'utf8')).toBe(box.original.projectMcp);
  });

  it('points wrapped servers whose node or cli.js is gone at this install, keeping their proxy options', () => {
    const box = sandbox();
    const stale = ['/gone/node-v18/lib/node_modules/toolmoat/dist/cli.js', 'proxy', '--name', 'time', '--mode', 'warn', '--', 'uvx', 'mcp-server-time'];
    const config = JSON.parse(box.original.windsurf) as Json;
    config.mcpServers.time = { command: '/gone/node-v18/bin/node', args: stale };
    fs.writeFileSync(box.paths.windsurf, `${JSON.stringify(config, null, 2)}\n`);

    const result = box.cli('wrap', '--client', 'windsurf');
    expect(result.status, result.stderr + result.stdout).toBe(0);
    expect(result.stdout).toContain('no longer exists; launcher updated');
    const time = readJson(box.paths.windsurf).mcpServers.time;
    expect(time.command).toBe(process.execPath);
    expect(sameFile(time.args[0], CLI)).toBe(true);
    expect(time.args.slice(1)).toEqual(stale.slice(1));
    expect(box.cli('wrap', '--client', 'windsurf').stdout).toContain('already wrapped');

    expect(box.cli('unwrap', '--client', 'windsurf').status).toBe(0);
    expect(readJson(box.paths.windsurf).mcpServers.time).toEqual({ command: 'uvx', args: ['mcp-server-time'] });
  });

  it('prints the Codex lines to paste and unwraps them the same way', () => {
    const box = sandbox();
    const result = box.cli('wrap', '--client', 'codex');
    expect(result.status).toBe(0);
    expect(fs.readFileSync(box.paths.codex, 'utf8')).toBe(box.original.codex);
    expect(result.stdout).toContain('[mcp_servers."local tools"]');
    expect(result.stdout).toContain(`command = '${process.execPath}'`);
    expect(result.stdout).toContain(`'proxy', '--name', 'codex.local tools', '--', 'C:\\tools\\mcp.exe', '--stdio', '--verbose']`);
    expect(result.stdout).toMatch(/Codex: 2 servers to wrap by hand/);

    const wrappedToml = [
      '[mcp_servers.done]',
      `command = 'node'`,
      `args = ['/x/dist/cli.js', 'proxy', '--name', 'done', '--', 'npx', '-y', 'pkg']`,
      '',
    ].join('\n');
    fs.writeFileSync(box.paths.codex, wrappedToml);
    const unwrap = box.cli('unwrap', '--client', 'codex');
    expect(unwrap.status).toBe(0);
    expect(unwrap.stdout).toContain(`command = 'npx'`);
    expect(unwrap.stdout).toContain(`args = ['-y', 'pkg']`);
    expect(fs.readFileSync(box.paths.codex, 'utf8')).toBe(wrappedToml);

    fs.writeFileSync(box.paths.codex, '[mcp_servers]\ninline = { command = "uvx", args = ["tool"] }\n');
    const inline = box.cli('wrap', '--client', 'codex');
    expect(inline.status).toBe(0);
    expect(inline.stdout).toMatch(/skipped +inline .*edit it by hand/);
    expect(inline.stdout).toContain('Nothing to wrap.');
  });

  it('rejects bad usage with exit code 2 and missing files with exit code 1', () => {
    const box = sandbox();
    const unknown = box.cli('wrap', '--client', 'notepad');
    expect(unknown.status).toBe(2);
    expect(unknown.stderr).toContain("unknown client 'notepad'");
    expect(box.cli('wrap', '--mode', 'loud').status).toBe(2);
    expect(box.cli('wrap', '--bogus').status).toBe(2);
    expect(box.cli('wrap', 'positional').status).toBe(2);
    expect(box.cli('unwrap', '--lock', 'x.lock').status).toBe(2);
    const missing = box.cli('wrap', '--config', 'missing.json');
    expect(missing.status).toBe(1);
    expect(missing.stdout).toContain('file not found');
    expect(box.cli('wrap', '--help').stdout).toContain('Usage: toolmoat wrap');
  });

  it('exits 1 when no client config exists at all', () => {
    const tmp = tempDir('toolmoat-wrap-empty-');
    temps.push(tmp);
    const env = { TOOLMOAT_TEST_USER_HOME: tmp, APPDATA: path.join(tmp, 'appdata'), XDG_CONFIG_HOME: path.join(tmp, 'appdata') };
    const result = runCli(['wrap'], { cwd: tmp, env });
    expect(result.status).toBe(1);
    expect(result.stdout).toContain('No MCP client configs found');
  });

  it('round-trips awkward servers exactly and never touches remote or unwrapped ones', () => {
    const box = sandbox();
    const config = {
      mcpServers: {
        'args-first': { args: ['one', '--', 'proxy'], command: 'node' },
        spaced: {
          command: 'C:\\Program Files\\nodejs\\node.exe',
          args: ['C:\\Users\\J Doe\\srv.js', '', ' x ', '--name=café 😀', 'proxy', '--'],
          env: { A: '1', B: '${env:B}' },
          cwd: 'D:\\work dir',
        },
        'cli-lookalike': { command: 'node', args: ['tool/cli.js', 'proxy', '--stdio', '--', 'upstream'] },
        'no-args': { type: 'stdio', command: 'tool', env: { X: 'y' }, disabled: false },
        'café 😀': { command: 'uvx', args: ['mcp-server-time'] },
        'remote-url': { url: 'https://a.example.invalid/mcp' },
        'remote-server-url': { serverUrl: 'https://b.example.invalid/sse', headers: { A: 'b' } },
        'remote-http-url': { httpUrl: 'https://c.example.invalid/mcp' },
        'remote-sse': { type: 'sse', headers: {} },
      },
      other: { keep: [1, 2.5, null, true, { nested: 'ü\u2028' }] },
    };
    const text = `${JSON.stringify(config, null, 2)}\n`;
    fs.writeFileSync(box.paths.desktop, text);

    const untouched = box.cli('unwrap', '--client', 'claude-desktop');
    expect(untouched.status, untouched.stderr + untouched.stdout).toBe(0);
    expect(untouched.stdout).toContain('Nothing to unwrap.');
    expect(fs.readFileSync(box.paths.desktop, 'utf8')).toBe(text);
    expect(fs.existsSync(backupPath(box.paths.desktop))).toBe(false);

    const wrapped = box.cli('wrap', '--client', 'claude-desktop');
    expect(wrapped.status, wrapped.stderr + wrapped.stdout).toBe(0);
    const servers = readJson(box.paths.desktop).mcpServers;
    const { mcpServers } = config;
    expectWrapped(servers['args-first'], 'claude-desktop.args-first', ['node', 'one', '--', 'proxy']);
    expectWrapped(servers.spaced, 'claude-desktop.spaced', [mcpServers.spaced.command, ...mcpServers.spaced.args]);
    expect(servers.spaced.env).toEqual(mcpServers.spaced.env);
    expect(servers.spaced.cwd).toBe(mcpServers.spaced.cwd);
    expectWrapped(servers['cli-lookalike'], 'claude-desktop.cli-lookalike', ['node', 'tool/cli.js', 'proxy', '--stdio', '--', 'upstream']);
    expectWrapped(servers['no-args'], 'claude-desktop.no-args', ['tool']);
    expectWrapped(servers['café 😀'], 'claude-desktop.café 😀', ['uvx', 'mcp-server-time']);
    for (const name of ['remote-url', 'remote-server-url', 'remote-http-url', 'remote-sse'] as const) {
      expect(servers[name], name).toEqual(mcpServers[name]);
    }
    expect(readJson(box.paths.desktop).other).toEqual(config.other);

    const unwrapped = box.cli('unwrap', '--client', 'claude-desktop');
    expect(unwrapped.status, unwrapped.stderr + unwrapped.stdout).toBe(0);
    expect(fs.readFileSync(box.paths.desktop, 'utf8')).toBe(text);
    expect(fs.readFileSync(backupPath(box.paths.desktop), 'utf8')).toBe(text);
  });

  it('keeps the first backup when a config is wrapped again after later edits', () => {
    const box = sandbox();
    expect(box.cli('wrap', '--client', 'windsurf').status).toBe(0);
    expect(box.cli('unwrap', '--client', 'windsurf').status).toBe(0);
    const edited = JSON.parse(box.original.windsurf) as Json;
    edited.mcpServers.extra = { command: 'extra-server' };
    fs.writeFileSync(box.paths.windsurf, `${JSON.stringify(edited, null, 2)}\n`);
    expect(box.cli('wrap', '--client', 'windsurf').status).toBe(0);
    expect(fs.readFileSync(backupPath(box.paths.windsurf), 'utf8')).toBe(box.original.windsurf);
  });

  it('skips servers whose name the proxy would reject instead of breaking them', () => {
    const box = sandbox();
    const config = {
      mcpServers: {
        '': { command: 'empty-name' },
        'bad\u0001name': { command: 'control' },
        ['x'.repeat(201)]: { command: 'long-name' },
        fine: { command: 'fine-server' },
      },
    };
    fs.writeFileSync(box.paths.windsurf, `${JSON.stringify(config, null, 2)}\n`);
    const result = box.cli('wrap', '--client', 'windsurf');
    expect(result.status, result.stderr + result.stdout).toBe(0);
    expect(result.stdout.match(/name is empty, longer than 200 characters or has control characters/g)).toHaveLength(2);
    const servers = readJson(box.paths.windsurf).mcpServers;
    expectWrapped(servers.fine, 'windsurf.fine', ['fine-server']);
    expectWrapped(servers[''], 'windsurf.', ['empty-name']);
    expect(servers['bad\u0001name']).toEqual({ command: 'control' });
    expect(servers['x'.repeat(201)]).toEqual({ command: 'long-name' });
  });

  it('refuses to rewrite a file with a number that JSON cannot hold exactly', () => {
    const box = sandbox();
    const config = '{\n  "id": 12345678901234567890,\n  "mcpServers": {\n    "a": {\n      "command": "x"\n    }\n  }\n}\n';
    fs.writeFileSync(box.paths.windsurf, config);
    for (const flags of [[], ['--dry-run'], ['--force']]) {
      const result = box.cli('wrap', '--client', 'windsurf', ...flags);
      expect(result.status, flags.join(' ')).toBe(1);
      expect(result.stdout).toMatch(/12345678901234567890.*by hand/);
      expect(fs.readFileSync(box.paths.windsurf, 'utf8')).toBe(config);
      expect(fs.existsSync(backupPath(box.paths.windsurf))).toBe(false);
    }
    // Large integers that survive a parse and stringify unchanged are fine.
    const exact = config.replace('12345678901234567890', '18446744073709552000');
    fs.writeFileSync(box.paths.windsurf, exact);
    expect(box.cli('wrap', '--client', 'windsurf').status).toBe(0);
    expect(fs.readFileSync(box.paths.windsurf, 'utf8')).toContain('"id": 18446744073709552000');
  });

  it('gives same-named servers in different clients separate lockfile names', () => {
    const box = sandbox();
    const desktop = JSON.parse(box.original.desktop) as Json;
    desktop.mcpServers.github = { command: 'npx', args: ['-y', '@modelcontextprotocol/server-github'] };
    fs.writeFileSync(box.paths.desktop, `${JSON.stringify(desktop, null, 2)}\n`);
    const result = box.cli('wrap');
    expect(result.status, result.stderr + result.stdout).toBe(0);
    expect(result.stdout).not.toContain('different programs');
    // Cursor's docker github server and Desktop's npx github server must not share pins.
    expectWrapped(readJson(box.paths.desktop).mcpServers.github, 'claude-desktop.github', ['npx', '-y', '@modelcontextprotocol/server-github']);
    expectWrapped(readJson(box.paths.cursor).mcpServers.github, 'cursor-user.github', ['docker', 'run', '-i', '--rm', '-e', 'GITHUB_PERSONAL_ACCESS_TOKEN', 'ghcr.io/github/github-mcp-server']);
  });

  it('builds scoped proxy names', () => {
    expect(scopedName('cursor-user', 'github')).toBe('cursor-user.github');
    expect(scopedName('claude-code-user', 'db', '/home/dev/My App')).toBe('claude-code-user.my-app.db');
    expect(scopedName('Claude Desktop', 'x')).toBe('claude-desktop.x');
  });
});

describe('writing a config file', () => {
  function configFile(text: string): string {
    const dir = tempDir('toolmoat-write-');
    temps.push(dir);
    const file = path.join(dir, 'mcp.json');
    fs.writeFileSync(file, text);
    return file;
  }

  it('refuses when the file changed after it was read, leaving it and the backup alone', () => {
    const file = configFile('{"mcpServers":{"a":{"command":"x"}}}\n');
    const config = readJsonConfig(file);
    const changed = '{"mcpServers":{"a":{"command":"x"},"b":{"command":"y"}}}\n';
    fs.writeFileSync(file, changed);
    expect(() => writeJsonConfig(config)).toThrow(/changed on disk/);
    expect(fs.readFileSync(file, 'utf8')).toBe(changed);
    expect(fs.existsSync(backupPath(file))).toBe(false);
  });

  it('removes its temp file and keeps the original when writing fails part way', () => {
    const text = '{"mcpServers":{"a":{"command":"x"}}}\n';
    const file = configFile(text);
    const config = readJsonConfig(file);
    (config.data.mcpServers as Json).a.command = 'z';
    const realWrite = fs.writeFileSync;
    const spy = vi.spyOn(fs, 'writeFileSync').mockImplementation((...args: Parameters<typeof fs.writeFileSync>) => {
      realWrite(args[0], 'partial', args[2]);
      throw new Error('ENOSPC: no space left on device');
    });
    try {
      expect(() => writeJsonConfig(config)).toThrow(/ENOSPC/);
    } finally {
      spy.mockRestore();
    }
    expect(fs.readFileSync(file, 'utf8')).toBe(text);
    expect(fs.readdirSync(path.dirname(file)).filter((name) => name.endsWith('.tmp'))).toEqual([]);
    expect(fs.readFileSync(backupPath(file), 'utf8')).toBe(text);
  });
});
