import fs from 'node:fs';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { classifyFile, discover } from '../src/scan/discover.js';
import type { DiscoverResult } from '../src/scan/discover.js';
import { parseIgnoreFile } from '../src/scan/ignore.js';
import type { FileKind, ScanFile } from '../src/types.js';
import { FIXTURES, tempDir } from './helpers.js';

const ENV_KEYS = ['TOOLMOAT_TEST_USER_HOME', 'TOOLMOAT_HOME', 'APPDATA', 'XDG_CONFIG_HOME'] as const;
const savedEnv = new Map(ENV_KEYS.map((key) => [key, process.env[key]]));
const MIB = 1024 * 1024;

let tmp = '';
let home = '';
let project = '';

function write(root: string, rel: string, content: string | Buffer): string {
  const abs = path.join(root, ...rel.split('/'));
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, content);
  return abs;
}

function setHome(dir: string): void {
  process.env.TOOLMOAT_TEST_USER_HOME = dir;
  process.env.APPDATA = path.join(dir, 'appdata');
  process.env.XDG_CONFIG_HOME = path.join(dir, 'appdata');
}

function byPath(result: DiscoverResult): Map<string, ScanFile> {
  return new Map(result.files.map((f) => [f.displayPath, f]));
}

/** Where appDataDir() points inside the fake home: macOS ignores APPDATA and XDG_CONFIG_HOME. */
const APPDATA_REL = process.platform === 'darwin' ? 'Library/Application Support' : 'appdata';

beforeAll(() => {
  tmp = tempDir('toolmoat-discover-');
  home = path.join(tmp, 'home');
  project = path.join(tmp, 'project');
  fs.cpSync(path.join(FIXTURES, 'discover', 'home'), home, { recursive: true });
  fs.cpSync(path.join(FIXTURES, 'discover', 'project'), project, { recursive: true });
  if (process.platform === 'darwin') {
    fs.cpSync(path.join(home, 'appdata'), path.join(home, 'Library', 'Application Support'), { recursive: true });
  }
  setHome(home);
  process.env.TOOLMOAT_HOME = path.join(tmp, 'toolmoat-home');

  // Files git would not keep (ignored directories, binary, oversized) are made at runtime.
  write(home, '.claude/skills/pdf-helper/node_modules/left-pad/index.js', 'module.exports = 1;\n');
  write(home, '.claude/skills/pdf-helper/scripts/blob.sh', Buffer.from([0x23, 0x21, 0x2f, 0x62, 0x00, 0x01, 0x02]));
  write(home, '.claude/commands/huge.md', 'x'.repeat(2 * MIB + 1));
  write(project, 'node_modules/evil-pkg/SKILL.md', '---\nname: evil-pkg\ndescription: vendored\n---\nHello.\n');
  write(project, '.git/hooks/pre-commit.sh', '#!/bin/sh\nexit 0\n');
});

afterAll(() => {
  for (const [key, value] of savedEnv) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe('classifyFile', () => {
  const none = () => path.join(tmp, 'does-not-exist');
  const cases: [string, string | undefined, FileKind | null][] = [
    ['skills/x/SKILL.md', undefined, 'skill'],
    ['skills/x/skill.md', undefined, 'skill'],
    ['CLAUDE.md', undefined, 'instructions'],
    ['AGENTS.md', undefined, 'instructions'],
    ['GEMINI.md', undefined, 'instructions'],
    ['.claude/commands/deploy.md', undefined, 'instructions'],
    ['.claude/commands/frontend/component.md', undefined, 'instructions'],
    ['.claude/agents/reviewer.md', undefined, 'instructions'],
    ['.cursor/rules/style.mdc', undefined, 'instructions'],
    ['prompts/summary.markdown', undefined, 'instructions'],
    ['commands/README.md', undefined, 'instructions'],
    ['README.md', undefined, 'docs'],
    ['CHANGELOG.md', undefined, 'docs'],
    ['SECURITY.md', undefined, 'docs'],
    ['docs/guide.mdx', undefined, 'docs'],
    ['.cursorrules', undefined, 'instructions'],
    ['.windsurfrules', undefined, 'instructions'],
    ['scripts/a.sh', undefined, 'script'],
    ['a.ps1', undefined, 'script'],
    ['a.py', undefined, 'script'],
    ['a.mjs', undefined, 'script'],
    ['a.tsx', undefined, 'script'],
    ['a.bat', undefined, 'script'],
    ['a.lua', undefined, 'script'],
    ['bin/run', '#!/bin/sh\necho hi\n', 'script'],
    ['LICENSE', 'MIT License\n', null],
    ['package.json', undefined, 'package-manifest'],
    ['pyproject.toml', undefined, 'package-manifest'],
    ['requirements.txt', undefined, 'package-manifest'],
    ['p/.claude-plugin/plugin.json', undefined, 'plugin-manifest'],
    ['m/.claude-plugin/marketplace.json', undefined, 'plugin-manifest'],
    ['.claude/settings.json', undefined, 'agent-settings'],
    ['.claude/settings.local.json', undefined, 'agent-settings'],
    ['p/hooks/hooks.json', undefined, 'agent-settings'],
    ['.mcp.json', undefined, 'mcp-config'],
    ['.vscode/mcp.json', undefined, 'mcp-config'],
    ['Claude/claude_desktop_config.json', undefined, 'mcp-config'],
    ['.codeium/windsurf/mcp_config.json', undefined, 'mcp-config'],
    ['.claude.json', undefined, 'mcp-config'],
    ['.gemini/settings.json', undefined, 'mcp-config'],
    ['.codex/config.toml', undefined, 'mcp-config'],
    ['other/config.toml', undefined, null],
    ['tools.json', '{"mcpServers": {}}', 'mcp-config'],
    ['ext/gemini-extension.json', '{"name": "x", "mcpServers": {"a": {"command": "node"}}}', 'mcp-config'],
    ['custom-hooks.json', '{"hooks": {"PreToolUse": []}}', 'agent-settings'],
    ['perms.json', '{"permissions": {"deny": ["Read(.env)"]}}', 'agent-settings'],
    ['.huskyrc.json', '{"hooks": {"pre-commit": "npm test"}}', null],
    ['settings.json', '{"editor.fontSize": 14}', null],
    ['tsconfig.json', '{"compilerOptions": {}}', null],
    ['logo.png', undefined, null],
    ['notes.txt', undefined, null],
  ];

  it.each(cases)('%s -> %s', (rel, content, expected) => {
    expect(classifyFile(path.join(none(), ...rel.split('/')), content)).toBe(expected);
  });

  it('treats markdown inside a skill or plugin as instructions, except README-style docs', () => {
    const root = path.join(tmp, 'classify');
    write(root, 'my-skill/SKILL.md', '---\nname: my-skill\n---\n');
    const reference = write(root, 'my-skill/docs/reference.md', '# Ref\n');
    const readme = write(root, 'my-skill/README.md', '# Readme\n');
    write(root, 'my-plugin/.claude-plugin/plugin.json', '{"name": "my-plugin"}');
    const pluginNotes = write(root, 'my-plugin/notes.md', '# Notes\n');
    const loose = write(root, 'loose/notes.md', '# Notes\n');
    expect(classifyFile(reference)).toBe('instructions');
    expect(classifyFile(readme)).toBe('docs');
    expect(classifyFile(pluginNotes)).toBe('instructions');
    expect(classifyFile(loose)).toBe('docs');
  });
});

describe('discover with default locations', () => {
  let result: DiscoverResult;
  let files: Map<string, ScanFile>;

  beforeAll(async () => {
    result = await discover({ paths: [], useDefaults: true, cwd: project });
    files = byPath(result);
  });

  const expectFile = (displayPath: string, kind: FileKind, target: string) => {
    const found = files.get(displayPath);
    expect(found, `${displayPath} not discovered; got ${[...files.keys()].join(', ')}`).toBeDefined();
    expect({ kind: found!.kind, target: found!.target }).toEqual({ kind, target });
  };

  it('finds user-level skills with their skill as target', () => {
    expectFile('~/.claude/skills/pdf-helper/SKILL.md', 'skill', 'skill:pdf-helper');
    expectFile('~/.claude/skills/pdf-helper/reference.md', 'instructions', 'skill:pdf-helper');
    expectFile('~/.claude/skills/pdf-helper/README.md', 'docs', 'skill:pdf-helper');
    expectFile('~/.claude/skills/pdf-helper/scripts/extract.py', 'script', 'skill:pdf-helper');
    expectFile('~/.agents/skills/notes-skill/SKILL.md', 'skill', 'skill:notes-skill');
  });

  it('finds plugin files and names the plugin from plugin.json', () => {
    const p = '~/.claude/plugins/cache/demo-market/demo-plugin/1.0.0';
    expectFile(`${p}/.claude-plugin/plugin.json`, 'plugin-manifest', 'plugin:demo-plugin');
    expectFile(`${p}/commands/hello.md`, 'instructions', 'plugin:demo-plugin');
    expectFile(`${p}/hooks/hooks.json`, 'agent-settings', 'plugin:demo-plugin');
    expectFile(`${p}/.mcp.json`, 'mcp-config', 'plugin:demo-plugin');
    expectFile(`${p}/scripts/run.sh`, 'script', 'plugin:demo-plugin');
    expectFile(`${p}/notes.md`, 'instructions', 'plugin:demo-plugin');
    expectFile(`${p}/README.md`, 'docs', 'plugin:demo-plugin');
    expectFile(`${p}/skills/inner-skill/SKILL.md`, 'skill', 'skill:inner-skill');
    expect(files.has('~/.claude/plugins/installed_plugins.json')).toBe(false);
  });

  it('finds user-level Claude Code files and every client config with a readable label', () => {
    expectFile('~/.claude/commands/deploy.md', 'instructions', 'Claude Code (user)');
    expectFile('~/.claude/settings.json', 'agent-settings', 'Claude Code (user)');
    expectFile('~/.claude/CLAUDE.md', 'instructions', 'Claude Code (user)');
    expectFile('~/.claude.json', 'mcp-config', 'Claude Code (user)');
    expectFile(`~/${APPDATA_REL}/Claude/claude_desktop_config.json`, 'mcp-config', 'Claude Desktop');
    expectFile(`~/${APPDATA_REL}/Code/User/mcp.json`, 'mcp-config', 'VS Code');
    expectFile('~/.cursor/mcp.json', 'mcp-config', 'Cursor');
    expectFile('~/.codeium/windsurf/mcp_config.json', 'mcp-config', 'Windsurf');
    expectFile('~/.codex/config.toml', 'mcp-config', 'Codex');
    expectFile('~/.gemini/settings.json', 'mcp-config', 'Gemini CLI');
    expectFile('~/.gemini/extensions/demo-ext/gemini-extension.json', 'mcp-config', 'Gemini CLI');
  });

  it('finds project-level files relative to cwd', () => {
    expectFile('.mcp.json', 'mcp-config', 'Claude Code (project .mcp.json)');
    expectFile('.vscode/mcp.json', 'mcp-config', 'VS Code (project)');
    expectFile('.cursor/mcp.json', 'mcp-config', 'Cursor (project)');
    expectFile('.claude/settings.json', 'agent-settings', 'project');
    expectFile('.claude/commands/review.md', 'instructions', 'project');
    expectFile('CLAUDE.md', 'instructions', 'project');
    expectFile('AGENTS.md', 'instructions', 'project');
    expect(files.has('src/app.js')).toBe(false);
  });

  it('skips node_modules, binary and oversized files, and reports the roots it scanned', () => {
    expect([...files.keys()].filter((p) => p.includes('node_modules'))).toEqual([]);
    expect(result.skipped).toContainEqual({ path: '~/.claude/skills/pdf-helper/scripts/blob.sh', reason: 'binary file' });
    expect(result.skipped).toContainEqual({ path: '~/.claude/commands/huge.md', reason: 'larger than 2 MiB' });
    expect(result.roots).toEqual(expect.arrayContaining(['~/.claude/skills', '~/.claude/plugins', '~/.claude.json', '.mcp.json', 'CLAUDE.md']));
    expect(result.roots).not.toContain('~/.claude/agents');
    expect(new Set(result.files.map((f) => f.displayPath)).size).toBe(result.files.length);
  });

  it('allows ~/.claude.json up to 20 MiB but holds other files to the 2 MiB limit', async () => {
    const bigHome = path.join(tmp, 'big-home');
    const padding = 'x'.repeat(3 * MIB);
    write(bigHome, '.claude.json', JSON.stringify({ mcpServers: {}, cache: padding }));
    write(bigHome, '.cursor/mcp.json', JSON.stringify({ mcpServers: {}, cache: padding }));
    setHome(bigHome);
    try {
      const big = await discover({ paths: [], useDefaults: true, cwd: path.join(tmp, 'empty-cwd') });
      expect(big.files.map((f) => f.displayPath)).toEqual(['~/.claude.json']);
      expect(big.skipped).toEqual([{ path: '~/.cursor/mcp.json', reason: 'larger than 2 MiB' }]);
    } finally {
      setHome(home);
    }
  });

  it('keeps the file content and absolute path', () => {
    const skill = files.get('~/.claude/skills/pdf-helper/SKILL.md')!;
    expect(skill.path).toBe(path.join(home, '.claude', 'skills', 'pdf-helper', 'SKILL.md'));
    expect(skill.content).toContain('name: pdf-helper');
  });
});

describe('discover with explicit paths', () => {
  it('walks a directory recursively and classifies by name and content', async () => {
    const result = await discover({ paths: [project], useDefaults: false, cwd: project });
    const files = byPath(result);
    expect(result.roots).toEqual(['.']);
    const kinds = Object.fromEntries([...files].map(([p, f]) => [p, f.kind]));
    expect(kinds).toMatchObject({
      'src/app.js': 'script',
      'bin/run': 'script',
      'docs/guide.md': 'docs',
      'tool.json': 'mcp-config',
      'hooks-config.json': 'agent-settings',
      'package.json': 'package-manifest',
      'pyproject.toml': 'package-manifest',
      'requirements.txt': 'package-manifest',
      '.mcp.json': 'mcp-config',
    });
    expect(files.get('src/app.js')!.target).toBe('project');
    expect(files.get('.mcp.json')!.target).toBe('Claude Code (project .mcp.json)');
    for (const absent of ['random.json', 'LICENSE', 'node_modules/evil-pkg/SKILL.md', '.git/hooks/pre-commit.sh']) {
      expect(files.has(absent), absent).toBe(false);
    }
  });

  it('walks vendored directories with deep, but never .git', async () => {
    const files = byPath(await discover({ paths: [project], useDefaults: false, cwd: project, deep: true }));
    expect(files.get('node_modules/evil-pkg/SKILL.md')).toMatchObject({ kind: 'skill', target: 'skill:evil-pkg' });
    expect(files.has('.git/hooks/pre-commit.sh')).toBe(false);
  });

  it('honours ignore paths', async () => {
    const ignore = parseIgnoreFile('docs/\nsrc/**\n*.toml\n');
    const files = byPath(await discover({ paths: [project], useDefaults: false, cwd: project, ignore }));
    expect(files.has('docs/guide.md')).toBe(false);
    expect(files.has('src/app.js')).toBe(false);
    expect(files.has('pyproject.toml')).toBe(false);
    expect(files.has('package.json')).toBe(true);
  });

  it('stops at maxFiles and says so', async () => {
    const result = await discover({ paths: [project], useDefaults: false, cwd: project, maxFiles: 3 });
    expect(result.files.length).toBeLessThanOrEqual(3);
    expect(result.skipped.some((s) => /stopped after 3 files/.test(s.reason))).toBe(true);
  });

  it('deduplicates files reached through overlapping roots', async () => {
    const paths = [project, path.join(project, '.claude'), path.join(project, 'CLAUDE.md')];
    if (process.platform === 'win32') paths.push(project.toUpperCase());
    const result = await discover({ paths, useDefaults: true, cwd: project });
    const shown = result.files.map((f) => f.displayPath);
    expect(shown.filter((p) => p === '.claude/settings.json')).toHaveLength(1);
    expect(shown.filter((p) => p === 'CLAUDE.md')).toHaveLength(1);
    expect(new Set(shown).size).toBe(shown.length);
  });

  it('attributes a single file to its skill and scans an explicit file of unknown kind as instructions', async () => {
    const reference = path.join(home, '.claude', 'skills', 'pdf-helper', 'reference.md');
    const result = await discover({ paths: [reference, path.join(project, 'LICENSE')], useDefaults: false, cwd: project });
    const files = byPath(result);
    expect(files.get('~/.claude/skills/pdf-helper/reference.md')).toMatchObject({ kind: 'instructions', target: 'skill:pdf-helper' });
    expect(files.get('LICENSE')).toMatchObject({ kind: 'instructions', target: 'project' });
  });

  it('expands ~ and reports missing paths', async () => {
    const result = await discover({ paths: ['~/.cursor/mcp.json', 'nope'], useDefaults: false, cwd: project });
    expect(result.files.map((f) => f.displayPath)).toEqual(['~/.cursor/mcp.json']);
    expect(result.skipped).toEqual([{ path: 'nope', reason: 'not found' }]);
    expect(result.roots).toEqual(['~/.cursor/mcp.json']);
  });

  it('decodes UTF-16 scripts instead of calling them binary', async () => {
    const dir = path.join(tmp, 'utf16');
    const text = "Write-Host 'hello'\r\n";
    write(dir, 'setup.ps1', Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(text, 'utf16le')]));
    write(dir, 'bom.sh', `﻿#!/bin/sh\necho hi\n`);
    const files = byPath(await discover({ paths: [dir], useDefaults: false, cwd: dir }));
    expect(files.get('setup.ps1')).toMatchObject({ kind: 'script', content: text });
    expect(files.get('bom.sh')!.content.startsWith('#!/bin/sh')).toBe(true);
  });
});

describe('discover and symbolic links', () => {
  function link(target: string, at: string): boolean {
    try {
      fs.symlinkSync(target, at, process.platform === 'win32' ? 'junction' : 'dir');
      return true;
    } catch {
      return false;
    }
  }

  it('does not follow directory links found while walking', async (ctx) => {
    const root = path.join(tmp, 'links');
    write(root, 'real/commands/a.md', '# A\n');
    write(root, 'tree/CLAUDE.md', '# Tree\n');
    if (!link(path.join(root, 'real'), path.join(root, 'tree', 'linked'))) ctx.skip();
    if (!link(path.join(root, 'tree'), path.join(root, 'tree', 'loop'))) ctx.skip();
    const result = await discover({ paths: [path.join(root, 'tree')], useDefaults: false, cwd: root });
    expect(result.files.map((f) => f.displayPath)).toEqual(['tree/CLAUDE.md']);
    expect(result.skipped.map((s) => s.path).sort()).toEqual(['tree/linked', 'tree/loop']);
    expect(result.skipped[0]!.reason).toMatch(/symbolic link to a directory, not followed/);
  });

  it('follows skill folders linked directly into a skills directory', async (ctx) => {
    const otherHome = path.join(tmp, 'linked-home');
    const external = path.join(tmp, 'external-skill');
    write(external, 'SKILL.md', '---\nname: external\n---\nDo things.\n');
    fs.mkdirSync(path.join(otherHome, '.claude', 'skills'), { recursive: true });
    if (!link(external, path.join(otherHome, '.claude', 'skills', 'linked-skill'))) ctx.skip();
    setHome(otherHome);
    try {
      const files = byPath(await discover({ paths: [], useDefaults: true, cwd: path.join(tmp, 'empty-cwd') }));
      expect(files.get('~/.claude/skills/linked-skill/SKILL.md')).toMatchObject({ kind: 'skill', target: 'skill:linked-skill' });
    } finally {
      setHome(home);
    }
  });
});
