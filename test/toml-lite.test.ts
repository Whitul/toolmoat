import { describe, expect, it } from 'vitest';
import { joinKeyPath, parseToml } from '../src/util/toml-lite.js';

describe('parseToml', () => {
  it('reads a Codex config with tables, arrays and inline tables', () => {
    const text = [
      '# Codex config',
      'model = "gpt-5"',
      'approval_policy = "on-request"',
      '',
      '[mcp_servers.github]',
      'command = "npx"',
      'args = ["-y", "@modelcontextprotocol/server-github"]',
      'env = { GITHUB_TOKEN = "x", "QUOTED KEY" = \'lit\' }',
      'startup_timeout_sec = 20',
      '',
      '[mcp_servers."docs.server"]',
      'url = "https://docs.example.invalid/mcp"',
      'bearer_token_env_var = "DOCS_TOKEN"',
      '',
      '[mcp_servers.github.env_extra]',
      'enabled = true',
    ].join('\n');
    const { data, lines, errors } = parseToml(text);
    expect(errors).toEqual([]);
    expect(data).toEqual({
      model: 'gpt-5',
      approval_policy: 'on-request',
      mcp_servers: {
        github: {
          command: 'npx',
          args: ['-y', '@modelcontextprotocol/server-github'],
          env: { GITHUB_TOKEN: 'x', 'QUOTED KEY': 'lit' },
          startup_timeout_sec: 20,
          env_extra: { enabled: true },
        },
        'docs.server': { url: 'https://docs.example.invalid/mcp', bearer_token_env_var: 'DOCS_TOKEN' },
      },
    });
    expect(lines.get('mcp_servers.github')).toBe(5);
    expect(lines.get('mcp_servers.github.command')).toBe(6);
    expect(lines.get('mcp_servers.github.args.1')).toBe(7);
    expect(lines.get('mcp_servers.github.env.GITHUB_TOKEN')).toBe(8);
    expect(lines.get(joinKeyPath(['mcp_servers', 'github', 'env', 'QUOTED KEY']))).toBe(8);
    expect(lines.get('mcp_servers."docs.server".url')).toBe(12);
    expect(lines.get('mcp_servers.github.env_extra.enabled')).toBe(16);
  });

  it('records the line of each element of a multi-line array', () => {
    const text = 'args = [\n  "-y",  # comment\n  "pkg@1.2.3",\n]\n';
    const { data, lines } = parseToml(text);
    expect(data.args).toEqual(['-y', 'pkg@1.2.3']);
    expect(lines.get('args')).toBe(1);
    expect(lines.get('args.0')).toBe(2);
    expect(lines.get('args.1')).toBe(3);
  });

  it('handles all string forms and escapes', () => {
    const text = [
      'basic = "tab\\there \\"quoted\\" \\u00e9 \\U0001F600"',
      "literal = 'C:\\Users\\nobody'",
      'multi = """',
      'line one',
      'line two \\',
      '    continued"""',
      "rawmulti = '''",
      'keep \\n as is',
      "'''",
      'quotes = """a ""quoted"" word""""',
    ].join('\n');
    const { data, errors } = parseToml(text);
    expect(errors).toEqual([]);
    expect(data.basic).toBe('tab\there "quoted" é 😀');
    expect(data.literal).toBe('C:\\Users\\nobody');
    expect(data.multi).toBe('line one\nline two continued');
    expect(data.rawmulti).toBe('keep \\n as is\n');
    expect(data.quotes).toBe('a ""quoted"" word"');
  });

  it('parses numbers, booleans, dates, dotted keys and nested arrays', () => {
    const text = [
      'int = 1_000',
      'neg = -17',
      'hex = 0xff',
      'oct = 0o17',
      'bin = 0b101',
      'float = 3.5e2',
      'inf = -inf',
      'flag = false',
      'when = 1979-05-27T07:32:00Z',
      'spaced = 1979-05-27 07:32:00',
      'site.name = "example"',
      'site."sub key".depth = 2',
      'nested = [["a", "b"], ["c"]]',
      'mixed = [ { name = "x" }, { name = "y" } ]',
    ].join('\n');
    const { data, lines, errors } = parseToml(text);
    expect(errors).toEqual([]);
    expect(data).toMatchObject({
      int: 1000,
      neg: -17,
      hex: 255,
      oct: 15,
      bin: 5,
      float: 350,
      inf: -Infinity,
      flag: false,
      when: '1979-05-27T07:32:00Z',
      spaced: '1979-05-27 07:32:00',
      site: { name: 'example', 'sub key': { depth: 2 } },
      nested: [['a', 'b'], ['c']],
      mixed: [{ name: 'x' }, { name: 'y' }],
    });
    expect(lines.get('site."sub key".depth')).toBe(12);
    expect(lines.get('mixed.1.name')).toBe(14);
  });

  it('supports arrays of tables', () => {
    const text = ['[[servers]]', 'name = "a"', '[servers.env]', 'K = "1"', '', '[[servers]]', 'name = "b"'].join('\n');
    const { data, lines, errors } = parseToml(text);
    expect(errors).toEqual([]);
    expect(data).toEqual({ servers: [{ name: 'a', env: { K: '1' } }, { name: 'b' }] });
    expect(lines.get('servers.0.name')).toBe(2);
    expect(lines.get('servers.0.env.K')).toBe(4);
    expect(lines.get('servers.1.name')).toBe(7);
  });

  it('accepts pyproject-style dependency lists', () => {
    const text = [
      '[project]',
      'name = "demo"',
      'dependencies = [',
      '  "requests>=2",',
      '  "tool @ git+https://git.example.invalid/tool.git@main",',
      ']',
      '',
      '[tool.uv.sources]',
      'other = { git = "https://git.example.invalid/other.git", branch = "dev" }',
    ].join('\n');
    const { data, lines, errors } = parseToml(text);
    expect(errors).toEqual([]);
    expect(data).toMatchObject({ project: { dependencies: ['requests>=2', 'tool @ git+https://git.example.invalid/tool.git@main'] } });
    expect(lines.get('project.dependencies.1')).toBe(5);
    expect(lines.get('tool.uv.sources.other.git')).toBe(9);
  });

  it('skips broken statements without throwing and keeps the rest', () => {
    const text = [
      'good = 1',
      'bad = ',
      'also bad',
      '[broken',
      'lost = "under a broken header"',
      '[ok]',
      'value = "kept"',
      'unterminated = "no end',
      'after = true',
    ].join('\n');
    const { data, errors } = parseToml(text);
    expect(data).toEqual({ good: 1, ok: { value: 'kept', after: true } });
    expect(errors.map((e) => e.line)).toEqual([2, 3, 4, 8]);
  });

  it('rejects redefining a value as a table', () => {
    const { data, errors } = parseToml('a = 1\n[a.b]\nc = 2\n');
    expect(data).toEqual({ a: 1 });
    expect(errors).toHaveLength(1);
  });

  it('stores __proto__ as a plain key without touching prototypes', () => {
    const { data } = parseToml('__proto__ = "x"\n[constructor]\nprototype = 1\n');
    expect(Object.hasOwn(data, '__proto__')).toBe(true);
    expect(({} as Record<string, unknown>).prototype).toBeUndefined();
    expect(Object.getPrototypeOf(data)).toBe(Object.prototype);
  });

  it('caps nesting depth', () => {
    const { errors } = parseToml(`a = ${'['.repeat(5000)}${']'.repeat(5000)}\nb = 1\n`);
    expect(errors[0]?.message).toMatch(/nested too deeply/);
  });

  it('handles a leading BOM and CRLF line endings', () => {
    const { data, lines, errors } = parseToml('\ufeffa = "1"\r\n[t]\r\nb = 2\r\n');
    expect(errors).toEqual([]);
    expect(data).toEqual({ a: '1', t: { b: 2 } });
    expect(lines.get('t.b')).toBe(3);
  });

  it('stays fast on long hostile input', () => {
    const N = 40_000;
    const inputs = [
      '"'.repeat(N),
      "'".repeat(N),
      '['.repeat(N),
      '{'.repeat(N),
      'a.'.repeat(N / 2),
      `a = [${"'x',".repeat(N / 4)}]`,
      `a = "${'\\'.repeat(N)}"`,
      `a = """${'\\ '.repeat(N / 2)}`,
      '#'.repeat(N),
      'a = 1\n'.repeat(N / 6),
      `x = ${'1'.repeat(N)}`,
    ];
    for (const input of inputs) {
      const started = performance.now();
      parseToml(input);
      expect(performance.now() - started).toBeLessThan(300);
    }
  });
});

describe('joinKeyPath', () => {
  it('quotes segments that are not bare keys', () => {
    expect(joinKeyPath(['mcp_servers', 'my.server', 'args', 0])).toBe('mcp_servers."my.server".args.0');
    expect(joinKeyPath(['a-b_c', 'with space'])).toBe('a-b_c."with space"');
  });
});
