import { describe, expect, it } from 'vitest';
import { asList, parseFrontmatter } from '../src/util/frontmatter.js';
import { matchesGlob } from '../src/util/glob.js';
import { canonicalJson } from '../src/util/hash.js';
import { parseJsonc } from '../src/util/jsonc.js';
import { lineAt, lineColAt, printable } from '../src/util/text.js';

describe('frontmatter', () => {
  it('parses scalars, lists and block scalars with line numbers', () => {
    const fm = parseFrontmatter(
      ['---', 'name: demo', 'description: >', '  Does a thing', '  well.', 'allowed-tools: [Read, "Bash(git:*)"]', 'tags:', '  - a', '  - b', '---', '# Body'].join('\n'),
    )!;
    expect(fm.data).toEqual({ name: 'demo', description: 'Does a thing well.', 'allowed-tools': ['Read', 'Bash(git:*)'], tags: ['a', 'b'] });
    expect(fm.lines['allowed-tools']).toBe(6);
    expect(fm.body).toBe('# Body');
    expect(fm.bodyLine).toBe(11);
  });

  it('returns null without frontmatter and splits string lists', () => {
    expect(parseFrontmatter('# Title')).toBeNull();
    expect(asList('Read, Grep Bash(git status:*)')).toEqual(['Read', 'Grep', 'Bash(git status:*)']);
  });
});

describe('jsonc', () => {
  it('accepts comments and trailing commas', () => {
    expect(parseJsonc('{ // c\n "a": [1, 2,], /* x */ "b": "//not a comment", }')).toEqual({ a: [1, 2], b: '//not a comment' });
    expect(parseJsonc('{ broken')).toBeUndefined();
  });
});

describe('glob', () => {
  it('matches gitignore-style patterns', () => {
    expect(matchesGlob('test/fixtures/a/b.md', 'test/fixtures/**')).toBe(true);
    expect(matchesGlob('deep/dir/node_modules/x.js', 'node_modules')).toBe(true);
    expect(matchesGlob('docs/a.md', 'docs/*.md')).toBe(true);
    expect(matchesGlob('docs/sub/a.md', 'docs/*.md')).toBe(false);
  });
});

describe('text', () => {
  it('computes positions and lines', () => {
    expect(lineColAt('ab\ncd', 4)).toEqual({ line: 2, column: 2 });
    expect(lineAt('a\r\nb\r\nc', 2)).toBe('b');
    expect(printable('a​b\u{e0041}')).toBe('a\\u200bb\\u{e0041}');
  });

  it('serializes canonically', () => {
    expect(canonicalJson({ b: 1, a: { d: 2, c: [3, { f: 1, e: 0 }] } })).toBe('{"a":{"c":[3,{"e":0,"f":1}],"d":2},"b":1}');
    // A "__proto__" key from parsed JSON must be kept, or content under it would not affect hashes.
    expect(canonicalJson(JSON.parse('{"__proto__":{"x":1},"a":2}'))).toBe('{"__proto__":{"x":1},"a":2}');
  });
});
