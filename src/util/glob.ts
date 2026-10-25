/**
 * Minimal glob matcher for ignore files: `**` crosses directories, `*` and `?`
 * stay within one path segment. A pattern without a slash matches a file or
 * directory name at any depth, like .gitignore.
 */
export function globToRegExp(pattern: string): RegExp {
  let p = pattern.trim().replace(/\\/g, '/');
  const anchored = p.startsWith('/');
  if (anchored) p = p.slice(1);
  if (p.endsWith('/')) p = `${p}**`;
  const floating = !anchored && !p.includes('/');

  let re = '';
  for (let i = 0; i < p.length; i++) {
    const ch = p[i]!;
    if (ch === '*') {
      if (p[i + 1] === '*') {
        i++;
        if (p[i + 1] === '/') {
          i++;
          re += '(?:[^/]*/)*';
        } else {
          re += '.*';
        }
      } else {
        re += '[^/]*';
      }
    } else if (ch === '?') {
      re += '[^/]';
    } else {
      re += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    }
  }
  const prefix = floating ? '(?:^|.*/)' : '^';
  return new RegExp(`${prefix}${re}(?:/.*)?$`, process.platform === 'win32' ? 'i' : '');
}

export function matchesGlob(filePath: string, pattern: string): boolean {
  return globToRegExp(pattern).test(filePath.replace(/\\/g, '/'));
}
