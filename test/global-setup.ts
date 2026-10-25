import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import path from 'node:path';

/** Builds dist/ once so end-to-end tests can spawn the real CLI. */
export default function setup(): void {
  const require = createRequire(import.meta.url);
  const tsc = path.join(path.dirname(require.resolve('typescript/package.json')), 'bin', 'tsc');
  const result = spawnSync(process.execPath, [tsc, '-p', 'tsconfig.build.json'], {
    cwd: path.resolve(import.meta.dirname, '..'),
    encoding: 'utf8',
  });
  if (result.status !== 0) {
    process.stderr.write(`[global-setup] tsc reported errors (dist was still emitted):\n${result.stdout}${result.stderr}\n`);
  }
}
