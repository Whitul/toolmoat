function enabled(stream: NodeJS.WriteStream): boolean {
  if (process.env.NO_COLOR !== undefined && process.env.NO_COLOR !== '') return false;
  if (process.env.FORCE_COLOR !== undefined && process.env.FORCE_COLOR !== '0') return true;
  return Boolean(stream.isTTY);
}

export interface Palette {
  bold(s: string): string;
  dim(s: string): string;
  red(s: string): string;
  yellow(s: string): string;
  blue(s: string): string;
  magenta(s: string): string;
  cyan(s: string): string;
  green(s: string): string;
  gray(s: string): string;
}

function wrap(open: number, close: number, on: boolean) {
  return (s: string) => (on ? `\u001b[${open}m${s}\u001b[${close}m` : s);
}

export function palette(stream: NodeJS.WriteStream = process.stdout, force?: boolean): Palette {
  const on = force ?? enabled(stream);
  return {
    bold: wrap(1, 22, on),
    dim: wrap(2, 22, on),
    red: wrap(31, 39, on),
    yellow: wrap(33, 39, on),
    blue: wrap(34, 39, on),
    magenta: wrap(35, 39, on),
    cyan: wrap(36, 39, on),
    green: wrap(32, 39, on),
    gray: wrap(90, 39, on),
  };
}
