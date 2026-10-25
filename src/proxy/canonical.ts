/**
 * Canonical JSON for hashing and comparing tool definitions that come from an
 * untrusted server. Same output as sorting keys and calling JSON.stringify,
 * except that a key named "__proto__" is kept: assigning to it on a plain
 * object sets the prototype instead of creating a property, so a schema
 * carrying one would hash the same whatever it contained under that key, while
 * the client still receives it.
 */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value !== null && typeof value === 'object') {
    const source = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(source).sort()) {
      const child = source[key];
      if (child !== undefined) Object.defineProperty(out, key, { value: sortKeys(child), enumerable: true, writable: true, configurable: true });
    }
    return out;
  }
  return value;
}

/** The value for an own key only, so names such as "constructor" or "toString" are never mistaken for entries. */
export function getOwn<T>(record: Readonly<Record<string, T>>, key: string): T | undefined {
  return Object.hasOwn(record, key) ? record[key] : undefined;
}

/** Sets an own property even for the key "__proto__" (plain assignment would replace the prototype). */
export function setOwn<T>(record: Record<string, T>, key: string, value: T): void {
  Object.defineProperty(record, key, { value, enumerable: true, writable: true, configurable: true });
}
