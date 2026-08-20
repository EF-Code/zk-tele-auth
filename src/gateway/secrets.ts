/** Secret-provider seam used by production entrypoints.  Adapters should
 * resolve references from the platform secret manager; this repository keeps
 * the interface deliberately small so secrets never need to be copied into an
 * image or configuration file. */
export interface SecretProvider {
  get(name: string): Promise<string | undefined>;
}

export class EnvironmentSecretProvider implements SecretProvider {
  constructor(private readonly environment: NodeJS.ProcessEnv = process.env) {}

  async get(name: string): Promise<string | undefined> {
    return this.environment[name];
  }
}

/** Resolve a reference to a mounted secret file without ever logging its contents. */
export class FileSecretProvider implements SecretProvider {
  async get(reference: string): Promise<string | undefined> {
    if (!reference.startsWith('/')) return undefined;
    try {
      const value = (await fs.readFile(reference, 'utf8')).trim();
      return value || undefined;
    } catch {
      return undefined;
    }
  }
}

/** Try provider adapters in order, allowing local env and mounted/cloud refs. */
export class ChainedSecretProvider implements SecretProvider {
  constructor(private readonly providers: readonly SecretProvider[]) {}

  async get(name: string): Promise<string | undefined> {
    for (const provider of this.providers) {
      const value = await provider.get(name);
      if (value !== undefined) return value;
    }
    return undefined;
  }
}

export function secretPresence(value: string | undefined): 'present' | 'absent' {
  return value ? 'present' : 'absent';
}

const SENSITIVE_KEY = /(token|secret|proof|witness|nonce|user|initdata|nullifier|signature|private|mnemonic|key)/i;

/** Recursively redact values before sending a structured event to a logger. */
export function redactLogFields(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactLogFields);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, nested]) => [
      key,
      SENSITIVE_KEY.test(key) ? '[REDACTED]' : redactLogFields(nested),
    ]));
  }
  if (typeof value === 'string' && value.length > 128) return '[REDACTED_LONG_VALUE]';
  return value;
}

export function structuredLog(event: string, fields: Record<string, unknown> = {}): string {
  return JSON.stringify(redactLogFields({ event, ...fields }));
}
import * as fs from 'node:fs/promises';
