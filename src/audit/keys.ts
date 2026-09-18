// The HMAC sealing keyring. The REAL key lives in the Supervisor (Ring 1) behind DPAPI and
// is never in agent reach; the vault holds its own key in-VM. `verifyChain` resolves a key
// by `writer_key_id` so historical entries stay verifiable across key rotation.

export interface KeyProvider {
  /** Raw HMAC key bytes for a writer_key_id, or null if unknown. */
  getKey(writerKeyId: string): Buffer | null;
  /** The id of the key new entries are sealed with. */
  activeKeyId(): string;
}

/** In-memory keyring for tests and local development only — never the production seal path. */
export class InMemoryKeyProvider implements KeyProvider {
  readonly #keys = new Map<string, Buffer>();
  readonly #activeId: string;

  constructor(keys: Record<string, Buffer | string>, activeId: string) {
    for (const [id, key] of Object.entries(keys)) {
      this.#keys.set(id, typeof key === 'string' ? Buffer.from(key, 'utf8') : key);
    }
    if (!this.#keys.has(activeId)) {
      throw new Error(`activeId '${activeId}' is not present in the keyring`);
    }
    this.#activeId = activeId;
  }

  getKey(writerKeyId: string): Buffer | null {
    return this.#keys.get(writerKeyId) ?? null;
  }

  activeKeyId(): string {
    return this.#activeId;
  }
}
