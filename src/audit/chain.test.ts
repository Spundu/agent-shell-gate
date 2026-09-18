import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import type { SealedAuditEntry } from '../contracts/index.js';
import { canonicalize } from './canonicalize.js';
import { InMemoryKeyProvider } from './keys.js';
import { appendEntry, type AuditDraft } from './seal.js';
import { verifyChain } from './verify.js';

function draft(i: number, over: Partial<AuditDraft> = {}): AuditDraft {
  return {
    v: 1,
    chain: 'brain',
    call_id: `call-${i}`,
    session_id: 'sess-1',
    agent: { name: 'brain', kind: 'main' },
    ts_unix_ms: 1000 + i,
    boot_id: 'boot-1',
    host_id: 'host-1',
    phase: 'pre',
    ...over,
  };
}

function buildChain(keys: InMemoryKeyProvider, n: number): SealedAuditEntry[] {
  const chain: SealedAuditEntry[] = [];
  let prev: SealedAuditEntry | null = null;
  for (let i = 0; i < n; i += 1) {
    prev = appendEntry(prev, draft(i), keys, 'agent-pipe');
    chain.push(prev);
  }
  return chain;
}

const keys = new InMemoryKeyProvider({ k1: Buffer.alloc(32, 7) }, 'k1');

describe('audit chain seal + verify', () => {
  it('verifies a well-formed chain', () => {
    const chain = buildChain(keys, 3);
    const result = verifyChain(chain, keys);
    expect(result.ok).toBe(true);
    expect(result.lastSeq).toBe(2);
  });

  it('detects content tampering (entry_hash)', () => {
    const chain = buildChain(keys, 3);
    const tampered = [chain[0]!, { ...chain[1]!, call_id: 'evil' }, chain[2]!];
    const result = verifyChain(tampered, keys);
    expect(result.ok).toBe(false);
    expect(result.brokenAt).toBe(1);
  });

  it('detects reordering (seq / prev_hash)', () => {
    const chain = buildChain(keys, 3);
    const result = verifyChain([chain[1]!, chain[0]!, chain[2]!], keys);
    expect(result.ok).toBe(false);
    expect(result.brokenAt).toBe(0);
  });

  it('detects a deleted middle entry', () => {
    const chain = buildChain(keys, 3);
    const result = verifyChain([chain[0]!, chain[2]!], keys);
    expect(result.ok).toBe(false);
    expect(result.brokenAt).toBe(1);
  });

  it('detects tail truncation only with an anchor', () => {
    const chain = buildChain(keys, 3);
    const truncated = [chain[0]!, chain[1]!];
    expect(verifyChain(truncated, keys).ok).toBe(true); // chain alone cannot tell
    const anchor = { count: 3, lastHash: chain[2]!.entry_hash };
    expect(verifyChain(truncated, keys, anchor).ok).toBe(false);
  });

  it('detects forgery: content re-hashed but HMAC cannot be reforged without the key', () => {
    const chain = buildChain(keys, 3);
    const { entry_hash: _h, entry_hmac, ...core } = chain[1]!;
    const forgedCore = { ...core, call_id: 'evil' };
    const forgedHash = createHash('sha256').update(canonicalize(forgedCore), 'utf8').digest('hex');
    const forged = { ...forgedCore, entry_hash: forgedHash, entry_hmac } as SealedAuditEntry;
    const result = verifyChain([chain[0]!, forged, chain[2]!], keys);
    expect(result.ok).toBe(false);
    expect(result.brokenAt).toBe(1);
    expect(result.reason).toMatch(/HMAC/);
  });

  it('fails verification under the wrong key', () => {
    const chain = buildChain(keys, 3);
    const wrong = new InMemoryKeyProvider({ k1: Buffer.alloc(32, 9) }, 'k1');
    expect(verifyChain(chain, wrong).ok).toBe(false);
  });

  it('returns ok:false (never throws) on a non-hex entry_hmac of the right length (cold review C-5)', () => {
    const chain = buildChain(keys, 3);
    // content unchanged → entry_hash stays valid and prev_hash linkage holds, so verification reaches the HMAC
    // comparison. A 64-char NON-hex hmac used to decode to a zero-length Buffer and make timingSafeEqual throw.
    const forged = { ...chain[1]!, entry_hmac: 'z'.repeat(64) } as SealedAuditEntry;
    let result: ReturnType<typeof verifyChain> | undefined;
    expect(() => {
      result = verifyChain([chain[0]!, forged, chain[2]!], keys);
    }).not.toThrow();
    expect(result?.ok).toBe(false);
    expect(result?.brokenAt).toBe(1);
    expect(result?.reason).toMatch(/HMAC/);
  });
});
