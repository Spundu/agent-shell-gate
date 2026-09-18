import { createHash, createHmac } from 'node:crypto';
import {
  AuditCoreSchema,
  GENESIS_HASH,
  type AuditCore,
  type SealedAuditEntry,
} from '../contracts/index.js';
import { canonicalize } from './canonicalize.js';
import type { KeyProvider } from './keys.js';

/**
 * What a producer submits. The chain assigns seq/prev_hash/writer_key_id, and the WRITER
 * stamps `producer` from the authenticated channel (P1-8) — it is never self-declared.
 */
export type AuditDraft = Omit<AuditCore, 'seq' | 'prev_hash' | 'writer_key_id' | 'producer'>;

export interface ChainState {
  seq: number;
  prevHash: string;
}

export function nextState(prev: SealedAuditEntry | null): ChainState {
  return prev ? { seq: prev.seq + 1, prevHash: prev.entry_hash } : { seq: 0, prevHash: GENESIS_HASH };
}

function digestHex(bytes: string): string {
  return createHash('sha256').update(bytes, 'utf8').digest('hex');
}

/** Seal a fully-formed core into a tamper-evident entry. Validates the core first (fail-closed). */
export function sealEntry(core: AuditCore, key: Buffer): SealedAuditEntry {
  // Re-validate: enforces strictness + the LAW (no secret on the brain chain) at seal time.
  const validated = AuditCoreSchema.parse(core);
  const bytes = canonicalize(validated);
  return {
    ...validated,
    entry_hash: digestHex(bytes),
    entry_hmac: createHmac('sha256', key).update(bytes, 'utf8').digest('hex'),
  };
}

/**
 * Append a draft to the chain: assigns seq/prev_hash/writer_key_id, then seals.
 * This is the WRITER's operation (Supervisor for the brain chain, vault for its own).
 */
export function appendEntry(
  prev: SealedAuditEntry | null,
  draft: AuditDraft,
  keys: KeyProvider,
  producer: AuditCore['producer'],
): SealedAuditEntry {
  const { seq, prevHash } = nextState(prev);
  const writerKeyId = keys.activeKeyId();
  const key = keys.getKey(writerKeyId);
  if (!key) throw new Error(`No HMAC key for writer_key_id='${writerKeyId}'`);
  const core = AuditCoreSchema.parse({
    ...draft,
    producer,
    seq,
    prev_hash: prevHash,
    writer_key_id: writerKeyId,
  });
  return sealEntry(core, key);
}
