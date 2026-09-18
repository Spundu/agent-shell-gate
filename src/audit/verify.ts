import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { GENESIS_HASH, type SealedAuditEntry } from '../contracts/index.js';
import { canonicalize } from './canonicalize.js';
import type { KeyProvider } from './keys.js';

/** External corroboration that pins the chain's length + head, detecting tail truncation. */
export interface ChainAnchor {
  count: number;
  lastHash: string;
}

export interface VerifyResult {
  ok: boolean;
  lastSeq: number;
  brokenAt: number | null;
  reason: string | null;
}

function sha256Hex(bytes: string): string {
  return createHash('sha256').update(bytes, 'utf8').digest('hex');
}

const HEX_ONLY = /^[0-9a-f]*$/i;

// Total by construction: any non-hex or odd/mismatched-length input returns false rather than throwing.
// Without the hex guard a 64-char NON-hex entry_hmac (same string length as the real one, so the length
// check passes) decodes via Buffer.from(_, 'hex') to a ZERO-length buffer, and timingSafeEqual then throws
// "Input buffers must have the same byte length" (cold review 2026-09-17, C-5). A recomputed HMAC is always
// valid hex, so a legitimate comparison is unaffected; a forged one now fails closed to a normal mismatch.
function hexEqual(a: string, b: string): boolean {
  if (a.length !== b.length || a.length % 2 !== 0) return false;
  if (!HEX_ONLY.test(a) || !HEX_ONLY.test(b)) return false;
  return timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
}

/**
 * Verify a hash-chained, HMAC-sealed audit stream. Detects content tampering (entry_hash),
 * reorder / middle-delete (seq + prev_hash linkage), and forgery / unseal (HMAC). Tail
 * truncation is only detectable WITH an anchor — the chain alone cannot prove how many
 * entries existed.
 */
export function verifyChain(
  entries: readonly SealedAuditEntry[],
  keys: KeyProvider,
  anchor?: ChainAnchor,
): VerifyResult {
  const broken = (at: number, reason: string): VerifyResult => ({
    ok: false,
    lastSeq: at - 1,
    brokenAt: at,
    reason,
  });

  let prevHash = GENESIS_HASH;
  for (let i = 0; i < entries.length; i += 1) {
    const entry = entries[i];
    if (entry === undefined) return broken(i, 'missing entry');
    if (entry.seq !== i) return broken(i, `seq mismatch: expected ${i}, got ${entry.seq}`);
    if (entry.prev_hash !== prevHash) return broken(i, 'prev_hash linkage broken (reorder/delete)');

    const { entry_hash, entry_hmac, ...core } = entry;
    const bytes = canonicalize(core);
    if (entry_hash !== sha256Hex(bytes)) {
      return broken(i, 'entry_hash mismatch (content tampered)');
    }
    const key = keys.getKey(entry.writer_key_id);
    if (!key) return broken(i, `unknown writer_key_id '${entry.writer_key_id}'`);
    const recomputedHmac = createHmac('sha256', key).update(bytes, 'utf8').digest('hex');
    if (!hexEqual(recomputedHmac, entry_hmac)) {
      return broken(i, 'HMAC mismatch (forged or unsealed)');
    }
    prevHash = entry_hash;
  }

  if (anchor) {
    if (entries.length !== anchor.count) {
      return broken(entries.length, `count ${entries.length} != anchor ${anchor.count} (truncation)`);
    }
    if (prevHash !== anchor.lastHash) {
      return broken(entries.length - 1, 'head hash does not match anchor');
    }
  }

  return { ok: true, lastSeq: entries.length - 1, brokenAt: null, reason: null };
}
