import { describe, it, expect } from 'vitest';
import { AUDIT_SCHEMA_VERSION, GENESIS_HASH, AuditCoreSchema } from './audit-record.js';

const minimalPre = {
  v: 1 as const,
  seq: 0,
  chain: 'brain' as const,
  call_id: 'call-1',
  session_id: 'sess-1',
  agent: { name: 'brain', kind: 'main' as const },
  producer: 'agent-pipe' as const,
  ts_unix_ms: 1,
  boot_id: 'boot-1',
  host_id: 'host-1',
  phase: 'pre' as const,
  prev_hash: GENESIS_HASH,
  writer_key_id: 'key-1',
};

describe('AuditCore contract', () => {
  it('genesis hash is 64 hex zeros', () => {
    expect(GENESIS_HASH).toHaveLength(64);
    expect(GENESIS_HASH).toMatch(/^0{64}$/);
  });

  it('schema version is pinned to 1', () => {
    expect(AUDIT_SCHEMA_VERSION).toBe(1);
  });

  it('accepts a minimal valid pre-tool-use record', () => {
    expect(AuditCoreSchema.safeParse(minimalPre).success).toBe(true);
  });

  it('rejects unknown extra fields (strict — no smuggled data)', () => {
    const tampered = { ...minimalPre, injected_authority: true };
    expect(AuditCoreSchema.safeParse(tampered).success).toBe(false);
  });

  it('rejects a malformed prev_hash (must be 64 hex)', () => {
    const bad = { ...minimalPre, prev_hash: 'not-a-hash' };
    expect(AuditCoreSchema.safeParse(bad).success).toBe(false);
  });

  it('rejects a nonce on the brain chain (LAW: secrets are vault-chain only)', () => {
    const leaked = { ...minimalPre, nonce: 'secret-nonce' };
    expect(AuditCoreSchema.safeParse(leaked).success).toBe(false);
  });

  it('rejects vault-only digests on the brain chain', () => {
    expect(AuditCoreSchema.safeParse({ ...minimalPre, recap_hash: 'x' }).success).toBe(false);
    expect(AuditCoreSchema.safeParse({ ...minimalPre, vault_receipt_digest: 'x' }).success).toBe(false);
  });

  it('accepts a nonce on the vault chain approval record', () => {
    const vault = { ...minimalPre, chain: 'vault' as const, phase: 'approval' as const, nonce: 'n' };
    expect(AuditCoreSchema.safeParse(vault).success).toBe(true);
  });
});
