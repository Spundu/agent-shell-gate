import { z } from 'zod';
import { TIERS } from './tier.js';

// The ONE canonical audit record. Both audit-chain writers (the Supervisor-written
// "brain" chain and the in-VM "vault" chain) produce this exact shape; the Python vault
// validates against the JSON-Schema generated from it. The audit log is tamper-EVIDENT
// (hash-chained + HMAC-sealed) and NON-AUTHORIZING — it records, it never gates.

export const AUDIT_SCHEMA_VERSION = 1 as const;
export const GENESIS_HASH = '0'.repeat(64);
const SHA256_HEX = /^[0-9a-f]{64}$/;
const Sha256Hex = z.string().regex(SHA256_HEX, 'must be 64 lowercase hex chars');

export const ChainSchema = z.enum(['brain', 'vault']);
export type Chain = z.infer<typeof ChainSchema>;

export const ToolKindSchema = z.enum([
  'read',
  // a connector data-read (Gmail/Drive/Calendar) — auto-allow GREEN when active, but NOT a cheap
  // backstopped local read: it pulls sensitive personal content into context, so it is deliberately
  // NOT kill-switch/depth EXEMPT (the panic button + runaway guard stop it). Distinct from 'read'.
  'connector-read',
  'write',
  'exec',
  'network',
  'money',
  'account',
  'login',
  'irreversible',
  'vault',
  'meta',
]);
export type ToolKind = z.infer<typeof ToolKindSchema>;

export const AuditPhaseSchema = z.enum(['pre', 'approval', 'post', 'control']);
export type AuditPhase = z.infer<typeof AuditPhaseSchema>;

export const AuditDecisionSchema = z
  .object({
    tier: z.enum(TIERS),
    action: z.enum(['allow', 'ask', 'deny', 'executed', 'failed']),
    source: z.string(),
    reason: z.string(),
  })
  .strict();
export type AuditDecision = z.infer<typeof AuditDecisionSchema>;

export const AuditResultSchema = z
  .object({
    status: z.enum(['ok', 'error', 'denied', 'timeout', 'crashed']),
    duration_ms: z.number().int().nonnegative(),
    output_digest: z.string().optional(),
    spend_settled: z.string().optional(),
  })
  .strict();

const AuditCoreObject = z
  .object({
    v: z.literal(1),
    seq: z.number().int().nonnegative(),
    chain: ChainSchema,
    call_id: z.string(),
    session_id: z.string(),
    // SELF-DECLARED label — recorded but NEVER trusted for authorization.
    agent: z
      .object({
        name: z.string(),
        kind: z.enum(['main', 'subagent', 'vault']),
        parent: z.string().optional(),
      })
      .strict(),
    // STAMPED by the writer from the authenticated channel, not self-declared.
    producer: z.enum(['agent-pipe', 'vault']),
    ts_unix_ms: z.number().int().nonnegative(),
    boot_id: z.string(),
    host_id: z.string(),
    phase: AuditPhaseSchema,
    tool: z.string().optional(),
    tool_kind: ToolKindSchema.optional(),
    // Tool args pre-serialized to one canonical (RFC-8785 JCS) string.
    args_canonical: z.string().optional(),
    redactions: z.array(z.string()).optional(),
    decision: AuditDecisionSchema.optional(),
    // Cross-chain join key: a gated payment's pre/approval/post records share one action_hash.
    action_hash: Sha256Hex.optional(),
    recap_hash: z.string().optional(),
    vault_receipt_digest: z.string().optional(),
    // Approval phase only, and only ever on the VAULT chain. Redacted everywhere else.
    nonce: z.string().optional(),
    result: AuditResultSchema.optional(),
    prev_hash: Sha256Hex,
    writer_key_id: z.string(),
  })
  .strict();

const VAULT_ONLY_FIELDS = ['nonce', 'recap_hash', 'vault_receipt_digest'] as const;

// THE LAW: a nonce is secret and the approval-phase digests are vault-internal — none may
// ever appear on the brain chain. Only the in-VM vault chain may carry them.
function enforceVaultOnlySecrets(
  data: z.infer<typeof AuditCoreObject>,
  ctx: z.RefinementCtx,
): void {
  if (data.chain === 'vault') return;
  for (const field of VAULT_ONLY_FIELDS) {
    if (data[field] !== undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: [field],
        message: `${field} may only appear on the vault chain, never the brain chain`,
      });
    }
  }
}

export const AuditCoreSchema = AuditCoreObject.superRefine(enforceVaultOnlySecrets);
export type AuditCore = z.infer<typeof AuditCoreSchema>;

export const SealedAuditEntrySchema = AuditCoreObject.extend({
  entry_hash: Sha256Hex,
  entry_hmac: z.string(),
})
  .strict()
  .superRefine(enforceVaultOnlySecrets);
export type SealedAuditEntry = z.infer<typeof SealedAuditEntrySchema>;
