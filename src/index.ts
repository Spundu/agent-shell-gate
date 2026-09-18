// agent-shell-gate — THE LAW at the tool layer. The gate is the full classifier: an
// exact-name tool catalog (default-deny), argument inspectors (escalate-only GREEN/YELLOW/RED),
// the two-class nonce model (powerless vault-request allowed; local world-changing tools gated
// by the vault approval manifest), kill-switch, and fail-closed audit.

export * from './contracts/tier.js';
export type { ToolKind, AuditDecision, AuditCore, SealedAuditEntry } from './contracts/audit-record.js';
export { isSecretShaped, isStrongSecret } from './shared/secret-shape.js';
export { canonicalize } from './audit/canonicalize.js';
export type { AuditDraft } from './audit/seal.js';
export * from './types.js';
export * from './catalog.js';
export * from './policy.js';
export * from './classifier.js';
export * from './browser-context.js';
export * from './browser-ctx-store.js';
export * from './approval-manifest.js';
export * from './audit-submit.js';
export * from './redact-args.js';
export * from './audit-reclassify.js';
export * from './killswitch.js';
export * from './hook.js';
export * from './inspectors/index.js';
export { runConformance } from './conformance.js';
