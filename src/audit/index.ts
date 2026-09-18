// Vendored from the origin monorepo's `audit` package — tamper-evident audit chain primitives
// (hash-chain + HMAC seal + verify). Pure crypto, no I/O. The gate itself uses only `canonicalize`
// (for the redacted-args pre-image and the approval-manifest action hash) and the `AuditDraft` type;
// `appendEntry`/`verifyChain`/`InMemoryKeyProvider` are here so the lockdown capstone test can prove
// that a gated session seals into a chain that detects tampering.

export * from './canonicalize.js';
export * from './keys.js';
export * from './seal.js';
export * from './verify.js';
