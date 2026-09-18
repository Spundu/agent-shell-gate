// Vendored from the origin monorepo's `contracts` package (the leaf package of wire types shared by the
// gate, the audit chain, and the vault). Only the pieces the gate and its audit capstone need are here:
// the three-tier autonomy law (tier.ts) and the canonical audit record schema (audit-record.ts).

export * from './tier.js';
export * from './audit-record.js';
