// Tiered autonomy — THE SAFETY LAW. Every action is classified GREEN / YELLOW / RED.
// Canonical wire form is lowercase (matches the DB CHECK constraints); TIER_LABEL gives
// the display form. Inspectors may ESCALATE a tier but never de-escalate (use `maxTier`).

export const TIERS = ['green', 'yellow', 'red'] as const;
export type Tier = (typeof TIERS)[number];

/** 🟢 act (safe/read-only/reversible) · 🟡 ask (money/account/promise/world-changing) · 🔴 block. */
export const TIER_RANK: Record<Tier, number> = { green: 0, yellow: 1, red: 2 };

export const TIER_LABEL: Record<Tier, 'GREEN' | 'YELLOW' | 'RED'> = {
  green: 'GREEN',
  yellow: 'YELLOW',
  red: 'RED',
};

/** Escalate-only combine: returns the higher-risk of two tiers. */
export function maxTier(a: Tier, b: Tier): Tier {
  return TIER_RANK[a] >= TIER_RANK[b] ? a : b;
}

/** True when `candidate` is at least as restrictive as `floor` (escalate-only guard). */
export function atLeastTier(candidate: Tier, floor: Tier): boolean {
  return TIER_RANK[candidate] >= TIER_RANK[floor];
}
