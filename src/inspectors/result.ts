import type { Tier } from '../contracts/index.js';

/** An inspector's verdict on a tool's arguments. The classifier takes maxTier(base, inspector). */
export interface InspectorResult {
  tier: Tier;
  reason: string;
}

const RANK: Readonly<Record<Tier, number>> = { green: 0, yellow: 1, red: 2 };

/**
 * The STRONGEST verdict in a set — the structural answer to a bug class that has now been found four
 * separate times in this repo (F1 silent-submit; the click-resolution downgrade; and on 2026-08-28 the
 * click branch dropping its pendings, the `file://` early return, and the originConflict early return).
 *
 * THE SHAPE: an argument inspector is escalate-only, but it was written as a chain of `return`s. Any branch
 * that `return`s a YELLOW silently discards every RED BELOW it that rests on DIFFERENT evidence — a
 * different argument, a different part of the page context. Each occurrence was fixed by re-ordering that
 * one branch, which is a band-aid: the next branch added re-opens it. Ordering is not the invariant;
 * "take the maximum over ALL applicable checks" is.
 *
 * So an inspector collects verdicts and ends with `strongest(...)`. Adding a check in the wrong place then
 * costs nothing, and no branch can drop a pending one.
 *
 * TIES KEEP THE FIRST verdict (`>` not `>=`), so the reason a human sees stays the earliest — and most
 * specific — description at that tier, exactly as the old ordered chain produced.
 */
export function strongest(...results: readonly (InspectorResult | null | undefined)[]): InspectorResult | null {
  let best: InspectorResult | null = null;
  for (const r of results) {
    if (!r) continue;
    if (best === null || RANK[r.tier] > RANK[best.tier]) best = r;
  }
  return best;
}
