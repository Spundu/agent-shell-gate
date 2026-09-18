import { describe, it, expect } from 'vitest';
import { FIXTURES, decisionOf, runConformance } from './conformance.js';

// The corpus used to collapse into ONE boolean (cold review 2026-09-17, TQ-11): truncating FIXTURES to 8
// entries still passed, and a failure read "expected false to be true". Each fixture is now its own test
// (a failure names the fixture and shows got/expected), the corpus has a size floor, and names are unique.
const MIN_FIXTURES = 284; // the size on the day the guard was added (raised for the round-3 structural fixtures, then the cold-review-2026-09 host-escape over-block fixtures) — never lower this, only raise it

describe('spine conformance (model-free)', () => {
  it(`has at least ${MIN_FIXTURES} fixtures with unique names`, () => {
    expect(FIXTURES.length).toBeGreaterThanOrEqual(MIN_FIXTURES);
    expect(new Set(FIXTURES.map((f) => f.name)).size).toBe(FIXTURES.length);
  });

  it.each(FIXTURES.map((f) => [f.name, f] as const))('%s', (_name, fixture) => {
    expect(decisionOf(fixture.input, true, undefined, fixture.session)).toBe(fixture.expect);
  });

  it('runConformance() (the boot-time gate) passes every fixture plus the fail-closed and kill-switch checks', async () => {
    expect(await runConformance()).toBe(true);
  });
});
