// Deterministic JSON canonicalization (RFC-8785 / JCS subset) used as the pre-image for
// both the hash and the HMAC. Object keys are sorted by UTF-16 code unit; arrays preserve
// order; `undefined` members are dropped (as JSON.stringify does). Our audit records use
// only strings, integers, booleans, arrays, and nested objects — the exotic-float corners
// of full RFC-8785 are never exercised, and that invariant is enforced by the schema.

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value !== null && typeof value === 'object') {
    const input = value as Record<string, unknown>;
    const output: Record<string, unknown> = {};
    for (const key of Object.keys(input).sort()) {
      output[key] = sortValue(input[key]);
    }
    return output;
  }
  return value;
}

/** Canonical, stable string form of a JSON-compatible value. */
export function canonicalize(value: unknown): string {
  return JSON.stringify(sortValue(value));
}
