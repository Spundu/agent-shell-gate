import { describe, it, expect } from 'vitest';
import { canonicalize } from './canonicalize.js';

describe('canonicalize (JCS subset)', () => {
  it('is independent of key insertion order', () => {
    expect(canonicalize({ b: 1, a: 2 })).toBe(canonicalize({ a: 2, b: 1 }));
    expect(canonicalize({ a: 2, b: 1 })).toBe('{"a":2,"b":1}');
  });

  it('sorts nested object keys but preserves array order', () => {
    expect(canonicalize({ z: [3, 1, 2], a: { y: 1, x: 2 } })).toBe('{"a":{"x":2,"y":1},"z":[3,1,2]}');
  });

  it('drops undefined members (as JSON does)', () => {
    expect(canonicalize({ a: 1, b: undefined })).toBe('{"a":1}');
  });
});
