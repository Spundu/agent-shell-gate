import { describe, it, expect } from 'vitest';
import { SECRET_SHAPES, isSecretShaped, isStrongSecret } from './secret-shape.js';

// isSecretShaped gates every Write/Edit/NotebookEdit (RED), every browser fill/type (RED) and what redactArgs
// scrubs from the audit chain — and until the cold review (2026-09-17, TQ-3) it had no direct test: every
// negative in the suite was under 20 chars or had spaces, so the entropy branch had zero negatives and a
// git SHA, a UUID and `user_profile_settings_manager_v2` were all "secrets" (an Edit of a branch name was DENIED).
// Every fixture below is synthetic.

// One positive per SECRET_SHAPES entry, in list order (the parallel shape IS the coverage assertion).
const SHAPE_POSITIVES = [
  '-----BEGIN OPENSSH PRIVATE KEY-----', // pragma: allowlist secret — header only, no key material
  `AKIA${'ABCDEFGHIJKLMNOP'}`, // pragma: allowlist secret
  'const k = "sk-proj-abcDEF123ghiJKL456mnoPQR789stu";', // vendor-prefixed sk- key inside a line of code
  'sk_live_' + '4eC39HqLyjWDarjtT1zdp7dc', // pragma: allowlist secret
  'xoxb-1234567890-abcdefghij', // pragma: allowlist secret
  `npm_${'A'.repeat(36)}`,
  `ghp_${'B'.repeat(36)}`,
  'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abcdefghijklmnop', // JWT shape — pragma: allowlist secret
  '"api_key": "supersecretvalue"', // credential assignment (JSON form)
];
const ASSIGNMENT_FORMS = ['password: hunter22', 'API_KEY=abcdef123456', '<token>abcdef123456</token>', "secret='0123456789'"]; // pragma: allowlist secret
const ENTROPY_POSITIVES = [
  'k7Jx9pQ2mWvR8sT5nL3hF6dG1aZ4cB0eY7uI2oP', // pragma: allowlist secret — mixed-case + digits, no structure
  'AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBxY', // pragma: allowlist secret — Google-API-key shape (fake)
  '12345678901234567890', // digits-only: detectable since the alphabet-normalised rule (2026-08-28)
  'dGhpcyBpcyBhIHRlc3Qgb2YgYmFzZTY0IGVuY29kaW5n', // a base64 chunk — encoded content is treated as opaque
];
// DECIDED (fail-closed): structured hex is NOT an identifier. A 40-hex string is also a legacy GitHub token, a
// UUID is also a Heroku API key, and shape alone cannot tell an id from a credential. Kept secret-shaped.
const PINNED_HEX = ['a94a8fe5ccb19ba61c4c0873d391e987982fbbd3', '550e8400-e29b-41d4-a716-446655440000'];
// Plain identifiers: word-like segments joined by - _ / — these were all "secrets" before the fix.
const IDENTIFIERS = [
  'user_profile_settings_manager_v2', 'react-dom-server-legacy-node', 'my-very-long-feature-branch-name-here',
  'feature/improve-checkout-flow-v2', 'getUserProfileSettingsManagerV2', 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef',
  'correcthorsebatterystaple', 'sha256-abcdef-checksum-file', 'packages/safety/src/inspectors/bash-lexer',
];
const OTHER_NEGATIVES = ['a normal sentence with spaces', 'vscode', 'v1.2.3', 'user@example.com', 'https://example.com/path', '', '   '];
const CARDS = { valid: ['4111 1111 1111 1111', '4111111111111111', '4111-1111-1111-1111', '5500005555555559'], invalid: ['4111111111111112', '1111111111111111', '123456789012'] }; // pragma: allowlist secret — Luhn test PANs

describe('SECRET_SHAPES', () => {
  it('has one positive per entry, in order, and every entry fires on its own positive', () => {
    expect(SHAPE_POSITIVES).toHaveLength(SECRET_SHAPES.length);
    SECRET_SHAPES.forEach((re, i) => expect(re.test(SHAPE_POSITIVES[i] ?? ''), `SECRET_SHAPES[${i}] ${re}`).toBe(true));
    for (const v of [...SHAPE_POSITIVES, ...ASSIGNMENT_FORMS]) {
      expect(isStrongSecret(v), v).toBe(true);
      expect(isSecretShaped(v), v).toBe(true);
    }
  });
  it('the old alphanumeric-only sk- rule would have missed the vendor-prefixed forms', () => {
    expect(isStrongSecret('sk-ant-api03-Xq7bT2mKp9wLzR4vNc8sYhJd1gFa6eUiO0nB5tAlQ')).toBe(true); // pragma: allowlist secret
    expect(isStrongSecret('sk_test_' + 'abcdefghijklmnopqrstuv')).toBe(true); // pragma: allowlist secret
  });
});

describe('Luhn card detection', () => {
  it('matches a Luhn-valid PAN in every spacing and rejects Luhn-invalid or repeated-digit runs', () => {
    for (const c of CARDS.valid) expect(isStrongSecret(c), c).toBe(true);
    for (const c of CARDS.invalid) expect(isStrongSecret(c), c).toBe(false);
  });
});

describe('the generic entropy branch', () => {
  it('flags unstructured high-entropy tokens, and is NOT part of isStrongSecret', () => {
    for (const v of ENTROPY_POSITIVES) {
      expect(isSecretShaped(v), v).toBe(true);
      expect(isStrongSecret(v), v).toBe(false); // honest random identifiers must survive audit metadata
    }
  });
  it('keeps a git SHA and a UUID secret-shaped (decided: fail-closed, see PINNED_HEX)', () => {
    for (const v of PINNED_HEX) expect(isSecretShaped(v), v).toBe(true);
  });
  it('does NOT flag plain identifiers — word-like segments joined by - _ / — nor ordinary text', () => {
    for (const v of [...IDENTIFIERS, ...OTHER_NEGATIVES]) expect(isSecretShaped(v), JSON.stringify(v)).toBe(false);
  });
  it('an identifier with a credential ASSIGNMENT around it is still a secret (the shapes run first)', () => {
    expect(isSecretShaped('token=user_profile_settings_manager_v2')).toBe(true);
  });
});
