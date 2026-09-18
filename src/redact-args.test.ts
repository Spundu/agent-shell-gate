import { describe, it, expect } from 'vitest';
import { redactArgs } from './redact-args.js';

const CARD = 4111111111111111; // pragma: allowlist secret — Luhn-valid test card (number form)

describe('redactArgs (F8 audit-arg redaction)', () => {
  it('redacts a secret-shaped string value', () => {
    const token = `AKIA${'ABCDEFGHIJKLMNOP'}`; // pragma: allowlist secret
    const r = redactArgs({ command: 'ls', token });
    expect(r.args_canonical).not.toContain(token);
    expect(r.redactions).toContain('token');
  });

  it('redacts a high-entropy token used as an object KEY (RT round-4 #4)', () => {
    const key = 'k7Jx9pQ2mWvR8sT5nL3hF6dG1aZ4cB0eY7uI2oP'; // pragma: allowlist secret — high-entropy key
    const r = redactArgs({ [key]: 'x' });
    expect(r.args_canonical).not.toContain(key);
    expect(r.redactions).toContain('<key>');
  });

  it('redacts a Luhn-valid card passed as a JSON number (RT round-4 #5)', () => {
    const r = redactArgs({ note: 'card', cc: CARD });
    expect(r.args_canonical).not.toContain(String(CARD));
    expect(r.redactions).toContain('cc');
  });

  it('leaves ordinary args and honest numeric ids intact', () => {
    const r = redactArgs({ command: 'ls -la', count: 42, ts: 1717171717 });
    expect(r.redactions).toHaveLength(0);
    expect(r.args_canonical).toContain('42');
  });
});
