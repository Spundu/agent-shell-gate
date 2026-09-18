import { createHash } from 'node:crypto';
import { canonicalize } from './audit/index.js';
import { isSecretShaped, isStrongSecret } from './shared/secret-shape.js';

// Canonicalize a tool's arguments for the audit chain, replacing any secret-shaped string value
// with a stable, non-reversible digest so a secret never lands on the (no-secret) brain chain (F8).
// Used by the hook on the honest path AND re-applied host-side by the Supervisor on drain, so even
// a forged outbox line carrying a plaintext secret is redacted before it is sealed.

export interface RedactedArgs {
  /** RFC-8785 JCS string of the (redacted) arguments. */
  args_canonical: string;
  /** Field paths (dot/bracket notation) whose secret-shaped value was replaced. */
  redactions: string[];
}

function digest(value: string): string {
  return `[redacted:sha256:${createHash('sha256').update(value, 'utf8').digest('hex').slice(0, 16)}]`;
}

export function redactArgs(toolInput: Record<string, unknown>): RedactedArgs {
  const redactions: string[] = [];
  const walk = (value: unknown, path: string): unknown => {
    if (typeof value === 'string') {
      if (isSecretShaped(value)) {
        redactions.push(path || '.');
        return digest(value);
      }
      return value;
    }
    // A numeric secret (e.g. a Luhn-valid card sent as a JSON number) would otherwise escape the
    // string-only walk and seal in plaintext (RT round-4 #5). Use the STRONG check so honest numeric
    // ids are not mangled.
    if (typeof value === 'number' && Number.isFinite(value)) {
      const s = String(value);
      if (isStrongSecret(s)) {
        redactions.push(path || '.');
        return digest(s);
      }
      return value;
    }
    if (Array.isArray(value)) return value.map((v, i) => walk(v, `${path}[${i}]`));
    if (value && typeof value === 'object') {
      const obj = value as Record<string, unknown>;
      const out: Record<string, unknown> = {};
      for (const key of Object.keys(obj)) {
        // A secret-shaped KEY name would otherwise seal in plaintext; use the SAME predicate as the
        // value path (RT round-3 #D / round-4 — close the key/value asymmetry).
        const outKey = isSecretShaped(key) ? digest(key) : key;
        if (outKey !== key) redactions.push(path ? `${path}.<key>` : '<key>');
        out[outKey] = walk(obj[key], path ? `${path}.${key}` : key);
      }
      return out;
    }
    return value;
  };
  const redacted = walk(toolInput, '');
  return { args_canonical: canonicalize(redacted), redactions };
}
