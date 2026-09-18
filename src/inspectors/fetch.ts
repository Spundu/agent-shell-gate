import { PAYMENT_CROWN_JEWEL_HOSTS } from '../policy.js';
import type { InspectorResult } from './result.js';

// Network reads (WebFetch/WebSearch) are RED until a MAIN-side egress allowlist exists — they can
// exfiltrate ingested data and ingest untrusted content. A payment/crown-jewel origin is RED with
// a specific reason.

export function inspectFetch(toolInput: Record<string, unknown>): InspectorResult {
  const candidates = [toolInput['url'], toolInput['prompt'], toolInput['query']];
  const target = candidates.find((value): value is string => typeof value === 'string') ?? '';
  if (PAYMENT_CROWN_JEWEL_HOSTS.some((re) => re.test(target))) {
    return { tier: 'red', reason: 'payment/crown-jewel origin (vault-only)' };
  }
  return { tier: 'red', reason: 'network egress (no MAIN egress allowlist yet)' };
}
