import type { AuditDecision } from './contracts/index.js';
import { classify } from './classifier.js';

// Re-derive the gate decision for a tool call HOST-SIDE, from tool name + already-parsed args. The
// Supervisor uses this to stamp the AUTHORITATIVE decision onto the sealed brain-chain record (F5):
// the Brain's self-submitted `decision`/`chain` are untrusted (a compromised Brain can bypass the
// in-process hook and append a forged line to the outbox), so the host independently classifies and
// records ITS verdict — a forged "allow" can never be laundered into the audit as legitimate.

export function reclassifyForAudit(toolName: string, toolInput: Record<string, unknown>): AuditDecision {
  const c = classify({ hook_event_name: 'PreToolUse', tool_name: toolName, tool_input: toolInput });
  const action: AuditDecision['action'] =
    c.gating === 'vault-request'
      ? 'allow'
      : c.gating === 'local-approval'
        ? 'deny' // no manifest consulted at audit time → records the default-deny posture
        : c.tier === 'green'
          ? 'allow'
          : c.tier === 'yellow'
            ? 'ask'
            : 'deny';
  return { tier: c.tier, action, source: 'host-reclassified', reason: c.reason };
}
