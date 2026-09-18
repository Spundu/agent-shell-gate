import { describe, it, expect } from 'vitest';
import { InMemoryKeyProvider, appendEntry, verifyChain, type AuditDraft } from './audit/index.js';
import type { SealedAuditEntry } from './contracts/index.js';
import { runPreHook, type HookEnv } from './hook.js';
import { isPreToolUseOutput, type HookInput } from './types.js';

// Capstone: a real session of tool calls flows through the full classifier/gate; every decision
// is submitted; the WRITER seals the submissions into the brain chain; the chain verifies and
// tampering with a logged decision is detected.

const env: HookEnv = { bootId: 'b', hostId: 'h', killSwitch: 'active', nowMs: () => 1 };
const keys = new InMemoryKeyProvider({ k1: Buffer.alloc(32, 5) }, 'k1');

const SESSION: { tool: string; input: Record<string, unknown>; expect: string }[] = [
  { tool: 'Read', input: { file_path: '/etc/os-release' }, expect: 'allow' },
  { tool: 'Bash', input: { command: 'rm -rf /' }, expect: 'deny' },
  { tool: 'Glob', input: { pattern: '*' }, expect: 'allow' },
  { tool: 'Write', input: { file_path: '/p/.claude/settings.json', content: 'x' }, expect: 'deny' },
  { tool: 'WebFetch', input: { url: 'https://api.stripe.com/v1/charges' }, expect: 'deny' },
  { tool: 'mcp__local__execute_checkout', input: { approval_id: 'x' }, expect: 'deny' },
];

describe('phase-2 gate → tamper-evident brain chain', () => {
  it('gates a session and logs every decision to a verifiable chain', () => {
    const drafts: AuditDraft[] = [];
    const submit = (d: AuditDraft): boolean => {
      drafts.push(d);
      return true;
    };

    const decisions = SESSION.map((step) => {
      const input: HookInput = { hook_event_name: 'PreToolUse', tool_name: step.tool, tool_input: step.input, session_id: 's' };
      const out = runPreHook(input, submit, env);
      return isPreToolUseOutput(out) ? out.hookSpecificOutput.permissionDecision : 'passthrough';
    });
    expect(decisions).toEqual(SESSION.map((s) => s.expect));

    const chain: SealedAuditEntry[] = [];
    let prev: SealedAuditEntry | null = null;
    for (const draft of drafts) {
      prev = appendEntry(prev, draft, keys, 'agent-pipe');
      chain.push(prev);
    }
    expect(chain).toHaveLength(SESSION.length);
    expect(verifyChain(chain, keys).ok).toBe(true);

    // Editing a logged decision (e.g. to hide that a payment fetch was blocked) is detected.
    const tampered = [...chain];
    tampered[4] = { ...chain[4]!, decision: { ...chain[4]!.decision!, action: 'allow' } };
    expect(verifyChain(tampered, keys).ok).toBe(false);
  });
});
