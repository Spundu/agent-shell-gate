import { describe, it, expect } from 'vitest';
import { reclassifyForAudit } from './audit-reclassify.js';
import { parseSnapshotText, type BrowserSession } from './browser-context.js';
import { decide, type HookEnv } from './hook.js';
import type { HookInput } from './types.js';

// reclassifyForAudit is what the Supervisor stamps onto the SEALED brain-chain record as the authoritative
// decision (apps/host/src/audit-sanitize.ts). It hand-duplicates decide()'s tier→action table and had no
// parity test (cold review 2026-09-17, TQ-6). The first block pins agreement over one input per gating class
// and tier; the second pins the divergences that are INTENTIONAL because the audit path has only
// (toolName, toolInput) — no cwd, no agent depth, no browser session, no kill-switch, no manifest.

const ENV: HookEnv = { bootId: 'b', hostId: 'h', killSwitch: 'active', nowMs: () => 0 };
const pre = (tool: string, toolInput: Record<string, unknown>, extra: Partial<HookInput> = {}): HookInput => ({
  hook_event_name: 'PreToolUse', tool_name: tool, tool_input: toolInput, session_id: 's', ...extra,
});

describe('reclassifyForAudit — parity with decide() on plain inputs', () => {
  const CASES: [string, Record<string, unknown>][] = [
    ['Read', { file_path: '/home/user/code/app.ts' }], // read, green → allow
    ['Read', { file_path: '/home/user/.ssh/id_rsa' }], // read, red → deny
    ['Grep', { pattern: 'x', path: '/home/user' }], // read, yellow (broad root) → ask
    ['Bash', { command: 'ls -la /etc' }], // green → allow
    ['Bash', { command: 'make build' }], // yellow → ask
    ['Bash', { command: 'rm -rf /' }], // red → deny
    ['Bash', { command: 'cat $KUBECONFIG' }], // yellow (expansion) → ask
    ['Write', { file_path: '/home/user/x.txt', content: 'y' }], // world-changing, yellow → ask
    ['Write', { file_path: '/p/.claude/settings.json', content: 'y' }], // protected → deny
    ['WebFetch', { url: 'https://example.com' }], // red → deny
    ['mcp__vault__request', { verb: 'pay' }], // vault-request → allow (powerless)
    ['mcp__local__execute_checkout', { approval_id: 'x' }], // local-approval, no manifest → deny
    ['mcp__evil__exfiltrate', {}], // unknown → deny
    ['TotallyMadeUpTool', {}], // default-deny
    ['mcp__chrome-devtools__navigate_page', { url: 'https://github.com/' }], // crown-jewel origin → deny
    ['mcp__chrome-devtools__navigate_page', { url: 'https://docs.example.com/' }], // ordinary → ask
    ['mcp__chrome-devtools__evaluate_script', { function: '() => 1' }], // red → deny
  ];
  it.each(CASES)('%s %j', (tool, toolInput) => {
    const audit = reclassifyForAudit(tool, toolInput);
    const gate = decide(pre(tool, toolInput), ENV);
    expect({ tier: audit.tier, action: audit.action }).toEqual({ tier: gate.tier, action: gate.action });
    expect(audit.source).toBe('host-reclassified');
  });
});

describe('reclassifyForAudit — documented divergences (context the audit path does not have)', () => {
  it('agent depth: the gate denies a world-changing call past the depth cap; the audit record shows the plain tier', () => {
    const deep = pre('Write', { file_path: '/home/user/x', content: 'y' }, { agent: { name: 'c', kind: 'subagent', parent: 'brain', depth: 9 } });
    expect(decide(deep, ENV).action).toBe('deny');
    expect(reclassifyForAudit('Write', { file_path: '/home/user/x', content: 'y' }).action).toBe('ask');
  });
  it('kill-switch: the gate denies everything non-read while paused; the audit path has no kill-switch', () => {
    expect(decide(pre('Bash', { command: 'ls' }), { ...ENV, killSwitch: 'paused' }).action).toBe('deny');
    expect(reclassifyForAudit('Bash', { command: 'ls' }).action).toBe('allow');
  });
  it('approval manifest: the gate can ALLOW a covered mcp__local__ call; the audit path always records deny', () => {
    // (the positive gate path is pinned in approval-manifest.test.ts; here only the audit posture matters)
    expect(reclassifyForAudit('mcp__local__execute_checkout', { approval_id: 'x' }).action).toBe('deny');
  });
  it('browser session: a benign click on a session-approved origin is allowed by the gate, asked in the audit', () => {
    const ctx = parseSnapshotText('uid=9_0 RootWebArea "Docs" url="https://shop.test/docs"\nuid=9_5 button "Read more"');
    const session: BrowserSession = { ctx, allowedOrigins: ['https://shop.test'] };
    expect(decide(pre('mcp__chrome-devtools__click', { uid: '9_5' }), ENV, session).action).toBe('allow');
    expect(reclassifyForAudit('mcp__chrome-devtools__click', { uid: '9_5' }).action).toBe('ask');
  });
  // cwd is the fifth dropped-context dimension, but it is NOT asserted here: reclassifyForAudit gets no cwd, so
  // it resolves a RELATIVE path against the HOST PROCESS cwd (resolveToolPath -> resolve(path)), which makes its
  // verdict for a relative write environment-dependent — not a fixed property of (toolName, toolInput). Pinning a
  // tier for it produced a test that passed under packages/safety (a protected cwd) and failed from the repo root.
  // The gate's own cwd resolution IS pinned deterministically with an explicit cwd in conformance.ts and read.ts.
});
