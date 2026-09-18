import { describe, it, expect } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { actionHash, manifestApproves } from './approval-manifest.js';
import { decide, type HookEnv } from './hook.js';
import type { HookInput } from './types.js';

// manifestApproves is the ONLY path on which a world-changing mcp__local__* tool is ALLOWED. Until the cold
// review (2026-09-17, TQ-1) no test set `manifestPath`, so lines 26-40 never ran: a mutant that dropped all
// three guards (`entries.some((e) => e.state !== 'denied')`) passed 223/223 and both probes, and a forged
// approval_id against a manifest for a DIFFERENT action decided `allow`. Every guard below fails that mutant.

const TOOL = 'mcp__local__execute_checkout';
const ACTION = { merchant: 'shop.example', amount: 1999, currency: 'GBP' };
const APPROVAL_ID = 'ap_01HXYZ';

const pre = (toolInput: Record<string, unknown>): HookInput => ({
  hook_event_name: 'PreToolUse', tool_name: TOOL, tool_input: toolInput, session_id: 's',
});
const withManifest = (manifestPath: string | undefined): HookEnv => ({
  bootId: 'b', hostId: 'h', killSwitch: 'active', nowMs: () => 0, ...(manifestPath ? { manifestPath } : {}),
});

function writeManifest(dir: string, content: unknown, raw = false): string {
  const path = join(dir, 'approved-actions.json');
  writeFileSync(path, raw ? String(content) : JSON.stringify(content), 'utf8');
  return path;
}

describe('actionHash — the contract the vault signs against', () => {
  it('excludes the powerless approval_id handle and is independent of key order', () => {
    const base = actionHash(ACTION);
    expect(base).toMatch(/^[0-9a-f]{64}$/);
    expect(actionHash({ ...ACTION, approval_id: APPROVAL_ID })).toBe(base); // the handle is not part of the action
    expect(actionHash({ currency: 'GBP', amount: 1999, merchant: 'shop.example' })).toBe(base); // JCS canonical order
  });
  it('changes when ANY action field changes', () => {
    const base = actionHash(ACTION);
    expect(actionHash({ ...ACTION, amount: 199900 })).not.toBe(base);
    expect(actionHash({ ...ACTION, merchant: 'evil.example' })).not.toBe(base);
    expect(actionHash({ ...ACTION, note: 'x' })).not.toBe(base); // an ADDED field is a different action
  });
});

describe('manifestApproves / decide — the mcp__local__* allow path', () => {
  let dir = '';
  const setup = (): void => { dir = mkdtempSync(join(tmpdir(), 'jarvis-manifest-')); };
  const teardown = (): void => { rmSync(dir, { recursive: true, force: true }); };
  const approved = (overrides: Partial<{ approval_id: string; action_hash: string; state: string }> = {}) => [
    { approval_id: APPROVAL_ID, action_hash: actionHash(ACTION), state: 'approved', ...overrides },
  ];
  const run = (manifest: unknown, toolInput: Record<string, unknown>, raw = false): ReturnType<typeof decide> => {
    setup();
    try {
      return decide(pre(toolInput), withManifest(writeManifest(dir, manifest, raw)));
    } finally {
      teardown();
    }
  };
  const call = { ...ACTION, approval_id: APPROVAL_ID };

  it('ALLOWS when an approved entry matches both the approval_id and the action hash', () => {
    const d = run(approved(), call);
    expect(d.action).toBe('allow');
    expect(d.reason).toBe('covered by a vault approval');
  });

  it('DENIES when any tool_input field differs from the approved action (hash mismatch)', () => {
    expect(run(approved(), { ...call, amount: 199900 }).action).toBe('deny'); // show £19.99, submit £1,999.00
    expect(run(approved(), { ...call, merchant: 'evil.example' }).action).toBe('deny');
    expect(run(approved(), { ...call, extra: true }).action).toBe('deny');
    expect(run(approved(), { ...call, amount: 199900 }).reason).toBe('gated:no-approval');
  });

  it('DENIES an approval_id that does not match the entry — even for the right action', () => {
    expect(run(approved(), { ...ACTION, approval_id: 'ap_forged' }).action).toBe('deny');
    expect(run(approved({ approval_id: 'ap_other' }), call).action).toBe('deny');
  });

  it('DENIES every state other than approved', () => {
    for (const state of ['pending', 'revoked', 'denied', 'executed', 'APPROVED', '']) {
      expect(run(approved({ state }), call).action, state).toBe('deny');
    }
  });

  it('DENIES a missing approval_id, or one that is not a string', () => {
    expect(run(approved(), ACTION).action).toBe('deny');
    expect(run(approved(), { ...ACTION, approval_id: 42 }).action).toBe('deny');
    expect(run(approved(), { ...ACTION, approval_id: [APPROVAL_ID] }).action).toBe('deny');
  });

  it('fails CLOSED on a corrupt, non-array, empty or missing manifest, or no manifest path at all', () => {
    expect(run('{not json', call, true).action).toBe('deny');
    expect(run({ approval_id: APPROVAL_ID, action_hash: actionHash(ACTION), state: 'approved' }, call).action).toBe('deny'); // object, not array
    expect(run([], call).action).toBe('deny');
    expect(run('', call, true).action).toBe('deny');
    expect(run(null, call).action).toBe('deny');
    setup();
    try {
      expect(decide(pre(call), withManifest(join(dir, 'does-not-exist.json'))).action).toBe('deny');
      expect(manifestApproves(pre(call), join(dir, 'does-not-exist.json'))).toBe(false);
      expect(manifestApproves(pre(call), undefined)).toBe(false);
      expect(manifestApproves(pre(call), '')).toBe(false);
    } finally {
      teardown();
    }
  });

  // re-adversarial-2 (cold review round 2, 2026-09-18): a JSON array whose elements are NON-objects made
  // manifestApproves THROW on `e.state` (e.g. [null]) instead of failing closed — an uncaught crash on the
  // gate's decision path (hook.ts calls it with no try/catch). Fix the CLASS: every non-object element is
  // skipped, never dereferenced, so it can neither throw nor forge an approval.
  it('fails CLOSED (never throws) on an array of NON-object entries', () => {
    expect(run([null], call).action, '[null]').toBe('deny');
    expect(run([123], call).action, '[123]').toBe('deny');
    expect(run([{}], call).action, '[{}]').toBe('deny');
    expect(run(['ap_forged'], call).action, '[string]').toBe('deny');
    expect(run([true], call).action, '[bool]').toBe('deny');
    expect(run([[APPROVAL_ID, actionHash(ACTION), 'approved']], call).action, '[nested array]').toBe('deny');
    expect(run([null, 123, {}], call).action, '[mixed non-objects]').toBe('deny');
  });

  it('a malformed sibling neither sinks a valid approval nor forges one', () => {
    // a null next to the real, matching entry: the null is skipped, the valid entry still ALLOWS
    expect(run([null, ...approved()], call).action, '[null, valid]').toBe('allow');
    expect(run([123, ...approved(), {}], call).action, '[123, valid, {}]').toBe('allow');
    // a null next to an entry that does NOT match: still DENY (the null cannot fabricate approval)
    expect(run([null, ...approved({ action_hash: actionHash({ ...ACTION, amount: 1 }) })], call).action, '[null, wrong-hash]').toBe('deny');
  });

  it('matches by ENTRY, not by field union: two half-matching entries do not add up to an approval', () => {
    const manifest = [
      { approval_id: APPROVAL_ID, action_hash: actionHash({ ...ACTION, amount: 1 }), state: 'approved' },
      { approval_id: 'ap_other', action_hash: actionHash(ACTION), state: 'approved' },
    ];
    expect(run(manifest, call).action).toBe('deny');
  });

  it('a manifest never lifts a kill-switch pause (deny precedes the approval check)', () => {
    setup();
    try {
      const env: HookEnv = { ...withManifest(writeManifest(dir, approved())), killSwitch: 'paused' };
      expect(decide(pre(call), env).action).toBe('deny');
    } finally {
      teardown();
    }
  });
});
