import { describe, it, expect } from 'vitest';
import type { AuditDraft } from './audit/index.js';
import { runPreHook, runPostHook, decide, type HookEnv } from './hook.js';
import { isPreToolUseOutput, type HookInput } from './types.js';

const env: HookEnv = { bootId: 'b', hostId: 'h', killSwitch: 'active', nowMs: () => 1 };
const pre = (tool: string, input: Record<string, unknown> = {}): HookInput => ({
  hook_event_name: 'PreToolUse',
  tool_name: tool,
  tool_input: input,
  session_id: 's1',
});

function recorder(): { submit: (d: AuditDraft) => boolean; drafts: AuditDraft[] } {
  const drafts: AuditDraft[] = [];
  return {
    submit: (d) => {
      drafts.push(d);
      return true;
    },
    drafts,
  };
}

function decision(out: ReturnType<typeof runPreHook>): string {
  return isPreToolUseOutput(out) ? out.hookSpecificOutput.permissionDecision : 'passthrough';
}

describe('decide', () => {
  it('maps green→allow, yellow→ask, red→deny', () => {
    expect(decide(pre('Read', { file_path: '/x' }), env).action).toBe('allow');
    expect(decide(pre('Write', { file_path: '/home/x' }), env).action).toBe('ask');
    expect(decide(pre('Bash', { command: 'rm -rf /' }), env).action).toBe('deny');
  });

  it('vault request is allowed (powerless)', () => {
    expect(decide(pre('mcp__vault__request', { verb: 'pay' }), env).action).toBe('allow');
  });

  it('local tool is denied without a manifest approval', () => {
    const d = decide(pre('mcp__local__execute_checkout', { approval_id: 'x' }), env);
    expect(d.action).toBe('deny');
    expect(d.reason).toBe('gated:no-approval');
  });

  it('kill-switch paused denies non-read, allows read', () => {
    const paused: HookEnv = { ...env, killSwitch: 'paused' };
    expect(decide(pre('Bash', { command: 'ls' }), paused).action).toBe('deny');
    expect(decide(pre('Read', { file_path: '/x' }), paused).action).toBe('allow');
  });
});

describe('runPreHook (the gate)', () => {
  it('allows a read and records exactly one audit draft', () => {
    const r = recorder();
    const out = runPreHook(pre('Read', { file_path: '/x' }), r.submit, env);
    expect(decision(out)).toBe('allow');
    expect(r.drafts).toHaveLength(1);
    expect(r.drafts[0]!.decision?.action).toBe('allow');
  });

  it('asks on a workspace write, denies a dangerous bash', () => {
    expect(decision(runPreHook(pre('Write', { file_path: '/home/x' }), () => true, env))).toBe('ask');
    expect(decision(runPreHook(pre('Bash', { command: 'rm -rf /' }), () => true, env))).toBe('deny');
  });

  it('fail-closed: allow OR ask with a failing audit becomes deny', () => {
    expect(decision(runPreHook(pre('Read', { file_path: '/x' }), () => false, env))).toBe('deny');
    expect(decision(runPreHook(pre('Write', { file_path: '/home/x' }), () => false, env))).toBe('deny');
  });

  it('passes through non-PreToolUse events', () => {
    const out = runPreHook({ ...pre('Read'), hook_event_name: 'SessionStart' }, () => true, env);
    expect(isPreToolUseOutput(out)).toBe(false);
    expect(out.continue).toBe(true);
  });
});

describe('runPostHook', () => {
  it('records a post draft and never blocks', () => {
    const r = recorder();
    const out = runPostHook({ hook_event_name: 'PostToolUse', tool_name: 'Read', session_id: 's1' }, r.submit, env);
    expect(out.continue).toBe(true);
    expect(r.drafts[0]!.phase).toBe('post');
  });
});
