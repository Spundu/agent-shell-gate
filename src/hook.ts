import type { AuditDraft } from './audit/index.js';
import type { Tier } from './contracts/index.js';
import type { BrowserSession } from './browser-context.js';
import { classify } from './classifier.js';
import { redactArgs } from './redact-args.js';
import { manifestApproves } from './approval-manifest.js';
import type { AuditSubmit } from './audit-submit.js';
import type { KillSwitchState } from './killswitch.js';
import type { HookInput, PassThroughOutput, PermissionDecision, PreToolUseOutput } from './types.js';

export interface HookEnv {
  bootId: string;
  hostId: string;
  killSwitch: KillSwitchState;
  manifestPath?: string;
  nowMs: () => number;
}

export interface GateDecision {
  action: PermissionDecision;
  tier: Tier;
  reason: string;
}

/**
 * Turn a classification into a decision. Order (P0-3): kill-switch (paused → deny non-read) →
 * vault-request is powerless (allow) → local-approval is gated (deny unless the vault manifest
 * covers the exact action) → otherwise tier maps to action (green→allow, yellow→ask, red→deny).
 */
export function decide(input: HookInput, env: HookEnv, session?: BrowserSession): GateDecision {
  const c = classify(input, session);

  if (env.killSwitch === 'paused' && !c.isRead) {
    return { action: 'deny', tier: 'red', reason: 'kill-switch:paused' };
  }
  if (c.gating === 'vault-request') {
    return { action: 'allow', tier: c.tier, reason: 'vault request (powerless; the vault gates internally)' };
  }
  if (c.gating === 'local-approval') {
    return manifestApproves(input, env.manifestPath)
      ? { action: 'allow', tier: c.tier, reason: 'covered by a vault approval' }
      : { action: 'deny', tier: 'red', reason: 'gated:no-approval' };
  }
  const action: PermissionDecision = c.tier === 'green' ? 'allow' : c.tier === 'yellow' ? 'ask' : 'deny';
  return { action, tier: c.tier, reason: c.reason };
}

function agentContext(input: HookInput): AuditDraft['agent'] {
  const declared = input.agent;
  return {
    name: declared?.name ?? 'brain',
    kind: declared?.kind ?? 'main',
    ...(declared?.parent ? { parent: declared.parent } : {}),
  };
}

function preDraft(input: HookInput, d: GateDecision, env: HookEnv): AuditDraft {
  const { args_canonical, redactions } = redactArgs(input.tool_input ?? {});
  return {
    v: 1,
    chain: 'brain',
    call_id: `${input.session_id ?? 'sess'}:${env.nowMs()}`,
    session_id: input.session_id ?? 'unknown',
    agent: agentContext(input),
    ts_unix_ms: env.nowMs(),
    boot_id: env.bootId,
    host_id: env.hostId,
    phase: 'pre',
    tool: input.tool_name,
    args_canonical,
    ...(redactions.length > 0 ? { redactions } : {}),
    decision: { tier: d.tier, action: d.action, source: 'phase2-classifier', reason: d.reason },
  };
}

function postDraft(input: HookInput, env: HookEnv): AuditDraft {
  return {
    v: 1,
    chain: 'brain',
    call_id: `${input.session_id ?? 'sess'}:${env.nowMs()}`,
    session_id: input.session_id ?? 'unknown',
    agent: agentContext(input),
    ts_unix_ms: env.nowMs(),
    boot_id: env.bootId,
    host_id: env.hostId,
    phase: 'post',
    tool: input.tool_name,
  };
}

function output(decision: PermissionDecision, reason: string, cont: boolean): PreToolUseOutput {
  return {
    hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: decision, permissionDecisionReason: reason },
    continue: cont,
  };
}

export const allowOutput = (reason: string): PreToolUseOutput => output('allow', reason, true);
export const askOutput = (reason: string): PreToolUseOutput => output('ask', reason, true);
export const denyOutput = (reason: string): PreToolUseOutput => output('deny', reason, false);

/**
 * The unbypassable PreToolUse gate. Fail-closed: an ALLOW or ASK is never returned unless the
 * audit event was accepted ("no log, no action"). A denied call denies regardless. Non-PreToolUse
 * events pass through.
 */
export function runPreHook(
  input: HookInput,
  submit: AuditSubmit,
  env: HookEnv,
  session?: BrowserSession,
): PreToolUseOutput | PassThroughOutput {
  if (input.hook_event_name !== 'PreToolUse') return { continue: true };
  const decision = decide(input, env, session);
  const audited = submit(preDraft(input, decision, env));
  if (decision.action !== 'deny' && !audited) {
    return denyOutput('audit-write-failed: no log, no action');
  }
  if (decision.action === 'deny') return denyOutput(decision.reason);
  if (decision.action === 'ask') return askOutput(decision.reason);
  return allowOutput(decision.reason);
}

/** PostToolUse: best-effort record of the completed call; never blocks. */
export function runPostHook(input: HookInput, submit: AuditSubmit, env: HookEnv): PassThroughOutput {
  if (input.hook_event_name === 'PostToolUse') submit(postDraft(input, env));
  return { continue: true };
}
