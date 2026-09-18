import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { actionHash } from './approval-manifest.js';

// Tests the REAL artifact the CLI runs: the bundled dist/hook-pre.cjs. Skipped if the bundle
// hasn't been built (a bare `npm test`); `npm run verify` builds it first so this runs.
const HOOK = join(dirname(fileURLToPath(import.meta.url)), '..', 'dist', 'hook-pre.cjs');
const built = existsSync(HOOK);

interface HookResult {
  hookSpecificOutput?: { permissionDecision: string };
  continue: boolean;
}

function runHook(input: unknown, outbox: string): HookResult {
  const res = spawnSync(process.execPath, [HOOK], {
    input: JSON.stringify(input),
    encoding: 'utf8',
    env: { ...process.env, JARVIS_AUDIT_OUTBOX: outbox },
  });
  return JSON.parse(res.stdout) as HookResult;
}

describe.skipIf(!built)('hook-pre.cjs (the real artifact)', () => {
  it('denies Bash, allows Read, and submits an audit draft for each', () => {
    const dir = mkdtempSync(join(tmpdir(), 'jarvis-hook-'));
    const outbox = join(dir, 'outbox.jsonl');
    try {
      const bash = runHook(
        { hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'rm -rf /' }, session_id: 's' },
        outbox,
      );
      expect(bash.hookSpecificOutput?.permissionDecision).toBe('deny');

      const read = runHook(
        { hook_event_name: 'PreToolUse', tool_name: 'Read', tool_input: { file_path: '/x' }, session_id: 's' },
        outbox,
      );
      expect(read.hookSpecificOutput?.permissionDecision).toBe('allow');

      // Submissions are newline-framed (F13: a leading + trailing newline), so filter blank lines
      // exactly as the drain does before counting the two audit drafts.
      const lines = readFileSync(outbox, 'utf8')
        .split('\n')
        .filter((line) => line.trim().length > 0);
      expect(lines).toHaveLength(2);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('fail-closes to deny on malformed stdin', () => {
    const dir = mkdtempSync(join(tmpdir(), 'jarvis-hook-'));
    try {
      const res = spawnSync(process.execPath, [HOOK], {
        input: 'not json',
        encoding: 'utf8',
        env: { ...process.env, JARVIS_AUDIT_OUTBOX: join(dir, 'o.jsonl') },
      });
      const out = JSON.parse(res.stdout) as HookResult;
      expect(out.hookSpecificOutput?.permissionDecision).toBe('deny');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  // cold review 2026-09-17 (TQ-5): stdin that PARSES but is not an event used to pass through (`continue:true`,
  // no decision) because runPreHook only checks `hook_event_name !== 'PreToolUse'`. Pinned as DENY.
  it('fail-closes to deny on stdin that parses but is not an event object', () => {
    const dir = mkdtempSync(join(tmpdir(), 'jarvis-hook-'));
    try {
      for (const raw of ['{}', '"str"', '[]', '42', 'true', 'null', '', '{"tool_name":"Bash"}']) {
        const res = spawnSync(process.execPath, [HOOK], {
          input: raw,
          encoding: 'utf8',
          env: { ...process.env, JARVIS_AUDIT_OUTBOX: join(dir, 'o.jsonl') },
        });
        const out = JSON.parse(res.stdout) as HookResult;
        expect(out.hookSpecificOutput?.permissionDecision, `stdin ${JSON.stringify(raw)}`).toBe('deny');
        expect(out.continue, `stdin ${JSON.stringify(raw)}`).toBe(false);
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('with NO audit outbox configured, even a read is denied ("no log, no action") — the real artifact', () => {
    const env = { ...process.env };
    delete env.JARVIS_AUDIT_OUTBOX;
    const res = spawnSync(process.execPath, [HOOK], {
      input: JSON.stringify({ hook_event_name: 'PreToolUse', tool_name: 'Read', tool_input: { file_path: '/x' }, session_id: 's' }),
      encoding: 'utf8',
      env,
    });
    const out = JSON.parse(res.stdout) as { hookSpecificOutput?: { permissionDecision: string; permissionDecisionReason: string } };
    expect(out.hookSpecificOutput?.permissionDecision).toBe('deny');
    expect(out.hookSpecificOutput?.permissionDecisionReason).toContain('no log, no action');
  });
});

const POST_HOOK = join(dirname(fileURLToPath(import.meta.url)), '..', 'dist', 'hook-post.cjs');
const postBuilt = existsSync(POST_HOOK);

describe.skipIf(!postBuilt)('hook-post.cjs (the real artifact)', () => {
  // cold review 2026-09-17 (TQ-5): dist/hook-post.cjs was never executed by a test. Swapping the grant/capture
  // order in main() survived the suite — and that mutant auto-allows the POST-click origin (one the human never
  // approved) instead of the PRE-click one. The GRANT-FIRST invariant was pinned only by a comment.
  const SHOP = 'uid=1_0 RootWebArea "Shop" url="https://shop.example.com/p/1"\nuid=1_4 button "Read more"';
  const EVIL = 'uid=2_0 RootWebArea "Evil" url="https://evil.example/landing"\nuid=2_4 button "Continue"';
  const run = (dir: string, input: unknown): { stdout: string; status: number | null } => {
    const res = spawnSync(process.execPath, [POST_HOOK], {
      input: typeof input === 'string' ? input : JSON.stringify(input),
      encoding: 'utf8',
      env: { ...process.env, JARVIS_AUDIT_OUTBOX: join(dir, 'o.jsonl'), JARVIS_BROWSER_CTX_DIR: dir },
    });
    return { stdout: res.stdout, status: res.status };
  };
  const post = (tool: string, text: string, sessionId = 'sid'): unknown => ({
    hook_event_name: 'PostToolUse', tool_name: tool, tool_input: { uid: '1_4' }, session_id: sessionId,
    tool_response: [{ type: 'text', text }],
  });
  const origins = (dir: string): unknown => JSON.parse(readFileSync(join(dir, 'sid.origins.json'), 'utf8'));

  it('never blocks: malformed stdin → {continue:true}, exit 0', () => {
    const dir = mkdtempSync(join(tmpdir(), 'jarvis-post-'));
    try {
      for (const raw of ['not json', '', 'null', '[]', '{}']) {
        const r = run(dir, raw);
        expect(r.status, raw).toBe(0);
        expect(JSON.parse(r.stdout), raw).toEqual({ continue: true });
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('GRANTS the PRE-click origin, then captures the POST-click page — never the other way round', () => {
    const dir = mkdtempSync(join(tmpdir(), 'jarvis-post-'));
    try {
      run(dir, post('mcp__chrome-devtools__take_snapshot', SHOP)); // the page the human saw and approved
      expect(existsSync(join(dir, 'sid.origins.json'))).toBe(false); // a snapshot grants nothing
      run(dir, post('mcp__chrome-devtools__click', EVIL)); // the click completed and LANDED on evil.example
      expect(origins(dir)).toEqual({ origins: ['https://shop.example.com'] }); // the PRE-click origin only
      const ctx = JSON.parse(readFileSync(join(dir, 'sid.json'), 'utf8')) as { pageUrl?: string };
      expect(ctx.pageUrl).toBe('https://evil.example/landing'); // and the context moved on to the new page
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('a non-click op grants nothing, even when it returns a snapshot', () => {
    const dir = mkdtempSync(join(tmpdir(), 'jarvis-post-'));
    try {
      run(dir, post('mcp__chrome-devtools__take_snapshot', SHOP));
      run(dir, post('mcp__chrome-devtools__hover', EVIL));
      run(dir, post('mcp__chrome-devtools__navigate_page', SHOP));
      expect(existsSync(join(dir, 'sid.origins.json'))).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe.skipIf(!built)('hook-pre.cjs Phase-2 gating (the real artifact)', () => {
  function gate(input: unknown): string | undefined {
    const dir = mkdtempSync(join(tmpdir(), 'jarvis-hook2-'));
    const killSwitch = join(dir, 'kill-switch.state');
    writeFileSync(killSwitch, 'active', 'utf8'); // no JARVIS_APPROVAL_MANIFEST ⇒ local tools denied
    // Since 2026-08-23 'active' also requires PROOF OF LIFE from the Supervisor: a fresh heartbeat in the
    // same directory (the gate derives the path, so there is no env var to set). Without it the real
    // artifact correctly denies everything non-read — which is exactly how this suite caught the change.
    writeFileSync(join(dir, 'supervisor.heartbeat'), JSON.stringify({ at: Date.now(), bootId: 'test', hostId: 'test' }), 'utf8');
    try {
      const res = spawnSync(process.execPath, [HOOK], {
        input: JSON.stringify(input),
        encoding: 'utf8',
        env: { ...process.env, JARVIS_AUDIT_OUTBOX: join(dir, 'o.jsonl'), JARVIS_KILLSWITCH_FILE: killSwitch },
      });
      return (JSON.parse(res.stdout) as HookResult).hookSpecificOutput?.permissionDecision;
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
  const pre = (tool: string, toolInput: Record<string, unknown>): unknown => ({
    hook_event_name: 'PreToolUse',
    tool_name: tool,
    tool_input: toolInput,
    session_id: 's',
  });

  it('blocks the dummy local checkout (no approval); the powerless vault request passes', () => {
    expect(gate(pre('mcp__local__execute_checkout', { approval_id: 'x' }))).toBe('deny');
    expect(gate(pre('mcp__vault__request', { verb: 'pay' }))).toBe('allow');
  });

  it('denies unknown tools and env-dump, allows read-only bash', () => {
    expect(gate(pre('mcp__evil__exfiltrate', {}))).toBe('deny');
    expect(gate(pre('Bash', { command: 'env' }))).toBe('deny');
    expect(gate(pre('Bash', { command: 'ls -la' }))).toBe('allow');
  });
});

describe.skipIf(!built)('hook-pre.cjs approval manifest (the real artifact, JARVIS_APPROVAL_MANIFEST set)', () => {
  // The env-var → manifestApproves wiring inside the bundle had no exec test (cold review 2026-09-17, TQ-1):
  // the in-process suite covers the parser; this proves the deployed hook reads the file the Supervisor names.
  const ACTION = { merchant: 'shop.example', amount: 1999, currency: 'GBP' };
  function gateWithManifest(toolInput: Record<string, unknown>, entries: unknown): string | undefined {
    const dir = mkdtempSync(join(tmpdir(), 'jarvis-hook3-'));
    const killSwitch = join(dir, 'kill-switch.state');
    const manifest = join(dir, 'approved-actions.json');
    writeFileSync(killSwitch, 'active', 'utf8');
    writeFileSync(join(dir, 'supervisor.heartbeat'), JSON.stringify({ at: Date.now(), bootId: 'test', hostId: 'test' }), 'utf8');
    writeFileSync(manifest, JSON.stringify(entries), 'utf8');
    try {
      const res = spawnSync(process.execPath, [HOOK], {
        input: JSON.stringify({ hook_event_name: 'PreToolUse', tool_name: 'mcp__local__execute_checkout', tool_input: toolInput, session_id: 's' }),
        encoding: 'utf8',
        env: {
          ...process.env,
          JARVIS_AUDIT_OUTBOX: join(dir, 'o.jsonl'),
          JARVIS_KILLSWITCH_FILE: killSwitch,
          JARVIS_APPROVAL_MANIFEST: manifest,
        },
      });
      return (JSON.parse(res.stdout) as HookResult).hookSpecificOutput?.permissionDecision;
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }

  it('allows the exact approved action and denies the same approval_id with a changed amount', () => {
    const entries = [{ approval_id: 'ap_1', action_hash: actionHash(ACTION), state: 'approved' }];
    expect(gateWithManifest({ ...ACTION, approval_id: 'ap_1' }, entries)).toBe('allow');
    expect(gateWithManifest({ ...ACTION, amount: 199900, approval_id: 'ap_1' }, entries)).toBe('deny');
    expect(gateWithManifest({ ...ACTION, approval_id: 'ap_forged' }, entries)).toBe('deny');
  });
});
