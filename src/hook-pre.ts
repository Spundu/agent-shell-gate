// External PreToolUse hook executable. Bundled to dist/hook-pre.cjs and invoked by the
// interactive Claude CLI as `node .../hook-pre.cjs`. Reads HookInput JSON on stdin, writes a
// permission-decision JSON on stdout. Fail-closed on every error path.

import { outboxSubmit, type AuditSubmit } from './audit-submit.js';
import { ctxDirFromEnv, loadBrowserContext, loadAllowedOrigins } from './browser-ctx-store.js';
import { denyOutput, runPreHook, type HookEnv } from './hook.js';
import { readKillSwitchFile } from './killswitch.js';
import type { HookInput } from './types.js';

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString('utf8');
}

function hookEnv(): HookEnv {
  const manifestPath = process.env.JARVIS_APPROVAL_MANIFEST;
  return {
    bootId: process.env.JARVIS_BOOT_ID ?? 'dev-boot',
    hostId: process.env.JARVIS_HOST_ID ?? 'dev-host',
    killSwitch: readKillSwitchFile(process.env.JARVIS_KILLSWITCH_FILE),
    ...(manifestPath ? { manifestPath } : {}),
    nowMs: () => Date.now(),
  };
}

function submitter(): AuditSubmit {
  const outbox = process.env.JARVIS_AUDIT_OUTBOX;
  // No configured audit channel ⇒ submission "fails" ⇒ nothing is allowed (fail-closed).
  return outbox ? outboxSubmit(outbox) : () => false;
}

async function main(): Promise<void> {
  const raw = await readStdin();
  let input: HookInput;
  try {
    input = JSON.parse(raw) as HookInput;
  } catch {
    process.stdout.write(JSON.stringify(denyOutput('hook-input-parse-error')));
    return;
  }
  // DECIDED (cold review 2026-09-17, TQ-5): stdin that parses but is not an EVENT — `{}`, `"str"`, `[]`, `42`,
  // `true` — is denied, not passed through. This executable is registered for PreToolUse only (deploy.ts), so
  // Claude Code always sends an object with a hook_event_name; anything else is malformed input on the gate's
  // stdin, and the fail-closed answer to malformed input is the same as for unparseable input. A genuine
  // OTHER event (`hook_event_name: 'Stop'`) still passes through inside runPreHook.
  if (input === null || typeof input !== 'object' || Array.isArray(input) || typeof input.hook_event_name !== 'string') {
    process.stdout.write(JSON.stringify(denyOutput('hook-input-shape-error')));
    return;
  }
  // Load this session's browser snapshot context + per-origin click allowance so the smart-click resolver can
  // classify a click by what it targets AND auto-allow benign clicks only on origins the human already approved.
  // A miss → undefined/empty → an unresolved or not-yet-approved click fails safe to ASK.
  const ctxDir = ctxDirFromEnv();
  const ctx = loadBrowserContext(ctxDir, input.session_id);
  const session = {
    ...(ctx !== undefined ? { ctx } : {}),
    allowedOrigins: loadAllowedOrigins(ctxDir, input.session_id),
  };
  const out = runPreHook(input, submitter(), hookEnv(), session);
  process.stdout.write(JSON.stringify(out));
}

main().catch(() => {
  process.stdout.write(JSON.stringify(denyOutput('hook-fatal-fail-closed')));
  process.exit(0);
});
