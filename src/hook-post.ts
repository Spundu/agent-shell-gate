// External PostToolUse hook executable. Bundled to dist/hook-post.cjs. Records the completed
// call (best-effort) and never blocks.

import { outboxSubmit, type AuditSubmit } from './audit-submit.js';
import { captureBrowserContext, grantClickOrigin, ctxDirFromEnv } from './browser-ctx-store.js';
import { runPostHook, type HookEnv } from './hook.js';
import type { HookInput, PassThroughOutput } from './types.js';

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString('utf8');
}

function hookEnv(): HookEnv {
  return {
    bootId: process.env.JARVIS_BOOT_ID ?? 'dev-boot',
    hostId: process.env.JARVIS_HOST_ID ?? 'dev-host',
    killSwitch: 'active', // PostToolUse never gates; the field is unused here.
    nowMs: () => Date.now(),
  };
}

function submitter(): AuditSubmit {
  const outbox = process.env.JARVIS_AUDIT_OUTBOX;
  return outbox ? outboxSubmit(outbox) : () => false;
}

const passThrough: PassThroughOutput = { continue: true };

async function main(): Promise<void> {
  const raw = await readStdin();
  try {
    const input = JSON.parse(raw) as HookInput;
    runPostHook(input, submitter(), hookEnv());
    const ctxDir = ctxDirFromEnv();
    // GRANT FIRST, then capture. A completed click means the PreToolUse gate ALLOWED it or the human APPROVED
    // the ask → record the origin (derived from the PRE-click context) as auto-allowed for benign clicks this
    // session. Must run BEFORE captureBrowserContext, which overwrites the context with the POST-click snapshot.
    grantClickOrigin(ctxDir, input);
    // Capture a fresh browser snapshot (if this call returned one) so the NEXT click resolves. Best-effort.
    captureBrowserContext(ctxDir, input);
  } catch {
    // PostToolUse must never block the session; swallow and continue.
  }
  process.stdout.write(JSON.stringify(passThrough));
}

main().catch(() => {
  process.stdout.write(JSON.stringify(passThrough));
  process.exit(0);
});
