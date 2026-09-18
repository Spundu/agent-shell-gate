import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { statSync } from 'node:fs';
import {
  parseSnapshotText, extractSnapshotText, offloadedSnapshotPath, looksLikeSnapshot, originOf,
  type BrowserContext,
} from './browser-context.js';
import type { HookInput } from './types.js';

// Per-session BrowserContext store — the bridge between the PostToolUse hook (which SEES a snapshot
// tool_response and CAPTURES it) and the PreToolUse hook (which LOADS it to resolve a click's opaque uid).
// File-backed because the hook is a fresh process per call: the gate has no in-memory state.
//
// FAIL-SAFE BY CONSTRUCTION: every path here is best-effort. A missing dir, an unreadable/half-written file,
// a malformed JSON, or a hostile session id all yield "no context" → the smart-click resolver treats the
// click as UNRESOLVED → YELLOW (ask). Nothing here can downgrade a tier; it can only enable an auto-allow of
// an already-resolved benign click, or — on any doubt — fall back to asking.

const CHROME_DEVTOOLS_PREFIX = 'mcp__chrome-devtools__';
// Session ids from the Claude CLI are UUIDs (hex + dashes). Accept ONLY a conservative slug so a crafted
// session_id can never traverse out of the ctx dir or collide with another file. Anything else → skip.
const SAFE_SESSION_ID = /^[A-Za-z0-9_-]{1,128}$/;

/** The configured per-session context directory (JARVIS_BROWSER_CTX_DIR), or undefined when unset. */
export function ctxDirFromEnv(env: NodeJS.ProcessEnv = process.env): string | undefined {
  const dir = env.JARVIS_BROWSER_CTX_DIR;
  return dir && dir.trim() ? dir : undefined;
}

/** A per-session state file path, or undefined if the dir/id is missing or the id is not a safe slug.
 * `suffix` separates the snapshot context ('.json') from the per-origin click allowance ('.origins.json'). */
function sessionFile(
  dir: string | undefined,
  sessionId: string | undefined,
  suffix = '.json',
): string | undefined {
  if (!dir || !sessionId || !SAFE_SESSION_ID.test(sessionId)) return undefined;
  return join(dir, `${sessionId}${suffix}`);
}

const ORIGINS_SUFFIX = '.origins.json';
const MAX_ALLOWED_ORIGINS = 256; // a sane per-session cap (a runaway store can't grow unbounded)

/** Load a session's BrowserContext, or undefined on any miss/error (→ the caller fail-safes to ASK). */
export function loadBrowserContext(
  dir: string | undefined,
  sessionId: string | undefined,
): BrowserContext | undefined {
  const file = sessionFile(dir, sessionId);
  if (!file) return undefined;
  try {
    const raw = readFileSync(file, 'utf8');
    const parsed = JSON.parse(raw) as unknown;
    // Validate the shape minimally — a corrupt/foreign file must not crash or be trusted blindly.
    if (!parsed || typeof parsed !== 'object') return undefined;
    const obj = parsed as { pageUrl?: unknown; nodes?: unknown; originConflict?: unknown };
    const nodes = obj.nodes && typeof obj.nodes === 'object' ? (obj.nodes as BrowserContext['nodes']) : {};
    const ctx: BrowserContext = { nodes };
    if (typeof obj.pageUrl === 'string') ctx.pageUrl = obj.pageUrl;
    // Restore the untrusted-origin signal across the round-trip so the resolver's explicit conflict→ASK
    // branch fires (the deleted pageUrl already fails safe, but the flag keeps the signal — and reason — intact).
    if (obj.originConflict === true) ctx.originConflict = true;
    return ctx;
  } catch {
    return undefined;
  }
}

/** Atomic write (tmp + rename) so a concurrent reader never sees a half-written file. */
function writeAtomic(dir: string, file: string, data: string): void {
  mkdirSync(dir, { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  writeFileSync(tmp, data, 'utf8');
  renameSync(tmp, file);
}

/** Persist a session's BrowserContext atomically. Best-effort: any error is swallowed (the next click just
 * fails safe to ASK). */
function saveBrowserContext(dir: string, sessionId: string, ctx: BrowserContext): void {
  const file = sessionFile(dir, sessionId);
  if (!file) return;
  try {
    writeAtomic(dir, file, JSON.stringify(ctx));
  } catch {
    // best-effort: a capture failure only means the next click fails safe to ASK.
  }
}

/** Load the session's per-origin click allowance — the origins the human has approved auto-clicks on this
 * session. Undefined/missing/corrupt → empty (→ benign clicks on every origin fail safe to ASK). */
export function loadAllowedOrigins(dir: string | undefined, sessionId: string | undefined): string[] {
  const file = sessionFile(dir, sessionId, ORIGINS_SUFFIX);
  if (!file) return [];
  try {
    const parsed = JSON.parse(readFileSync(file, 'utf8')) as unknown;
    const arr = (parsed as { origins?: unknown })?.origins;
    if (!Array.isArray(arr)) return [];
    // Keep the MOST-RECENT cap (slice(-MAX)) to match grantClickOrigin's eviction, so a hand-edited/oversized
    // file and the grant path agree on which origins survive (red-team cycle 1, consistency).
    return arr.filter((o): o is string => typeof o === 'string').slice(-MAX_ALLOWED_ORIGINS);
  } catch {
    return [];
  }
}

/** GRANT: a `click` on this session COMPLETED (PostToolUse fires only when the PreToolUse gate ALLOWED or the
 * human APPROVED the ask), so record the origin the click happened on as auto-allowed for subsequent BENIGN
 * clicks this session. The origin is derived from the PRE-click snapshot context (loaded BEFORE this call's
 * own snapshot capture overwrites it) and ONLY when that origin is trusted (no conflicting roots). Money/login
 * clicks still escalate regardless of the allowance, so granting from any completed click is safe.
 * Best-effort; never throws. */
export function grantClickOrigin(
  dir: string | undefined,
  input: HookInput,
  env: NodeJS.ProcessEnv = process.env,
): void {
  const resolvedDir = dir ?? ctxDirFromEnv(env);
  if (!resolvedDir) return;
  if (input.tool_name !== `${CHROME_DEVTOOLS_PREFIX}click`) return;
  const sessionId = input.session_id;
  if (!sessionId) return;
  const file = sessionFile(resolvedDir, sessionId, ORIGINS_SUFFIX);
  if (!file) return;
  try {
    const ctx = loadBrowserContext(resolvedDir, sessionId);
    if (ctx?.originConflict) return; // untrusted origin → never grant
    const origin = originOf(ctx?.pageUrl);
    if (!origin) return;
    const current = loadAllowedOrigins(resolvedDir, sessionId);
    if (current.includes(origin)) return; // idempotent
    const next = [...current, origin].slice(-MAX_ALLOWED_ORIGINS);
    writeAtomic(resolvedDir, file, JSON.stringify({ origins: next }));
  } catch {
    // best-effort: a grant failure only means the next benign click on this origin asks again.
  }
}

/** PostToolUse capture: if THIS completed call was a chrome-devtools op whose response carries an a11y
 * snapshot (take_snapshot, a navigation, or any op that returns the refreshed tree), parse it and store the
 * fresh per-session context for the NEXT click to resolve against. Best-effort + never throws. */
export function captureBrowserContext(
  dir: string | undefined,
  input: HookInput,
  env: NodeJS.ProcessEnv = process.env,
): void {
  const resolvedDir = dir ?? ctxDirFromEnv(env);
  if (!resolvedDir) return;
  if (typeof input.tool_name !== 'string' || !input.tool_name.startsWith(CHROME_DEVTOOLS_PREFIX)) return;
  const sessionId = input.session_id;
  if (!sessionId) return;
  // (1) inline snapshot (small pages fit under Claude Code's tool-result token cap).
  let text = extractSnapshotText(input.tool_response);
  // (2) offloaded snapshot (real pages overflow the cap → Claude Code saved the tree to a file + left a
  //     pointer). Follow the validated pointer and read it (size-capped, content-guarded). Best-effort.
  if (!text) text = readOffloadedSnapshot(input.tool_response);
  // There is deliberately NO third path reading an AGENT-SUPPLIED file path — see the removal note below.
  if (!text) return; // not a snapshot-bearing response → leave the prior context untouched
  saveBrowserContext(resolvedDir, sessionId, parseSnapshotText(text));
}

const MAX_SNAPSHOT_BYTES = 8 * 1024 * 1024; // cap the offloaded-snapshot read (a tree is ~tens-to-hundreds KB)

/** Read a chrome-devtools snapshot that Claude Code offloaded to a file (because it overflowed the inline
 * token cap), via the validated pointer in tool_response. Returns the text only if it actually looks like a
 * snapshot. Best-effort + fully fail-safe: any miss/oversize/error → undefined → the click fails safe to ASK. */
function readOffloadedSnapshot(toolResponse: unknown): string | undefined {
  const path = offloadedSnapshotPath(toolResponse);
  if (!path) return undefined;
  try {
    if (statSync(path).size > MAX_SNAPSHOT_BYTES) return undefined; // don't slurp a pathological file
    const text = readFileSync(path, 'utf8');
    return looksLikeSnapshot(text) ? text : undefined;
  } catch {
    return undefined;
  }
}

// REMOVED 2026-08-28 — `readSnapshotFromArg`, a P1 gate-state FORGERY channel.
//
// It read whatever path the AGENT put in `filePath`/`path`/`file`/`responseFilePath`/… and, if the bytes
// merely matched `looksLikeSnapshot`, installed them as the session's BrowserContext. It ran on EVERY
// chrome-devtools call whose response carried no snapshot — which is every click ("clicked ok").
//
// That context is the gate's entire view of the page: `pageUrl` drives the crown-jewel and money-context
// REDs and is the per-origin allowance key, and every `uid → {label,url}` is what the smart-click resolver
// classifies against. So the Brain could write a file describing a harmless page, hand the gate that path on
// any browser call, and turn a real "Place order" click on a checkout origin from DENY into a silent ALLOW.
// `grantClickOrigin` read the same forged `pageUrl`, so an arbitrary origin could be pushed into
// `allowedOrigins` too. Demonstrated end-to-end: deny/red → allow/green.
//
// The comment that justified it — "the path is one the operator just wrote its OWN snapshot to" — was an
// assumption the gate CANNOT check. Validating the path cannot rescue it either: any path the Brain can
// name is a path the Brain can write. The invariant has to be structural:
//
//     GATE STATE MAY ONLY COME FROM A CHANNEL THE AGENT CANNOT AUTHOR.
//
// The two remaining capture paths satisfy that — the inline `tool_response`, and Claude Code's own
// offload file reached through a `/tool-results/` pointer it emitted and we path-validate. Both are written
// by the harness, not the agent.
//
// Nothing is lost: since b68b622 the operator can READ Claude Code's offload file directly, so the dump-to-
// disk workaround this existed to support is obsolete (the crew doctrine now tells it so explicitly). If an
// operator does dump to a file anyway, the gate simply captures nothing and its next click fails safe to
// ASK — the correct direction.
