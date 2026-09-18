import { readFileSync } from 'node:fs';

// The hook reads the kill-switch from a HOST-OWNED state file (the host materializes it from
// jarvis.db.system_meta). FAIL-CLOSED: a missing path, an unreadable file, or any value other
// than exactly 'active' is treated as 'paused'. When paused, the gate denies all non-read tools.
//
// ...but a static file alone fails OPEN in the one case that matters most. If the Supervisor never
// boots — a DPAPI failure on the seal key, a missing bundle, a claimSingleton throw — nothing ever
// rewrites this file, so it keeps whatever it last said. It last said 'active'. Meanwhile
// start-brain.ps1 is an independent `while($true)` loop that relaunches the Brain every 30s
// regardless. Net effect: the Brain runs at FULL capability with Ring 1 absent and nothing draining
// or sealing its audit — precisely the state the kill-switch exists to prevent.
//
// So 'active' now also requires PROOF OF LIFE: a heartbeat the Supervisor rewrites on a timer, and
// which it DELETES on clean shutdown. Absent, unreadable, malformed, or older than the TTL ⇒ paused.
// This matters more the more autonomously the Brain runs: with a human watching, a dead Supervisor
// is eventually noticed; without one, nothing notices.

export type KillSwitchState = 'active' | 'paused';

/** How stale a heartbeat may be before Ring 1 counts as absent. Generously above the Supervisor's
 * write interval (5s) so a GC pause, a slow disk, or a brief clock step cannot flap the gate — but
 * far below the horizon over which an unattended Brain could do real damage. */
export const HEARTBEAT_TTL_MS = 60_000;

/** Read the Supervisor heartbeat and decide whether Ring 1 is demonstrably alive.
 *
 * Fail-closed on every branch, including a heartbeat from the FUTURE: a timestamp far ahead of now
 * means the clock moved (or the file was forged), and neither is evidence of a live Supervisor.
 * A small forward skew is tolerated because the writer and the reader are different processes. */
export function isSupervisorAlive(path: string | undefined, nowMs: number): boolean {
  if (!path) return false;
  let raw: string;
  try {
    raw = readFileSync(path, 'utf8');
  } catch {
    return false; // absent (never booted, or deleted on clean shutdown) or unreadable
  }
  let beatMs: number;
  try {
    const parsed = JSON.parse(raw) as { at?: unknown };
    if (typeof parsed.at !== 'number' || !Number.isFinite(parsed.at)) return false;
    beatMs = parsed.at;
  } catch {
    return false; // malformed ⇒ not proof of life
  }
  const age = nowMs - beatMs;
  if (age > HEARTBEAT_TTL_MS) return false; // stale ⇒ Ring 1 is gone
  if (age < -HEARTBEAT_TTL_MS) return false; // implausibly future-dated ⇒ clock step or forgery
  return true;
}

/** The heartbeat is a fixed-name SIBLING of the kill-switch state file (both live in the host-owned
 * jarvis-home/state/). Deriving it rather than taking a separate env var is deliberate: a second
 * variable could be unset — by a stale start-brain.sh, a hand-run hook, a future refactor — and
 * "unset" would have to mean either fail-open (defeats the purpose) or fail-closed (bricks a Brain
 * whose env predates the change). Deriving makes the two paths structurally inseparable, so there is
 * no configuration in which the state file is consulted and the liveness proof is not. */
export function heartbeatPathFor(killSwitchPath: string): string {
  const lastSlash = killSwitchPath.lastIndexOf('/');
  const lastBackslash = killSwitchPath.lastIndexOf('\\');
  const lastSep = Math.max(lastSlash, lastBackslash);
  // A bare file name has no separator: both indexes are -1 and `slice(0, -1)` used to drop the LAST character
  // of the name instead — `state.json` → `state.jso\supervisor.heartbeat`, a file that never exists, so a
  // relative JARVIS_KILLSWITCH_FILE was permanently `paused` (cold review 2026-09-17, C-6; fails closed, but
  // a gate that cannot be turned on is not the design). A bare name's sibling is the bare name.
  if (lastSep < 0) return 'supervisor.heartbeat';
  const sep = lastSlash > lastBackslash ? '/' : '\\';
  return `${killSwitchPath.slice(0, lastSep)}${sep}supervisor.heartbeat`;
}

/** The kill-switch as the gate must act on it: the state file says exactly 'active' AND the
 * Supervisor is demonstrably alive. There is deliberately no way to ask for one without the other. */
export function readKillSwitchFile(path: string | undefined, nowMs: number = Date.now()): KillSwitchState {
  if (!path) return 'paused';
  let state: KillSwitchState;
  try {
    state = readFileSync(path, 'utf8').trim() === 'active' ? 'active' : 'paused';
  } catch {
    return 'paused';
  }
  if (state === 'paused') return 'paused';
  return isSupervisorAlive(heartbeatPathFor(path), nowMs) ? 'active' : 'paused';
}
