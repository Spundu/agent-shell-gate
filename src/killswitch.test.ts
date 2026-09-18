import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  HEARTBEAT_TTL_MS,
  heartbeatPathFor,
  isSupervisorAlive,
  readKillSwitchFile,
} from './killswitch.js';

// The fail-OPEN this closes (2026-08-23): kill-switch.state is a STATIC file. If the Supervisor never
// boots — a DPAPI failure on the seal key, a missing bundle, a claimSingleton throw — nothing rewrites it,
// so it keeps saying 'active' forever, while start-brain.ps1's independent `while($true)` loop relaunches
// the Brain every 30s. The Brain then runs at full capability with Ring 1 absent and nothing sealing its
// audit. 'active' now additionally requires PROOF OF LIFE.

let dir: string;
let state: string;
let beat: string;
const NOW = 1_700_000_000_000;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'jarvis-ks-'));
  state = join(dir, 'kill-switch.state');
  beat = join(dir, 'supervisor.heartbeat');
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

const writeBeat = (atMs: number): void => writeFileSync(beat, JSON.stringify({ at: atMs, bootId: 'b', hostId: 'h' }));

describe('heartbeatPathFor', () => {
  it('derives a sibling of the state file (posix and windows)', () => {
    expect(heartbeatPathFor('/u/jarvis-home/state/kill-switch.state')).toBe('/u/jarvis-home/state/supervisor.heartbeat');
    expect(heartbeatPathFor('C:\\jarvis-home\\state\\kill-switch.state')).toBe('C:\\jarvis-home\\state\\supervisor.heartbeat');
  });

  it('is DERIVED, not configured — there is no env var that could be unset', () => {
    // A second variable would have to mean fail-open (defeats the purpose) or fail-closed (bricks a Brain
    // whose env predates the change). Deriving makes the two structurally inseparable.
    expect(heartbeatPathFor(state)).toBe(beat);
  });

  it('a bare file name (no separator) derives the bare sibling — not a truncated name (cold review C-6)', () => {
    // `Math.max(-1, -1)` = -1 and `slice(0, -1)` dropped the last character: `state.jso\supervisor.heartbeat`.
    expect(heartbeatPathFor('kill-switch.state')).toBe('supervisor.heartbeat');
    expect(heartbeatPathFor('state.json')).toBe('supervisor.heartbeat');
    expect(heartbeatPathFor('/kill-switch.state')).toBe('/supervisor.heartbeat'); // root-level sibling
  });

  it('a RELATIVE kill-switch path resolves its heartbeat in the same (current) directory end-to-end', () => {
    const prev = process.cwd();
    process.chdir(dir);
    try {
      writeFileSync('kill-switch.state', 'active', 'utf8');
      writeFileSync('supervisor.heartbeat', JSON.stringify({ at: NOW - 1_000 }), 'utf8');
      expect(readKillSwitchFile('kill-switch.state', NOW)).toBe('active'); // was 'paused' before the fix
      expect(readKillSwitchFile(state, NOW)).toBe('active'); // and the absolute form agrees
    } finally {
      process.chdir(prev);
    }
  });
});

describe('isSupervisorAlive', () => {
  it('true for a fresh heartbeat', () => {
    writeBeat(NOW - 1000);
    expect(isSupervisorAlive(beat, NOW)).toBe(true);
  });

  it('false when absent — the Supervisor never booted, or shut down cleanly', () => {
    expect(isSupervisorAlive(beat, NOW)).toBe(false);
  });

  it('false once older than the TTL', () => {
    writeBeat(NOW - HEARTBEAT_TTL_MS - 1);
    expect(isSupervisorAlive(beat, NOW)).toBe(false);
    writeBeat(NOW - HEARTBEAT_TTL_MS + 1000); // just inside
    expect(isSupervisorAlive(beat, NOW)).toBe(true);
  });

  it('false for a FUTURE-dated beat (clock step or forgery is not proof of life)', () => {
    writeBeat(NOW + HEARTBEAT_TTL_MS + 60_000);
    expect(isSupervisorAlive(beat, NOW)).toBe(false);
  });

  it('tolerates small forward skew between two processes', () => {
    writeBeat(NOW + 2000);
    expect(isSupervisorAlive(beat, NOW)).toBe(true);
  });

  it('false for malformed content — every parse failure fails closed', () => {
    for (const body of ['', 'not json', '{}', '{"at":"soon"}', '{"at":null}', 'null', '[]', '{"at":NaN}']) {
      writeFileSync(beat, body);
      expect(isSupervisorAlive(beat, NOW)).toBe(false);
    }
  });

  it('false when no path is configured at all', () => {
    expect(isSupervisorAlive(undefined, NOW)).toBe(false);
  });
});

describe('readKillSwitchFile', () => {
  it("ACTIVE requires both 'active' AND a live Supervisor", () => {
    writeFileSync(state, 'active');
    writeBeat(NOW);
    expect(readKillSwitchFile(state, NOW)).toBe('active');
  });

  it('THE FIX: active state + dead Supervisor is PAUSED', () => {
    writeFileSync(state, 'active');
    // no heartbeat at all — exactly the "Supervisor never booted" case
    expect(readKillSwitchFile(state, NOW)).toBe('paused');
    // ...and a heartbeat that has gone stale
    writeBeat(NOW - HEARTBEAT_TTL_MS - 1);
    expect(readKillSwitchFile(state, NOW)).toBe('paused');
  });

  it('paused stays paused regardless of liveness', () => {
    writeFileSync(state, 'paused');
    writeBeat(NOW);
    expect(readKillSwitchFile(state, NOW)).toBe('paused');
  });

  it('every pre-existing fail-closed path still holds', () => {
    expect(readKillSwitchFile(undefined, NOW)).toBe('paused'); // unconfigured
    expect(readKillSwitchFile(join(dir, 'nope.state'), NOW)).toBe('paused'); // missing file
    writeFileSync(state, 'ACTIVE'); // not exactly 'active'
    writeBeat(NOW);
    expect(readKillSwitchFile(state, NOW)).toBe('paused');
    writeFileSync(state, 'active\n'); // trailing whitespace IS tolerated (pre-existing behaviour)
    expect(readKillSwitchFile(state, NOW)).toBe('active');
  });
});
