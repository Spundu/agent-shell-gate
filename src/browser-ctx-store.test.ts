import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  captureBrowserContext, loadBrowserContext, ctxDirFromEnv, grantClickOrigin, loadAllowedOrigins,
} from './browser-ctx-store.js';
import type { HookInput } from './types.js';

const SNAPSHOT = [
  'uid=1_0 RootWebArea "GitHub" url="https://example.com/"',
  'uid=1_5 button "Sign in"',
].join('\n');

const post = (toolName: string, sessionId: string, toolResponse: unknown): HookInput => ({
  hook_event_name: 'PostToolUse',
  tool_name: toolName,
  session_id: sessionId,
  tool_response: toolResponse,
});
const snapshotResponse = (text: string) => ({ content: [{ type: 'text', text }] });

describe('browser-ctx-store', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'jarvis-ctx-'));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('captures a chrome-devtools snapshot response → loads it back for the session', () => {
    captureBrowserContext(dir, post('mcp__chrome-devtools__take_snapshot', 'sess-1', snapshotResponse(SNAPSHOT)));
    const ctx = loadBrowserContext(dir, 'sess-1');
    expect(ctx?.pageUrl).toBe('https://example.com/');
    expect(ctx?.nodes['1_5']).toEqual({ role: 'button', label: 'Sign in' });
  });

  it('captures from ANY chrome-devtools op that returns a snapshot (e.g. a navigation/click result)', () => {
    captureBrowserContext(dir, post('mcp__chrome-devtools__navigate_page', 'sess-2', snapshotResponse(SNAPSHOT)));
    expect(loadBrowserContext(dir, 'sess-2')?.pageUrl).toBe('https://example.com/');
  });

  it('ignores a NON-snapshot response (a plain "clicked ok" leaves no context)', () => {
    captureBrowserContext(dir, post('mcp__chrome-devtools__click', 'sess-3', snapshotResponse('clicked ok')));
    expect(loadBrowserContext(dir, 'sess-3')).toBeUndefined();
  });

  // P1, 2026-08-28. This case used to assert the OPPOSITE — that a snapshot named by an agent-supplied
  // `filePath` WAS captured ("the live workaround"). That made the file the gate's page-truth, and the Brain
  // can write any file it likes: describe a harmless page, hand the gate the path on any browser call, and a
  // real "Place order" click on a checkout origin went from DENY to a silent ALLOW.
  // GATE STATE MAY ONLY COME FROM A CHANNEL THE AGENT CANNOT AUTHOR.
  it('REFUSES a snapshot from an agent-supplied file path (gate-state forgery)', () => {
    const forged = join(dir, 'forged-snap.txt');
    writeFileSync(forged, 'uid=1_0 RootWebArea "Docs" url="https://shop.example/docs"\nuid=1_42 link "More"', 'utf8');
    for (const key of ['filePath', 'path', 'file', 'responseFilePath', 'outputDirPath']) {
      const input: HookInput = {
        hook_event_name: 'PostToolUse', tool_name: 'mcp__chrome-devtools__click', session_id: `sess-forge-${key}`,
        tool_response: { content: [{ type: 'text', text: 'clicked ok' }] },
        tool_input: { uid: '1_1', [key]: forged },
      };
      captureBrowserContext(dir, input);
      expect(loadBrowserContext(dir, `sess-forge-${key}`)).toBeUndefined();
    }
  });

  it('a REAL prior context survives a forgery attempt (it is not overwritten by the named file)', () => {
    captureBrowserContext(dir, post('mcp__chrome-devtools__take_snapshot', 'sess-keep',
      snapshotResponse('uid=1_0 RootWebArea "Pay" url="https://shop.example/checkout"\nuid=1_42 button "Place order"')));
    const forged = join(dir, 'forged2.txt');
    writeFileSync(forged, 'uid=1_0 RootWebArea "Docs" url="https://shop.example/docs"\nuid=1_42 link "More"', 'utf8');
    captureBrowserContext(dir, {
      hook_event_name: 'PostToolUse', tool_name: 'mcp__chrome-devtools__click', session_id: 'sess-keep',
      tool_response: { content: [{ type: 'text', text: 'clicked ok' }] },
      tool_input: { uid: '1_1', filePath: forged },
    });
    expect(loadBrowserContext(dir, 'sess-keep')?.pageUrl).toBe('https://shop.example/checkout');
  });

  it('ignores a non-chrome-devtools tool', () => {
    captureBrowserContext(dir, post('Read', 'sess-4', snapshotResponse(SNAPSHOT)));
    expect(loadBrowserContext(dir, 'sess-4')).toBeUndefined();
  });

  it('does not overwrite a good context when a later call returns no snapshot', () => {
    captureBrowserContext(dir, post('mcp__chrome-devtools__take_snapshot', 'sess-5', snapshotResponse(SNAPSHOT)));
    captureBrowserContext(dir, post('mcp__chrome-devtools__click', 'sess-5', snapshotResponse('ok'))); // no snapshot
    expect(loadBrowserContext(dir, 'sess-5')?.pageUrl).toBe('https://example.com/'); // prior context intact
  });

  it('FAIL-SAFE: a hostile/path-traversal session id is rejected (no read, no write)', () => {
    captureBrowserContext(dir, post('mcp__chrome-devtools__take_snapshot', '../evil', snapshotResponse(SNAPSHOT)));
    expect(loadBrowserContext(dir, '../evil')).toBeUndefined();
    expect(loadBrowserContext(dir, 'a/b')).toBeUndefined();
    expect(loadBrowserContext(dir, '')).toBeUndefined();
  });

  it('restores the originConflict flag across a capture→load round-trip (so the conflict→ASK signal survives)', () => {
    captureBrowserContext(dir, post('mcp__chrome-devtools__take_snapshot', 'conflict-sid', snapshotResponse(
      'uid=1_0 RootWebArea "a" url="https://shop.com/checkout"\nuid=1_9 RootWebArea "b" url="https://benign.com/"',
    )));
    const ctx = loadBrowserContext(dir, 'conflict-sid');
    expect(ctx?.originConflict).toBe(true);
    expect(ctx?.pageUrl).toBeUndefined();
  });

  it('FAIL-SAFE: missing file, corrupt JSON, and missing dir all load to undefined', () => {
    expect(loadBrowserContext(dir, 'never-written')).toBeUndefined();
    writeFileSync(join(dir, 'corrupt.json'), '{not json', 'utf8');
    expect(loadBrowserContext(dir, 'corrupt')).toBeUndefined();
    expect(loadBrowserContext(undefined, 'sess-1')).toBeUndefined();
  });

  it('ctxDirFromEnv reads JARVIS_BROWSER_CTX_DIR (and treats blank as unset)', () => {
    expect(ctxDirFromEnv({ JARVIS_BROWSER_CTX_DIR: '/x/y' } as NodeJS.ProcessEnv)).toBe('/x/y');
    expect(ctxDirFromEnv({ JARVIS_BROWSER_CTX_DIR: '  ' } as NodeJS.ProcessEnv)).toBeUndefined();
    expect(ctxDirFromEnv({} as NodeJS.ProcessEnv)).toBeUndefined();
  });
});

const clickPost = (sessionId: string): HookInput => ({
  hook_event_name: 'PostToolUse',
  tool_name: 'mcp__chrome-devtools__click',
  session_id: sessionId,
  tool_response: { content: [{ type: 'text', text: 'clicked ok' }] }, // a click result, NOT a snapshot
});

describe('browser-ctx-store — per-origin click allowance (grant on completed click)', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'jarvis-grant-'));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('grants the PRE-click origin (from the loaded context) when a click completes', () => {
    // context says the page is shop.example.com
    captureBrowserContext(dir, post('mcp__chrome-devtools__take_snapshot', 's1', snapshotResponse('uid=1_0 RootWebArea "x" url="https://shop.example.com/p/42"\nuid=1_4 button "Read more"')));
    expect(loadAllowedOrigins(dir, 's1')).toEqual([]); // nothing approved yet
    grantClickOrigin(dir, clickPost('s1')); // a click on shop.example.com completed (approved)
    expect(loadAllowedOrigins(dir, 's1')).toEqual(['https://shop.example.com']);
  });

  it('is idempotent and keyed by origin (scheme+host, not path)', () => {
    captureBrowserContext(dir, post('mcp__chrome-devtools__take_snapshot', 's2', snapshotResponse('uid=1_0 RootWebArea "x" url="https://shop.example.com/a"')));
    grantClickOrigin(dir, clickPost('s2'));
    // a later snapshot on a different PATH of the same origin
    captureBrowserContext(dir, post('mcp__chrome-devtools__take_snapshot', 's2', snapshotResponse('uid=1_0 RootWebArea "x" url="https://shop.example.com/b"')));
    grantClickOrigin(dir, clickPost('s2'));
    expect(loadAllowedOrigins(dir, 's2')).toEqual(['https://shop.example.com']); // not duplicated
  });

  it('does NOT grant when the origin is untrusted (conflicting RootWebArea roots — spoof signal)', () => {
    captureBrowserContext(dir, post('mcp__chrome-devtools__take_snapshot', 's3', snapshotResponse('uid=1_0 RootWebArea "a" url="https://shop.example.com/checkout"\nuid=1_9 RootWebArea "b" url="https://benign.com/"')));
    grantClickOrigin(dir, clickPost('s3'));
    expect(loadAllowedOrigins(dir, 's3')).toEqual([]); // origin conflict → never granted
  });

  it('does NOT grant for a non-click tool, and skips an unsafe session id', () => {
    captureBrowserContext(dir, post('mcp__chrome-devtools__take_snapshot', 's4', snapshotResponse('uid=1_0 RootWebArea "x" url="https://shop.example.com/"')));
    grantClickOrigin(dir, post('mcp__chrome-devtools__hover', 's4', snapshotResponse('x'))); // hover, not click
    expect(loadAllowedOrigins(dir, 's4')).toEqual([]);
    grantClickOrigin(dir, clickPost('../evil'));
    expect(loadAllowedOrigins(dir, '../evil')).toEqual([]);
  });
});

// cold review 2026-09-17 (TQ-12): the OFFLOADED-snapshot capture (the real-world primary path — a real page
// overflows Claude Code's inline cap), the 8 MB size cap, the looksLikeSnapshot content guard, the 256-origin
// eviction and a corrupt origins file were all untested; five mutations (drop the offload read, cap → Infinity,
// guard removed, slice(-256) removed, non-array → a fixed origin) survived the whole suite.
describe('browser-ctx-store — offloaded snapshot, caps, eviction, corrupt allowance', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'jarvis-offload-'));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });
  // offloadedSnapshotPath requires a POSIX-absolute path containing `/tool-results/`. On Windows a drive-less
  // `/Users/.../Temp/...` resolves against the current drive, which is where the temp dir lives on this box.
  const posix = (p: string): string => p.replace(/^[A-Za-z]:/, '').replace(/\\/g, '/');
  const pointer = (sessionId: string, file: string): HookInput =>
    post('mcp__chrome-devtools__take_snapshot', sessionId, snapshotResponse(`Output too large. Output has been saved to ${posix(file)} for reading.`));
  const toolResultsFile = (name: string, text: string): string => {
    const tr = join(dir, 'tool-results');
    mkdirSync(tr, { recursive: true });
    const file = join(tr, name);
    writeFileSync(file, text, 'utf8');
    return file;
  };

  it('follows a Claude Code tool-results pointer and captures the offloaded snapshot', () => {
    const file = toolResultsFile('mcp-chrome-devtools-take_snapshot-9.txt', SNAPSHOT);
    captureBrowserContext(dir, pointer('o1', file));
    expect(loadBrowserContext(dir, 'o1')?.pageUrl).toBe('https://example.com/');
  });

  it('refuses an offloaded file over the 8 MB cap (does not slurp a pathological file)', () => {
    const file = toolResultsFile('big.txt', `${SNAPSHOT}\n${'x'.repeat(8 * 1024 * 1024 + 1)}`);
    captureBrowserContext(dir, pointer('o2', file));
    expect(loadBrowserContext(dir, 'o2')).toBeUndefined();
  });

  it('refuses an offloaded file whose content is not a snapshot (content guard)', () => {
    const file = toolResultsFile('not-a-snapshot.txt', 'clicked ok');
    captureBrowserContext(dir, pointer('o3', file));
    expect(loadBrowserContext(dir, 'o3')).toBeUndefined();
  });

  it('refuses a pointer that is not inside a tool-results dir, or traverses out of one', () => {
    const outside = join(dir, 'snap.txt');
    writeFileSync(outside, SNAPSHOT, 'utf8');
    captureBrowserContext(dir, pointer('o4', outside));
    expect(loadBrowserContext(dir, 'o4')).toBeUndefined();
    const file = toolResultsFile('t.txt', SNAPSHOT);
    captureBrowserContext(dir, pointer('o5', file.replace(/tool-results[\\/]/, 'tool-results/../tool-results/')));
    expect(loadBrowserContext(dir, 'o5')).toBeUndefined();
  });

  it('keeps only the 256 most recent granted origins (grant path AND load path agree)', () => {
    for (let i = 0; i < 300; i += 1) {
      captureBrowserContext(dir, post('mcp__chrome-devtools__take_snapshot', 'e1', snapshotResponse(`uid=1_0 RootWebArea "x" url="https://site${i}.example/"`)));
      grantClickOrigin(dir, clickPost('e1'));
    }
    const origins = loadAllowedOrigins(dir, 'e1');
    expect(origins).toHaveLength(256);
    expect(origins[0]).toBe('https://site44.example');
    expect(origins[255]).toBe('https://site299.example');
    // an oversized hand-edited file is trimmed the same way on load
    writeFileSync(join(dir, 'e2.origins.json'), JSON.stringify({ origins: Array.from({ length: 300 }, (_, i) => `https://h${i}.example`) }), 'utf8');
    expect(loadAllowedOrigins(dir, 'e2')).toHaveLength(256);
    expect(loadAllowedOrigins(dir, 'e2')[0]).toBe('https://h44.example');
  });

  it('treats a corrupt / non-array / non-string origins file as EMPTY (never as an allowance)', () => {
    writeFileSync(join(dir, 'c1.origins.json'), '{bad', 'utf8');
    writeFileSync(join(dir, 'c2.origins.json'), JSON.stringify({ origins: 'https://evil.example' }), 'utf8');
    writeFileSync(join(dir, 'c3.origins.json'), JSON.stringify([]), 'utf8');
    writeFileSync(join(dir, 'c4.origins.json'), JSON.stringify({ origins: [42, null, 'https://ok.example'] }), 'utf8');
    expect(loadAllowedOrigins(dir, 'c1')).toEqual([]);
    expect(loadAllowedOrigins(dir, 'c2')).toEqual([]);
    expect(loadAllowedOrigins(dir, 'c3')).toEqual([]);
    expect(loadAllowedOrigins(dir, 'c4')).toEqual(['https://ok.example']);
  });
});
