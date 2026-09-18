import { describe, it, expect } from 'vitest';
import {
  parseSnapshotText, extractSnapshotText, resolveClickTarget, originOf, offloadedSnapshotPath,
} from './browser-context.js';

// A real chrome-devtools-mcp take_snapshot excerpt (captured live from the operator on github.com,
// 2026-06-14) — including the tricky lines: a label-less node (`main`), an attr-with-quotes node
// (`paragraph live="polite"`), and an attr after the label (`heading "…" level="2"` / `button "…" expandable`).
const REAL_SNAPSHOT = [
  'uid=1_0 RootWebArea "GitHub · Change is constant" url="https://github.com/"',
  '  uid=1_4 heading "Navigation Menu" level="2"',
  '  uid=1_7 button "Platform" expandable',
  '  uid=1_12 link "Pricing" url="https://github.com/pricing"',
  '  uid=1_15 link "Sign in" url="https://github.com/login"',
  '  uid=1_17 link "Sign up" url="https://github.com/signup?ref_cta=Sign+up"',
  '  uid=1_19 main',
  '  uid=1_26 textbox "Enter your email"',
  '  uid=1_27 button "Sign up for GitHub"',
  '  uid=1_38 paragraph live="polite" relevant="additions text"',
].join('\n');

describe('browser-context: parseSnapshotText', () => {
  const ctx = parseSnapshotText(REAL_SNAPSHOT);

  it('extracts the page URL from RootWebArea', () => {
    expect(ctx.pageUrl).toBe('https://github.com/');
  });

  it('resolves uid → role + label + (link) url', () => {
    expect(ctx.nodes['1_15']).toEqual({ role: 'link', label: 'Sign in', url: 'https://github.com/login' });
    expect(ctx.nodes['1_27']).toEqual({ role: 'button', label: 'Sign up for GitHub' });
    expect(ctx.nodes['1_12']).toEqual({ role: 'link', label: 'Pricing', url: 'https://github.com/pricing' });
  });

  it('captures the label even when a trailing attr follows it', () => {
    expect(ctx.nodes['1_4']).toEqual({ role: 'heading', label: 'Navigation Menu' });
    expect(ctx.nodes['1_7']).toEqual({ role: 'button', label: 'Platform' });
  });

  it('does NOT mistake an attribute value (key="value") for a label', () => {
    // `paragraph live="polite"` has NO accessible label — the live= attr must not be captured as one.
    expect(ctx.nodes['1_38']).toEqual({ role: 'paragraph' });
    // a node with no label at all
    expect(ctx.nodes['1_19']).toEqual({ role: 'main' });
  });

  it('empty / garbage input → empty context (fail-safe)', () => {
    expect(parseSnapshotText('')).toEqual({ nodes: {} });
    expect(parseSnapshotText('not a snapshot at all').nodes).toEqual({});
  });
});

describe('browser-context: extractSnapshotText', () => {
  it('digs the text out of an MCP tool_response content block', () => {
    const resp = { content: [{ type: 'text', text: 'preamble\nuid=1_0 RootWebArea "x" url="https://e.com/"' }] };
    expect(extractSnapshotText(resp)).toContain('uid=1_0 RootWebArea');
  });
  it('returns undefined for a non-snapshot response (→ fail-safe)', () => {
    expect(extractSnapshotText({ content: [{ type: 'text', text: 'clicked ok' }] })).toBeUndefined();
    expect(extractSnapshotText(undefined)).toBeUndefined();
    expect(extractSnapshotText({ foo: 'bar' })).toBeUndefined();
  });
  it('handles a BARE STRING tool_response and a {content:"…"} shape (not just content[].text)', () => {
    expect(extractSnapshotText('uid=1_0 RootWebArea "x" url="https://e.com/"')).toContain('RootWebArea');
    expect(extractSnapshotText({ content: 'uid=1_0 RootWebArea "x" url="https://e.com/"' })).toContain('RootWebArea');
  });
  it('handles the REAL Claude Code shape: a BARE ARRAY [{type,text}] (NOT wrapped in {content})', () => {
    // Claude Code passes the MCP content array directly as tool_response — the shape that broke capture live.
    const inline = [{ type: 'text', text: 'uid=1_0 RootWebArea "x" url="https://e.com/"' }];
    expect(extractSnapshotText(inline)).toContain('RootWebArea');
    // and the offload pointer arrives in the same bare-array shape:
    const ptr = [{ type: 'text', text: 'saved to /h/.claude/projects/p/tool-results/mcp-chrome-devtools-take_snapshot-9.txt\nFormat' }];
    expect(offloadedSnapshotPath(ptr)).toBe('/h/.claude/projects/p/tool-results/mcp-chrome-devtools-take_snapshot-9.txt');
  });
});

describe('browser-context: offloadedSnapshotPath (large snapshots saved to a file by Claude Code)', () => {
  const pointer = (p: string) =>
    `Error: result (60,518 characters across 916 lines) exceeds maximum allowed tokens. Output has been saved to ${p}\nFormat: Plain text`;
  it('extracts the validated tool-results .txt path from the offload pointer', () => {
    const p = '/home/user/.claude/projects/-home-user/sid/tool-results/mcp-chrome-devtools-take_snapshot-123.txt';
    expect(offloadedSnapshotPath(pointer(p))).toBe(p);
    expect(offloadedSnapshotPath({ content: [{ type: 'text', text: pointer(p) }] })).toBe(p); // also the wrapped shape
  });
  it('rejects a non-offload / non-tool-results / traversal / relative path (fail-safe)', () => {
    expect(offloadedSnapshotPath('clicked ok')).toBeUndefined();
    expect(offloadedSnapshotPath(pointer('/etc/passwd'))).toBeUndefined(); // not under tool-results/
    expect(offloadedSnapshotPath(pointer('/home/x/tool-results/../../../etc/shadow.txt'))).toBeUndefined(); // traversal
    expect(offloadedSnapshotPath(pointer('relative/tool-results/x.txt'))).toBeUndefined(); // not absolute
  });
});

describe('browser-context: parseSnapshotText — origin trust (red-team #2)', () => {
  it('FIRST RootWebArea wins; a second DIFFERENT root marks the origin untrusted (conflict)', () => {
    const ctx = parseSnapshotText([
      'uid=1_0 RootWebArea "Pay" url="https://shop.com/checkout"',
      'uid=1_4 button "Continue"',
      'uid=1_9 RootWebArea "ok" url="https://benign.com/"', // injected to spoof the origin
    ].join('\n'));
    expect(ctx.pageUrl).toBeUndefined();
    expect(ctx.originConflict).toBe(true);
  });
  it('a repeated root with the SAME url is not a conflict', () => {
    const ctx = parseSnapshotText('uid=1_0 RootWebArea "x" url="https://shop.com/"\nuid=1_9 RootWebArea "x" url="https://shop.com/"');
    expect(ctx.pageUrl).toBe('https://shop.com/');
    expect(ctx.originConflict).toBeUndefined();
  });
});

describe('browser-context: originOf', () => {
  it('returns scheme://host (lowercased), dropping path/query/fragment', () => {
    expect(originOf('https://Shop.Example.com/cart?x=1#y')).toBe('https://shop.example.com');
    expect(originOf('http://localhost:8080/a')).toBe('http://localhost:8080');
  });
  it('uses the TRUE host after userinfo (a userinfo-disguised URL resolves to its real host, not the userinfo)', () => {
    expect(originOf('https://approved.com@evil.com/path')).toBe('https://evil.com'); // NOT approved.com
    expect(originOf('https://approved.com@evil.com/')).not.toBe('https://approved.com'); // can't impersonate approved.com
  });
  it('undefined for non-absolute / non-http(s) / malformed', () => {
    expect(originOf(undefined)).toBeUndefined();
    expect(originOf('about:blank')).toBeUndefined();
    expect(originOf('data:text/html,x')).toBeUndefined();
    expect(originOf('/relative/path')).toBeUndefined();
    expect(originOf('https://@/')).toBeUndefined(); // empty host
  });
});

describe('browser-context: resolveClickTarget', () => {
  const ctx = parseSnapshotText(REAL_SNAPSHOT);
  it('resolves a known uid to its node', () => {
    expect(resolveClickTarget({ uid: '1_15' }, ctx)?.label).toBe('Sign in');
  });
  it('returns undefined for an unknown uid or missing context (→ caller asks)', () => {
    expect(resolveClickTarget({ uid: '9_99' }, ctx)).toBeUndefined();
    expect(resolveClickTarget({ uid: '1_15' }, undefined)).toBeUndefined();
    expect(resolveClickTarget({}, ctx)).toBeUndefined();
  });
});
