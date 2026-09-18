import { describe, it, expect } from 'vitest';
import { classifyMcp } from '../catalog.js';
import { inspectClaudeInChrome } from './claude-in-chrome.js';

// The second browser channel (2026-09-05). The governing rule is PARITY: the same capability gets the same
// tier no matter which channel delivers it. The one asymmetry is deliberate — this channel addresses tabs by
// a bare integer `tabId` with no generation, so the gate can never know WHERE a tab is when a commit lands.
// chrome-devtools resolves a click because a snapshot `uid` is bound to its snapshot and a stale one is
// DETECTABLE; the equivalent here would fail OPEN. So every commit asks, exactly as on the operator-gui
// coordinate channel, and for the same reason.

const cls = (op: string, input: Record<string, unknown> = {}) =>
  classifyMcp(`mcp__claude-in-chrome__${op}`, input);

describe('claude-in-chrome catalog tiers', () => {
  it('navigate + tab management are GREEN (their whole risk is in the args)', () => {
    for (const op of ['navigate', 'tabs_create_mcp', 'tabs_close_mcp', 'resize_window']) {
      expect(cls(op)?.baseTier, op).toBe('green');
    }
  });

  it('reads ASK, and are never kill-switch/depth exempt', () => {
    for (const op of ['read_page', 'get_page_text', 'find', 'read_console_messages',
      'read_network_requests', 'tabs_context_mcp', 'list_connected_browsers']) {
      const c = cls(op);
      expect(c?.baseTier, op).toBe('yellow');
      // `isRead` is the kill-switch/depth EXEMPTION. It belongs to a channel whose logged-out profile
      // invariant is proven at launch; this one has no such proof, so nothing here may be exempt.
      expect(c?.kind, op).not.toBe('read');
    }
  });

  it('every in-page COMMIT asks', () => {
    for (const op of ['form_input', 'file_upload', 'upload_image', 'gif_creator']) {
      expect(cls(op)?.baseTier, op).toBe('yellow');
    }
    for (const action of ['left_click', 'right_click', 'double_click', 'type', 'key', 'left_click_drag']) {
      expect(cls('computer', { action })?.baseTier, action).toBe('yellow');
    }
  });

  it('capability-escalation tools are RED, not merely asked', () => {
    // javascript_tool: identical capability to evaluate_script, which is RED. browser_batch: it BUNDLES
    // other calls, so name-keyed classification stops working. select/switch_browser: they can move the
    // agent off the SANDBOXED browser onto the human's real one (Fork B, rejected 2026-08-28).
    for (const op of ['javascript_tool', 'browser_batch', 'shortcuts_execute',
      'select_browser', 'switch_browser']) {
      expect(cls(op)?.baseTier, op).toBe('red');
    }
  });

  it('computer is ARG-dispatched — a missing or unknown action is default-deny', () => {
    // A name-keyed entry would give screenshot and left_click one shared tier; that is itself the hole.
    expect(cls('computer', {})?.baseTier).toBe('red');
    expect(cls('computer', { action: 42 })?.baseTier).toBe('red');
    expect(cls('computer', { action: 'not_a_verb' })?.baseTier).toBe('red');
    expect(cls('computer', { action: 'scroll' })?.baseTier).toBe('green');
  });

  it('an unlisted op falls through to default-deny', () => {
    expect(cls('some_new_tool_they_ship_next_month')).toBeNull();
  });
});

describe('claude-in-chrome inspector escalations', () => {
  const red = (input: Record<string, unknown>) => inspectClaudeInChrome(input)?.tier;

  it('REDs a crown-jewel or dangerous navigation', () => {
    expect(red({ url: 'https://mail.google.com' })).toBe('red');
    expect(red({ url: 'https://gmail.com' })).toBe('red');       // the apex fixed earlier today
    expect(red({ url: 'javascript:alert(1)' })).toBe('red');
    expect(red({ url: 'https://example.com' })).toBeUndefined(); // negative control
  });

  it('finds a URL smuggled through a plural or nested argument', () => {
    // A rule that reads only `url` is defeated by the same value arriving as `urls` or inside an object.
    expect(red({ urls: ['https://example.com', 'https://mail.google.com'] })).toBe('red');
    expect(red({ target: { href: 'https://gmail.com' } })).toBe('red');
  });

  it('REDs a secret-shaped value on every typing channel', () => {
    const PAN = '4111111111111111'; // pragma: allowlist secret (the standard Visa TEST PAN)
    expect(red({ value: PAN })).toBe('red');   // form_input
    expect(red({ text: PAN })).toBe('red');    // computer{type}
    expect(red({ input: PAN })).toBe('red');
  });

  it('REDs a crown-jewel file pushed into a page', () => {
    expect(red({ filePaths: ['/home/user/.ssh/id_rsa'] })).toBe('red');
    expect(red({ file_path: '/tmp/holiday.png' })).toBeUndefined(); // negative control
  });

  it('asks on a silent submit (typing that also presses Enter)', () => {
    expect(red({ text: 'hello\n' })).toBe('yellow');
    expect(red({ text: 'hello' })).toBeUndefined();
  });
});
