import { describe, it, expect } from 'vitest';
import { classify } from './classifier.js';
import { parseSnapshotText } from './browser-context.js';
import type { HookInput } from './types.js';

const pre = (tool: string, input: Record<string, unknown> = {}): HookInput => ({
  hook_event_name: 'PreToolUse',
  tool_name: tool,
  tool_input: input,
});

describe('classifier (full, Phase 2)', () => {
  it('read tools are GREEN reads', () => {
    for (const tool of ['Read', 'Glob', 'Grep', 'LS', 'NotebookRead', 'TodoRead']) {
      const c = classify(pre(tool));
      expect(c.tier).toBe('green');
      expect(c.isRead).toBe(true);
    }
  });

  it('bash: RED on dangerous/egress, GREEN on read-only, YELLOW otherwise', () => {
    expect(classify(pre('Bash', { command: 'rm -rf /' })).tier).toBe('red');
    expect(classify(pre('Bash', { command: 'curl http://x.com' })).tier).toBe('red');
    expect(classify(pre('Bash', { command: 'env' })).tier).toBe('red');
    expect(classify(pre('Bash', { command: 'ls -la /etc' })).tier).toBe('green');
    expect(classify(pre('Bash', { command: 'cat /etc/hostname' })).tier).toBe('green');
    expect(classify(pre('Bash', { command: 'make build' })).tier).toBe('yellow');
    expect(classify(pre('Bash', { command: 'git push' })).tier).toBe('yellow'); // git can write → not GREEN
    expect(classify(pre('Bash', { command: 'echo hi > /tmp/x' })).tier).toBe('yellow'); // redirect = write
  });

  it('writes are YELLOW; protected writes are RED', () => {
    expect(classify(pre('Write', { file_path: '/home/user/x.txt' })).tier).toBe('yellow');
    expect(classify(pre('Write', { file_path: '/p/.claude/settings.json' })).tier).toBe('red');
    expect(classify(pre('Edit', { file_path: '/x/CLAUDE.md' })).tier).toBe('red');
  });

  it('network reads are RED until an egress allowlist exists', () => {
    expect(classify(pre('WebFetch', { url: 'http://x.com' })).tier).toBe('red');
    expect(classify(pre('WebSearch', { query: 'x' })).tier).toBe('red');
  });

  it('the two MCP classes are tagged correctly (P0-3)', () => {
    expect(classify(pre('mcp__vault__request', { verb: 'pay' })).gating).toBe('vault-request');
    const local = classify(pre('mcp__local__execute_checkout', { approval_id: 'x' }));
    expect(local.gating).toBe('local-approval');
    expect(local.tier).toBe('red');
  });

  it('unknown tools default-deny (RED)', () => {
    expect(classify(pre('mcp__evil__exfiltrate')).tier).toBe('red');
    expect(classify(pre('Frobnicate')).tier).toBe('red');
  });

  it('chrome-devtools: reads GREEN+isRead; observe/navigate/type GREEN+non-read; COMMIT ops YELLOW; evaluate_script + unknown RED', () => {
    for (const op of ['take_snapshot', 'take_screenshot', 'list_pages', 'get_console_message', 'wait_for']) {
      const c = classify(pre(`mcp__chrome-devtools__${op}`));
      expect(c.tier).toBe('green');
      expect(c.isRead).toBe(true);
    }
    // GREEN (non-read): observe / navigate / position / type-into-field — none COMMIT by themselves. Still
    // NON-read, so the paused kill-switch + depth guard stop them; the inspector REDs the dangerous args.
    for (const op of ['navigate_page', 'new_page', 'hover', 'close_page', 'fill', 'fill_form', 'type_text', 'emulate', 'get_network_request', 'list_network_requests']) {
      const c = classify(pre(`mcp__chrome-devtools__${op}`, { url: 'https://example.com' }));
      expect(c.tier).toBe('green');
      expect(c.isRead).toBe(false);
    }
    // COMMIT / ACTIVATE / EGRESS → YELLOW (the human checkpoint THE LAW requires)
    for (const op of ['click', 'press_key', 'drag', 'upload_file', 'handle_dialog']) {
      expect(classify(pre(`mcp__chrome-devtools__${op}`, { uid: '1' })).tier).toBe('yellow');
    }
    expect(classify(pre('mcp__chrome-devtools__evaluate_script', { function: '()=>1' })).tier).toBe('red');
    expect(classify(pre('mcp__chrome-devtools__future_op')).tier).toBe('red'); // unknown → default-deny
  });

  it('chrome-devtools inspector escalates the powerful-arg + crown-jewel cases to RED', () => {
    // crown-jewel navigate (incl. a real bank brand + a path login the old patterns missed)
    expect(classify(pre('mcp__chrome-devtools__navigate_page', { url: 'https://api.stripe.com' })).tier).toBe('red');
    expect(classify(pre('mcp__chrome-devtools__navigate_page', { url: 'https://www.chase.com/login' })).tier).toBe('red');
    expect(classify(pre('mcp__chrome-devtools__navigate_page', { url: 'https://login.microsoftonline.com/' })).tier).toBe('red');
    // broadened crown-jewel origins (RED, vault-only): webmail, dev/source, cloud consoles
    for (const u of ['https://mail.google.com/mail/u/0/', 'https://outlook.live.com/mail/', 'https://github.com/login', 'https://gitlab.com/users/sign_in', 'https://console.aws.amazon.com/', 'https://www.icloud.com/mail']) {
      expect(classify(pre('mcp__chrome-devtools__navigate_page', { url: u })).tier).toBe('red');
    }
    // ORDINARY (non-crown-jewel) login/registration → YELLOW (ask once per session), not RED, not GREEN
    for (const u of ['https://forum.example.com/login', 'https://shop.example.com/signup', 'https://app.example.com/users/sign_in', 'https://example.com/register']) {
      expect(classify(pre('mcp__chrome-devtools__navigate_page', { url: u })).tier).toBe('yellow');
    }
    // initScript = arbitrary in-page JS → RED (the evaluate_script keystone, parallel channel)
    expect(classify(pre('mcp__chrome-devtools__navigate_page', { url: 'https://example.com', initScript: 'fetch("//x")' })).tier).toBe('red');
    // emulate header / UA override = covert-exfil channel → RED
    expect(classify(pre('mcp__chrome-devtools__emulate', { extraHttpHeaders: { 'X-Exfil': 'secret' } })).tier).toBe('red');
    // network-body dump to a protected path → RED
    expect(classify(pre('mcp__chrome-devtools__get_network_request', { responseFilePath: '/u/jarvis-home/state/dump.json' })).tier).toBe('red');
    expect(classify(pre('mcp__chrome-devtools__upload_file', { filePath: '/home/user/.ssh/id_rsa' })).tier).toBe('red');
    expect(classify(pre('mcp__chrome-devtools__click', { uid: '1', text: 'Place order' })).tier).toBe('red');
    // broadened commit-label coverage (max-autonomy money guard): order-completion verbs → RED
    for (const label of ['Complete order', 'Confirm purchase', 'Order now', 'Place your order', 'Proceed to checkout', 'Buy']) {
      expect(classify(pre('mcp__chrome-devtools__click', { uid: '1', text: label })).tier).toBe('red');
    }
    // a benign-labeled click is YELLOW (every click is a commit checkpoint), NOT auto-allowed
    expect(classify(pre('mcp__chrome-devtools__click', { uid: '1', text: 'Read more' })).tier).toBe('yellow');
    // a typed crown-jewel URL (address-bar nav via type_text/fill) → RED; benign field text auto-allows GREEN
    expect(classify(pre('mcp__chrome-devtools__type_text', { text: 'https://accounts.google.com/signin' })).tier).toBe('red');
    expect(classify(pre('mcp__chrome-devtools__fill', { uid: '1', value: 'update my billing address' })).tier).toBe('green');
    // benign navigate auto-allows GREEN; an opaque click ASKS (YELLOW — the commit checkpoint)
    expect(classify(pre('mcp__chrome-devtools__navigate_page', { url: 'https://example.com' })).tier).toBe('green');
    expect(classify(pre('mcp__chrome-devtools__click', { uid: '1' })).tier).toBe('yellow');
  });

  it('SMART-CLICK RESOLVER (per-origin allow-once, end-to-end)', () => {
    const NORMAL = parseSnapshotText([
      'uid=2_0 RootWebArea "Docs" url="https://example.com/docs"',
      'uid=2_5 button "Read more"',
      'uid=2_9 button "Place order"',
      'uid=2_12 link "Sign in" url="https://example.com/login"',
      'uid=2_15 link "Open account" url="https://accounts.google.com/signin"',
      'uid=2_20 button "Subscribe now"',
    ].join('\n'));
    const CART = parseSnapshotText('uid=3_0 RootWebArea "Cart" url="https://shop.example.com/cart"\nuid=3_4 button "Continue"');
    const CHECKOUT = parseSnapshotText('uid=5_0 RootWebArea "Pay" url="https://shop.example.com/checkout"\nuid=5_4 button "Continue"');
    const CROWN = parseSnapshotText('uid=4_0 RootWebArea "GitHub" url="https://github.com/dashboard"\nuid=4_3 button "Settings"');
    const click = (uid: string) => pre('mcp__chrome-devtools__click', { uid });
    const allowed = (ctx: ReturnType<typeof parseSnapshotText>) => ({ ctx, allowedOrigins: ['https://example.com'] });
    const seen = (ctx: ReturnType<typeof parseSnapshotText>) => ({ ctx }); // resolved, origin NOT yet approved

    // benign click on an APPROVED origin → GREEN (auto-allow), but NON-read (kill-switch stops it)
    const benign = classify(click('2_5'), allowed(NORMAL));
    expect(benign.tier).toBe('green');
    expect(benign.isRead).toBe(false);
    // benign click on a NOT-yet-approved origin → YELLOW (the first-click-per-origin ask)
    expect(classify(click('2_5'), seen(NORMAL)).tier).toBe('yellow');

    // money / crown-jewel → RED (vault-only) — EVEN on an approved origin (allowance never covers these)
    expect(classify(click('2_9'), allowed(NORMAL)).tier).toBe('red'); // "Place order"
    expect(classify(click('2_15'), allowed(NORMAL)).tier).toBe('red'); // link → accounts.google.com
    expect(classify(click('4_3'), seen(CROWN)).tier).toBe('red'); // landed on github (crown-jewel origin)
    expect(classify(click('5_4'), seen(CHECKOUT)).tier).toBe('red'); // /checkout origin is a money keyword

    // softer money + login → YELLOW even on an approved origin
    expect(classify(click('2_20'), allowed(NORMAL)).tier).toBe('yellow'); // "Subscribe now" (money-ish)
    expect(classify(click('2_12'), allowed(NORMAL)).tier).toBe('yellow'); // "Sign in"
    expect(classify(click('3_4'), seen(CART)).tier).toBe('yellow'); // "Continue" on /cart (money-context path)

    // FAIL-SAFE: unresolved uid OR no session at all → YELLOW (never an auto-allow)
    expect(classify(click('9_99'), allowed(NORMAL)).tier).toBe('yellow'); // unknown uid
    expect(classify(click('2_5')).tier).toBe('yellow'); // no session threaded
    // the resolver is scoped to click — hover stays GREEN even with an unresolved uid (it can't commit)
    expect(classify(pre('mcp__chrome-devtools__hover', { uid: '9_99' }), allowed(NORMAL)).tier).toBe('green');
  });

  it('a capture op that SAVES TO FILE is a write (YELLOW + not read), and RED on a protected target', () => {
    // bare capture (no file) is a free GREEN read
    const bare = classify(pre('mcp__chrome-devtools__take_screenshot', {}));
    expect(bare.tier).toBe('green');
    expect(bare.isRead).toBe(true);
    // capture-to-file is a WRITE: YELLOW (asks) + not a read (respects the kill-switch + depth guards)
    const toFile = classify(pre('mcp__chrome-devtools__take_screenshot', { filePath: '/tmp/x.png' }));
    expect(toFile.tier).toBe('yellow');
    expect(toFile.isRead).toBe(false);
    // capture-to-PROTECTED-file → RED, even via a RELATIVE path resolved against cwd (F9)
    expect(classify(pre('mcp__chrome-devtools__take_snapshot', { filePath: '/u/jarvis-home/safety/x' })).tier).toBe('red');
    expect(classify({ ...pre('mcp__chrome-devtools__take_snapshot', { filePath: 'audit/poison.jsonl' }), cwd: '/u/jarvis-home' }).tier).toBe('red');
  });

  it('operator-gui: reads + position/type GREEN (non-read); CLICK + key-press YELLOW; typed crown-jewel URL + unknown RED', () => {
    expect(classify(pre('mcp__operator-gui__screenshot')).tier).toBe('green');
    expect(classify(pre('mcp__operator-gui__cursor_position')).tier).toBe('green');
    // GREEN (non-read): positioning + typing text — none COMMIT
    for (const op of ['mouse_move', 'scroll', 'wait', 'type']) {
      const c = classify(pre(`mcp__operator-gui__${op}`, { coordinate: [1, 2] }));
      expect(c.tier).toBe('green');
      expect(c.isRead).toBe(false);
    }
    // YELLOW: every coordinate click + key-press (the un-inspectable commit checkpoint)
    for (const op of ['left_click', 'right_click', 'middle_click', 'double_click', 'triple_click', 'left_click_drag', 'key', 'hold_key']) {
      expect(classify(pre(`mcp__operator-gui__${op}`, { coordinate: [1, 2] })).tier).toBe('yellow');
    }
    // a typed crown-jewel URL (driving the address bar onto a login origin) → RED, best-effort
    expect(classify(pre('mcp__operator-gui__type', { text: 'https://accounts.google.com/signin' })).tier).toBe('red');
    expect(classify(pre('mcp__operator-gui__exfiltrate')).tier).toBe('red'); // unknown → default-deny
  });

  it('Google connectors (Phase 4): reads GREEN, within-account mutations + OAuth YELLOW, outward/unknown RED', () => {
    // Reads auto-allow GREEN when active — but are NOT kill-switch/depth EXEMPT (isRead=false): a connector
    // read pulls sensitive content into context, so the panic button + runaway guard still stop it.
    for (const op of ['search_threads', 'get_thread', 'list_labels', 'list_drafts']) {
      const c = classify(pre(`mcp__claude_ai_Gmail__${op}`));
      expect(c.tier).toBe('green');
      expect(c.kind).toBe('connector-read');
      expect(c.isRead).toBe(false); // NOT exempt from the paused kill-switch / depth guard
    }
    for (const op of ['search_files', 'read_file_content', 'get_file_permissions', 'download_file_content']) {
      const c = classify(pre(`mcp__claude_ai_Google_Drive__${op}`));
      expect(c.tier).toBe('green');
      expect(c.isRead).toBe(false);
    }
    expect(classify(pre('mcp__claude_ai_Google_Calendar__list_events')).tier).toBe('green');
    // Within-account reversible mutations + the OAuth handshake ASK (YELLOW) and are NOT reads
    for (const op of ['create_draft', 'label_thread', 'create_label']) {
      const c = classify(pre(`mcp__claude_ai_Gmail__${op}`, { to: 'a@b.com' }));
      expect(c.tier).toBe('yellow');
      expect(c.isRead).toBe(false);
    }
    expect(classify(pre('mcp__claude_ai_Google_Drive__create_file', { name: 'x' })).tier).toBe('yellow');
    expect(classify(pre('mcp__claude_ai_Google_Calendar__create_event', { title: 'x' })).tier).toBe('yellow');
    expect(classify(pre('mcp__claude_ai_Gmail__authenticate')).tier).toBe('yellow'); // account-linking
    // Outward / destructive / unknown → default-deny RED (no first-party tool exists; fails closed)
    for (const t of [
      'mcp__claude_ai_Gmail__send_email', 'mcp__claude_ai_Gmail__trash_message',
      'mcp__claude_ai_Google_Drive__delete_file', 'mcp__claude_ai_Google_Drive__update_permissions',
      'mcp__claude_ai_Google_Calendar__delete_event', 'mcp__claude_ai_Gmail__future_superpower',
      'mcp__claude_ai_Dropbox__list_files',
    ]) {
      expect(classify(pre(t)).tier).toBe('red');
    }
  });
});
