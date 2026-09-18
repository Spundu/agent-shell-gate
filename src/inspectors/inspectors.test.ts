import { describe, it, expect } from 'vitest';
import { inspectChromeDevtools } from './chrome-devtools.js';
import { inspectComputerUse } from './computer-use.js';
import { inspectFile } from './file.js';
import { inspectFetch } from './fetch.js';
import { inspectRead } from './read.js';
import { parseSnapshotText, type BrowserContext } from '../browser-context.js';

const FAKE_AWS_KEY = `AKIA${'ABCDEFGHIJKLMNOP'}`; // pragma: allowlist secret — matches the AKIA rejector

describe('inspectRead (native read tools — crown-jewel parity with Bash, #8)', () => {
  it('RED on crown-jewel/secret targets via Read/Grep/Glob keys', () => {
    expect(inspectRead({ file_path: '/u/jarvis-home/state/seal.key.dpapi' })?.tier).toBe('red');
    expect(inspectRead({ file_path: '/home/user/.ssh/id_rsa' })?.tier).toBe('red');
    expect(inspectRead({ path: '/home/user/.aws/credentials' })?.tier).toBe('red'); // Grep search dir
    expect(inspectRead({ pattern: '**/*.dpapi' })?.tier).toBe('red'); // Glob pattern
    expect(inspectRead({ file_path: './seal.key.dpapi' }, '/u/jarvis-home/state')?.tier).toBe('red'); // F9 relative
    // round-2: whole-directory coverage (#6) + new stores (#7/#8/#9)
    expect(inspectRead({ path: '/home/user/.kube' })?.tier).toBe('red'); // recursive Grep over parent dir
    expect(inspectRead({ path: '/home/user/.docker' })?.tier).toBe('red');
    expect(inspectRead({ file_path: '/home/user/.azure/accessTokens.json' })?.tier).toBe('red'); // azure
    expect(inspectRead({ file_path: '/home/user/.config/doctl/config.yaml' })?.tier).toBe('red'); // doctl
    expect(inspectRead({ file_path: '/home/user/.bash_history' })?.tier).toBe('red'); // history
    expect(inspectRead({ file_path: '/home/user/.config/google-chrome/Default/Local State' })?.tier).toBe('red'); // chromium key
    // round-3 enumeration additions
    expect(inspectRead({ file_path: '/home/user/.pypirc' })?.tier).toBe('red');
    expect(inspectRead({ file_path: '/home/user/.config/sops/age/keys.txt' })?.tier).toBe('red');
    expect(inspectRead({ file_path: '/home/user/.config/rclone/rclone.conf' })?.tier).toBe('red');
    expect(inspectRead({ file_path: '/home/user/project/main.tfstate' })?.tier).toBe('red');
    expect(inspectRead({ file_path: '/home/user/wallet.dat' })?.tier).toBe('red');
  });

  it('RED on a recursive read rooted at an intermediate ancestor of a secret leaf (RT round-4 #3)', () => {
    expect(inspectRead({ path: '/home/user/.config/google-chrome' })?.tier).toBe('red'); // browser profile root
    expect(inspectRead({ path: '/home/user/.mozilla' })?.tier).toBe('red');
    expect(inspectRead({ path: '/home/user/.config/containers' })?.tier).toBe('red');
    expect(inspectRead({ file_path: '/home/user/.ethereum/keystore/UTC--x' })?.tier).toBe('red');
  });

  it('YELLOW (review) for a recursive read over a broad root (RT round-3 #B / round-4)', () => {
    expect(inspectRead({ path: '/home/user' })?.tier).toBe('yellow'); // whole home — recurses into dotfile secrets
    expect(inspectRead({ path: '/home/user/.config' })?.tier).toBe('yellow'); // parent of many secret stores
    expect(inspectRead({ path: '/home/user/.config/somenewapp' })?.tier).toBe('yellow'); // any .config child app dir
    expect(inspectRead({ path: '/' })?.tier).toBe('yellow'); // filesystem root
  });

  it('null (stays GREEN) for ordinary source reads', () => {
    expect(inspectRead({ file_path: '/home/user/code/app.ts' })).toBeNull();
    expect(inspectRead({ pattern: '**/*.ts' })).toBeNull();
    expect(inspectRead({ path: '/home/user/code' })).toBeNull(); // a narrow project dir is fine
    expect(inspectRead({})).toBeNull();
  });

  it('ALLOWS reading Claude Code tool-results overflow files (tool outputs under .claude, not secrets)', () => {
    // The operator reads its own offloaded snapshot here instead of saving a copy via a gated write.
    expect(inspectRead({ file_path: '/home/user/.claude/projects/-home-user/sid/tool-results/mcp-chrome-devtools-take_snapshot-9.txt' })).toBeNull();
    expect(inspectRead({ path: '/home/user/.claude/projects/p/sid/tool-results' })).toBeNull(); // the dir
  });
  it('but a TRAVERSAL out of tool-results to a real secret is still RED (no carve-out bypass)', () => {
    expect(inspectRead({ file_path: '/home/user/.claude/projects/p/sid/tool-results/../../../../.ssh/id_rsa' })?.tier).toBe('red');
    // a non-tool-results .claude file (settings) stays RED
    expect(inspectRead({ file_path: '/home/user/.claude/settings.json' })?.tier).toBe('red');
  });
});

describe('inspectFile', () => {
  it('RED on protected paths', () => {
    expect(inspectFile({ file_path: '/x/.claude/settings.json' }).tier).toBe('red');
    expect(inspectFile({ file_path: '/x/CLAUDE.md' }).tier).toBe('red');
    expect(inspectFile({ file_path: '/u/jarvis-home/state/seal.key.dpapi' }).tier).toBe('red');
  });

  it('RED on a relative path that RESOLVES into a protected dir (F9)', () => {
    expect(inspectFile({ file_path: './approved-actions.json' }, '/u/jarvis-home/state').tier).toBe('red');
    expect(inspectFile({ file_path: '../config/brain.settings.json' }, '/u/jarvis-home/state').tier).toBe('red');
  });

  it('RED on secret-shaped write content (F8)', () => {
    expect(inspectFile({ file_path: '/home/user/x', content: FAKE_AWS_KEY }).tier).toBe('red');
  });

  it('YELLOW on ordinary workspace writes', () => {
    expect(inspectFile({ file_path: '/home/user/code/app.ts', content: 'const x = 1;' }).tier).toBe('yellow');
  });
});

describe('inspectFetch', () => {
  it('RED always, with payment origins flagged specifically', () => {
    expect(inspectFetch({ url: 'http://example.com' }).tier).toBe('red');
    expect(inspectFetch({ url: 'https://api.stripe.com' }).reason).toMatch(/payment/);
  });
});

describe('inspectChromeDevtools', () => {
  it('RED on a navigation to a payment/crown-jewel origin', () => {
    for (const url of [
      'https://api.stripe.com/v1/charges',
      'https://www.paypal.com/checkout',
      'https://checkout.shop.com/cart',
      'https://my.bank.com/transfer',
      'https://accounts.google.com/signin',
      'https://appleid.apple.com/auth',
      'https://www.namecheap.com/cart',
    ]) {
      expect(inspectChromeDevtools({ url })?.tier).toBe('red');
    }
    // `link` arg is also checked.
    expect(inspectChromeDevtools({ link: 'https://accounts.google.com/signin' })?.tier).toBe('red');
  });

  it('YELLOW (ask-once) on a GENERIC login/registration page on an ordinary host (not a crown jewel)', () => {
    for (const url of [
      'https://signin.example.com',
      'https://forum.example.com/login',
      'https://shop.example.com/signup',
      'https://app.example.com/users/sign_in',
      'https://example.com/register',
    ]) {
      expect(inspectChromeDevtools({ url })?.tier).toBe('yellow');
    }
    // a crown-jewel host on a login path still wins RED (checked before the login/registration YELLOW)
    expect(inspectChromeDevtools({ url: 'https://github.com/login' })?.tier).toBe('red');
    expect(inspectChromeDevtools({ url: 'https://mail.google.com/' })?.tier).toBe('red');
  });

  it('RED on uploading a crown-jewel/secret file', () => {
    expect(inspectChromeDevtools({ filePath: '/home/user/.ssh/id_rsa' })?.tier).toBe('red');
    expect(inspectChromeDevtools({ path: '/srv/app/.env' })?.tier).toBe('red');
    expect(inspectChromeDevtools({ file: '/u/jarvis-home/state/seal.key.dpapi' })?.tier).toBe('red');
  });

  it('RED on a click/target whose control label names a payment/submit action', () => {
    expect(inspectChromeDevtools({ text: 'Pay now' })?.tier).toBe('red');
    expect(inspectChromeDevtools({ label: 'Place order' })?.tier).toBe('red');
    expect(inspectChromeDevtools({ text: 'Complete purchase' })?.tier).toBe('red');
  });

  it('RED on a script-bearing arg (initScript = arbitrary in-page JS, the evaluate_script keystone)', () => {
    expect(inspectChromeDevtools({ url: 'https://example.com', initScript: 'fetch("//x")' })?.tier).toBe('red');
    expect(inspectChromeDevtools({ pageScript: 'document.cookie' })?.tier).toBe('red');
    expect(inspectChromeDevtools({ initScript: '   ' })).toBeNull(); // blank is not a script
  });

  it('RED on a request-header / user-agent override (emulate covert-exfil channel)', () => {
    expect(inspectChromeDevtools({ extraHttpHeaders: { 'X-Exfil': 'secret' } })?.tier).toBe('red');
    expect(inspectChromeDevtools({ userAgent: 'EvilBot/1.0' })?.tier).toBe('red');
  });

  it('RED on a network-body dump targeting a crown-jewel or protected path', () => {
    expect(inspectChromeDevtools({ responseFilePath: '/home/user/.ssh/id_rsa' })?.tier).toBe('red');
    expect(inspectChromeDevtools({ requestFilePath: '/u/jarvis-home/state/dump.json' })?.tier).toBe('red'); // protected
  });

  it('RED on a RELATIVE protected file path once resolved against cwd (F9 parity)', () => {
    expect(inspectChromeDevtools({ filePath: 'audit/poison.jsonl' }, '/u/jarvis-home')?.tier).toBe('red');
    expect(inspectChromeDevtools({ responseFilePath: 'safety/hook-pre.cjs' }, '/u/jarvis-home')?.tier).toBe('red');
    // CONTRACT CHANGE 2026-08-23: an ordinary file arg is no longer `null` — every save-to-disk now asks.
    // It used to rely on classifyMcp having already made the op YELLOW, which held for take_screenshot but
    // NOT for the ops in CDT_GREEN_OPS, so take_heapsnapshot{filePath} / get_network_request
    // {responseFilePath} / performance_stop_trace{filePath} were silent dump-to-disk channels at GREEN.
    // The inspector is escalate-only, so ops that were already YELLOW are unaffected.
    expect(inspectChromeDevtools({ filePath: 'notes/page.png' }, '/home/user')?.tier).toBe('yellow');
  });

  it('RED on a typed crown-jewel URL (address-bar nav), null on benign free text', () => {
    expect(inspectChromeDevtools({ text: 'https://accounts.google.com/signin' })?.tier).toBe('red');
    expect(inspectChromeDevtools({ value: 'www.bankofamerica.com' })?.tier).toBe('red');
    expect(inspectChromeDevtools({ elements: [{ value: 'https://checkout.shop.com/cart' }] })?.tier).toBe('red');
    expect(inspectChromeDevtools({ text: 'update my billing address next week' })).toBeNull();
    expect(inspectChromeDevtools({ value: 'checkout the new feature please' })).toBeNull();
  });

  it('null (no escalation) on benign navigate/click/fill — value is NOT pay-scanned', () => {
    expect(inspectChromeDevtools({ url: 'https://example.com/docs' })).toBeNull();
    expect(inspectChromeDevtools({ uid: '42' })).toBeNull();
    expect(inspectChromeDevtools({ uid: '7', value: 'pay rent invoice' })).toBeNull(); // a fill value, not a control
    // See the CONTRACT CHANGE note above: a dump-to-file asks even when the path is ordinary.
    expect(inspectChromeDevtools({ responseFilePath: '/home/user/dump.json' })?.tier).toBe('yellow');
  });
});

describe('inspectChromeDevtools — SMART-CLICK RESOLVER (per-origin allow-once)', () => {
  // A normal page with a mix of benign, money, login, money-ish, and crown-jewel-link controls.
  const NORMAL = parseSnapshotText([
    'uid=2_0 RootWebArea "Docs" url="https://example.com/docs"',
    'uid=2_5 button "Read more"',
    'uid=2_9 button "Place order"',
    'uid=2_12 link "Sign in" url="https://example.com/login"',
    'uid=2_15 link "Open account" url="https://accounts.google.com/signin"',
    'uid=2_20 button "Subscribe"',
  ].join('\n'));
  // A cart page (ordinary host, money-context PATH): even a generic "Continue" here is a money step.
  const CART = parseSnapshotText('uid=3_0 RootWebArea "Cart" url="https://shop.example.com/cart"\nuid=3_4 button "Continue"');
  // A /checkout page: the "checkout" keyword makes the ORIGIN itself a money origin → RED (stronger).
  const CHECKOUT = parseSnapshotText('uid=5_0 RootWebArea "Pay" url="https://shop.example.com/checkout"\nuid=5_4 button "Continue"');
  // A crown-jewel landing (a redirect put us on github): ANY click is vault-only.
  const CROWN = parseSnapshotText('uid=4_0 RootWebArea "GitHub" url="https://github.com/dashboard"\nuid=4_3 button "New repository"');
  const APPROVED = ['https://example.com']; // the human approved auto-clicks on example.com this session
  // a click whose origin the human has ALREADY approved:
  const onAllowed = (uid: string, ctx = NORMAL) =>
    inspectChromeDevtools({ uid }, undefined, { op: 'click', ctx, allowedOrigins: APPROVED });
  // a click whose origin is NOT yet approved (the first-click-per-origin case):
  const firstClick = (uid: string, ctx = NORMAL) => inspectChromeDevtools({ uid }, undefined, { op: 'click', ctx });

  it('benign click on an APPROVED origin → no escalation (stays GREEN — the frictionless path)', () => {
    expect(onAllowed('2_5')).toBeNull();
  });
  it('benign click on a NOT-yet-approved origin → YELLOW (the first-click-per-origin ask grants the origin)', () => {
    expect(firstClick('2_5')?.tier).toBe('yellow');
  });
  it('a resolved pay/order-commit control → RED even on an approved origin (allowance never covers money)', () => {
    expect(onAllowed('2_9')?.tier).toBe('red');
  });
  it('a softer money-ish control (Subscribe) → YELLOW even on an approved origin', () => {
    expect(onAllowed('2_20')?.tier).toBe('yellow');
  });
  it('money-ish NOUN forms ("subscription"/"pledging") → YELLOW on an approved origin (red-team cycle 1)', () => {
    const ctx = parseSnapshotText([
      'uid=7_0 RootWebArea "Plans" url="https://example.com/account/plans"',
      'uid=7_1 button "Start subscription"',
      'uid=7_2 button "Confirm subscription"',
      'uid=7_3 button "Pledging now"',
    ].join('\n'));
    const c = (uid: string) => inspectChromeDevtools({ uid }, undefined, { op: 'click', ctx, allowedOrigins: APPROVED });
    expect(c('7_1')?.tier).toBe('yellow'); // "Start subscription" must NOT slip to GREEN
    expect(c('7_2')?.tier).toBe('yellow');
    expect(c('7_3')?.tier).toBe('yellow'); // "Pledging"
  });
  it('a click whose link NAVIGATES to a crown-jewel origin → RED', () => {
    expect(onAllowed('2_15')?.tier).toBe('red');
  });
  it('a resolved login/sign-in control → YELLOW even on an approved origin', () => {
    expect(onAllowed('2_12')?.tier).toBe('yellow');
  });
  it('a benign-labeled click while ON a money-context page (/cart) → YELLOW even if the origin is approved', () => {
    expect(inspectChromeDevtools({ uid: '3_4' }, undefined, { op: 'click', ctx: CART, allowedOrigins: ['https://shop.example.com'] })?.tier).toBe('yellow');
  });
  it('a click while ON a /checkout origin (money keyword) → RED (origin is crown-jewel)', () => {
    expect(inspectChromeDevtools({ uid: '5_4' }, undefined, { op: 'click', ctx: CHECKOUT, allowedOrigins: ['https://shop.example.com'] })?.tier).toBe('red');
  });
  it('ANY click while landed on a crown-jewel origin → RED', () => {
    expect(firstClick('4_3', CROWN)?.tier).toBe('red');
  });
  it('an UNRESOLVED click (unknown uid / no ctx) → YELLOW (fail-safe ask)', () => {
    expect(onAllowed('9_99')?.tier).toBe('yellow'); // uid not in the snapshot
    expect(inspectChromeDevtools({ uid: '2_5' }, undefined, { op: 'click' })?.tier).toBe('yellow'); // no ctx
  });

  // ── Click-resolution DIAGNOSIS (2026-08-27). The audit chain showed 6 of 17 real clicks failing to
  // resolve under ONE collapsed reason, so the cause could not be fixed without guessing. Every case below
  // is still YELLOW — only the reason distinguishes them, which is exactly the point.
  describe('unresolved-click diagnosis (reason only — the tier is unconditionally YELLOW)', () => {
    const reasonFor = (input: Record<string, unknown>, ctx?: BrowserContext): string => {
      const r = inspectChromeDevtools(input, undefined, { op: 'click', ...(ctx ? { ctx } : {}) });
      expect(r?.tier).toBe('yellow'); // the tier NEVER varies with the diagnosis
      return r?.reason ?? '';
    };

    it('no context at all → names the missing snapshot (not a generic "not resolved")', () => {
      expect(reasonFor({ uid: '2_5' })).toMatch(/no page snapshot captured this session/);
    });
    it('a context that parsed to zero nodes → names the capture/parse failure', () => {
      expect(reasonFor({ uid: '2_5' }, parseSnapshotText(''))).toMatch(/held no nodes/);
    });
    it('a uid from a DIFFERENT generation → named as STALE, with both generations', () => {
      // NORMAL holds generation 2; the agent is clicking against generation 7.
      const reason = reasonFor({ uid: '7_11' }, NORMAL);
      expect(reason).toMatch(/stale snapshot/);
      expect(reason).toContain('generation 7');
      expect(reason).toContain('holds 2');
    });
    it('a uid in the CURRENT generation but absent from the tree → named as absent, not stale', () => {
      const reason = reasonFor({ uid: '2_999' }, NORMAL);
      expect(reason).toMatch(/absent from the current snapshot/);
      expect(reason).not.toMatch(/stale/);
    });
    it('a click with no uid at all → named, and never treated as resolved', () => {
      expect(reasonFor({}, NORMAL)).toMatch(/no uid to resolve/);
      expect(reasonFor({ uid: '' }, NORMAL)).toMatch(/no uid to resolve/);
    });
    it('an agent-supplied uid is TRUNCATED in the reason (it is written to the sealed audit event)', () => {
      const reason = reasonFor({ uid: `2_${'A'.repeat(500)}` }, NORMAL);
      expect(reason.length).toBeLessThan(120);
      expect(reason).toContain('…');
    });
    it('a uid with no generation prefix still fails safe, with the absent-uid reason', () => {
      expect(reasonFor({ uid: 'no-generation-here' }, NORMAL)).toMatch(/absent from the current snapshot/);
    });
    it('the diagnosis NEVER downgrades a money/login click that also fails to resolve', () => {
      // A stale uid on a CHECKOUT page: the origin RED must still win over any resolution diagnosis.
      expect(inspectChromeDevtools({ uid: '99_1' }, undefined, { op: 'click', ctx: CHECKOUT })?.tier).toBe('red');
    });
  });
  it('CONFLICTING RootWebArea origins (spoof signal, red-team #2) → YELLOW, NOT downgraded to GREEN', () => {
    const SPOOF = parseSnapshotText([
      'uid=6_0 RootWebArea "Pay" url="https://shop.example.com/checkout"',
      'uid=6_4 button "Continue"',
      'uid=6_9 RootWebArea "ok" url="https://example.com/"', // injected 2nd root to spoof the origin to a benign one
    ].join('\n'));
    expect(SPOOF.originConflict).toBe(true);
    expect(SPOOF.pageUrl).toBeUndefined();
    // even with example.com "approved", the conflict forces ASK — the real /checkout RED is NOT laundered to GREEN
    expect(inspectChromeDevtools({ uid: '6_4' }, undefined, { op: 'click', ctx: SPOOF, allowedOrigins: APPROVED })?.tier).toBe('yellow');
  });
  it('the resolver fires ONLY for the click op — hover with an unresolved uid stays GREEN (null)', () => {
    expect(inspectChromeDevtools({ uid: '9_99' }, undefined, { op: 'hover', ctx: NORMAL })).toBeNull();
  });
  it('with NO browser hint at all, a bare uid is inert (back-compat: the classifier supplies the op/ctx)', () => {
    expect(inspectChromeDevtools({ uid: '2_9' })).toBeNull(); // no op → click block skipped
  });
});

describe('inspectComputerUse', () => {
  it('RED on a typed string carrying a payment/crown-jewel URL (address-bar drive)', () => {
    expect(inspectComputerUse({ action: 'type', text: 'https://accounts.google.com/signin' })?.tier).toBe('red');
    expect(inspectComputerUse({ text: 'https://www.bankofamerica.com' })?.tier).toBe('red');
  });

  it('null on coordinate actions / benign typed text (coordinates carry no inspectable origin)', () => {
    expect(inspectComputerUse({ action: 'left_click', coordinate: [10, 20] })).toBeNull();
    expect(inspectComputerUse({ action: 'type', text: 'hello world' })).toBeNull();
    expect(inspectComputerUse({})).toBeNull();
  });
});
