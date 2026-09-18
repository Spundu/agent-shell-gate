import {
  PAYMENT_CROWN_JEWEL_HOSTS, CROWN_JEWEL_READ_PATTERNS, PROTECTED_PATH_PATTERNS, LOGIN_REGISTRATION_PATTERNS,
  DANGEROUS_URL_SCHEMES,
} from '../policy.js';
import { isSecretShaped } from '../shared/secret-shape.js';
import {
  resolveClickTarget, originOf, uidGeneration, contextGenerations,
  type BrowserContext, type BrowserHint,
} from '../browser-context.js';
import {
  fileArgPaths, typedCrownJewelUrl, typedLoginUrl, urlMatches, urlMatchesAny,
} from './browser-args.js';
import { resolveToolPath } from './path.js';
import { strongest, type InspectorResult } from './result.js';

// The argument inspector for the chrome-devtools MCP (Browser Operator). Escalate-ONLY: it can raise a tier
// but never lower one (the classifier takes maxTier). It reasons ONLY about the agent's own structured
// arguments — NEVER about page content (which is untrusted; see the threat model). Single source of truth:
// it reuses PAYMENT_CROWN_JEWEL_HOSTS + CROWN_JEWEL_READ_PATTERNS + PROTECTED_PATH_PATTERNS from policy.ts.
//
// HONEST SCOPE: the origin RED catches a DIRECT navigate / typed crown-jewel URL, but it is NOT airtight —
// it cannot see an open-redirect or a client-side navigation, and the gate is stateless (it cannot read the
// browser's LANDED origin). The real money/login backstops are the layered controls (attended yellow-ask,
// the SANDBOXED logged-out operator profile, the vault) + the operator's landed-origin re-check (Phase D),
// NOT this inspector alone. See design-notes/BROWSER-OPERATOR-THREAT-MODEL.md.

// Visible-label hints that name a money / order-commit control → RED (hand off to the vault). Under the
// max-autonomy posture (clicks are GREEN by default), THIS is the load-bearing block that keeps the
// operator from PLACING AN ORDER / MOVING MONEY without the vault — so it covers the common commit verbs,
// not just "pay". BEST-EFFORT for DOM clicks (matched on the control's own label/text, never a fill VALUE);
// coordinate clicks (operator-gui) carry no label, so their money-safety rests on the no-card logged-out
// profile + crown-jewel-origin RED + live oversight (see threat model §5). Slight over-blocking of a benign
// "buy"/"checkout" link is accepted — money-safety beats one extra prompt.
const PAY_SUBMIT_LABEL =
  /\b(pay|buy|checkout|check\s*out|order\s+now|pre-?order)\b|\b(place|complete|confirm|submit|review|finali[sz]e|authori[sz]e|proceed\s+to|continue\s+to)\b[\s\S]{0,16}\b(order|purchase|payment|checkout)\b/i;

// The LABEL analog of LOGIN_REGISTRATION_PATTERNS (which are URL-shaped): a RESOLVED click whose control text
// names a login / sign-up / account action → YELLOW (ask once). Over-matching is safe (a benign "Sign up for
// the newsletter" just adds one prompt — never opens a money/login hole).
const LOGIN_SUBMIT_LABEL =
  /\b(log\s?in|sign\s?in|sign\s?on|log\s?on|sign\s?up|register|registration|create\s+account|continue\s+with)\b/i;
// SOFTER money-ish commit verbs (red-team #3/#5: the e-commerce-only PAY_SUBMIT_LABEL missed whole money
// categories). These → YELLOW (ASK), not RED — they're ambiguous (a free "Subscribe to newsletter" is not a
// charge), so the human decides rather than a hard vault-only block. The point is they NEVER auto-allow, even
// on an already-approved origin. Clearly-pay verbs stay in PAY_SUBMIT_LABEL (RED).
// NOTE on stems: use `subscri\w*` (NOT `subscrib\w*`) — "subscription" is spelled subscri-P-tion, so a
// `subscrib` stem misses the noun form (red-team cycle 1). Likewise `pledg\w*` catches "pledging"/"pledges".
const MONEY_ISH_LABEL =
  /\b(subscri\w*|donat\w*|pledg\w*|contribut\w*|member(?:ship)?|become\s+a\s+member|renew\w*|redeem\w*|upgrade|send\s+money|transfer\s+(?:funds|money)|wire\s+(?:funds|money)|gift\s+card|add\s+funds|top\s*-?\s*up)\b/i;
// A page-URL PATH that signals a money/checkout context. A resolved click while ON such a page is YELLOW even
// when its own label looks benign (a generic "Continue"/"Next" on a checkout page is still a money step).
const MONEY_CONTEXT_PATH =
  /[/](?:cart|carts|shopping-?cart|checkout|check-?out|order|orders|payment|pay|billing|basket|purchase|subscri\w*|donat\w*|member(?:ship)?|pledg\w*)\b/i;

// A uid is agent-supplied, so it is truncated before it reaches a reason string (the reason is written to the
// sealed audit event and rendered to the human — it must stay short and boring).
const UID_ECHO_MAX = 32;
const echoUid = (uid: string): string => (uid.length > UID_ECHO_MAX ? `${uid.slice(0, UID_ECHO_MAX)}…` : uid);

/** WHY a click failed to resolve. EVERY branch returns the same YELLOW — this is pure DIAGNOSIS, not policy.
 *
 * It exists because the audit chain showed 6 of 17 real clicks failing to resolve, all carrying one
 * indistinguishable reason string, which made the cause unfixable without guessing (`tasks/lessons.md`:
 * instrument before fixing). The reason lands in the sealed audit event for every such ask, so the next
 * browsing run tells us which of these it actually is. */
function unresolvedClickReason(
  toolInput: Record<string, unknown>,
  ctx: BrowserContext | undefined,
): string {
  const uid = toolInput['uid'];
  if (typeof uid !== 'string' || uid.length === 0) {
    return 'click carries no uid to resolve — ask (fail-safe)';
  }
  if (!ctx) {
    return 'no page snapshot captured this session — ask (fail-safe: take_snapshot first)';
  }
  const gens = contextGenerations(ctx);
  if (gens.size === 0) {
    return 'page snapshot captured but held no nodes (parse/capture failure) — ask (fail-safe)';
  }
  const gen = uidGeneration(uid);
  if (gen !== undefined && !gens.has(gen)) {
    // Sorted + capped so the reason stays short and deterministic when a context spans several generations.
    const held = [...gens].sort().slice(0, 4).join('/');
    return `stale snapshot: click targets generation ${gen}, context holds ${held} — ask (fail-safe)`;
  }
  return `uid ${echoUid(uid)} absent from the current snapshot — ask (fail-safe)`;
}

/** Typed strings the operator supplies (could carry a crown-jewel URL driven into an address/URL field). */
function typedValues(toolInput: Record<string, unknown>): string[] {
  const out: string[] = [];
  for (const key of ['text', 'value']) {
    const v = toolInput[key];
    if (typeof v === 'string') out.push(v);
  }
  const elements = toolInput['elements']; // fill_form: [{ value }, ...]
  if (Array.isArray(elements)) {
    for (const el of elements) {
      if (el && typeof el === 'object') {
        const v = (el as Record<string, unknown>)['value'];
        if (typeof v === 'string') out.push(v);
      }
    }
  }
  return out;
}

export function inspectChromeDevtools(
  toolInput: Record<string, unknown>,
  cwd?: string,
  browser?: BrowserHint,
): InspectorResult | null {
  // 0) Arbitrary in-page JS via a script-bearing arg (navigate_page/new_page `initScript`, or any *Script
  //    key) = the SAME capability as evaluate_script → RED.
  for (const [key, value] of Object.entries(toolInput)) {
    if (typeof value === 'string' && value.trim() && (key === 'initScript' || key === 'script' || /Script$/.test(key))) {
      return { tier: 'red', reason: 'in-page script arg = arbitrary JS (same control as evaluate_script — RED)' };
    }
  }
  // 1) Request-header / user-agent override (emulate) = persistent covert-exfil + auth-injection → RED.
  const ua = toolInput['userAgent'];
  if (toolInput['extraHttpHeaders'] != null || (typeof ua === 'string' && ua.trim())) {
    return { tier: 'red', reason: 'request-header / user-agent override (covert exfil / injection) — RED' };
  }
  // A pending YELLOW (login/registration access → ask-once). Collected but returned LAST, so any RED below
  // (crown-jewel host, pay label, secret file) always WINS over it.
  let pendingLogin: InspectorResult | null = null;
  // A save-to-disk ask, held like pendingLogin so any RED below still wins.
  let pendingFileWrite: InspectorResult | null = null;
  // A `file://` navigation ask, held for the same reason.
  let pendingFileRead: InspectorResult | null = null;
  // 1b) A SECRET-SHAPED value driven into the page (fill / fill_form / type_text) → RED, vault-only. This is
  //     the browser mirror of inspectFile's "refusing to write secret-shaped content to disk": a card number
  //     or an API token must never leave the vault, and typing it into an UNTRUSTED page is strictly worse
  //     than writing it to local disk. It classified GREEN (verified 2026-08-23: a Luhn-valid PAN and an
  //     `sk-ant-…` key both auto-executed). Note isSecretShaped matches PANs/tokens/JWTs, NOT passwords —
  //     so an ordinary site login is unaffected; the credential channel is covered by the login patterns.
  if (typedValues(toolInput).some(isSecretShaped)) {
    return { tier: 'red', reason: 'secret-shaped value typed into a page (card/token) — vault-only' };
  }
  // 1c) SILENT SUBMIT. The threat model's stated reason typing is GREEN is that "typing a value doesn't send
  //     it; the SUBMIT (a click / Enter) does, and that asks". Two args defeat exactly that: type_text's
  //     `submitKey` presses Enter as part of the same call, and a typed TEXT that embeds a newline does the
  //     same. Both were GREEN, so a form could be filled AND submitted with no human in the loop. Escalate
  //     to the tier a real submit carries.
  //
  //     THE NEWLINE HALF WAS MISSED THE FIRST TIME (found by the 2026-08-23 deep audit, confirmed against
  //     the LIVE deployed gate). The original fix added the newline check to inspectComputerUse and only the
  //     `submitKey` check here — while the comment above it already named BOTH channels. So the FALLBACK
  //     channel was covered and the PRIMARY one was not: `type_text{text:"secret\n"}` stayed GREEN.
  //     `type_text` is documented as "Type text using keyboard", so an embedded \n is an Enter KEYSTROKE.
  //
  //     Deliberately NOT applied to `fill`/`fill_form`: those SET a value rather than typing keys, and a
  //     multi-line value is ordinary there (a textarea bio, an address). Asking on every such fill would be
  //     an over-block, and an ask nobody believes is worth less than no ask at all.
  //
  //     Held as PENDING, never returned early: this inspector is escalate-only, so a YELLOW that
  //     short-circuits would LOSE a RED below it — e.g. type_text{text:"accounts.google.com", submitKey}
  //     must stay the crown-jewel RED, not become a submit ask.
  const submitKey = toolInput['submitKey'];
  const typedText = toolInput['text'];
  const submitsViaKey = typeof submitKey === 'string' && submitKey.trim().length > 0;
  // `text` is TYPED by type_text. wait_for also takes a `text`, but as a MATCH TARGET on a read — a newline
  // there is not a keystroke, and asking would be a pure over-block. Anything else carrying `text` is
  // treated as typing (fail closed); `op` is derived from the tool name, so it is always known here.
  const NON_TYPING_TEXT_OPS: ReadonlySet<string> = new Set(['wait_for']);
  const submitsViaNewline =
    !NON_TYPING_TEXT_OPS.has(browser?.op ?? '') && typeof typedText === 'string' && /[\r\n]/.test(typedText);
  const pendingSubmit: InspectorResult | null =
    submitsViaKey || submitsViaNewline
      ? {
          tier: 'yellow',
          reason: submitsViaKey
            ? 'type + submitKey submits the form in one call (a commit — ask)'
            : 'typed text contains Enter — types AND submits in one call (a commit — ask)',
        }
      : null;
  // 2) Navigation target (url/link arg): crown-jewel origin → RED (vault-only); a generic login/registration
  //    page on an ORDINARY host → YELLOW (ask once per session). Crown-jewel is checked first so it wins.
  const url = [toolInput['url'], toolInput['link']].find((v): v is string => typeof v === 'string');
  if (url) {
    // `javascript:`/`data:`/`blob:`/`vbscript:` navigation IS in-page script execution — the same capability
    // as evaluate_script, which is RED and is even in the settings deny-belt. It reached GREEN because this
    // block only ever tested the URL against HOST patterns, and a scheme URL has no host to match.
    // Tested over every NORMALISED form (urlMatchForms): the WHATWG parser strips ASCII tab/LF/CR from
    // anywhere in the input before reading the scheme, so `java<TAB>script:` and `da<TAB>ta:` are the same
    // URLs to the browser while defeating a contiguous-literal regex. Verified GREEN before this (2026-08-28).
    if (urlMatches(url, DANGEROUS_URL_SCHEMES)) {
      return { tier: 'red', reason: 'javascript:/data: navigation = arbitrary in-page JS (same control as evaluate_script) — RED' };
    }
    // `file://` reads a LOCAL file into the page (and thus into the agent's context, and into anything the
    // page can exfiltrate). RED when it names a crown-jewel/protected path, otherwise an ask.
    if (urlMatches(url, /^\s*file:/i)) {
      const localPath = url.replace(/^\s*file:\/\/(?:localhost)?/i, '');
      const probes = [localPath, resolveToolPath(localPath, cwd)];
      if (probes.some((p) => [...CROWN_JEWEL_READ_PATTERNS, ...PROTECTED_PATH_PATTERNS].some((re) => re.test(p)))) {
        return { tier: 'red', reason: 'file:// navigation to a crown-jewel/protected path (vault-only)' };
      }
      // HELD, NOT RETURNED (fixed 2026-08-28): returning here made every check below unreachable for any
      // `file:` url — including the typed-crown-jewel RED (§3) and the file-arg protected-path RED (§4),
      // both of which rest on a DIFFERENT argument entirely.
      pendingFileRead ??= { tier: 'yellow', reason: 'file:// navigation reads a local file into the page — ask' };
    }
    if (urlMatchesAny(url, PAYMENT_CROWN_JEWEL_HOSTS)) {
      return { tier: 'red', reason: 'navigate to payment/crown-jewel origin (vault-only)' };
    }
    if (urlMatchesAny(url, LOGIN_REGISTRATION_PATTERNS)) {
      pendingLogin = { tier: 'yellow', reason: 'navigate to a login/registration page (ask once per session)' };
    }
  }
  // 3) A crown-jewel URL typed into an address/URL field (type_text / fill / fill_form) → RED; a generic
  //    login/registration URL typed → YELLOW. Mirrors the Computer-Use channel.
  const typed = typedValues(toolInput);
  if (typed.some(typedCrownJewelUrl)) {
    return { tier: 'red', reason: 'typed text drives a payment/crown-jewel URL (address-bar nav) — vault-only' };
  }
  if (!pendingLogin && typed.some(typedLoginUrl)) {
    pendingLogin = { tier: 'yellow', reason: 'typed text drives a login/registration URL (ask once per session)' };
  }
  // 4) A file-WRITE arg (save-to-file / dump-to-file). RED if it targets a crown-jewel/protected path —
  //    checked on BOTH the raw string AND the cwd-resolved absolute path (F9), so a RELATIVE path like
  //    'audit/x.jsonl' cannot slip past the leading-slash protected patterns. (The op is already YELLOW via
  //    classifyMcp's arg-aware classification, so a non-protected write still asks; this adds the RED.)
  // fileArgPaths covers BOTH the string keys and the ARRAY-valued ones (upload_file's `filePaths`), which the
  // old string-only loop skipped entirely.
  {
    for (const target of fileArgPaths(toolInput)) {
      const probes = [target, resolveToolPath(target, cwd)];
      if (probes.some((p) => [...CROWN_JEWEL_READ_PATTERNS, ...PROTECTED_PATH_PATTERNS].some((re) => re.test(p)))) {
        return { tier: 'red', reason: 'file arg targets a crown-jewel/protected path (vault-only)' };
      }
      // ...and ANY save-to-disk is at least an ask. The comment above assumed classifyMcp had already made
      // the op YELLOW via its arg-aware classification, which holds for take_screenshot but NOT for the ops
      // sitting in CDT_GREEN_OPS: take_heapsnapshot{filePath}, get_network_request{responseFilePath} and
      // performance_stop_trace{filePath} all classified GREEN (verified 2026-08-23) — three silent
      // dump-to-disk channels, one of which writes a full heap snapshot that can contain page secrets.
      // Escalating here keeps the rule in one place instead of re-deriving it per op in the catalog.
      pendingFileWrite ??= { tier: 'yellow', reason: 'browser dump-to-file (save to disk — ask)' };
    }
  }
  // 5) Best-effort backstop: a control label naming a payment/submit action → RED. Excludes a fill VALUE.
  const target = [toolInput['uid'], toolInput['selector'], toolInput['label'], toolInput['text']]
    .filter((v): v is string => typeof v === 'string')
    .join(' ');
  if (PAY_SUBMIT_LABEL.test(target)) {
    return { tier: 'red', reason: 'payment/submit control — hand off to the vault' };
  }
  // 6) SMART-CLICK RESOLVER (per-origin allow-once, decided 2026-06-14): `click` is GREEN base, but its `uid` is
  //    opaque — resolve it against the session's snapshot context and escalate by WHAT IT TARGETS / WHERE IT
  //    LANDS. The page-authored label/url/origin can ONLY ESCALATE (raise friction), NEVER justify an
  //    auto-allow — the ONLY thing that opens GREEN is the human having approved auto-clicks on THIS origin this
  //    session (browser.allowedOrigins). This closes the red-team's denylist-fails-open class: a money/login
  //    click is never GREEN by virtue of a benign-looking page. ONLY the `click` op is resolved here.
  // 5b) THE LANDED ORIGIN gates EVERY page interaction, not just `click`.
  //
  // This check used to live inside the click branch, so it only ever ran for `click`. With the session
  // snapshot showing the browser landed on accounts.google.com/signin, the tiers were:
  //     click -> RED        fill -> GREEN    fill_form -> GREEN    type_text -> GREEN
  // i.e. the operator could type the human's credentials INTO a crown-jewel login page with no gate at all,
  // while merely clicking a button on the same page was vault-only. Typing the credential is the more
  // dangerous half. Verified 2026-08-28.
  //
  // READS stay GREEN deliberately: observing a crown-jewel page is not the threat the profile invariant is
  // about — ESTABLISHING or USING a session there is (see BROWSER-OPERATOR-THREAT-MODEL.md §4a). Navigation
  // is excluded too: it is judged on its TARGET url above, and blocking it here would strand the operator on
  // the very page we want it to leave.
  const PAGE_INTERACTION_OPS: ReadonlySet<string> = new Set([
    'click', 'fill', 'fill_form', 'type_text', 'press_key', 'drag', 'upload_file', 'handle_dialog',
  ]);
  const landedUrl = browser?.ctx?.originConflict ? undefined : browser?.ctx?.pageUrl;
  if (
    browser?.op !== undefined && PAGE_INTERACTION_OPS.has(browser.op) &&
    landedUrl !== undefined && urlMatchesAny(landedUrl, PAYMENT_CROWN_JEWEL_HOSTS)
  ) {
    return { tier: 'red', reason: `${browser.op} on a payment/crown-jewel origin (vault-only)` };
  }

  let clickVerdict: InspectorResult | null = null;
  if (browser?.op === 'click') {
    const ctx = browser.ctx;
    const pageUrl = ctx?.pageUrl;
    const node = resolveClickTarget(toolInput, ctx);
    // FAIL-SAFE: the page origin is untrusted — conflicting RootWebArea roots (red-team #2 spoof signal) →
    // ASK. `parseSnapshotText` deletes pageUrl on a conflict, so no PAGE-level verdict below is sound.
    //
    // HELD, NOT RETURNED (fixed 2026-08-28). Returning it here skipped the NODE-derived REDs below, which
    // rest on entirely different evidence (the control's own label/url). A page that appends a second
    // RootWebArea — the very spoof this branch detects — therefore DOWNGRADED a "Place order" click from
    // RED to a mere ask: page-authored content lowering a tier, which this file states must never happen.
    if (ctx?.originConflict) {
      clickVerdict = { tier: 'yellow', reason: 'page origin ambiguous/untrusted (conflicting snapshot roots) — ask' };
    }
    // RED (vault-only): we are LANDED ON a payment/crown-jewel origin. This depends ONLY on `pageUrl`, never
    // on resolving the node — so it MUST be decided before the unresolved-node fail-safe below.
    //
    // IT USED TO SIT AFTER IT (found 2026-08-27 by a test written for the resolution diagnosis). Because the
    // `!node` branch returned early with a YELLOW, a click carrying a uid that was simply ABSENT from the
    // snapshot — a stale generation, or one the agent invented — turned this DENY into an ASK on a checkout
    // or github page. That is the same shape as the F1 silent-submit finding: an escalate-only inspector
    // must never `return` a YELLOW while a RED that does not depend on the same evidence is still below it.
    if (pageUrl && PAYMENT_CROWN_JEWEL_HOSTS.some((re) => re.test(pageUrl))) {
      return { tier: 'red', reason: 'click on a payment/crown-jewel origin (vault-only)' };
    }
    // FAIL-SAFE: an unresolved click (no/stale snapshot, unknown uid) → ASK. The TIER is unconditional; only
    // the reason distinguishes the cause, so a diagnosis bug can add confusion but never open a hole.
    if (!node) {
      clickVerdict ??= { tier: 'yellow', reason: unresolvedClickReason(toolInput, ctx) };
    } else {
      const nodeUrl = node.url;
      const targetText = [node.label, nodeUrl].filter((s): s is string => typeof s === 'string').join(' ');
      // RED (vault-only): the control LINKS TO a payment-crown-jewel origin (node-dependent, so it belongs here).
      if (nodeUrl && PAYMENT_CROWN_JEWEL_HOSTS.some((re) => re.test(nodeUrl))) {
        return { tier: 'red', reason: 'click navigates to a payment/crown-jewel origin (vault-only)' };
      }
      if (PAY_SUBMIT_LABEL.test(targetText)) {
        return { tier: 'red', reason: 'click on a payment/order-commit control (vault-only)' };
      }
      // YELLOW (ask — NEVER covered by the per-origin allowance): softer money verbs, login/registration
      // controls or pages (label OR page-URL — red-team #4), money-context page paths.
      if (
        MONEY_ISH_LABEL.test(targetText) ||
        LOGIN_SUBMIT_LABEL.test(targetText) ||
        (nodeUrl != null && LOGIN_REGISTRATION_PATTERNS.some((re) => re.test(nodeUrl))) ||
        (pageUrl != null && LOGIN_REGISTRATION_PATTERNS.some((re) => re.test(pageUrl))) ||
        (pageUrl != null && MONEY_CONTEXT_PATH.test(pageUrl))
      ) {
        clickVerdict ??= { tier: 'yellow', reason: 'click in a login / money context — ask' };
      } else {
        // Benign control. AUTO-ALLOW (GREEN) ONLY if the human approved auto-clicks on THIS origin this session;
        // else the FIRST benign click on a new origin ASKS — approving grants the origin (see hook-post.ts).
        const origin = originOf(pageUrl);
        if (!origin || !browser.allowedOrigins?.includes(origin)) {
          clickVerdict ??= {
            tier: 'yellow',
            reason: origin
              ? `first click on ${origin} this session — approve to auto-allow benign clicks here (money/login still ask)`
              : 'benign click but page origin unknown — ask (fail-safe)',
          };
        }
        // else: approved origin + benign control → contributes NO verdict, so the base tier (GREEN) stands
        // — but the pendings below still apply, which is the point of the 2026-08-28 fix.
      }
    }
  }
  // THE ONLY EXIT for every non-RED path. `strongest` takes the maximum, so no branch can shadow another and
  // adding a check in the "wrong" place cannot open a hole.
  //
  // The click branch USED TO `return` from inside itself, which silently discarded pendingSubmit and
  // pendingFileWrite: `click{uid, filePath}` was GREEN while the identical args on `hover` were YELLOW, and
  // `click{uid, submitKey}` dropped the F1 silent-submit escalation entirely. That auto-allowed the exact
  // call that carries a forged snapshot path to hook-post (see browser-ctx-store), so the context-forgery
  // channel needed no human prompt at all. Found 2026-08-28.
  //
  // Order within a tier still decides the REASON a human reads: submit and dump-to-disk name an ACTION being
  // taken, which is more useful than the access note, so they come before the login/click verdicts.
  return strongest(pendingSubmit, pendingFileWrite, pendingFileRead, clickVerdict, pendingLogin);
}
