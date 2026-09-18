import { isSecretShaped } from '../shared/secret-shape.js';
import { PAYMENT_CROWN_JEWEL_HOSTS, DANGEROUS_URL_SCHEMES, LOGIN_REGISTRATION_PATTERNS } from '../policy.js';
import {
  fileArgPaths, typedCrownJewelUrl, typedLoginUrl, urlMatches, urlMatchesAny,
} from './browser-args.js';
import { CROWN_JEWEL_READ_PATTERNS } from '../policy.js';
import { resolveToolPath } from './path.js';
import { strongest, type InspectorResult } from './result.js';

// The argument inspector for Claude in Chrome (`mcp__claude-in-chrome__<op>`) — the second browser channel.
// ESCALATE-ONLY, like every inspector here: it can raise a tier, never lower one.
//
// WHY THIS IS NOT JUST chrome-devtools WITH DIFFERENT ARG NAMES. Every page-acting op here is addressed by a
// bare integer `tabId`, not by a snapshot-bound `uid`. A tabId survives navigation and is recycled, so there
// is no generation to check and no way to know WHERE that tab is now. The chrome-devtools smart-click
// resolver works precisely because a stale uid is DETECTABLE and fails safe to ask; the equivalent here
// would fail OPEN, naming a benign origin for a tab that has since moved. So this inspector deliberately
// does NOT attempt an origin resolution — the catalog tier carries that weight (every commit asks), and
// what is inspected here is only what genuinely IS in the arguments: URLs, typed text, and file paths.
//
// Anything the args do not contain is not guessed. See catalog.ts for the tier rationale.

/** Every string leaf in a value, so a URL cannot hide inside an array or a nested object. */
function stringLeaves(value: unknown, depth = 0): string[] {
  if (depth > 4) return [];
  if (typeof value === 'string') return [value];
  if (Array.isArray(value)) return value.flatMap((v) => stringLeaves(v, depth + 1));
  if (value !== null && typeof value === 'object') {
    return Object.values(value as Record<string, unknown>).flatMap((v) => stringLeaves(v, depth + 1));
  }
  return [];
}

/** The URL-ish arguments of a navigate. Plural/alternate keys included: a rule that reads only `url` is
 * defeated by the same value arriving as `urls` or inside an object, which is how arg-smuggling works. */
const URL_KEYS = ['url', 'urls', 'href', 'link', 'target', 'destination'] as const;

export function inspectClaudeInChrome(
  toolInput: Record<string, unknown>,
  cwd?: string,
): InspectorResult | null {
  let pendingLogin: InspectorResult | null = null;
  let pendingSubmit: InspectorResult | null = null;

  // ── 1. NAVIGATION TARGETS ──────────────────────────────────────────────────────────────────────────
  for (const key of URL_KEYS) {
    for (const url of stringLeaves(toolInput[key])) {
      if (urlMatches(url, DANGEROUS_URL_SCHEMES)) {
        return { tier: 'red', reason: 'dangerous URL scheme (javascript:/data:/blob:/vbscript:) — blocked' };
      }
      if (urlMatchesAny(url, PAYMENT_CROWN_JEWEL_HOSTS)) {
        return { tier: 'red', reason: 'navigate to payment/crown-jewel origin (vault-only)' };
      }
      if (urlMatchesAny(url, LOGIN_REGISTRATION_PATTERNS)) {
        pendingLogin = { tier: 'yellow', reason: 'navigates to a login/registration URL (ask once per session)' };
      }
    }
  }

  // ── 2. TYPED / FILLED VALUES ───────────────────────────────────────────────────────────────────────
  // `form_input` and `computer{action:type}` both put a string into the page. A card number or an API key
  // going in that way is vault-only on EVERY channel — that parity is the whole point of having one gate.
  for (const key of ['value', 'text', 'input', 'content', 'query'] as const) {
    for (const typed of stringLeaves(toolInput[key])) {
      if (isSecretShaped(typed)) {
        return { tier: 'red', reason: 'secret-shaped value typed into a page (card/token) — vault-only' };
      }
      if (typedCrownJewelUrl(typed)) {
        return { tier: 'red', reason: 'typed text drives a payment/crown-jewel URL — hand off to the vault' };
      }
      if (typedLoginUrl(typed)) {
        pendingLogin = { tier: 'yellow', reason: 'typed text drives a login/registration URL (ask once per session)' };
      }
      // SILENT SUBMIT: an embedded newline presses Enter inside the same call, so it fills AND submits
      // with no separate checkpoint. Same rule the other two channels carry.
      if (/[\r\n]/.test(typed)) {
        pendingSubmit = {
          tier: 'yellow',
          reason: 'typed text contains Enter — types AND submits in one call (a commit — ask)',
        };
      }
    }
  }

  // ── 3. FILE EGRESS ─────────────────────────────────────────────────────────────────────────────────
  // file_upload / upload_image push a local file INTO an untrusted page. A crown-jewel path there is
  // exfiltration, not an upload — the same check upload_file carries on the chrome-devtools side.
  for (const raw of fileArgPaths(toolInput)) {
    const probes = [raw, resolveToolPath(raw, cwd)];
    if (probes.some((p) => CROWN_JEWEL_READ_PATTERNS.some((re) => re.test(p)))) {
      return { tier: 'red', reason: 'uploads a crown-jewel/secret file into a page (vault-only)' };
    }
  }

  return strongest(pendingSubmit, pendingLogin);
}
