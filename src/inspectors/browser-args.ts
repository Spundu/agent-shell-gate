import { PAYMENT_CROWN_JEWEL_HOSTS, LOGIN_REGISTRATION_PATTERNS } from '../policy.js';

// Shared helpers for the browser-operator inspectors + the catalog's arg-aware classification. Kept in their
// own leaf module (imports only policy) so both catalog.ts and the inspectors can use them with no cycle.

/** Arg keys across the chrome-devtools ops that cause a FILE WRITE to disk (save-to-file / dump-to-file).
 * A read-classed op carrying one of these is NOT a free read — it writes the world (see catalog.ts). */
export const FILE_WRITE_KEYS = [
  'filePath', 'path', 'file', 'requestFilePath', 'responseFilePath', 'outputDirPath',
  // `upload_file`'s REAL argument is the PLURAL ARRAY `filePaths` — it was in neither this list nor the
  // string-only guard below, so `upload_file {filePaths:['~/.ssh/id_rsa']}` reached the page at YELLOW while
  // the singular `{filePath:...}` was correctly RED. Sending a crown-jewel file INTO an untrusted page is
  // strictly worse than dumping one to local disk (found 2026-08-28).
  'filePaths', 'files', 'paths',
] as const;

/** Every file path named by the tool input, across BOTH the string and the array-valued keys. */
export function fileArgPaths(toolInput: Record<string, unknown>): string[] {
  const out: string[] = [];
  for (const key of FILE_WRITE_KEYS) {
    const value = toolInput[key];
    if (typeof value === 'string' && value.length > 0) out.push(value);
    else if (Array.isArray(value)) {
      for (const item of value) if (typeof item === 'string' && item.length > 0) out.push(item);
    }
  }
  return out;
}

/** The first non-empty file-write target in the tool input, or undefined. */
export function fileWriteArg(toolInput: Record<string, unknown>): string | undefined {
  return fileArgPaths(toolInput)[0];
}

/**
 * Every form of a URL the BROWSER may actually act on. The gate must test its patterns against ALL of them,
 * because the browser normalises before it navigates and the gate was comparing the raw string.
 *
 * Two demonstrated bypasses (2026-08-28), both classified GREEN:
 *  1. CONTROL CHARACTERS IN THE SCHEME. The WHATWG URL parser REMOVES every ASCII tab (U+0009), LF and CR
 *     from anywhere in the input before parsing. `java<TAB>script:fetch(...)` is `javascript:` to the
 *     browser, but `DANGEROUS_URL_SCHEMES` — which needs the scheme contiguous — did not match, and a
 *     scheme URL has no host for the crown-jewel patterns to catch either. That is arbitrary in-page JS,
 *     the capability `evaluate_script` is RED for, reached at GREEN by one whitespace character.
 *  2. PERCENT-ENCODING. `https://git%68ub.com/x` reaches github.com, but `/\bgithub\.com/` is a literal.
 *
 * Decoding can only ADD matches, and every pattern that consumes these forms is escalate-only, so a false
 * positive costs one prompt and never opens a hole — the direction this repo has consistently chosen
 * ("over-matching is safe", policy.ts). Malformed percent sequences throw, and are simply skipped.
 */
export function urlMatchForms(url: string): string[] {
  const forms = [url];
  const push = (candidate: string): void => {
    if (candidate && !forms.includes(candidate)) forms.push(candidate);
  };
  // (1) exactly what the WHATWG parser strips, from anywhere in the input.
  const stripped = url.replace(/[\t\n\r]/g, '');
  push(stripped);
  // (2) percent-decoding. Both a full decode (catches an encoded PATH keyword like `/che%63kout`) and an
  //     authority-only decode (kept separate so a malformed query cannot suppress the host check).
  for (const base of forms.slice()) {
    try {
      push(decodeURIComponent(base));
    } catch {
      /* malformed % sequence — the raw form is still tested */
    }
    const m = /^([A-Za-z][A-Za-z0-9+.-]*:)?(\/\/)([^/?#]*)([\s\S]*)$/.exec(base);
    if (m) {
      try {
        push(`${m[1] ?? ''}${m[2]}${decodeURIComponent(m[3] ?? '')}${m[4] ?? ''}`);
      } catch {
        /* malformed authority encoding — raw form still tested */
      }
    }
  }
  return forms;
}

/** True if ANY normalised form of `url` matches ANY of `patterns`. Escalate-only by construction. */
export function urlMatchesAny(url: string, patterns: readonly RegExp[]): boolean {
  const forms = urlMatchForms(url);
  return patterns.some((re) => forms.some((f) => re.test(f)));
}

/** True if ANY normalised form of `url` matches the single `pattern`. */
export function urlMatches(url: string, pattern: RegExp): boolean {
  return urlMatchForms(url).some((f) => pattern.test(f));
}

const URL_TOKEN = /\bhttps?:\/\/[^\s'"]+/i;
// A bare host typed into an address/URL field, e.g. "accounts.google.com/signin", "www.bank.com" — a dotted
// host with no whitespace. Deliberately URL-SHAPED so free text ("update my billing", "checkout the cart")
// does NOT false-positive against the broad crown-jewel keyword patterns.
const BARE_HOST = /^(www\.)?[a-z0-9-]+(\.[a-z0-9-]+)+(\/\S*)?$/i;

/** The URL/host candidates embedded in a typed value (a URL token and/or a bare dotted host). URL-SHAPED
 * only, so free text doesn't false-positive against the broad keyword patterns. */
function urlCandidates(value: string): string[] {
  const candidates: string[] = [];
  const m = value.match(URL_TOKEN);
  if (m) candidates.push(m[0]);
  const bare = value.trim();
  if (BARE_HOST.test(bare)) candidates.push(bare);
  return candidates;
}

/** True if `value` is (or embeds) a URL/host that resolves to a payment/crown-jewel origin — catches a
 * crown-jewel URL typed into an address/URL field (the address-bar navigation vector). */
export function typedCrownJewelUrl(value: string): boolean {
  return urlCandidates(value).some((c) => urlMatchesAny(c, PAYMENT_CROWN_JEWEL_HOSTS));
}

/** True if `value` is (or embeds) a generic login/registration URL (NOT a crown-jewel host) — the typed
 * (address-bar) vector for visiting a login/signup page → YELLOW (ask-once). Crown-jewel is checked first. */
export function typedLoginUrl(value: string): boolean {
  return urlCandidates(value).some((c) => urlMatchesAny(c, LOGIN_REGISTRATION_PATTERNS));
}
