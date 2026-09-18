// Secret-shape detection — a pure, dependency-free heuristic shared by the datastore (reject
// secret-shaped memory writes, P2-17) and the safety gate (redact secret-shaped tool args before
// they are sealed, F8; refuse Write/Edit of secret content). Kept in @jarvis/shared so neither the
// datastore nor the safety spine has to import the other (module-dependency law).

/** Known credential shapes. Exported (frozen) so secret-shape.test.ts can pin one positive per entry. */
export const SECRET_SHAPES: readonly RegExp[] = Object.freeze([
  /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/,
  /\bAKIA[0-9A-Z]{16}\b/,
  // `sk-` keys, INCLUDING the modern vendor-prefixed forms. The old pattern was /\bsk-[A-Za-z0-9]{20,}\b/,
  // which requires the body to be alphanumerics only — so `sk-proj-…`, `sk-ant-api03-…` and `sk_test_…` all
  // failed at the first inner separator. They were then caught ONLY when the whole tool-arg value was the
  // bare token (the generic rule below is anchored), so a live key sitting inside a line of code
  // (`const k = "sk-proj-…"`) matched nothing at all. Confirmed 2026-08-28.
  /\bsk[-_](?:[A-Za-z0-9]+[-_])*[A-Za-z0-9]{16,}\b/,
  /\bsk_live_[0-9A-Za-z]{16,}\b/,
  /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/,
  /\bnpm_[A-Za-z0-9]{36}\b/,
  /\bgh[pousr]_[A-Za-z0-9]{36,}\b/,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/,
  // A credential ASSIGNMENT. The separator may be preceded and the value followed by a quote, because the
  // most common thing the Brain writes is JSON: `"api_key": "…"`. The old pattern put `[:=]` immediately
  // after the keyword's word boundary, so the closing quote in JSON (and the `=` in XML/attr form) sat
  // between them and it never matched a config file at all. Confirmed 2026-08-28.
  // `>` is a separator too, so the XML/HTML element form `<token>value</token>` matches alongside
  // JSON (`"api_key": "…"`), YAML (`password: …`) and env (`API_KEY=…`).
  /\b(?:password|passwd|secret|api[_-]?key|token)\b["'`\]]?\s*(?:[:=]>?|>)\s*["'`]?\S{6,}/i,
]);

function luhnValid(digits: string): boolean {
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    let d = digits.charCodeAt(i) - 48;
    if (d < 0 || d > 9) return false;
    if (alt) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    alt = !alt;
  }
  return sum % 10 === 0;
}

function looksLikeCard(value: string): boolean {
  const matches = value.match(/\b(?:\d[ -]?){13,19}\b/g);
  if (!matches) return false;
  return matches.some((m) => {
    const digits = m.replace(/[ -]/g, '');
    return digits.length >= 13 && digits.length <= 19 && !/^(\d)\1+$/.test(digits) && luhnValid(digits);
  });
}

function bitsPerChar(value: string): number {
  const counts = new Map<string, number>();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/** How many DISTINCT characters the token draws on. Its log2 is the hard ceiling on bitsPerChar. */
function distinctChars(value: string): number {
  return new Set(value).size;
}

/**
 * Does the token use its own character set close to UNIFORMLY — the signature of a randomly generated
 * secret, as opposed to structured text, whose character frequencies are skewed?
 *
 * WHY THIS REPLACED A FIXED `bitsPerChar >= 3.5`: per-character entropy is hard-bounded by
 * log2(alphabet size), so ONE absolute threshold means completely different strictness per alphabet. The
 * 3.5 constant was tuned for the base64-ish charset the regex admits (ceiling ~6.0, lots of headroom) and
 * was then applied to small sub-alphabets sitting at or below it — hex ceilings at 4.0, and DIGITS ceiling
 * at log2(10) = 3.32, i.e. BELOW the threshold, so a pure-digit secret could never be detected at any
 * length. Measured miss rates on 5000 random tokens per cell (2026-08-28):
 *
 *     alphabet          len 20    24     32     40     64
 *     lowercase hex      79.4%  55.9%  18.4%   4.4%   0.1%
 *     digits only       100.0% 100.0% 100.0% 100.0% 100.0%
 *
 * Normalising against the token's OWN ceiling removes the alphabet dependence, which was the actual defect.
 * `distinct >= 8` keeps degenerate strings out ("ababab…" uses its 2-char set perfectly uniformly but is
 * plainly not a secret), and the ratio is what separates a random draw from structured text.
 */
function usesCharsetUniformly(token: string): boolean {
  const distinct = distinctChars(token);
  if (distinct < 8) return false;
  const ceiling = Math.log2(distinct);
  return bitsPerChar(token) >= 0.85 * ceiling;
}

/**
 * A PLAIN IDENTIFIER: word-like segments (letters, then at most three digits — `v2`, `sha256`, `api03`) joined
 * by `-`, `_` or `/`. `user_profile_settings_manager_v2`, `react-dom-server-legacy-node`,
 * `feature/improve-checkout-flow-v2`, `getUserProfileSettingsManagerV2` and a 25-letter passphrase all use
 * their alphabet "uniformly enough" to pass the entropy rule at 20-40 chars, so an Edit whose new_string was
 * a branch or symbol name was DENIED, not asked (cold review 2026-09-17, TQ-3). A random token virtually never
 * splits into letter-only segments (a 20-char base62 draw has no digit with p ≈ 3%; hex never does), so this
 * excludes identifiers without opening the branch to real tokens.
 *
 * DECIDED — structured hex is NOT an identifier here: a git SHA (40 hex) and a UUID stay secret-shaped. They
 * are also the exact shape of a legacy 40-hex GitHub token and of a Heroku API key, and the gate cannot tell
 * an id from a credential by shape alone. Fail-closed; pinned in secret-shape.test.ts.
 */
function isPlainIdentifier(token: string): boolean {
  return token.split(/[-_/]+/).every((seg) => /^[A-Za-z]+\d{0,3}$/.test(seg));
}

/** True if a value looks like a secret (private key, card, high-entropy token, credential assignment). */
export function isSecretShaped(value: string): boolean {
  if (isStrongSecret(value)) return true;
  const token = value.trim();
  // The OLD absolute threshold is kept as an alternative so nothing detected before becomes undetected;
  // the union is strictly more inclusive than either rule alone.
  if (token.length >= 20 && /^[A-Za-z0-9+/=_-]+$/.test(token) && !isPlainIdentifier(token)
      && (bitsPerChar(token) >= 3.5 || usesCharsetUniformly(token))) {
    return true;
  }
  return false;
}

/**
 * True only for a STRONGLY-shaped secret (a known credential pattern or a Luhn card) — excludes the
 * generic high-entropy heuristic, so legitimately random identifiers (session ids, call ids, UUIDs)
 * do NOT match. Used to scrub audit metadata fields without mangling honest identifiers (F8/F12).
 */
export function isStrongSecret(value: string): boolean {
  return SECRET_SHAPES.some((re) => re.test(value)) || looksLikeCard(value);
}
