// Smart-click resolver — FOUNDATION (pure parsing + resolution; no live-gate wiring yet).
//
// The safety gate is a stateless arg-inspector: a chrome-devtools `click {uid}` carries only an opaque uid,
// so the gate cannot tell a benign click from a money/login commit. This module lets the gate become
// CONTEXT-AWARE: the chrome-devtools `take_snapshot` (and navigation) result is an accessibility tree that
// names every element + the page URL, e.g.
//     uid=1_0 RootWebArea "GitHub · …" url="https://github.com/"
//     uid=1_15 link "Sign in" url="https://github.com/login"
//     uid=1_27 button "Sign up for GitHub"
// The PostToolUse hook will parse that result into a per-session BrowserContext; the PreToolUse hook will
// resolve a click's uid → its role/label/url so the inspector can classify the click by WHAT IT TARGETS.
//
// Coupling to the chrome-devtools snapshot TEXT format is isolated HERE and is FULLY FAIL-SAFE: anything this
// module cannot parse yields an empty/absent context → the click classifier (built next) treats an
// unresolved click as YELLOW (ask). So a format change can only ADD prompts, never open a hole.

/** A resolved snapshot element: its ARIA role, accessible label, and (for links) destination URL. */
export interface SnapshotNode {
  role: string;
  label?: string;
  url?: string;
}

/** The browser context for a session: the current page URL + a uid → node map from the latest snapshot.
 * `originConflict` is set when the snapshot text contained MORE THAN ONE RootWebArea url (an injection /
 * cross-frame-spoof signal) — the page URL is then untrusted and the resolver fails safe to ASK. */
export interface BrowserContext {
  pageUrl?: string;
  originConflict?: boolean;
  nodes: Record<string, SnapshotNode>;
}

/** The session's per-origin click allowance + the latest snapshot — everything the click resolver needs. */
export interface BrowserSession {
  ctx?: BrowserContext;
  allowedOrigins?: readonly string[];
}

/** What the classifier hands the chrome-devtools inspector so it can reason about a click in context: the
 * mcp op name (e.g. 'click'), the session's latest BrowserContext, and the per-origin click allowance (the
 * origins the human has approved auto-clicks on THIS session). All optional — absent → the inspector fail-safes
 * (an unresolved click, or a benign click on a not-yet-approved origin → YELLOW ask). */
export interface BrowserHint {
  op?: string;
  ctx?: BrowserContext;
  allowedOrigins?: readonly string[];
}

/** The scheme://host origin of a URL (lowercased host), or undefined if it isn't an absolute http(s) URL.
 * Used as the key for the per-origin click allowance. The host portion is browser-reported (a page can
 * `history.pushState` only WITHIN its own origin, never cross-origin), so the origin is a sound allowance
 * key once the multi-RootWebArea spoof is closed (see parseSnapshotText). */
export function originOf(url: string | undefined): string | undefined {
  if (typeof url !== 'string') return undefined;
  const m = /^(https?):\/\/([^/?#\s]+)/i.exec(url);
  if (!m || !m[1] || !m[2]) return undefined;
  // Strip any `userinfo@` so the key is the TRUE browser origin: per the URL spec the host is the authority
  // AFTER the last '@', so `https://approved.com@evil.com/` is really evil.com — not approved.com. Using the
  // real host means a userinfo-disguised URL can never match an approved origin (it correctly resolves to its
  // actual host). Both GRANT and CHECK call this, so the normalization is consistent on both sides.
  const authority = m[2];
  const at = authority.lastIndexOf('@');
  const host = at >= 0 ? authority.slice(at + 1) : authority;
  if (!host) return undefined;
  return `${m[1].toLowerCase()}://${host.toLowerCase()}`;
}

// A snapshot line: `<indent>uid=<id> <role>[ "<label>"][ ...attrs incl url="..."]`. The LABEL is the quoted
// string that immediately follows the role (role SPACE quote); attribute values like `level="2"` /
// `live="polite"` are `key="value"` (no space before the quote) so they never match the label group.
const NODE_RE = /uid=(\S+)\s+([A-Za-z]\w*)(?:\s+"((?:[^"\\]|\\.)*)")?/;
const URL_ATTR_RE = /\burl="([^"]*)"/;

/** Parse a chrome-devtools snapshot text into a BrowserContext. Unparseable input → empty context. */
export function parseSnapshotText(text: string): BrowserContext {
  const ctx: BrowserContext = { nodes: {} };
  if (typeof text !== 'string' || !text) return ctx;
  let rootSeen = false;
  for (const line of text.split('\n')) {
    const m = NODE_RE.exec(line);
    if (!m) continue;
    const uid = m[1];
    const role = m[2];
    const label = m[3];
    if (!uid || !role) continue;
    const urlM = URL_ATTR_RE.exec(line);
    const url = urlM ? urlM[1] : undefined;
    const node: SnapshotNode = { role };
    if (label !== undefined) node.label = unescapeQuotes(label);
    if (url !== undefined) node.url = url;
    ctx.nodes[uid] = node;
    // The document root is the FIRST RootWebArea line; its url is the page URL. A SECOND RootWebArea with a
    // DIFFERENT url is an injection / cross-frame-spoof signal (red-team #2: a page appends a benign root to
    // override the real origin) — treat the page URL as UNTRUSTED so the click resolver fails safe to ASK
    // instead of trusting the attacker-chosen origin. First-wins (not last-wins) so a later forged root never
    // overrides the real document root.
    if (role === 'RootWebArea' && url) {
      if (!rootSeen) {
        ctx.pageUrl = url;
        rootSeen = true;
      } else if (url !== ctx.pageUrl) {
        delete ctx.pageUrl;
        ctx.originConflict = true;
      }
    }
  }
  return ctx;
}

function unescapeQuotes(s: string): string {
  return s.replace(/\\"/g, '"').replace(/\\\\/g, '\\');
}

/** True if a blob looks like the a11y snapshot tree (has `uid=… <role>` lines). The gate-safe guard: only
 * text that actually looks like a snapshot is ever treated as one. */
export function looksLikeSnapshot(text: string): boolean {
  return /uid=\S+\s+\w+/.test(text);
}

/** All text carried by an MCP tool_response. Claude Code passes the MCP content ARRAY DIRECTLY
 * (`[{type:'text',text}]`), NOT wrapped in `{content:[…]}` — handle that (the real shape) plus a bare string
 * and the `{content:…}` shapes. Tolerant of unknown shapes (→ ''). */
export function rawResponseText(toolResponse: unknown): string {
  if (typeof toolResponse === 'string') return toolResponse;
  const content = (toolResponse as { content?: unknown })?.content;
  const arr = Array.isArray(toolResponse) ? toolResponse : Array.isArray(content) ? content : null;
  if (arr) {
    const parts: string[] = [];
    for (const item of arr) {
      const t = item as { text?: unknown };
      if (typeof t?.text === 'string') parts.push(t.text);
    }
    return parts.join('\n');
  }
  if (typeof content === 'string') return content;
  return '';
}

/** Pull the INLINE snapshot text out of an MCP tool_response, or undefined if it isn't a snapshot. (Large
 * snapshots are NOT inline — Claude Code offloads them to a file; see offloadedSnapshotPath.) */
export function extractSnapshotText(toolResponse: unknown): string | undefined {
  const text = rawResponseText(toolResponse);
  return looksLikeSnapshot(text) ? text : undefined;
}

// When a tool result exceeds Claude Code's inline token cap (real pages routinely do — a Wikipedia snapshot is
// ~900 lines), Claude Code SAVES it to a file and replaces tool_response with a pointer like:
//   "...Output has been saved to /home/.../.claude/projects/<p>/tool-results/mcp-chrome-devtools-take_snapshot-<n>.txt..."
// The snapshot text is then in that FILE, not inline. We follow the pointer (path-validated) to capture it.
// The path is emitted by Claude Code (trusted infra), points into its own tool-results dir, and we still
// content-guard with looksLikeSnapshot — so following it cannot be steered by the page to read a secret.
const OFFLOAD_POINTER_RE = /saved to\s+(\/\S+?\/tool-results\/\S+\.txt)\b/i;

/** If the tool_response is an "output saved to <file>" offload pointer for a chrome-devtools result, return
 * the validated absolute file path; else undefined. Pure (no fs) — the caller reads + content-guards it. */
export function offloadedSnapshotPath(toolResponse: unknown): string | undefined {
  const m = OFFLOAD_POINTER_RE.exec(rawResponseText(toolResponse));
  if (!m || !m[1]) return undefined;
  const path = m[1];
  // Defensive: must be an absolute path inside a Claude `tool-results/` dir, no traversal.
  if (!path.startsWith('/') || !path.includes('/tool-results/') || path.includes('/..')) return undefined;
  return path;
}

// ── Click-resolution DIAGNOSIS (2026-08-27) ────────────────────────────────────────────────────────────
// A click that does not resolve is always the same YELLOW. But the gate used to collapse EVERY cause into
// one reason string ("click target not resolved from a snapshot"), and the audit chain showed 6 of 17 real
// clicks landing there — with no way to tell a never-captured snapshot from a stale one without guessing.
// These two helpers exist purely so the reason string can name the cause. They authorize nothing.

/** The snapshot GENERATION a chrome-devtools uid belongs to. chrome-devtools mints uids as
 * `<generation>_<index>` and bumps the generation on each new snapshot, so a uid whose generation is absent
 * from the captured context means the agent is clicking against a tree the gate no longer holds (STALE) —
 * a materially different failure from an unknown uid WITHIN the current tree. Undefined if the uid does not
 * carry a generation prefix (a format change → no diagnosis, same fail-safe ask). */
export function uidGeneration(uid: string): string | undefined {
  const m = /^([^_]+)_/.exec(uid);
  return m?.[1];
}

/** The distinct snapshot generations present in a captured context (empty when there is no context). */
export function contextGenerations(ctx: BrowserContext | undefined): ReadonlySet<string> {
  const gens = new Set<string>();
  for (const uid of Object.keys(ctx?.nodes ?? {})) {
    const g = uidGeneration(uid);
    if (g !== undefined) gens.add(g);
  }
  return gens;
}

/** Resolve the element a click/interaction targets from its tool_input, using the session context. Returns
 * the node if the uid is known, else undefined (→ the caller fail-safes to ASK). */
export function resolveClickTarget(
  toolInput: Record<string, unknown>,
  ctx: BrowserContext | undefined,
): SnapshotNode | undefined {
  if (!ctx) return undefined;
  const uid = toolInput['uid'];
  if (typeof uid !== 'string') return undefined;
  // OWN-PROPERTY ONLY. `ctx.nodes` is a plain object (built here, or JSON.parsed in loadBrowserContext), so
  // a bare `ctx.nodes[uid]` also reaches Object.prototype: uid `__proto__` returned Object.prototype and
  // `constructor`/`toString`/`valueOf`/`hasOwnProperty` returned inherited functions. All are TRUTHY, so the
  // `if (!node)` fail-safe in the click inspector — whose whole job is "an unknown uid must ASK" — was
  // skipped, and the click was then judged against a "node" with no label and no url, i.e. maximally benign.
  // On an origin already in the allowance that graded GREEN. A magic string must never resolve to a page
  // element (found 2026-08-28).
  if (!Object.hasOwn(ctx.nodes, uid)) return undefined;
  const node = ctx.nodes[uid];
  // A JSON-parsed context can also carry a non-object value at an own key; only a real node shape resolves.
  return node !== null && typeof node === 'object' && typeof node.role === 'string' ? node : undefined;
}
