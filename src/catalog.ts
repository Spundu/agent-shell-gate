import type { Tier, ToolKind } from './contracts/index.js';
import { fileWriteArg } from './inspectors/browser-args.js';

// The tool catalog: EXACT tool names → classification. Default-deny — anything not listed (and
// not a recognized mcp__ class) is unknown → RED. No permissive regex on built-in tools.
//
// IMMUTABILITY: the catalog Map + the classification Sets below are typed `ReadonlyMap`/`ReadonlySet` — the
// TYPE is the integrity guard (source code cannot `.set()`/`.add()`/`.delete()` them; TS errors). They are
// deliberately NOT `Object.freeze`'d (unlike the frozen ARRAY constants in policy.ts): `Object.freeze` on a
// Map/Set is INEFFECTIVE — it locks object properties, not the internal entries, so `.set()`/`.add()` still
// mutate a frozen Map/Set. Do not "fix" this with Object.freeze (false security). Runtime in-process mutation
// would require arbitrary code execution inside the hook process — at which point the gate is already wholly
// compromised regardless (out of threat model). Verified by red-team (2026-06-14, 6 candidates → 0 real).

export type InspectorName =
  | 'none' | 'bash' | 'file' | 'fetch' | 'read' | 'chrome-devtools' | 'computer-use' | 'claude-in-chrome';

/** How a tool is gated, independent of its tier (P0-3 two-class model). */
export type GatingClass =
  | 'none' // tier alone decides (green→allow, yellow→ask, red→deny)
  | 'vault-request' // powerless request to the vault — allowed through; the vault gates internally
  | 'local-approval'; // locally-executed world-changing tool — denied unless a vault approval covers it

export interface ToolClass {
  kind: ToolKind;
  baseTier: Tier;
  inspector: InspectorName;
  gating: GatingClass;
}

const C = (kind: ToolKind, baseTier: Tier, inspector: InspectorName = 'none', gating: GatingClass = 'none'): ToolClass => ({
  kind,
  baseTier,
  inspector,
  gating,
});

export const CATALOG: ReadonlyMap<string, ToolClass> = new Map<string, ToolClass>([
  // read-only / meta — GREEN, but the read inspector escalates a crown-jewel/secret target to RED (F3)
  ['Read', C('read', 'green', 'read')],
  ['Glob', C('read', 'green', 'read')],
  ['Grep', C('read', 'green', 'read')],
  ['LS', C('read', 'green', 'read')],
  ['NotebookRead', C('read', 'green', 'read')],
  ['TodoRead', C('read', 'green')],
  ['TodoWrite', C('meta', 'green')],
  ['ExitPlanMode', C('meta', 'green')],
  // Loads DEFERRED tool schemas into context (Claude Code defers the many MCP tools — chrome-devtools/
  // operator-gui — behind it). Read-only + powerless: it only reveals tool DEFINITIONS; every tool it makes
  // callable is still classified + gated WHEN CALLED, so it can't be a bypass (loading evaluate_script's
  // schema doesn't make calling it any less RED). Meta/GREEN. Without this the operator can't reach its
  // browser tools at all (default-deny was blocking the loader itself).
  ['ToolSearch', C('meta', 'green')],
  ['Task', C('meta', 'green')], // spawns a subagent; the subagent's own tool calls hit this same gate

  // --- 2026-08-23 CATALOG RECONCILIATION. These are ordinary Claude Code built-ins that were absent, so
  // default-deny made every one of them RED. Default-deny fails SAFE, which is why this was never a security
  // hole — but an omission is not free: it silently removes a capability, and two of the omissions removed
  // the agent's ability to TALK TO THE HUMAN and to PLAN, which is exactly backwards as autonomy increases.
  // Only tools whose semantics are clear are listed; anything still unlisted stays RED on purpose, because a
  // guessed tier fails OPEN whereas an omission fails CLOSED.

  // THE ASK CHANNEL. Verified denied twice in the real audit chain ("unknown tool 'AskUserQuestion'").
  // It renders a structured question to the human and returns their choice — it cannot touch the world, and
  // it is the ONLY structured way the Brain can consult the human. Denying it while the doctrine tells the Brain
  // "asks are normal — tell the human when you are blocked" is a direct contradiction, and under autonomous
  // operation it is the channel that substitutes for a human watching the tmux pane. meta/GREEN.
  ['AskUserQuestion', C('meta', 'green')],
  // Plan mode RESTRICTS the agent. ExitPlanMode was already GREEN while its counterpart was RED, so the
  // Brain could leave plan mode but never enter it — the safety-increasing half was the blocked one.
  ['EnterPlanMode', C('meta', 'green')],
  // Loads a packaged set of instructions into the turn. Powerless by the same argument as ToolSearch: it
  // supplies TEXT, and every tool the skill goes on to call is classified and gated when called. Skills live
  // under `.claude/`, which is gate-PROTECTED for writes, so the Brain cannot author its own. meta/GREEN.
  ['Skill', C('meta', 'green')],
  // Reads the accumulated output of a background shell / task the Brain already started — and whose STARTING
  // command was itself gated. Pulling that output into context is a read, so: read/GREEN, isRead like Read.
  ['BashOutput', C('read', 'green')],
  ['TaskOutput', C('read', 'green')],
  // STOPPING something is the safe direction, and both only reach work this same agent started. meta/GREEN.
  ['KillShell', C('meta', 'green')],
  ['TaskStop', C('meta', 'green')],
  // Runs a NAMED slash command — far more open-ended than Skill (it can invoke any project-defined command),
  // so it gets the ask rather than the auto-allow. Its own tool calls are still gated; this is defence in
  // depth, and slash commands are rare enough on the Brain's hot path that one prompt costs nothing.
  ['SlashCommand', C('meta', 'yellow')],
  // Waits on a condition over background output. The semantics are a WAIT, not an action — but it is the one
  // entry here I cannot fully justify from first principles, so it takes the conservative tier rather than a
  // guessed GREEN. Revisit with evidence from the live tool list.
  ['Monitor', C('meta', 'yellow')],
  // MCP RESOURCES. Listing resource NAMES is metadata → meta/GREEN. Reading resource CONTENT pulls external,
  // untrusted data into context — precisely the `connector-read` case established for Gmail/Drive/Supabase:
  // GREEN while the gate is active, but deliberately NOT kill-switch/depth-exempt, so the panic button and
  // the runaway-depth guard both STOP it (that exemption was a red-team P2 on the connectors).
  ['ListMcpResourcesTool', C('meta', 'green')],
  ['ReadMcpResourceTool', C('connector-read', 'green')],
  ['ReadMcpResourceDirTool', C('connector-read', 'green')],
  // writes — YELLOW, escalated by the file inspector (protected paths → RED)
  ['Write', C('write', 'yellow', 'file')],
  ['Edit', C('write', 'yellow', 'file')],
  ['MultiEdit', C('write', 'yellow', 'file')],
  ['NotebookEdit', C('write', 'yellow', 'file')],
  // exec — base GREEN is the floor; the bash inspector escalates (read-only stays GREEN,
  // unknown → YELLOW, dangerous/egress → RED). Inspectors only escalate, never de-escalate.
  ['Bash', C('exec', 'green', 'bash')],
  // network — RED until a MAIN-side egress allowlist exists
  ['WebFetch', C('network', 'red', 'fetch')],
  ['WebSearch', C('network', 'red', 'fetch')],
]);

// Browser Operator — chrome-devtools MCP (`mcp__chrome-devtools__<op>`). POSTURE (the human's call, 2026-06-14, after a
// red-team proved "everything GREEN" auto-executes money/login/upload with no approval): AUTO-ALLOW anything
// that CANNOT itself commit the world, ASK at the moment of commit. THE LAW: money / account-create /
// irreversible / crown-jewel-login ALWAYS require explicit human approval.
//   • READ ops → GREEN + isRead (kill-switch/depth-exempt). A capture op with a `filePath` is a DISK WRITE →
//     YELLOW (RED on a protected path), via the arg-aware branch.
//   • GREEN ops (non-read, auto-allow): observe / navigate / position / TYPE-into-a-field — none COMMIT by
//     themselves. The inspector still escalates a crown-jewel/login navigation, a script/header arg, a
//     network-dump-to-file, or a typed crown-jewel URL to RED.
//   • `click` is GREEN **base** (the SMART-CLICK RESOLVER, 2026-06-14): a click's `uid` is opaque, so the
//     chrome-devtools inspector resolves it against the per-session snapshot context (browser-context.ts) and
//     ESCALATES — a pay/order-commit control or a crown-jewel-origin/landing → RED, a login/commit/money-page
//     context → YELLOW, an UNRESOLVED uid (no/stale snapshot) → YELLOW (fail-safe ask). A benign control on a
//     normal origin stays GREEN (the whole point — frictionless clicking). The escalate-only model means a
//     resolution miss can only ADD a prompt, never open a hole.
//   • ASK ops (YELLOW base): the still-un-resolvable COMMIT/EGRESS surface — key-press (Enter/Space activate),
//     dialog-accept, drag, file-upload. These carry no element label to resolve, so they stay the human
//     checkpoint THE LAW requires (login submit, confirm dialog, file egress).
//   • `evaluate_script` → RED. Unknown op → default-deny RED.
const CDT_READ_OPS: ReadonlySet<string> = new Set([
  'take_snapshot', 'take_screenshot', 'list_pages', 'list_console_messages', 'get_console_message',
  'lighthouse_audit', 'performance_analyze_insight', 'wait_for', 'select_page', 'resize_page',
]);
const CDT_GREEN_OPS: ReadonlySet<string> = new Set([
  'navigate_page', 'new_page', 'hover', 'close_page', 'fill', 'fill_form', 'type_text', 'click',
  'emulate', 'get_network_request', 'list_network_requests',
  'performance_start_trace', 'performance_stop_trace', 'take_heapsnapshot',
]);
const CDT_ASK_OPS: ReadonlySet<string> = new Set([
  'press_key', 'drag', 'upload_file', 'handle_dialog',
]);

// Computer Use — the fallback, exposed as the MCP server `operator-gui` (NOT `computer-use`: claude silently
// drops a custom server colliding with its built-in `computer-use`; verified live). Same posture as
// chrome-devtools, but the coordinate channel is WHOLLY un-inspectable (a click(x,y) carries no label/origin)
// — so its COMMIT ops MUST ask. READ (screenshot/cursor) GREEN+isRead; position/type GREEN (non-read); every
// CLICK + key-press YELLOW (the only human checkpoint for this channel). Typed crown-jewel URL → RED.
// Claude in Chrome (`mcp__claude-in-chrome__<op>`) — a SECOND browser channel, added 2026-09-05 because
// chrome-devtools struggles on some real pages and this one reads them far better. It drives the SAME
// sandboxed Chrome (the extension is installed in the operator profile), so chrome-devtools can
// independently verify what it did — that cross-check is the point of having both.
//
// THE ONE STRUCTURAL DIFFERENCE, and it decides every tier below. chrome-devtools addresses elements by a
// snapshot `uid`, which encodes WHICH snapshot it came from — so the gate resolves the element's label and
// page origin, and a STALE uid is detectable and fails safe to ASK. Claude-in-Chrome addresses everything by
// a bare integer `tabId`, which is stable across navigation and recycled across restarts. There is no
// generation to check, so a remembered tabId->origin map is stale-by-construction and fails OPEN: it would
// confidently name a benign origin for a tab that has since navigated to a bank. Hence NO auto-allowed
// commit on this channel — exactly the posture operator-gui already has for the same reason (a click(x,y)
// carries no label or origin either), and for the same reason it is ASK rather than BLOCK: attended
// operation with the screen visible is a better check than any recap.
//
//   • Reads → YELLOW (`connector-read`). They pull page content from a tab the gate cannot name. Unlike a
//     chrome-devtools read there is no origin in the args to escalate on, so GREEN would be an
//     unconditional GREEN over whatever the profile is logged into.
//   • navigate → GREEN base: the `url` IS an argument, so the inspector can carry the strictness
//     (crown-jewel/dangerous-scheme escalation, exactly as for navigate_page).
//   • COMMITS (click/type/key/form_input/uploads) → YELLOW. The human checkpoint THE LAW requires.
//   • RED outright: `javascript_tool` (arbitrary in-page JS — `evaluate_script` is RED, same capability),
//     `browser_batch` (it BUNDLES other calls, so name-keyed classification stops working — you could post
//     javascript_tool inside it), `shortcuts_execute` (an opaque stored workflow: no inspectable payload),
//     and `select_browser`/`switch_browser` (they can move the agent OFF the sandboxed browser onto
//     the human's real one — Fork B, which was rejected 2026-08-28).
//   • is_read is FALSE for every op here. `isRead` is the kill-switch/depth EXEMPTION, and that belongs to
//     a channel whose logged-out profile invariant is PROVEN at launch (guard-operator-profile.py). Reads
//     here are `connector-read`: GREEN-active elsewhere, but never exempt.
const CIC_GREEN_OPS: ReadonlySet<string> = new Set([
  'navigate', 'tabs_create_mcp', 'tabs_close_mcp', 'resize_window',
]);
const CIC_READ_ASK_OPS: ReadonlySet<string> = new Set([
  'read_page', 'get_page_text', 'find', 'read_console_messages', 'read_network_requests',
  'tabs_context_mcp', 'list_connected_browsers', 'shortcuts_list',
]);
const CIC_COMMIT_ASK_OPS: ReadonlySet<string> = new Set([
  'form_input', 'file_upload', 'upload_image', 'gif_creator',
]);
const CIC_RED_OPS: ReadonlySet<string> = new Set([
  'javascript_tool', 'browser_batch', 'shortcuts_execute', 'select_browser', 'switch_browser',
]);
// `computer` multiplexes many verbs behind ONE tool name via `action`, so it is ARG-DISPATCHED — a
// name-keyed entry would give screenshot and left_click the same tier, which is itself the hole.
const CIC_COMPUTER_GREEN: ReadonlySet<string> = new Set(['hover', 'scroll', 'scroll_to', 'wait', 'mouse_move']);
const CIC_COMPUTER_ASK: ReadonlySet<string> = new Set([
  'screenshot', 'zoom', 'type', 'key', 'left_click', 'right_click', 'middle_click',
  'double_click', 'triple_click', 'left_click_drag', 'drag',
]);

const CU_READ_OPS: ReadonlySet<string> = new Set(['screenshot', 'cursor_position']);
const CU_GREEN_OPS: ReadonlySet<string> = new Set(['mouse_move', 'scroll', 'wait', 'type']);
const CU_ASK_OPS: ReadonlySet<string> = new Set([
  'left_click', 'left_click_drag', 'right_click', 'middle_click', 'double_click', 'triple_click',
  'key', 'hold_key',
]);

// Google Workspace connectors (`mcp__claude_ai_<Service>__<op>`) — Phase 4, READ-ONLY-FIRST. Anthropic's
// managed Gmail / Calendar / Drive connectors. READS (search/list/get/read) auto-allow GREEN; MUTATIONS that
// stay WITHIN the user's own account and are reversible (create a draft/label/file/event) are YELLOW (ask);
// account-LINKING (the OAuth `authenticate` handshake) is YELLOW. Any op NOT listed — notably anything
// OUTWARD or DESTRUCTIVE (send mail, delete/trash, share / permission-change, empty trash), NONE of which
// exist in the first-party connectors today — is unknown → default-deny RED, so a future surface change
// fails CLOSED. Op names verified against Anthropic's connector docs + the claude-code issue tracker
// (2026-06-13); the **Calendar** op names are the connector's LIKELY set (not verbatim-confirmed) — a wrong
// guess still fails safe (a dead read entry is harmless; the real name is RED until added). Confirm the live
// set with `/mcp` after the connectors are authenticated, then reconcile these sets.
const CONNECTOR_AUTH: ReadonlySet<string> = new Set(['authenticate', 'complete_authentication']);
const GMAIL_READ: ReadonlySet<string> = new Set([
  'search_threads', 'get_thread', 'list_labels', 'list_drafts',
]);
const GMAIL_MUTATE: ReadonlySet<string> = new Set([
  'create_draft', 'label_thread', 'unlabel_thread', 'label_message', 'create_label',
]);
const GCAL_READ: ReadonlySet<string> = new Set([
  'list_calendars', 'list_events', 'get_event', 'find_free_time', // LIKELY names — verify with /mcp
]);
const GCAL_MUTATE: ReadonlySet<string> = new Set([
  'create_event', 'update_event', // delete_event deliberately OMITTED → default-deny RED (destructive/outward)
]);
const GDRIVE_READ: ReadonlySet<string> = new Set([
  'search_files', 'list_recent_files', 'get_file_metadata', 'get_file_permissions',
  'read_file_content', 'download_file_content',
]);
const GDRIVE_MUTATE: ReadonlySet<string> = new Set([
  'create_file', // the only first-party write; no move/rename/trash/delete/share exists → those stay RED
]);

// Supabase connector (`mcp__supabase__<op>`) — a READ-ONLY DB/project connector for the Brain (the
// `@supabase/mcp-server-supabase` server, deployed with `--read-only --project-ref=<pinned>`). Posture:
//   • STRUCTURED reads (list_tables, get_logs, search_docs, …) auto-allow as `connector-read` (GREEN-active,
//     but pause/depth STILL stop them — DB rows pull sensitive user content into context).
//   • `execute_sql` (ARBITRARY SQL) → YELLOW (ask), NOT auto-allow. The SQL string is never inspected, and
//     the server's `--read-only` is a read-only ROLE (SECURITY-DEFINER-bypassable), NOT a read-only
//     transaction — so even "read-only" SQL can reach a privileged definer write. THE LAW: approve the
//     un-inspected unknown. (Server-side defense-in-depth — a dedicated read-only role w/ EXECUTE revoked on
//     writing definer functions, or a read replica — is a follow-up for the human, out of the gate's control.)
//   • EVERYTHING ELSE is default-deny RED — no mutate set, so every write op (apply_migration,
//     deploy_edge_function, create/pause/restore_project, branch ops, …) is RED even though `--read-only`
//     already excludes them (defense in depth: the gate denies a write op even if the server were mis-deployed).
// Op names are the server's LIKELY set; a wrong/extra name just fails safe (a dead read entry is harmless; an
// unlisted real name is RED until added). Reconcile with `/mcp` once the connector is live.
const SUPABASE_READ: ReadonlySet<string> = new Set([
  'list_tables', 'list_extensions', 'list_migrations',
  'list_edge_functions', 'get_edge_function', 'get_logs', 'get_advisors',
  'get_project', 'get_project_url', 'get_anon_key', 'list_projects',
  'generate_typescript_types', 'search_docs',
]);
const SUPABASE_MUTATE: ReadonlySet<string> = new Set<string>(); // read-only connector — every write op stays RED

/** Classify a Google-connector op: READS GREEN, within-account reversible MUTATIONS + the OAuth handshake
 * YELLOW (ask), and anything else (outward / destructive / unknown) → null → default-deny RED. Inspector is
 * 'none': the tier + the human's YELLOW approval + default-deny are the closure, and connector-returned data
 * (email/file/event content) is never an input to classification — only the op NAME is.
 *
 * Reads are kind 'connector-read' (NOT 'read'): GREEN auto-allow under normal attended operation, but —
 * unlike a cheap, inspector-backstopped local `Read` — a connector read pulls sensitive personal content
 * (mail/file/event bodies) into context, so it is deliberately NOT kill-switch/depth EXEMPT. When the
 * operator hits PAUSE, or a runaway subagent nests past the depth cap, connector reads are DENIED. This
 * mirrors the catalog's treatment of the chrome-devtools network tools (content-into-context = non-read). */
function classifyConnector(op: string, read: ReadonlySet<string>, mutate: ReadonlySet<string>): ToolClass | null {
  if (read.has(op)) return C('connector-read', 'green'); // auto-allow when active; pause/depth still STOP it
  if (CONNECTOR_AUTH.has(op) || mutate.has(op)) return C('write', 'yellow'); // account-link / within-account change
  return null; // OUTWARD / DESTRUCTIVE / unknown → default-deny RED (fails closed on a surface change)
}

/** Classify the mcp__ tool families (P0-3). `toolInput` is consulted only where a tool's CLASS depends on
 * its args (a chrome-devtools "read" op that carries a save-to-file arg is actually a write). Returns null
 * for unknown mcp tools (→ default-deny). */
export function classifyMcp(toolName: string, toolInput?: Record<string, unknown>): ToolClass | null {
  if (toolName === 'mcp__vault__request') return C('vault', 'yellow', 'none', 'vault-request');
  if (toolName.startsWith('mcp__local__')) return C('irreversible', 'red', 'none', 'local-approval');
  if (toolName.startsWith('mcp__chrome-devtools__')) {
    const op = toolName.slice('mcp__chrome-devtools__'.length);
    if (CDT_READ_OPS.has(op)) {
      // A capture/observe op that SAVES TO A FILE (filePath / outputDirPath / *FilePath) is not a free
      // read — it writes the world (on the BRAIN's filesystem, where the MCP runs). Classify it as a write
      // (YELLOW + not isRead) so it asks AND respects the kill-switch + depth guards; the inspector then
      // REDs a crown-jewel/protected target (raw or cwd-resolved).
      if (toolInput && fileWriteArg(toolInput)) return C('write', 'yellow', 'chrome-devtools');
      return C('read', 'green', 'chrome-devtools');
    }
    if (op === 'evaluate_script') return C('exec', 'red', 'chrome-devtools'); // arbitrary in-page JS
    // COMMIT/ACTIVATE/EGRESS → YELLOW (the human checkpoint THE LAW requires; the stateless gate can't see a
    // click's target/landed-origin, so it must ask at the commit).
    if (CDT_ASK_OPS.has(op)) return C('write', 'yellow', 'chrome-devtools');
    // observe / navigate / position / type-into-field / CLICK → GREEN base (non-read; the inspector still
    // REDs a crown-jewel navigation, script/header arg, network-dump-to-file, or typed crown-jewel URL — and
    // for `click`, resolves the uid against the snapshot context to escalate a money/login/unresolved click).
    if (CDT_GREEN_OPS.has(op)) return C('write', 'green', 'chrome-devtools');
    return null; // unknown DOM op → default-deny
  }
  if (toolName.startsWith('mcp__operator-gui__')) {
    // The Computer-Use fallback server (named `operator-gui` to dodge claude's built-in `computer-use`).
    const op = toolName.slice('mcp__operator-gui__'.length);
    if (CU_READ_OPS.has(op)) return C('read', 'green', 'computer-use');
    // The coordinate channel is un-inspectable, so COMMIT ops (clicks, key-presses) MUST ask — the only
    // human checkpoint for a buy/login/confirm via x,y.
    if (CU_ASK_OPS.has(op)) return C('write', 'yellow', 'computer-use');
    // position / type → GREEN (non-read); the inspector still REDs a typed crown-jewel URL.
    if (CU_GREEN_OPS.has(op)) return C('write', 'green', 'computer-use');
    return null; // unknown coordinate op → default-deny
  }
  if (toolName.startsWith('mcp__claude-in-chrome__')) {
    const op = toolName.slice('mcp__claude-in-chrome__'.length);
    // RED FIRST, before any permissive lookup, so a name can never fall through into a green set.
    if (CIC_RED_OPS.has(op)) return C('exec', 'red', 'claude-in-chrome');
    if (op === 'computer') {
      // The verb is an ARGUMENT. A missing / non-string / unlisted action is default-deny, not a guess.
      const action = (toolInput ?? {})['action'];
      if (typeof action !== 'string') return C('write', 'red', 'claude-in-chrome');
      if (CIC_COMPUTER_GREEN.has(action)) return C('write', 'green', 'claude-in-chrome');
      if (CIC_COMPUTER_ASK.has(action)) return C('write', 'yellow', 'claude-in-chrome');
      return C('write', 'red', 'claude-in-chrome');
    }
    // Reads pull page content from a tab the gate cannot name → ask, and never kill-switch/depth exempt.
    if (CIC_READ_ASK_OPS.has(op)) return C('connector-read', 'yellow', 'claude-in-chrome');
    if (CIC_COMMIT_ASK_OPS.has(op)) return C('write', 'yellow', 'claude-in-chrome');
    if (CIC_GREEN_OPS.has(op)) return C('write', 'green', 'claude-in-chrome');
    return null; // unknown op → default-deny
  }
  // Google Workspace connectors (Phase 4, read-only-first): reads GREEN, within-account mutations + OAuth
  // YELLOW, outward/destructive/unknown → default-deny RED.
  if (toolName.startsWith('mcp__claude_ai_Gmail__'))
    return classifyConnector(toolName.slice('mcp__claude_ai_Gmail__'.length), GMAIL_READ, GMAIL_MUTATE);
  if (toolName.startsWith('mcp__claude_ai_Google_Calendar__'))
    return classifyConnector(toolName.slice('mcp__claude_ai_Google_Calendar__'.length), GCAL_READ, GCAL_MUTATE);
  if (toolName.startsWith('mcp__claude_ai_Google_Drive__'))
    return classifyConnector(toolName.slice('mcp__claude_ai_Google_Drive__'.length), GDRIVE_READ, GDRIVE_MUTATE);
  // Supabase READ-ONLY connector: structured reads → connector-read GREEN (pause/depth still stop them);
  // execute_sql (arbitrary SQL) → YELLOW (human checkpoint — uninspected, --read-only is a bypassable role);
  // every other op (writes/project-mgmt/branching) → default-deny RED.
  if (toolName.startsWith('mcp__supabase__')) {
    const op = toolName.slice('mcp__supabase__'.length);
    if (op === 'execute_sql') return C('write', 'yellow');
    return classifyConnector(op, SUPABASE_READ, SUPABASE_MUTATE);
  }
  return null;
}
