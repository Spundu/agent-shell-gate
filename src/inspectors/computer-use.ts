import { isSecretShaped } from '../shared/secret-shape.js';
import { typedCrownJewelUrl, typedLoginUrl } from './browser-args.js';
import { strongest, type InspectorResult } from './result.js';

// The argument inspector for the Computer Use MCP (the Browser Operator's universal fallback). A Computer
// Use call is a raw input event — mouse_move/click/type at a COORDINATE — which carries no origin, URL, or
// path the gate can reason about, so most calls are inspectable only as their catalog tier (every coordinate
// ACTION is YELLOW = ask).
//
// The ONE inspectable signal is a TYPED string: driving the address bar onto a payment/login origin via a
// `type`/`key` event. We escalate that to RED (best-effort) so the Computer Use channel has at least the
// same direct-crown-jewel-URL protection the chrome-devtools navigate inspector has. This is NOT airtight
// (coordinates can't be read), so — exactly as for chrome-devtools — the load-bearing money/login backstops
// are the layered controls, NOT this inspector: the SANDBOXED operator display (never the host desktop),
// attended yellow-ask on every action, the logged-out throwaway profile (no session to abuse), and the
// vault (the AI never touches a card). See design-notes/BROWSER-OPERATOR-THREAT-MODEL.md.
export function inspectComputerUse(toolInput: Record<string, unknown>): InspectorResult | null {
  let pendingLogin: InspectorResult | null = null;
  // SILENT SUBMIT: the whole reason `type` is GREEN is that typing a value does not SEND it — the submit
  // (a click, or Enter) is a separate YELLOW. A newline/carriage-return INSIDE the typed text presses Enter
  // as part of the same call, so it fills AND submits with no human in the loop. Verified GREEN 2026-08-23
  // (a `type` whose text ends in a newline). Pending, not early-returned, so a crown-jewel RED still wins.
  const typed = toolInput['text'];
  const pendingSubmit: InspectorResult | null =
    typeof typed === 'string' && /[\r\n]/.test(typed)
      ? { tier: 'yellow', reason: 'typed text contains Enter — types AND submits in one call (a commit — ask)' }
      : null;
  for (const value of Object.values(toolInput)) {
    if (typeof value !== 'string') continue;
    // A SECRET-SHAPED value typed into the page → RED, vault-only. This is the PARITY half of the check
    // chrome-devtools has had since 2026-08-23: a Luhn-valid PAN or an `sk-…` key typed through this
    // channel classified GREEN, so the same card that is vault-only via `fill` could be typed freely via
    // Computer Use. Exactly the fallback-channel gap the F1 finding was about, in the other direction
    // (there the DOM path was missed, here the coordinate path was) — found 2026-08-28.
    if (isSecretShaped(value)) {
      return { tier: 'red', reason: 'secret-shaped value typed into a page (card/token) — vault-only' };
    }
    if (typedCrownJewelUrl(value)) {
      return { tier: 'red', reason: 'typed text drives a payment/crown-jewel URL — hand off to the vault' };
    }
    if (typedLoginUrl(value)) {
      pendingLogin = { tier: 'yellow', reason: 'typed text drives a login/registration URL (ask once per session)' };
    }
  }
  return strongest(pendingSubmit, pendingLogin); // crown-jewel/secret REDs return above
}
