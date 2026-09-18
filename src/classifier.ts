import { maxTier, type Tier, type ToolKind } from './contracts/index.js';
import { CATALOG, classifyMcp, type GatingClass } from './catalog.js';
import type { BrowserSession } from './browser-context.js';
import { runInspector } from './inspectors/index.js';
import { MAX_SUBAGENT_DEPTH } from './policy.js';
import type { HookInput } from './types.js';

const CHROME_DEVTOOLS_PREFIX = 'mcp__chrome-devtools__';

/** The chrome-devtools mcp op name (e.g. 'click'), or undefined for any other tool. Lets the inspector
 * resolve a click's opaque uid against the snapshot context (the smart-click resolver). */
function chromeDevtoolsOp(toolName: string): string | undefined {
  return toolName.startsWith(CHROME_DEVTOOLS_PREFIX) ? toolName.slice(CHROME_DEVTOOLS_PREFIX.length) : undefined;
}

// THE full classifier (Phase 2). Looks the EXACT tool name up in the catalog (default-deny on
// unknown), runs the relevant argument inspector (escalate-only via maxTier), and records the
// gating class (P0-3). The hook turns this Classification into a decision (see hook.ts/decide).

export interface Classification {
  tier: Tier;
  kind: ToolKind;
  isRead: boolean;
  gating: GatingClass;
  reason: string;
}

export function classify(input: HookInput, session?: BrowserSession): Classification {
  const cls = CATALOG.get(input.tool_name) ?? classifyMcp(input.tool_name, input.tool_input ?? undefined);
  if (!cls) {
    return {
      tier: 'red',
      kind: 'meta',
      isRead: false,
      gating: 'none',
      reason: `unknown tool '${input.tool_name}' (default-deny)`,
    };
  }

  const op = chromeDevtoolsOp(input.tool_name);
  const browser = {
    ...(op !== undefined ? { op } : {}),
    ...(session?.ctx !== undefined ? { ctx: session.ctx } : {}),
    ...(session?.allowedOrigins !== undefined ? { allowedOrigins: session.allowedOrigins } : {}),
  };
  const inspection = runInspector(cls.inspector, input.tool_input ?? {}, input.cwd, browser);
  let tier = cls.baseTier;
  let reason = `${cls.kind} tool`;
  if (inspection) {
    tier = maxTier(cls.baseTier, inspection.tier);
    reason = inspection.reason;
  }

  const isRead = cls.kind === 'read';
  // F14 runaway guard: a (self-declared) subagent nesting depth at/above the cap is denied for any
  // world-changing call. Self-declared ⇒ a guard against honest runaway fan-out, not a boundary.
  const depth = input.agent?.depth;
  if (typeof depth === 'number' && depth >= MAX_SUBAGENT_DEPTH && !isRead) {
    tier = maxTier(tier, 'red');
    reason = `subagent depth ${depth} ≥ cap ${MAX_SUBAGENT_DEPTH} (runaway guard)`;
  }

  return { tier, kind: cls.kind, isRead, gating: cls.gating, reason };
}
