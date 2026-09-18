import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { canonicalize } from './audit/index.js';
import type { HookInput } from './types.js';

// The host-owned approved-action manifest (vault-pushed). A local world-changing tool (mcp__local__*)
// is allowed ONLY if the manifest holds an 'approved' entry whose action_hash matches
// JCS(tool_input \ {approval_id}) and whose approval_id matches the powerless handle the model
// supplied. Phase 2: the manifest is empty/absent → every local tool is denied 'gated:no-approval'.
// Fail-closed on any read/parse error. The nonce is NEVER here — it's injected host-side at execute.

interface ManifestEntry {
  approval_id: string;
  action_hash: string;
  state: string;
}

/** A parsed manifest element is untrusted `unknown`: JSON.parse can yield an array holding null, numbers,
 * strings or bare objects. A non-object element can never be an approval AND reading `.state` off `null`
 * THROWS — which, on the gate's decision path (hook.ts calls manifestApproves with no try/catch), is a
 * fail-open crash. Narrow to a well-formed entry first; anything else simply does not match (fail-closed). */
function isManifestEntry(e: unknown): e is ManifestEntry {
  return (
    typeof e === 'object' &&
    e !== null &&
    typeof (e as ManifestEntry).approval_id === 'string' &&
    typeof (e as ManifestEntry).action_hash === 'string' &&
    typeof (e as ManifestEntry).state === 'string'
  );
}

/** sha256(JCS(tool_input with the powerless approval_id handle removed)). */
export function actionHash(toolInput: Record<string, unknown>): string {
  const { approval_id: _handle, ...rest } = toolInput;
  return createHash('sha256').update(canonicalize(rest), 'utf8').digest('hex');
}

export function manifestApproves(input: HookInput, manifestPath: string | undefined): boolean {
  if (!manifestPath || !existsSync(manifestPath)) return false;
  const toolInput = input.tool_input ?? {};
  const approvalId = toolInput['approval_id'];
  if (typeof approvalId !== 'string') return false;

  let entries: unknown[];
  try {
    const parsed: unknown = JSON.parse(readFileSync(manifestPath, 'utf8'));
    if (!Array.isArray(parsed)) return false;
    entries = parsed;
  } catch {
    return false; // fail-closed
  }

  const hash = actionHash(toolInput);
  // A malformed element (null / number / string / {}) is skipped, never dereferenced — so it can neither
  // throw out of the gate nor forge an approval. A well-formed sibling still stands on its own merits.
  return entries.some(
    (e) => isManifestEntry(e) && e.state === 'approved' && e.approval_id === approvalId && e.action_hash === hash,
  );
}
