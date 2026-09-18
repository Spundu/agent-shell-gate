import { isSecretShaped } from '../shared/secret-shape.js';
import { PROTECTED_PATH_PATTERNS } from '../policy.js';
import { resolveToolPath } from './path.js';
import type { InspectorResult } from './result.js';

// Write/Edit are YELLOW (ask) by default. They escalate to RED (deny) when EITHER:
//  - the content being written is itself secret-shaped (F8) — the Brain must never persist a secret
//    to disk; secrets live in the vault; OR
//  - the target path resolves into a protected location (the spine, the audit log, the vault
//    material, CLAUDE.md, .claude/**). Paths are resolved to absolute FIRST (F9) so a relative or
//    `..`-laden path cannot slip past the protected-prefix match; both the raw and resolved forms
//    are checked so a previously-caught absolute path is never lost.

function pickString(toolInput: Record<string, unknown>, keys: readonly string[]): string | undefined {
  for (const key of keys) {
    const value = toolInput[key];
    if (typeof value === 'string') return value;
  }
  return undefined;
}

/** Collect every string the tool would write (Write.content, Edit.new_string, NotebookEdit.new_source,
 * MultiEdit.edits[]). */
function writtenContent(toolInput: Record<string, unknown>): string[] {
  const out: string[] = [];
  for (const key of ['content', 'new_string', 'new_str', 'new_source']) {
    const value = toolInput[key];
    if (typeof value === 'string') out.push(value);
  }
  const edits = toolInput['edits'];
  if (Array.isArray(edits)) {
    for (const edit of edits) {
      if (edit && typeof edit === 'object') {
        const ns = (edit as Record<string, unknown>)['new_string'];
        if (typeof ns === 'string') out.push(ns);
      }
    }
  }
  return out;
}

export function inspectFile(toolInput: Record<string, unknown>, cwd?: string): InspectorResult {
  if (writtenContent(toolInput).some(isSecretShaped)) {
    return { tier: 'red', reason: 'refusing to write secret-shaped content to disk (vault-only)' };
  }

  const path = pickString(toolInput, ['file_path', 'path', 'notebook_path']) ?? '';
  const probes = [path, resolveToolPath(path, cwd)];
  if (probes.some((p) => PROTECTED_PATH_PATTERNS.some((re) => re.test(p)))) {
    return { tier: 'red', reason: 'write to a protected path (spine/audit/vault/config)' };
  }
  return { tier: 'yellow', reason: 'file write' };
}
