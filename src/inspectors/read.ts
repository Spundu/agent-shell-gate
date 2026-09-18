import { CROWN_JEWEL_READ_PATTERNS } from '../policy.js';
import { resolveToolPath } from './path.js';
import type { InspectorResult } from './result.js';

// The native read primitives (Read/Grep/Glob/LS/NotebookRead) execute outside the Bash inspector,
// so the SAME crown-jewel read protection (F3) must guard them — otherwise the Brain could `Read`
// the seal key / ssh keys / .env / browser credential DBs at GREEN, exactly the F2/F3 exfil threat.
// Escalate-only: a non-secret read stays GREEN; a crown-jewel/secret target → RED. Paths are
// resolved to absolute first (F9) so a relative/`..` path cannot dodge the prefix match.

const PATH_KEYS = ['file_path', 'path', 'notebook_path', 'pattern', 'glob'] as const;

// Grep/Glob recurse by default, so a search ROOT at or above the user's home — or the ~/.config
// parent of many secret stores, or a filesystem root — would descend INTO crown-jewel dotfiles and
// exfiltrate their contents at GREEN even though the root path itself matches no secret pattern (RT
// round-3). Such a broad recursive read is escalated to YELLOW (review). Narrow project-dir searches
// (e.g. /home/u/code) are unaffected.
function isBroadReadRoot(p: string): boolean {
  if (/^(?:[A-Za-z]:)?[\\/]?$/.test(p)) return true; // filesystem root: /, \, C:\, C:
  if (/[\\/]\.config(?:[\\/][^\\/]+)?[\\/]?$/i.test(p)) return true; // ~/.config or a direct child app-config dir
  // A read root at/under the JARVIS_HOME tree recurses INTO brain-state/secrets/ (the connector token) — ask,
  // mirroring the Bash `grep -r` posture. (The leaf token + the secrets/ dir stay RED via crown-jewel patterns.)
  if (/[\\/](?:jarvis-home|brain-state)(?:[\\/]|$)/i.test(p)) return true;
  // THE WSL FORM. The Brain runs inside WSL, where the human's ENTIRE Windows profile is mounted at
  // /mnt/c/Users/user — browser credential stores, .ssh, .aws, everything. The alternation below covered
  // the POSIX (/home/user) and native-Windows (C:/Users/<user>) spellings but not the one the Brain actually
  // uses, so `Grep {pattern:'password', path:'/mnt/c/Users/user'}` classified GREEN and recursively read the
  // whole profile while the other two spellings asked. Verified 2026-08-28. Also covers the drive root
  // (/mnt/c) and the bare /mnt.
  if (/^[\\/]mnt(?:[\\/][A-Za-z](?:[\\/]Users(?:[\\/][^\\/]+)?)?)?[\\/]?$/i.test(p)) return true;
  return /^(?:[A-Za-z]:[\\/]Users(?:[\\/][^\\/]+)?|[\\/](?:home|Users)(?:[\\/][^\\/]+)?|[\\/]root)[\\/]?$/i.test(p);
}

// Claude Code offloads a too-large tool RESULT to a file under .claude/<project>/<session>/tool-results/.
// Those are the agent's OWN tool outputs (page snapshots, command output) — NOT secrets — and the Brain
// CANNOT write there (.claude is write-protected, so it can only read what Claude Code itself wrote). Reading
// them is therefore safe even though the path sits under .claude, and the operator NEEDS it: otherwise it
// saves its own snapshot copy via a `filePath` arg, which is a (gated) disk WRITE — needless friction + a
// page-content-to-file vector. Traversal-guarded: a path containing `..` is NEVER exempt (its resolved form
// is checked separately and will hit the crown-jewel RED if it escapes the tool-results dir).
function isClaudeToolResult(p: string): boolean {
  return /[\\/]\.claude[\\/]/i.test(p) && /[\\/]tool-results(?:[\\/]|$)/i.test(p) && !p.includes('..');
}

export function inspectRead(toolInput: Record<string, unknown>, cwd?: string): InspectorResult | null {
  const probes: string[] = [];
  for (const key of PATH_KEYS) {
    const value = toolInput[key];
    if (typeof value === 'string' && value.length > 0) probes.push(value, resolveToolPath(value, cwd));
  }
  if (probes.some((p) => CROWN_JEWEL_READ_PATTERNS.some((re) => re.test(p)) && !isClaudeToolResult(p))) {
    return { tier: 'red', reason: 'reads a crown-jewel/secret path (vault-only)' };
  }
  if (probes.some(isBroadReadRoot)) {
    return { tier: 'yellow', reason: 'recursive read over a broad root may surface secrets — review' };
  }
  return null;
}
