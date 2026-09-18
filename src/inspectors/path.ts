import { isAbsolute, resolve } from 'node:path';

// Resolve a tool-supplied path to absolute (against the session cwd when relative) so a relative or
// `..`-laden path cannot slip past a protected-prefix match (F9). Best-effort: returns the original
// string if resolution throws. Shared by the file (write) and read inspectors.
export function resolveToolPath(path: string, cwd?: string): string {
  if (path.length === 0) return path;
  try {
    return cwd && !isAbsolute(path) ? resolve(cwd, path) : resolve(path);
  } catch {
    return path;
  }
}
