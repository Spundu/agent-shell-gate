import type { InspectorName } from '../catalog.js';
import type { BrowserHint } from '../browser-context.js';
import { inspectBash } from './bash.js';
import { inspectChromeDevtools } from './chrome-devtools.js';
import { inspectClaudeInChrome } from './claude-in-chrome.js';
import { inspectComputerUse } from './computer-use.js';
import { inspectFile } from './file.js';
import { inspectFetch } from './fetch.js';
import { inspectRead } from './read.js';
import type { InspectorResult } from './result.js';

export type { InspectorResult } from './result.js';
export { inspectBash } from './bash.js';
export { inspectChromeDevtools } from './chrome-devtools.js';
export { inspectClaudeInChrome } from './claude-in-chrome.js';
export { inspectComputerUse } from './computer-use.js';
export { inspectFile } from './file.js';
export { inspectFetch } from './fetch.js';
export { inspectRead } from './read.js';

/** Dispatch to the named inspector. Returns null when no inspection applies. `cwd` lets the file, read
 * AND bash inspectors resolve relative paths against the calling session's working directory (F9), so a
 * shell write/read of a protected/crown-jewel path is classified the same whether the path is absolute or
 * relative — parity with the Write/Read tools. `browser`
 * carries the mcp op name + the session's snapshot context so the chrome-devtools inspector can
 * resolve a click's opaque uid (the smart-click resolver). */
export function runInspector(
  name: InspectorName,
  toolInput: Record<string, unknown>,
  cwd?: string,
  browser?: BrowserHint,
): InspectorResult | null {
  switch (name) {
    case 'bash':
      return inspectBash(toolInput, cwd);
    case 'file':
      return inspectFile(toolInput, cwd);
    case 'fetch':
      return inspectFetch(toolInput);
    case 'read':
      return inspectRead(toolInput, cwd);
    case 'chrome-devtools':
      return inspectChromeDevtools(toolInput, cwd, browser);
    case 'claude-in-chrome':
      return inspectClaudeInChrome(toolInput, cwd);
    case 'computer-use':
      return inspectComputerUse(toolInput);
    case 'none':
      return null;
    default:
      return null;
  }
}
