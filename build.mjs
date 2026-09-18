import { build } from 'esbuild';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

// Paths are resolved relative to THIS file (not the CWD) so the build is runnable from anywhere.
const here = dirname(fileURLToPath(import.meta.url));
const dist = join(here, 'dist');
rmSync(dist, { recursive: true, force: true });

// 1. The library: plain ESM + .d.ts via tsc (dist/lib/**). Tests, probes and the hook executables are
//    excluded by tsconfig.build.json.
const tsc = spawnSync(
  process.execPath,
  [join(here, 'node_modules', 'typescript', 'bin', 'tsc'), '-p', join(here, 'tsconfig.build.json')],
  { stdio: 'inherit' },
);
if (tsc.status !== 0) {
  throw new Error(`tsc library emit failed (exit ${tsc.status ?? 'signal ' + tsc.signal})`);
}

// 2. The two hook executables, bundled to self-contained CJS the interactive Claude CLI invokes as
//    `node dist/hook-pre.cjs` / `node dist/hook-post.cjs`. Everything (incl. zod, which the sealing
//    schema needs) is inlined so the host-owned hook has no node_modules dependency at runtime.
//    `absWorkingDir` is pinned so the `// <path>` banner esbuild writes per module is byte-stable
//    regardless of which directory the build is launched from (a deployed-gate integrity check
//    compares dist byte-for-byte; a check that can spuriously fail is a check nobody trusts).
await build({
  entryPoints: [join(here, 'src/hook-pre.ts'), join(here, 'src/hook-post.ts')],
  absWorkingDir: here,
  outdir: dist,
  outExtension: { '.js': '.cjs' },
  bundle: true,
  platform: 'node',
  format: 'cjs',
  target: 'node22',
  logLevel: 'warning',
});

console.log('built: dist/lib/** (ESM + d.ts), dist/hook-pre.cjs, dist/hook-post.cjs');
