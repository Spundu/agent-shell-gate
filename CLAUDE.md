# agent-shell-gate

A fail-closed PreToolUse gate for AI coding agents (Claude Code hook protocol). Every tool call is classified
GREEN (auto-run) / YELLOW (ask) / RED (deny) by an exact-name tool catalog (default-deny on anything unknown)
plus escalate-only argument inspectors. The core is `src/inspectors/bash.ts`: a quote-aware shell lexer that
grants GREEN only when it can PROVE the command is a single, bare, read-only program with no composition,
substitution, redirect, write-flag, glob, or unbalanced quote. `src/policy.ts` holds the frozen pattern lists
(dangerous commands, host-escape interpreters, crown-jewel secret paths, protected write paths, crown-jewel
hosts). `docs/GATE-SECURITY-MODEL.md` is the threat model and accepted residual; read it before changing patterns.

Extracted from the `safety` package of a private personal-agent monorepo. Cross-package imports were vendored
into `src/contracts/` (tiers + audit record schema), `src/shared/` (secret-shape detector) and `src/audit/`
(JCS canonicalize + HMAC hash-chain). The cockpit live-feed emitter was left out (display-only, not the gate).
Inherited vocabulary: "the Brain" is the agent, "the vault" is the separate money/secrets principal, and
`jarvis-home` / `JARVIS_*` are the deployed gate's protected-path tag and env-var contract. Do not rename them.

Rules: inspectors escalate only (`maxTier` / `strongest`) and never return early past a pending RED; every new
guard gets a fixture in `src/conformance.ts` (284 today) and, if adversarial, a vector in `probes/`. Run
`npm run verify` (build, typecheck, lint, 579 vitest tests, 285-vector gate probe, 242-check audit probe);
`npm test` alone skips the 4 tests that exercise the bundled `dist/hook-pre.cjs` until you build.
