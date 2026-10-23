# Gate security model, red-team convergence, and the accepted residual

> Written during the June 2026 hardening run and updated after the September 2026 cold review of this
> extract. Captures WHAT the gate guarantees, what it does NOT, and why. The rounds are told in full in
> [RED-TEAM.md](RED-TEAM.md).

## 1. The model

Every agent tool call is classified by this package (originally the `safety` package of a personal-agent monorepo) into a tier:

- **GREEN** → auto-run, no human. Granted ONLY for things we can PROVE are safe-to-auto-run:
  reads, and a single bare read-only shell program with no command-introducing metacharacter and no
  write/exec/mutate side-channel.
- **YELLOW** → ask the human (the attended flow). The default for anything world-changing, composed,
  substituted, redirected, unknown, or broad.
- **RED** → deny. Dangerous/irreversible, host-escape interpreters, network egress, and crown-jewel
  secret reads.

The gate is **escalate-only** (`maxTier`) and **fail-closed** (no audit ⇒ no action). It is enforced
in host-owned code at the hook layer, unbypassable per-agent (subagents inherit it).

## 2. What the red-team rounds taught us

Rounds 1–5 ran in June 2026 and confirmed 60 defects. Row 6 is the third round of a cold review of
this public extract, in September 2026.

| Round | Confirmed | Theme |
|------|-----------|-------|
| 1 | 16 | First-cut lexer holes: **double-quote command substitution** reaching GREEN; native Read/Grep skipping the crown-jewel check; `>&word`, write-flag programs, path-qualified programs, `.exe`/`/mnt` interpreters. |
| 2 | 13 | Residuals: punctuation-trailer redirects (`>&0,foo`, `>/dev/null.bak`); `uniq -`/`file -C`/`hostname` mutate forms; recursive Grep over leaf-only secret dirs; host-escape behind env-assignment/exec-wrapper prefixes; F12 `tool`-field leak. |
| 3 | 26 (25 GREEN) | **Two tails surfaced:** (a) read-only-program **execute/mutate side-channels** — `sort --compress-program=powershell.exe` runs arbitrary code at GREEN, `date <positional>` sets the clock, `jq -n env` dumps env; (b) **crown-jewel filename enumeration** — ~18 standard credential stores (terraform, sops/age, rclone, .my.cnf, wallets, …) not yet listed. |
| 4 | 5 (3 GREEN) | Narrowed to structural: GNU long-option **prefix abbreviation** (`sort --comp=` = `--compress-program` → exec), the **ANSI-C `$'...'` quote desync** (`ls $'\''` hides the trailing `;powershell.exe`), recursive read at an **intermediate ancestor** of a secret leaf; + 2 audit-redaction gaps (entropy key, numeric secret). |
| 5 | 0 GREEN | Attacked the structural nets directly. Clean lenses (flag / host-escape / read-audit) found 0 in-scope GREEN bypasses; the quote-net lens was session-limited and re-run by hand (`gate-probe.mts`) — locale `$"..."`, here-string, backslash-newline, backtick, `${IFS}`, ANSI-C+`;rm` all escalate; benign quoted args stay GREEN. **Structural nets held.** |
| 6 (2026-09-18) | 0 GREEN; a RED→YELLOW **downgrade** class | Detection was anchored to the PROGRAM POSITION (`words[0]`). Moving the real operation off it — a later pipeline segment (`echo x \| sort --output <spine>`), an exec / network-shaping wrapper (`nohup …`, `torsocks curl`), or a `sh -c '<script>'` body — demoted a protected-write / crown-jewel-read / egress from RED to YELLOW (still an ASK, never GREEN). Fixed structurally: every check runs at **every** segment's real program (assignments + exec/network wrappers skipped) and interpreter `-c` bodies are re-lexed to their max severity. |

**The counts did not monotonically fall** (16→13→26→5→0), but round 5 is the first to find **no GREEN
bypass** once the structural nets (§3b) were in place — the signal that the *class* attacks, not just
individual bugs, are now closed. It was a floor, not a proof: the August and September reviews still
found GREEN bypasses the five rounds never aimed at (`echo x >&3`, a bare `$VAR`, a function definition
`ls() (…)`, recursive `grep` through option prefixes, a relative secret path). Each is now a vector. The bounded residual (§3) is the novel-secret-filename read, owned by
the vault (Phase 3). Round 3 found *more* than round 2 — because it was sharpened
to hunt GREEN bypasses and struck the two tails above. This is the key finding: the gate is a
**program-allowlist + secret-path-blocklist**, and a blocklist of "files that hold secrets" can never
be complete.

## 3. Two tails — one closed structurally, one accepted

- **Execute/mutate/write side-channels (CLOSED).** This class is BOUNDED: only a handful of read-only
  programs have a write/exec/env-dump flag, and they are now all guarded (`hasWriteInvocation` for
  sort/tree/date/uniq/file/hostname incl. `--compress-program`/positional clock-set; `jq` removed from
  the allowlist; a flag-value host-escape backstop so `--compress-program=<interpreter>` is RED). Every
  member of `READ_ONLY_PROGRAMS` was audited for remaining exec/env/write primitives — none found.
  Round 4 is the convergence confirmation. (Not the last word: the September cold review found two more
  members, `date -s` glued to its value and `hostname -F<file>`, now guarded too.)

- **Crown-jewel filename enumeration (ACCEPTED, BOUNDED RESIDUAL).** There will always be another
  credential-file format. A novel one (`~/.config/somenewcloud/token`) could be **read** at GREEN. We
  accept this as a bounded residual because:
  1. **Exfil requires a gated action.** A secret read into the Brain's context cannot LEAVE without a
     network egress (RED for known network programs, YELLOW for anything else) or a Write (YELLOW) — both gated. It does reach the model provider's transcript. So a GREEN secret-read is a
     confidentiality exposure in-context, not an exfiltration primitive.
  2. **The secret should not be on disk to read.** Phase 3 (the vault) is the real fix: crown-jewel
     secrets live in the vault, not in dotfiles the Brain can `cat`. The blocklist is a stopgap for the
     pre-vault period.
  3. **Attended-first.** The human is present; the gate is not the sole line of defense.
  We have nonetheless enumerated the **common** stores (cloud CLIs, k8s/helm, terraform, IaC secrets,
  DB clients, package registries, browsers, shells, wallets) so the realistic cases are RED.

## 3b. Why this is an arms race — and the structural nets that end it

Writing a bash-command classifier is **adversarial parsing of a Turing-complete shell**; a hand-written
lexer will never be *provably* complete against bash's grammar. Every round found a new lexer/flag
corner. So beyond fixing each, we added **structural nets** that fail safe against *whole classes*,
including future-unknown bugs:

- **Balanced-quote net:** GREEN is refused if the lexer ends with any quote still open. A quoting
  construct we mis-handle (the class ANSI-C `$'...'` was) typically leaves the lexer mid-quote → caught
  → YELLOW, even if we never anticipated that construct. (All four bash quoting modes — `'`, `"`,
  `$'...'`, `$"..."` — are now handled; this net backstops the rest.)
- **Prefix-flag matching:** long-option guards match any unambiguous PREFIX (GNU getopt semantics), so
  `--comp`/`--out`/`--s` can't dodge the write/exec guard by abbreviation.
- **Effective-program + flag-value host-escape:** the host-interpreter check sees through
  env-assignments, exec-wrappers (`nohup`/`env`/`timeout`/…), `--flag=value` program values, and all
  substitution-body tokens — not just `words[0]`.
- **Broad-root + ancestor read escalation:** recursive reads over home/`.config`/profile roots escalate
  structurally, not only when the exact secret leaf is named.

These convert most of the tail from "enumerate every bug" to "the safe shape is closed."

## 3c. The durable end-state (decision for the owner)

The most robust fix to the lexer arms race is to **invert GREEN to a strict safe-grammar**: auto-run
only a command that is metacharacter-free with a bare read-only program and plain args. That would end
the arms race definitively — but it makes common quoted commands (`cat "my file"`, `grep "a b" f`)
YELLOW, i.e. the Brain asks far more. That is a UX tradeoff **the owner should choose**, not one to impose
overnight. Current posture (handle all quoting modes + the balanced net + flag/host-escape nets) keeps
quoted commands GREEN while closing the known classes; the strict grammar is the lever if we ever want
zero residual at the cost of more asking.

## 4. Stronger fixes for later (post-vault / when tightening)

- **Conservative GREEN-read policy:** escalate reads of dotfiles / `~/.config|.local|.aws`-style paths
  to YELLOW structurally, instead of enumerating each secret. (Deferred: too disruptive for dev
  workflows today; revisit once the Brain's heavy dotfile reads are characterized.)
- **Egress allowlist (the real exfil control):** today known network programs are RED and any other network use asks; a JIT allowlist that the
  vault brokers means even a leaked-into-context secret has nowhere to go.
- **Two-principal accounts (F2):** isolates the ONE secret that matters most — the audit seal key — so
  even a perfect read bypass can't reach it.

## 5. Bottom line

The **critical invariant — a dangerous/world-changing/secret-touching command never AUTO-RUNS (GREEN)
— holds** for every vector in the 285-vector probe and the conformance fixtures, with the execute
side-channel class structurally closed. That is a statement about every attack found so far, not a proof
about bash. The residual is the long tail of *novel* secret filenames being *readable* (not
exfiltratable) at GREEN, which keeping secrets out of the agent's reach (a vault) closes properly.
