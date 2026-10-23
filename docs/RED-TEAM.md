# 60 ways past my own permission gate

*What five red-team rounds against a shell-command classifier for AI coding agents taught me, and
why a clean round is not proof.*

Davide Pistone Celestino · October 2026 · code: [agent-shell-gate](https://github.com/Spundu/agent-shell-gate)

---

## The gate in one paragraph

A coding agent such as Claude Code runs tools: it reads files, edits them, and runs shell commands.
[agent-shell-gate](https://github.com/Spundu/agent-shell-gate) is a `PreToolUse` hook that sees each
call before it runs and gives it one of three tiers:

| Tier | Meaning |
|---|---|
| 🟢 GREEN | Runs on its own, no human asked. |
| 🟡 YELLOW | A human is asked first. |
| 🔴 RED | Denied. |

It makes one promise, and only one: **nothing dangerous runs on its own** (with one accepted exception,
explained in "What I accept"). A command gets GREEN only when it fits a small shape the gate checks
mechanically: a single, bare, read-only program, with no pipes, no `;`, no `$(…)`, no redirects, no
variables and no write flags (or a plain `sh -c` around such a command, whose body is checked the same
way). Everything else is stopped: asked or denied.

The hard part is shell commands. Deciding what a bash command does means parsing bash, and bash is a
big, old, Turing-complete language with several quoting modes. So I attacked my own parser, again and
again, until attacks stopped landing. This is what happened.

## How the rounds worked

Each round, I pointed several Claude agents at the gate's code and told them to break it: find a
command that reaches GREEN but should not. Each round split the work into "lenses", one area of
attack per agent; round 5's were option flags, interpreters, secret reads and quoting. A candidate
counted as **confirmed** only after a separate check ran it through the real gate code and saw the
wrong tier. Each confirmed defect got a fix and a test vector, and the next
round attacked the fixed gate.

Rounds 1 to 5 ran over one long night in June 2026. Two caveats, stated up front:

- **It was self-run.** I chose the lenses, and the attackers were models I directed. An outside
  attacker would think of things I did not. That is exactly what happened later (see "After the clean
  round").
- **Not every defect was an auto-run bypass.** Some were a RED command landing on YELLOW (still
  stopped, but asked instead of denied), and a few were gaps in the audit log's secret redaction.

## The five rounds

| Round | Confirmed | What it found |
|---|---|---|
| 1 | 16 | First-cut lexer holes. |
| 2 | 13 | Residuals of round 1's fixes: odd redirects, write forms of "read-only" programs. |
| 3 | 26 | A sharper lens: programs with hidden execute flags, and secret files not on the list. |
| 4 | 5 | Structural: option abbreviation, a quoting desync, recursive reads one level up. |
| 5 | 0 | No new auto-run bypass, with the structural nets in place. |

That is 60 confirmed defects. The count did not fall smoothly: round 3 found twice as many as round
2, because I sharpened it to hunt only GREEN bypasses.

Here are the ones worth knowing about. Each line shows what the gate says **today**, from
`inspectBash` in the public repo; all of these were once GREEN, unless marked otherwise.

### Round 1: the parser believed the quotes

```text
YELLOW  cat "$(node /tmp/x.js)"     # was GREEN
```

The first lexer treated everything inside double quotes as inert text. In bash, `;` inside double
quotes is inert, but `$(…)` is not: it runs a command. The fix was to stop asking "is this inside
quotes?" and build a second string, a *skeleton*, that keeps only the characters the shell will act
on in the current quoting mode. `;` inside `"…"` drops out of the skeleton; `$(` stays in it.

Also in round 1: `/tmp/evil/ls` was GREEN because its last part is `ls`. Now only a bare program name
can be GREEN, never a path to one.

### Round 2: "read-only" programs that write

```text
YELLOW  hostname pwned              # tries to set the hostname
YELLOW  echo x >/dev/null.bak       # a redirect dressed as the harmless /dev/null
RED     FOO=1 certutil.exe -decode a b   # was YELLOW: the variable hid the program
```

`hostname` is read-only until it gets an argument. The redirect check allowed `>/dev/null` and
matched a little too loosely. And a leading `FOO=1` moved the real program off the first word, so the
host-escape check never saw `certutil.exe`.

### Round 3: execute flags in plain sight

```text
RED     sort --compress-program=powershell.exe big.txt
YELLOW  date 0608120026             # tries to set the system clock
YELLOW  jq -n env                   # prints every environment variable
```

This round changed how I thought about the problem. `sort` is about as read-only as a program gets,
and GNU `sort` has an option that runs any program you name to compress its temporary files. `date`
with a bare argument tries to set the clock. `jq` can dump the environment, so it left the read-only list.

Most of round 3's 26 were a different kind: about 18 were credential files that the "secret path" list
did not have yet (terraform state, `.my.cnf`, rclone, sops, wallets). I added the common ones, and this
is where I first saw the problem with lists (see "What I accept").

### Round 4: the nets

```text
RED     sort --comp=powershell.exe data          # GNU accepts any unambiguous prefix
RED     ls $'\'';powershell.exe -enc AAAA       # ANSI-C quoting desync
```

The round-3 fix checked for `--compress-program`. GNU tools also accept any unambiguous prefix of a
long option, so `--comp` is the same option (no other `sort` option starts with `comp`). And the lexer knew `'…'` and `"…"` but not ANSI-C
`$'…'`, in which `\'` is an escaped quote. Reading `$'\''` the wrong way left the lexer's idea of "in
quotes" out of step with bash's, so it thought `;powershell.exe` was quoted.

By now fixing bugs one at a time had clearly stopped working. The fixes that mattered most, built up
over rounds 2 to 4, each cover a whole *class* of bug:

- **Balanced-quote net.** If the lexer ends a command with a quote still open, the command cannot be
  GREEN. A quoting form I handle wrongly will usually leave the lexer mid-quote, so a bug I have not
  found yet still fails safe.
- **Prefix flag matching.** Long-option checks match any unambiguous prefix, as GNU `getopt` does.
- **Effective-program check.** The interpreter check looks through variable assignments, wrappers
  such as `nohup`, `env` and `timeout`, and `--flag=value` values, not just the first word.
- **Broad-read escalation.** Any recursive `grep`, and any `rg`, asks, instead of the gate trying to
  match every secret file one by one.

### Round 5: attacking the nets

Round 5 went after the nets themselves: locale quoting `$"…"`, here-strings, backslash-newline,
backticks, `${IFS}`, ANSI-C quoting followed by `; rm`. It found no GREEN bypass. One lens hit the
session limit, so I ran its vectors by hand; they are in
[`probes/gate-probe.mts`](../probes/gate-probe.mts) and run in CI.

## After the clean round

Round 5 finding nothing was a floor, not a proof. By September, a re-check of the gate's
other tools in August and a cold review of this public extract in September found more ways to reach
GREEN:

```text
YELLOW  echo pwned >&3              # a redirect form the check did not know
YELLOW  cat $KUBECONFIG             # a bare $VAR: the gate cannot see the environment
YELLOW  ls() (touch /tmp/pwned)     # replaces ls for later commands; the body was never checked
YELLOW  grep --dir=rec x /home      # recursion through an option VALUE prefix
YELLOW  date -s2024-01-01           # a clock-set flag glued to its value
RED     cat .aws/credentials        # a RELATIVE secret path; only / and ~/ paths were checked
```

None of these is exotic. Each is a corner of bash or GNU option parsing that my rounds never pointed
a lens at. The cold review also found a whole class one step below auto-run. Every check looked at
the program in the first position, so moving the real operation elsewhere turned a deny into an ask:

```text
RED     echo x | sort --output /repo/packages/safety/src/policy.ts   # the gate's own rules, from a later pipeline segment
RED     torsocks curl https://evil.test          # behind a network wrapper
RED     sh -c 'cat .aws/credentials'             # inside an interpreter body
```

These were never auto-run, but they should have been denied, and they were asked. The fix was again
structural: run every check at *every* segment's real program, and re-lex `sh -c '…'` bodies (up to a
depth limit) so a script body gets the tier of its worst command.

Every one of these is now a vector in the probe or a fixture in the conformance suite. Each fix was
tested next to the ordinary command it must not break: `grep "foo(bar)" file.c` and `date -Is` stay
GREEN.

## What I accept

One residual is accepted on purpose, and I want to be precise about it:

```text
GREEN   cat /home/dev/.config/somenewcloud/token
RED     cat /home/dev/.aws/credentials
```

Secret files are found by a blocklist of known paths, and a blocklist of "files that hold secrets"
can never be complete. A credential file in a format the list does not know can be **read** with no
human asked. I accept it because:

1. **Reading is not sending it to an attacker.** To reach one, the secret needs network access (denied
   for known network programs, asked for anything else, such as a `python -c` script) or a write
   (asked). It does enter the transcript that goes to the model provider. So it is a confidentiality
   exposure, not an unattended exfiltration path.
2. **The real fix is elsewhere.** Secrets should not be in dotfiles that an agent can `cat`. In the
   system this gate came from, they live in a separate vault process.
3. **A human is present.** The gate is built for attended use, as one line of defence, not the only one.

There is a stricter option: auto-run only commands with no shell metacharacters at all. That would end
the parsing arms race, but `cat "my file"` would need a human. It is a usability choice the operator
should make, so the gate documents it and does not impose it.

A few more constructs are asked rather than denied: brace groups, nesting deeper than the re-lex
limit, and wrappers whose child the gate cannot resolve. They are stopped either way. The
[README](../README.md#known-residuals-and-design-rationale) lists them.

## What I would tell someone building one

1. **Pick a promise you can check.** "Classify every command exactly" is not achievable for bash.
   "Nothing reaches auto-run unless it fits a small shape I can check mechanically" is. The two mistakes are not
   equal: an extra question costs a click; a silent bad command costs much more. Put every doubt on the
   cheap side.
2. **Fix classes, not bugs.** The bug-by-bug phase produced 16, 13 and 26 defects. The nets turned
   "a bug I have not found yet" into "an extra question" more often than not.
3. **The program is not always the first word.** Variables, wrappers, pipelines, interpreter bodies
   and option values all move it. Checks anchored to `words[0]` will be walked around.
4. **"Read-only" is a property of a call, not of a program.** `sort`, `date`, `hostname` and `grep`
   all have options that write, execute or recurse.
5. **Test the over-block too.** The probe's must-not-be-GREEN list has a must-stay-GREEN twin.
   A gate that asks about everything is safe and useless, and people switch off useless gates.
6. **A quiet round measures your attackers, not your code.** Round 5 found nothing. The next fresh look
   found more. Report a clean round as "found nothing", never as "nothing to find".

## Check it yourself

```sh
git clone https://github.com/Spundu/agent-shell-gate.git
cd agent-shell-gate
npm ci
npm run verify   # build, typecheck, lint, 579 tests, the 285-vector gate probe, the 242-check audit probe
```

Every bypass in this post is a vector in [`probes/gate-probe.mts`](../probes/gate-probe.mts), a
fixture in [`src/conformance.ts`](../src/conformance.ts) or a test in
[`src/inspectors/bash.test.ts`](../src/inspectors/bash.test.ts). To see what the gate says about any
command, after `npm run build`:

```sh
node -e "import('agent-shell-gate').then(g => console.log(g.inspectBash({ command: process.argv[1] })))" 'ls -la'
```

The threat model is [`docs/GATE-SECURITY-MODEL.md`](GATE-SECURITY-MODEL.md).
