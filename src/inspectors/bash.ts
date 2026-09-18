import { isAbsolute, resolve } from 'node:path';
import {
  CROWN_JEWEL_READ_PATTERNS,
  DANGEROUS_BASH_PATTERNS,
  HOST_ESCAPE_PROGRAMS,
  DANGEROUS_PROGRAM_PATTERNS,
  NETWORK_PROGRAM_PATTERNS,
  PROTECTED_PATH_PATTERNS,
  READ_ONLY_PROGRAMS,
} from '../policy.js';
import { analyzeBash, basename, substitutionBodies, substitutionTokens, type BashAnalysis } from './bash-lexer.js';
import { strongest, type InspectorResult } from './result.js';

// The protected-path / crown-jewel patterns in policy.ts anchor a directory segment on a LEADING separator
// (`[\\/]audit[\\/]…jsonl`, `[\\/]vault[\\/]`, `[\\/]packages[\\/]safety[\\/]`, `[\\/]\.ssh…`). A bare RELATIVE
// path (`audit/x.jsonl`, `vault/y`, `.ssh/id_rsa`) has no leading separator, so it slips past every one of
// them — while the identical Write/Read tool call is RED because inspectFile/inspectRead resolve the path to
// absolute first (resolveToolPath). That asymmetry was the round-2 parity break: a relative shell write to
// the gate's own spine was only YELLOW while the Write was RED. `pathProbes` closes it for bash by testing
// each command word in BOTH raw and resolved form, exactly as the file/read inspectors do.

/** For each command word, the path forms a protected/crown-jewel pattern must be tested against: the raw
 * word, plus — for a RELATIVE word — its resolved absolute form. With a known session cwd we resolve against
 * it (accurate, mirroring resolveToolPath). With cwd UNKNOWN we still anchor the relative word at the
 * filesystem ROOT: a fail-closed floor so `audit/x.jsonl` / `vault/y` / `.ssh/id_rsa` cannot dodge a
 * leading-separator-anchored pattern merely because no cwd was supplied — WITHOUT falling back to the gate
 * process's own cwd (resolve(word) alone), which would spuriously anchor every relative argument. An
 * already-absolute word is left as-is (its raw form already carries the separators). */
function pathProbes(words: readonly string[], cwd?: string): string[] {
  const base = cwd !== undefined && cwd.length > 0 && isAbsolute(cwd) ? cwd : '/';
  const out: string[] = [];
  for (const w of words) {
    out.push(w);
    if (w.length === 0 || isAbsolute(w)) continue;
    try {
      out.push(resolve(base, w));
    } catch {
      /* a non-resolvable word keeps only its raw form */
    }
  }
  return out;
}

// inspectBash decides the tier for a Bash tool call. GREEN (auto-run, no human) is granted ONLY
// when we can PROVE the command is a SINGLE, bare, read-only program with no shell construct that
// could introduce or execute another command. Everything else escalates: host-escape / dangerous /
// secret-read / process-substitution → RED; composition / command-substitution / redirect /
// write-flag / path-qualified / unknown program → YELLOW (ask).
//
// The quote-aware lexer (analyzeBash / substitutionTokens) lives in bash-lexer.ts; this file is the policy.

const matchesAny = (patterns: readonly RegExp[], probe: string): boolean => patterns.some((re) => re.test(probe));

const touchesCrownJewel = (words: readonly string[], cwd?: string): boolean =>
  pathProbes(words, cwd).some((w) => CROWN_JEWEL_READ_PATTERNS.some((re) => re.test(w)));

/** `ps` invoked to DUMP environment: the BSD `e` option is a BARE option-cluster char (ps auxe / ps e / ps
 * eww), distinct from `-e`/`-A` (which only SELECT all processes); plus the long form `--environment`. Any of
 * these prints other processes' environ (where an inherited secret lives) and must be RED, like env/printenv. */
function isPsEnvDump(words: readonly string[]): boolean {
  if (basename(words[0] ?? '') !== 'ps') return false;
  return words.slice(1).some((w) => w === '--environment' || (!w.startsWith('-') && w.includes('e')));
}

// A Windows executable/interpreter invoked from WSL is a host-escape (F2): it runs as the same
// Windows user and can DPAPI-unseal the audit key. Detect by interpreter NAME, by a Windows-exe
// extension, or by execution from the Windows mount — not just a fixed denylist.
const WIN_EXE = /\.(?:exe|bat|cmd|com|ps1|psm1|vbs|vbe|wsf|wsh|scr|msc|pif)$/i;
const isHostName = (word: string): boolean =>
  HOST_ESCAPE_PROGRAMS.has(basename(word).replace(/\.exe$/i, '').toLowerCase());
const isWinInterpreter = (word: string): boolean => {
  const b = basename(word);
  return WIN_EXE.test(b) || /^\/mnt\/[a-z]\//i.test(word) || isHostName(word);
};

// Benign wrappers that re-exec their argument as a real subprocess — a Windows interpreter passed to
// one of these still runs (RT round-2 #10/#12), so the host-escape check must see through them.
const EXEC_WRAPPER: ReadonlySet<string> = new Set([
  'nohup', 'timeout', 'nice', 'ionice', 'setsid', 'stdbuf', 'command', 'xargs', 'env', 'time', 'doas',
  'sudo', 'chrt', 'taskset', 'exec', 'builtin', 'unbuffer',
]);

// Network-SHAPING wrappers: they re-exec their argument like the exec-wrappers, but their whole point is to
// route the child's traffic (Tor, a proxy chain, a sandbox). `torsocks curl https://evil` runs `curl`, so
// the network / dangerous / write / crown-jewel checks must resolve past them to the REAL program — the same
// way they see past `nohup`. Anchoring on words[0] left `torsocks curl …` (verified YELLOW) un-denied.
const NETWORK_SHAPING_WRAPPERS: ReadonlySet<string> = new Set([
  'torsocks', 'torify', 'proxychains', 'proxychains4', 'firejail', 'catchsegv',
]);

// Every wrapper whose argument is the REAL program of the SAME shell segment (argv-shift). Skipping these +
// leading `VAR=val` assignments is how each per-segment check finds the program position it must anchor to.
const SEGMENT_WRAPPERS: ReadonlySet<string> = new Set([...EXEC_WRAPPER, ...NETWORK_SHAPING_WRAPPERS]);

const isAssignment = (w: string): boolean => /^[A-Za-z_]\w*=/.test(w);

/** The index of the REAL program of a shell segment: skip leading `VAR=val` assignments and wrapper tokens
 * (exec-wrappers + network-shaping wrappers) together with their flags / numeric durations / env-assignments,
 * so `FOO=1 nohup torsocks curl …` resolves to `curl`, not the prefix token. Returns segment.length when the
 * segment is nothing but assignments/wrappers. */
function realProgramIndex(segment: readonly string[]): number {
  let i = 0;
  while (i < segment.length && isAssignment(segment[i] ?? '')) i += 1;
  while (i < segment.length && SEGMENT_WRAPPERS.has(programKey(segment[i] ?? ''))) {
    i += 1;
    while (i < segment.length) {
      const w = segment[i] ?? '';
      if (w.startsWith('-') || /^\d+[smhd]?$/.test(w) || isAssignment(w)) i += 1;
      else break;
    }
  }
  return i;
}

/** The EFFECTIVE program of the first command (host-escape uses it): the real program after skipping
 * leading `VAR=val` assignments and exec/network-shaping wrappers. */
function effectiveProgram(words: readonly string[]): string | undefined {
  return words[realProgramIndex(words)];
}

/** Values of `--flag=value` words — a program-spawning flag (`sort --compress-program=powershell.exe`)
 * EXECUTES its value, so the value is a host-escape if it is an interpreter (RT round-3 #A). */
function flagValues(words: readonly string[]): string[] {
  const out: string[] = [];
  for (const w of words) {
    const m = /^--?[A-Za-z][\w-]*=(.+)$/.exec(w);
    if (m?.[1]) out.push(m[1]);
  }
  return out;
}

function isHostEscape(a: BashAnalysis, substTokens: readonly string[]): boolean {
  const flagVals = flagValues(a.words);
  // A host interpreter is an escape only when it is actually INVOKED — never when it is merely NAMED as a
  // plain argument. The clause that used to live here, `words.some(isHostName)`, matched the NAME in ANY word,
  // so `cat cmd`, `which pwsh`, `grep "cmd" file.ts` (the name is an argument the program reads/searches, not a
  // program it runs) were wrongly RED. An interpreter is INVOKED in exactly three structural positions, each
  // proven below; isWinInterpreter subsumes isHostName (it also matches a `.exe` extension and a `/mnt/<drive>/`
  // path), so a bare host NAME at any of these positions is still caught:
  //  (1) the effective PROGRAM position of SOME segment — after skipping env-assignments and exec/network
  //      wrappers. Per-segment (not just words[0]) so a later segment is covered: `powershell -c evil`,
  //      `wsl bash -c x`, `nohup python.exe …`, `ls; cmd /c dir`, and the ANSI-C-desync'd
  //      `ls $'…';powershell.exe -enc AAAA` (the lexer still splits each segment) all land on a program
  //      position, while an interpreter NAME that is only an argument never does.
  if (a.segments.some((seg) => {
    const eff = effectiveProgram(seg);
    return eff !== undefined && isWinInterpreter(eff);
  })) return true;
  //  (2) a program-spawning flag VALUE — `sort --compress-program=powershell.exe` EXECUTES its value.
  if (flagVals.some(isWinInterpreter)) return true;
  //  (3) inside an executing substitution body — `$(pwsh -c evil)`, `"$(FOO=1 /mnt/c/evil.exe)"`.
  return substTokens.some(isWinInterpreter);
}

// ── GNU option-grammar helpers, shared by every guarded read-only program. The cold review (2026-09-17, C-2/C-3)
// found that each of these rules existed for ONE program and was missing for another: prefix matching lived only
// in hasWriteInvocation while isBroadSearch matched `--recursive` exactly, and the short-cluster rule matched
// `sort -o` but not `date -s2024…`. A rule that is right for one program is right for all of them.

/** The NAME of a `--long[=value]` word (`--comp=x` → `comp`), or undefined for anything else. */
const longOptionName = (word: string): string | undefined => /^--([A-Za-z][\w-]*)/.exec(word)?.[1];

/** GNU getopt_long accepts any UNAMBIGUOUS PREFIX of a long option (and the `=value` form), so a guard must
 * match a `--`word whose name is a PREFIX of a guarded option — `--comp` == --compress-program, `--out` ==
 * --output, `--s` == --set (RT round-4), `--rec` == --recursive, `--deref` == --dereference-recursive (C-3).
 * Over-escalating a prefix collision to YELLOW is safe (the real binary rejects it as ambiguous);
 * under-escalating is the danger. */
const matchesLongOption = (word: string, guarded: readonly string[]): boolean => {
  const name = longOptionName(word);
  return name !== undefined && guarded.some((opt) => opt.startsWith(name));
};

/** True when a SHORT option cluster (`-abc`, `-n3r`, `-us2024-01-01`) contains one of `flags` BEFORE any option
 * in `valueFlags`. A value-taking option consumes the REST of the cluster as its argument, so a guarded letter
 * after it is data (`date -Is` is `-I seconds`, not `-s`). Digits are cluster members: grep takes `-NUM` as
 * `-C NUM`, so `-3r` is `-C3 -r` and recursed in real GNU grep 3.0 while the letters-only rule saw no `r`. */
function clusterHasFlag(word: string, flags: string, valueFlags = ''): boolean {
  if (!/^-[A-Za-z0-9]/.test(word)) return false; // a long option, a bare `-`, or a positional
  for (const ch of word.slice(1)) {
    if (flags.includes(ch)) return true;
    if (valueFlags.includes(ch)) return false;
  }
  return false;
}

/** `recurse` or any prefix of it — GNU grep's argmatch takes an unambiguous prefix for the -d/--directories
 * ACTION (`rec` is the shortest real grep 3.0 accepts; `r`/`re` are ambiguous with `read`, over-escalated). */
const isRecurseValue = (value: string): boolean => value.length > 0 && 'recurse'.startsWith(value.toLowerCase());

const GREP_FAMILY: ReadonlySet<string> = new Set(['grep', 'egrep', 'fgrep']);
const RECURSIVE_LONG_OPTIONS = ['recursive', 'dereference-recursive'] as const;

/** Broad/recursive searches can surface secrets across a whole tree → ask, never auto-run (F3). */
function isBroadSearch(a: BashAnalysis): boolean {
  if (a.program === 'rg') return true; // ripgrep recurses by default (and --pre EXECUTES a program)
  if (!GREP_FAMILY.has(a.program)) return false;
  const ws = a.words;
  return ws.some((w, i) => {
    // -r / -R anywhere in a short cluster — including after -NUM context digits (`-3r`) and the attached
    // -d<action> forms (`-drec`, `-ndrecurse`), since every prefix of `recurse` starts with an `r`.
    if (clusterHasFlag(w, 'rR')) return true;
    const name = longOptionName(w);
    if (name !== undefined) {
      if (RECURSIVE_LONG_OPTIONS.some((opt) => opt.startsWith(name))) return true; // --rec, --recu, --deref, …
      if (!'directories'.startsWith(name)) return false;
      const eq = w.indexOf('=');
      return isRecurseValue(eq >= 0 ? w.slice(eq + 1) : (ws[i + 1] ?? '')); // --dir=rec, --directories recurse
    }
    if (/^-[A-Za-z0-9]*d$/.test(w)) return isRecurseValue(ws[i + 1] ?? ''); // -d rec, -nd recurse
    return false;
  });
}

/** A read-only program invoked with a flag/positional that WRITES or mutates state (e.g. sort -o). Takes the
 * program key and its full word list (`[program, ...args]`) so it can be evaluated at EVERY segment's real
 * program position, not only at words[0]. */
function hasWriteInvocation(program: string, words: readonly string[]): boolean {
  const args = words.slice(1);
  const hasLong = (guarded: readonly string[]): boolean => args.some((w) => matchesLongOption(w, guarded));
  switch (program) {
    case 'sort':
      // -o/--output writes; --compress-program/--files0-from SPAWN a subprocess (RT round-3 #A).
      return hasLong(['output', 'compress-program', 'files0-from']) || args.some((w) => clusterHasFlag(w, 'o'));
    case 'tree':
      return hasLong(['output']) || args.some((w) => clusterHasFlag(w, 'o'));
    case 'date':
      // -s/--set OR the POSIX positional MMDDhhmm[[CC]YY] form both SET the system clock (RT #A).
      // The -s may be ATTACHED to its value or CLUSTERED: GNU getopt reads `-s2024-01-01` and `-us2024-01-01` as
      // a clock-set (verified: "cannot set date: Operation not permitted"), but the guard matched only the exact
      // token `-s` (cold review 2026-09-17, C-2). -d/-f/-r/-I consume the rest of a cluster as their VALUE, so an
      // `s` after one of them is data — `date -Is` is `-I seconds` and must stay GREEN.
      return (
        hasLong(['set']) ||
        args.some((w, i) => {
          if (clusterHasFlag(w, 's', 'dfrI')) return true;
          const prev = args[i - 1] ?? '';
          const takesValue = ['-d', '--date', '-r', '--reference', '-f', '--file'].includes(prev);
          return !takesValue && !w.startsWith('-') && !w.startsWith('+'); // a bare positional sets the clock
        })
      );
    case 'uniq':
      // [INPUT [OUTPUT]] — the 2nd positional is an OUTPUT file uniq truncates. A lone `-` is the
      // stdin INPUT positional (not an option), so it must count (RT round-2 #3).
      return args.filter((w) => w === '-' || !w.startsWith('-')).length >= 2;
    case 'file':
      return hasLong(['compile']) || args.some((w) => clusterHasFlag(w, 'C')); // file -C writes a .mgc
    case 'hostname':
      // `hostname NAME`, `hostname -F file`, `hostname -b` SET the system hostname (RT round-2 #5). The -F may be
      // attached (`-F/tmp/n`) or clustered (`-bF`) — same class as the date -s gap above; no hostname short
      // option other than -F takes a value, so a cluster scan needs no stop set.
      return hasLong(['file', 'boot']) || args.some((w) => !w.startsWith('-') || clusterHasFlag(w, 'bF'));
    default:
      return false;
  }
}

/** True when ANY segment's real program (assignments + exec/network wrappers skipped) is a read-only program
 * invoked with a write/mutate flag. This is the all-position form of hasWriteInvocation: `echo x | sort -o p`
 * writes via the SECOND segment, and `nohup sort -o p` via the program behind the wrapper — both invisible to
 * an words[0]-anchored check. The command line splits into segments in the lexer (| ; && || newline ( )). */
function segmentWriteInvocation(a: BashAnalysis): boolean {
  return a.segments.some((seg) => {
    const i = realProgramIndex(seg);
    const head = seg[i];
    return head !== undefined && hasWriteInvocation(programKey(head), seg.slice(i));
  });
}

/** Programs that WRITE a file named in their own arguments. Not an exhaustive taxonomy of every writer —
 * it does not need to be. It feeds `writesProtectedPath` below, which is deliberately COARSE: it asks "can
 * this command write at all?", not "which argument is the destination?". Getting the destination right per
 * program means reimplementing each tool's option grammar (cp/mv/install's `-t` INVERTS the positional
 * order; tar/unzip use `-C`/`-d`; 7z attaches `-o<dir>` with no space; GNU accepts unambiguous long-option
 * prefixes) — a parser that is wrong once is a hole, whereas over-escalation is merely an extra prompt. */
const WRITER_PROGRAMS: ReadonlySet<string> = new Set([
  'tee', 'cp', 'mv', 'install', 'ln', 'rsync', 'touch', 'truncate', 'mkdir', 'mkfifo', 'mknod', 'sponge',
  'split', 'csplit', 'zip', 'unzip', 'tar', 'cpio', '7z', '7za', 'patch', 'dd', 'sed', 'perl', 'ruby',
  'awk', 'gawk', 'python', 'python3', 'node', 'sh', 'bash', 'zsh', 'openssl', 'gpg', 'base64', 'xxd',
  'git', 'chmod', 'chown', 'chgrp', 'chattr', 'setfacl', 'find', 'xargs', 'sqlite3', 'make', 'npm', 'pnpm',
  'yarn', 'pip', 'pip3', 'curl', 'wget', 'script', 'ffmpeg', 'mktemp',
]);

/** RED when a command that CAN write names a gate-protected path.
 *
 * The parity bug this closes: `inspectFile` REDs a Write/Edit to a protected path, but bash never consulted
 * PROTECTED_PATH_PATTERNS at all — so `Write brain-state/browser-ctx/<sid>.origins.json` was RED while
 * `echo '…' > <the same file>` was merely YELLOW. Same forge, two verdicts, and only the RED half had
 * fixtures. That asymmetry mattered more once the operator profile became persistent (2026-08-23): forging
 * the per-origin click allowance now buys silent AUTHENTICATED clicks, and under autonomy a YELLOW nobody
 * reads is an allow.
 *
 * Deliberately coarse in BOTH directions:
 *  - it fires on a protected path anywhere in the command (source OR destination), because the lexer does
 *    not associate a redirect operator with its target word (`<`/`>` are appended to the skeleton only and
 *    never pushed into `words`), so the destination is present but indistinguishable;
 *  - it requires write CAPABILITY, so a pure `cat <protected>` is unaffected and stays a read decision.
 * The false-positive is `cp <protected> /tmp/x` (reading a protected file into a scratch copy) — RED rather
 * than an ask. That is the correct direction to be wrong in.
 *
 * A RELATIVE destination IS now covered: the session cwd is threaded in and every word is resolved to
 * absolute (pathProbes) before the match, so `echo x > audit/log.jsonl` is RED exactly as the absolute and
 * `~`-relative spellings are — and RED even with no cwd, via the fail-closed root anchor.
 *
 * HONEST LIMIT — this is still a LITERAL path check and cannot see a destination that is not in the command
 * text: `cd <protected-dir> && echo x > y` (the cwd threaded in is the SESSION cwd, not the post-`cd` one);
 * `exec > <path>` poisoning every later command in a persistent shell; `bash payload.sh` where the whole
 * write lives in the file; `$VAR`/glob/`~`-assembled paths. Those stay YELLOW — `$VAR` and `${…}` via the
 * lexer's hasParamExpansion (bare `$NAME` included since the 2026-09-17 cold review; before that only the
 * braced form was seen), glob and `~` via the surviving-metacharacter rung below — and are bounded by the OS
 * ACLs, NOT by this check. Closing them needs shell-state tracking, not a bigger regex. */
function writesProtectedPath(a: BashAnalysis, substTokens: readonly string[], cwd?: string): boolean {
  // Match a writer ANYWHERE in the word list, not just at words[0]. The program of `echo x | tee <path>` is
  // `echo`; the same is true behind every wrapper that shifts argv (`sudo cp`, `env cp`, `xargs cp`,
  // `nohup`, `timeout N`, `busybox cp`) and after any `;`/`&&`. Checking only the first program missed all
  // of them. The false positive - a writer NAME appearing as a literal argument, e.g. `grep cp <protected>`
  // - still requires a protected path in the same command to matter, and over-escalation is the safe side.
  // hasWriteInvocation is the SAME per-program write-flag grammar the YELLOW rung uses (sort/tree -o &
  // --output incl. GNU space-separated + unambiguous-prefix forms, the short-attached `-o<path>` cluster,
  // date -s, hostname -F, file -C, uniq's OUTPUT positional). Reusing it here closes the RED->YELLOW
  // downgrade: before, canWrite recognised only the `=`-attached `--output=`/`-o` spellings, so
  // `sort --output <protected>` / `sort --out <protected>` / `sort -o<protected>` / `tree --output <protected>`
  // wrote to the spine yet fell through to the "write/mutate flag" YELLOW instead of this RED. A write form
  // that the gate flags for one purpose must flag it for both.
  const canWrite =
    a.hasFileRedirect ||
    a.hasHeredoc ||
    a.words.some((w) => WRITER_PROGRAMS.has(basename(w))) ||
    a.words.slice(1).some((w) => /^--?o(?:utput)?=/.test(w) || w === '-o' || /^of=/.test(w)) ||
    segmentWriteInvocation(a);
  if (!canWrite) return false;
  return pathProbes([...a.words, ...substTokens], cwd).some((w) => matchesAny(PROTECTED_PATH_PATTERNS, w));
}

/** Programs that EXECUTE one of their own arguments: the exec / network-shaping wrappers, the shells
 * (`sh -c '…'`), `eval`, the multi-call binaries, and the runners that take a command line. For these, every
 * non-flag argument is a possible program (the gate does not model each one's option grammar — `sudo -u root
 * rm`, `xargs -I{} rm`, `find . -exec rm`, `torsocks curl`), and any argument that is itself a command line
 * (`bash -c 'rm -rf /'`) is lexed again. */
const ARG_EXEC_PROGRAMS: ReadonlySet<string> = new Set([
  ...SEGMENT_WRAPPERS, 'sh', 'bash', 'zsh', 'dash', 'ksh', 'ash', 'fish', 'eval', 'su', 'runuser', 'pkexec',
  'busybox', 'toybox', 'find', 'watch', 'parallel', 'screen', 'tmux', 'script', 'strace', 'ltrace', 'chroot',
  'unshare', 'nsenter', 'flock', 'systemd-run',
]);

/** The name a program-name pattern is tested against: de-quoted basename, `.exe` stripped, lowercased. */
const programKey = (word: string): string => basename(word).replace(/\.exe$/i, '').toLowerCase();

const MAX_SCRIPT_DEPTH = 4; // `sh -c "sh -c \"sh -c …\""` — bounded re-lexing; anything deeper is an ask anyway

/** Every word in PROGRAM POSITION, across every simple command of the command line, the substitution bodies,
 * and (recursively) every argument that a shell / exec-wrapper would run as a command line. This is what the
 * DANGEROUS_PROGRAM_PATTERNS / NETWORK_PROGRAM_PATTERNS are tested against — an ARGUMENT that merely names a
 * dangerous program (`cat format.md`, `npm run format`) is not in it. Fail-closed in construction: a word
 * that is NOT really a program (a wrapper's option value, `sudo -u root`) costs at most an over-escalation. */
function programCandidates(command: string, depth = 0): string[] {
  if (depth > MAX_SCRIPT_DEPTH) return [];
  const out: string[] = [];
  for (const segment of analyzeBash(command).segments) {
    let i = 0;
    while (i < segment.length && isAssignment(segment[i] ?? '')) i += 1;
    const head = segment[i];
    if (head === undefined) continue;
    out.push(head);
    if (!ARG_EXEC_PROGRAMS.has(programKey(head))) continue;
    for (const w of segment.slice(i + 1)) {
      if (w.startsWith('-') || isAssignment(w)) continue;
      out.push(w);
      if (/[\s|&;()`]/.test(w)) out.push(...programCandidates(w, depth + 1)); // an argument that is a command line
    }
  }
  for (const body of substitutionBodies(command)) out.push(...programCandidates(body, depth + 1));
  return out;
}

// ── Interpreter wrappers. `sh -c '<script>'` (and bash/zsh/dash/ksh/ash) does not run a program named in an
// argument — it runs a NESTED SHELL COMMAND LINE carried in the -c value. Because the lexer de-quotes that
// value into a SINGLE word, the crown-jewel-path and protected-write checks (which scan words/tokens) cannot
// see the `cat .aws/credentials` inside it: they saw one opaque word and let a RED body pass as a blanket
// YELLOW. The fix re-lexes the body with the SAME grammar and takes its tier — recursively. A body we cannot
// isolate fails closed to DENY; a benign body is exactly its own inner tier.
const SHELL_INTERPRETERS: ReadonlySet<string> = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'ash']);

/** A short-flag cluster that enables the shell's `-c` "run this command string" mode: `-c`, `-lc`, `-ic`,
 * `-lic`, … (in getopt the command string is the NEXT positional regardless of where `c` sits in the cluster,
 * so its position is not constrained). Over-matching only means we try to classify the next word as a script —
 * the safe direction. */
const isCommandFlag = (w: string): boolean => /^-[a-z]*c[a-z]*$/i.test(w);

type InterpreterBody = { body: string } | { failed: true } | undefined;

/** If `segment`'s real program (assignments + wrappers skipped) is a shell invoked with a `-c`-family flag,
 * return the script body (the word after that flag). `{ failed: true }` when it IS such an invocation but the
 * single body word cannot be isolated (→ fail closed to DENY). `undefined` when the segment is not a `-c`
 * shell invocation at all (`sh script.sh`, `sh -s`, a non-shell program). */
function interpreterBody(segment: readonly string[]): InterpreterBody {
  const i = realProgramIndex(segment);
  const head = segment[i];
  if (head === undefined || !SHELL_INTERPRETERS.has(programKey(head))) return undefined;
  const rest = segment.slice(i + 1);
  const flagIdx = rest.findIndex(isCommandFlag);
  if (flagIdx < 0) return undefined; // a shell without -c runs a FILE/stdin we can't see — handled as YELLOW
  const body = rest[flagIdx + 1];
  return body === undefined ? { failed: true } : { body };
}

const FAIL_CLOSED: InspectorResult = {
  tier: 'red',
  reason: 'interpreter -c script could not be parsed — fail closed (deny)',
};

/** The STRONGEST verdict among every nested shell-`-c` body reachable from `command` — each segment's `-c`
 * body, and (recursively) each command-substitution body, whose QUOTED `"$(…)"` content is not split into
 * a.segments. A RED here denies a command the outer shell would only ask about. Bounded by MAX_SCRIPT_DEPTH. */
function worstNestedBody(a: BashAnalysis, command: string, cwd: string | undefined, depth: number): InspectorResult | null {
  if (depth >= MAX_SCRIPT_DEPTH) return null;
  const results: (InspectorResult | null)[] = [];
  for (const seg of a.segments) {
    const b = interpreterBody(seg);
    if (b === undefined) continue;
    results.push('failed' in b ? FAIL_CLOSED : classifyBash(b.body, cwd, depth + 1));
  }
  for (const body of substitutionBodies(command)) results.push(classifyBash(body, cwd, depth + 1));
  return strongest(...results);
}

export function inspectBash(toolInput: Record<string, unknown>, cwd?: string): InspectorResult {
  const command = typeof toolInput['command'] === 'string' ? toolInput['command'] : '';
  return classifyBash(command, cwd, 0);
}

function classifyBash(command: string, cwd: string | undefined, depth: number): InspectorResult {
  const a = analyzeBash(command);
  const substTokens = substitutionTokens(command);
  const allTokens = [...a.words, ...substTokens];
  // Content patterns (DPAPI surface, pipe-to-shell, `git push -f`, …) are matched against the raw command AND
  // every de-quoted token (incl. substitution bodies), defeating quote-evasion and hidden nested commands.
  const probe = `${command}\n${allTokens.join(' ')}`;
  // Program-NAME patterns are matched only against words in program position (see programCandidates).
  const programs = programCandidates(command).map(programKey);

  if (isHostEscape(a, substTokens)) {
    return { tier: 'red', reason: 'host-escape interpreter (powershell/wsl/cmd/.exe) — vault/forbidden' };
  }
  if (programs.some((p) => matchesAny(DANGEROUS_PROGRAM_PATTERNS, p)) || matchesAny(DANGEROUS_BASH_PATTERNS, probe)) {
    return { tier: 'red', reason: 'dangerous/irreversible shell command' };
  }
  if (isPsEnvDump(a.words)) {
    // `ps auxe` / `ps e` / `ps --environment` dumps OTHER processes' environment (incl. an MCP subprocess
    // holding a token) — env-dump parity with env/printenv (which are already RED). RED, vault-only.
    return { tier: 'red', reason: "ps environment dump (a process's env may hold a secret) — vault-only" };
  }
  // Crown-jewel BEFORE network, so `ssh -i ~/.ssh/id_rsa host` names the secret it reaches for. (Before the
  // 2026-09-17 review `cat ~/.ssh/id_rsa` was RED for "network egress" because `\bssh\b` matched `.ssh`.)
  if (touchesCrownJewel(allTokens, cwd)) {
    return { tier: 'red', reason: 'reads a crown-jewel/secret path (vault-only)' };
  }
  if (programs.some((p) => matchesAny(NETWORK_PROGRAM_PATTERNS, p))) {
    return { tier: 'red', reason: 'shell network egress (no egress allowlist yet)' };
  }
  // Bash/file PARITY: a write that touches gate-protected state is RED here exactly as it is in inspectFile —
  // absolute, `~`-relative, or cwd-relative (pathProbes resolves the destination against the session cwd).
  if (writesProtectedPath(a, substTokens, cwd)) {
    return { tier: 'red', reason: 'shell write to a protected path (spine/audit/vault/config/gate state)' };
  }
  if (a.hasProcSubst) {
    return { tier: 'red', reason: 'process substitution executes an un-inspectable command' };
  }

  // ── Interpreter wrappers (`sh -c '<script>'`). The outer RED rungs above already ran (host-escape, a
  // dangerous/network program NAME re-lexed out of the body, a windows `sh.exe`, a protected path in an
  // UNquoted body segment), so anything they catch stays caught. What they cannot see is a crown-jewel READ
  // or a protected WRITE hidden in the single de-quoted `-c` word — that needs the body re-lexed.
  if (depth < MAX_SCRIPT_DEPTH) {
    // SOLE wrapper: the whole command is just `<wrappers> sh -c BODY` — one clean simple command, nothing
    // else. The wrapper is transparent: the tier IS the body's (re-lexed), so a benign `sh -c 'ls'` is its
    // inner GREEN and a `sh -c 'cat .aws/credentials'` is RED — never a blanket YELLOW that, under autonomy,
    // lets a RED body pass as an unread ask. Fail closed to DENY when the body cannot be isolated. Guarded to
    // a clean outer lex (balanced, no byte-desync, no second command / redirect / substitution / expansion)
    // so nothing outside the body can be smuggled past this transparency.
    const outerClean =
      a.balanced && !a.hasAnsiCEscape && !a.hasComposition && !a.hasCommandSubst && !a.hasHeredoc &&
      !a.hasFileRedirect && !a.hasParamExpansion && a.segments.length === 1;
    if (outerClean) {
      const sole = interpreterBody(a.segments[0] ?? []);
      if (sole !== undefined) return 'failed' in sole ? FAIL_CLOSED : classifyBash(sole.body, cwd, depth + 1);
    }
    // Otherwise a RED hidden in ANY nested body (a `-c` body in one segment of a pipeline, a quoted `"$(…)"`)
    // still denies — the max-severity fold, escalate-only.
    const nested = worstNestedBody(a, command, cwd, depth);
    if (nested?.tier === 'red') return nested;
  }

  if (command.trim().length === 0) {
    return { tier: 'yellow', reason: 'empty shell command' };
  }
  if (a.hasComposition || a.hasCommandSubst || a.hasHeredoc || a.hasFileRedirect) {
    return { tier: 'yellow', reason: 'shell command (composition/substitution/redirect — needs review)' };
  }
  // ANY parameter expansion — `${…}` or the bare `$NAME` / `$1` / `$?` forms, quoted or not — is YELLOW. The
  // gate is stateless and cannot see the environment: `cat $KUBECONFIG` is a crown-jewel read the literal path
  // patterns cannot name, and `echo $ANTHROPIC_API_KEY` prints a secret exactly as `printenv` (RED) would.
  // DECIDED (cold review 2026-09-17, C-4/ADV-1): `echo "$HOME"` is YELLOW too, not an allowlisted exception.
  // Printing any environment variable may leak a secret and a safe-variable allowlist is one more list to
  // get wrong; one extra prompt for the benign case is the accepted cost. This reverses the earlier
  // `echo "$HOME"` → GREEN fixture on purpose.
  if (a.hasParamExpansion) {
    return { tier: 'yellow', reason: 'shell parameter expansion ($VAR/${…}) reads the environment — needs review' };
  }
  if (isBroadSearch(a)) {
    return { tier: 'yellow', reason: 'recursive/broad search may surface secrets — review' };
  }
  if (segmentWriteInvocation(a)) {
    return { tier: 'yellow', reason: 'read-only program invoked with a write/mutate flag' };
  }
  // A surviving (de-quoted) shell-EXPANSION metacharacter in an argument means the shell will expand it to
  // paths the stateless gate cannot see — so it cannot prove the read is benign. Globs (`* ? [`), brace
  // expansion (`{ }` — e.g. `cat .../secret{s,}/supabase.toke{n,}`, `cat /proc/1234/envi{ron,}`), and tilde
  // (`~`) all dodge the LITERAL crown-jewel patterns this way. Escalate to YELLOW (a quoted-literal
  // metacharacter false-positives to an ask — the safe direction). `$VAR`/`${…}` are the lexer's
  // hasParamExpansion rung and `$(…)` is hasCommandSubst, both above; `$` is deliberately NOT in this class.
  if (a.words.slice(1).some((w) => /[*?[{}~]/.test(w))) {
    return { tier: 'yellow', reason: 'glob/brace/tilde expands to unknown paths — cannot prove read-only' };
  }
  // An ANSI-C $'…' escape (`$'\x73…'`, `$'\163…'`) de-quotes to BYTES the gate can't faithfully reproduce, so
  // a crown-jewel path can be byte-encoded past the literal patterns (`cat /proc/1234/$'\x65\x6e\x76\x69\x72\x6f\x6e'`).
  // The decoded word diverges from what bash opens → refuse GREEN (fail-safe, same posture as the glob case).
  if (a.hasAnsiCEscape) {
    return { tier: 'yellow', reason: "ANSI-C $'…' escape de-quotes to bytes — cannot prove read-only" };
  }
  // Structural fail-safe: an UNbalanced lexer end (a quote we never closed) signals either a malformed
  // command OR a quoting construct we mis-handled (the class of bug ANSI-C $'...' was) — refuse GREEN.
  if (!a.balanced) {
    return { tier: 'yellow', reason: 'unbalanced quoting — cannot prove read-only' };
  }
  // GREEN only for a BARE, path-unqualified read-only program — never /tmp/evil/ls or ./ls.
  if (READ_ONLY_PROGRAMS.has(a.program) && !/[\\/]/.test(a.words[0] ?? '')) {
    return { tier: 'green', reason: 'read-only shell' };
  }
  return { tier: 'yellow', reason: 'shell command' };
}
