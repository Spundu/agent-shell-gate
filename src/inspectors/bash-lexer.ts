// The quote-aware bash lexer behind inspectBash. Pure: it turns a command string into de-quoted words
// plus a SKELETON that exposes only shell-active operators, and extracts command-substitution bodies.
// No policy lives here — every tier decision is in bash.ts.
//
// Lexing is quote-aware (F1). Crucially, the shell STILL performs $(...) / `...` substitution and
// ${...} expansion INSIDE double quotes (only single quotes suppress them), so the skeleton keeps
// the expansion-active characters inside double quotes, and substitution BODIES are lexed so an
// interpreter/secret hidden in `"$(…)"` is still caught.

export interface BashAnalysis {
  words: string[]; // de-quoted words, in order; words[0] is the program
  segments: string[][]; // the same words grouped per simple command — split at | & ; newline ( ) and backtick
  program: string; // basename of the de-quoted program
  hasComposition: boolean; // active newline / ; / | / & (excluding fd-dups), or an unquoted ( ) subshell/function
  hasCommandSubst: boolean; // $(…) or backticks
  hasProcSubst: boolean; // <(…) or >(…)
  hasParamExpansion: boolean; // ${…} OR a bare $NAME / $special ($1, $?, $@, $#, $!, $$, $-, $*)
  hasHeredoc: boolean; // <<
  hasFileRedirect: boolean; // a real > / < redirect (not a benign fd-dup or /dev/null discard)
  hasAnsiCEscape: boolean; // a $'\xNN'/$'\NNN'/$'\n'… escape — de-quotes to bytes the gate can't reproduce
  balanced: boolean; // the lexer closed every quote — an UNbalanced end signals a quoting desync
}

const isSpace = (c: string): boolean => c === ' ' || c === '\t' || c === '\r';
/** The character after an ACTIVE `$` that makes it a parameter expansion: a name (`$HOME`, `$_`), a positional
 * (`$1`) or a special parameter (`$? $@ $* $# $! $$ $-`). `$(` and `${` are detected from the skeleton; `$'`
 * (ANSI-C) and `$"` (locale) are quoting, not expansion; a trailing or punctuation-followed `$` is literal. */
const EXPANSION_START = /^[A-Za-z_0-9@*#?!$-]$/;
export const basename = (word: string): string => word.replace(/^.*[\\/]/, '');

/** Quote-aware shell lexer → de-quoted words + a skeleton that exposes only SHELL-ACTIVE operators. */
export function analyzeBash(command: string): BashAnalysis {
  const words: string[] = [];
  let cur = '';
  let started = false;
  let skeleton = '';
  let inSingle = false;
  let inDouble = false;
  let inAnsiC = false; // inside an ANSI-C $'...' string
  let hasAnsiCEscape = false; // a $'\xNN'/$'\NNN'/$'\n'… escape — the gate can't faithfully decode it to bytes
  // A bare `$NAME` / `$special` is a live expansion outside single quotes AND inside double quotes. The skeleton
  // blanks the NAME inside double quotes (only the `$` survives there), so the expansion is recorded here, at the
  // point the lexer sees it, rather than recovered from the skeleton afterwards. Before this flag existed only
  // the braced `${…}` form was detected, so `cat $KUBECONFIG` / `echo $ANTHROPIC_API_KEY` reached GREEN while
  // `cat ${KUBECONFIG}` was YELLOW — the same read at two tiers (cold review 2026-09-17, C-4/ADV-1).
  let hasBareExpansion = false;
  let hasUnquotedParen = false; // a subshell / function-body paren outside quotes (composition)

  const segments: string[][] = [];
  let segment: string[] = [];
  const endWord = (): void => {
    if (started) {
      words.push(cur);
      segment.push(cur);
      cur = '';
      started = false;
    }
  };
  // A command-introducing operator closes the current simple command. `<` / `>` are redirects, not boundaries.
  const endSegment = (): void => {
    endWord();
    if (segment.length > 0) segments.push(segment);
    segment = [];
  };

  for (let i = 0; i < command.length; i += 1) {
    const c = command.charAt(i);

    if (inSingle) {
      if (c === "'") inSingle = false;
      else {
        cur += c;
        started = true;
      }
      skeleton += ' '; // single quotes suppress ALL expansion → inert
      continue;
    }
    if (inAnsiC) {
      // ANSI-C quoting: a backslash escapes the next char, so `\'` does NOT close the string. Keeping
      // the quote state in sync with bash here is what stops `ls $'\''; powershell.exe` from hiding
      // the trailing command and reaching GREEN.
      if (c === '\\') {
        if (command.charAt(i + 1) !== '') {
          cur += command.charAt(i + 1);
          i += 1;
        }
        hasAnsiCEscape = true; // the de-quoted word diverges from bash's real byte expansion → fail-safe escalate
        started = true;
        skeleton += ' ';
        continue;
      }
      if (c === "'") {
        inAnsiC = false;
      } else {
        cur += c;
        started = true;
      }
      skeleton += ' ';
      continue;
    }
    if (inDouble) {
      if (c === '"') {
        inDouble = false;
        skeleton += ' ';
        continue;
      }
      if (c === '\\') {
        const next = command.charAt(i + 1);
        if (next === '"' || next === '\\' || next === '$' || next === '`') {
          cur += next;
          i += 1;
        } else {
          cur += c;
        }
        started = true;
        skeleton += ' '; // an escaped char inside double quotes is inert
        continue;
      }
      if (c === '$' && EXPANSION_START.test(command.charAt(i + 1))) hasBareExpansion = true;
      cur += c;
      started = true;
      // Double quotes still run $(…)/`…` substitution and ${…} expansion; ; | & < > are literal here.
      skeleton += c === '$' || c === '`' || c === '(' || c === ')' || c === '{' || c === '}' ? c : ' ';
      continue;
    }
    // outside quotes
    if (c === '\\') {
      const next = command.charAt(i + 1);
      if (next !== '') {
        cur += next;
        started = true;
        i += 1;
      }
      skeleton += '_'; // a backslash-escaped char can never be a shell operator
      continue;
    }
    if (c === '$' && command.charAt(i + 1) === "'") {
      inAnsiC = true; // ANSI-C $'...' — consume the $ and the opening '
      started = true;
      skeleton += '  ';
      i += 1;
      continue;
    }
    if (c === "'") {
      inSingle = true;
      started = true;
      skeleton += ' ';
      continue;
    }
    if (c === '"') {
      inDouble = true;
      started = true;
      skeleton += ' ';
      continue;
    }
    if (c === '\n') {
      endSegment();
      skeleton += '\n';
      continue;
    }
    if (isSpace(c)) {
      endWord();
      skeleton += c;
      continue;
    }
    if (c === '|' || c === '&' || c === ';' || c === '<' || c === '>' || c === '(' || c === ')' || c === '`') {
      if (c === '<' || c === '>') endWord();
      else endSegment();
      skeleton += c;
      // An UNQUOTED paren opens a subshell `( … )` or a function body `name() ( … )` / `name() { … }` — a
      // construct that INTRODUCES commands. The skeleton keeps parens inside double quotes too (so `"$(…)"`
      // is seen), which is why this is recorded here, on the unquoted branch only: `echo "(hi)"` stays inert.
      // Before this flag, `ls() (touch /tmp/pwned)` was GREEN: words[0] was `ls` and the body was never a
      // program in anyone's eyes (cold review 2026-09-17, C-1).
      if (c === '(' || c === ')') hasUnquotedParen = true;
      continue;
    }
    if (c === '$' && EXPANSION_START.test(command.charAt(i + 1))) hasBareExpansion = true;
    cur += c; // ordinary char (incl. $ { } -)
    started = true;
    skeleton += c;
  }
  endSegment();

  const hasCommandSubst = skeleton.includes('$(') || skeleton.includes('`');
  const hasProcSubst = /[<>]\(/.test(skeleton);
  const hasParamExpansion = skeleton.includes('${') || hasBareExpansion;
  const hasHeredoc = skeleton.includes('<<');

  // Strip constructs flagged separately (proc-subst, heredoc) OR benign (fd-dups, /dev/null discard).
  // A fd-dup must have a real descriptor target (digits or `-`); `>&word` is a FILE redirect, kept.
  // A construct is only blanked when followed by a TRUE terminator (whitespace, a shell operator —
  // | & ; < > ( ) backtick — or end-of-string). Otherwise a file-writing redirect to a digit/null-
  // PREFIXED filename — `>&0,foo`, `>/dev/null.bak` — would be mis-stripped and reach GREEN (RT #1/#2).
  // [\x60 is a literal backtick.]
  let cleaned = skeleton.replace(/[<>]\(/g, '  ').replace(/<</g, '  ');
  // The discard/fd-dup strips run over the SKELETON, where quoted spans were blanked to SPACES — so a quote
  // glued to the target satisfies the "true terminator" lookahead with whitespace that does not exist in the
  // real command. `echo x >/dev/null''bar` writes the FILE /dev/nullbar, yet stripped clean and reached GREEN
  // (verified 2026-08-23). Decide "is this the bit-bucket" from the RAW command, where the quote is visible.
  if (!/(?:\d*|&)>>?\s*\/dev\/null['"]/.test(command)) {
    cleaned = cleaned.replace(/(?:\d*|&)>>?\s*\/dev\/null(?=[\s|&;<>()\x60]|$)/g, ' ');
  }
  cleaned = cleaned
    // Only fds 0-2 are the ordinary stdio dups. `>&3` and above write to a descriptor this shell INHERITED,
    // which the parent may have attached to any file — `echo pwned >&3` classified GREEN "read-only shell"
    // (verified 2026-08-23). A dup to an inherited fd is an un-inspectable write, so it stays a redirect.
    .replace(/\d*>&(?:[0-2]|-)(?=[\s|&;<>()\x60]|$)/g, ' ') // fd-dup out (2>&1, >&2, >&-)
    .replace(/\d*<&(?:[0-2]|-)(?=[\s|&;<>()\x60]|$)/g, ' '); // fd-dup in (<&0)

  return {
    words,
    segments,
    program: basename(words[0] ?? ''),
    hasComposition: /[\n;|&]/.test(cleaned) || hasUnquotedParen,
    hasCommandSubst,
    hasProcSubst,
    hasParamExpansion,
    hasHeredoc,
    hasFileRedirect: /[<>]/.test(cleaned),
    hasAnsiCEscape,
    balanced: !inSingle && !inDouble && !inAnsiC,
  };
}

/** Blank single-quoted spans (and escaped chars) so substitution extraction ignores literal text. */
function blankSingleQuotes(command: string): string {
  let out = '';
  let inSingle = false;
  let inDouble = false;
  let inAnsiC = false;
  for (let i = 0; i < command.length; i += 1) {
    const c = command.charAt(i);
    if (inSingle) {
      out += ' ';
      if (c === "'") inSingle = false;
      continue;
    }
    if (inAnsiC) {
      out += '  ';
      if (c === '\\') i += 1; // backslash escapes next — `\'` does not close
      else if (c === "'") inAnsiC = false;
      continue;
    }
    if (c === '\\') {
      out += '  ';
      i += 1; // drop the escaped char — it cannot open a substitution
      continue;
    }
    if (c === '$' && command.charAt(i + 1) === "'" && !inDouble) {
      inAnsiC = true; // ANSI-C $'...' — handled with backslash-escaping like bash
      out += '  ';
      i += 1;
      continue;
    }
    if (c === '"') {
      inDouble = !inDouble;
      out += c;
      continue;
    }
    if (c === "'" && !inDouble) {
      inSingle = true;
      out += ' ';
      continue;
    }
    out += c;
  }
  return out;
}

/** The BODY of every (non-single-quoted) COMMAND substitution — `$(…)` and backticks. Process
 * substitution `<(…)`/`>(…)` is NOT extracted: it is inert inside double quotes (extracting it there
 * false-RED'd benign strings, RT round-2 rejected-R1), and when unquoted it is already RED via
 * hasProcSubst. Command substitution IS live inside double quotes, so it must be lexed. */
export function substitutionBodies(command: string): string[] {
  const src = blankSingleQuotes(command);
  const bodies: string[] = [];
  const reParen = /\$\(([^()]*(?:\([^()]*\)[^()]*)*)\)/g;
  const reTick = /`([^`]*)`/g;
  let m: RegExpExecArray | null;
  while ((m = reParen.exec(src)) !== null) bodies.push(m[1] ?? '');
  while ((m = reTick.exec(src)) !== null) bodies.push(m[1] ?? '');
  return bodies;
}

/** Every token of every substitution body (see substitutionBodies), split on whitespace and operators. */
export function substitutionTokens(command: string): string[] {
  const tokens: string[] = [];
  for (const body of substitutionBodies(command)) {
    for (const p of body.split(/[\s|&;<>()`]+/)) if (p.length > 0) tokens.push(p);
  }
  return tokens;
}
