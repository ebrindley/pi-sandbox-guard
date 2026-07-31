#!/bin/bash

# SPDX-License-Identifier: MIT
# Bash-command analyzer for pi-sandbox-guard. Owned and maintained in this
# repository (see docs/SETUP.md); adapted from an earlier MIT-licensed
# analyzer by the same author and MIT-licensed here.
#
# validate-bash-command.sh v3.16
# Path-aware rm -rf handling with operand parsing and canonicalization
#
# Exit codes:
#   0 = allow (safe to proceed)
#   1 = warn/ask (requires confirmation)
#   2 = hard-deny (catastrophic, blocked)
#
# v3.16: close seven literal fail-opens (Pi analyzer lane):
#   - shred on /dev/* blocked (device-destroy verb group with wipefs/blkdiscard)
#   - truncate/shred of critical roots blocked (critical-dir verb list)
#   - output redirect into critical paths blocked (token-level; quote-aware so
#     `echo ': > /etc/passwd'` stays allow)
#   - xargs/parallel/find -exec with quoted rm utility ASK (same tier as unquoted);
#     quote-aware lexer. ANSI-C `$'rm'` executor forms are covered when the guard
#     ANSI-C probe reduces them to quoted form.
#   Accepted boundary unchanged: bash -c '$'\''rm'\'' -rf /' (non-contiguous
#   ANSI-C reassembly for nested shell -c).
#
# v3.15: literal interpreter-payload scan. python/python3 -c, node -e/--eval,
# perl/ruby -e, and awk programs that call system() now have their *literal*
# code payloads classified for destructive filesystem/process intent:
#   - BLOCK when a dangerous API clearly targets a protected root/device
#   - ASK for dangerous APIs / command-execution / ambiguous dynamic shapes
#   - ALLOW for benign print/JSON/math/version one-liners
# Fully dynamic payloads (python -c "$VAR", runtime-assembled code) remain out
# of scope; see docs/ARCHITECTURE.md.
#
# v3.14: fix rm flag parsing. segment_has_rf_flags() used a loose regex
# ("-[a-zA-Z]*[rRfF]") that matched ANY option carrying r/R/f/F, so a plain
# "rm -f <file>" (force, no recursion) was misclassified as recursive and its
# operand was run through the catastrophic-path resolver. The flag check now
# tokenizes the rm segment, honors "--", skips redirect targets, and treats
# recursion (-r/-R/--recursive) as the destructive signal. Recursive rm on
# protected roots is blocked even without -f; "rm -f" alone is allowed.
#
# v3.13: two independent adversarial reviews. One found NO
# realistic statically-present catastrophic ALLOW across 90+ probes; the other
# found two realistic gaps + one self-introduced regression, all fixed here:
#   - xargs/parallel running a shell -c '<rm>' with NO option token between them
#     ("xargs sh -c 'rm -rf /'") now ASKs (the pattern required an intervening
#     token).
#   - Recursive chmod/chown where R is not first in the short-option cluster
#     (-fR, -hR, -HR) now DENY (was literal -R only).
#   - FORK BOMB regression: v3.11's grouping rewrite (s/[(){}]/ ; /) shredded the
#     ":(){ :|:& };:" pattern before the grep. The fork bomb is now matched on the
#     RAW command before that rewrite.
#
# v3.12: close residual gaps found in a SEVENTH adversarial review round in the
# v3.11 command-substitution / control-structure handling (adversarial review):
#   - The command-substitution recursion prefilter now also tests a quote/
#     backslash/brace-stripped probe, so a substitution body whose command word
#     is obscured (r"m", r\m, r{m,}, d"d") is still recursed into.
#   - Reaching the substitution-recursion DEPTH CAP now fails safe (ASK) when the
#     command mentions a dangerous tool, instead of silently allowing.
#   - The non-rm dangerous greps now rewrite grouping chars ( ) { } to ";" (so a
#     subshell-wrapped "(dd ... of=/dev/..)" / "(chmod -R 777 /etc)" is at a
#     command position) and scan a quote/backslash-stripped copy (so d"d"/mk"fs"
#     match). chmod/chown protected-root terminators now include ; && | ).
#
# v3.11: close residual bypasses found in a SIXTH adversarial review round (two
# independent reviewers converged):
#   - COMMAND SUBSTITUTION: a catastrophic command hidden inside $(...) or `...`
#     (even inside double quotes, e.g. echo "$(rm -rf /)") is now extracted and
#     re-analyzed recursively (depth-capped); worst decision propagates.
#   - Brace-expansion fail-open: a deeply-nested brace word (r{a,b}{a,b}...x21 =
#     2^21 expansions) hung past the 2s timeout BEFORE the size cap. Now the
#     expansion size is bounded BEFORE eval (comma/brace count) -> fail safe.
#   - dd/mkfs/chmod inside a shell -c / env -S string or after a control-structure
#     keyword (if/then/do/{) are now scanned: the dangerous-pattern greps run on
#     a text that rewrites reserved-word boundaries to ";" and appends decoded
#     shell-string payloads.
#   - find -exec/-execdir/xargs/parallel running a shell with -c '<rm -rf>' now
#     ASKs (DENY when on a system dir).
#   - flock --command / --command= and watch -d/--differences (optional-arg)
#     option forms handled.
#
# v3.10: close residual bypasses found in a FIFTH adversarial review round (two
# independent reviewers converged), all interactions with v3.9's new code paths:
#   - flock -c '<str>' / watch '<str>' run a shell command STRING (like bash -c),
#     not an argv command word -> recurse into the string payload.
#   - Heredoc data/executable classification now skips wrapper PREFIXES
#     (env bash <<EOF resolves to bash, body kept) and keeps the body when the
#     heredoc line pipes into a shell (cat <<EOF | sh).
#   - dd / mkfs detection allows an arbitrary command-runner wrapper option run
#     before the tool (env -i dd ..., timeout 5 mkfs ..., taskset 0x1 dd ...).
#   - The brace command-word check is tri-state: a brace word that also contains
#     a shell substitution ($(...)/backtick) -- which could expand to rm via a
#     path we will NOT eval -- fails safe (ASK/DENY) instead of being treated as
#     "cannot be rm".
#   - xargs/parallel rm and find -exec/-execdir/-ok/-okdir rm are covered (ASK;
#     find on a system dir is DENY).
#
# v3.9: close residual bypasses found in a FOURTH adversarial review round (two
# independent reviewers converged again). KEY CHANGE: wrapper-unwrap was INVERTED
# from a per-wrapper option-arity allowlist (which failed three review rounds --
# each found another wrapper/option spelling that desynced the parse and FAILED
# OPEN) to a STRUCTURAL FORWARD SCAN: once the leading word is a known command
# runner, scan forward to the first literal rm token in this simple command and
# validate from there, regardless of option arity. An unknown option can no longer
# hide the rm. Also:
#   - Nested ${IFS:-${x}} / ${IFS/${a}/ } neutralized via a balanced-brace awk
#     scanner (the old sed [^}]* stopped at the first inner "}").
#   - Named-fd redirect "{name}>" recognized by the lexer (was a leading-redirect
#     that hid the command word).
#   - Brace-expansion command word is expanded with bash's own brace expansion in
#     an array-assignment context (gated to a metacharacter-free word, so no
#     command runs) -- exact for comma groups, {a..b} sequences, and nesting; the
#     check also runs after wrapper unwrap and on bash -c / env -S payloads.
#   - Relative/path-qualified dd & mkfs (./dd, /usr/local/bin/dd) caught at command
#     position; "echo dd of=..." (dd as data) still allowed.
#   - Data heredoc bodies (cat <<EOF ... EOF) are stripped before scanning (were
#     false-DENYing); shell/ssh heredoc bodies (bash <<EOF) are KEPT (executable).
#   - Oversized (>32KB) path no longer skips IFS/brace fail-safes: an $IFS or
#     command-position brace near an -r/-f flag routes to ASK instead of allow.
#   - is_compound_command newline check fixed ($'\n', not the always-empty
#     "$(printf '\n')").
#
# v3.8: close the residual bypasses found in a THIRD adversarial review round
# (two independent reviewers again converged), after v3.7's fixes. All confirmed
# against the live hook before fixing; each has a regression test.
#   - Path-qualified wrappers (/usr/bin/env, /bin/sudo, ...) are unwrapped by
#     BASENAME, not literal token. ("/usr/bin/env rm -rf /" was ALLOWed.)
#   - Exec-wrapper LONG options with a separate-token argument (timeout --signal
#     KILL 5 rm..., nice --adjustment N rm..., stdbuf --output L rm...) no longer
#     desync the parse: an option's following token is consumed as its argument
#     UNLESS it is the command/a wrapper/a separator (so the rm is never swallowed).
#   - More redirection forms split by the lexer: &>-fused on the command word
#     (rm&>log), fd-dup (rm>&2, rm 2>&-, rm <&0), and any-fd leading redirect
#     (9>log rm...). is_redirect_op_token is now fd-agnostic, and the rm
#     reconstruction drops redirect ops sitting between rm and its flags.
#   - ${IFS...} parameter-expansion forms (${IFS:- }, ${IFS%?}, ${IFS#x},
#     ${IFS/x/y}) are neutralized to whitespace, not just literal ${IFS}.
#   - dd to a raw device is command-position anchored with path support
#     (/bin/dd ... of=/dev/...) AND no longer false-DENYs "echo dd of=/dev/sda".
#   - Brace-expansion command word is now ACTUALLY expanded (top-level comma
#     groups) and only flagged when an alternative yields the command word rm --
#     fixing false-DENYs like br{m,avo} / fo{r,m} / x{rm,} while still catching
#     r{m,} and {rm,echo}.
#   - rm operand catastrophic check now also tests the LEXICAL (pre-symlink) path,
#     so /etc and /var (macOS symlinks to /private/...) and their subpaths DENY
#     consistently regardless of how the command word is written.
#
# v3.7: close catastrophic-ALLOW bypasses + a per-operand fail-open, found in a
# second adversarial review (two independent reviewers). All confirmed against the
# live hook before fixing; each has a regression test.
#   - F1 (fail-open, P0): rm operand validation forked a path-canonicalization
#     subprocess (python3) PER operand, plus a git + per-safe-root canonicalize
#     each call. A routine "rm -rf ./node_modules ./dist ./build ./coverage"
#     (48 bytes) took ~2s -- at the 2s timeout edge -> KILLED -> FAILS OPEN; the
#     byte cap never tripped (cost scales with operand COUNT, not size). Fixed by
#     memoizing the loop-invariant work (home canonical, safe roots, repo root)
#     and BATCH-canonicalizing all operands in ONE python3 call; added an
#     operand-count cap that fails safe (DENY catastrophic / ASK) above the cap.
#     30 operands: 17s -> <1s.
#   - F2: env -S / --split-string payloads that START with env options
#     (env -S '-i rm -rf /', env -iS '...', env -C DIR ...) now strip the env
#     options first, then detect the rm.
#   - F3: exec-wrappers that run a literal rm (nice/timeout/nohup/stdbuf/setsid/
#     ionice/exec/...) are unwrapped.
#   - F4: a command word assembled by brace expansion (r{m,} -rf /, {rm,echo}
#     -rf /) is detected by shape and fails safe (DENY if a literal catastrophic
#     target is present, else ASK).
#   - F5: any path whose basename is rm (/opt/homebrew/bin/rm, ./rm) is rm.
#   - F6: a relative rm operand after a cwd change (cd / && rm -rf etc) is
#     re-resolved against the effective cwd; DENY if catastrophic, ASK if the cwd
#     is dynamic and the operand can traverse upward. Recurses into shell -c.
#   - F7: ${IFS}/$IFS references are neutralized to whitespace before detection
#     (rm${IFS}-rf${IFS}/), revealing the real argv.
#   - F8: a redirection fused to the command word (rm>log -rf /, rm</dev/null,
#     rm>|out) is split by the lexer so rm is still recognized.
#   - F9: dd is denied regardless of operand order (of=/dev/... anywhere); mkfs
#     is denied in any spelling (mkfs, mkfs.ext4, mkfs -t, /sbin/mkfs.xfs).
#   - F10: chmod/chown protected-dir matching is anchored to a path boundary, so
#     a benign subpath (chmod -R 755 /tmp/usr) no longer false-positives.
#
# v3.6: linear performance + compound-completeness.
#   - Command tokenization is an embedded awk lexer (split-once char array,
#     O(1) index) instead of a per-character bash loop. The old loop was O(n^2)
#     (bash "${s:i:1}" rescans from the start), so a large command exceeded this
#     hook's 2s timeout; a timed-out PreToolUse hook is KILLED and FAILS OPEN, so
#     the catastrophic-rm guard was silently disabled on big commands. Now linear
#     on BSD awk / gawk / mawk.
#   - rm detection scans EVERY command segment (a benign leading rm no longer
#     hides a later catastrophic one), splits at ; && || | & and newlines and
#     standalone ( ) { } groups (quote/comment aware), and follows shell -c
#     payloads (bash/sh/zsh -c '...') and env -S strings.
#   - Defensive fail-safe caps (never fail open): a command-byte cap and an
#     rm-segment cap route oversized/over-segmented input to a cheap linear
#     regex classification that DENYs catastrophic and ASKs the unclassifiable.
#
# Known limitations (a static text guard cannot prove these; out of scope):
#   - Fully dynamic execution where rm is not literally present as a command
#     word, such as eval "$var" or a command assembled from runtime data.
#   - The raw analyzer does not decode ANSI-C command words such as $'rm'; the
#     Pi guard's reveal-only probe mitigates direct and executor-operand forms.
#   - Commands larger than the byte cap, or with more rm operands/segments than
#     the count caps, fall back to a cheap regex classifier (fail-safe DENY/ASK).
#
# Features:
#   - Detects rm -rf anywhere in command (not just at start)
#   - Handles compound commands (;, &&, ||) - warns to split
#   - Handles prefixes: sudo, env, /bin/rm, /usr/bin/rm, \rm
#   - Parses rm operands properly (handles -rf, -fr, -r -f, --, quotes)
#   - Canonicalizes paths (resolves symlinks, ./.., ~)
#   - Auto-allows rm -rf under safe roots (repo, /tmp) - warns on exact match
#   - Hard-denies catastrophic targets (/, ~, /Users, /System, etc.)
#   - Warns on shell expansion ($, *, ?, {})
#   - Validates user-configured safe roots (rejects overly broad ones)
#   - Scoped overrides via environment variables
#
# v3.5 security pattern improvements:
#   - Recursive chmod/chown on protected roots: blocks any mode (777, a+w, 666),
#     any flag order (chmod -R 777 /var, chmod 777 -R /var), handles --
#   - find -delete blocks system dirs INCLUDING subdirs (/var/log, ~/Documents)
#   - /opt moved to WARN tier (Homebrew/MacPorts use case)
#   - ERE-compatible syntax throughout (no PCRE \b word boundaries)
#   - curl/wget|sh requires explicit shell (sh|bash|zsh|dash)
#   - Network script download warns only on -o/-O/--output or redirects

SECURITY_LOG="${HOME:-/tmp}/.pi/agent/security-events.log"

log_security_event() {
    local level="$1" pattern="$2" cmd="$3"
    mkdir -p "$(dirname "$SECURITY_LOG")" 2>/dev/null || true
    # Full command text is a secret-retention surface; create the log 0600 so it
    # is never world-readable even momentarily. Create under umask 077 (in a
    # subshell so the caller's umask is untouched) rather than create-then-chmod,
    # which would leave a 0644 window under the default umask; chmod after as a
    # defensive backstop for a pre-existing 0644 file.
    [ -e "$SECURITY_LOG" ] || ( umask 077; : >> "$SECURITY_LOG" ) 2>/dev/null || true
    chmod 0600 "$SECURITY_LOG" 2>/dev/null || true
    { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $level | Pattern: $pattern | Command: $cmd" >> "$SECURITY_LOG"; } 2>/dev/null || true
}

# =============================================================================
# CONFIGURATION
# =============================================================================

# THESE VARIABLES ONLY APPLY WHEN THIS SCRIPT IS RUN DIRECTLY as a standalone
# hook. Under pi-sandbox-guard they do nothing: the guard builds the analyzer's
# environment from an allow-list (ALLOWED_POLICY_KEYS in src/guard-core.mjs) and
# lists the disarm keys below explicitly as dropped, so a project .envrc, shell
# profile, or npm script cannot weaken the analyzer. The guard's equivalent of the
# safe-roots knob is POLICY_RM_SAFE_ROOTS, set in the HOST environment; there is
# no guard equivalent of the scoped overrides, by design.

# User-configurable additional safe roots (colon-separated)
# Example: CLAUDE_RM_SAFE_ROOTS="/Users/me/scratch:/data/temp"
# NOTE: Overly broad roots (/, /Users, $HOME) are rejected for safety
ADDITIONAL_SAFE_ROOTS="${CLAUDE_RM_SAFE_ROOTS:-}"

# Scoped override: requires both flag AND scope. Standalone use only (see above).
#   CLAUDE_ALLOW_RM_RF=1 CLAUDE_ALLOW_RM_RF_SCOPE=expansion - allow shell expansion
#   CLAUDE_ALLOW_RM_RF=1 CLAUDE_ALLOW_RM_RF_SCOPE=all       - allow outside safe roots
#   CLAUDE_ALLOW_RM_RF=1 CLAUDE_ALLOW_RM_RF_SCOPE=compound  - allow compound commands
ALLOW_RM_RF="${CLAUDE_ALLOW_RM_RF:-0}"
ALLOW_RM_RF_SCOPE="${CLAUDE_ALLOW_RM_RF_SCOPE:-}"

# =============================================================================
# HELPERS
# =============================================================================

# Canonicalize path to absolute, resolving symlinks and ./..
# Returns empty string on failure
canonicalize_path() {
    local path="$1"

    # Handle empty path
    [[ -z "$path" ]] && return 1

    # Expand ~ to $HOME
    path="${path/#\~/$HOME}"

    # Robust canonicalization that also handles NON-EXISTENT paths. BSD realpath
    # cannot: macOS has no `realpath -m` and it exits 1 on a missing path.
    #
    # Preferred interpreter is "$GUARD_NODE" — an ABSOLUTE node path exported by
    # the Node guard (process.execPath). Absolute, so it cannot be shadowed, and
    # it is always present when the guard is the caller (node is running it).
    # Falls back to python3 for STANDALONE use (e.g. as a Claude Code hook), where
    # GUARD_NODE is unset. Both implementations have identical semantics.
    if [[ -n "${GUARD_NODE:-}" && -x "${GUARD_NODE:-}" ]]; then
        "$GUARD_NODE" -e '
const fs = require("fs"), path = require("path");
const p = process.argv[1];
try {
  if (fs.existsSync(p)) process.stdout.write(fs.realpathSync(p) + "\n");
  else {
    const parent = path.dirname(p) || ".";
    const base = path.basename(p);
    if (fs.existsSync(parent)) process.stdout.write(path.join(fs.realpathSync(parent), base) + "\n");
    else process.stdout.write(path.resolve(p) + "\n");
  }
} catch (e) { process.exit(1); }
' "$path" 2>/dev/null
        return $?
    fi

    if command -v python3 >/dev/null 2>&1; then
        python3 -c "
import os, sys
p = sys.argv[1]
# For non-existent paths, normalize what we can
if os.path.exists(p):
    print(os.path.realpath(p))
else:
    # Resolve parent, then append basename
    parent = os.path.dirname(p) or '.'
    base = os.path.basename(p)
    if os.path.exists(parent):
        print(os.path.join(os.path.realpath(parent), base))
    else:
        # Best effort: just normalize
        print(os.path.normpath(os.path.abspath(p)))
" "$path" 2>/dev/null
        return $?
    fi

    # Fallback: use realpath if available
    if command -v realpath >/dev/null 2>&1; then
        realpath -m "$path" 2>/dev/null
        return $?
    fi

    # Very basic fallback (no symlink resolution)
    if [[ "$path" = /* ]]; then
        echo "$path"
    else
        echo "$(pwd)/$path"
    fi
}

# Get git repo root (empty if not in a repo). Memoized: the value cannot change
# within a single hook invocation, but get_safe_roots was calling this (a git
# subprocess) once PER rm operand, which dominated cost on multi-target commands.
_NOSYNC_REPO_ROOT_CACHED=""
_NOSYNC_REPO_ROOT_DONE=0
get_repo_root() {
    if [[ "$_NOSYNC_REPO_ROOT_DONE" -eq 0 ]]; then
        _NOSYNC_REPO_ROOT_CACHED="$(git rev-parse --show-toplevel 2>/dev/null || echo "")"
        _NOSYNC_REPO_ROOT_DONE=1
    fi
    printf '%s\n' "$_NOSYNC_REPO_ROOT_CACHED"
}

# Canonicalized $HOME. Memoized for the same reason: is_catastrophic and
# is_overly_broad_root each canonicalized $HOME (a python3 subprocess) on every
# call, i.e. once per operand.
_NOSYNC_HOME_CANON_CACHED=""
_NOSYNC_HOME_CANON_DONE=0
home_canonical() {
    if [[ "$_NOSYNC_HOME_CANON_DONE" -eq 0 ]]; then
        _NOSYNC_HOME_CANON_CACHED="$(canonicalize_path "$HOME")"
        _NOSYNC_HOME_CANON_DONE=1
    fi
    printf '%s\n' "$_NOSYNC_HOME_CANON_CACHED"
}

# Check if path is strictly under a given root (not equal to it)
is_strictly_under_root() {
    local path="$1" root="$2"
    [[ -z "$root" ]] && return 1
    [[ "$path" == "$root"/* ]]
}

# Check if path is under or equal to a given root
is_under_or_equal_root() {
    local path="$1" root="$2"
    [[ -z "$root" ]] && return 1
    [[ "$path" == "$root" || "$path" == "$root"/* ]]
}

# Check if operand contains shell expansion characters
has_shell_expansion() {
    local operand="$1"
    # Check for $VAR, ${VAR}, $(cmd), `cmd`, *, ?, [, {
    [[ "$operand" =~ [\$\`\*\?\[\{] ]] || [[ "$operand" =~ \$\( ]]
}

# Check if command contains compound operators
is_compound_command() {
    local cmd="$1"
    # A command is "compound" (i.e. contains more than one simple command, so we
    # must validate every segment, not just the first) if it contains any shell
    # command separator: ; | & (covers && || |&) OR a newline. Newline and a bare
    # & are real separators too -- the segmenter (extract_all_rm_segments) splits
    # on them, so is_compound_command must agree or a catastrophic rm in a later
    # statement (e.g. "rm -rf /tmp/ok\nrm -rf /") would never be validated.
    case "$cmd" in
        *";"* | *"|"* | *"&"* ) return 0 ;;
    esac
    # Literal newline. NOTE: must use $'\n' (ANSI-C), NOT "$(printf '\n')" --
    # command substitution strips trailing newlines, yielding the empty string,
    # which made the pattern *""* match EVERY command (is_compound_command was
    # unconditionally true). The independent segmenter masked it, but the predicate
    # was meaningless; this restores the intended newline detection.
    case "$cmd" in
        *$'\n'* ) return 0 ;;
    esac
    return 1
}

# Extract the rm portion from a compound command for analysis (first match only)
extract_rm_segment() {
    local cmd="$1"
    extract_all_rm_segments "$cmd" | head -1
}

# Split a command into command segments at the shell control operators
# (; && || | |& & and newlines), RESPECTING quotes / backslash escapes /
# comments so an operator inside a quoted string or comment does not split.
# Implemented in awk for linear performance and correct quote handling; the old
# sed approach split blindly and also failed to isolate operators written
# without surrounding spaces (e.g. "echo hi;rm -rf /" -- the ; -separated
# catastrophic rm was missed). One segment per output line.
# shellcheck disable=SC2016 # awk program, not a shell string to expand
SEGMENT_AWK='
function flush_seg(   t) { t = seg; sub(/^[ \t]+/, "", t); if (t != "") print t; seg = "" }
BEGIN { RS = "\0" }
{
  nch = split($0, CH, "")
  seg = ""; q = ""; i = 1
  while (i <= nch) {
    c = CH[i]
    if (q != "") { seg = seg c; if (c == q) q = ""; i++; continue }
    if (c == "\\") { seg = seg c; if (i < nch) { seg = seg CH[i+1]; i += 2 } else i++; continue }
    if (c == "\047" || c == "\042") { q = c; seg = seg c; i++; continue }
    if (c == "#" && (seg == "" || seg ~ /[ \t]$/)) {
      # comment ends at the next newline (which also ends the segment), not EOF.
      flush_seg()
      while (i <= nch && CH[i] != "\n") i++
      continue
    }
    if (c == "\n") { flush_seg(); i++; continue }
    if (c == ";") { flush_seg(); if (i < nch && CH[i+1] == ";") i += 2; else i++; continue }
    if (c == "&") {
      if (i < nch && CH[i+1] == "&") { flush_seg(); i += 2; continue }
      if (i < nch && CH[i+1] == ">") { seg = seg "&>"; i += 2; continue }
      flush_seg(); print "__NOSYNC_CWD_RESET__"; i++; continue
    }
    # A clobber redirect ">|" is NOT a pipe: the "|" belongs to the redirection,
    # so keep both in the segment (otherwise "rm>|out -rf /" splits at the | and
    # the catastrophic rm is never validated).
    if (c == ">" && i < nch && CH[i+1] == "|") { seg = seg ">|"; i += 2; continue }
    if (c == "|") {
      if (i < nch && CH[i+1] == "|") { flush_seg(); i += 2; continue }
      if (i < nch && CH[i+1] == "&") { flush_seg(); print "__NOSYNC_CWD_RESET__"; i += 2; continue }
      flush_seg(); print "__NOSYNC_CWD_RESET__"; i++; continue
    }
    if (c == "(") { flush_seg(); print "__NOSYNC_SUBSHELL_OPEN__"; i++; continue }
    if (c == ")") { flush_seg(); print "__NOSYNC_SUBSHELL_CLOSE__"; i++; continue }
    # Braces split only when standalone (reserved-word group), NOT when embedded
    # in a word (brace expansion like /tmp/x{a,b} must stay intact so the operand
    # is validated whole).
    if (c == "{" && seg ~ /(^|[ \t])$/) {
      nxt = (i < nch) ? CH[i+1] : ""
      if (nxt == "" || nxt == " " || nxt == "\t") { flush_seg(); print "__NOSYNC_GROUP_OPEN__"; i++; continue }
    }
    if (c == "}" && seg ~ /(^|[ \t])$/) { flush_seg(); print "__NOSYNC_GROUP_CLOSE__"; i++; continue }
    seg = seg c; i++
  }
  flush_seg()
}'

# Extract ALL rm segments from a (possibly compound) command, one per line.
# Each segment is run through normalize_rm_command so that quoted/escaped/env -S
# spellings of rm (r\m, r"m", env -S 'rm -rf /') are recognized the SAME way as
# in a single command -- the old raw grep only matched a literal "rm" token and
# missed those in compound commands (e.g. "rm -rf /ok && r\m -rf /"). A segment
# that normalizes to an rm command carrying -r/-f flags is emitted.
# Hard cap on the number of rm-bearing segments we will normalize+validate in a
# single command. Each full validation costs awk + a path-canonicalization
# subprocess per operand (~250ms), and a timed-out hook fails OPEN, so beyond the
# cap we stop and let the caller treat the command as unclassifiable (fail-safe
# ASK). A realistic compound command has at most a handful of rm segments; the
# cap keeps total validation well under the 2s hook timeout.
NOSYNC_MAX_RM_SEGMENTS="${CLAUDE_BASH_GUARD_MAX_RM_SEGMENTS:-4}"

# Emits one normalized rm segment per line. If more than NOSYNC_MAX_RM_SEGMENTS
# rm-bearing segments are found, it stops and emits a final sentinel line
# "<<NOSYNC_TRUNCATED>>" so the caller (which reads this via a subshell, where a
# plain variable would not propagate) knows it did NOT see every segment and must
# fail safe rather than allow.
extract_all_rm_segments() {
    local cmd="$1"
    local seg norm probe emitted=0
    while IFS= read -r seg; do
        [[ -z "$seg" ]] && continue
        # Cheap pre-filter: skip the normalize subprocess unless this segment can
        # possibly contain an rm token (quotes/backslashes can form it).
        probe="${seg//\\/}"; probe="${probe//\"/}"; probe="${probe//\'/}"
        case "$probe" in *rm*) : ;; *) continue ;; esac
        norm="$(normalize_rm_command "$seg")"
        case "$norm" in
            rm" "*|rm)
                if segment_has_rf_flags "$norm"; then
                    if [[ $emitted -ge $NOSYNC_MAX_RM_SEGMENTS ]]; then
                        printf '%s\n' "<<NOSYNC_TRUNCATED>>"
                        return
                    fi
                    printf '%s\n' "$norm"
                    ((emitted++))
                fi
                ;;
        esac
    done < <(printf '%s' "$cmd" | awk "$SEGMENT_AWK")
}

# =============================================================================
# CATASTROPHIC DENY LIST
# =============================================================================

# These paths are NEVER allowed as rm -rf targets
CATASTROPHIC_ROOTS=(
    "/"
    "/Users"
    "/System"
    "/Library"
    "/Applications"
    "/bin"
    "/sbin"
    "/usr"
    "/etc"
    "/var"
    "/opt"
    "/boot"
    "/proc"
    "/sys"
    "/private"
    "/cores"
    "/dev"
)

is_catastrophic() {
    local canonical="$1"

    # Empty or failed canonicalization
    [[ -z "$canonical" ]] && return 0

    # Check $HOME separately (expands at runtime)
    local hc
    hc=$(home_canonical)
    if [[ "$canonical" == "$hc" ]]; then
        return 0  # Is catastrophic
    fi

    # Direct match against catastrophic roots
    for root in "${CATASTROPHIC_ROOTS[@]}"; do
        if [[ "$canonical" == "$root" ]]; then
            return 0  # Is catastrophic
        fi
    done

    # Deny direct children of / except known-safe ones
    if [[ "$canonical" =~ ^/[^/]+$ ]]; then
        case "$canonical" in
            /tmp|/private) return 1 ;;  # These are okay as targets
            *) return 0 ;;  # Deny /anything-else at root level
        esac
    fi

    return 1  # Not catastrophic
}

# Check if a path is too broad to be a safe root
is_overly_broad_root() {
    local path="$1"
    local canonical
    canonical=$(canonicalize_path "$path")

    # Reject these as safe roots
    case "$canonical" in
        /|/Users|/System|/Library|/Applications|/bin|/sbin|/usr|/etc|/var|/opt|/private)
            return 0  # Too broad
            ;;
    esac

    # Reject $HOME as safe root
    local hc
    hc=$(home_canonical)
    if [[ "$canonical" == "$hc" ]]; then
        return 0  # Too broad
    fi

    return 1  # Acceptable
}

# =============================================================================
# SAFE ROOTS
# =============================================================================

get_safe_roots() {
    local roots=()

    # Always safe: temp directories
    roots+=("/tmp")
    roots+=("/private/tmp")

    # macOS per-user temp (typically /var/folders/xx/xxx/)
    if [[ -d "/var/folders" ]]; then
        roots+=("/var/folders")
    fi

    # Current git repo root (if in one)
    local repo_root
    repo_root=$(get_repo_root)
    if [[ -n "$repo_root" ]]; then
        roots+=("$repo_root")
    fi

    # User-configured additional roots (validated)
    if [[ -n "$ADDITIONAL_SAFE_ROOTS" ]]; then
        IFS=':' read -ra extra <<< "$ADDITIONAL_SAFE_ROOTS"
        for r in "${extra[@]}"; do
            if [[ -n "$r" ]]; then
                # Validate: reject overly broad roots
                if is_overly_broad_root "$r"; then
                    echo "⚠️  Ignoring overly broad safe root: $r" >&2
                else
                    roots+=("$r")
                fi
            fi
        done
    fi

    printf '%s\n' "${roots[@]}"
}

# Canonicalized safe roots, computed ONCE. The previous code canonicalized every
# safe root (each a python3 subprocess) on every check_safe_root_status call, i.e.
# (#roots) subprocesses PER rm operand -- the dominant cost behind the per-operand
# timeout fail-open. Cache holds newline-joined "canonical<TAB>original" pairs.
_NOSYNC_SAFE_ROOTS_CANON=""
_NOSYNC_SAFE_ROOTS_DONE=0
build_safe_roots_canon() {
    [[ "$_NOSYNC_SAFE_ROOTS_DONE" -eq 1 ]] && return
    local root rc out=""
    while IFS= read -r root; do
        [[ -z "$root" ]] && continue
        rc=$(canonicalize_path "$root")
        out+="${rc}	${root}"$'\n'
    done < <(get_safe_roots)
    _NOSYNC_SAFE_ROOTS_CANON="$out"
    _NOSYNC_SAFE_ROOTS_DONE=1
}

# Check if path is safe (under a safe root, not the root itself)
# Returns: 0=strictly under, 1=equals safe root (warn), 2=outside
check_safe_root_status() {
    local canonical="$1"

    [[ -z "$canonical" ]] && echo "outside" && return

    build_safe_roots_canon
    local line root_canonical root
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        root_canonical="${line%%	*}"
        root="${line#*	}"

        if [[ "$canonical" == "$root_canonical" ]]; then
            echo "equals_root:$root"
            return
        fi

        if is_strictly_under_root "$canonical" "$root_canonical"; then
            echo "under"
            return
        fi
    done <<< "$_NOSYNC_SAFE_ROOTS_CANON"

    echo "outside"
}

# =============================================================================
# RM COMMAND PARSER
# =============================================================================

# Tokenize a shell-like command into tokens, handling quotes and backslash
# escapes. This is not a full shell parser, but is good enough for our safety
# checks. One token per output line.
#
# Implemented as an embedded awk program rather than a per-character bash loop:
# bash string slicing ("${cmd:$i:1}") is O(n) per access, so a per-char loop is
# O(n^2) and a large command made this hook exceed its 2s timeout -- and a
# timed-out PreToolUse hook is KILLED by Claude Code and falls back to the normal
# permission path, i.e. the catastrophic-command guard FAILS OPEN. awk splits the
# input into a char array ONCE (C-level) and indexes it O(1), so the scan is
# linear on BSD awk / gawk / mawk. The command is fed on STDIN (no ARG_MAX limit)
# and awk only does string ops -- it never evaluates the command text.
#
# This tokenizer ALSO emits shell command separators (; && || | |& &) as their
# own tokens, so normalize_rm_command finds command boundaries even when an
# operator is written without surrounding spaces (e.g. "x&&rm -rf /", "a;rm").
# The old whitespace-only tokenizer kept "x&&rm" as one token and missed those.
# shellcheck disable=SC2016 # awk program, not a shell string to expand
TOKENIZE_AWK='
function emitw(   ) { if (have) { print word; word=""; have=0 } }
function emito(op) { emitw(); print op }
BEGIN { RS = "\0" }
{
  nch = split($0, CH, "")
  word = ""; have = 0; q = ""; i = 1
  while (i <= nch) {
    c = CH[i]
    if (q != "") {
      # Inside double quotes, bash only treats backslash as an escape before
      # $, `, ", \, or newline. Preserve other backslashes literally. Single
      # quotes have no backslash escapes at all.
      if (q == "\042" && c == "\\") {
        nx = (i < nch) ? CH[i+1] : ""
        if (nx == "$" || nx == "`" || nx == "\042" || nx == "\\") {
          word = word nx; have = 1; i += 2; continue
        }
        if (nx == "\n") { i += 2; continue }
        word = word c; have = 1; i++; continue
      }
      if (c == q) q = ""; else { word = word c; have = 1 }
      i++; continue
    }
    if (c == "\\") {
      if (i < nch) { word = word CH[i+1]; have = 1; i += 2 } else i++
      continue
    }
    if (c == "\047" || c == "\042") { q = c; have = 1; i++; continue }
    if (c == " " || c == "\t" || c == "\r") { emitw(); i++; continue }
    if (c == "\n") { emito(";"); i++; continue }
    if (c == "#" && have == 0) {
      # a # at a word boundary starts a comment that ends at the NEXT newline,
      # not end-of-input -- skip to the newline so later lines are still scanned.
      while (i <= nch && CH[i] != "\n") i++
      continue
    }
    if (c == ";") { emito(";"); if (i < nch && CH[i+1] == ";") i += 2; else i++; continue }
    if (c == "&") {
      if (i < nch && CH[i+1] == "&") { emito("&&"); i += 2; continue }
      # "&>" / "&>>" output redirect: emit any preceding command word FIRST (so
      # "rm&>log" yields the command word "rm", not a fused "rm&>log" that hides
      # the rm), then emit the redirect operator as its own token.
      if (i < nch && CH[i+1] == ">") {
        emitw()
        if (i+1 < nch && CH[i+2] == ">") { print "&>>"; i += 3 } else { print "&>"; i += 2 }
        continue
      }
      emito("&"); i++; continue
    }
    if (c == "|") {
      if (i < nch && CH[i+1] == "|") { emito("||"); i += 2; continue }
      if (i < nch && CH[i+1] == "&") { emito("|&"); i += 2; continue }
      emito("|"); i++; continue
    }
    # Redirection operators (> >> >| < << <<< <>), possibly FUSED to a preceding
    # command word ("rm>log") and/or carrying a leading fd number ("2>log",
    # "rm2>log"). The shell treats these as syntax anywhere in a simple command,
    # so a fused redirect must NOT hide the command word. Split: pull trailing
    # digits off the current word as the fd, emit the remaining command word as
    # its own token, then emit the operator (fd + operator chars) as a separate
    # token. The target becomes the next token naturally. ("&>" is handled in the
    # "&" branch above and intentionally left attached.)
    if (c == ">" || c == "<") {
      fd = ""
      while (length(word) > 0 && substr(word, length(word), 1) ~ /[0-9]/) {
        fd = substr(word, length(word), 1) fd
        word = substr(word, 1, length(word) - 1)
      }
      # bash named-fd redirect: a "{name}" immediately before the operator is an
      # fd-name prefix, NOT a command word ("{fd}>log rm -rf /" runs rm). If the
      # remaining word is exactly {identifier}, drop it (treat like an fd number)
      # so it does not become a spurious command word that hides the rm.
      if (word ~ /^\{[A-Za-z_][A-Za-z0-9_]*\}$/) { word = "" }
      if (word != "") print word
      word = ""; have = 0
      op = fd c
      if (c == ">" && i < nch && CH[i+1] == ">") { op = fd ">>"; i++ }
      else if (c == ">" && i < nch && CH[i+1] == "|") { op = fd ">|"; i++ }
      else if (c == "<" && i < nch && CH[i+1] == "<") {
        op = fd "<<"; i++
        if (i < nch && CH[i+1] == "<") { op = fd "<<<"; i++ }
      }
      else if (c == "<" && i < nch && CH[i+1] == ">") { op = fd "<>"; i++ }
      # fd-dup form: >&N, <&N, >&-, <&- (e.g. "rm>&2", "rm 2>&-", "rm <&0"). The
      # "&" and the following fd digits / "-" belong to the redirect operator, NOT
      # to a separate "&" separator (which would truncate the rm reconstruction).
      if (i < nch && CH[i+1] == "&") {
        op = op "&"; i++
        while (i < nch && (CH[i+1] ~ /[0-9]/ || CH[i+1] == "-")) { op = op CH[i+1]; i++ }
      }
      print op
      i++
      continue
    }
    # Subshell parens are always shell metacharacters (a(b is a syntax error),
    # so they always break a token and mark a command boundary.
    if (c == "(" || c == ")") { emito(c); i++; continue }
    # Braces are reserved words ONLY when standalone-delimited ({ at a word start
    # followed by whitespace, or } as its own token). Embedded braces are brace
    # EXPANSION and must stay in the word so has_shell_expansion can force ASK
    # (e.g. rm -rf /tmp/x{,/../../Users} expands to a catastrophic second path).
    if (c == "{" && have == 0) {
      nx = (i < nch) ? CH[i+1] : ""
      if (nx == "" || nx == " " || nx == "\t" || nx == "\r" || nx == "\n") { emito("{"); i++; continue }
    }
    if (c == "}") {
      # closing brace counts as a boundary only when it ends a token (next is a
      # separator/space/EOL); embedded } stays in the word.
      nx = (i < nch) ? CH[i+1] : ""
      if (have == 0 || nx == "" || nx == " " || nx == "\t" || nx == "\r" || nx == "\n" || nx == ";") {
        if (have == 0) { emito("}"); i++; continue }
      }
    }
    word = word c
    have = 1
    i++
  }
  emitw()
}'

tokenize_command() {
    printf '%s' "$1" | awk "$TOKENIZE_AWK"
}

# Preserve dollars that shell quoting makes literal before using the general
# lexer for parameter-fallback path analysis. The general lexer intentionally
# removes quotes, so without this marker `'\${x:-/etc}'` and `${x:-/etc}` would
# become indistinguishable. Double-quoted unescaped dollars remain active.
PROTECT_LITERAL_PARAMETER_DOLLARS_AWK='
function literal_marker(c) {
  if (c == "$") return "__NOSYNC_LITERAL_DOLLAR__"
  if (c == "~") return "__NOSYNC_LITERAL_TILDE__"
  if (c == "*") return "__NOSYNC_LITERAL_STAR__"
  if (c == "?") return "__NOSYNC_LITERAL_QUESTION__"
  if (c == "[") return "__NOSYNC_LITERAL_BRACKET__"
  if (c == "{") return "__NOSYNC_LITERAL_BRACE__"
  return c
}
BEGIN { RS = "\0" }
{
  s = $0; n = length(s); i = 1; q = ""; out = ""
  while (i <= n) {
    c = substr(s, i, 1)
    if (q == "\047") {
      if (c == "\047") { q = ""; out = out c }
      else out = out literal_marker(c)
      i++; continue
    }
    if (q == "\042") {
      if (c == "\042") { q = ""; out = out c; i++; continue }
      if (c == "\\" && index("$~*?[{", substr(s, i+1, 1)) != 0) {
        out = out literal_marker(substr(s, i+1, 1)); i += 2; continue
      }
      if (c == "{" && substr(s, i-1, 1) == "$") out = out c
      else if (index("~*?[{", c) != 0) out = out literal_marker(c)
      else out = out c
      i++; continue
    }
    if (c == "\047" || c == "\042") { q = c; out = out c; i++; continue }
    if (c == "\\" && index("$~*?[{", substr(s, i+1, 1)) != 0) {
      out = out literal_marker(substr(s, i+1, 1)); i += 2; continue
    }
    out = out c; i++
  }
  printf "%s", out
}'
protect_literal_parameter_dollars() { printf '%s' "$1" | awk "$PROTECT_LITERAL_PARAMETER_DOLLARS_AWK"; }

# True when a shell short-option cluster enables command-string mode. Bash/sh
# accept `-cl` / `-ce` as well as `-c`; long options such as `--norc` do not.
shell_short_options_have_c() {
    case "$1" in
        --*|+*) return 1 ;;
        -?*) [[ "${1#-}" == *c* ]] ;;
        *) return 1 ;;
    esac
}

# Locate the real command word after common execution wrappers. Callers assign
# the token array to _scan_tokens, then inspect _wrapped_index. An index of -1
# means the wrapper is informational (`command -v/-V`) and executes no command.
wrapped_command_index() {
    local i="$1" n="$2" t b wrapper_i direct_exec
    _wrapped_index=-1
    _wrapped_cwds=()
    _wrapped_write_targets=()
    while [[ "$i" -lt "$n" ]]; do
        t="${_scan_tokens[$i]}"
        case "$t" in
            ";"|"&&"|"||"|"|"|"|&"|"&"|"("|")"|"{"|"}")
                _wrapped_index=-1
                return
                ;;
        esac
        case "$t" in
            [A-Za-z_][A-Za-z0-9_]*=*) i=$((i + 1)); continue ;;
        esac
        b="${t##*/}"
        case "$b" in
            command)
                i=$((i + 1))
                while [[ "$i" -lt "$n" ]]; do
                    t="${_scan_tokens[$i]}"
                    case "$t" in
                        --) i=$((i + 1)); break ;;
                        -?*)
                            case "${t#-}" in *v*|*V*) _wrapped_index=-1; return ;; esac
                            i=$((i + 1)); continue ;;
                        *) break ;;
                    esac
                done
                ;;
            env)
                i=$((i + 1))
                while [[ "$i" -lt "$n" ]]; do
                    t="${_scan_tokens[$i]}"
                    case "$t" in
                        -C|--chdir)
                            [[ $((i + 1)) -lt "$n" ]] && _wrapped_cwds+=("${_scan_tokens[$((i + 1))]}")
                            i=$((i + 2)); continue ;;
                        -C?*)
                            _wrapped_cwds+=("${t#-C}")
                            i=$((i + 1)); continue ;;
                        --chdir=*)
                            _wrapped_cwds+=("${t#--chdir=}")
                            i=$((i + 1)); continue ;;
                        -u|--unset|-P)
                            i=$((i + 2)); continue ;;
                        --unset=*|-*) i=$((i + 1)); continue ;;
                        [A-Za-z_][A-Za-z0-9_]*=*) i=$((i + 1)); continue ;;
                        --) i=$((i + 1)); break ;;
                        *) break ;;
                    esac
                done
                ;;
            nice)
                i=$((i + 1))
                while [[ "$i" -lt "$n" ]]; do
                    t="${_scan_tokens[$i]}"
                    case "$t" in
                        -n|--adjustment) i=$((i + 2)); continue ;;
                        -n?*|--adjustment=*|-[0-9]*) i=$((i + 1)); continue ;;
                        --) i=$((i + 1)); break ;;
                        -*) i=$((i + 1)); continue ;;
                        *) break ;;
                    esac
                done
                ;;
            timeout)
                i=$((i + 1))
                while [[ "$i" -lt "$n" ]]; do
                    t="${_scan_tokens[$i]}"
                    case "$t" in
                        -s|--signal|-k|--kill-after)
                            i=$((i + 2)); continue ;;
                        --signal=*|--kill-after=*|--preserve-status|--foreground|--verbose)
                            i=$((i + 1)); continue ;;
                        --) i=$((i + 1)); break ;;
                        -*) i=$((i + 1)); continue ;;
                        *) break ;;
                    esac
                done
                # timeout's mandatory DURATION precedes COMMAND.
                [[ "$i" -lt "$n" ]] && i=$((i + 1))
                ;;
            stdbuf)
                i=$((i + 1))
                while [[ "$i" -lt "$n" ]]; do
                    t="${_scan_tokens[$i]}"
                    case "$t" in
                        -i|-o|-e|--input|--output|--error)
                            i=$((i + 2)); continue ;;
                        -i?*|-o?*|-e?*|--input=*|--output=*|--error=*)
                            i=$((i + 1)); continue ;;
                        --) i=$((i + 1)); break ;;
                        -*) i=$((i + 1)); continue ;;
                        *) break ;;
                    esac
                done
                ;;
            flock)
                wrapper_i="$i"
                i=$((i + 1))
                while [[ "$i" -lt "$n" ]]; do
                    t="${_scan_tokens[$i]}"
                    case "$t" in
                        -w|--timeout|-E|--conflict-exit-code)
                            i=$((i + 2)); continue ;;
                        --timeout=*|--conflict-exit-code=*|-s|--shared|-x|--exclusive|-u|--unlock|-n|--nonblock|-o|--close|-F|--no-fork|--verbose)
                            i=$((i + 1)); continue ;;
                        --) i=$((i + 1)); break ;;
                        -*) i=$((i + 1)); continue ;;
                        *) break ;;
                    esac
                done
                # FILE/DIR/FD belongs to flock, not the nested command.
                [[ "$i" -lt "$n" ]] && i=$((i + 1))
                if [[ "$i" -lt "$n" ]]; then
                    case "${_scan_tokens[$i]}" in
                        -c|--command|--command=*)
                            _wrapped_index="$wrapper_i"
                            return
                            ;;
                    esac
                fi
                ;;
            chrt)
                i=$((i + 1))
                while [[ "$i" -lt "$n" ]]; do
                    t="${_scan_tokens[$i]}"
                    case "$t" in
                        -m|--max|-p|--pid|-a|--all-tasks|-v|--verbose|-b|--batch|-d|--deadline|-f|--fifo|-i|--idle|-o|--other|-r|--rr)
                            i=$((i + 1)); continue ;;
                        -T|--sched-runtime|-P|--sched-period|-D|--sched-deadline)
                            i=$((i + 2)); continue ;;
                        --*=*) i=$((i + 1)); continue ;;
                        --) i=$((i + 1)); break ;;
                        -*) i=$((i + 1)); continue ;;
                        *) break ;;
                    esac
                done
                # Non-pid mode has a PRIORITY operand before COMMAND.
                [[ "$i" -lt "$n" ]] && i=$((i + 1))
                ;;
            taskset)
                i=$((i + 1))
                while [[ "$i" -lt "$n" ]]; do
                    t="${_scan_tokens[$i]}"
                    case "$t" in
                        -a|--all-tasks|-c|--cpu-list|-p|--pid) i=$((i + 1)); continue ;;
                        --) i=$((i + 1)); break ;;
                        -*) i=$((i + 1)); continue ;;
                        *) break ;;
                    esac
                done
                # MASK/LIST precedes COMMAND in execution mode.
                [[ "$i" -lt "$n" ]] && i=$((i + 1))
                ;;
            ionice)
                i=$((i + 1))
                while [[ "$i" -lt "$n" ]]; do
                    t="${_scan_tokens[$i]}"
                    case "$t" in
                        -c|--class|-n|--classdata|-t|--ignore|-p|--pid|-P|--pgid|-u|--uid)
                            case "$t" in -t|--ignore) i=$((i + 1)) ;; *) i=$((i + 2)) ;; esac
                            continue ;;
                        --*=*) i=$((i + 1)); continue ;;
                        --) i=$((i + 1)); break ;;
                        -*) i=$((i + 1)); continue ;;
                        *) break ;;
                    esac
                done
                ;;
            watch)
                wrapper_i="$i"
                direct_exec=0
                i=$((i + 1))
                while [[ "$i" -lt "$n" ]]; do
                    t="${_scan_tokens[$i]}"
                    case "$t" in
                        -n|--interval) i=$((i + 2)); continue ;;
                        --interval=*|-n?*) i=$((i + 1)); continue ;;
                        -x|--exec) direct_exec=1; i=$((i + 1)); continue ;;
                        --) i=$((i + 1)); break ;;
                        -*) i=$((i + 1)); continue ;;
                        *) break ;;
                    esac
                done
                if [[ "$direct_exec" -eq 0 ]]; then
                    _wrapped_index="$wrapper_i"
                    return
                fi
                ;;
            arch)
                i=$((i + 1))
                while [[ "$i" -lt "$n" ]]; do
                    t="${_scan_tokens[$i]}"
                    case "$t" in
                        -arch) i=$((i + 2)); continue ;;
                        --) i=$((i + 1)); break ;;
                        -*) i=$((i + 1)); continue ;;
                        *) break ;;
                    esac
                done
                ;;
            catchsegv|busybox)
                i=$((i + 1))
                ;;
            sudo|doas)
                i=$((i + 1))
                while [[ "$i" -lt "$n" ]]; do
                    t="${_scan_tokens[$i]}"
                    case "$t" in
                        -u|-g|-h|-p|-C|-T|-R|-r|-t|--user|--group|--host|--prompt|--chdir)
                            i=$((i + 2)); continue ;;
                        --*=*|-*) i=$((i + 1)); continue ;;
                        --) i=$((i + 1)); break ;;
                        *) break ;;
                    esac
                done
                ;;
            exec)
                i=$((i + 1))
                while [[ "$i" -lt "$n" ]]; do
                    t="${_scan_tokens[$i]}"
                    case "$t" in
                        -a) i=$((i + 2)); continue ;;
                        -c|-l) i=$((i + 1)); continue ;;
                        --) i=$((i + 1)); break ;;
                        *) break ;;
                    esac
                done
                ;;
            time)
                i=$((i + 1))
                while [[ "$i" -lt "$n" ]]; do
                    t="${_scan_tokens[$i]}"
                    case "$t" in
                        -o|--output)
                            [[ $((i + 1)) -lt "$n" ]] && _wrapped_write_targets+=("${_scan_tokens[$((i + 1))]}")
                            i=$((i + 2)); continue ;;
                        --output=*)
                            _wrapped_write_targets+=("${t#--output=}")
                            i=$((i + 1)); continue ;;
                        -f|--format) i=$((i + 2)); continue ;;
                        --format=*|-a|--append|-p|--portability|-v|--verbose)
                            i=$((i + 1)); continue ;;
                        --) i=$((i + 1)); break ;;
                        -*)
                            if [[ "$t" =~ ^-[ahlpqvV]*o(.+)$ ]]; then
                                _wrapped_write_targets+=("${BASH_REMATCH[1]}")
                                i=$((i + 1)); continue
                            elif [[ "$t" =~ ^-[ahlpqvV]*o$ ]]; then
                                [[ $((i + 1)) -lt "$n" ]] && _wrapped_write_targets+=("${_scan_tokens[$((i + 1))]}")
                                i=$((i + 2)); continue
                            fi
                            i=$((i + 1)); continue ;;
                        *) break ;;
                    esac
                done
                ;;
            nohup|setsid)
                i=$((i + 1))
                while [[ "$i" -lt "$n" ]]; do
                    t="${_scan_tokens[$i]}"
                    case "$t" in --) i=$((i + 1)); break ;; -*) i=$((i + 1)); continue ;; *) break ;; esac
                done
                ;;
            *)
                _wrapped_index="$i"
                return
                ;;
        esac
    done
}

# Safely quote a token for later re-parsing by our tokenizer.
quote_token() {
    local token="$1"

    if [[ -z "$token" ]]; then
        printf "''"
        return
    fi

    case "$token" in
        *[[:space:]]*|*[\$\\\`\"\'\*\?\[\]\{\}\(\)\;\|\&\<\>]*)
            token=${token//\'/\'\\\'\'}
            printf "'%s'" "$token"
            ;;
        *)
            printf "%s" "$token"
            ;;
    esac
}

# Normalize a command by locating the first rm invocation and returning a
# reconstructed string that starts at rm. This avoids needing to perfectly parse
# sudo/env prefixes (including long options).
#
# Handles: sudo ... rm, env ... rm, /bin/rm, /usr/bin/rm, \rm, command rm,
#          command -- rm, VAR=val ... rm
# Normalize an `env -S` / `--split-string` payload. The payload is a continuation
# of env's OWN argument list: leading env options and NAME=VAL assignments that
# real env consumes, then COMMAND [ARGS]. The previous code normalized the raw
# payload, so a payload that STARTS with an env option (env -S '-i rm -rf /')
# made the recursive normalize see a leading "-i" and bail, missing the rm. Strip
# the leading env options/assignments here, then normalize from the command word.
normalize_env_split_string() {
    local s="$1"
    # Bound recursion (nested env -S ...). A pathological deep nest is never
    # legitimate; fail SAFE toward DENY by emitting a single-segment root path
    # (is_catastrophic denies "/UNRESOLVED..."), never the untouched command.
    NOSYNC_ENV_DEPTH=$(( ${NOSYNC_ENV_DEPTH:-0} + 1 ))
    if [[ "$NOSYNC_ENV_DEPTH" -gt 8 ]]; then
        echo "rm -rf /UNRESOLVED_ENV_SPLIT_STRING"
        return
    fi
    local etoks=() et k n rebuilt=() m
    while IFS= read -r et; do etoks+=("$et"); done < <(tokenize_command "$s")
    k=0; n=${#etoks[@]}
    while [[ $k -lt $n ]]; do
        et="${etoks[$k]}"
        case "$et" in
            --) ((k++)); break ;;
            -S|--split-string)
                if [[ $((k+1)) -lt $n ]]; then normalize_env_split_string "${etoks[$((k+1))]}"; return; fi
                ((k++)); continue ;;
            --split-string=*) normalize_env_split_string "${et#--split-string=}"; return ;;
            # 1-argument env options (GNU/BSD): unset NAME, chdir DIR (-C), -P PATH.
            -u|--unset|-C|--chdir|-P) ((k+=2)); continue ;;
            --unset=*|--chdir=*) ((k++)); continue ;;
            # Short-option cluster containing S: chars after S are the nested split
            # string; if none, the next token is the split string.
            -[A-Za-z]*S*)
                local rest="${et#*S}"
                if [[ -n "$rest" ]]; then normalize_env_split_string "$rest"; return; fi
                if [[ $((k+1)) -lt $n ]]; then normalize_env_split_string "${etoks[$((k+1))]}"; return; fi
                ((k++)); continue ;;
            -*) ((k++)); continue ;;
            *)
                if [[ "$et" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]]; then ((k++)); continue; fi
                break ;;
        esac
    done
    if [[ $k -ge $n ]]; then echo ""; return; fi
    for ((m=k; m<n; m++)); do rebuilt+=("$(quote_token "${etoks[$m]}")"); done
    normalize_rm_command "${rebuilt[*]}"
}

normalize_rm_command() {
    local cmd="$1"

    # Cheap raw pre-filter: if the command cannot possibly contain an "rm" token,
    # skip tokenization entirely. This keeps the common case (and large non-rm
    # commands like a giant `echo`) off the tokenize + bash-array path, which
    # dominates cost at scale. Backslash escapes and quotes can FORM "rm" from
    # non-adjacent characters (r\m, r"m", 'r'm -> rm), so strip those characters
    # before the substring test; otherwise we would skip (and fail to detect) an
    # escaped/quoted rm. False positives here only cost a tokenize pass.
    local probe="${cmd//\\/}"   # drop backslashes
    probe="${probe//\"/}"       # drop double quotes
    probe="${probe//\'/}"       # drop single quotes
    case "$probe" in
        *rm*) : ;;
        *) echo "$cmd"; return ;;
    esac

    local tokens=()
    while IFS= read -r t; do
        tokens+=("$t")
    done < <(tokenize_command "$cmd")

    is_command_separator_token() {
        case "$1" in
            ";"|"&&"|"||"|"|"|"|&"|"&"|"("|")"|"{"|"}") return 0 ;;
            *) return 1 ;;
        esac
    }

    # A standalone redirection operator at the start of a command (e.g. the
    # leading "2>" in "2>/tmp/log rm -rf /", or "9>log") and its target must be
    # skipped so we still find the real command word. fd-agnostic: any leading fd
    # number, the &> forms, and the >&N / <&N fd-dup forms are all redirects.
    is_redirect_op_token() {
        case "$1" in
            # &>, &>>
            "&>"|"&>>") return 0 ;;
            # optional fd number + operator (> >> >| < << <<< <> ), incl >&N / <&N dup
            [0-9]*">"*|[0-9]*"<"*|">"*|"<"*) return 0 ;;
            *) return 1 ;;
        esac
    }

    is_rm_token() {
        case "$1" in
            rm|/bin/rm|/usr/bin/rm) return 0 ;;
            # Any absolute or relative path whose basename is exactly "rm"
            # (e.g. /opt/homebrew/bin/rm, /usr/local/bin/rm, ./rm, bin/rm). The
            # earlier list only covered the two canonical locations, so a
            # Homebrew/MacPorts rm bypassed detection.
            */rm) return 0 ;;
            *) return 1 ;;
        esac
    }

    # Shell reserved words that INTRODUCE another command: a command word can
    # follow them, so they keep us at a command boundary (e.g. the "rm" in
    # "if true; then rm -rf /; fi" follows the reserved word "then").
    is_reserved_word_token() {
        case "$1" in
            if|then|elif|else|while|until|do|"!"|time|"{"|"("|fi|done|"}"|")") return 0 ;;
            *) return 1 ;;
        esac
    }

    local at_boundary=true
    local i=0
    while [[ $i -lt ${#tokens[@]} ]]; do
        local tok="${tokens[$i]}"

        if is_command_separator_token "$tok"; then
            at_boundary=true
            ((i++))
            continue
        fi

        # At a boundary, a reserved word that introduces a command keeps us at the
        # boundary so the following command word is still inspected.
        if [[ "$at_boundary" == true ]] && is_reserved_word_token "$tok"; then
            ((i++))
            continue
        fi

        if [[ "$at_boundary" != true ]]; then
            ((i++))
            continue
        fi

        # At start of command segment: allow wrappers (sudo/env/command),
        # assignments, and leading redirections, then look for rm as the invoked
        # command.
        local j=$i

        # Skip leading assignments (FOO=bar) and leading redirections
        # (2>/tmp/log rm ..., FOO=1 2>/dev/null rm ...). A standalone redirect
        # operator also consumes its following target token.
        local advanced=true
        while [[ "$advanced" == true ]]; do
            advanced=false
            while [[ $j -lt ${#tokens[@]} && "${tokens[$j]}" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]]; do
                ((j++)); advanced=true
            done
            if [[ $j -lt ${#tokens[@]} ]] && is_redirect_op_token "${tokens[$j]}"; then
                local _rop="${tokens[$j]}"
                ((j++)); advanced=true
                # consume the redirect target ONLY for a bare operator (> , 2> );
                # an fd-dup or fused-target op (>&2, 2>&-, 2>/dev/null) already
                # carries its target, so consuming the NEXT token would wrongly eat
                # the command word (the rm).
                case "$_rop" in
                    *"&"*|*"/"*) : ;;   # fused dup/target: nothing more to skip
                    *)
                        if [[ $j -lt ${#tokens[@]} ]] && ! is_command_separator_token "${tokens[$j]}"; then
                            ((j++))
                        fi ;;
                esac
            elif [[ $j -lt ${#tokens[@]} && "${tokens[$j]}" =~ ^(\&|[0-9]+)?(\>\>?|\<)[^[:space:]]+$ ]]; then
                # inline redirect with attached target where the operator is at the
                # START of the token (optionally after an fd number or &): e.g.
                # 2>/tmp/log, >file, &>/dev/null, <in. A token like "rm>log" or
                # "foo>out" has a COMMAND WORD before the operator and must NOT be
                # treated as a pure redirection (that command still runs).
                ((j++)); advanced=true
            fi
        done

        # Locate the rm invocation at this command boundary, SEEING THROUGH command
        # wrapper chains. After three adversarial review rounds proved that
        # per-wrapper option-arity parsing is structurally unmaintainable -- each
        # round found another wrapper or option spelling that desynced the parse
        # and FAILED OPEN -- this is a STRUCTURAL FORWARD SCAN that fails safe:
        # once the leading word is a known command-runner wrapper, walk forward
        # through this one simple command (stopping at the next separator) and the
        # first rm command word found IS the wrapped rm, regardless of how many
        # options/arguments the wrapper(s) consumed. An unknown option arity can no
        # longer hide the rm. Trade-off: an unusual benign command that merely
        # NAMES rm as a later argv word after a wrapper (e.g. "timeout 5 echo rm
        # -rf x") may be conservatively flagged -- the SAFE direction for a
        # catastrophic-delete guard. Special forms that turn the command into a
        # STRING (shell -c, env -S) are handled explicitly during the scan.
        #
        # Known command-runner wrappers, by BASENAME (so /usr/bin/env etc. count):
        #   sudo doas env command exec nice nohup setsid stdbuf timeout ionice
        #   chrt taskset arch catchsegv watch flock busybox time
        local saw_wrapper=false
        while [[ $j -lt ${#tokens[@]} ]]; do
            local tj="${tokens[$j]}" tb="${tokens[$j]##*/}"

            # Found the rm command word (possibly after one or more wrappers).
            if is_rm_token "$tj"; then break; fi
            # End of this simple command: no rm here.
            if is_command_separator_token "$tj"; then break; fi

            # Shell interpreter with a -c payload runs a command STRING; normalize
            # that payload so the inner rm is seen. Matched by basename for sh/
            # bash/zsh/dash (NOT a broad *sh, which would catch ssh -> remote).
            case "$tb" in
                sh|bash|zsh|dash)
                    local si=$((j + 1)) sc_found=0 shell_opt
                    while [[ $si -lt ${#tokens[@]} ]]; do
                        shell_opt="${tokens[$si]}"
                        if shell_short_options_have_c "$shell_opt"; then
                            if [[ $((si + 1)) -lt ${#tokens[@]} ]]; then
                                normalize_rm_command "${tokens[$((si + 1))]}"
                                return
                            fi
                            sc_found=1
                            break
                        fi
                        case "$shell_opt" in
                            -*o|+*o|-O|+O|--rcfile|--init-file) si=$((si + 2)); continue ;;
                            -*) ((si++)); continue ;;
                            *) break ;;
                        esac
                    done
                    # Not a -c form: bash/sh is itself the runner -> treat as wrapper.
                    saw_wrapper=true; ((j++)); continue ;;
            esac

            # env: a -S/--split-string payload is a command STRING (handled by
            # normalize_env_split_string, which strips env's own leading options);
            # otherwise env is a plain wrapper.
            if [[ "$tb" == "env" ]]; then
                local ei=$((j + 1))
                while [[ $ei -lt ${#tokens[@]} ]]; do
                    local et="${tokens[$ei]}"
                    case "$et" in
                        "--") break ;;
                        "-S"|"--split-string")
                            if [[ $((ei + 1)) -lt ${#tokens[@]} ]]; then
                                normalize_env_split_string "${tokens[$((ei + 1))]}"; return
                            fi
                            break ;;
                        --split-string=*) normalize_env_split_string "${et#--split-string=}"; return ;;
                        -[A-Za-z]*S*|-S*)
                            local er="${et#*S}"
                            if [[ -n "$er" ]]; then normalize_env_split_string "$er"; return; fi
                            if [[ $((ei + 1)) -lt ${#tokens[@]} ]]; then normalize_env_split_string "${tokens[$((ei + 1))]}"; return; fi
                            break ;;
                        *) break ;;   # no -S: env is a plain wrapper, fall through
                    esac
                done
                saw_wrapper=true; ((j++)); continue
            fi

            # command -v / command -V QUERY the resolution, they do NOT execute the
            # utility -- so "command -v rm" is not an rm invocation. Plain "command"
            # (and "command -p") DO run the utility -> treat as a wrapper.
            if [[ "$tb" == "command" ]]; then
                local ci=$((j + 1))
                [[ $ci -lt ${#tokens[@]} && "${tokens[$ci]}" == "--" ]] && ((ci++))
                if [[ $ci -lt ${#tokens[@]} ]]; then
                    case "${tokens[$ci]}" in
                        -*v*|-*V*) echo "$cmd"; return ;;   # query form: not an rm run
                    esac
                fi
                saw_wrapper=true; ((j++)); continue
            fi

            # flock and watch can run a shell COMMAND STRING (like bash -c), not an
            # argv command word: "flock /tmp/l -c 'rm -rf /'" and "watch 'rm -rf /'"
            # execute the string via sh -c. Recurse into that payload so the inner
            # rm is seen (the forward scan would otherwise treat the quoted payload
            # as a single non-rm token).
            if [[ "$tb" == "flock" ]]; then
                local fi=$((j + 1))
                while [[ $fi -lt ${#tokens[@]} ]]; do
                    case "${tokens[$fi]}" in
                        -c|--command) [[ $((fi + 1)) -lt ${#tokens[@]} ]] && { normalize_rm_command "${tokens[$((fi + 1))]}"; return; }; break ;;
                        --command=*) normalize_rm_command "${tokens[$fi]#--command=}"; return ;;
                        *) ((fi++)); continue ;;
                    esac
                done
                saw_wrapper=true; ((j++)); continue
            fi
            if [[ "$tb" == "watch" ]]; then
                local wi=$((j + 1)) wexec=0
                while [[ $wi -lt ${#tokens[@]} ]]; do
                    case "${tokens[$wi]}" in
                        -x|--exec) wexec=1; ((wi++)); continue ;;   # -x: exec argv, not sh -c
                        # watch options that take a separate argument (-n SECS).
                        -n|--interval) ((wi += 2)); continue ;;
                        # -d/--differences take an OPTIONAL arg (=val form only); as
                        # a bare flag they consume NOTHING -- the next token is the
                        # command. -p/-t/-b/-e/-c/-g/-h are no-arg flags.
                        -*) ((wi++)); continue ;;
                        *) break ;;
                    esac
                done
                # The command argument. If it is a SINGLE token that itself contains
                # whitespace (a quoted string like 'rm -rf /'), watch runs it via
                # sh -c -> recurse into the string. Otherwise (watch rm -rf / : the
                # command is spread across argv tokens, or the -x exec form) fall
                # through to the normal forward scan, which finds the rm directly.
                if [[ "$wexec" -ne 1 && $wi -lt ${#tokens[@]} && "${tokens[$wi]}" == *[[:space:]]* ]]; then
                    normalize_rm_command "${tokens[$wi]}"; return
                fi
                saw_wrapper=true; ((j++)); continue
            fi

            # Any other known command-runner wrapper: mark and skip the wrapper word;
            # the forward scan then walks over its options/arguments to the rm.
            case "$tb" in
                sudo|doas|exec|nice|nohup|setsid|stdbuf|timeout|ionice|chrt|taskset|arch|catchsegv|busybox|time)
                    saw_wrapper=true; ((j++)); continue ;;
            esac

            # Inside a wrapper chain: this token is a wrapper option or argument
            # (never the rm itself, which is caught at the top). Skip it and keep
            # scanning forward for the rm.
            if [[ "$saw_wrapper" == true ]]; then ((j++)); continue; fi

            # Leading word is neither rm nor a known wrapper: rm (if any later) is
            # this command's DATA, not an invocation. Stop.
            break
        done

        if [[ $j -lt ${#tokens[@]} ]] && is_rm_token "${tokens[$j]}"; then
            local rebuilt="rm"
            local k=$((j + 1))
            while [[ $k -lt ${#tokens[@]} ]] && ! is_command_separator_token "${tokens[$k]}"; do
                # Drop redirection operators (and a standalone op's target) from the
                # reconstructed rm command, so a redirect sitting BETWEEN rm and its
                # flags (e.g. "rm >&2 -rf /", "rm 2>&- -rf /") does not break the
                # anchored "rm -rf" flag detection. Fused-target ops (2>/dev/null,
                # >&2, 2>&-) carry their own target; bare ops (> , 2> ) consume the
                # next token as the target.
                if is_redirect_op_token "${tokens[$k]}"; then
                    case "${tokens[$k]}" in
                        # bare operator with NO attached fd-dup/target -> skip its target too
                        ">"|">>"|"<"|"<<"|"<<<"|"<>"|">|"|"&>"|"&>>"|[0-9]*">"|[0-9]*">>"|[0-9]*"<")
                            ((k++))
                            [[ $k -lt ${#tokens[@]} ]] && ! is_command_separator_token "${tokens[$k]}" && ((k++))
                            continue ;;
                        *) ((k++)); continue ;;   # fused-target op (>&2, 2>file, <&0): skip just it
                    esac
                fi
                rebuilt+=" $(quote_token "${tokens[$k]}")"
                ((k++))
            done
            echo "$rebuilt"
            return
        fi

        # No rm at this boundary; skip to next separator.
        at_boundary=false
        ((i++))
    done

    echo "$cmd"
}

# Parse rm command and extract operands (paths being deleted)
# Handles: rm -rf, rm -fr, rm -r -f, rm -rf --, rm -rf -- path, etc.
parse_rm_operands() {
    local cmd="$1"
    local in_operands=false

    # Normalize the command first
    cmd=$(normalize_rm_command "$cmd")

    local tokens=()
    while IFS= read -r t; do
        tokens+=("$t")
    done < <(tokenize_command "$cmd")

    # Extract operands
    local operands=()
    local found_rm=false
    local skip_next_redirect_target=false

    for token in "${tokens[@]}"; do
        # Skip until we find rm
        if [[ "$found_rm" == false ]]; then
            if [[ "$token" == "rm" ]]; then
                found_rm=true
            fi
            continue
        fi

        # Stop on compound operators / pipelines / backgrounding.
        # These are not part of rm's argv; they separate shell commands.
        case "$token" in
            ";"|"&&"|"||"|"|"|"|&"|"&")
                break
                ;;
        esac

        # Skip redirect target following a standalone redirect operator.
        if [[ "$skip_next_redirect_target" == true ]]; then
            skip_next_redirect_target=false
            continue
        fi

        # Skip common redirection operators and redirection expressions.
        # Examples: > file, 2> file, >>file, 2>&1, &>/dev/null, < file, <<EOF, etc.
        case "$token" in
            ">"|">>"|"<"|"<<"|"<<<"|"<>"|">|"|"&>"|"&>>"|"1>"|"1>>"|"2>"|"2>>"|"0<"|"0<<"|"0<<<")
                skip_next_redirect_target=true
                continue
                ;;
        esac

        if [[ "$token" == *">"* || "$token" == *"<"* ]]; then
            # Inline redirect with a target (e.g. 2>/dev/null, &>/dev/null, 2>&1)
            continue
        fi

        # After --, everything is an operand
        if [[ "$token" == "--" ]]; then
            in_operands=true
            continue
        fi

        # Skip options (anything starting with -)
        if [[ "$token" == -* && "$in_operands" != true ]]; then
            continue
        fi

        # This is an operand
        operands+=("$token")
    done

    printf '%s\n' "${operands[@]}"
}

# =============================================================================
# RM -RF FLAG DETECTION
# =============================================================================

# Check if command contains a recursive rm invocation.
# True if the SINGLE command normalizes to an rm carrying -r/-R/--recursive.
# Recursive deletes on protected roots are destructive even without -f.
# (Uses [[:space:]] rather than \s, which is not POSIX ERE.)
segment_has_rf_flags() {
    local normalized="$1"
    case "$normalized" in
        rm" "*|rm) : ;;
        *) return 1 ;;
    esac

    local tokens=() token seen_rm=false after_double_dash=false
    local has_recursive=false skip_next_redirect_target=false
    while IFS= read -r token; do
        tokens+=("$token")
    done < <(tokenize_command "$normalized")

    for token in "${tokens[@]}"; do
        if [[ "$seen_rm" == false ]]; then
            [[ "$token" == "rm" ]] && seen_rm=true
            continue
        fi

        case "$token" in
            ";"|"&&"|"||"|"|"|"|&"|"&"|"("|")"|"{"|"}")
                break
                ;;
        esac

        if [[ "$skip_next_redirect_target" == true ]]; then
            skip_next_redirect_target=false
            continue
        fi

        case "$token" in
            ">"|">>"|"<"|"<<"|"<<<"|"<>"|">|"|"&>"|"&>>"|[0-9]*">"|[0-9]*">>"|[0-9]*"<")
                skip_next_redirect_target=true
                continue
                ;;
            [0-9]*">"*|[0-9]*"<"*|">"*|"<"*)
                continue
                ;;
        esac

        [[ "$after_double_dash" == true ]] && continue
        if [[ "$token" == "--" ]]; then
            after_double_dash=true
            continue
        fi

        case "$token" in
            --recursive) has_recursive=true ;;
            --force) ;;
            --*) ;;
            -?*)
                [[ "$token" == *[rR]* ]] && has_recursive=true
                ;;
        esac

        [[ "$has_recursive" == true ]] && return 0
    done
    return 1
}

# True if the command contains an rm -rf invocation ANYWHERE. For a compound
# command this must scan EVERY segment, not just the first rm: a benign leading
# rm (e.g. "rm /tmp/f; rm -rf /") otherwise hides the catastrophic one because
# normalize_rm_command only returns the first invocation. extract_all_rm_segments
# already emits one normalized line per rm-bearing (with -r/-f) segment.
has_rf_flags() {
    local cmd="$1"

    # Cheapest possible bail: if there is no "rm" substring at all, there is
    # nothing to do. Try the raw string first (no allocation); only if that has
    # no "rm" do we pay for the quote/backslash strip that catches escaped forms
    # (r\m, r"m"). This keeps large non-rm commands (e.g. a huge `echo`) off both
    # the strip and the normalize/segment paths.
    case "$cmd" in
        *rm*) : ;;
        *)
            local probe="${cmd//\\/}"; probe="${probe//\"/}"; probe="${probe//\'/}"
            case "$probe" in *rm*) : ;; *) return 1 ;; esac
            ;;
    esac

    # Fast path: the single-command normalization (handles the common,
    # non-compound case without the per-segment work).
    if segment_has_rf_flags "$(normalize_rm_command "$cmd")"; then
        return 0
    fi

    # Compound path: scan all segments. A non-empty extraction (the sentinel
    # counts too -- truncation means "could be more, fail safe") means yes.
    if is_compound_command "$cmd"; then
        local line
        while IFS= read -r line; do
            [[ -n "$line" ]] && return 0
        done < <(extract_all_rm_segments "$cmd")
    fi
    return 1
}

# =============================================================================
# RM -RF VALIDATION
# =============================================================================

validate_rm_rf() {
    local cmd="$1"
    local operands=()

    # Warm the loop-invariant caches ONCE here, in this function's own (non-subshell)
    # scope. The per-operand checks below call is_catastrophic / check_safe_root_status
    # via $(...) command substitution -- a subshell INHERITS these globals, so it skips
    # the git + python3 subprocesses that were previously re-run for every operand
    # (the per-operand fan-out that made multi-target rm exceed the 2s timeout and
    # fail OPEN). Warming directly (not via $(...)) is what makes the cache stick.
    _NOSYNC_HOME_CANON_CACHED="$(canonicalize_path "$HOME")"; _NOSYNC_HOME_CANON_DONE=1
    build_safe_roots_canon

    while IFS= read -r op; do
        [[ -n "$op" ]] && operands+=("$op")
    done < <(parse_rm_operands "$cmd")

    if [[ ${#operands[@]} -eq 0 ]]; then
        echo "warn:no_operands:Cannot determine rm targets"
        return
    fi

    # Operand-count cap (fail SAFE). Each operand below costs a canonicalize_path
    # subprocess (~25ms), so a command with hundreds of rm targets is hundreds of
    # subprocesses and could exceed this hook's 2s timeout -- and a timed-out hook
    # FAILS OPEN. Above the cap, skip the per-operand subprocess path and classify
    # cheaply with pure-bash string checks: DENY if any operand is literally a
    # catastrophic/critical path, else ASK (never silently allow).
    local NOSYNC_MAX_RM_OPERANDS="${CLAUDE_BASH_GUARD_MAX_RM_OPERANDS:-32}"
    if [[ ${#operands[@]} -gt $NOSYNC_MAX_RM_OPERANDS ]]; then
        local op2 lex
        for op2 in "${operands[@]}"; do
            case "$op2" in
                /*) lex=$(lexical_normalize "$op2") ;;
                "~"|"~"/*) lex=$(lexical_normalize "${op2/#\~/$HOME}") ;;
                *) continue ;;   # relative operand: cannot be a bare system root
            esac
            if is_under_catastrophic_root "$lex"; then
                echo "deny:operand_count_cap:$op2 → $lex (>$NOSYNC_MAX_RM_OPERANDS operands; cheap scan)"
                return
            fi
        done
        echo "ask:operand_count_cap:${#operands[@]} rm targets exceeds cap ($NOSYNC_MAX_RM_OPERANDS); split for a precise check"
        return
    fi

    local all_safe=true
    local has_catastrophic=false
    local has_expansion=false
    local has_root_exact_match=false
    local warnings=()
    local deny_reasons=()
    local root_matches=()

    # Batch-canonicalize every operand in a SINGLE interpreter call instead of one
    # subprocess per operand. The per-operand fork was the cost that made a
    # multi-target rm exceed the 2s timeout and fail OPEN. Operands and results
    # are NUL-delimited so spaces/newlines in paths are safe -- and the
    # interpreter is piped DIRECTLY into the read loop (NOT captured in a variable
    # first: bash cannot hold NUL bytes in a variable, so $(...) would lose the
    # delimiters). After this, the per-operand loop is pure-bash string comparison.
    # "$GUARD_NODE" preferred, python3 fallback for standalone use -- same
    # rationale and identical semantics as canonicalize_path above.
    local -a canon_list=()
    local _have_batch=0
    if [[ ${#operands[@]} -gt 0 && -n "${GUARD_NODE:-}" && -x "${GUARD_NODE:-}" ]]; then
        local _idx=0 _piece
        while IFS= read -r -d '' _piece; do
            canon_list[$_idx]="$_piece"; ((_idx++))
        done < <(printf '%s\0' "${operands[@]}" | HOME="$HOME" "$GUARD_NODE" -e '
const fs = require("fs"), path = require("path"), os = require("os");
const chunks = [];
process.stdin.on("data", (c) => chunks.push(c));
process.stdin.on("end", () => {
  let parts = Buffer.concat(chunks).toString("utf8").split("\0");
  if (parts.length && parts[parts.length - 1] === "") parts.pop();
  const home = os.homedir();
  const out = [];
  for (const raw of parts) {
    let p = raw;
    if (p.startsWith("~")) p = home + p.slice(1);
    let r = "";
    try {
      if (fs.existsSync(p)) r = fs.realpathSync(p);
      else {
        const parent = path.dirname(p) || ".";
        const base = path.basename(p);
        r = fs.existsSync(parent) ? path.join(fs.realpathSync(parent), base) : path.resolve(p);
      }
    } catch (e) { r = ""; }
    // Trailing NUL after EVERY item so the bash read -d "" loop captures the last one.
    out.push(r, "\0");
  }
  process.stdout.write(out.join(""));
});
' 2>/dev/null)
        # Only trust the batch if it produced one result per operand.
        [[ ${#canon_list[@]} -eq ${#operands[@]} ]] && _have_batch=1
    fi
    if [[ "$_have_batch" -eq 0 && ${#operands[@]} -gt 0 ]] && command -v python3 >/dev/null 2>&1; then
        canon_list=()
        local _idx=0 _piece
        while IFS= read -r -d '' _piece; do
            canon_list[$_idx]="$_piece"; ((_idx++))
        done < <(printf '%s\0' "${operands[@]}" | HOME="$HOME" python3 -c '
import os, sys
data = sys.stdin.buffer.read().split(b"\0")
if data and data[-1] == b"": data = data[:-1]
home = os.path.expanduser("~")
for raw in data:
    p = raw.decode("utf-8", "surrogateescape")
    if p.startswith("~"):
        p = home + p[1:]
    try:
        if os.path.exists(p):
            r = os.path.realpath(p)
        else:
            parent = os.path.dirname(p) or "."
            base = os.path.basename(p)
            r = os.path.join(os.path.realpath(parent), base) if os.path.exists(parent) else os.path.normpath(os.path.abspath(p))
    except Exception:
        r = ""
    # Trailing NUL after EVERY item so the bash read -d "" loop captures the last one.
    sys.stdout.buffer.write(r.encode("utf-8", "surrogateescape") + b"\0")
' 2>/dev/null)
        # Only trust the batch if it produced one result per operand.
        [[ ${#canon_list[@]} -eq ${#operands[@]} ]] && _have_batch=1
    fi

    local _oi=-1
    for operand in "${operands[@]}"; do
        ((_oi++))
        # Check for shell expansion characters
        if has_shell_expansion "$operand"; then
            has_expansion=true
            warnings+=("Shell expansion in: $operand")
            all_safe=false
            continue
        fi

        # Canonicalize the path: use the batched result if available, else fall
        # back to a single canonicalize_path (e.g. python3 missing or count
        # mismatch).
        local canonical
        if [[ "$_have_batch" -eq 1 ]]; then
            canonical="${canon_list[$_oi]:-}"
        else
            canonical=$(canonicalize_path "$operand")
        fi

        if [[ -z "$canonical" ]]; then
            warnings+=("Cannot resolve: $operand")
            all_safe=false
            continue
        fi

        # Check if catastrophic. Test BOTH the symlink-resolved canonical path AND
        # the LEXICAL (pre-symlink) normalization: on macOS /etc and /var are
        # symlinks (/etc -> /private/etc), so canonicalize_path turns "rm -rf /etc"
        # into /private/etc, which is_catastrophic's exact-root list would miss.
        # is_under_catastrophic_root on the lexical form catches the user's literal
        # intent regardless of symlinks.
        local lexop=""
        case "$operand" in
            /*) lexop=$(lexical_normalize "$operand") ;;
            "~"|"~"/*) lexop=$(lexical_normalize "${operand/#\~/$HOME}") ;;
        esac
        if is_catastrophic "$canonical" || { [[ -n "$lexop" ]] && is_under_catastrophic_root "$lexop"; }; then
            has_catastrophic=true
            deny_reasons+=("$operand → ${lexop:-$canonical}")
            continue
        fi

        # Check safe root status
        local status
        status=$(check_safe_root_status "$canonical")

        case "$status" in
            under)
                # Strictly under a safe root - OK
                ;;
            equals_root:*)
                # Equals a safe root exactly - warn
                has_root_exact_match=true
                local matched_root="${status#equals_root:}"
                root_matches+=("$operand equals safe root $matched_root")
                ;;
            outside)
                all_safe=false
                warnings+=("Outside safe roots: $operand → $canonical")
                ;;
        esac
    done

    # Decision logic
    if [[ "$has_catastrophic" == true ]]; then
        echo "deny:catastrophic:${deny_reasons[*]}"
    elif [[ "$has_expansion" == true ]]; then
        # Shell expansion requires explicit override
        if [[ "$ALLOW_RM_RF" == "1" && "$ALLOW_RM_RF_SCOPE" == "expansion" ]]; then
            echo "allow:override_expansion"
        else
            echo "ask:expansion:${warnings[*]}"
        fi
    elif [[ "$has_root_exact_match" == true ]]; then
        # Deleting a safe root itself - warn (larger blast radius)
        echo "warn:safe_root_exact:${root_matches[*]}"
    elif [[ "$all_safe" == true ]]; then
        echo "allow:safe_roots"
    else
        # Outside safe roots - check for scoped override
        if [[ "$ALLOW_RM_RF" == "1" && "$ALLOW_RM_RF_SCOPE" == "all" ]]; then
            echo "allow:override_all"
        else
            echo "warn:outside_safe:${warnings[*]}"
        fi
    fi
}

# =============================================================================
# MAIN VALIDATION LOGIC
# =============================================================================

# Ensure jq is available
if ! command -v jq &> /dev/null; then
    echo "❌ jq is required but not installed" >&2
    exit 2
fi

# Read the agent guard JSON envelope from stdin
if ! json_input=$(cat); then
    echo "❌ Failed to read input" >&2
    exit 2
fi

# Validate JSON and extract command
if ! command=$(echo "$json_input" | jq -r '.tool_input.command // empty' 2>/dev/null); then
    echo "❌ Invalid JSON input" >&2
    exit 2
fi

# Exit early if no command
if [ -z "$command" ] || [ "$command" = "null" ]; then
    exit 0
fi

# Defensive size cap (fail SAFE, never fail open).
#
# This hook has a 2s timeout. The lexer is now linear, but the rm -rf operand
# validator still spawns one canonicalize_path (a python/perl subprocess) per
# operand, so a command with thousands of rm targets is O(operands) subprocesses
# and could still approach the timeout. A legitimate interactive/agent command
# is never anywhere near this size. Above the cap we therefore SKIP the expensive
# per-operand path and fall back to a cheap, linear, regex-only classification:
#   - if it looks like a catastrophic rm -rf of a root/critical path -> DENY
#   - else if it has an rm -rf shape we cannot cheaply clear           -> ASK
#   - else fall through to the normal (linear, grep-based) pattern checks.
# A timed-out hook is killed and FAILS OPEN, so erring toward DENY/ASK here is
# the correct safe direction for a catastrophic-command guard.
NOSYNC_MAX_CMD_BYTES="${CLAUDE_BASH_GUARD_MAX_BYTES:-32768}"
if [ "${#command}" -gt "$NOSYNC_MAX_CMD_BYTES" ]; then
    # Cheap linear check: rm with -r and -f (any order/combined) targeting a
    # filesystem root or a critical system dir, allowing sudo/env/command/path
    # prefixes. Intentionally broad; this path only runs for implausibly large
    # commands where precise parsing would risk the timeout.
    # shellcheck disable=SC2016 # grep patterns match the LITERAL text $HOME etc. in the command; no expansion intended
    # Command-boundary class includes grouping punctuation ( ) { } and the operator
    # metacharacters so a grouped/subshelled rm (e.g. "(rm -rf /)") is recognized.
    if printf '%s' "$command" \
        | grep -Eq '(^|[;&|(){}[:space:]])((command|sudo|env)[[:space:]]+)*((\\|/usr/bin/|/bin/)?rm)([[:space:]]+-[[:alpha:]]*[rR][[:alpha:]]*[fF]|[[:space:]]+-[[:alpha:]]*[fF][[:alpha:]]*[rR]|([[:space:]]+-[rR])([[:space:]].*[[:space:]]-[fF]))' \
        && printf '%s' "$command" | grep -Eq '[[:space:]](/|/etc|/bin|/sbin|/usr|/var|/boot|/sys|/proc|/lib|/System|/Library|~|\$HOME)([[:space:]]|/|$)'; then
        log_security_event "BLOCKED" "oversized_catastrophic_rm" "$command"
        echo "❌ BLOCKED: Oversized command contains a catastrophic rm -rf pattern (size-capped fail-safe)" >&2
        echo "   Command length: ${#command} bytes (cap: ${NOSYNC_MAX_CMD_BYTES})" >&2
        exit 2
    fi
    if printf '%s' "$command" | grep -Eq '((\\|/usr/bin/|/bin/)?rm)[[:space:]].*-[rRfF]'; then
        log_security_event "WARNING" "oversized_unclassifiable_rm" "$command"
        echo "⚠️  WARNING: Command too large to classify safely; contains an rm -r/-f pattern" >&2
        echo "   Command length: ${#command} bytes (cap: ${NOSYNC_MAX_CMD_BYTES}). Split it up to get a precise check." >&2
        exit 1
    fi
    # The two greps above scan the RAW command. A quoted/escaped command word
    # (r\m, r"m", r'm') would evade them, so ALSO probe a quote/backslash-stripped
    # copy -- but ONLY when the command actually contains a quote or backslash
    # (the strip is O(n) x3 and costly at hundreds of KB; a giant plain `echo`
    # has neither, so we skip the strip for it). If the stripped copy reveals an
    # rm + -r/-f shape, fail safe (ASK) rather than skip-then-allow.
    case "$command" in
        *\\* | *\"* | *\'*)
            oversized_probe="${command//\\/}"
            oversized_probe="${oversized_probe//\"/}"
            oversized_probe="${oversized_probe//\'/}"
            if printf '%s' "$oversized_probe" | grep -Eq '(^|[;&|(){}[:space:]])((command|sudo|env)[[:space:]]+)*(/usr/bin/|/bin/)?rm[[:space:]].*-[rRfF]'; then
                log_security_event "WARNING" "oversized_unclassifiable_rm_quoted" "$command"
                echo "⚠️  WARNING: Command too large to classify safely; contains a quoted/escaped rm -r/-f pattern" >&2
                echo "   Command length: ${#command} bytes (cap: ${NOSYNC_MAX_CMD_BYTES}). Split it up to get a precise check." >&2
                exit 1
            fi
            ;;
    esac
    # The raw greps above see a LITERAL "rm" token. An oversized command could
    # still hide an rm via ${IFS}/$IFS whitespace tricks ("rm${IFS}-rf /") or a
    # brace-expansion command word ("r{m,} -rf /"); we do NOT run the (costly)
    # IFS-neutralizer / brace-expander on a multi-100KB command, so fail SAFE: if
    # the command contains an IFS reference or a command-position brace AND any
    # rm-style -r/-f flag, ASK rather than skip-to-allow.
    # $IFS reference anywhere with an -r/-f flag shape (the flag may be glued to
    # the IFS ref, e.g. "rm${IFS}-rf", so accept } or $ as the boundary too).
    if printf '%s' "$command" | grep -Eq '\$\{?IFS' \
        && printf '%s' "$command" | grep -Eq '([[:space:]}]|\$\{?IFS\}?)-[a-zA-Z]*[rRfF]'; then
        log_security_event "WARNING" "oversized_ifs_rm" "$command"
        echo "⚠️  WARNING: Oversized command uses \$IFS near an -r/-f flag; too large to classify safely" >&2
        exit 1
    fi
    if printf '%s' "$command" | grep -Eq '[[:space:]]-[a-zA-Z]*[rRfF]' \
        && printf '%s' "$command" | grep -Eq '(^|[;&|(){}[:space:]])[^[:space:];&|]*\{[^}]*[,.][^}]*\}'; then
        log_security_event "WARNING" "oversized_brace_rm" "$command"
        echo "⚠️  WARNING: Oversized command uses brace expansion near an -r/-f flag; too large to classify safely" >&2
        exit 1
    fi
    # No rm-rf shape in this oversized command (raw or unquoted). Skip the
    # expensive rm normalization path below (its string ops are costly at hundreds
    # of KB) and run ONLY the cheap linear dangerous-pattern greps.
    NOSYNC_OVERSIZED_NO_RM=1
fi

# Replace every "${IFS...}" parameter expansion with a space, honoring NESTED
# braces (e.g. "${IFS:-${x}}", "${IFS/${a}/ }"). bash expands all of these to the
# IFS whitespace, so "rm${IFS:-${x}}-rf /" really runs "rm -rf /". A single sed
# regex cannot balance braces (${IFS[^}]*} stops at the first inner "}"), so this
# is a small awk balanced-brace scanner. Replacing can only REVEAL a dangerous
# shape, never hide one, so it is always the safe direction.
# shellcheck disable=SC2016 # awk program, not a shell string to expand
NEUTRALIZE_IFS_AWK='
BEGIN { RS = "\0" }
{
  s = $0; out = ""; n = length(s); i = 1
  while (i <= n) {
    if (substr(s, i, 6) == "${IFS}" ) { out = out " "; i += 6; continue }
    # "${IFS" followed by a parameter-expansion operator -> consume to the matching
    # close brace, tracking nesting depth, and emit a single space.
    if (substr(s, i, 5) == "${IFS" ) {
      c6 = substr(s, i + 5, 1)
      if (c6 == ":" || c6 == "-" || c6 == "+" || c6 == "?" || c6 == "=" || c6 == "%" || c6 == "#" || c6 == "/") {
        depth = 1; j = i + 5
        while (j <= n && depth > 0) {
          ch = substr(s, j, 1)
          if (ch == "{") depth++
          else if (ch == "}") depth--
          j++
        }
        out = out " "; i = j; continue
      }
    }
    out = out substr(s, i, 1); i++
  }
  printf "%s", out
}'
neutralize_ifs() { awk "$NEUTRALIZE_IFS_AWK"; }

# Strip heredoc BODIES that are pure DATA, not executable script. "cat <<EOF ...
# rm -rf / ... EOF" feeds the body to cat as data, so the body must NOT be scanned
# as a command (it was false-DENYing). BUT a heredoc fed to a shell interpreter
# (bash/sh/zsh/dash <<EOF) or a remote shell (ssh host <<EOF) IS executable, so we
# KEEP those bodies. Conservative: a body is dropped only when the heredoc-
# introducing line's first command word is plainly a non-interpreter; anything we
# are unsure about keeps the body (fail safe toward scanning). One heredoc per
# line is handled (the common case); multiple on one line keep all bodies.
# shellcheck disable=SC2016 # awk program
STRIP_HEREDOC_AWK='
function is_interp(w) {
  return (w == "sh" || w == "bash" || w == "zsh" || w == "dash" || w == "ksh" || w == "csh" || w == "tcsh" || w == "ssh" || w == "eval")
}
function is_wrapper(w) {
  return (w == "sudo" || w == "doas" || w == "env" || w == "command" || w == "exec" || w == "nice" || w == "nohup" || w == "setsid" || w == "stdbuf" || w == "timeout" || w == "ionice" || w == "chrt" || w == "taskset" || w == "arch" || w == "catchsegv" || w == "watch" || w == "flock" || w == "busybox" || w == "time")
}
# The command word that consumes the heredoc, skipping leading assignments,
# redirections, AND command-runner wrappers (so "env bash <<EOF" resolves to
# bash, not env). Returns basename.
function first_word(line,   a, n, ii, t, in_wrap) {
  sub(/^[ \t]+/, "", line)
  n = split(line, a, /[ \t]+/)
  ii = 1; in_wrap = 0
  while (ii <= n) {
    t = a[ii]; sub(/^.*\//, "", t)
    if (a[ii] ~ /^[A-Za-z_][A-Za-z0-9_]*=/) { ii++; continue }   # assignment
    if (a[ii] ~ /^[0-9]*[<>]/) { ii++; continue }                # leading redirect
    if (is_wrapper(t)) { in_wrap = 1; ii++; continue }           # wrapper word
    # Inside a wrapper run, skip the wrappers OPTIONS and any OPTION-ARGUMENT or
    # positional (e.g. the "5" in "timeout 5 bash", "-n 1" in "watch -n 1 bash",
    # "0x1" in "taskset 0x1 bash") -- UNLESS the token is itself an interpreter or
    # another wrapper (then it is the real command word).
    if (in_wrap && !is_interp(t) && !is_wrapper(t)) { ii++; continue }
    break
  }
  t = a[ii]; sub(/^.*\//, "", t)
  return t
}
# True if the heredoc-introducing line pipes into a shell interpreter ("| sh",
# "| bash"), so the body is executable even though the first word (cat/tee) is not.
function pipes_to_shell(line,   a, n, k, t) {
  n = split(line, a, /[ \t]+/)
  for (k = 1; k <= n; k++) {
    if (a[k] == "|" || a[k] == "|&") {
      t = a[k+1]; sub(/^.*\//, "", t)
      if (is_interp(t)) return 1
    }
  }
  return 0
}
BEGIN { RS = "\0"; FS = "\n" }
{
  out = ""
  for (li = 1; li <= NF; li++) {
    line = $li
    if (in_body) {
      # body of a data heredoc: a line equal to the delimiter (optionally
      # tab-indented for <<-) ends it; drop the body lines and the delimiter.
      stripped = line; sub(/^\t+/, "", stripped)
      if (stripped == delim || line == delim) { in_body = 0 }
      continue
    }
    out = out (out == "" ? "" : "\n") line
    # does THIS line open a heredoc?  match <<[-] optionally then a delimiter word
    if (match(line, /<<-?[ \t]*[A-Za-z_"'"'"'\\][A-Za-z0-9_"'"'"'\\]*/)) {
      hd = substr(line, RSTART, RLENGTH)
      d = hd; sub(/^<<-?[ \t]*/, "", d); gsub(/["'"'"'\\]/, "", d)
      cw = first_word(line)
      # KEEP the body (treat as executable) for shell interpreters / remote shells
      # / wrapper-prefixed interpreters / pipe-to-shell. Otherwise it is data.
      if (is_interp(cw) || pipes_to_shell(line)) {
        # leave in_body = 0 so the body lines are scanned normally
      } else {
        in_body = 1; delim = d
      }
    }
  }
  printf "%s", out
}'
strip_data_heredocs() { printf '%s' "$1" | awk "$STRIP_HEREDOC_AWK"; }

# Emit the CONTENTS of every command substitution -- $(...) and `...` -- one per
# line, so a catastrophic command HIDDEN inside a substitution (even inside double
# quotes, e.g. echo "$(rm -rf /)") is surfaced and scanned as a command in its own
# right. Single-quoted regions suppress substitution, so they are skipped. Nested
# $() are tracked by depth. Backtick pairs are taken at face value (no nesting).
# This only REVEALS commands to scan; it never hides one. Linear awk.
# shellcheck disable=SC2016 # awk program
COMMAND_SUBSTS_AWK='
BEGIN { RS = "\0" }
{
  s = $0; n = length(s); i = 1; q = ""
  while (i <= n) {
    c = substr(s, i, 1)
    if (q == "\047") { if (c == "\047") q = ""; i++; continue }   # single quote: opaque
    if (c == "\047") { q = "\047"; i++; continue }
    if (c == "\\") { i += 2; continue }
    # $( ... ) with nesting
    if (c == "$" && substr(s, i+1, 1) == "(") {
      depth = 1; j = i + 2; start = j; iq = ""
      while (j <= n && depth > 0) {
        cj = substr(s, j, 1)
        if (iq != "") { if (cj == iq) iq = ""; j++; continue }
        if (cj == "\047" || cj == "\042") { iq = cj; j++; continue }
        if (cj == "\\") { j += 2; continue }
        if (cj == "(") depth++
        else if (cj == ")") { depth--; if (depth == 0) break }
        j++
      }
      if (j <= n) { print substr(s, start, j - start) }
      i = j + 1; continue
    }
    # `...`
    if (c == "`") {
      j = i + 1; start = j
      while (j <= n && substr(s, j, 1) != "`") { if (substr(s,j,1)=="\\") j++; j++ }
      print substr(s, start, j - start)
      i = j + 1; continue
    }
    i++
  }
}'
extract_command_substs() { printf '%s' "$1" | awk "$COMMAND_SUBSTS_AWK"; }

all_command_substs_are_simple_output_only() {
    extract_command_substs "$1" | awk '
      BEGIN { count = 0 }
      {
        count++
        if ($0 ~ /^[[:space:]]*(echo|printf)[[:space:]]+[A-Za-z0-9_.\/%+-]+[[:space:]]*$/) next
        if ($0 ~ /^[[:space:]]*git[[:space:]]+config[[:space:]]+[A-Za-z0-9_.\/%+-]+[[:space:]]*$/) next
        bad = 1
      }
      END { exit (count > 0 && !bad) ? 0 : 1 }
    '
}

# Collapse allowlisted output-only substitutions before the later token scanners.
# This avoids repeatedly parsing large inert fan-outs while preserving the
# surrounding command and quoting.
NEUTRALIZE_COMMAND_SUBSTS_AWK='
BEGIN { RS = "\0" }
{
  s = $0; n = length(s); i = 1; q = ""; out = ""
  while (i <= n) {
    c = substr(s, i, 1)
    if (q == "\047") {
      out = out c
      if (c == "\047") q = ""
      i++; continue
    }
    if (c == "\047") { q = "\047"; out = out c; i++; continue }
    if (c == "\\") { out = out substr(s, i, 2); i += 2; continue }
    if (c == "$" && substr(s, i+1, 1) == "(") {
      depth = 1; j = i + 2; iq = ""
      while (j <= n && depth > 0) {
        cj = substr(s, j, 1)
        if (iq != "") { if (cj == iq) iq = ""; j++; continue }
        if (cj == "\047" || cj == "\042") { iq = cj; j++; continue }
        if (cj == "\\") { j += 2; continue }
        if (cj == "(") depth++
        else if (cj == ")") depth--
        j++
      }
      out = out "__SUBST__"; i = j; continue
    }
    if (c == "`") {
      j = i + 1
      while (j <= n && substr(s, j, 1) != "`") { if (substr(s,j,1)=="\\") j++; j++ }
      out = out "__SUBST__"; i = j + 1; continue
    }
    out = out c; i++
  }
  printf "%s", out
}'
neutralize_command_substs() { printf '%s' "$1" | awk "$NEUTRALIZE_COMMAND_SUBSTS_AWK"; }

# Normalize command for analysis. Strip data heredoc bodies, neutralize ${IFS...}
# (braced, incl. nested) and $IFS (unbraced) to whitespace, then collapse runs of
# spaces. (A var named $IFSX is left alone -- only $IFS as a whole token.)
normalized_cmd=$(strip_data_heredocs "$command" | neutralize_ifs \
    | sed 's/\$IFS\([^A-Za-z0-9_]\)/ \1/g; s/\$IFS$/ /g' \
    | tr -s ' ' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

# Recursively analyze each command substitution's contents. A catastrophic rm/dd/
# mkfs/etc. inside $(...) or `...` runs for real, so we re-enter this guard on the
# extracted command text and propagate the worst decision. Done up front so it
# applies regardless of which later branch handles the outer command.
NOSYNC_SUBST_DEPTH="${NOSYNC_SUBST_DEPTH:-0}"
# Cheap prefilter: only do the (awk + recursive) substitution analysis when the
# command actually contains a substitution opener. A large plain command (e.g. a
# 16KB echo) has neither, so it skips this entirely -- keeping it off the hot path.
case "$command" in
    *'$('*|*'`'*) _has_subst=1 ;;
    *) _has_subst=0 ;;
esac
if [[ "$_has_subst" -eq 1 ]]; then
    _subst_fast_safe=0
    _subst_neutralized=""
    if all_command_substs_are_simple_output_only "$command"; then
        _subst_neutralized="$(neutralize_command_substs "$normalized_cmd")"
        _simple_output_outer_re='^[[:space:]]*(echo|printf[[:space:]]+['\''"]?%s['\''"]?)([[:space:]]+"?__SUBST__"?)+[[:space:]]*$'
        [[ "$_subst_neutralized" =~ $_simple_output_outer_re ]] && _subst_fast_safe=1
    fi
    if [[ "$_subst_fast_safe" -eq 1 ]]; then
        normalized_cmd="$_subst_neutralized"
    elif [[ "$NOSYNC_SUBST_DEPTH" -ge 4 ]]; then
        # Depth cap reached: the surface checks below cannot see a command
        # hidden this deep. Fail safe for every deeper substitution rather than
        # trying to maintain a dangerous-verb prefilter.
        log_security_event "ASK" "command_substitution_depth_cap" "$command"
        echo "⚠️  CONFIRMATION REQUIRED: command nests substitutions too deeply to analyze safely" >&2
        exit 1
    else
        _sub_allowed=()
        _sub_batch=""
        while IFS= read -r _subcmd; do
            [[ -z "$_subcmd" ]] && continue
            _sub_seen=0
            for _sub_prev in "${_sub_allowed[@]}"; do
                if [[ "$_sub_prev" == "$_subcmd" ]]; then _sub_seen=1; break; fi
            done
            [[ "$_sub_seen" -eq 1 ]] && continue
            _sub_allowed+=("$_subcmd")
            # Each substitution executes in its own subshell. Group every unique
            # body so cwd/variable changes cannot leak between bodies, then send
            # the whole batch through one recursive analyzer process.
            _sub_batch+="("$'\n'"$_subcmd"$'\n'")"$'\n'
        done < <(extract_command_substs "$command")
        if [[ -n "$_sub_batch" ]]; then
            _subjson=""
            if ! _subjson="$(jq -nc --arg c "$_sub_batch" '{tool_input:{command:$c}}' 2>/dev/null)" \
                || [[ -z "$_subjson" ]]; then
                log_security_event "BLOCKED" "command_substitution_input_failure" "$command"
                echo "❌ BLOCKED: unable to construct recursive substitution analysis input" >&2
                exit 2
            fi
            _subrc=0
            printf '%s' "$_subjson" | NOSYNC_SUBST_DEPTH=$((NOSYNC_SUBST_DEPTH + 1)) bash "$0" >/dev/null 2>&1 || _subrc=$?
            if [[ "$_subrc" -eq 2 ]]; then
                log_security_event "BLOCKED" "command_substitution_catastrophic" "$command"
                echo "❌ BLOCKED: catastrophic command inside a command substitution: $command" >&2
                exit 2
            elif [[ "$_subrc" -eq 1 ]]; then
                log_security_event "ASK" "command_substitution" "$command"
                echo "⚠️  CONFIRMATION REQUIRED: risky command inside a command substitution: $command" >&2
                exit 1
            elif [[ "$_subrc" -ne 0 ]]; then
                log_security_event "BLOCKED" "command_substitution_analyzer_failure" "$command"
                echo "❌ BLOCKED: recursive substitution analysis failed unexpectedly" >&2
                exit 2
            fi
        fi
    fi
    unset _subst_fast_safe _subst_neutralized _simple_output_outer_re
    unset _sub_allowed _sub_batch _sub_seen _sub_prev
fi

# =============================================================================
# NON-RM DANGEROUS PATTERNS (hard block)
# =============================================================================

# Lexically normalize an absolute path WITHOUT resolving symlinks (pure string):
# collapse repeated slashes, drop "." components, and pop ".." components.
lexical_normalize() {
    lexical_normalize_into "$1"
    printf '%s' "$_lexical_result"
}

lexical_normalize_into() {
    local p="$1" out="" comp
    local IFS=/
    local parts=()
    read -ra parts <<< "$p"
    local stack=() i
    for comp in "${parts[@]}"; do
        case "$comp" in
            ""|.) continue ;;
            ..) [[ ${#stack[@]} -gt 0 ]] && unset 'stack[${#stack[@]}-1]' ;;
            *) stack+=("$comp") ;;
        esac
    done
    for i in "${stack[@]}"; do out="$out/$i"; done
    [[ -z "$out" ]] && out="/"
    _lexical_result="$out"
}

is_literal_critical_system_path() {
    local p="$1"
    [[ "$p" == /* ]] || return 1
    lexical_normalize_into "$p"
    p="$_lexical_result"
    case "$p" in
        /etc|/etc/*|/bin|/bin/*|/sbin|/sbin/*|/usr|/usr/*|/var|/var/*|/private|/private/*|/System|/System/*|/Library|/Library/*|/Applications|/Applications/*|/opt|/opt/*|/Volumes|/Volumes/*|/boot|/boot/*|/sys|/sys/*|/proc|/proc/*)
            return 0 ;;
        /dev/sd*|/dev/hd*|/dev/vd*|/dev/xvd*|/dev/nvme*|/dev/disk*|/dev/rdisk*|/dev/mapper/*|/dev/dm-*|/dev/loop*)
            return 0 ;;
        *) return 1 ;;
    esac
}

path_is_in_safe_root() {
    local status canonical
    canonical="$(canonicalize_path "$1")"
    status="$(check_safe_root_status "$canonical")"
    case "$status" in under|equals_root:*) return 0 ;; *) return 1 ;; esac
}

glob_static_prefix() {
    local p="$1" i c
    _glob_prefix=""
    for ((i=0; i<${#p}; i++)); do
        c="${p:i:1}"
        case "$c" in "*"|"?"|"[") break ;; esac
        _glob_prefix+="$c"
    done
}

glob_may_target_critical_root() {
    local p="$1" rest first root device_rest
    [[ "$p" == /* ]] || return 1
    rest="${p#/}"
    first="${rest%%/*}"
    for root in etc bin sbin usr var private System Library Applications opt Volumes boot sys proc; do
        [[ "$root" == $first ]] && return 0
    done
    [[ "dev" == $first ]] || return 1
    [[ "$rest" == */* ]] || return 1
    device_rest="${rest#*/}"
    case "$device_rest" in
        *'*'*|*'?'*|*'['*) return 0 ;;
    esac
    is_literal_critical_system_path "/dev/$device_rest"
}

resolve_literal_parameter_fallbacks() {
    local s="$1" round before start i depth end inner replacement
    _parameter_candidate="$s"
    for ((round=0; round<64; round++)); do
        case "$_parameter_candidate" in *'${'*) : ;; *) return 0 ;; esac
        before="${_parameter_candidate%%\$\{*}"
        start="${#before}"
        depth=1
        end=-1
        for ((i=start+2; i<${#_parameter_candidate}; i++)); do
            case "${_parameter_candidate:i:1}" in
                "{") depth=$((depth + 1)) ;;
                "}")
                    depth=$((depth - 1))
                    if [[ "$depth" -eq 0 ]]; then end="$i"; break; fi
                    ;;
            esac
        done
        [[ "$end" -ge 0 ]] || return 1
        inner="${_parameter_candidate:start+2:end-start-2}"
        if [[ "$inner" =~ ^([A-Za-z_][A-Za-z0-9_]*|[0-9]+)(:?[-=+])(.*)$ ]]; then
            replacement="${BASH_REMATCH[3]}"
        else
            return 1
        fi
        _parameter_candidate="${_parameter_candidate:0:start}$replacement${_parameter_candidate:end+1}"
    done
    return 2
}

brace_decimal() {
    local raw="$1" digits
    if [[ "$raw" == -* ]]; then
        digits="${raw#-}"
        _brace_decimal=$(( -(10#$digits) ))
    else
        _brace_decimal=$(( 10#$raw ))
    fi
}

brace_ranges_too_large() {
    local rest="$1" a b step diff width product=1 matched
    local range_re='\{(-?[0-9]+)\.\.(-?[0-9]+)(\.\.(-?[0-9]+))?\}'
    while [[ "$rest" =~ $range_re ]]; do
        matched="${BASH_REMATCH[0]}"
        a="${BASH_REMATCH[1]}"
        b="${BASH_REMATCH[2]}"
        step="${BASH_REMATCH[4]:-1}"
        [[ "${#a}" -gt 9 || "${#b}" -gt 9 || "${#step}" -gt 9 ]] && return 0
        brace_decimal "$a"; a="$_brace_decimal"
        brace_decimal "$b"; b="$_brace_decimal"
        brace_decimal "$step"; step="$_brace_decimal"
        [[ "$step" -eq 0 ]] && return 0
        [[ "$step" -lt 0 ]] && step=$((-step))
        diff=$((a > b ? a - b : b - a))
        width=$((diff / step + 1))
        [[ "$width" -gt 1024 || "$product" -gt $((1024 / width)) ]] && return 0
        product=$((product * width))
        rest="${rest#*"$matched"}"
    done
    case "$rest" in *"{"*".."*"}"*) return 0 ;; esac
    return 1
}

is_critical_system_path() {
    local p="$1" item ncommas nopen counted _parameter_rc
    case "$p" in
        "~"|"~"/*) p="$HOME${p#\~}" ;;
    esac
    case "$p" in
        *'*'*|*'?'*|*'['*)
            if [[ "$p" == /* ]]; then
                glob_static_prefix "$p"
                [[ -z "$_glob_prefix" || "$_glob_prefix" == "/" ]] && return 0
                path_is_in_safe_root "$_glob_prefix" && return 1
                is_literal_critical_system_path "$_glob_prefix" && return 0
                glob_may_target_critical_root "$p" && return 0
                return 1
            fi
            ;;
    esac
    case "$p" in
        *"{"*) : ;;
        *) [[ "$p" == /* ]] && path_is_in_safe_root "$p" && return 1 ;;
    esac
    case "$p" in *"{"*) : ;; *) is_literal_critical_system_path "$p" && return 0 ;; esac
    if [[ "$p" == *'${'* ]]; then
        resolve_literal_parameter_fallbacks "$p"
        _parameter_rc=$?
        [[ "$_parameter_rc" -eq 2 ]] && return 0
        [[ "$_parameter_rc" -eq 0 ]] \
            && is_literal_critical_system_path "$_parameter_candidate" \
            && return 0
    fi
    case "$p" in *"{"*) : ;; *) return 1 ;; esac
    # Expand only a shell-inert brace word. No command substitution, globbing,
    # whitespace, operators, or quotes may reach eval.
    case "$p" in
        *'$'*|*'`'*|*'('*|*')'*|*';'*|*'&'*|*'|'*|*'<'*|*'>'*|*' '*|*'	'*|*'*'*|*'?'*|*'['*|*']'*|*'!'*|*'"'*|*"'"*|*'\'*)
            return 1 ;;
    esac
    counted="${p//[^,]/}"; ncommas="${#counted}"
    counted="${p//[^\{]/}"; nopen="${#counted}"
    [[ "$ncommas" -gt 8 || "$nopen" -gt 12 ]] && return 0
    brace_ranges_too_large "$p" && return 0
    local expanded=()
    eval "expanded=($p)" 2>/dev/null || return 1
    [[ ${#expanded[@]} -gt 1024 ]] && return 0
    for item in "${expanded[@]}"; do
        is_literal_critical_system_path "$item" && return 0
    done
    return 1
}

brace_word_is_critical_verb() {
    local w="$1" item ncommas nopen counted
    case "$w" in *"{"*) : ;; *) return 1 ;; esac
    case "$w" in
        *'$'*|*'`'*|*'('*|*')'*|*';'*|*'&'*|*'|'*|*'<'*|*'>'*|*' '*|*'	'*|*'*'*|*'?'*|*'['*|*']'*|*'!'*|*'"'*|*"'"*|*'\'*)
            return 1 ;;
    esac
    counted="${w//[^,]/}"; ncommas="${#counted}"
    counted="${w//[^\{]/}"; nopen="${#counted}"
    [[ "$ncommas" -gt 8 || "$nopen" -gt 12 ]] && return 0
    brace_ranges_too_large "$w" && return 0
    local expanded=()
    eval "expanded=($w)" 2>/dev/null || return 1
    [[ ${#expanded[@]} -gt 1024 ]] && return 0
    for item in "${expanded[@]}"; do
        case "${item##*/}" in truncate|shred) return 0 ;; esac
    done
    return 1
}

dangerous_patterns=(
    # Disk operations
    "> /dev/sd[a-z]"
    # dd writing to a raw/block device, REGARDLESS of operand order
    # (dd if=/dev/zero of=/dev/sda AND dd of=/dev/sda if=/dev/zero). Anchored to a
    # COMMAND position (start / separator / wrapper / path prefix) so "echo dd
    # of=/dev/sda" (dd as data) does NOT match, and path-qualified /bin/dd DOES.
    # ... allowing an arbitrary run of wrapper words + their args/options before dd
    # (env -i dd ..., timeout 5 dd ..., taskset 0x1 dd ...). The wrapper run is
    # zero-or-more "<word> " repetitions where the FINAL word before dd may carry
    # options/args; we keep it broad (any tokens) but require dd at a token start.
    "(^|[;&|])[[:space:]]*((sudo|command|exec|nice|nohup|timeout|setsid|env|doas|ionice|chrt|taskset|stdbuf|arch|catchsegv|busybox|flock|time|watch)[[:space:]]+([^|;&]*[[:space:]]+)?)?([A-Za-z0-9_./-]*/)?dd[[:space:]].*of=/dev/"
    # mkfs in any spelling: mkfs.ext4, mkfs -t ext4, bare `mkfs /dev/sda1`,
    # and absolute paths (/sbin/mkfs.xfs). basename match, optional .fstype.
    # Anchored to a COMMAND position (start, after a separator/wrapper, or a
    # path prefix) so "echo mkfs is a tool" (mkfs as an argument) does NOT match.
    "(^|[;&|])[[:space:]]*((sudo|command|exec|nice|nohup|timeout|setsid|env|doas|ionice|chrt|taskset|stdbuf|arch|catchsegv|busybox|flock|time|watch)[[:space:]]+([^|;&]*[[:space:]]+)?)?([A-Za-z0-9_./-]*/)?mkfs(\.[a-zA-Z0-9]+)?([[:space:]]|$)"
    # Device-destroy tools (incl. shred): require a /dev/ operand so
    # `shred ./secret` and `shred /tmp/x` stay allow.
    "(^|[;&|])[[:space:]]*((sudo|command|exec|nice|nohup|timeout|setsid|env|doas|ionice|chrt|taskset|stdbuf|arch|catchsegv|busybox|flock|time|watch)[[:space:]]+([^|;&]*[[:space:]]+)?)?([A-Za-z0-9_./-]*/)?(fdisk|parted|gpart|sgdisk|wipefs|blkdiscard|shred)[[:space:]].*/dev/"
    # Fork bomb
    ":(){ :[|]:& };:"
    # Recursive chmod on protected roots (any mode, any flag order). Each
    # protected root is anchored to a command-word boundary BEFORE the leading
    # slash ((^|[[:space:]])) so a benign subpath like /tmp/usr or ./etc does NOT
    # match (the old pattern's bare "/" alternative matched the slash inside any
    # path). Catches: chmod -R 777 /var, chmod 777 -R /var, chmod --recursive 666 /usr.
    # The recursive flag may be a short-option CLUSTER with R anywhere in it
    # (-R, -Rf, -fR, -hR, -HR, -RP) or --recursive.
    "chmod[[:space:]]+.*(-[A-Za-z]*[R][A-Za-z]*|--recursive).*(^|[[:space:]])(/|/var|/etc|/usr|/bin|/sbin|/boot|/sys|/proc|/System|/Library|/private)([[:space:];&|)]|/|$)"
    # Recursive chown on protected roots (any owner, any flag order)
    "chown[[:space:]]+.*(-[A-Za-z]*[R][A-Za-z]*|--recursive).*(^|[[:space:]])(/|/var|/etc|/usr|/bin|/sbin|/boot|/sys|/proc|/System|/Library|/private)([[:space:];&|)]|/|$)"
    # Reverse shell
    "[|]&[[:space:]]*/dev/tcp/"
    # Pipe to shell - require explicit shell commands (sh|bash|zsh|dash)
    "curl[[:space:]].*[|][[:space:]]*((env|busybox)[[:space:]]+([^|;&]*[[:space:]]+)?)?([A-Za-z0-9_./-]*/)?(sh|bash|zsh|dash)([[:space:]]|$)"
    "wget[[:space:]].*[|][[:space:]]*((env|busybox)[[:space:]]+([^|;&]*[[:space:]]+)?)?([A-Za-z0-9_./-]*/)?(sh|bash|zsh|dash)([[:space:]]|$)"
    # find -delete on system directories (including subdirs like /var/log)
    # /opt moved to WARN tier (Homebrew/MacPorts)
    "find[[:space:]]+(/|/etc|/usr|/bin|/sbin|/var|/boot|/lib|/System|/Library|/private|/Volumes|~)([[:space:]]|/).*-delete"
    # find on a system dir with an -exec/-execdir/-ok/-okdir rm action (any rm
    # path: rm, /bin/rm, ./rm). This deletes system files just like -delete.
    "find[[:space:]]+(/|/etc|/usr|/bin|/sbin|/var|/boot|/lib|/System|/Library|/private|/Volumes|~)([[:space:]]|/).*-(exec|execdir|ok|okdir)[[:space:]]+([A-Za-z0-9_./-]*/)?rm([[:space:]]|$)"
    # find on a system dir with an -exec ... sh -c '<payload>' that contains rm:
    # the exec command is the shell, with rm inside the quoted string.
    "find[[:space:]]+(/|/etc|/usr|/bin|/sbin|/var|/boot|/lib|/System|/Library|/private|/Volumes|~)([[:space:]]|/).*-(exec|execdir|ok|okdir)[[:space:]]+([A-Za-z0-9_./-]*/)?(sh|bash|zsh|dash)[[:space:]].*[[:space:]]([A-Za-z0-9_./-]*/)?rm[[:space:]]+-[a-zA-Z]*[rRfF]"
)

# Build the text the dangerous-pattern greps scan. Beyond normalized_cmd we add:
#  (a) reserved-word command boundaries rewritten to ";" so a dangerous tool that
#      sits right after then/do/else/{ (e.g. "if true; then dd if=.. of=/dev/..")
#      is at a recognized command position; and
#  (b) the DECODED payloads of shell -c '...' and env -S '...' (extracted via the
#      quote-aware lexer), so "bash -c 'dd .. of=/dev/..'" and "env -S 'mkfs .."
#      are scanned too (the non-rm checks are otherwise regex-only on the surface
#      command and never saw inside the string).
# Fork bomb -- checked on the RAW normalized command BEFORE the grouping-rewrite
# below (that rewrite turns "(){ }" into ";" and would shred the fork-bomb shape).
# Match the classic ":(){ :|:& };:" and minor whitespace variants.
if printf '%s' "$normalized_cmd" | grep -Eq ':[[:space:]]*\([[:space:]]*\)[[:space:]]*\{.*:[[:space:]]*[|][[:space:]]*:.*&.*\}[[:space:]]*;[[:space:]]*:'; then
    log_security_event "BLOCKED" "fork_bomb" "$command"
    echo "❌ BLOCKED: fork bomb pattern: $command" >&2
    exit 2
fi

execution_scan_text="$normalized_cmd"
dangerous_scan_text="$execution_scan_text"
# (a) reserved-word and grouping command boundaries -> ";". Covers then/do/else/
# elif followed by space AND grouping chars ( { whether or not followed by space
# (so "(dd if=..", "if true; then(dd .." put dd at a command position), plus the
# matching close ) } -> ";" so a target before them is terminated.
dangerous_scan_text="$(printf '%s' "$dangerous_scan_text" | sed -E 's/(^|[[:space:]])(then|do|else|elif)[[:space:]]/\1; /g; s/[(){}]/ ; /g')"
# (b) append decoded shell-string / env -S payloads. Extraction is anchored to
# an actual shell/env command position; `echo -c "..."` is data, not code.
_append_execution_payload() {
    local payload="$1"
    execution_scan_text="$execution_scan_text"$'\n'"$payload"
    dangerous_scan_text="$dangerous_scan_text"$'\n'"$payload"
}
_dtoks=(); while IFS= read -r _dt; do _dtoks+=("$_dt"); done < <(tokenize_command "$normalized_cmd")
_d_cmdpos=1
_d_skip=0
for ((_di=0; _di<${#_dtoks[@]}; _di++)); do
    _dt="${_dtoks[$_di]}"
    case "$_dt" in
        ";"|"&&"|"||"|"|"|"|&"|"&"|"("|")"|"{"|"}"|then|do|else|elif|if|while|until|"!")
            _d_cmdpos=1
            continue
            ;;
    esac
    if [[ "$_d_skip" -eq 1 ]]; then
        _d_skip=0
        continue
    fi
    [[ "$_d_cmdpos" -eq 1 ]] || continue
    _dbase="${_dt##*/}"
    case "$_dbase" in
        sudo|command|exec|nice|nohup|setsid|doas|time)
            continue
            ;;
        timeout)
            _d_skip=1
            continue
            ;;
        sh|bash|zsh|dash)
            _dj=$((_di + 1))
            while [[ $_dj -lt ${#_dtoks[@]} ]]; do
                _dn="${_dtoks[$_dj]}"
                if shell_short_options_have_c "$_dn"; then
                    [[ $((_dj + 1)) -lt ${#_dtoks[@]} ]] && _append_execution_payload "${_dtoks[$((_dj + 1))]}"
                    break
                fi
                case "$_dn" in
                    ";"|"&&"|"||"|"|"|"|&"|"&") break ;;
                    -*o|+*o|-O|+O|--rcfile|--init-file) _dj=$((_dj + 2)); continue ;;
                    -*) _dj=$((_dj + 1)); continue ;;
                    *) break ;;
                esac
            done
            _d_cmdpos=0
            ;;
        env)
            _dj=$((_di + 1))
            while [[ $_dj -lt ${#_dtoks[@]} ]]; do
                _dn="${_dtoks[$_dj]}"
                _dnbase="${_dn##*/}"
                case "$_dn" in
                    -S)
                        [[ $((_dj + 1)) -lt ${#_dtoks[@]} ]] && _append_execution_payload "env ${_dtoks[$((_dj + 1))]}"
                        break ;;
                    --split-string=*)
                        _append_execution_payload "env ${_dn#--split-string=}"
                        break ;;
                    -u|--unset|-C|--chdir|-P) _dj=$((_dj + 2)); continue ;;
                    -*|[A-Za-z_][A-Za-z0-9_]*=*) _dj=$((_dj + 1)); continue ;;
                    *)
                        case "$_dnbase" in
                            sh|bash|zsh|dash)
                                _dk=$((_dj + 1))
                                while [[ $_dk -lt ${#_dtoks[@]} ]]; do
                                    _dn="${_dtoks[$_dk]}"
                                    if shell_short_options_have_c "$_dn"; then
                                        [[ $((_dk + 1)) -lt ${#_dtoks[@]} ]] && _append_execution_payload "${_dtoks[$((_dk + 1))]}"
                                        break
                                    fi
                                    case "$_dn" in
                                        ";"|"&&"|"||"|"|"|"|&"|"&") break ;;
                                        -*o|+*o|-O|+O|--rcfile|--init-file) _dk=$((_dk + 2)); continue ;;
                                        -*) _dk=$((_dk + 1)); continue ;;
                                        *) break ;;
                                    esac
                                done
                                ;;
                        esac
                        break
                        ;;
                esac
            done
            _d_cmdpos=0
            ;;
        [A-Za-z_][A-Za-z0-9_]*=*)
            continue
            ;;
        *)
            _d_cmdpos=0
            ;;
    esac
done

# Literal string runners and executor-contained shells also create a shell
# execution context. Add their payloads to the same scan text as direct `sh -c`.
_scan_tokens=("${_dtoks[@]}")
_d_cmdpos=1
for ((_di=0; _di<${#_dtoks[@]}; _di++)); do
    _dt="${_dtoks[$_di]}"
    case "$_dt" in
        ";"|"&&"|"||"|"|"|"|&"|"&"|"("|")"|"{"|"}"|then|do|else|elif|if|while|until|"!")
            _d_cmdpos=1
            continue
            ;;
    esac
    [[ "$_d_cmdpos" -eq 1 ]] || continue
    wrapped_command_index "$_di" "${#_dtoks[@]}"
    [[ "$_wrapped_index" -ge 0 ]] || { _d_cmdpos=0; continue; }
    _di="$_wrapped_index"
    _dt="${_dtoks[$_di]}"
    _dbase="${_dt##*/}"
    case "$_dbase" in
        sh|bash|zsh|dash)
            _dj=$((_di + 1))
            while [[ "$_dj" -lt "${#_dtoks[@]}" ]]; do
                _dn="${_dtoks[$_dj]}"
                if shell_short_options_have_c "$_dn"; then
                    [[ $((_dj + 1)) -lt ${#_dtoks[@]} ]] && _append_execution_payload "${_dtoks[$((_dj + 1))]}"
                    break
                fi
                case "$_dn" in
                    -*o|+*o|-O|+O|--rcfile|--init-file) _dj=$((_dj + 2)); continue ;;
                    -*) _dj=$((_dj + 1)); continue ;;
                    *) break ;;
                esac
            done
            ;;
        flock)
            _dj=$((_di + 1))
            _d_flock_target=0
            while [[ "$_dj" -lt "${#_dtoks[@]}" ]]; do
                _dn="${_dtoks[$_dj]}"
                case "$_dn" in
                    ";"|"&&"|"||"|"|"|"|&"|"&") break ;;
                esac
                if [[ "$_d_flock_target" -eq 0 ]]; then
                    case "$_dn" in
                        -w|--timeout|-E|--conflict-exit-code) _dj=$((_dj + 2)); continue ;;
                        --timeout=*|--conflict-exit-code=*|-s|--shared|-x|--exclusive|-u|--unlock|-n|--nonblock|-o|--close|-F|--no-fork|--verbose)
                            _dj=$((_dj + 1)); continue ;;
                        --) _dj=$((_dj + 1)); continue ;;
                        -*) _dj=$((_dj + 1)); continue ;;
                        *) _d_flock_target=1; _dj=$((_dj + 1)); continue ;;
                    esac
                fi
                case "$_dn" in
                    -c|--command)
                        [[ $((_dj + 1)) -lt ${#_dtoks[@]} ]] && _append_execution_payload "${_dtoks[$((_dj + 1))]}"
                        break ;;
                    --command=*) _append_execution_payload "${_dn#--command=}"; break ;;
                    *) break ;;
                esac
                _dj=$((_dj + 1))
            done
            ;;
        watch)
            _dj=$((_di + 1))
            _d_watch_payload=""
            while [[ "$_dj" -lt "${#_dtoks[@]}" ]]; do
                _dn="${_dtoks[$_dj]}"
                case "$_dn" in
                    ";"|"&&"|"||"|"|"|"|&"|"&") break ;;
                esac
                if [[ -z "$_d_watch_payload" ]]; then
                    case "$_dn" in
                        -n|--interval) _dj=$((_dj + 2)); continue ;;
                        --interval=*|-n?*|--color|--no-color|-b|--beep|-d|--differences|-e|--errexit|-g|--chgexit|-p|--precise|-t|--no-title|-x|--exec)
                            _dj=$((_dj + 1)); continue ;;
                        --) _dj=$((_dj + 1)); continue ;;
                        -*) _dj=$((_dj + 1)); continue ;;
                    esac
                    _d_watch_payload="$_dn"
                else
                    _d_watch_payload="$_d_watch_payload $_dn"
                fi
                _dj=$((_dj + 1))
            done
            [[ -n "$_d_watch_payload" ]] && _append_execution_payload "$_d_watch_payload"
            ;;
        find)
            _dj=$((_di + 1))
            while [[ "$_dj" -lt "${#_dtoks[@]}" ]]; do
                _dn="${_dtoks[$_dj]}"
                case "$_dn" in
                    ";"|"&&"|"||"|"|"|"|&"|"&") break ;;
                    -exec|-execdir|-ok|-okdir)
                        _dk=$((_dj + 1))
                        _d_end="$_dk"
                        while [[ "$_d_end" -lt "${#_dtoks[@]}" ]]; do
                            case "${_dtoks[$_d_end]}" in ";"|"+") break ;; esac
                            _d_end=$((_d_end + 1))
                        done
                        wrapped_command_index "$_dk" "$_d_end"
                        if [[ "$_wrapped_index" -ge 0 ]]; then
                            _dk="$_wrapped_index"
                            _dnbase="${_dtoks[$_dk]##*/}"
                            case "$_dnbase" in
                                sh|bash|zsh|dash)
                                    _dk=$((_dk + 1))
                                    while [[ "$_dk" -lt "$_d_end" ]]; do
                                        _dn="${_dtoks[$_dk]}"
                                        if shell_short_options_have_c "$_dn"; then
                                            [[ $((_dk + 1)) -lt "$_d_end" ]] && _append_execution_payload "${_dtoks[$((_dk + 1))]}"
                                            break
                                        fi
                                        case "$_dn" in
                                            -*o|+*o|-O|+O|--rcfile|--init-file) _dk=$((_dk + 2)); continue ;;
                                            -*) _dk=$((_dk + 1)); continue ;;
                                            *) break ;;
                                        esac
                                    done
                                    ;;
                            esac
                        fi
                        _dj="$_d_end"
                        ;;
                esac
                _dj=$((_dj + 1))
            done
            ;;
    esac
    _d_cmdpos=0
done
unset -f _append_execution_payload
unset _scan_tokens _wrapped_index _dtoks _d_cmdpos _d_skip _di _dt _dbase _dj _dn _dnbase _dk _d_end
unset _d_watch_payload _d_flock_target
# (c) append a quote/backslash-stripped copy when quotes/backslashes are present,
# so a command word obscured by them (d"d" -> dd, mk"fs" -> mkfs, \dd) is matched
# by the literal dangerous-pattern greps. Only pay the strip when needed.
case "$dangerous_scan_text" in
    *\\*|*\"*|*\'*)
        _dst_stripped="${dangerous_scan_text//\\/}"; _dst_stripped="${_dst_stripped//\"/}"; _dst_stripped="${_dst_stripped//\'/}"
        dangerous_scan_text="$dangerous_scan_text"$'\n'"$_dst_stripped" ;;
esac

for pattern in "${dangerous_patterns[@]}"; do
    if echo "$dangerous_scan_text" | grep -E "$pattern" &>/dev/null; then
        log_security_event "BLOCKED" "$pattern" "$command"
        echo "❌ BLOCKED: Dangerous command pattern: $command" >&2
        echo "   Pattern matched: $pattern" >&2
        exit 2
    fi
done

# Clobber/append redirect to a critical system path.
# Covers `: > /etc/passwd`, `true >/etc/shadow`, `>> /etc/hosts`, `>| /var/...`.
# The dedicated extractor preserves operator quote provenance, unlike the
# general command tokenizer: `echo '>' /etc/passwd` is data, while `>&/etc/passwd`
# is an actual redirect. Targets are quote-decoded and lexically normalized.
# shellcheck disable=SC2016 # awk program
OUTPUT_REDIRECT_TARGETS_AWK='
function literal_marker(c) {
  if (c == "$") return "__NOSYNC_LITERAL_DOLLAR__"
  if (c == "~") return "__NOSYNC_LITERAL_TILDE__"
  if (c == "*") return "__NOSYNC_LITERAL_STAR__"
  if (c == "?") return "__NOSYNC_LITERAL_QUESTION__"
  if (c == "[") return "__NOSYNC_LITERAL_BRACKET__"
  if (c == "{") return "__NOSYNC_LITERAL_BRACE__"
  return c
}
function emit_target(j,   c,nx,q,w) {
  while (j <= nch && (CH[j] == " " || CH[j] == "\t" || CH[j] == "\r" || CH[j] == "\n")) j++
  q = ""; w = ""
  while (j <= nch) {
    c = CH[j]
    if (q != "") {
      if (q == "\047" && index("$~*?[{", c) != 0) { w = w literal_marker(c); j++; continue }
      if (q == "\042" && c == "\\") {
        nx = (j < nch) ? CH[j+1] : ""
        if (index("$~*?[{", nx) != 0) { w = w literal_marker(nx); j += 2; continue }
        if (nx == "`" || nx == "\042" || nx == "\\") { w = w nx; j += 2; continue }
      }
      if (q == "\042" && c == "{" && CH[j-1] == "$") { w = w c; j++; continue }
      if (q == "\042" && index("~*?[{", c) != 0) { w = w literal_marker(c); j++; continue }
      if (c == q) q = ""; else w = w c
      j++; continue
    }
    if (c == "\047" || c == "\042") { q = c; j++; continue }
    if (c == "\\") {
      if (j < nch && index("$~*?[{", CH[j+1]) != 0) { w = w literal_marker(CH[j+1]); j += 2 }
      else if (j < nch) { w = w CH[j+1]; j += 2 }
      else j++
      continue
    }
    if (c == " " || c == "\t" || c == "\r" || c == "\n" || c == ";" || c == "|" || c == "&" || c == "(" || c == ")") break
    w = w c; j++
  }
  if (w != "") print w
  return j
}
BEGIN { RS = "\0" }
{
  nch = split($0, CH, ""); i = 1; q = ""; in_cond = 0; in_arith = 0
  while (i <= nch) {
    c = CH[i]
    if (in_cond) {
      if (c == "]" && i < nch && CH[i+1] == "]") { in_cond = 0; i += 2 } else i++
      continue
    }
    if (in_arith) {
      if (c == ")" && i < nch && CH[i+1] == ")") { in_arith = 0; i += 2 } else i++
      continue
    }
    if (q != "") {
      if (q == "\042" && c == "\\") { i += 2; continue }
      if (c == q) q = ""
      i++; continue
    }
    if (c == "\047" || c == "\042") { q = c; i++; continue }
    if (c == "\\") { i += 2; continue }
    if (c == "$" && i < nch && CH[i+1] == "{") {
      depth = 1; i += 2
      while (i <= nch && depth > 0) {
        if (CH[i] == "\\") { i += 2; continue }
        if (CH[i] == "{") depth++
        else if (CH[i] == "}") depth--
        i++
      }
      continue
    }
    if (c == "$" && i+2 <= nch && CH[i+1] == "(" && CH[i+2] == "(") {
      i += 3
      while (i+1 <= nch && !(CH[i] == ")" && CH[i+1] == ")")) i++
      i += 2
      continue
    }
    prev = (i == 1) ? " " : CH[i-1]
    boundary = (prev == " " || prev == "\t" || prev == "\r" || prev == "\n" || prev == ";" || prev == "&" || prev == "|" || prev == "(" || prev == ")" || prev == "{" || prev == "}")
    if (c == "#" && boundary) {
      while (i <= nch && CH[i] != "\n") i++
      continue
    }
    if (c == "[" && i < nch && CH[i+1] == "[" && boundary) { in_cond = 1; i += 2; continue }
    if (c == "(" && i < nch && CH[i+1] == "(" && boundary) { in_arith = 1; i += 2; continue }
    if (c == "&" && i < nch && CH[i+1] == ">") {
      j = i + 2
      if (j <= nch && CH[j] == ">") j++
      i = emit_target(j); continue
    }
    if (c == ">") {
      j = i + 1
      if (j <= nch && (CH[j] == ">" || CH[j] == "|")) j++
      if (j <= nch && CH[j] == "&") {
        nx = (j < nch) ? CH[j+1] : ""
        if (nx ~ /[0-9-]/) { i = j + 2; continue }
        j++
      }
      i = emit_target(j); continue
    }
    i++
  }
}'
extract_output_redirect_targets() { printf '%s' "$1" | awk "$OUTPUT_REDIRECT_TARGETS_AWK"; }

{
    while IFS= read -r _redir_target; do
        if is_critical_system_path "$_redir_target"; then
            log_security_event "BLOCKED" "critical_path_redirect" "$command"
            echo "❌ BLOCKED: Redirect into critical system path: $command" >&2
            exit 2
        fi
    done < <(extract_output_redirect_targets "$execution_scan_text")
    unset _redir_target
}

# Check for operations in critical system directories
# Require directory targeting: space or / after dirname (blocks /etc but not /etc-backup)
# Verbs: rm/mv/cp (classic) plus truncate (zero a critical file) and shred (secure-
# erase a critical path that is not a raw device — devices are blocked above).
#
# First use the quote-aware tokenizer for direct, grouped, and decoded shell
# payload truncate/shred commands. This catches path-qualified verbs and quoted
# paths without treating `echo "truncate /etc/passwd"` as execution.
{
    _crit_toks=()
    _crit_source="$(protect_literal_parameter_dollars "$execution_scan_text")"
    while IFS= read -r _ct; do _crit_toks+=("$_ct"); done < <(tokenize_command "$_crit_source")
    _scan_tokens=("${_crit_toks[@]}")
    _crit_cmdpos=1
    _crit_active=0
    _crit_skip=0
    for ((_ci=0; _ci<${#_crit_toks[@]}; _ci++)); do
        _ct="${_crit_toks[$_ci]}"
        case "$_ct" in
            ";"|"&&"|"||"|"|"|"|&"|"&"|"("|")"|"{"|"}"|then|do|else|elif|if|while|until|"!")
                _crit_cmdpos=1
                _crit_active=0
                _crit_skip=0
                continue
                ;;
        esac
        if [[ "$_crit_skip" -eq 1 ]]; then
            _crit_skip=0
            continue
        fi
        if [[ "$_crit_cmdpos" -eq 1 ]]; then
            wrapped_command_index "$_ci" "${#_crit_toks[@]}"
            for _wrapped_target in "${_wrapped_write_targets[@]}"; do
                if is_critical_system_path "$_wrapped_target"; then
                    log_security_event "BLOCKED" "wrapper_output_critical_path" "$command"
                    echo "❌ BLOCKED: Wrapper output targets a critical system path: $command" >&2
                    exit 2
                fi
            done
            if [[ "$_wrapped_index" -lt 0 ]]; then
                _crit_cmdpos=0
                continue
            fi
            _ci="$_wrapped_index"
            _ct="${_crit_toks[$_ci]}"
            _cbase="${_ct##*/}"
            if brace_word_is_critical_verb "$_ct"; then
                _crit_active=1
                _crit_cmdpos=0
                continue
            fi
            case "$_cbase" in
                truncate|shred)
                    _crit_active=1
                    _crit_cmdpos=0
                    continue
                    ;;
                *)
                    _crit_cmdpos=0
                    ;;
            esac
        elif [[ "$_crit_active" -eq 1 ]]; then
            case "$_ct" in
                -r|--reference)
                    _crit_skip=1
                    continue
                    ;;
                --reference=*)
                    continue
                    ;;
                --random-source|-s|--size|-n|--iterations)
                    if [[ "$_cbase" == "shred" ]]; then
                        _crit_skip=1
                        continue
                    fi
                    ;;
                --random-source=*|--size=*|--iterations=*)
                    [[ "$_cbase" == "shred" ]] && continue
                    ;;
            esac
            if is_critical_system_path "$_ct"; then
                log_security_event "BLOCKED" "critical_directory_operation" "$command"
                echo "❌ BLOCKED: Operation on critical system directory: $command" >&2
                exit 2
            fi
        fi
    done
    unset _scan_tokens _wrapped_index _wrapped_cwds _wrapped_write_targets _wrapped_target
    unset _crit_source _crit_toks _crit_cmdpos _crit_active _crit_skip _ci _ct _cbase
}

# The legacy regex remains authoritative for rm/mv/cp. truncate/shred use the
# operand-aware token path above so read-only options such as --reference do not
# turn their source path into a false write target.
critical_dirs_pattern="(^|[;&|])[[:space:]]*((sudo|command|exec|nice|nohup|timeout|setsid|env|doas)[[:space:]]+([^;&|]*[[:space:]]+)?)?([A-Za-z0-9_./-]*/)?(rm|mv|cp)[[:space:]]+([^;&|[:space:]]+[[:space:]]+)*(/etc|/bin|/sbin|/usr|/var|/private|/System|/Library|/Applications|/opt|/Volumes|/dev|/boot|/sys|/proc)([[:space:]]|/|$)"
if echo "$normalized_cmd" | grep -E "$critical_dirs_pattern" &>/dev/null; then
    # Exception: allow if clearly in a subpath (e.g., ./usr/bin in a project)
    if ! echo "$normalized_cmd" | grep -E "(^|[[:space:]])/(etc|bin|sbin|usr|var|private|System|Library|Applications|opt|Volumes|dev|boot|sys|proc)([[:space:]]|/|$)" &>/dev/null; then
        : # Relative path, allow
    else
        log_security_event "BLOCKED" "critical_directory_operation" "$command"
        echo "❌ BLOCKED: Operation on critical system directory: $command" >&2
        exit 2
    fi
fi

# =============================================================================
# CWD-CHANGING COMPOUND COMMANDS
# =============================================================================
#
# Relative rm operands are canonicalized against the HOOK's cwd, not the command's
# runtime cwd. So "cd / && rm -rf etc" deletes /etc, but the operand "etc"
# resolves under the (safe) repo cwd here and is ALLOWED. Walk the segments in
# order, track the effective cwd from each cd/pushd, and re-resolve relative rm,
# truncate/shred, and output-redirect targets against it.
# True if a lexical absolute path equals or is under a catastrophic/critical root
# (the same roots the literal-string greps protect: deleting anything under /usr,
# /etc, /bin, ... is catastrophic). Covers what is_catastrophic (exact-root +
# direct-child-of-/) does NOT: deep critical paths like /usr/bin, /var/log.
is_under_catastrophic_root() {
    local p="$1"
    case "$p" in
        /|/Users|/System|/Library|/Applications|/bin|/sbin|/usr|/etc|/var|/boot|/proc|/sys|/lib|/private|/cores|/dev|/opt) return 0 ;;
        /Users/*|/System/*|/Library/*|/Applications/*|/bin/*|/sbin/*|/usr/*|/etc/*|/var/*|/boot/*|/proc/*|/sys/*|/lib/*|/private/*|/cores/*|/dev/*|/opt/*) return 0 ;;
    esac
    # $HOME and anything directly under it (rm of a top-level home dir).
    [[ "$p" == "$HOME" ]] && return 0
    return 1
}

is_relative_write_critical() {
    local p="$1" safe_status
    is_literal_critical_system_path "$p" || return 1
    safe_status="$(check_safe_root_status "$p")"
    case "$safe_status" in under|equals_root:*) return 1 ;; esac
    return 0
}

scan_cd_relative_rm() {
    local nc="$1" depth="${2:-0}" initial_cwd="${3:-$PWD}"
    [[ "$depth" -gt 4 ]] && { echo "ask"; return 0; }

    local eff_cwd="$initial_cwd" cwd_known=true cwd_changed=false seg
    local cwd_stack=() known_stack=() changed_stack=() stack_i
    local group_cwd_stack=() group_known_stack=() group_changed_stack=()
    local seg_base_cwd="$initial_cwd" seg_base_known=true seg_base_changed=false
    while IFS= read -r seg; do
        [[ -z "$seg" ]] && continue
        if [[ "$seg" == "__NOSYNC_CWD_RESET__" ]]; then
            eff_cwd="$seg_base_cwd"
            cwd_known="$seg_base_known"
            cwd_changed="$seg_base_changed"
            continue
        fi
        if [[ "$seg" == "__NOSYNC_SUBSHELL_OPEN__" ]]; then
            cwd_stack+=("$eff_cwd")
            known_stack+=("$cwd_known")
            changed_stack+=("$cwd_changed")
            continue
        fi
        if [[ "$seg" == "__NOSYNC_SUBSHELL_CLOSE__" ]]; then
            stack_i=$((${#cwd_stack[@]} - 1))
            if [[ "$stack_i" -ge 0 ]]; then
                eff_cwd="${cwd_stack[$stack_i]}"
                cwd_known="${known_stack[$stack_i]}"
                cwd_changed="${changed_stack[$stack_i]}"
                unset 'cwd_stack[$stack_i]' 'known_stack[$stack_i]' 'changed_stack[$stack_i]'
                seg_base_cwd="$eff_cwd"
                seg_base_known="$cwd_known"
                seg_base_changed="$cwd_changed"
            fi
            continue
        fi
        if [[ "$seg" == "__NOSYNC_GROUP_OPEN__" ]]; then
            group_cwd_stack+=("$eff_cwd")
            group_known_stack+=("$cwd_known")
            group_changed_stack+=("$cwd_changed")
            continue
        fi
        if [[ "$seg" == "__NOSYNC_GROUP_CLOSE__" ]]; then
            stack_i=$((${#group_cwd_stack[@]} - 1))
            if [[ "$stack_i" -ge 0 ]]; then
                seg_base_cwd="${group_cwd_stack[$stack_i]}"
                seg_base_known="${group_known_stack[$stack_i]}"
                seg_base_changed="${group_changed_stack[$stack_i]}"
                unset 'group_cwd_stack[$stack_i]' 'group_known_stack[$stack_i]' 'group_changed_stack[$stack_i]'
            fi
            continue
        fi
        seg_base_cwd="$eff_cwd"
        seg_base_known="$cwd_known"
        seg_base_changed="$cwd_changed"
        local toks=() tk
        while IFS= read -r tk; do toks+=("$tk"); done < <(tokenize_command "$seg")
        [[ ${#toks[@]} -eq 0 ]] && continue
        local _cmd_i=0
        while [[ "$_cmd_i" -lt "${#toks[@]}" ]]; do
            case "${toks[$_cmd_i]}" in
                then|do|else|elif|if|while|until|"!"|"{"|"(") _cmd_i=$((_cmd_i + 1)) ;;
                *) break ;;
            esac
        done
        _scan_tokens=("${toks[@]}")
        wrapped_command_index "$_cmd_i" "${#toks[@]}"
        local op_cwd="$eff_cwd" op_known="$cwd_known" op_changed="$cwd_changed"
        local _wrapped_cwd
        for _wrapped_cwd in "${_wrapped_cwds[@]}"; do
            op_changed=true
            if has_shell_expansion "$_wrapped_cwd"; then
                op_known=false
            elif [[ "$_wrapped_cwd" == /* ]]; then
                lexical_normalize_into "$_wrapped_cwd"
                op_cwd="$_lexical_result"
            elif [[ "$op_known" == true ]]; then
                lexical_normalize_into "$op_cwd/$_wrapped_cwd"
                op_cwd="$_lexical_result"
            else
                op_known=false
            fi
        done
        _cmd_i="$_wrapped_index"
        [[ "$_cmd_i" -ge 0 ]] || { unset _scan_tokens _wrapped_index; continue; }
        local w0="${toks[$_cmd_i]}"

        # Recurse into a shell -c payload: "bash -c 'cd / && rm -rf etc'".
        case "$w0" in
            sh|bash|zsh|dash|/bin/sh|/bin/bash|/bin/zsh|/bin/dash|/usr/bin/*sh)
                local ci=$((_cmd_i + 1))
                while [[ $ci -lt ${#toks[@]} ]]; do
                    if shell_short_options_have_c "${toks[$ci]}"; then
                        if [[ $((ci+1)) -lt ${#toks[@]} ]]; then
                            local sub
                            sub=$(scan_cd_relative_rm "${toks[$((ci+1))]}" $((depth+1)) "$op_cwd")
                            [[ -n "$sub" ]] && { echo "$sub"; return 0; }
                        fi
                        break
                    fi
                    case "${toks[$ci]}" in
                        -*o|+*o|-O|+O|--rcfile|--init-file) ci=$((ci+2)); continue ;;
                        -*) ((ci++)); continue ;;
                        *) break ;;
                    esac
                done
                ;;
        esac

        if [[ "$w0" == "cd" || "$w0" == "pushd" ]]; then
            cwd_changed=true
            local ti=$((_cmd_i + 1)) target=""
            while [[ $ti -lt ${#toks[@]} ]]; do
                case "${toks[$ti]}" in
                    -*) ((ti++)); continue ;;
                    *) target="${toks[$ti]}"; break ;;
                esac
            done
            if [[ -z "$target" ]]; then
                eff_cwd="$HOME"; cwd_known=true
            elif has_shell_expansion "$target"; then
                cwd_known=false      # dynamic cd target -> unknown cwd
            elif [[ "$target" == /* ]]; then
                eff_cwd="$target"; cwd_known=true
            elif [[ "$target" == "~"* ]]; then
                eff_cwd="${target/#\~/$HOME}"; cwd_known=true
            elif [[ "$cwd_known" == true ]]; then
                lexical_normalize_into "$eff_cwd/$target"
                eff_cwd="$_lexical_result"
            else
                cwd_known=false      # relative cd from an unknown base
            fi
            continue
        fi

        # Output redirects and truncate/shred operands are path-sensitive too.
        local target joined
        for target in "${_wrapped_write_targets[@]}"; do
            if [[ "$target" == /* ]]; then
                is_critical_system_path "$target" && { echo "deny:$target (wrapper output)"; return 0; }
            elif ! has_shell_expansion "$target" && [[ "$op_known" == true ]]; then
                lexical_normalize_into "$op_cwd/$target"
                joined="$_lexical_result"
                is_relative_write_critical "$joined" && { echo "deny:$target (wrapper output under $op_cwd) → $joined"; return 0; }
            fi
        done
        while IFS= read -r target; do
            [[ -z "$target" || "$target" == /* ]] && continue
            has_shell_expansion "$target" && continue
            if [[ "$op_known" == true ]]; then
                lexical_normalize_into "$op_cwd/$target"
                joined="$_lexical_result"
                if is_relative_write_critical "$joined"; then
                    echo "deny:$target (redirect under cwd $op_cwd) → $joined"; return 0
                fi
            elif [[ "/$target/" == *"/../"* ]]; then
                echo "ask"; return 0
            fi
        done < <(extract_output_redirect_targets "$seg")

        local _cw_i _cw_base _cw_skip=0
        _cw_i="$_cmd_i"
        if [[ "$_cw_i" -ge 0 ]]; then
            _cw_base="${toks[$_cw_i]##*/}"
            case "$_cw_base" in
                truncate|shred)
                    _cw_i=$((_cw_i + 1))
                    while [[ "$_cw_i" -lt "${#toks[@]}" ]]; do
                        target="${toks[$_cw_i]}"
                        if [[ "$_cw_skip" -eq 1 ]]; then
                            _cw_skip=0
                            _cw_i=$((_cw_i + 1))
                            continue
                        fi
                        case "$_cw_base:$target" in
                            truncate:-r|truncate:--reference|truncate:-s|truncate:--size)
                                _cw_skip=1; _cw_i=$((_cw_i + 1)); continue ;;
                            truncate:--reference=*|truncate:--size=*|shred:--random-source=*|shred:--size=*|shred:--iterations=*)
                                _cw_i=$((_cw_i + 1)); continue ;;
                            shred:--random-source|shred:-s|shred:--size|shred:-n|shred:--iterations)
                                _cw_skip=1; _cw_i=$((_cw_i + 1)); continue ;;
                            *:-*) _cw_i=$((_cw_i + 1)); continue ;;
                        esac
                        if [[ "$target" != /* ]] && ! has_shell_expansion "$target" && [[ "$op_known" == true ]]; then
                            lexical_normalize_into "$op_cwd/$target"
                            joined="$_lexical_result"
                            if is_relative_write_critical "$joined"; then
                                echo "deny:$target ($_cw_base under cwd $op_cwd) → $joined"; return 0
                            fi
                        fi
                        _cw_i=$((_cw_i + 1))
                    done
                    ;;
            esac
        fi
        unset _scan_tokens _wrapped_index

        # An rm -rf segment: re-resolve its relative operands against eff_cwd.
        if [[ "$op_changed" == true ]] && has_rf_flags "$seg"; then
            local ops=() op
            while IFS= read -r op; do [[ -n "$op" ]] && ops+=("$op"); done < <(parse_rm_operands "$seg")
            for op in "${ops[@]}"; do
                case "$op" in
                    /*|"~"|"~"/*) continue ;;   # absolute: normal path handles it
                esac
                has_shell_expansion "$op" && continue   # handled elsewhere
                if [[ "$op_known" == true ]]; then
                    # Resolve the operand against the effective cwd LEXICALLY (no
                    # symlink resolution, which would turn /etc into /private/etc
                    # and miss the match). cd targets are absolute by construction
                    # here (a relative cd left cwd_known=false).
                    local joined
                    joined=$(lexical_normalize "$op_cwd/$op")
                    if is_under_catastrophic_root "$joined"; then
                        echo "deny:$op (under cwd $op_cwd) → $joined"; return 0
                    fi
                else
                    # cwd changed to something we cannot resolve; a ..-traversal
                    # operand could escape to anywhere -> fail safe.
                    case "/$op/" in
                        *"/../"*) echo "ask"; return 0 ;;
                    esac
                fi
            done
        fi
    done < <(printf '%s' "$nc" | awk "$SEGMENT_AWK")
    return 1
}

if [ "${NOSYNC_OVERSIZED_NO_RM:-0}" != "1" ]; then
    cd_rm_result="$(scan_cd_relative_rm "$execution_scan_text")"
    case "$cd_rm_result" in
        deny:*)
            log_security_event "BLOCKED" "cd_relative_critical_path" "$command"
            echo "❌ BLOCKED: relative destructive target resolves to a critical path after cd" >&2
            echo "   Command: $command" >&2
            echo "   Target: ${cd_rm_result#deny:}" >&2
            exit 2
            ;;
        ask)
            log_security_event "ASK" "cd_relative_path_dynamic" "$command"
            echo "⚠️  CONFIRMATION REQUIRED: destructive relative path after a cwd change that cannot be resolved" >&2
            echo "   Command: $command" >&2
            exit 1
            ;;
    esac
fi

# =============================================================================
# EXPANSION-OBSCURED rm COMMAND WORD (brace expansion)
# =============================================================================
#
# Brace expansion can ASSEMBLE the rm command word from text that contains no
# literal "rm" token: "r{m,} -rf /" expands to "rm r -rf /" and "{rm,echo} -rf /"
# expands to "rm -rf /" / "echo -rf /". The tokenizer/normalizer only recognize a
# literal rm word, so these slip past has_rf_flags entirely. We cannot fully
# evaluate brace expansion, but we CAN expand the first command word of each
# segment's simple comma groups and check whether any alternative yields the
# command word "rm". This avoids the previous over-broad shape match that
# false-DENIED benign words like br{m,avo} or fo{r,m} (neither expands to rm).
# brace_word_can_be_rm WORD -> 0 if some expansion of WORD has basename rm.
brace_word_can_be_rm() {
    local w="$1"
    case "$w" in *"{"*) : ;; *) return 1 ;; esac   # no brace at all: not our case
    # Use bash's OWN brace expansion (exact for comma groups, {a..b} sequences,
    # and nesting) by expanding the word in an ARRAY-assignment context. This
    # NEVER executes a command. To keep it a pure string operation we first reject
    # any word containing a shell-active metacharacter other than braces/commas/
    # dots/word-chars/slashes/dashes -- so $, `, (), ;, &, |, <, >, *, ?, [, !,
    # whitespace, and quotes can never be present, leaving brace expansion as the
    # only thing eval can do. A rejected word is conservatively treated as "could
    # be rm" only if it still pattern-suggests rm (handled by the caller's flag
    # check); here we simply bail to "not our case" since such words are rare and
    # the literal-rm detector covers the common forms.
    # TRI-STATE return: 0 = an expansion is exactly "rm" (DENY/ASK by caller);
    # 2 = UNSAFE -- the brace word also contains a shell-active metacharacter
    # ($ ` ( ) glob ...), so it could expand to rm via a path we will NOT eval
    # (e.g. "r{$(echo m),}" -> bash expands the brace, THEN the cmd-sub, to "rm");
    # the caller must fail safe (ASK). 1 = cannot be rm.
    case "$w" in
        *'$'*|*'`'*|*'('*|*')'*|*';'*|*'&'*|*'|'*|*'<'*|*'>'*|*' '*|*'	'*|*'*'*|*'?'*|*'['*|*']'*|*'!'*|*'"'*|*"'"*|*'\'*)
            return 2 ;;
    esac
    # PRE-BOUND the expansion size BEFORE eval (eval expands eagerly, so
    # "r{a,b}{a,b}...x21" is 2^21 strings and would hang past the 2s timeout =
    # FAIL OPEN). Cheaply estimate the product of comma-group cardinalities and
    # sequence widths; if it could exceed the cap, fail SAFE (could be rm) without
    # evaluating. Counting commas is an over-estimate (fine -- conservative).
    local ncommas nopen
    ncommas=$(printf '%s' "$w" | tr -cd ',' | wc -c)
    nopen=$(printf '%s' "$w" | tr -cd '{' | wc -c)
    # A word with many comma-groups or many braces can blow up multiplicatively.
    if [[ "$ncommas" -gt 8 || "$nopen" -gt 12 ]]; then
        return 0   # fail safe: too large to expand, treat as could-be-rm
    fi
    brace_ranges_too_large "$w" && return 0
    local expanded item
    eval "expanded=($w)" 2>/dev/null || return 1
    # Safety bound: a huge expansion (e.g. {1..100000}) -> fail SAFE (could be rm).
    [[ ${#expanded[@]} -gt 1024 ]] && return 0
    for item in "${expanded[@]}"; do
        case "${item##*/}" in rm) return 0 ;; esac
    done
    return 1
}

# Find the first COMMAND WORD of a brace segment, skipping leading wrapper words
# (sudo/env/nice/...) and assignments, and stripping any leading-redirect prefix,
# so "env r{m,} -rf /" and "nice r{m,} -rf /" are examined at the real command
# word. Echoes the candidate command word (may be empty).
brace_first_cmd_word() {
    local seg="$1" tok rest="$1"
    while [[ -n "$rest" ]]; do
        tok="${rest%%[[:space:]]*}"
        local tb="${tok##*/}"
        case "$tb" in
            sudo|doas|env|command|exec|nice|nohup|setsid|stdbuf|timeout|ionice|chrt|taskset|arch|catchsegv|watch|flock|busybox|time)
                : ;;   # wrapper word: skip it
            *)
                case "$tok" in
                    *=*) : ;;          # leading assignment: skip
                    -*) : ;;           # an option to a preceding wrapper: skip
                    *) printf '%s' "$tok"; return ;;   # real command word
                esac ;;
        esac
        # advance past this token + following whitespace
        local nrest="${rest#"$tok"}"
        nrest="${nrest#"${nrest%%[![:space:]]*}"}"
        [[ "$nrest" == "$rest" ]] && break
        rest="$nrest"
    done
    printf ''
}

if [ "${NOSYNC_OVERSIZED_NO_RM:-0}" != "1" ]; then
    # Per segment: if the first real COMMAND WORD (after skipping wrapper words)
    # uses brace expansion that CAN expand to rm, and the segment carries an
    # rm-style -r/-f flag, fail safe -- DENY if a literal catastrophic target is
    # present, else ASK. ${IFS} is already neutralized in normalized_cmd above.
    # NOTE: bash -c '...' / env -S '...' payloads are normalized into the rm path
    # by normalize_rm_command, so a brace rm inside a -c payload is caught by the
    # has_rf_flags / validate_rm_rf logic below after this block.
    brace_seg_hit=0
    brace_hit_text=""
    while IFS= read -r bseg; do
        [[ -z "$bseg" ]] && continue
        case "$bseg" in *"{"*"}"*|*"{"*".."*"}"*) : ;; *) continue ;; esac
        # A bash -c '<payload>' / env -S '<payload>' whose PAYLOAD assembles rm via
        # brace expansion: the payload is ONE token after our quote-aware lexer
        # (so spaces inside it are preserved). Pull it out and check it directly
        # (normalize_rm_command cannot see a non-literal rm). Only bother if the
        # segment actually has a -c/-S form and a brace.
        case "$bseg" in
            *"-c "*|*"-c'"*|*'-c"'*|*"-S "*|*"--split-string="*|*"-lc "*|*"-ic "*)
                bpayload=""
                _btoks=(); while IFS= read -r _bt; do _btoks+=("$_bt"); done < <(tokenize_command "$bseg")
                for ((_bi=0; _bi<${#_btoks[@]}; _bi++)); do
                    case "${_btoks[$_bi]}" in
                        -*c|-S) [[ $((_bi+1)) -lt ${#_btoks[@]} ]] && bpayload="${_btoks[$((_bi+1))]}"; break ;;
                        --split-string=*) bpayload="${_btoks[$_bi]#--split-string=}"; break ;;
                    esac
                done
                if [[ -n "$bpayload" ]]; then
                    case "$bpayload" in *"{"*)
                        pw="$(brace_first_cmd_word "$bpayload")"
                        if [[ -n "$pw" ]]; then
                            brace_word_can_be_rm "$pw"; _bc=$?
                            if { [[ "$_bc" -eq 0 ]] || [[ "$_bc" -eq 2 ]]; } && printf '%s' "$bpayload" | grep -Eq '[[:space:]]-[a-zA-Z]*[rRfF]'; then
                                brace_seg_hit=1; brace_hit_text="$bpayload"; break
                            fi
                        fi ;;
                    esac
                fi ;;
        esac
        bword="$(brace_first_cmd_word "$bseg")"
        [[ -z "$bword" ]] && continue
        # 0 = expands to rm; 2 = brace word with shell-active metachar (could be rm
        # via a path we won't eval). Both fail safe; 1 = cannot be rm.
        brace_word_can_be_rm "$bword"; _bc=$?
        [[ "$_bc" -eq 0 || "$_bc" -eq 2 ]] || continue
        # must also carry an -r/-f flag somewhere in the segment
        printf '%s' "$bseg" | grep -Eq '[[:space:]]-[a-zA-Z]*[rRfF]' || continue
        brace_seg_hit=1
        brace_hit_text="$bseg"
        break
    done < <(printf '%s' "$normalized_cmd" | awk "$SEGMENT_AWK")

    # Fallback: a brace command word that ALSO contains a shell substitution
    # ("r{$(echo m),} -rf /") is split by the segmenter at the "(", so the
    # per-segment first-word check above misses it. Catch it directly on the whole
    # command: a command-position token containing BOTH a brace group and a $/`
    # substitution, with an rm-style -r/-f flag present -> fail safe (ASK).
    if [[ "$brace_seg_hit" -eq 0 ]]; then
        if printf '%s' "$normalized_cmd" | grep -Eq '(^|[;&|(){}]|[[:space:]])[A-Za-z0-9_./-]*\{[^}]*(\$|`)' \
            && printf '%s' "$normalized_cmd" | grep -Eq '[[:space:]]-[a-zA-Z]*[rRfF]'; then
            brace_seg_hit=1
            brace_hit_text="$normalized_cmd"
        fi
    fi

    if [[ "$brace_seg_hit" -eq 1 ]]; then
        # Look for a literal catastrophic target in the whole command AND in the
        # hit text (a -c/-S payload's target may be inside quotes, e.g. the "/" in
        # bash -c 'r{m,} -rf /', where it is not space/EOL-delimited in the outer
        # command). A trailing-quote-delimited target counts too.
        if printf '%s' "$normalized_cmd $brace_hit_text" | grep -Eq "[[:space:]](/|/Users|/System|/Library|/Applications|/bin|/sbin|/usr|/etc|/var|/opt|/boot|/proc|/sys|/private|/cores|/dev|~|\\\$HOME)([[:space:]/'\"]|$)"; then
            log_security_event "BLOCKED" "brace_expansion_rm_catastrophic" "$command"
            echo "❌ BLOCKED: rm command word assembled via brace expansion targets a catastrophic path" >&2
            echo "   Command: $command" >&2
            exit 2
        fi
        log_security_event "ASK" "brace_expansion_rm" "$command"
        echo "⚠️  CONFIRMATION REQUIRED: command word uses brace expansion that can assemble rm next to an rm -r/-f flag" >&2
        echo "   Command: $command" >&2
        exit 1
    fi
fi

# =============================================================================
# RM -RF HANDLING (path-aware, handles compound commands)
# =============================================================================

# Check if command contains rm -rf anywhere. Skipped for an oversized command
# already shown (by cheap linear greps above) to have no rm -r/-f shape -- the
# normalize/segment string ops are too costly at hundreds of KB.
if [ "${NOSYNC_OVERSIZED_NO_RM:-0}" != "1" ] && has_rf_flags "$normalized_cmd"; then

    # Check if this is a compound command
    if is_compound_command "$normalized_cmd"; then
        # Compound command with rm -rf - warn unless explicitly allowed
        if [[ "$ALLOW_RM_RF" == "1" && "$ALLOW_RM_RF_SCOPE" == "compound" ]]; then
            : # Allow compound commands with override
        else
            # Extract ALL rm -rf segments and validate each
            # Security: must validate every segment, not just the first
            # e.g., "rm -rf /tmp/x && rm -rf /" must catch the second segment
            all_segments=()
            worst_decision="allow"
            worst_segment=""
            worst_details=""
            segment_count=0

            saw_truncation=false
            while IFS= read -r rm_segment; do
                [[ -z "$rm_segment" ]] && continue
                if [[ "$rm_segment" == "<<NOSYNC_TRUNCATED>>" ]]; then
                    saw_truncation=true
                    continue
                fi
                ((segment_count++))

                if has_rf_flags "$rm_segment"; then
                    result=$(validate_rm_rf "$rm_segment")
                    decision="${result%%:*}"
                    rest="${result#*:}"
                    details="${rest#*:}"

                    # Track worst decision: deny > ask > warn > allow
                    case "$decision" in
                        deny)
                            worst_decision="deny"
                            worst_segment="$rm_segment"
                            worst_details="$details"
                            ;;
                        ask)
                            if [[ "$worst_decision" != "deny" ]]; then
                                worst_decision="ask"
                                worst_segment="$rm_segment"
                                worst_details="$details"
                            fi
                            ;;
                        warn)
                            if [[ "$worst_decision" == "allow" ]]; then
                                worst_decision="warn"
                                worst_segment="$rm_segment"
                                worst_details="$details"
                            fi
                            ;;
                    esac
                fi
            done < <(extract_all_rm_segments "$normalized_cmd")

            # Act on the worst decision across all segments
            if [[ $segment_count -gt 0 ]]; then
                case "$worst_decision" in
                    deny)
                        log_security_event "BLOCKED" "compound_rm_rf_catastrophic" "$command"
                        echo "❌ BLOCKED: Compound command contains catastrophic recursive rm" >&2
                        echo "   Command: $command" >&2
                        echo "   Dangerous segment: $worst_segment" >&2
                        echo "   Target: $worst_details" >&2
                        exit 2
                        ;;
                    ask|warn)
                        log_security_event "WARNING" "compound_rm_rf_$worst_decision" "$command"
                        echo "⚠️  WARNING: Compound command contains recursive rm outside safe roots" >&2
                        echo "   Command: $command" >&2
                        echo "   Problem segment: $worst_segment" >&2
                        echo "   Issue: $worst_details" >&2
                        [[ $segment_count -gt 1 ]] && echo "   Note: $segment_count rm -rf segments found in command" >&2
                        echo "" >&2
                        echo "   Split into separate commands for safer execution." >&2
                        echo "   (Standalone hook use only: CLAUDE_ALLOW_RM_RF=1 CLAUDE_ALLOW_RM_RF_SCOPE=compound." >&2
                        echo "    Under pi-sandbox-guard that is ignored by design; there is no override.)" >&2
                        exit 1
                        ;;
                    allow)
                        # If extraction stopped early at the segment cap, we did
                        # NOT inspect every rm segment, so we cannot safely allow:
                        # ask instead (fail-safe, never silent allow).
                        if [[ "$saw_truncation" == true ]]; then
                            log_security_event "WARNING" "compound_rm_rf_segment_cap" "$command"
                            echo "⚠️  WARNING: Command has more rm -rf segments than can be checked safely ($NOSYNC_MAX_RM_SEGMENTS+)" >&2
                            echo "   Command: $command" >&2
                            echo "   Split into separate commands so each rm can be validated." >&2
                            exit 1
                        fi
                        # All segments validated as safe - allow compound command
                        : # fall through, don't exit
                        ;;
                esac
            fi
        fi
    fi

    # Validate the rm invocation itself. For compound commands, validate the
    # extracted rm segment to avoid treating pipes/redirects as operands.
    cmd_to_validate="$normalized_cmd"
    if is_compound_command "$normalized_cmd"; then
        rm_segment=$(extract_rm_segment "$normalized_cmd")
        if [[ -n "$rm_segment" ]]; then
            cmd_to_validate="$rm_segment"
        fi
    fi

    if has_rf_flags "$cmd_to_validate"; then
        result=$(validate_rm_rf "$cmd_to_validate")
        decision="${result%%:*}"
        rest="${result#*:}"
        reason="${rest%%:*}"
        details="${rest#*:}"

        case "$decision" in
            deny)
                log_security_event "BLOCKED" "rm_rf_catastrophic" "$command"
                echo "❌ BLOCKED: Catastrophic recursive rm target" >&2
                echo "   Command: $command" >&2
                echo "   Target: $details" >&2
                exit 2
                ;;
            ask)
                log_security_event "ASK" "rm_rf_$reason" "$command"
                echo "⚠️  CONFIRMATION REQUIRED: recursive rm with shell expansion" >&2
                echo "   Command: $command" >&2
                echo "   Issue: $details" >&2
                echo "" >&2
                echo "   Name the paths explicitly instead of using a glob." >&2
                echo "   (Standalone hook use only: CLAUDE_ALLOW_RM_RF=1 CLAUDE_ALLOW_RM_RF_SCOPE=expansion." >&2
                echo "    Under pi-sandbox-guard that is ignored by design; there is no override.)" >&2
                exit 1
                ;;
            warn)
                log_security_event "WARNING" "rm_rf_$reason" "$command"
                echo "⚠️  WARNING: recursive rm $reason" >&2
                echo "   Command: $command" >&2
                echo "   Issue: $details" >&2
                echo "   Safe roots: $(get_safe_roots | tr '\n' ' ')" >&2
                echo "" >&2
                echo "   Under pi-sandbox-guard: add a PARENT of this path to" >&2
                echo "   POLICY_RM_SAFE_ROOTS in the host shell that launches Pi." >&2
                echo "   Naming this exact path is deliberately not enough — deleting a safe" >&2
                echo "   root itself still asks, so only paths INSIDE one become allowed." >&2
                echo "   (Standalone hook use only: CLAUDE_ALLOW_RM_RF=1 CLAUDE_ALLOW_RM_RF_SCOPE=all.)" >&2
                exit 1
                ;;
            allow)
                # Allowed - proceed silently
                exit 0
                ;;
        esac
    fi
fi

# =============================================================================
# NON-RM WARNING PATTERNS
# =============================================================================

warning_patterns=(
    # Privilege escalation
    "(^|[[:space:]])sudo[[:space:]]"
    "(^|[[:space:]])su[[:space:]]"
    # User/auth management
    "(^|[[:space:]])passwd([[:space:]]|$)"
    "(^|[[:space:]])usermod[[:space:]]"
    "(^|[[:space:]])crontab[[:space:]]"
    # Service management - only destructive operations
    "(^|[[:space:]])systemctl[[:space:]]+(stop|restart|disable|mask)[[:space:]]"
    "(^|[[:space:]])service[[:space:]]+[^[:space:]]+[[:space:]]+(stop|restart)"
    # Mount operations
    "(^|[[:space:]])mount[[:space:]]"
    "(^|[[:space:]])umount[[:space:]]"
    # Firewall
    "(^|[[:space:]])iptables[[:space:]]"
    "(^|[[:space:]])ufw[[:space:]]"
    "(^|[[:space:]])firewall-cmd[[:space:]]"
    # Git destructive operations
    "git[[:space:]]+reset[[:space:]]+--hard"
    "git[[:space:]]+clean[[:space:]]+-[a-zA-Z]*f"
    # core.hooksPath repointing is handled by the option-aware token scan below:
    # git config keys are CASE-INSENSITIVE and the key can be quote-split
    # (core."hooksPath"), neither of which a flat ERE handles.
    # find with destructive actions (non-system dirs - system dirs blocked above).
    # Covers -exec/-execdir/-ok/-okdir and any unquoted rm path
    # (rm, /bin/rm, ./rm). The token scan below handles quoted utility words.
    "find[[:space:]].*-delete"
    "find[[:space:]].*-(exec|execdir|ok|okdir)[[:space:]]+([A-Za-z0-9_./-]*/)?rm([[:space:]]|$)"
    # find/xargs/parallel running a shell with -c and rm -r/-f inside the string.
    "find[[:space:]].*-(exec|execdir|ok|okdir)[[:space:]]+([A-Za-z0-9_./-]*/)?(sh|bash|zsh|dash)[[:space:]].*[[:space:]\"']([A-Za-z0-9_./-]*/)?rm[[:space:]]+-[a-zA-Z]*[rRfF]"
    # Direct xargs/parallel utility ownership is handled by the option-aware
    # token scan below; a flat ERE cannot distinguish an option argument from
    # the utility word.
    "xargs[[:space:]].*[[:space:]]([A-Za-z0-9_./-]*/)?rm[[:space:]]+-[a-zA-Z]*[rRfF]"
    # xargs/parallel running a shell -c string with rm -r/-f inside, with ZERO or
    # more option/assignment tokens before the shell ("xargs sh -c '..'",
    # "xargs -I{} sh -c '..'", "parallel sh -c '..' ::: x").
    "(xargs|parallel)([[:space:]]+-[^[:space:]]+|[[:space:]]+[A-Za-z0-9_]+=[^[:space:]]+)*[[:space:]]+([A-Za-z0-9_./-]*/)?(sh|bash|zsh|dash)[[:space:]].*[[:space:]\"']([A-Za-z0-9_./-]*/)?rm[[:space:]]+-[a-zA-Z]*[rRfF]"
    # Docker privileged/volume mounts
    "docker[[:space:]].*--privileged"
    "docker[[:space:]].*-v[[:space:]]+[^[:space:]]*:/[^[:space:]]*:"
)

for pattern in "${warning_patterns[@]}"; do
    if echo "$normalized_cmd" | grep -E "$pattern" &>/dev/null; then
        log_security_event "WARNING" "$pattern" "$command"
        echo "⚠️  WARNING: Potentially risky command: $command" >&2
        echo "   Pattern matched: $pattern" >&2
        echo "   Review carefully before proceeding" >&2
        exit 1
    fi
done

# Executor utility-word check via the quote-aware lexer. The EREs above catch
# simple unquoted spellings; the tokenizer is the source of truth for quote
# normalization and path-qualified */rm. Scan tokens so
# `xargs 'rm'`, `parallel "rm"`, `find . -exec 'rm'` ASK at the same tier as
# their unquoted twins. Does NOT whole-line strip (that would false-ask
# `echo 'xargs rm'`). ANSI-C `$'rm'` is reduced to `'rm'` by the guard probe
# before re-analysis; raw analyzer sees `$rm` for that form (accepted boundary).
{
    _ex_is_rm() {
        case "$1" in
            rm|/bin/rm|/usr/bin/rm|*/rm) return 0 ;;
            *) return 1 ;;
        esac
    }
    _ex_is_sep() {
        case "$1" in
            ";"|"&&"|"||"|"|"|"|&"|"&"|"("|")"|"{"|"}") return 0 ;;
            *) return 1 ;;
        esac
    }
    # True when a git config key names core.hooksPath. Git config keys are
    # CASE-INSENSITIVE (`core.hookspath` sets the same key), so compare lowered.
    _ex_is_hookspath_key() {
        local _k
        _k="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
        [[ "$_k" == "core.hookspath" ]]
    }
    _ex_toks=()
    while IFS= read -r _et; do _ex_toks+=("$_et"); done < <(tokenize_command "$execution_scan_text")
    _scan_tokens=("${_ex_toks[@]}")
    _ex_n=${#_ex_toks[@]}
    _ex_cmdpos=1
    for ((_ei=0; _ei<_ex_n; _ei++)); do
        _et="${_ex_toks[$_ei]}"
        if _ex_is_sep "$_et"; then
            _ex_cmdpos=1
            continue
        fi
        case "$_et" in
            then|do|else|elif|if|while|until|time|"!")
                _ex_cmdpos=1
                continue
                ;;
        esac
        [[ "$_ex_cmdpos" -eq 1 ]] || continue
        wrapped_command_index "$_ei" "$_ex_n"
        if [[ "$_wrapped_index" -lt 0 ]]; then
            _ex_cmdpos=0
            continue
        fi
        _ei="$_wrapped_index"
        _et="${_ex_toks[$_ei]}"
        _ebase="${_et##*/}"
        case "$_ebase" in
            xargs|parallel)
                _ej=$((_ei + 1))
                while [[ $_ej -lt $_ex_n ]]; do
                    _en="${_ex_toks[$_ej]}"
                    if _ex_is_sep "$_en"; then break; fi
                    # parallel input source marker — utility word is before this
                    case "$_en" in :::|::::) break ;; esac
                    if [[ "$_ebase" == "parallel" ]]; then
                        _parallel_output=""
                        case "$_en" in
                            --joblog|--results)
                                [[ $((_ej + 1)) -lt "$_ex_n" ]] && _parallel_output="${_ex_toks[$((_ej + 1))]}" ;;
                            --joblog=*|--results=*)
                                _parallel_output="${_en#*=}" ;;
                        esac
                        if [[ -n "$_parallel_output" ]] && is_critical_system_path "$_parallel_output"; then
                            log_security_event "BLOCKED" "parallel_output_critical_path" "$command"
                            echo "❌ BLOCKED: Parallel output targets a critical system path: $command" >&2
                            exit 2
                        fi
                    fi
                    case "$_en" in
                        -*)
                            if [[ "$_ebase" == "xargs" ]]; then
                                case "$_en" in
                                    -I|-J|-R|-S|-n|-L|-E|-P|-s|-a|-d|--max-args|--max-lines|--max-procs|--replace-str|--logical-eof|--delimiter|--arg-file)
                                        _ej=$((_ej + 2)); continue ;;
                                    -i|-e|-l|--replace|--eof)
                                        _ej=$((_ej + 1)); continue ;;
                                    --*=*|-?*) _ej=$((_ej + 1)); continue ;;
                                esac
                            else
                                case "$_en" in
                                    -j|-S|-a|-N|-L|--jobs|--sshlogin|--sshloginfile|--joblog|--results|--workdir|--wd|--delay|--timeout|--retries|--halt|--basefile|--transferfile|--return|--env|--rpl|--tagstring|--arg-sep|--arg-file|--arg-file-sep)
                                        _ej=$((_ej + 2)); continue ;;
                                    --*=*|-?*) _ej=$((_ej + 1)); continue ;;
                                esac
                            fi
                            ;;
                        *)
                            if _ex_is_rm "$_en"; then
                                log_security_event "WARNING" "executor_rm_utility" "$command"
                                echo "⚠️  WARNING: Potentially risky command: $command" >&2
                                echo "   Pattern matched: executor (xargs/parallel) invoking rm" >&2
                                echo "   Review carefully before proceeding" >&2
                                exit 1
                            fi
                            break
                            ;;
                    esac
                done
                _ex_cmdpos=0
                ;;
            find)
                _ej=$((_ei + 1))
                while [[ $_ej -lt $_ex_n ]]; do
                    _en="${_ex_toks[$_ej]}"
                    if _ex_is_sep "$_en"; then break; fi
                    case "$_en" in
                        -exec|-execdir|-ok|-okdir)
                            if [[ $((_ej + 1)) -lt $_ex_n ]]; then
                                _uk=$((_ej + 1))
                                _uend="$_uk"
                                while [[ "$_uend" -lt "$_ex_n" ]]; do
                                    case "${_ex_toks[$_uend]}" in "{}") : ;; "+"|";") break ;; esac
                                    _uend=$((_uend + 1))
                                done
                                wrapped_command_index "$_uk" "$_uend"
                                if [[ "$_wrapped_index" -ge 0 ]] && _ex_is_rm "${_ex_toks[$_wrapped_index]}"; then
                                    log_security_event "WARNING" "find_exec_rm_utility" "$command"
                                    echo "⚠️  WARNING: Potentially risky command: $command" >&2
                                    echo "   Pattern matched: find -exec/-ok invoking rm" >&2
                                    echo "   Review carefully before proceeding" >&2
                                    exit 1
                                fi
                            fi
                            _ej=$((_ej + 2)); continue
                            ;;
                        *) _ej=$((_ej + 1)); continue ;;
                    esac
                done
                _ex_cmdpos=0
                ;;
            git)
                # Git-hook persistence via core.hooksPath. The Seatbelt profile
                # write-denies the ACTIVE_HOOKS tree as resolved by the launcher at
                # STARTUP; re-pointing hooksPath mid-session relocates hooks to a
                # path that deny does not cover, and the planted hook then runs
                # OUTSIDE the sandbox on the next unsandboxed `git`.
                #
                # Token-based, not an ERE: git config keys are case-insensitive and
                # may be quote-split (core."hooksPath"), which the lexer normalizes.
                #
                # ASK, not BLOCK: legitimate use exists (scripts/setup-hooks.sh).
                # Two shapes relocate the tree; read/remove shapes only inspect it:
                #   1. `git [opts] config [opts] [set] <key> <value>` — persistent
                #   2. `git -c <key>=<value> <subcmd>`               — per-invocation
                # `set` is git >= 2.46's explicit spelling of shape 1 and must be
                # recognized, or `git config set core.hooksPath v` reads `set` as
                # the key and slips through.
                #
                # `--get`/`get`/`--unset`/`unset`/`--list`/`list` and a bare
                # `config <key>` with no value do not repoint anything, so they stay
                # allow: gating a read — or the remediation — trains click-through
                # without adding cover.
                _git_hookspath=0
                _git_is_config=0
                _git_config_reads=0
                _git_config_key=""
                _git_config_argc=0
                _ej=$((_ei + 1))
                while [[ $_ej -lt $_ex_n ]]; do
                    _en="${_ex_toks[$_ej]}"
                    if _ex_is_sep "$_en"; then break; fi
                    if [[ "$_git_is_config" -eq 0 ]]; then
                        case "$_en" in
                            # Pre-subcommand `-c key=value` (and its split spelling).
                            -c)
                                if [[ $((_ej + 1)) -lt $_ex_n ]]; then
                                    _en2="${_ex_toks[$((_ej + 1))]}"
                                    case "$_en2" in
                                        *=*) _ex_is_hookspath_key "${_en2%%=*}" && _git_hookspath=1 ;;
                                    esac
                                fi
                                _ej=$((_ej + 2)); continue ;;
                            -c*=*)
                                _en2="${_en#-c}"
                                _ex_is_hookspath_key "${_en2%%=*}" && _git_hookspath=1
                                _ej=$((_ej + 1)); continue ;;
                            config) _git_is_config=1; _ej=$((_ej + 1)); continue ;;
                            # Pre-subcommand options that take a SEPARATE value, which
                            # must be consumed or it is mistaken for the subcommand.
                            -C|--git-dir|--work-tree|--namespace|--exec-path|--super-prefix)
                                _ej=$((_ej + 2)); continue ;;
                            -*) _ej=$((_ej + 1)); continue ;;
                            # Any other bare word is the subcommand; only `config`
                            # can set a key, so stop scanning for one.
                            *) break ;;
                        esac
                    fi
                    # Inside `git config`: find the key and whether a value follows.
                    case "$_en" in
                        # Read/remove shapes, in both the option and subcommand spelling.
                        --get|--get-all|--get-regexp|--get-urlmatch|--unset|--unset-all|--list|-l|--edit|-e)
                            _git_config_reads=1; _ej=$((_ej + 1)); continue ;;
                        get|unset|list|edit|rename-section|remove-section)
                            [[ "$_git_config_argc" -eq 0 ]] && _git_config_reads=1
                            _ej=$((_ej + 1)); continue ;;
                        # `set` is the explicit write spelling: not a key, not a value.
                        set)
                            _ej=$((_ej + 1)); continue ;;
                        # Options taking a SEPARATE value. Without consuming it, the
                        # value is counted as the key: `--file .git/config core.hooksPath v`
                        # took `.git/config` as the key and returned allow.
                        --file|-f|--blob|--default|--type|-t|--comment)
                            _ej=$((_ej + 2)); continue ;;
                        -*) _ej=$((_ej + 1)); continue ;;
                        *)
                            if [[ -z "$_git_config_key" ]]; then
                                _git_config_key="$_en"
                            fi
                            _git_config_argc=$((_git_config_argc + 1))
                            _ej=$((_ej + 1)); continue ;;
                    esac
                done
                if [[ "$_git_is_config" -eq 1 && "$_git_config_reads" -eq 0 && \
                      "$_git_config_argc" -ge 2 ]] && \
                   _ex_is_hookspath_key "$_git_config_key"; then
                    _git_hookspath=1
                fi
                if [[ "$_git_hookspath" -eq 1 ]]; then
                    log_security_event "WARNING" "git_hookspath_repoint" "$command"
                    echo "⚠️  WARNING: Potentially risky command: $command" >&2
                    echo "   Pattern matched: git core.hooksPath repoint (relocates the active hook tree)" >&2
                    echo "   Review carefully before proceeding" >&2
                    exit 1
                fi
                _ex_cmdpos=0
                ;;
            *)
                _ex_cmdpos=0
                ;;
        esac
    done
    unset -f _ex_is_rm _ex_is_sep _ex_is_hookspath_key
    unset _scan_tokens _wrapped_index _ex_toks _ex_n _ex_cmdpos _ei _ej _et _ebase _en _enext
    unset _util _uk _uend _ubase _parallel_output _en2
    unset _git_hookspath _git_is_config _git_config_reads _git_config_key _git_config_argc
}

# Check for network script downloads - only warn when:
# - curl/wget has output flags (-o, -O, --output*) AND targets script extensions
# - OR curl/wget redirects (>, >>) to script files
# This avoids false positives on ordinary local helper scripts
network_script_download_pattern="(curl|wget)[[:space:]].*(-o[[:space:]]+|-O[[:space:]]+|--output[^[:space:]]*[=[:space:]])[^[:space:]]*\.(sh|py|pl|rb|js)([[:space:]]|$)"
network_script_redirect_pattern="(curl|wget)[[:space:]].*>[[:space:]]*[^[:space:]]*\.(sh|py|pl|rb|js)([[:space:]]|$)"
if echo "$normalized_cmd" | grep -E "$network_script_download_pattern" &>/dev/null || \
   echo "$normalized_cmd" | grep -E "$network_script_redirect_pattern" &>/dev/null; then
    log_security_event "WARNING" "network_script_download" "$command"
    echo "⚠️  WARNING: Network download of executable script: $command" >&2
    exit 1
fi

# Check for environment variable manipulation that could be risky
if echo "$normalized_cmd" | grep -E "(export|unset).*(PATH|LD_LIBRARY_PATH|DYLD_)" &>/dev/null; then
    log_security_event "WARNING" "env_var_modification" "$command"
    echo "⚠️  WARNING: Critical environment variable modification: $command" >&2
    exit 1
fi

# =============================================================================
# LITERAL INTERPRETER PAYLOADS (python -c, node -e/--eval, perl/ruby -e, awk)
# =============================================================================
#
# Scan *literal* code strings passed to common interpreters for destructive
# filesystem / process intent. This is a static string classifier — it does not
# execute the payload and does not resolve runtime-assembled code
# (python3 -c "$VAR", node -e "$(cat f)", etc.). Those remain the dynamic class
# tracked under docs/ARCHITECTURE.md (known analyzer gaps).
#
# Verdict contract for this section:
#   BLOCK (2) — dangerous API + clear protected root/device target, or shell
#               execution of a catastrophic command against a protected target
#   ASK   (1) — dangerous filesystem/process/command-exec APIs without a clear
#               protected target, OR ambiguous/dynamic shapes that mention those
#               APIs (fail closed; never silent allow)
#   fall-through ALLOW — benign print / JSON / version / math one-liners
#
# Cheap reveal-only prefilter: remove quote/backslash/dollar bytes so quoted and
# ANSI-C-quoted command words still reach the real quote-aware tokenizer. This
# probe only decides whether to tokenize; it never supplies classification text.
_interp_probe="${normalized_cmd//\\/}"
_interp_probe="${_interp_probe//\"/}"
_interp_probe="${_interp_probe//\'/}"
_interp_probe="${_interp_probe//\$/}"
if printf '%s' "$_interp_probe" | grep -Eq \
    '(^|[[:space:]/;|&])([A-Za-z0-9_./-]*/)?(python[0-9.]*|node|nodejs|perl|ruby)[[:space:]]' \
    || printf '%s' "$_interp_probe" | grep -Eq \
    '(^|[[:space:]/;|&])([A-Za-z0-9_./-]*/)?(awk|gawk|mawk|nawk)[[:space:]]'; then

    # Collect literal payloads via the quote-aware lexer. For python/node/perl/
    # ruby the payload is the token after -c / -e / --eval / --eval=. For awk
    # the program is the first non-option argument (or -e/--source operand).
    # Classify each extracted payload independently. Combining payloads, or
    # appending the whole shell command, lets benign text outside one payload
    # supply the API/path half of a match in another payload.
    _interp_payloads=()
    _interp_payload_types=()
    _has_interp_payload=0
    _add_interp_payload() {
        _interp_payloads+=("$1")
        _interp_payload_types+=("$2")
        _has_interp_payload=1
    }
    _itoks=()
    while IFS= read -r _it; do _itoks+=("$_it"); done < <(tokenize_command "$normalized_cmd")
    _i=0
    while [[ $_i -lt ${#_itoks[@]} ]]; do
        _tb="${_itoks[$_i]##*/}"
        case "$_tb" in
            python|python[0-9]|python[0-9].*|node|nodejs|perl|ruby)
                # Collect the CODE operand of -c / -e / --eval / --print.
                # Short-opt clusters: -c, -e, -we (perl), -nc (rare). Long forms:
                # --eval CODE, --eval=CODE, --print CODE (node).
                _j=$((_i + 1))
                while [[ $_j -lt ${#_itoks[@]} ]]; do
                    _tj="${_itoks[$_j]}"
                    if [[ "$_tj" == --eval=* ]]; then
                        _add_interp_payload "${_tj#--eval=}" "$_tb"
                        _j=$((_j + 1))
                        continue
                    fi
                    # Perl -E is -e plus a feature bundle. It is a code-eval
                    # flag, unlike Ruby/Python -E options.
                    if [[ "$_tb" == "perl" ]]; then
                        if [[ "$_tj" =~ ^-[A-Za-z]*E$ ]] \
                            && [[ $((_j + 1)) -lt ${#_itoks[@]} ]]; then
                            _add_interp_payload "${_itoks[$((_j + 1))]}" "$_tb"
                            _j=$((_j + 2))
                            continue
                        fi
                        case "$_tj" in
                            -*E?*)
                                _glued_code="${_tj#*E}"
                                _add_interp_payload "$_glued_code" "$_tb"
                                _j=$((_j + 1))
                                continue
                                ;;
                        esac
                    fi
                    # Shell permits the code string to be glued to -c/-e
                    # through quote removal: python3 -c'code', node -e"code".
                    case "$_tj" in
                        -c?*|-e?*)
                            _add_interp_payload "${_tj:2}" "$_tb"
                            _j=$((_j + 1))
                            continue
                            ;;
                    esac
                    # Perl/Ruby commonly cluster switches before -e (for
                    # example -we'code'). Quote removal glues the code to the
                    # option token; scanning the full short-option token keeps
                    # the literal API/path bytes without guessing where a code
                    # identifier beginning with letters starts.
                    case "$_tj" in
                        --*) ;;
                        -*e*)
                            _glued_code="${_tj#*e}"
                            if [[ -n "$_glued_code" ]]; then
                                _add_interp_payload "$_glued_code" "$_tb"
                                _j=$((_j + 1))
                                continue
                            fi
                            ;;
                    esac
                    if [[ "$_tj" == "--eval" || "$_tj" == "--print" \
                        || "$_tj" =~ ^-[A-Za-z]*c$ \
                        || "$_tj" =~ ^-[A-Za-z]*e$ ]]; then
                        if [[ $((_j + 1)) -lt ${#_itoks[@]} ]]; then
                            _add_interp_payload "${_itoks[$((_j + 1))]}" "$_tb"
                            _j=$((_j + 2))
                            continue
                        fi
                    fi
                    # Interpreter options that consume the following argv item.
                    # Without this arity handling, the option argument looks like
                    # a script filename and stops the scan before a later -c/-e.
                    _takes_arg=0
                    case "$_tb" in
                        python|python[0-9]|python[0-9].*)
                            case "$_tj" in -W|-X) _takes_arg=1 ;; esac
                            ;;
                        node|nodejs)
                            case "$_tj" in
                                -r|--require|--import|--loader|--experimental-loader|--conditions|-C)
                                    _takes_arg=1 ;;
                            esac
                            ;;
                        ruby)
                            case "$_tj" in -E|--encoding|-I|-C|-F|-K|-r) _takes_arg=1 ;; esac
                            ;;
                        perl)
                            case "$_tj" in -I) _takes_arg=1 ;; esac
                            ;;
                    esac
                    if [[ "$_takes_arg" -eq 1 ]]; then
                        if [[ $((_j + 1)) -lt ${#_itoks[@]} ]]; then
                            _j=$((_j + 2))
                            continue
                        fi
                        break
                    fi
                    case "$_tj" in
                        -*)
                            _j=$((_j + 1))
                            continue
                            ;;
                        *)
                            break ;; # end of this interpreter's options
                    esac
                done
                ;;
            awk|gawk|mawk|nawk)
                _j=$((_i + 1))
                _awk_prog=""
                while [[ $_j -lt ${#_itoks[@]} ]]; do
                    _tj="${_itoks[$_j]}"
                    case "$_tj" in
                        -e|--source|--exec)
                            if [[ $((_j + 1)) -lt ${#_itoks[@]} ]]; then
                                _awk_prog="${_awk_prog}"$'\n'"${_itoks[$((_j + 1))]}"
                                _j=$((_j + 1))
                            fi
                            ;;
                        --source=*|--exec=*)
                            _awk_prog="${_awk_prog}"$'\n'"${_tj#*=}"
                            ;;
                        -f|--file)
                            # program from file — not a literal payload; skip operand
                            [[ $((_j + 1)) -lt ${#_itoks[@]} ]] && _j=$((_j + 1))
                            ;;
                        --file=*)
                            :
                            ;;
                        -*)
                            # awk options that take an argument: -v VAR=VAL, -F fs
                            case "$_tj" in
                                -v|-F|-W) [[ $((_j + 1)) -lt ${#_itoks[@]} ]] && _j=$((_j + 1)) ;;
                            esac
                            ;;
                        *)
                            # first non-option token is the program text
                            if [[ -z "$_awk_prog" ]]; then
                                _awk_prog="$_tj"
                            fi
                            break
                            ;;
                    esac
                    _j=$((_j + 1))
                done
                if [[ -n "$_awk_prog" ]]; then
                    _add_interp_payload "$_awk_prog" "awk"
                fi
                ;;
        esac
        _i=$((_i + 1))
    done

    if [[ "$_has_interp_payload" -eq 1 ]]; then
      _interp_ask=0
      _interp_idx=0
      while [[ "$_interp_idx" -lt "${#_interp_payloads[@]}" ]]; do
        _interp_scan="${_interp_payloads[$_interp_idx]}"
        _interp_type="${_interp_payload_types[$_interp_idx]}"
        _interp_idx=$((_interp_idx + 1))
        # Protected roots / devices (same family as critical_dirs_pattern).
        # Matched as path literals inside code strings.
        _prot_path='(^|[^A-Za-z0-9_])(/|/etc|/bin|/sbin|/usr|/var|/private|/System|/Library|/Applications|/opt|/Volumes|/dev|/boot|/sys|/proc)(/|["'"'"'\`,);[:space:]]|$)'
        _prot_home='(^|[^A-Za-z0-9_])(~|\$HOME|\$\{HOME\})(/|["'"'"'\`,);[:space:]]|$)'

        # Filesystem-destroy / mutate APIs across languages.
        # Prefer CALL shapes (name followed by '(' or, for Perl, a string/path
        # operand) so a print/comment that merely mentions the API name does not
        # trip the classifier. Method names are also matched after require("fs")
        # noise (quote-stripping yields require(fs).rmSync).
        _fs_destroy='(shutil\.rmtree[[:space:]]*\(|os\.(remove|unlink|rmdir|replaced?|truncate)[[:space:]]*\(|pathlib\.Path\([^)]*\)\.(unlink|rmdir|write_bytes|write_text)[[:space:]]*\(|(^|[^A-Za-z0-9_])(rmSync|rmdirSync|unlinkSync|truncateSync|writeFileSync)[[:space:]]*\(|\.(rm|rmdir)[[:space:]]*\(|\.promises\.(rm|rmdir|unlink|writeFile|truncate)[[:space:]]*\(|FileUtils\.(rm_rf|rm_r|rmtree|remove_entry_secure|remove_entry)([[:space:]]*\(|[[:space:]]+["'"'"'/])|File\.(delete|unlink|truncate|write)[[:space:]]*\(|Pathname.*\.(rmtree|delete|unlink)[[:space:]]*\(|(^|[^A-Za-z0-9_])unlink[[:space:]]*(\(|["'"'"'/~$])|(^|[^A-Za-z0-9_])rmtree[[:space:]]*\()'
        _fs_perm='(os\.(chmod|chown|fchmod|fchown)[[:space:]]*\(|(^|[^A-Za-z0-9_])(chmodSync|chownSync)[[:space:]]*\(|File\.(chmod|chown)[[:space:]]*\(|(^|[^A-Za-z0-9_])chmod[[:space:]]*\(|(^|[^A-Za-z0-9_])chown[[:space:]]*\()'
        # Command / process execution APIs.
        _cmd_exec='(os\.(system|popen|execv?e?p?|spawnv?e?p?)[[:space:]]*\(|subprocess\.(call|run|Popen|check_call|check_output|getoutput|getstatusoutput)[[:space:]]*\(|(^|[^A-Za-z0-9_])(execSync|execFileSync|spawnSync|execFile|spawn)[[:space:]]*\(|require[[:space:]]*\([[:space:]]*["'"'"']child_process["'"'"']|(^|[^A-Za-z0-9_])(system|exec)([[:space:]]*\(|[[:space:]]+["'"'"'\`])|Process\.(spawn|exec|kill)[[:space:]]*\(|IO\.popen[[:space:]]*\(|open[[:space:]]*\([[:space:]]*["'"'"']\|)'
        # Backticks execute commands in Perl/Ruby, but are ordinary JavaScript
        # template literals in Node. Treating every Node template as command
        # execution turned benign `node -e 'console.log(`hi`)'` into ASK.
        if [[ "$_interp_type" == "perl" || "$_interp_type" == "ruby" ]]; then
            _cmd_exec="${_cmd_exec%?}"'|`[^`]*`)'
        fi
        _proc_kill='(os\.(kill|fork)[[:space:]]*\(|process\.kill[[:space:]]*\(|Process\.kill[[:space:]]*\(|signal\.pthread_kill[[:space:]]*\(|(^|[^A-Za-z0-9_])fork[[:space:]]*\()'
        # Dynamic evaluation of code (fail toward ASK when co-present with risk).
        _dyn_eval='(^|[^A-Za-z0-9_])(eval|exec|Function)[[:space:]]*\('
        # Shell-catastrophe shapes that may appear inside system("...") strings.
        # Keep these linear (no unbounded .*) — the scan text is short but the
        # patterns run on every interpreter one-liner.
        _shell_cat='((^|[^A-Za-z0-9_])rm[[:space:]]+-[a-zA-Z]*[rRfF]|(^|[^A-Za-z0-9_])(mkfs|wipefs|dd)[[:space:]]|(^|[^A-Za-z0-9_])chmod[[:space:]]+[^;&|]*-[A-Za-z]*R|(^|[^A-Za-z0-9_])chown[[:space:]]+[^;&|]*-[A-Za-z]*R)'
        # Device write intent.
        _dev_write='(/dev/(sd[a-z]|hd[a-z]|nvme|disk|rdisk|zero|null)[0-9]*|of=/dev/)'

        _has_prot=0
        printf '%s' "$_interp_scan" | grep -Eq "$_prot_path" && _has_prot=1
        printf '%s' "$_interp_scan" | grep -Eq "$_prot_home" && _has_prot=1
        _has_dev=0
        printf '%s' "$_interp_scan" | grep -Eq "$_dev_write" && _has_dev=1

        _has_fs_destroy=0
        printf '%s' "$_interp_scan" | grep -Eq "$_fs_destroy" && _has_fs_destroy=1
        # Destructured fs/fs-promises imports produce a bare rm()/rmdir() call.
        # Require an fs module import in the same literal payload before treating
        # the bare local call as a filesystem API.
        if printf '%s' "$_interp_scan" | grep -Eq \
            '(require[[:space:]]*\([[:space:]]*["'"'"']?(node:)?fs(/promises)?["'"'"']?[[:space:]]*\)|from[[:space:]]*["'"'"']?(node:)?fs(/promises)?["'"'"']?)' \
            && printf '%s' "$_interp_scan" | grep -Eq \
            '(^|[^A-Za-z0-9_.])(rm|rmdir)[[:space:]]*\('; then
            _has_fs_destroy=1
        fi
        _has_fs_perm=0
        printf '%s' "$_interp_scan" | grep -Eq "$_fs_perm" && _has_fs_perm=1
        _has_cmd_exec=0
        printf '%s' "$_interp_scan" | grep -Eq "$_cmd_exec" && _has_cmd_exec=1
        _has_proc_kill=0
        printf '%s' "$_interp_scan" | grep -Eq "$_proc_kill" && _has_proc_kill=1
        _has_dyn_eval=0
        printf '%s' "$_interp_scan" | grep -Eq "$_dyn_eval" && _has_dyn_eval=1
        _has_shell_cat=0
        printf '%s' "$_interp_scan" | grep -Eq "$_shell_cat" && _has_shell_cat=1

        # open(..., "w"/"a") or write modes targeting protected paths — treat as
        # destroy/write intent when a protected path is also present.
        _has_open_write=0
        if printf '%s' "$_interp_scan" | grep -Eq \
            'open[[:space:]]*\([^)]*(["'"'"'][wa+]+["'"'"']|mode[[:space:]]*=[[:space:]]*["'"'"'][wa])' \
            || printf '%s' "$_interp_scan" | grep -Eq \
            '\.(write_text|write_bytes|writeFileSync|writeFile)[[:space:]]*\('; then
            _has_open_write=1
        fi

        # ---- BLOCK: clear protected-root / device destruction ----
        if { [[ "$_has_fs_destroy" -eq 1 ]] || [[ "$_has_open_write" -eq 1 ]] || [[ "$_has_fs_perm" -eq 1 ]]; } \
            && { [[ "$_has_prot" -eq 1 ]] || [[ "$_has_dev" -eq 1 ]]; }; then
            log_security_event "BLOCKED" "interpreter_payload_protected_fs" "$command"
            echo "❌ BLOCKED: Interpreter payload mutates a protected path/device: $command" >&2
            echo "   Literal code passed to python/node/perl/ruby/awk targets a critical filesystem root." >&2
            exit 2
        fi
        # system/exec of a catastrophic shell command against a protected path
        if [[ "$_has_cmd_exec" -eq 1 ]] && [[ "$_has_shell_cat" -eq 1 ]] \
            && { [[ "$_has_prot" -eq 1 ]] || [[ "$_has_dev" -eq 1 ]]; }; then
            log_security_event "BLOCKED" "interpreter_payload_shell_catastrophic" "$command"
            echo "❌ BLOCKED: Interpreter payload executes a catastrophic shell command: $command" >&2
            exit 2
        fi
        # ---- ASK: dangerous intent without a clear protected target, or
        #      ambiguous/dynamic shapes that mention dangerous APIs ----
        if [[ "$_has_fs_destroy" -eq 1 ]] || [[ "$_has_fs_perm" -eq 1 ]] \
            || [[ "$_has_cmd_exec" -eq 1 ]] || [[ "$_has_proc_kill" -eq 1 ]] \
            || [[ "$_has_open_write" -eq 1 ]]; then
            _interp_ask=1
            continue
        fi
        # eval/exec present alongside anything that looks like code loading from
        # outside the literal (open/read/decode) — fail toward ASK, never allow.
        if [[ "$_has_dyn_eval" -eq 1 ]] && printf '%s' "$_interp_scan" | grep -Eq \
            '(open[[:space:]]*\(|read[[:space:]]*\(|decode|base64|compile[[:space:]]*\(|__import__|importlib|getattr|globals[[:space:]]*\(|vars[[:space:]]*\()'; then
            _interp_ask=1
            continue
        fi
        # Bare eval/exec of a non-literal argument (eval(x), exec(cmd), Function(s))
        # — argument is not a quoted string literal immediately inside. Conservative
        # ASK when eval/exec appears at all with an identifier/variable operand.
        if [[ "$_has_dyn_eval" -eq 1 ]] && printf '%s' "$_interp_scan" | grep -Eq \
            '(^|[^A-Za-z0-9_])(eval|exec|Function)[[:space:]]*\([[:space:]]*[A-Za-z_$!]'; then
            _interp_ask=1
            continue
        fi
      done
      if [[ "$_interp_ask" -eq 1 ]]; then
          log_security_event "WARNING" "interpreter_payload_dangerous_api" "$command"
          echo "⚠️  CONFIRMATION REQUIRED: interpreter payload uses dangerous filesystem/process APIs: $command" >&2
          echo "   Destructive or command-execution intent in a python/node/perl/ruby/awk one-liner." >&2
          exit 1
      fi
    fi
fi

# =============================================================================
# ALLOW
# =============================================================================

exit 0
