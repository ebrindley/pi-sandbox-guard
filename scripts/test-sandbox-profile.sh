#!/usr/bin/env bash
#
# test-sandbox-profile.sh — validate the SBPL profile compiles, applies, and
# enforces its write/read boundary, WITHOUT installing anything.
#
# This is the non-installing counterpart to deploy-launchers.sh's pre-install
# gate: deploy-launchers.sh calls this script so there is ONE source of truth
# for the profile's live behavior, and `npm run test:sandbox-profile` can run
# the same checks in isolation (e.g. locally before a deploy, or as a discrete
# CI step).
#
# Requires macOS Seatbelt (`sandbox-exec`). On a host without it (Linux CI,
# or a nested sandbox that blocks sandbox-exec), the script SKIPS with exit 0
# unless PI_SANDBOX_PROFILE_STRICT=1 is set (CI on macOS sets it to force a
# real run). Skipping keeps `npm test` green on non-macOS while still letting
# macOS CI and deploy enforce the boundary.
#
# Usage: scripts/test-sandbox-profile.sh [path/to/pi-sandbox.sb]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE_SRC="${1:-$REPO_ROOT/sandbox/pi-sandbox.sb}"

say() { printf '%s\n' "$*"; }
die() { printf 'Error: %s\n' "$*" >&2; exit 1; }

[ -f "$PROFILE_SRC" ] || die "missing profile: $PROFILE_SRC"

SBX="/usr/bin/sandbox-exec"
strict="${PI_SANDBOX_PROFILE_STRICT:-0}"

# Two ways sandbox-exec can be unusable here, both of which must SKIP in
# non-strict mode (so `npm test` stays green) but FAIL in strict mode (so a
# deploy never proceeds on an unvalidated profile):
#   1. the binary is missing / not executable (non-macOS, stripped image);
#   2. the binary EXISTS but `sandbox_apply` is refused — happens inside an
#      already-applied Seatbelt sandbox or a restricted CI runner, where a
#      trivial `sandbox-exec … true` fails with "Operation not permitted".
# We probe (2) with a minimal always-allow profile so we detect it before the
# real probes reach `sb true` and hard-fail the suite.
skip_or_die() {
  if [ "$strict" = "1" ]; then
    die "$1 but PI_SANDBOX_PROFILE_STRICT=1; cannot validate profile"
  fi
  say "[test-sandbox-profile] $1; SKIPPING profile probes (set PI_SANDBOX_PROFILE_STRICT=1 to force)."
  exit 0
}

if ! command -v sandbox-exec >/dev/null 2>&1 || [ ! -x "$SBX" ]; then
  skip_or_die "sandbox-exec unavailable"
fi
# Can this process actually APPLY a profile? Minimal allow-all profile; no params.
if ! "$SBX" -p '(version 1)(allow default)' /usr/bin/true >/dev/null 2>&1; then
  skip_or_die "sandbox-exec present but cannot apply profiles here (nested sandbox / restricted runner)"
fi

say "[test-sandbox-profile] validating SBPL profile compiles & applies: $PROFILE_SRC"

# IMPORTANT: the fake HOME must NOT live under the TMPDIR we pass to the profile,
# or "escape" writes would succeed simply by being under the (writable) TMPDIR and
# the boundary test would be meaningless. Put the fake HOME under /private/tmp and
# pass a SEPARATE, sibling TMPDIR. Project path INCLUDES A SPACE to catch argv bugs.
PROBEROOT="$(mktemp -d /private/tmp/pi-sb-probe-XXXXXX)"
trap 'rm -rf "$PROBEROOT" 2>/dev/null || true' EXIT
FAKEHOME="$PROBEROOT/home"
FAKETMP="$PROBEROOT/tmp"
PROJ="$FAKEHOME/My Project"
# ACTIVE_HOOKS is the effective active hooks dir (launcher resolves core.hooksPath
# or defaults to PROJECT/.git/hooks). Tests flip this for .githooks / out-of-project
# active-hook cases; default is the standard hooks path.
ACTIVE_HOOKS="$PROJ/.git/hooks"
mkdir -p "$PROJ" "$PROJ/.git/hooks" "$PROJ/.githooks" \
  "$PROJ/.git/modules/sub/hooks" "$PROJ/.git/modules/outer/modules/inner/hooks" \
  "$FAKEHOME/.pi/agent/extensions" "$FAKEHOME/.ssh" "$FAKEHOME/.config/git" "$FAKETMP"
printf 'SECRET\n' > "$PROJ/.env"
printf 'cert\n'   > "$PROJ/server.pem"          # project "secret-looking" file: must stay READABLE
printf 'cfg\n'    > "$FAKEHOME/.pi/agent/settings.json"
printf 'auth\n'   > "$FAKEHOME/.pi/agent/auth.json"
printf 'trust\n'  > "$FAKEHOME/.pi/agent/trust.json"
printf 'prompt\n' > "$FAKEHOME/.pi/agent/my-custom-prompt.md"
mkdir -p "$FAKEHOME/.pi/agent/prompts"
printf 'prompt\n' > "$FAKEHOME/.pi/agent/prompts/nested-prompt.md"   # nested layout
printf 'state\n'  > "$FAKEHOME/.pi/agent/run-history.json"           # ordinary state: WRITABLE
mkdir -p "$PROJ/docs"
printf 'doc\n'    > "$PROJ/docs/prompt-guide.md"   # legit project file: must stay WRITABLE
printf 'k\n'      > "$FAKEHOME/.ssh/id_probe"
printf 'creds\n'  > "$FAKEHOME/.netrc"
printf 'git-creds\n' > "$FAKEHOME/.config/git/credentials"
printf 'log\n'    > "$FAKEHOME/.pi/agent/security-events.log"

# Always pass ACTIVE_HOOKS (required profile param; the launcher supplies it at runtime).
sb() { "$SBX" -D PROJECT="$PROJ" -D HOME="$FAKEHOME" -D TMPDIR="$FAKETMP" -D ACTIVE_HOOKS="$ACTIVE_HOOKS" -f "$PROFILE_SRC" "$@"; }

sb true || die "profile failed to apply (missing ACTIVE_HOOKS param?)"

# 1. in-project write allowed (path has a space — exercises argv correctness)
sb /bin/sh -c "echo ok > '$PROJ/w.txt'" || die "in-project write denied (argv/space bug?)"
# 1b. PROJECT/.git/hooks ACTIVE hook files DENIED (persistence/escape vector),
# but inert *.sample files, the hooks dir node, and .git/config stay writable so
# `git init` and routine git operations through the sandbox still work. The whole
# hooks subtree is denied (covers EVERY hook name — common, obscure p4-*, and
# future), then the dir node + *.sample are re-allowed (last-match-wins). Note
# $PROJ here contains a space; the profile matches via subpath/literal, not a
# PROJECT-interpolated regex, so paths with regex metacharacters are safe too.
if sb /bin/sh -c "echo x > '$PROJ/.git/hooks/pre-commit'" 2>/dev/null; then
  die "SECURITY: PROJECT/.git/hooks/pre-commit write ALLOWED (planted hook runs outside the sandbox)"; fi
if sb /bin/sh -c "echo x > '$PROJ/.git/hooks/post-checkout'" 2>/dev/null; then
  die "SECURITY: PROJECT/.git/hooks/post-checkout write ALLOWED"; fi
# Obscure hook names NOT on any hand-maintained list must ALSO be denied (the
# subtree deny covers them; a name-allow-list would not).
if sb /bin/sh -c "echo x > '$PROJ/.git/hooks/post-index-change'" 2>/dev/null; then
  die "SECURITY: PROJECT/.git/hooks/post-index-change write ALLOWED (subtree deny regressed to a name list)"; fi
if sb /bin/sh -c "echo x > '$PROJ/.git/hooks/p4-changelist'" 2>/dev/null; then
  die "SECURITY: PROJECT/.git/hooks/p4-changelist write ALLOWED"; fi
# A hostile file that merely CONTAINS 'sample' but is not a *.sample suffix must
# stay denied (guards against a too-loose sample re-allow).
if sb /bin/sh -c "echo x > '$PROJ/.git/hooks/sample-evil'" 2>/dev/null; then
  die "SECURITY: PROJECT/.git/hooks/sample-evil write ALLOWED (sample re-allow too loose)"; fi
sb /bin/sh -c "echo x > '$PROJ/.git/hooks/pre-commit.sample'" \
  || die "PROJECT/.git/hooks/*.sample write denied ('git init' would fail; the *.sample re-allow is missing)"
# The *.sample re-allow must be SCOPED to this project — a *.sample write in some
# OTHER repo on the host must stay denied (write-containment). Use a
# hooks path under the REAL home, outside every writable root.
OTHER_HOOKS="$HOME/.pi-sb-hookprobe.$$/.git/hooks"
mkdir -p "$OTHER_HOOKS"
if sb /bin/sh -c "echo x > '$OTHER_HOOKS/evil.sample'" 2>/dev/null; then
  rm -rf "$HOME/.pi-sb-hookprobe.$$" 2>/dev/null || true
  die "SECURITY: out-of-project .git/hooks/*.sample write ALLOWED (write-containment breach)"; fi
rm -rf "$HOME/.pi-sb-hookprobe.$$" 2>/dev/null || true
sb /bin/sh -c "echo x >> '$PROJ/.git/config'" \
  || die "PROJECT/.git/config write denied (routine git ops would break; deny is meant to be scoped to hooks dirs)"

# 1c. core.hooksPath-style active hooks (PROJECT/.githooks): when ACTIVE_HOOKS
# points here, active hook writes (common + obscure names) must be denied. Default
# .git/hooks remains denied via the static PROJECT/.git/hooks rule.
ACTIVE_HOOKS="$PROJ/.githooks"
if sb /bin/sh -c "echo x > '$PROJ/.githooks/pre-commit'" 2>/dev/null; then
  die "SECURITY: ACTIVE_HOOKS=.githooks pre-commit write ALLOWED"; fi
if sb /bin/sh -c "echo x > '$PROJ/.githooks/post-checkout'" 2>/dev/null; then
  die "SECURITY: ACTIVE_HOOKS=.githooks post-checkout write ALLOWED"; fi
if sb /bin/sh -c "echo x > '$PROJ/.githooks/post-index-change'" 2>/dev/null; then
  die "SECURITY: ACTIVE_HOOKS=.githooks post-index-change write ALLOWED"; fi
if sb /bin/sh -c "echo x > '$PROJ/.githooks/p4-changelist'" 2>/dev/null; then
  die "SECURITY: ACTIVE_HOOKS=.githooks p4-changelist write ALLOWED"; fi
# Default hooks still denied while ACTIVE_HOOKS is the alternate path.
if sb /bin/sh -c "echo x > '$PROJ/.git/hooks/pre-commit'" 2>/dev/null; then
  die "SECURITY: default .git/hooks write ALLOWED while ACTIVE_HOOKS=.githooks"; fi
# Intended project write still works with ACTIVE_HOOKS flipped.
sb /bin/sh -c "echo ok > '$PROJ/w2.txt'" || die "in-project write denied when ACTIVE_HOOKS=.githooks"
ACTIVE_HOOKS="$PROJ/.git/hooks"

# 1d. Submodule metadata hooks under PROJECT/.git/modules/**/hooks — denied for
# every hook name; inert *.sample and the hooks dir node stay re-allowed so
# submodule init scaffolding still works.
if sb /bin/sh -c "echo x > '$PROJ/.git/modules/sub/hooks/pre-commit'" 2>/dev/null; then
  die "SECURITY: submodule hooks/pre-commit write ALLOWED"; fi
if sb /bin/sh -c "echo x > '$PROJ/.git/modules/sub/hooks/post-index-change'" 2>/dev/null; then
  die "SECURITY: submodule hooks/post-index-change write ALLOWED"; fi
if sb /bin/sh -c "echo x > '$PROJ/.git/modules/outer/modules/inner/hooks/p4-changelist'" 2>/dev/null; then
  die "SECURITY: nested submodule hooks write ALLOWED"; fi
if sb /bin/sh -c "echo x > '$PROJ/.git/modules/sub/hooks/sample-evil'" 2>/dev/null; then
  die "SECURITY: submodule hooks/sample-evil write ALLOWED (sample re-allow too loose)"; fi
sb /bin/sh -c "echo x > '$PROJ/.git/modules/sub/hooks/pre-commit.sample'" \
  || die "submodule hooks/*.sample write denied (submodule init scaffolding would break)"
sb /bin/sh -c "echo x > '$PROJ/.git/modules/outer/modules/inner/hooks/update.sample'" \
  || die "nested submodule hooks/*.sample write denied"

# 1e. Out-of-project ACTIVE_HOOKS under a writable root (/private/tmp via
# PROBEROOT): the ACTIVE_HOOKS subtree deny must override the /private/tmp allow.
OUT_ACTIVE_HOOKS="$PROBEROOT/out-of-project-hooks"
mkdir -p "$OUT_ACTIVE_HOOKS"
ACTIVE_HOOKS="$OUT_ACTIVE_HOOKS"
if sb /bin/sh -c "echo x > '$OUT_ACTIVE_HOOKS/pre-commit'" 2>/dev/null; then
  die "SECURITY: out-of-project ACTIVE_HOOKS/pre-commit write ALLOWED"; fi
if sb /bin/sh -c "echo x > '$OUT_ACTIVE_HOOKS/post-index-change'" 2>/dev/null; then
  die "SECURITY: out-of-project ACTIVE_HOOKS obscure hook write ALLOWED"; fi
# Writable root outside ACTIVE_HOOKS still works; default project hooks stay denied.
sb /bin/sh -c "echo x > '$PROBEROOT/not-hooks.txt'" \
  || die "write under /private/tmp (non-ACTIVE_HOOKS) denied unexpectedly"
if sb /bin/sh -c "echo x > '$PROJ/.git/hooks/pre-commit'" 2>/dev/null; then
  die "SECURITY: default .git/hooks write ALLOWED while ACTIVE_HOOKS is out-of-project"; fi
ACTIVE_HOOKS="$PROJ/.git/hooks"

# 2. outside-project write DENIED — the key proof. Target the REAL home dir: it is
# outside every writable root (the profile's HOME param points at FAKEHOME, and the
# real home is not under PROJECT/TMPDIR//private/tmp). Non-recursive cleanup.
ESC="$HOME/.pi-sb-escape-probe.$$"
if sb /bin/sh -c "echo x > '$ESC'" 2>/dev/null; then
  rm -f "$ESC" 2>/dev/null || true
  die "SECURITY: outside-project write ALLOWED"; fi
# 3. ~/.pi/agent/sessions-style write allowed but settings.json / extensions DENIED
sb /bin/sh -c "mkdir -p '$FAKEHOME/.pi/agent/sessions' && echo s > '$FAKEHOME/.pi/agent/sessions/x'" \
  || die "~/.pi/agent/sessions write denied (Pi session persistence would break)"
if sb /bin/sh -c "echo x >> '$FAKEHOME/.pi/agent/settings.json'" 2>/dev/null; then
  die "SECURITY: ~/.pi/agent/settings.json write ALLOWED"; fi
if sb /bin/sh -c "echo x >> '$FAKEHOME/.pi/agent/auth.json'" 2>/dev/null; then
  die "SECURITY: ~/.pi/agent/auth.json write ALLOWED"; fi
if sb /bin/sh -c "echo x >> '$FAKEHOME/.pi/agent/trust.json'" 2>/dev/null; then
  die "SECURITY: ~/.pi/agent/trust.json write ALLOWED"; fi
# Any *prompt*.md under ~/.pi/agent is denied (arbitrary name, not a fixed pair) —
# an agent-writable appended system prompt is a persistent steering-injection vector.
if sb /bin/sh -c "echo x >> '$FAKEHOME/.pi/agent/my-custom-prompt.md'" 2>/dev/null; then
  die "SECURITY: ~/.pi/agent custom prompt write ALLOWED"; fi
# Nested layouts too: a `[^/]*` selector covered only direct children and left
# ~/.pi/agent/prompts/*.md agent-writable (regression pin).
if sb /bin/sh -c "echo x >> '$FAKEHOME/.pi/agent/prompts/nested-prompt.md'" 2>/dev/null; then
  die "SECURITY: nested ~/.pi/agent/prompts prompt write ALLOWED"; fi
# …and the scoped require-all must NOT leak into the project: a bare suffix regex
# would be unanchored and deny this legitimate file (regression pin).
if ! sb /bin/sh -c "echo x >> '$PROJ/docs/prompt-guide.md'" 2>/dev/null; then
  die "OVER-DENY: PROJECT/docs/prompt-guide.md write DENIED (prompt regex not scoped)"; fi
# Ordinary agent runtime state must stay writable (no over-deny inside ~/.pi/agent).
if ! sb /bin/sh -c "echo x >> '$FAKEHOME/.pi/agent/run-history.json'" 2>/dev/null; then
  die "OVER-DENY: ~/.pi/agent/run-history.json write DENIED"; fi
if sb /bin/sh -c "touch '$FAKEHOME/.pi/agent/extensions/tamper'" 2>/dev/null; then
  die "SECURITY: ~/.pi/agent/extensions write ALLOWED (guard could be disabled)"; fi
# 4. secret reads denied (~/.ssh, project .env) but project source/cert READABLE
if sb /bin/sh -c "cat '$FAKEHOME/.ssh/id_probe'" >/dev/null 2>&1; then
  die "SECURITY: ~/.ssh read ALLOWED"; fi
if sb /bin/sh -c "cat '$FAKEHOME/.config/git/credentials'" >/dev/null 2>&1; then
  die "SECURITY: ~/.config/git/credentials read ALLOWED"; fi
if sb /bin/sh -c "cat '$PROJ/.env'" >/dev/null 2>&1; then
  die "SECURITY: project .env read ALLOWED"; fi
sb /bin/sh -c "cat '$PROJ/server.pem'" >/dev/null 2>&1 \
  || die "project .pem read DENIED (over-restriction; legit project files must be readable)"
# 5. write-deny symmetry for poisonable credential files + security log privacy:
#    ~/.netrc must not be writable (poisoned creds fire on next unsandboxed run);
#    the analyzer's security log (full command text) appendable but NOT readable.
if sb /bin/sh -c "echo x >> '$FAKEHOME/.netrc'" 2>/dev/null; then
  die "SECURITY: ~/.netrc write ALLOWED"; fi
if sb /bin/sh -c "echo x >> '$FAKEHOME/.config/git/credentials'" 2>/dev/null; then
  die "SECURITY: ~/.config/git/credentials write ALLOWED"; fi
if sb /bin/sh -c "cat '$FAKEHOME/.pi/agent/security-events.log'" >/dev/null 2>&1; then
  die "SECURITY: security-events.log read ALLOWED (flagged-command history leak)"; fi
sb /bin/sh -c "echo probe >> '$FAKEHOME/.pi/agent/security-events.log'" \
  || die "security-events.log append DENIED (analyzer logging would break)"

rm -rf "$PROBEROOT" 2>/dev/null || true
trap - EXIT
say "[test-sandbox-profile] profile OK: in-project write + project-file read allowed; default/.githooks/"
say "[test-sandbox-profile]   submodule/out-of-project ACTIVE_HOOKS, outside-project, ~/.pi config/auth/"
say "[test-sandbox-profile]   extensions writes, and secret reads all denied; *.sample + .git/config preserved."
