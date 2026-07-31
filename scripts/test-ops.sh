#!/usr/bin/env bash
#
# test-ops.sh — non-installing checks for ops/deploy/status/hook scripts.
#
# NEVER mutates live ~/.pi or ~/.local/bin. All deploys use temp destinations.
# Safe for CI and local pre-push without side effects on the host install.
#
# Two host touches, both restored on exit (including on failure) by the EXIT trap:
# a scratch directory under ~/.local/share (bind refuses targets under the standard
# temp roots, so the one case needing an ACCEPTED target cannot use the workdir),
# and repo-local core.hooksPath, restored to its prior value — set, empty, or
# absent — after the setup-hooks check.
#
# Usage: scripts/test-ops.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib-ops.sh
. "$REPO_ROOT/scripts/lib-ops.sh"

say() { ops_say "$@"; }
die() { ops_die "$@"; }

PASS=0
fail() { die "FAIL: $*"; }
pass() { PASS=$((PASS + 1)); say "OK: $*"; }

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/pi-ops-test-XXXXXX")"
trap 'rm -rf "$WORKDIR" 2>/dev/null || true' EXIT

# Space in path: shell-safety regression.
DEST_BASE="$WORKDIR/My Dest"
GUARD_DEST="$DEST_BASE/extensions/pi-sandbox-guard"
LAUNCHERS_DEST="$DEST_BASE/bin"
mkdir -p "$DEST_BASE"

say "[test-ops] workdir=$WORKDIR"

# --- 1. Syntax ---
for s in \
  scripts/lib-ops.sh \
  scripts/setup-hooks.sh \
  scripts/deploy-local.sh \
  scripts/deploy-launchers.sh \
  scripts/deploy-all.sh \
  scripts/status.sh \
  scripts/test-ops.sh \
  scripts/test-sandbox-profile.sh \
  .githooks/pre-push
do
  bash -n "$REPO_ROOT/$s" || fail "bash -n $s"
done
pass "bash -n on ops scripts"

# --- 2. setup-hooks --check is non-mutating; --set only touches repo-local git config ---
# Exercising --set means writing repo-local core.hooksPath, so restore whatever the
# developer had. Without this, merely running the test suite opts the repository into
# the pre-push gate — a side effect on the host checkout that this script promises not
# to have, and a surprising one for someone still deciding whether to enable it.
# Track PRESENCE separately from value: `--get` exits 0 with empty output for a
# key explicitly set to the empty string, and 1 when the key is absent. Those are
# different states — an empty local value deliberately overrides an inherited
# global hooksPath — so testing the captured string for emptiness would unset a key
# that existed and silently activate the global hooks path.
HOOKSPATH_PRE=""
HOOKSPATH_WAS_SET=0
if HOOKSPATH_PRE="$(git -C "$REPO_ROOT" config --local --get core.hooksPath 2>/dev/null)"; then
  HOOKSPATH_WAS_SET=1
fi
restore_hookspath() {
  if [ "$HOOKSPATH_WAS_SET" -eq 1 ]; then
    git -C "$REPO_ROOT" config --local core.hooksPath "$HOOKSPATH_PRE" 2>/dev/null || true
  else
    git -C "$REPO_ROOT" config --local --unset core.hooksPath 2>/dev/null || true
  fi
}
trap 'rm -rf "$WORKDIR" "${BIND_OK_DIR:-}" 2>/dev/null || true; restore_hookspath' EXIT
bash "$REPO_ROOT/scripts/setup-hooks.sh" --check >/dev/null 2>&1 \
  || bash "$REPO_ROOT/scripts/setup-hooks.sh" >/dev/null
bash "$REPO_ROOT/scripts/setup-hooks.sh" --check || fail "setup-hooks --check after set"
restore_hookspath
pass "setup-hooks check/set"

# --- 3. status on empty temp dests with --allow-missing ---
bash "$REPO_ROOT/scripts/status.sh" \
  --dest-guard "$GUARD_DEST" \
  --dest-launchers "$LAUNCHERS_DEST" \
  --allow-missing || fail "status --allow-missing on empty dests"
pass "status allow-missing"

# --- 4. deploy-all --dry-run (no live mutation; skip full suite) ---
# On non-macOS, deploy-launchers still requires sandbox-exec binary presence.
# Guard dry-run is always exercised. Nested sandboxes may skip live SBPL apply
# during dry-run (non-strict); real deploy remains strict.
if command -v sandbox-exec >/dev/null 2>&1; then
  bash "$REPO_ROOT/scripts/deploy-all.sh" \
    --dry-run --skip-tests \
    --dest-guard "$GUARD_DEST" \
    --dest-launchers "$LAUNCHERS_DEST" \
    || fail "deploy-all --dry-run"
  [ ! -e "$GUARD_DEST" ] || fail "dry-run should not create guard dest"
  [ ! -e "$LAUNCHERS_DEST" ] || fail "dry-run should not create launchers dest"
  pass "deploy-all dry-run"
else
  bash "$REPO_ROOT/scripts/deploy-local.sh" \
    --dry-run --skip-tests \
    --dest "$GUARD_DEST" \
    || fail "deploy-local --dry-run"
  pass "deploy-local dry-run (non-macOS)"
fi

# --- 5. Real deploy into TEMP dirs only (coordinated), then status ---
# Real launcher deploy requires STRICT Seatbelt apply. Non-strict skip exits 0,
# so probe with STRICT=1 to decide whether the install path is runnable here.
if command -v sandbox-exec >/dev/null 2>&1 \
  && PI_SANDBOX_PROFILE_STRICT=1 bash "$REPO_ROOT/scripts/test-sandbox-profile.sh" >/dev/null 2>&1
then
  bash "$REPO_ROOT/scripts/deploy-all.sh" \
    --skip-tests \
    --dest-guard "$GUARD_DEST" \
    --dest-launchers "$LAUNCHERS_DEST" \
    || fail "deploy-all to temp dests"
  bash "$REPO_ROOT/scripts/status.sh" \
    --dest-guard "$GUARD_DEST" \
    --dest-launchers "$LAUNCHERS_DEST" \
    || fail "status after temp deploy"
  rid_g="$(ops_stamp_get "$GUARD_DEST/.deployed-version" release_id)"
  rid_l="$(ops_stamp_get "$LAUNCHERS_DEST/.pi-sandbox-launchers-version" release_id)"
  [ -n "$rid_g" ] || fail "missing guard release_id"
  [ "$rid_g" = "$rid_l" ] || fail "release_id mismatch guard=$rid_g launchers=$rid_l"
  # Forged/unusual stamp text must remain valid JSON and compare as data.
  weird_rid='release-"quoted"'
  for stamp in \
    "$GUARD_DEST/.deployed-version" \
    "$LAUNCHERS_DEST/.pi-sandbox-launchers-version"
  do
    awk -F= -v rid="$weird_rid" \
      '$1 == "release_id" { $0 = "release_id=" rid } { print }' \
      "$stamp" > "$stamp.tmp"
    mv "$stamp.tmp" "$stamp"
  done
  bash "$REPO_ROOT/scripts/status.sh" \
    --json \
    --dest-guard "$GUARD_DEST" \
    --dest-launchers "$LAUNCHERS_DEST" > "$WORKDIR/status.json" \
    || fail "status --json with quoted release_id"
  node -e 'JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"))' \
    "$WORKDIR/status.json" \
    || fail "status --json emitted invalid JSON"
  # Tamper detection: corrupt installed analyzer and expect status drift
  printf 'TAMPER\n' >> "$GUARD_DEST/src/validate-bash-command.sh"
  if bash "$REPO_ROOT/scripts/status.sh" \
    --dest-guard "$GUARD_DEST" \
    --dest-launchers "$LAUNCHERS_DEST" >/dev/null 2>&1
  then
    fail "status should detect tampered analyzer hash"
  fi
  pass "deploy-all + status + tamper detection (temp only)"

  # Retired-wrapper detection is scoped to launcher_names_seen, NOT to every
  # executable in the launcher dest. That dest is normally ~/.local/bin, a SHARED
  # PATH dir, so scanning all of it reported every unrelated tool sharing that
  # directory as "stale?" and printed DRIFT on a clean install — which teaches the
  # reader to ignore drift. Both directions matter, so assert both.
  RETIRE_DEST="$WORKDIR/retire-bin"
  mkdir -p "$RETIRE_DEST"
  cp "$LAUNCHERS_DEST/pi" "$RETIRE_DEST/pi"
  cp "$LAUNCHERS_DEST/pi-sandbox.sb" "$LAUNCHERS_DEST/pi-sandbox-preamble.zsh" "$RETIRE_DEST/"
  chmod +x "$RETIRE_DEST/pi"
  {
    echo "deployed_at=2026-07-29T00:00:00-0400"
    echo "release_id=retire-test"
    echo "component=launchers"
    echo "git_sha=deadbee"
    echo "git_state=clean"
    echo "hash_algo=sha256"
    echo "hash_profile=$(ops_hash_file "$RETIRE_DEST/pi-sandbox.sb")"
    echo "hash_preamble=$(ops_hash_file "$RETIRE_DEST/pi-sandbox-preamble.zsh")"
    echo "launcher_names=pi"
    echo "launcher_names_seen=pi,example-retired"
    echo "hash_launcher_pi=$(ops_hash_file "$RETIRE_DEST/pi")"
  } > "$RETIRE_DEST/.pi-sandbox-launchers-version"

  # An unrelated executable that this dest never deployed must NOT be reported.
  : > "$RETIRE_DEST/some-unrelated-tool"
  chmod +x "$RETIRE_DEST/some-unrelated-tool"
  bash "$REPO_ROOT/scripts/status.sh" --dest-launchers "$RETIRE_DEST" \
    > "$WORKDIR/retire-clean.txt" 2>&1 || true
  if grep -q 'some-unrelated-tool' "$WORKDIR/retire-clean.txt"; then
    fail "status flagged an unrelated executable as a stale launcher"
  fi

  # A wrapper this dest HAS deployed before, still executable but dropped from the
  # current set, must be reported — that is the shim-bypass-retirement case.
  : > "$RETIRE_DEST/example-retired"
  chmod +x "$RETIRE_DEST/example-retired"
  bash "$REPO_ROOT/scripts/status.sh" --dest-launchers "$RETIRE_DEST" \
    > "$WORKDIR/retire-drift.txt" 2>&1 || true
  grep -q 'launcher:example-retired' "$WORKDIR/retire-drift.txt" \
    || fail "status missed a previously deployed wrapper left executable on PATH"

  # An older stamp predates launcher_names_seen; status must degrade quietly, not error.
  grep -v '^launcher_names_seen=' "$RETIRE_DEST/.pi-sandbox-launchers-version" \
    > "$RETIRE_DEST/.stamp.tmp"
  mv "$RETIRE_DEST/.stamp.tmp" "$RETIRE_DEST/.pi-sandbox-launchers-version"
  bash "$REPO_ROOT/scripts/status.sh" --dest-launchers "$RETIRE_DEST" \
    > "$WORKDIR/retire-legacy.txt" 2>&1 || true
  grep -q 'launcher:pi' "$WORKDIR/retire-legacy.txt" \
    || fail "status broke on a stamp written before launcher_names_seen existed"
  pass "retired-wrapper scan is stamp-scoped, not a shared-PATH sweep"

  # Force a launcher install failure after profile/preamble mutation and prove
  # the transactional rollback restores prior files and leaves no partial set.
  ROLLBACK_DEST="$DEST_BASE/rollback-bin"
  mkdir -p "$ROLLBACK_DEST/pi"
  printf 'old-profile\n' > "$ROLLBACK_DEST/pi-sandbox.sb"
  printf 'old-preamble\n' > "$ROLLBACK_DEST/pi-sandbox-preamble.zsh"
  if bash "$REPO_ROOT/scripts/deploy-launchers.sh" \
    --dest "$ROLLBACK_DEST" >/dev/null 2>&1
  then
    fail "forced launcher failure unexpectedly succeeded"
  fi
  [ "$(cat "$ROLLBACK_DEST/pi-sandbox.sb")" = "old-profile" ] \
    || fail "launcher rollback did not restore profile"
  [ "$(cat "$ROLLBACK_DEST/pi-sandbox-preamble.zsh")" = "old-preamble" ] \
    || fail "launcher rollback did not restore preamble"
  [ -d "$ROLLBACK_DEST/pi" ] || fail "launcher rollback disturbed pre-existing pi directory"
  [ ! -e "$ROLLBACK_DEST/example-custom" ] || fail "launcher rollback left a partial example-custom"
  [ ! -e "$ROLLBACK_DEST/.pi-sandbox-launchers-version" ] \
    || fail "launcher rollback left a provenance stamp"
  pass "launcher transactional rollback"
elif command -v sandbox-exec >/dev/null 2>&1; then
  # Still exercise guard-only temp install + status without launcher mutation.
  bash "$REPO_ROOT/scripts/deploy-local.sh" \
    --skip-tests \
    --dest "$GUARD_DEST" \
    || fail "deploy-local to temp dest"
  # Guard present + launchers absent => status must report incomplete install.
  if bash "$REPO_ROOT/scripts/status.sh" \
    --dest-guard "$GUARD_DEST" \
    --dest-launchers "$LAUNCHERS_DEST" >/dev/null 2>&1
  then
    fail "status should fail when launchers missing but guard present"
  fi
  # Source/runtime hash for guard alone should match (stamp + file).
  rid_g="$(ops_stamp_get "$GUARD_DEST/.deployed-version" release_id)"
  [ -n "$rid_g" ] || fail "missing guard release_id after temp deploy"
  hs="$(ops_hash_file "$REPO_ROOT/src/validate-bash-command.sh")"
  hd="$(ops_hash_file "$GUARD_DEST/src/validate-bash-command.sh")"
  [ "$hs" = "$hd" ] || fail "guard analyzer hash mismatch after temp deploy"
  printf 'TAMPER\n' >> "$GUARD_DEST/src/validate-bash-command.sh"
  hs2="$(ops_hash_file "$REPO_ROOT/src/validate-bash-command.sh")"
  hd2="$(ops_hash_file "$GUARD_DEST/src/validate-bash-command.sh")"
  [ "$hs2" != "$hd2" ] || fail "tamper did not change runtime analyzer hash"
  pass "guard temp deploy + tamper detection (launchers skipped: no live profile apply)"
else
  say "[test-ops] sandbox-exec absent; skipping install path"
  pass "skipped install (no sandbox-exec)"
fi

# --- 6. Provenance helper: hash mismatch fails loudly ---
# ops_require_same_hash exits the process on mismatch (deploy fail-closed);
# probe it in a subshell so the test harness survives the expected failure.
A="$WORKDIR/a.txt"; B="$WORKDIR/b.txt"
printf 'x\n' > "$A"
printf 'y\n' > "$B"
if ( ops_require_same_hash "probe" "$A" "$B" ) 2>/dev/null; then
  fail "ops_require_same_hash should fail on different content"
fi
printf 'x\n' > "$B"
ops_require_same_hash "probe" "$A" "$B" || fail "ops_require_same_hash should pass on same content"
pass "provenance hash helper"

# --- 7. JSON helper: untrusted stamp text remains valid JSON ---
JSON_QUOTED="$(ops_json_quote 'release-"quoted"\backslash')"
printf '%s' "$JSON_QUOTED" \
  | node -e 'let s="";process.stdin.on("data",c=>s+=c).on("end",()=>JSON.parse(s))' \
  || fail "ops_json_quote emitted invalid JSON"
pass "JSON quoting helper"

# --- 8. Line-oriented state values reject record injection ---
if ( ops_require_single_line "probe" $'safe\nbackup=/private/tmp/other' ) 2>/dev/null; then
  fail "ops_require_single_line accepted an LF"
fi
if ( ops_require_single_line "probe" $'safe\rbackup=/private/tmp/other' ) 2>/dev/null; then
  fail "ops_require_single_line accepted a CR"
fi
ops_require_single_line "probe" "path with spaces" || fail "single-line value rejected"

INJECTED_GUARD_DEST="$WORKDIR/decoy"$'\n'"backup=$WORKDIR/victim/pi-sandbox-guard"
if bash "$REPO_ROOT/scripts/deploy-local.sh" \
  --dry-run --skip-tests --dest "$INJECTED_GUARD_DEST" >/dev/null 2>&1
then
  fail "deploy-local accepted a newline-bearing --dest"
fi
if bash "$REPO_ROOT/scripts/deploy-all.sh" \
  --dry-run --skip-tests \
  --dest-guard "$INJECTED_GUARD_DEST" \
  --dest-launchers "$LAUNCHERS_DEST" >/dev/null 2>&1
then
  fail "deploy-all accepted a newline-bearing --dest-guard"
fi
pass "deploy state inputs reject newline record injection"

# --- 9. Launcher static check still green (no deploy) ---
node "$REPO_ROOT/scripts/check-launchers.mjs" >/dev/null \
  || fail "check-launchers"
pass "launcher static check"

# --- 10. PATH lint: an EMPTY component is a cwd lookup, not padding ---
# zsh resolves an empty PATH field against the current directory, so `/usr/bin::/bin`
# lets a project-local binary win BEFORE Seatbelt applies. A `.filter(Boolean)` that
# drops the empty field passes this wrapper, which is why it is pinned here.
LINT_DIR="$WORKDIR/lint"
mkdir -p "$LINT_DIR"
# The wholly empty forms are included deliberately: a `+` quantifier in the
# matcher skipped those lines entirely, so the MOST permissive spelling was the
# one that escaped the check.
for pv in 'PATH="/usr/bin::/bin"' 'PATH=":/usr/bin"' 'PATH="/usr/bin:"' 'PATH=""' 'PATH='; do
  awk -v pv="$pv" 'NR==1{print; print pv; next} {print}' \
    "$REPO_ROOT/launchers/example-custom" > "$LINT_DIR/w"
  if node "$REPO_ROOT/scripts/check-launchers.mjs" --sources "$LINT_DIR/w" >/dev/null 2>&1; then
    fail "check-launchers accepted an empty PATH component ($pv)"
  fi
done
# The same wrapper with no empty field must still pass, or the check is vacuous.
awk 'NR==1{print; print "PATH=\"/usr/bin:/bin\""; next} {print}' \
  "$REPO_ROOT/launchers/example-custom" > "$LINT_DIR/w"
node "$REPO_ROOT/scripts/check-launchers.mjs" --sources "$LINT_DIR/w" >/dev/null 2>&1 \
  || fail "check-launchers rejected a wrapper with only trusted PATH components"
pass "PATH lint rejects empty components"

# --- 11. Launcher handoff: every exec must target the sibling shim ---
awk '
  /^exec "\$PI_SHIM" "\$@"$/ {
    print "if false; then"
    print "  exec \"$PI_SHIM\" \"$@\""
    print "fi"
    print "BIN=\"/opt/homebrew/bin/pi\""
    print "exec \"$BIN\" \"$@\""
    next
  }
  { print }
' "$REPO_ROOT/launchers/example-custom" > "$LINT_DIR/dead-shim-exec"
if node "$REPO_ROOT/scripts/check-launchers.mjs" --sources "$LINT_DIR/dead-shim-exec" >/dev/null 2>&1; then
  fail "check-launchers accepted a dead protected-shim exec plus a live alternate exec"
fi
awk '
  /^exec "\$PI_SHIM" "\$@"$/ {
    print "if true; then exec \"/opt/homebrew/bin/pi\" \"$@\"; fi"
    print "exec \"$PI_SHIM\" \"$@\""
    next
  }
  { print }
' "$REPO_ROOT/launchers/example-custom" > "$LINT_DIR/inline-alternate-exec"
if node "$REPO_ROOT/scripts/check-launchers.mjs" --sources "$LINT_DIR/inline-alternate-exec" >/dev/null 2>&1; then
  fail "check-launchers accepted a same-line alternate exec before the protected handoff"
fi
awk '
  /^exec "\$PI_SHIM" "\$@"$/ {
    print "\"/opt/homebrew/bin/pi\" \"$@\""
    print "exit 0"
    print "exec \"$PI_SHIM\" \"$@\""
    next
  }
  { print }
' "$REPO_ROOT/launchers/example-custom" > "$LINT_DIR/non-exec-pi"
if node "$REPO_ROOT/scripts/check-launchers.mjs" --sources "$LINT_DIR/non-exec-pi" >/dev/null 2>&1; then
  fail "check-launchers accepted a direct non-exec Pi invocation"
fi
awk '
  /^exec "\$PI_SHIM" "\$@"$/ {
    print "if [ -n \"${USE_A:-}\" ]; then"
    print "  exec \"$PI_SHIM\" \"$@\""
    print "fi"
    print "exec \"$PI_SHIM\" \"$@\""
    next
  }
  { print }
' "$REPO_ROOT/launchers/example-custom" > "$LINT_DIR/branch-shim-execs"
node "$REPO_ROOT/scripts/check-launchers.mjs" --sources "$LINT_DIR/branch-shim-execs" >/dev/null \
  || fail "check-launchers rejected multiple protected conditional handoffs"
pass "launcher lint requires every exec handoff to target the protected shim"

# --- 12. Pre-sandbox commands: reject known bare shells/downloaders and writable absolute helpers ---
for command in 'bash -c true' 'sh -c true' 'wget https://example.invalid/x' 'osascript -e return' '/tmp/preflight-helper'; do
  awk -v command="$command" 'NR==2 { print command } { print }' \
    "$REPO_ROOT/launchers/example-custom" > "$LINT_DIR/untrusted-helper"
  if node "$REPO_ROOT/scripts/check-launchers.mjs" --sources "$LINT_DIR/untrusted-helper" >/dev/null 2>&1; then
    fail "check-launchers accepted untrusted pre-sandbox command: $command"
  fi
done
awk 'NR==2 { print "HELPER_BIN=\"/tmp/evil\""; print "\"$HELPER_BIN\" preflight" } { print }' \
  "$REPO_ROOT/launchers/example-custom" > "$LINT_DIR/untrusted-helper-var"
if node "$REPO_ROOT/scripts/check-launchers.mjs" --sources "$LINT_DIR/untrusted-helper-var" >/dev/null 2>&1; then
  fail "check-launchers accepted a helper variable pinned to an untrusted path"
fi
awk 'NR==2 { print "path=(/usr/bin /bin)" } { print }' \
  "$REPO_ROOT/launchers/example-custom" > "$LINT_DIR/trusted-path-array"
node "$REPO_ROOT/scripts/check-launchers.mjs" --sources "$LINT_DIR/trusted-path-array" >/dev/null \
  || fail "check-launchers rejected a trusted zsh path array"

for command in \
  '{ /opt/homebrew/bin/pi "$@"; exit 0; }' \
  'command pi "$@"' \
  'case "${1:-}" in raw) /opt/homebrew/bin/pi "$@" ;; esac' \
  '/bin/sh -c '\''exec /opt/homebrew/bin/pi "$@"'\''' \
  '/usr/bin/env /tmp/evil' \
  'if [ -n "$HOME" ] && /tmp/evil ]; then' \
  'if [ -n "$HOME" ] && exec /opt/homebrew/bin/pi "$@" ]; then' \
  'env FOO=1 /tmp/evil' \
  'until /tmp/evil; do break; done'
do
  awk -v command="$command" 'NR==2 { print command } { print }' \
    "$REPO_ROOT/launchers/example-custom" > "$LINT_DIR/unsupported-shell-form"
  if node "$REPO_ROOT/scripts/check-launchers.mjs" --sources "$LINT_DIR/unsupported-shell-form" >/dev/null 2>&1; then
    fail "check-launchers accepted unsupported pre-sandbox shell form: $command"
  fi
done
awk 'NR==2 { print "helper=\"/tmp/evil\""; print "\"$helper\" preflight" } { print }' \
  "$REPO_ROOT/launchers/example-custom" > "$LINT_DIR/lowercase-helper-var"
if node "$REPO_ROOT/scripts/check-launchers.mjs" --sources "$LINT_DIR/lowercase-helper-var" >/dev/null 2>&1; then
  fail "check-launchers accepted an unclassified lowercase command variable"
fi
awk 'NR==2 { print "readonly SED_BIN=\"/usr/bin/sed\"  # pinned"; print "\"$SED_BIN\" --version >/dev/null" } { print }' \
  "$REPO_ROOT/launchers/example-custom" > "$LINT_DIR/readonly-helper"
node "$REPO_ROOT/scripts/check-launchers.mjs" --sources "$LINT_DIR/readonly-helper" >/dev/null \
  || fail "check-launchers rejected a readonly trusted helper with a trailing comment"

for declaration in \
  'readonly PATH="/tmp:/usr/bin"' \
  'typeset PATH="/tmp:/usr/bin"' \
  'local PATH="/tmp:/usr/bin"'
do
  awk -v declaration="$declaration" 'NR==2 { print declaration } { print }' \
    "$REPO_ROOT/launchers/example-custom" > "$LINT_DIR/untrusted-prefixed-path"
  if node "$REPO_ROOT/scripts/check-launchers.mjs" --sources "$LINT_DIR/untrusted-prefixed-path" >/dev/null 2>&1; then
    fail "check-launchers accepted an untrusted prefixed PATH declaration: $declaration"
  fi
done
pass "launcher lint rejects untrusted pre-sandbox commands"

# --- bind-executable.sh -----------------------------------------------------
# bind is the only writer of the recorded binding, and the binding is exempt from the
# trusted-prefix list. So bind must refuse exactly what the shim would refuse: recording
# a value the launcher then rejects would trade a clear error here for a confusing one at
# launch. These cases mirror the resolver tests in test/shim.mjs.
BIND_SH="$REPO_ROOT/scripts/bind-executable.sh"
BIND_CFG_DIR="$(mktemp -d "${TMPDIR:-/tmp}/pi-bind-test.XXXXXX")"
BIND_WRITABLE="$BIND_CFG_DIR/agent-writable-pi"
cp /usr/bin/true "$BIND_WRITABLE"
chmod +x "$BIND_WRITABLE"

bind_refuses() {
  local desc="$1"; shift
  if PI_SANDBOX_CONFIG_DIR="$BIND_CFG_DIR/conf" bash "$BIND_SH" --yes "$@" >/dev/null 2>&1; then
    fail "bind accepted $desc"
  fi
}

bind_refuses "a relative path" --pi ./pi
bind_refuses "a nonexistent path" --pi /opt/homebrew/bin/pi-does-not-exist
bind_refuses "a directory" --pi /opt/homebrew/bin
bind_refuses "the protected shim itself" --pi "$REPO_ROOT/launchers/pi"
# The mktemp dir is under the Darwin per-user temp root, which the profile grants
# file-write* to: a binding there would let a confined session rewrite its own launcher.
bind_refuses "an executable inside a Seatbelt write root" --pi "$BIND_WRITABLE"

# A legitimate target records, round-trips through --show/--check, and preserves
# unrelated keys so a re-bind never silently drops hand-written config.
#
# This target must be one bind ACCEPTS, so it cannot live in the workdir: on a
# stock host $TMPDIR is a Darwin per-user temp path, which is one of the Seatbelt
# write roots bind refuses (the case just above asserts that refusal). Note the
# refusal list is a fixed set of path shapes — /tmp, /var/tmp, /var/folders/*/T,
# and specific ~ caches — not "whatever $TMPDIR points at", so pointing TMPDIR
# somewhere exotic would make the refusal case above stop refusing.
#
# Registered with the EXIT trap rather than deleted at the end of the block,
# because any fail() in between exits immediately under `set -e` and would
# otherwise leave the directory behind in a real $HOME.
# mktemp does not create parents, and macOS does not ship ~/.local/share — it
# appears only once some tool creates it. Without this, a clean host aborts here
# under `set -e` at the last check group, which reads like an ops-script defect.
mkdir -p "$HOME/.local/share"
BIND_OK_DIR="$(mktemp -d "$HOME/.local/share/pi-bind-ok.XXXXXX")"
# Re-arm the same trap so it now also removes BIND_OK_DIR. Restated in full
# because a bare `trap` REPLACES the handler — dropping restore_hookspath here
# would silently undo the git-config restore installed above.
trap 'rm -rf "$WORKDIR" "$BIND_OK_DIR" 2>/dev/null || true; restore_hookspath' EXIT
cp /usr/bin/true "$BIND_OK_DIR/pi"
chmod +x "$BIND_OK_DIR/pi"
BIND_CONF_DIR="$BIND_CFG_DIR/conf"
mkdir -p "$BIND_CONF_DIR"
printf '# hand-written comment\nsomeother=/usr/bin/true\n' > "$BIND_CONF_DIR/executables.conf"
PI_SANDBOX_CONFIG_DIR="$BIND_CONF_DIR" bash "$BIND_SH" --pi "$BIND_OK_DIR/pi" --yes >/dev/null \
  || fail "bind refused a legitimate out-of-prefix target"
grep -q "^pi=$BIND_OK_DIR/pi$" "$BIND_CONF_DIR/executables.conf" \
  || fail "bind did not record the pi key"
grep -q '^someother=/usr/bin/true$' "$BIND_CONF_DIR/executables.conf" \
  || fail "bind dropped an unrelated key on write"
grep -q '^# hand-written comment$' "$BIND_CONF_DIR/executables.conf" \
  || fail "bind dropped a hand-written comment on write"
PI_SANDBOX_CONFIG_DIR="$BIND_CONF_DIR" bash "$BIND_SH" --check >/dev/null \
  || fail "bind --check rejected a fresh valid binding"

# Staleness must be exit 3 (actionable), never exit 0 (silently fine).
printf 'pi=/opt/homebrew/bin/pi-vanished\n' > "$BIND_CONF_DIR/executables.conf"
bind_check_rc=0
PI_SANDBOX_CONFIG_DIR="$BIND_CONF_DIR" bash "$BIND_SH" --check >/dev/null 2>&1 || bind_check_rc=$?
[ "$bind_check_rc" -eq 3 ] || fail "bind --check exited $bind_check_rc for a stale binding (expected 3)"

rm -rf "$BIND_CFG_DIR"
pass "bind records only launchable targets and reports staleness"

say ""
say "[test-ops] all checks passed ($PASS groups)"
