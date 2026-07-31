#!/usr/bin/env bash
#
# deploy-all.sh — coordinated deploy of guard extension + launchers.
#
# Semantics:
#   1. Optional source gate (npm test) once for both components.
#   2. Preflight BOTH artifacts (dry-run) BEFORE any live mutation.
#   3. One shared release_id stamped into both provenance files.
#   4. Mutate guard first, then launchers.
#   5. On partial failure: restore the guard from its backup when safe;
#      report launcher backup paths (per-file restores are left for the operator
#      if a mid-install failure left mixed hashes — post-install hash checks
#      fail closed before declaring success).
#
# Does not run as part of npm test. Prefer temp --dest-* in CI.
#
# Usage:
#   scripts/deploy-all.sh [--dry-run] [--force-degraded] [--skip-tests]
#                         [--dest-guard <pi-sandbox-guard-dir>]
#                         [--dest-launchers <bin-dir>]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib-ops.sh
. "$REPO_ROOT/scripts/lib-ops.sh"

DRY_RUN=0
FORCE_DEGRADED=0
SKIP_TESTS=0
DEST_GUARD="$(ops_default_guard_dest)"
DEST_LAUNCHERS="$(ops_default_launchers_dest)"

say() { ops_say "$@"; }
die() { ops_die "$@"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --force-degraded) FORCE_DEGRADED=1; shift ;;
    --skip-tests) SKIP_TESTS=1; shift ;;
    --dest-guard)
      [ $# -ge 2 ] || die "--dest-guard requires a directory"
      DEST_GUARD="$2"; shift 2 ;;
    --dest-launchers)
      [ $# -ge 2 ] || die "--dest-launchers requires a directory"
      DEST_LAUNCHERS="$2"; shift 2 ;;
    *) die "unknown arg: $1" ;;
  esac
done

ops_require_single_line "--dest-guard" "$DEST_GUARD"
ops_require_single_line "--dest-launchers" "$DEST_LAUNCHERS"

[ "$(basename "$DEST_GUARD")" = "pi-sandbox-guard" ] \
  || die "--dest-guard must end with pi-sandbox-guard (got: $DEST_GUARD)"

RELEASE_ID="$(ops_make_release_id "$REPO_ROOT")"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/pi-sandbox-deploy-all-XXXXXX")"
GUARD_STATE="$WORKDIR/guard.state"
LAUNCHERS_STATE="$WORKDIR/launchers.state"
GUARD_OK=0
LAUNCHERS_OK=0
PHASE="init"

cleanup() {
  status=$?
  rm -rf "$WORKDIR" 2>/dev/null || true
  if [ "$status" -ne 0 ]; then
    say ""
    say "[deploy-all] FAILED during phase=$PHASE (exit $status)"
    say "[deploy-all] release_id=$RELEASE_ID"
    say "[deploy-all] guard_ok=$GUARD_OK launchers_ok=$LAUNCHERS_OK"
    if [ "$GUARD_OK" -eq 1 ] && [ "$LAUNCHERS_OK" -eq 0 ]; then
      say "[deploy-all] PARTIAL FAILURE: guard deployed, launchers did not."
    fi
  fi
  exit "$status"
}
trap cleanup EXIT

restore_guard_from_state() {
  local dest backup
  dest="$(ops_stamp_get "$GUARD_STATE" dest)"
  backup="$(ops_stamp_get "$GUARD_STATE" backup)"
  if [ -z "$dest" ]; then
    ops_warn "cannot restore guard: missing dest in state file $GUARD_STATE"
    return 1
  fi
  if [ -n "$backup" ] && [ -e "$backup" ]; then
    if ! rm -rf "$dest"; then
      ops_warn "cannot restore guard: failed to remove partial destination $dest"
      return 1
    fi
    if ! mv "$backup" "$dest"; then
      ops_warn "cannot restore guard: failed to move $backup back to $dest"
      return 1
    fi
    say "[deploy-all] restored guard from backup: $backup -> $dest"
    return 0
  fi
  # Fresh install (no prior artifact): safest rollback is to remove the new tree
  # so a partial coordinated release does not leave only-guard half-installed.
  if [ -e "$dest" ]; then
    if ! rm -rf "$dest"; then
      ops_warn "cannot roll back fresh guard install at $dest"
      return 1
    fi
    say "[deploy-all] removed fresh guard install at $dest (no prior backup)"
    return 0
  fi
  ops_warn "cannot restore guard: dest missing and no backup"
  return 1
}

# --- 1. Shared source gate (once) ---
PHASE="source-gate"
if [ "$SKIP_TESTS" -eq 1 ]; then
  say "[deploy-all] skipping source test suite (--skip-tests)"
elif [ "$DRY_RUN" -eq 1 ]; then
  say "[deploy-all] dry-run: skipping full test suite; component preflights still run"
else
  say "[deploy-all] running source test suite once for both components"
  ( cd "$REPO_ROOT" && npm test >/dev/null ) || die "source tests failed; refusing deploy:all"
  say "[deploy-all] source tests passed"
fi

# Shared argv fragments for optional --force-degraded (bash 3.2-safe).
run_deploy_local() {
  # Args after the function name are forwarded; optional force-degraded prepended.
  if [ "$FORCE_DEGRADED" -eq 1 ]; then
    bash "$REPO_ROOT/scripts/deploy-local.sh" --force-degraded "$@"
  else
    bash "$REPO_ROOT/scripts/deploy-local.sh" "$@"
  fi
}

# --- 2. Preflight both (no mutation) ---
PHASE="preflight-guard"
say "[deploy-all] preflight guard (dry-run) -> $DEST_GUARD"
run_deploy_local \
  --dry-run --skip-tests --release-id "$RELEASE_ID" \
  --dest "$DEST_GUARD" --state-file "$GUARD_STATE" \
  || die "guard preflight failed; no mutation performed"

PHASE="preflight-launchers"
say "[deploy-all] preflight launchers (dry-run) -> $DEST_LAUNCHERS"
bash "$REPO_ROOT/scripts/deploy-launchers.sh" \
  --dry-run --release-id "$RELEASE_ID" \
  --dest "$DEST_LAUNCHERS" --state-file "$LAUNCHERS_STATE" \
  || die "launchers preflight failed; no mutation performed"

say "[deploy-all] both preflights OK; release_id=$RELEASE_ID"

if [ "$DRY_RUN" -eq 1 ]; then
  PHASE="dry-run-done"
  say "[deploy-all] dry-run complete; no live destinations mutated"
  say "[deploy-all] would deploy guard -> $DEST_GUARD"
  say "[deploy-all] would deploy launchers -> $DEST_LAUNCHERS"
  exit 0
fi

# --- 3. Mutate guard ---
PHASE="deploy-guard"
say "[deploy-all] deploying guard -> $DEST_GUARD"
if run_deploy_local \
  --skip-tests --release-id "$RELEASE_ID" \
  --dest "$DEST_GUARD" --state-file "$GUARD_STATE"
then
  GUARD_OK=1
else
  die "guard deploy failed; launchers not attempted"
fi

# --- 4. Mutate launchers; roll back guard on failure when safe ---
PHASE="deploy-launchers"
say "[deploy-all] deploying launchers -> $DEST_LAUNCHERS"
if bash "$REPO_ROOT/scripts/deploy-launchers.sh" \
  --release-id "$RELEASE_ID" \
  --dest "$DEST_LAUNCHERS" --state-file "$LAUNCHERS_STATE"
then
  LAUNCHERS_OK=1
else
  ops_warn "launchers deploy failed after guard success"
  PHASE="rollback-guard"
  if restore_guard_from_state; then
    GUARD_OK=0
    say "[deploy-all] rolled back guard after launchers failure"
  else
    ops_warn "guard rollback incomplete; inspect $DEST_GUARD and backups"
  fi
  die "partial failure: launchers deploy failed (guard rollback attempted)"
fi

PHASE="done"
say ""
say "[deploy-all] DONE. Coordinated release_id=$RELEASE_ID"
say "[deploy-all] guard -> $DEST_GUARD"
say "[deploy-all] launchers -> $DEST_LAUNCHERS"

# An unconditional pointer, not a state check: the binding is host-local state, not a
# deployed artifact, and reporting it here would mean reconstructing the home the shim
# derives for itself. `status.sh` owns state reporting.
say "[deploy-all] if you have not recorded the Pi install yet: npm run bind"
say "[deploy-all]   (auto-detection covers only an npm -g install into /opt/homebrew"
say "[deploy-all]    or /usr/local; anything else fails closed until bound)"
say "[deploy-all] verify with: npm run status"
