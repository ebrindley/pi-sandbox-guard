#!/usr/bin/env bash
#
# setup-hooks.sh — explicitly configure this repo's core.hooksPath to .githooks.
#
# Intentionally NOT wired as an npm `prepare` script: installing this package
# as a dependency must not mutate the consumer repository's git config.
# Contributors run this once after clone:  npm run setup:hooks
#
# Usage: scripts/setup-hooks.sh [--check] [--unset]
#   --check  verify hooksPath points at this repo's .githooks (exit 1 if not)
#   --unset  remove this repo's local core.hooksPath (if set)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib-ops.sh
. "$REPO_ROOT/scripts/lib-ops.sh"

MODE="set"
while [ $# -gt 0 ]; do
  case "$1" in
    --check) MODE="check"; shift ;;
    --unset) MODE="unset"; shift ;;
    *) ops_die "unknown arg: $1" ;;
  esac
done

if ! command -v git >/dev/null 2>&1; then
  ops_die "git not found"
fi

if ! ( cd "$REPO_ROOT" && git rev-parse --is-inside-work-tree >/dev/null 2>&1 ); then
  ops_die "not a git work tree: $REPO_ROOT"
fi

HOOKS_DIR="$REPO_ROOT/.githooks"
PRE_PUSH="$HOOKS_DIR/pre-push"
EXPECTED_REL=".githooks"

current="$(cd "$REPO_ROOT" && git config --local --get core.hooksPath 2>/dev/null || true)"

case "$MODE" in
  check)
    if [ "$current" != "$EXPECTED_REL" ] && [ "$current" != "$HOOKS_DIR" ]; then
      ops_say "hooksPath not configured (current='${current:-unset}'); run: npm run setup:hooks"
      exit 1
    fi
    [ -f "$PRE_PUSH" ] || ops_die "missing $PRE_PUSH"
    ops_say "OK: core.hooksPath=$current"
    exit 0
    ;;
  unset)
    if [ -n "$current" ]; then
      ( cd "$REPO_ROOT" && git config --local --unset core.hooksPath ) || true
      ops_say "unset local core.hooksPath (was $current)"
    else
      ops_say "core.hooksPath already unset"
    fi
    exit 0
    ;;
  set)
    [ -d "$HOOKS_DIR" ] || ops_die "missing hooks directory: $HOOKS_DIR"
    [ -f "$PRE_PUSH" ] || ops_die "missing pre-push hook: $PRE_PUSH"
    if [ ! -x "$PRE_PUSH" ]; then
      chmod +x "$PRE_PUSH" || ops_die "could not chmod +x $PRE_PUSH"
    fi
    ( cd "$REPO_ROOT" && git config --local core.hooksPath "$EXPECTED_REL" ) \
      || ops_die "failed to set core.hooksPath"
    ops_say "OK: set local core.hooksPath=$EXPECTED_REL"
    ops_say "    pre-push gate active for every push: fast checks (~12s), full suite"
    ops_say "    on main or analyzer changes (SKIP_PREPUSH_TESTS=1 to bypass)"
    exit 0
    ;;
  *)
    ops_die "internal: bad mode $MODE"
    ;;
esac
