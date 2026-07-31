#!/usr/bin/env bash
#
# status.sh — read-only drift check: source vs runtime hashes + shared release_id.
#
# Compares repo source files to installed guard/launchers artifacts.
# Does NOT read auth/settings/trust or any credential files.
# Exit 0 when in sync (or components absent and --allow-missing).
# Exit 1 on drift / mismatched release identities / hash failures.
#
# Usage:
#   scripts/status.sh [--dest-guard <dir>] [--dest-launchers <dir>]
#                     [--allow-missing] [--json]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib-ops.sh
. "$REPO_ROOT/scripts/lib-ops.sh"

DEST_GUARD="$(ops_default_guard_dest)"
DEST_LAUNCHERS="$(ops_default_launchers_dest)"
ALLOW_MISSING=0
JSON=0
DRIFT=0
MISSING=0

say() { ops_say "$@"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --dest-guard)
      [ $# -ge 2 ] || ops_die "--dest-guard requires a directory"
      DEST_GUARD="$2"; shift 2 ;;
    --dest-launchers)
      [ $# -ge 2 ] || ops_die "--dest-launchers requires a directory"
      DEST_LAUNCHERS="$2"; shift 2 ;;
    --allow-missing) ALLOW_MISSING=1; shift ;;
    --json) JSON=1; shift ;;
    *) ops_die "unknown arg: $1" ;;
  esac
done

report() {
  # kind path detail
  if [ "$JSON" -eq 0 ]; then
    printf '%s | %s | %s\n' "$1" "$2" "$3"
  fi
}

check_pair() {
  local label="$1" src="$2" dst="$3"
  local hs hd
  if [ ! -f "$src" ]; then
    report "error" "$src" "missing source"
    DRIFT=1
    return
  fi
  if [ ! -f "$dst" ]; then
    report "missing" "$dst" "runtime absent for $label"
    MISSING=1
    DRIFT=1
    return
  fi
  hs="$(ops_hash_file "$src")"
  hd="$(ops_hash_file "$dst")"
  if [ "$hs" = "$hd" ] && [ -n "$hs" ]; then
    report "ok" "$label" "$hs"
  else
    report "drift" "$label" "source=$hs runtime=$hd"
    DRIFT=1
  fi
}

GUARD_STAMP="$DEST_GUARD/.deployed-version"
LAUNCHERS_STAMP="$DEST_LAUNCHERS/.pi-sandbox-launchers-version"
GUARD_PRESENT=0
LAUNCHERS_PRESENT=0
if [ -d "$DEST_GUARD" ]; then
  GUARD_PRESENT=1
fi
if [ -f "$DEST_LAUNCHERS/pi-sandbox.sb" ] || [ -f "$DEST_LAUNCHERS/pi" ]; then
  LAUNCHERS_PRESENT=1
fi

if [ "$JSON" -eq 0 ]; then
  say "[status] repo=$REPO_ROOT"
  say "[status] guard_dest=$DEST_GUARD present=$GUARD_PRESENT"
  say "[status] launchers_dest=$DEST_LAUNCHERS present=$LAUNCHERS_PRESENT"
  say "[status] (read-only; no auth files opened)"
fi

# Guard components
if [ "$GUARD_PRESENT" -eq 1 ]; then
  check_pair "guard-core.mjs" \
    "$REPO_ROOT/src/guard-core.mjs" \
    "$DEST_GUARD/src/guard-core.mjs"
  check_pair "index.mjs" \
    "$REPO_ROOT/src/index.mjs" \
    "$DEST_GUARD/src/index.mjs"
  check_pair "vendor/validate-bash-command.sh" \
    "$REPO_ROOT/vendor/validate-bash-command.sh" \
    "$DEST_GUARD/vendor/validate-bash-command.sh"
  # Stamped hashes must match installed files (detect partial/corrupt stamps).
  if [ -f "$GUARD_STAMP" ]; then
    stamped="$(ops_stamp_get "$GUARD_STAMP" hash_guard_core_mjs)"
    actual="$(ops_hash_file "$DEST_GUARD/src/guard-core.mjs")"
    if [ -n "$stamped" ] && [ "$stamped" != "$actual" ]; then
      report "drift" "guard-stamp-hash_guard_core_mjs" "stamp=$stamped file=$actual"
      DRIFT=1
    fi
    stamped="$(ops_stamp_get "$GUARD_STAMP" hash_vendor_sh)"
    actual="$(ops_hash_file "$DEST_GUARD/vendor/validate-bash-command.sh")"
    if [ -n "$stamped" ] && [ "$stamped" != "$actual" ]; then
      report "drift" "guard-stamp-hash_vendor_sh" "stamp=$stamped file=$actual"
      DRIFT=1
    fi
  else
    report "missing" "$GUARD_STAMP" "no guard provenance stamp"
    DRIFT=1
  fi
else
  report "missing" "$DEST_GUARD" "guard not installed"
  MISSING=1
  DRIFT=1
fi

# Launchers / sandbox
if [ "$LAUNCHERS_PRESENT" -eq 1 ]; then
  check_pair "pi-sandbox.sb" \
    "$REPO_ROOT/sandbox/pi-sandbox.sb" \
    "$DEST_LAUNCHERS/pi-sandbox.sb"
  check_pair "pi-sandbox-preamble.zsh" \
    "$REPO_ROOT/sandbox/pi-sandbox-preamble.zsh" \
    "$DEST_LAUNCHERS/pi-sandbox-preamble.zsh"
  # The protected shim is first-party: compare installed copy against repo source.
  check_pair "launcher:pi" \
    "$REPO_ROOT/launchers/pi" \
    "$DEST_LAUNCHERS/pi"
  # Extra launchers came from --extra-launchers outside this repo, so there is no
  # repo source to diff. Verify each against the hash recorded at deploy time —
  # that still detects post-install tampering and a stale wrapper left on PATH
  # after it stopped being deployed.
  recorded_names="$(ops_stamp_get "$LAUNCHERS_STAMP" launcher_names)"
  if [ -z "$recorded_names" ]; then
    # Fail closed: an absent/partial stamp must not silently skip extra-launcher
    # verification, or an interrupted write would report a clean install while
    # unverified wrappers sit on PATH.
    report "drift" "launcher_names" "no launcher set recorded in $LAUNCHERS_STAMP; cannot verify extras"
    DRIFT=1
  else
    OLD_IFS="$IFS"; IFS=','
    for l in $recorded_names; do
      IFS="$OLD_IFS"
      if [ "$l" != "pi" ]; then
        dst="$DEST_LAUNCHERS/$l"
        stamped="$(ops_stamp_get "$LAUNCHERS_STAMP" "hash_launcher_${l}")"
        if [ ! -f "$dst" ]; then
          report "missing" "launcher:$l" "recorded in stamp but absent from $DEST_LAUNCHERS"
          MISSING=1; DRIFT=1
        elif [ -z "$stamped" ]; then
          # A recorded name with no recorded hash cannot be verified either way.
          report "drift" "launcher:$l" "installed but no hash recorded in stamp"
          DRIFT=1
        elif [ "$stamped" != "$(ops_hash_file "$dst")" ]; then
          report "drift" "launcher:$l" "stamp=$stamped file=$(ops_hash_file "$dst")"
          DRIFT=1
        else
          report "ok" "launcher:$l" "$stamped (extra; hash from deploy stamp)"
        fi
      fi
      IFS=','
    done
    IFS="$OLD_IFS"

    # Wrappers this dest has deployed BEFORE but the current set no longer claims.
    # Redeploying without a previously-deployed wrapper leaves it callable on
    # PATH; without this it would simply stop being checked, so a wrapper retired
    # for bypassing Seatbelt would go quietly unnoticed.
    #
    # Scoped to names recorded in launcher_names_seen, NOT every executable in
    # DEST_LAUNCHERS. That dir is normally ~/.local/bin — a SHARED PATH directory.
    # Scanning all of it reported every unrelated executable that happens to
    # share the directory as a "stale?" launcher and printed DRIFT on a clean
    # install, which trains the reader to ignore the drift signal entirely.
    #
    # Deliberately NOT detected here: a wrapper hand-planted in this dir that was
    # never deployed by this repo. Nothing in a stamp can attest to a file the
    # deploy never wrote, and a content heuristic cannot help either — the lint
    # (check-launchers.mjs) makes PI_SHIM="${0:A:h}/pi" mandatory, so grepping for
    # that marker matches only well-formed wrappers and MISSES precisely the
    # shim-bypassing file worth catching. Detecting those needs an allowlist of
    # expected PATH contents, which is a different feature; see docs/SANDBOX.md on
    # PATH ordering as the boundary.
    seen_names="$(ops_stamp_get "$LAUNCHERS_STAMP" launcher_names_seen)"
    if [ -n "$seen_names" ]; then
      OLD_IFS="$IFS"; IFS=','
      for prior in $seen_names; do
        IFS="$OLD_IFS"
        [ -n "$prior" ] || { IFS=','; continue; }
        # Still in the current set: already verified by hash above.
        case ",$recorded_names," in
          *",$prior,"*) IFS=','; continue ;;
        esac
        if [ -f "$DEST_LAUNCHERS/$prior" ] && [ -x "$DEST_LAUNCHERS/$prior" ]; then
          report "drift" "launcher:$prior" "previously deployed here but not in the current deploy set; still executable on PATH (stale?)"
          DRIFT=1
        fi
        IFS=','
      done
      IFS="$OLD_IFS"
    fi
  fi
  if [ -f "$LAUNCHERS_STAMP" ]; then
    stamped="$(ops_stamp_get "$LAUNCHERS_STAMP" hash_profile)"
    actual="$(ops_hash_file "$DEST_LAUNCHERS/pi-sandbox.sb")"
    if [ -n "$stamped" ] && [ "$stamped" != "$actual" ]; then
      report "drift" "launchers-stamp-hash_profile" "stamp=$stamped file=$actual"
      DRIFT=1
    fi
  else
    report "missing" "$LAUNCHERS_STAMP" "no launchers provenance stamp"
    DRIFT=1
  fi
else
  report "missing" "$DEST_LAUNCHERS" "launchers not installed"
  MISSING=1
  DRIFT=1
fi

# Shared release identity
RID_G="$(ops_stamp_get "$GUARD_STAMP" release_id)"
RID_L="$(ops_stamp_get "$LAUNCHERS_STAMP" release_id)"
RELEASE_MATCH="n/a"
if [ -n "$RID_G" ] && [ -n "$RID_L" ]; then
  if [ "$RID_G" = "$RID_L" ]; then
    RELEASE_MATCH="match"
    report "ok" "release_id" "$RID_G"
  else
    RELEASE_MATCH="mismatch"
    report "drift" "release_id" "guard=$RID_G launchers=$RID_L"
    DRIFT=1
  fi
elif [ -n "$RID_G" ] || [ -n "$RID_L" ]; then
  RELEASE_MATCH="partial"
  report "drift" "release_id" "guard=${RID_G:-none} launchers=${RID_L:-none}"
  DRIFT=1
else
  RELEASE_MATCH="absent"
  report "missing" "release_id" "no shared release identity recorded"
  # Only count as drift if something is installed.
  if [ "$GUARD_PRESENT" -eq 1 ] || [ "$LAUNCHERS_PRESENT" -eq 1 ]; then
    DRIFT=1
  fi
fi

if [ "$ALLOW_MISSING" -eq 1 ] && [ "$MISSING" -eq 1 ] && [ "$GUARD_PRESENT" -eq 0 ] && [ "$LAUNCHERS_PRESENT" -eq 0 ]; then
  # Nothing installed and that is OK for a clean machine check.
  DRIFT=0
fi

# Pi executable binding. Reported but NOT counted as drift: this file records a
# host-local fact (where Pi is installed), so it is legitimately different on every
# machine and cannot be compared against the checkout. It is surfaced because an
# unbound or stale binding is the difference between a working shim and a shim that
# refuses to launch, and that should be visible here rather than only at first use.
BIND_CONF="${PI_SANDBOX_CONFIG_DIR:-$HOME/.config/pi-sandbox-guard}/executables.conf"
BIND_STATE="unbound"
BIND_PI=""
if [ -f "$BIND_CONF" ]; then
  BIND_PI="$(sed -n 's/^[[:space:]]*pi[[:space:]]*=[[:space:]]*//p' "$BIND_CONF" | head -1)"
  # Delegate to bind-executable.sh --check rather than testing -x here: a bare -x test
  # calls a recorded directory or write-root executable "ok" while the launcher refuses
  # it, and status would then disagree with the thing it is reporting on. One rule set,
  # one owner.
  if [ -z "$BIND_PI" ]; then
    BIND_STATE="unbound"
  elif PI_SANDBOX_CONFIG_DIR="$(dirname "$BIND_CONF")" \
       bash "$(dirname "$0")/bind-executable.sh" --check >/dev/null 2>&1; then
    BIND_STATE="ok"
  else
    BIND_STATE="stale"
  fi
fi
if [ "$JSON" -eq 0 ]; then
  case "$BIND_STATE" in
    ok)      say "[status] pi binding: $BIND_PI" ;;
    stale)   say "[status] pi binding STALE (recorded path is not executable): $BIND_PI"
             say "[status]   re-record: npm run bind" ;;
    unbound) say "[status] pi binding: none recorded (auto-detection covers only npm installs"
             say "[status]   into /opt/homebrew or /usr/local; otherwise run: npm run bind)" ;;
  esac
fi

if [ "$JSON" -eq 1 ]; then
  # Structured quoting keeps forged or unusual stamp values from corrupting
  # the JSON document. No deployed stamp is ever evaluated as shell code.
  printf '{"guard_present":%s,"launchers_present":%s,"release_match":%s,"guard_release_id":%s,"launchers_release_id":%s,"pi_binding":%s,"pi_binding_path":%s,"drift":%s}\n' \
    "$GUARD_PRESENT" "$LAUNCHERS_PRESENT" "$(ops_json_quote "$RELEASE_MATCH")" \
    "$(ops_json_quote "${RID_G:-}")" "$(ops_json_quote "${RID_L:-}")" \
    "$(ops_json_quote "$BIND_STATE")" "$(ops_json_quote "$BIND_PI")" "$DRIFT"
fi

if [ "$DRIFT" -ne 0 ]; then
  if [ "$JSON" -eq 0 ]; then
    say "[status] DRIFT or incomplete install detected"
  fi
  exit 1
fi

if [ "$JSON" -eq 0 ]; then
  say "[status] OK: source and runtime hashes agree; release identity consistent"
fi
exit 0
