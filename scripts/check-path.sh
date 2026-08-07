#!/usr/bin/env bash
# check-path.sh — confirm protected `pi` and `omp` shims win PATH resolution.
#
# The shim is only a boundary if it WINS PATH resolution. deploy-launchers can
# install a perfect shim and the host can still launch the real Pi directly,
# which is unsandboxed and looks identical until you notice the missing
# "OS sandbox ON" line. Nothing else in the deploy chain checks this: status.sh
# compares installed file hashes, not resolution order.
#
# Exit 0 = plain `pi` and `omp` resolve to the installed shared shim copies.
# Exit 1 = it does not (not installed, not on PATH, or shadowed by the real Pi).
set -uo pipefail

DEST="${PI_SANDBOX_INSTALL_DIR:-$HOME/.local/bin}"

# Compare canonical paths: a symlinked or ../-containing PATH entry can name the
# same file by a different string. Resolve the LEAF too, not just its directory —
# an earlier PATH entry may be a symlink pointing at the shim, which is protected
# and must not be reported as a failure.
canon() {
  # Declare BEFORE assigning: `local t; t="$(readlink ...)"` on bash 3.2 emits the
  # assignment to stdout inside a while loop, which would corrupt the comparison.
  local p n t
  p="$1"
  n=0
  while [ -L "$p" ] && [ "$n" -lt 32 ]; do
    t="$(readlink "$p")"
    case "$t" in
      /*) p="$t" ;;
      *) p="$(dirname "$p")/$t" ;;
    esac
    n=$((n + 1))
  done
  cd "$(dirname "$p")" 2>/dev/null && printf '%s/%s\n' "$(pwd -P)" "$(basename "$p")"
}
check_runtime() {
  local runtime="$1" shim="$DEST/$1" resolved=""
  if [ ! -x "$shim" ]; then
    echo "[check-path] FAIL: no protected shim at $shim"
    return 1
  fi

  # Use a login shell's PATH; npm prepends a transient node_modules/.bin.
  resolved="$(/bin/zsh -lc "command -v $runtime" 2>/dev/null || true)"
  [ -n "$resolved" ] || resolved="$(command -v "$runtime" 2>/dev/null || true)"
  if [ -z "$resolved" ]; then
    echo "[check-path] FAIL: '$runtime' is not on PATH."
    return 1
  fi
  if [ "$(canon "$resolved")" = "$(canon "$shim")" ]; then
    echo "[check-path] OK: '$runtime' resolves to the protected shim ($resolved)"
    return 0
  fi
  echo "[check-path] FAIL: '$runtime' resolves to $resolved, not $shim"
  return 1
}

status=0
check_runtime pi || status=1
check_runtime omp || status=1
if [ "$status" -ne 0 ]; then
  echo "[check-path] Put $DEST before the real agent binaries in PATH:"
  echo "[check-path]   export PATH=\"$DEST:\$PATH\""
fi
exit "$status"
