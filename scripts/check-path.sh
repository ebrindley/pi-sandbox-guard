#!/usr/bin/env bash
# check-path.sh — confirm the protected `pi` shim is what a plain `pi` resolves to.
#
# The shim is only a boundary if it WINS PATH resolution. deploy-launchers can
# install a perfect shim and the host can still launch the real Pi directly,
# which is unsandboxed and looks identical until you notice the missing
# "OS sandbox ON" line. Nothing else in the deploy chain checks this: status.sh
# compares installed file hashes, not resolution order.
#
# Exit 0 = a plain `pi` resolves to the installed shim.
# Exit 1 = it does not (not installed, not on PATH, or shadowed by the real Pi).
set -uo pipefail

DEST="${PI_SANDBOX_INSTALL_DIR:-$HOME/.local/bin}"
SHIM="$DEST/pi"

if [ ! -x "$SHIM" ]; then
  echo "[check-path] FAIL: no protected shim at $SHIM"
  echo "[check-path]   run: npm run deploy:launchers"
  exit 1
fi

# Resolve `pi` against a LOGIN shell's PATH, not this process's. Under `npm run`
# npm prepends node_modules/.bin, so resolving here would test a PATH the user
# never has. Fall back to the ambient PATH if the login shell cannot be probed.
RESOLVED="$(/bin/zsh -lc 'command -v pi' 2>/dev/null || true)"
[ -n "$RESOLVED" ] || RESOLVED="$(command -v pi 2>/dev/null || true)"

if [ -z "$RESOLVED" ]; then
  echo "[check-path] FAIL: 'pi' is not on PATH at all."
  echo "[check-path]   add $DEST to PATH, e.g. in ~/.zshrc:"
  echo "[check-path]     export PATH=\"$DEST:\$PATH\""
  exit 1
fi

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
if [ "$(canon "$RESOLVED")" = "$(canon "$SHIM")" ]; then
  echo "[check-path] OK: 'pi' resolves to the protected shim ($RESOLVED)"
  exit 0
fi

echo "[check-path] FAIL: 'pi' resolves to $RESOLVED, NOT the protected shim."
echo "[check-path]   The shim is installed at $SHIM but something earlier on PATH"
echo "[check-path]   wins. Launching 'pi' would run UNSANDBOXED."
echo "[check-path]   Fix: put $DEST before $(dirname "$RESOLVED") on PATH, e.g. in ~/.zshrc:"
echo "[check-path]     export PATH=\"$DEST:\$PATH\""
exit 1
