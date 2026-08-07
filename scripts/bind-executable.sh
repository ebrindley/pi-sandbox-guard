#!/usr/bin/env bash
#
# bind-executable.sh — record the Pi and OMP installs the shared shim should launch.
#
# WHY THIS EXISTS
# The shim resolves the real Pi from a fixed list of trusted path prefixes. That list
# cannot describe the real world: Homebrew's formula installs into Cellar/libexec, npm's
# documented sudo-free pattern uses a user prefix, and nvm/fnm/volta/asdf/mise/pnpm/bun/
# yarn/Nix each have their own layout. Enumerating them is a losing game, and the prefix
# list was never a privilege boundary anyway — on a standard Apple-Silicon host every
# allowlisted /opt/homebrew path is owned by the unprivileged install user.
#
# So instead of guessing, the operator records the answer ONCE, deliberately, from an
# unsandboxed shell. That recorded value is exempt from the path-shape rules; what
# replaces them is that it came from host state rather than from the environment, plus
# the shim's own checks (absolute, executable, not the shim, not inside a Seatbelt
# write root).
#
# WHAT THIS DOES NOT CLAIM
# This is a NON-AMBIENT HOST PIN, not an integrity control. A same-uid attacker outside
# the sandbox who can write this config can equally rewrite the shim or the Pi install
# itself. What it does defend: project-controlled environment (a repo .envrc/Makefile/
# npm script cannot retarget the launch), and a confined Pi session cannot repoint its
# own next launch, because the config is not sandbox-writable.
#
# Pi is required by setup; OMP is optional.
#
# Usage:
#   bind-executable.sh --detect            propose an install, confirm, then record
#   bind-executable.sh --pi <abs-path> [--omp <abs-path>] [--node <abs-path>]
#   bind-executable.sh --show              print the current binding
#   bind-executable.sh --check             verify the binding still resolves (exit 3 if not)
#   bind-executable.sh --detect --yes      non-interactive (CI/scripted setup)
#
# Exit codes: 0 ok; 2 usage/validation failure; 3 binding missing or stale (--check).

set -euo pipefail

CONFIG_DIR="${PI_SANDBOX_CONFIG_DIR:-$HOME/.config/pi-sandbox-guard}"
CONFIG="$CONFIG_DIR/executables.conf"
SHIM="${PI_SANDBOX_SHIM:-$HOME/.local/bin/pi}"
OMP_SHIM="${OMP_SANDBOX_SHIM:-$HOME/.local/bin/omp}"

MODE=""
PI_PATH=""
OMP_PATH=""
NODE_PATH=""
ASSUME_YES=0

die() { printf 'bind: %s\n' "$*" >&2; exit 2; }

usage() { sed -n '2,/^set -euo pipefail$/s/^# \{0,1\}//p' "$0"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --detect|--show|--check)
      [ -z "$MODE" ] || die "only one of --detect/--show/--check"
      MODE="${1#--}"; shift ;;
    --pi)   [ $# -ge 2 ] || die "--pi needs an absolute path";   PI_PATH="$2";   MODE="${MODE:-explicit}"; shift 2 ;;
    --omp)  [ $# -ge 2 ] || die "--omp needs an absolute path";  OMP_PATH="$2";  MODE="${MODE:-explicit}"; shift 2 ;;
    --node) [ $# -ge 2 ] || die "--node needs an absolute path"; NODE_PATH="$2"; MODE="${MODE:-explicit}"; shift 2 ;;
    --yes|-y) ASSUME_YES=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done
# Bare invocation means --detect. `npm run bind` must stay a one-word command, and it
# cannot bake --detect into the npm script: `npm run bind -- --check` would then expand
# to `--detect --check` and die on the one-mode rule, so the documented --show/--check
# verbs would be unreachable through npm.
[ -n "$MODE" ] || MODE="detect"

# canonicalize <path> — absolute, symlinks resolved. Empty on failure.
#
# Uses node, not python3, for the same reason deploy-local.sh does: /usr/bin/python3
# is a Command Line Tools shim that can be absent on a clean macOS host, and failing
# here is not a no-op — every path in this script routes through canonicalize(), so an
# absent python3 made `npm run bind` die with "cannot be canonicalized" and no hint.
# node is already required to reach this script at all (it runs via `npm run bind`).
# Must match os.path.realpath on MISSING paths too, and that is not the same as
# "realpathSync, else path.resolve". realpathSync throws if any component is absent,
# and a lexical fallback then discards symlinks already resolved in the surviving
# prefix — so `~/bin/link-to-tmp/missing/../pi` would canonicalize to a path that
# hides the symlink into /private/tmp, and the Seatbelt-write-root check below would
# not see it. That check is the reason this function exists, so it must not be
# defeatable by a nonexistent trailing component.
#
# Resolve component by component instead: walk the path, expanding each symlink as
# encountered, and fall back to lexical joining only for the components that truly do
# not exist. This is what os.path.realpath does.
#
# Verified against os.path.realpath on 30 probe paths — exact match on all of them,
# including symlinked ancestors with missing leaves, ".." escaping past a symlink,
# dangling links, spaces, and the Homebrew/nvm/volta/Nix chain shapes. One deliberate
# difference: a symlink CYCLE yields empty (so the caller refuses) rather than
# realpath's non-throwing partial result — an uncanonicalizable path must not be
# recordable, since the write-root check below cannot vet a path it cannot resolve.
canonicalize() {
  [ -n "${1:-}" ] || return 0
  node -e '
    const fs = require("fs"), path = require("path");
    // Pending components, consumed left to right. A symlink pushes its own
    // components back onto the front, so an absolute target restarts the walk from
    // "/" — without that restart, a link pointing at /tmp/... would keep the
    // unresolved /tmp prefix and hide the very symlink this check exists to catch.
    //
    // INVARIANT: nothing may collapse ".." before the walk sees it. Both
    // path.resolve() and path.join() normalize lexically, so neither may touch the
    // input — with `opt/node -> ../Cellar/node/24.4.1`, a lexical pass rewrites the
    // valid `opt/node/../24.4.1/bin/node` to a nonexistent `opt/24.4.1/...` and
    // refuses a real binding. Prepend the cwd by STRING concatenation only; every
    // ".." then reaches the ".." branch below, which applies it to the resolved,
    // symlink-free prefix in kernel order.
    const input = process.argv[1];
    const absolute = input.startsWith("/") ? input : process.cwd() + "/" + input;
    const queue = absolute.split("/").filter(Boolean);
    let resolved = "/";
    // Bounded like the kernel: a symlink cycle must terminate, not spin. Exiting
    // non-zero here yields an empty result, which the caller treats as
    // un-canonicalizable and refuses — the safe direction for a cyclic path.
    let hops = 0;
    const MAX_HOPS = 64;
    while (queue.length) {
      const part = queue.shift();
      if (part === ".") continue;
      // ".." applies to the already-resolved (symlink-free) prefix, as the kernel does.
      if (part === "..") { resolved = path.dirname(resolved); continue; }
      const next = path.join(resolved, part);
      let link;
      try { link = fs.readlinkSync(next); } catch { resolved = next; continue; }
      if (++hops > MAX_HOPS) process.exit(1);
      if (path.isAbsolute(link)) resolved = "/";
      queue.unshift(...link.split("/").filter(Boolean));
    }
    process.stdout.write(resolved);
  ' "$1" 2>/dev/null || true
}

# Reject anything the shim itself would reject, with a specific reason. Keeping the
# rules here in sync with the preamble is the point: bind must never record a value
# that the launcher will then refuse, because that trades a clear error at bind time
# for a confusing one at launch time.
validate_target() {
  local raw="$1" label="$2" canon=""
  case "$raw" in
    /*) ;;
    *) die "$label must be an absolute path: $raw" ;;
  esac
  canon="$(canonicalize "$raw")"
  [ -n "$canon" ] || die "$label cannot be canonicalized: $raw"
  [ -e "$canon" ] || die "$label does not exist: $canon"
  [ -d "$canon" ] && die "$label is a directory: $canon"
  [ -x "$canon" ] || die "$label is not executable: $canon"

  local shim_canon omp_shim_canon
  shim_canon="$(canonicalize "$SHIM")"
  omp_shim_canon="$(canonicalize "$OMP_SHIM")"
  if { [ -n "$shim_canon" ] && [ "$canon" = "$shim_canon" ]; } \
    || { [ -n "$omp_shim_canon" ] && [ "$canon" = "$omp_shim_canon" ]; }; then
    die "$label resolves to the protected shim itself ($canon); that would loop"
  fi
  if grep -q 'pi-sandbox-guard' "$canon" 2>/dev/null; then
    die "$label looks like a pi-sandbox-guard script ($canon); that would loop"
  fi

  # Seatbelt write roots: an executable the sandboxed agent can rewrite turns one
  # confined session into persistence across every later launch.
  # Must match executable_under_sandbox_write_root() in the preamble, including the
  # Darwin per-user temp shape (/var/folders/<xx>/<...>/T/...), which is what becomes
  # -D TMPDIR=... and is therefore agent-writable.
  local home_canon; home_canon="$(canonicalize "$HOME")"
  case "$canon" in
    /private/tmp/*|/tmp/*|/var/tmp/*|/private/var/tmp/* \
    |/var/folders/*/T/*|/private/var/folders/*/T/* \
    |"$home_canon"/.pi/*|"$home_canon"/.omp/* \
    |"$home_canon"/.omp-*/*|"$home_canon"/.omp.*/*|"$home_canon"/.omp_*/* \
    |"$home_canon"/.npm/*|"$home_canon"/.cache/* \
    |"$home_canon"/Library/Caches/*)
      die "$label is inside a sandbox-writable root ($canon); the agent could rewrite it" ;;
  esac
  printf '%s\n' "$canon"
}

# Ordered discovery. Each candidate is a real install layout observed in the wild; the
# list is for PROPOSING a value, never for trusting one — the operator confirms.
# Ambient PATH is consulted last and only to notice an install the layouts missed.
detect_pi() {
  local c
  local -a candidates=()
  # npm-style layouts: <prefix>/lib/node_modules/<pkg>/dist/cli.js
  local -a prefixes=(
    "/opt/homebrew" "/usr/local" "$HOME/.npm-global" "$HOME/.local"
    "$HOME/.nvm/versions/node"/* "$HOME/.asdf/installs/nodejs"/*
    "$HOME/.local/share/mise/installs/node"/*
    "$HOME/Library/Application Support/fnm/node-versions"/*/installation
  )
  for c in "${prefixes[@]}"; do
    [ -d "$c" ] || continue
    [ -e "$c/lib/node_modules/@earendil-works/pi-coding-agent/dist/cli.js" ] \
      && candidates+=("$c/lib/node_modules/@earendil-works/pi-coding-agent/dist/cli.js")
  done
  # Homebrew formula: bin/pi is a wrapper script into libexec.
  for c in /opt/homebrew/Cellar/pi-coding-agent/*/bin/pi /usr/local/Cellar/pi-coding-agent/*/bin/pi; do
    [ -x "$c" ] && candidates+=("$c")
  done
  # volta / pnpm / bun / yarn globals.
  for c in \
    "$HOME/.volta/tools/image/packages/@earendil-works/pi-coding-agent/dist/cli.js" \
    "$HOME/Library/pnpm/global"/*/node_modules/@earendil-works/pi-coding-agent/dist/cli.js \
    "$HOME/.bun/install/global/node_modules/@earendil-works/pi-coding-agent/dist/cli.js" \
    "$HOME/.yarn/global/node_modules/@earendil-works/pi-coding-agent/dist/cli.js"; do
    [ -e "$c" ] && candidates+=("$c")
  done
  # npm's own answer, if npm is available and its prefix was not already covered.
  if command -v npm >/dev/null 2>&1; then
    local np; np="$(npm prefix -g 2>/dev/null || true)"
    if [ -n "$np" ] && [ -e "$np/lib/node_modules/@earendil-works/pi-coding-agent/dist/cli.js" ]; then
      candidates+=("$np/lib/node_modules/@earendil-works/pi-coding-agent/dist/cli.js")
    fi
  fi
  # Ambient PATH last, and never the shim dir.
  local ambient; ambient="$(command -v pi 2>/dev/null || true)"
  if [ -n "$ambient" ]; then
    local ac; ac="$(canonicalize "$ambient")"
    if [ -n "$ac" ] && ! grep -q 'pi-sandbox-guard' "$ac" 2>/dev/null; then
      candidates+=("$ac")
    fi
  fi
  local seen="" out=""
  for c in "${candidates[@]}"; do
    out="$(canonicalize "$c")"
    [ -n "$out" ] || continue
    case "$seen" in *"|$out|"*) continue ;; esac
    seen="$seen|$out|"
    printf '%s\n' "$out"
  done
}

detect_omp() {
  local c out="" seen=""
  local -a candidates=(
    "$HOME/.local/lib/omp/omp"
    /opt/homebrew/bin/omp
    /usr/local/bin/omp
    /opt/homebrew/Cellar/omp/*/bin/omp
    /usr/local/Cellar/omp/*/bin/omp
    "$HOME/.bun/bin/omp"
  )
  local ambient; ambient="$(command -v omp 2>/dev/null || true)"
  [ -n "$ambient" ] && candidates+=("$ambient")
  for c in "${candidates[@]}"; do
    [ -x "$c" ] || continue
    out="$(canonicalize "$c")"
    [ -n "$out" ] || continue
    grep -q 'pi-sandbox-guard' "$out" 2>/dev/null && continue
    case "$seen" in *"|$out|"*) continue ;; esac
    seen="$seen|$out|"
    printf '%s\n' "$out"
  done
}

# Only needed when the entry point is a `node` shebang script.
needs_interpreter() {
  head -c 128 "$1" 2>/dev/null | head -1 | grep -Eq '^#!.*[ /]node( |$)'
}

detect_node() {
  local c
  for c in "$(command -v node 2>/dev/null || true)" \
    /opt/homebrew/bin/node /usr/local/bin/node /usr/bin/node \
    /opt/homebrew/opt/node/bin/node /opt/homebrew/opt/node@*/bin/node; do
    [ -n "$c" ] && [ -x "$c" ] && { canonicalize "$c"; return 0; }
  done
  return 1
}

read_key() {
  [ -f "$CONFIG" ] || return 1
  awk -F= -v k="$1" '
    /^[[:space:]]*($|#)/ { next }
    { n=$1; gsub(/^[[:space:]]+|[[:space:]]+$/,"",n)
      if (n==k) { sub(/^[^=]*=/,"",$0); gsub(/^[[:space:]]+|[[:space:]]+$/,"",$0)
                  gsub(/^["\047]|["\047]$/,"",$0); print; found=1; exit } }
    END { if (!found) exit 1 }' "$CONFIG" 2>/dev/null
}

case "$MODE" in
  show)
    [ -f "$CONFIG" ] || { echo "no binding recorded ($CONFIG)"; exit 3; }
    printf 'config: %s\n' "$CONFIG"
    printf 'pi   = %s\n' "$(read_key pi || echo '(unset)')"
    printf 'omp  = %s\n' "$(read_key omp || echo '(unset)')"
    printf 'node = %s\n' "$(read_key node || echo '(unset — shebang resolves via sanitized PATH)')"
    exit 0 ;;
  check)
    pi_rec="$(read_key pi || true)"
    if [ -z "$pi_rec" ]; then
      echo "no pi= binding recorded in $CONFIG"
      echo "  auto-resolution only covers fixed trusted prefixes; run: bind-executable.sh --detect"
      exit 3
    fi
    ok=1
    # Apply the FULL rule set, not just -x. A bare -x test calls a hand-recorded
    # directory, relative path, guard script, or write-root executable "ok" while the
    # launcher refuses it — a false green that sends the operator looking somewhere else.
    # validate_target dies on failure, so run it in a subshell and capture the reason.
    if ! pi_reason="$(validate_target "$pi_rec" "pi" 2>&1 >/dev/null)"; then
      echo "invalid: ${pi_reason#bind: }"; ok=0
    fi
    omp_rec="$(read_key omp || true)"
    if [ -n "$omp_rec" ] && ! omp_reason="$(validate_target "$omp_rec" "omp" 2>&1 >/dev/null)"; then
      echo "invalid: ${omp_reason#bind: }"; ok=0
    fi
    node_rec="$(read_key node || true)"
    if [ -n "$node_rec" ]; then
      if ! node_reason="$(validate_target "$node_rec" "node" 2>&1 >/dev/null)"; then
        echo "invalid: ${node_reason#bind: }"; ok=0
      fi
    fi
    if [ "$ok" -eq 1 ]; then
      echo "binding ok: $pi_rec"
      [ -n "$omp_rec" ] && echo "omp: $omp_rec"
      [ -n "$node_rec" ] && echo "interpreter: $node_rec"
      exit 0
    fi
    echo "  re-record: bind-executable.sh --detect"
    exit 3 ;;
esac

# --- detect / explicit -------------------------------------------------------
if [ "$MODE" = "detect" ] && [ -z "$PI_PATH" ]; then
  # Not mapfile: macOS ships bash 3.2, where it does not exist. Read line-by-line so
  # this runs on a stock host without requiring a newer bash.
  found=()
  while IFS= read -r line; do
    [ -n "$line" ] && found+=("$line")
  done < <(detect_pi)
  # The shim is excluded as a candidate (it would point at itself), so once it is
  # installed and first on PATH, an install layout this script does not enumerate
  # -- Nix, an unusual prefix -- leaves nothing to propose even though Pi is
  # present. Name that case: the fix is one flag, not a reinstall.
  [ "${#found[@]}" -gt 0 ] || die "no Pi install found in the layouts this script knows.
  If Pi IS installed (Nix or another custom prefix), record it explicitly:
    npm run bind -- --pi \"\$(command -v pi)\"   # from a shell where that is the REAL pi
  or pass the absolute path directly: npm run bind -- --pi /abs/path/to/pi"
  if [ "${#found[@]}" -gt 1 ] && [ "$ASSUME_YES" -eq 0 ]; then
    echo "Multiple Pi installs found:"
    i=1; for f in "${found[@]}"; do printf '  %d) %s\n' "$i" "$f"; i=$((i+1)); done
    printf 'Select [1-%d]: ' "${#found[@]}"
    read -r sel </dev/tty || die "no tty for selection; pass --pi <abs-path>"
    case "$sel" in
      ''|*[!0-9]*) die "invalid selection: $sel" ;;
    esac
    [ "$sel" -ge 1 ] && [ "$sel" -le "${#found[@]}" ] || die "selection out of range: $sel"
    PI_PATH="${found[$((sel-1))]}"
  else
    PI_PATH="${found[0]}"
  fi
fi

# Detect OMP when available. An OMP-free host remains a supported Pi-only
# installation; an existing omp= key is preserved by explicit Pi-only updates.
if [ "$MODE" = "detect" ] && [ -z "$OMP_PATH" ]; then
  omp_found=()
  while IFS= read -r line; do
    [ -n "$line" ] && omp_found+=("$line")
  done < <(detect_omp)
  if [ "${#omp_found[@]}" -gt 0 ]; then
    OMP_PATH="${omp_found[0]}"
  else
    OMP_PATH="$(read_key omp || true)"
  fi
elif [ -z "$OMP_PATH" ]; then
  OMP_PATH="$(read_key omp || true)"
fi

if [ -z "$PI_PATH" ]; then
  PI_PATH="$(read_key pi || true)"
fi
[ -n "$PI_PATH" ] || die "no Pi path supplied or previously recorded"

PI_CANON="$(validate_target "$PI_PATH" "pi")"
OMP_CANON=""
[ -n "$OMP_PATH" ] && OMP_CANON="$(validate_target "$OMP_PATH" "omp")"

if [ -z "$NODE_PATH" ] && needs_interpreter "$PI_CANON"; then
  NODE_PATH="$(read_key node || true)"
  if [ -z "$NODE_PATH" ]; then
    NODE_PATH="$(detect_node || true)"
  fi
  [ -n "$NODE_PATH" ] \
    || die "$PI_CANON needs a Node interpreter and none was found; pass --node <abs-path>"
fi
NODE_CANON=""
[ -n "$NODE_PATH" ] && NODE_CANON="$(validate_target "$NODE_PATH" "node")"

echo "About to record:"
printf '  pi   = %s\n' "$PI_CANON"
if [ -n "$OMP_CANON" ]; then
  printf '  omp  = %s\n' "$OMP_CANON"
fi
if [ -n "$NODE_CANON" ]; then
  printf '  node = %s\n' "$NODE_CANON"
  printf '  launch = %s %s\n' "$NODE_CANON" "$PI_CANON"
else
  printf '  launch = %s\n' "$PI_CANON"
fi
printf '  config = %s\n' "$CONFIG"
echo "This grants the recorded program the agent's project-write and network access."
if [ "$ASSUME_YES" -eq 0 ]; then
  printf 'Record it? [y/N] '
  read -r ans </dev/tty || die "no tty to confirm; re-run with --yes to accept non-interactively"
  case "$ans" in [yY]|[yY][eE][sS]) ;; *) echo "aborted; nothing written"; exit 0 ;; esac
fi

mkdir -p "$CONFIG_DIR"
# Preserve any keys we do not own, so a hand-written comment or an unrelated wrapper
# key survives a re-bind. Written via mktemp + mv so a concurrent reader never sees a
# half-written config.
tmp="$(mktemp "$CONFIG.XXXXXX")"
if [ -f "$CONFIG" ]; then
  awk -F= '
    /^[[:space:]]*($|#)/ { print; next }
    { n=$1; gsub(/^[[:space:]]+|[[:space:]]+$/,"",n)
      if (n=="pi" || n=="omp" || n=="node") next
      print }' "$CONFIG" >>"$tmp"
else
  {
    echo "# pi-sandbox-guard executable binding — written by bind-executable.sh."
    echo "# Recorded absolute paths are exempt from the shim's trusted-prefix list;"
    echo "# the shim still refuses a non-executable, the shim itself, or anything"
    echo "# inside a Seatbelt write root. Re-run bind-executable.sh after an upgrade"
    echo "# that moves these paths (nvm/volta/mise version bumps, brew upgrades)."
  } >>"$tmp"
fi
printf 'pi=%s\n' "$PI_CANON" >>"$tmp"
[ -n "$OMP_CANON" ] && printf 'omp=%s\n' "$OMP_CANON" >>"$tmp"
[ -n "$NODE_CANON" ] && printf 'node=%s\n' "$NODE_CANON" >>"$tmp"
chmod 600 "$tmp"
mv -f "$tmp" "$CONFIG"
echo "recorded in $CONFIG"
