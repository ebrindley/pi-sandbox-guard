# shellcheck shell=zsh
# pi-sandbox-preamble.zsh — sourced by Pi launchers right before exec'ing pi.
#
# Computes a safe project boundary, refuses unsafe/nested contexts (fail-closed),
# and sets the PI_SANDBOX_CMD ARRAY to the sandbox-exec prefix (empty when bypassed).
# The launcher then does:  exec "${PI_SANDBOX_CMD[@]}" "$PI_EXECUTABLE" <args> "$@"
#
# Contract:
#  - FAIL CLOSED: if the protected shim cannot sandbox safely, REFUSE to launch.
#  - Project boundary = git toplevel, explicit PI_PROJECT, or non-git cwd.
#  - Explicit launchers refuse nested sandboxes. Transparent PATH shims pass
#    through only for own-shim re-entry (profile digest + behavioral probes).
#  - Trusted ABSOLUTE binary paths (no PATH lookup for security-critical tools).
#  - PI_SANDBOX_CMD is an ARRAY so project paths with spaces are passed as one argv item.

emit() { print -u2 -- "[pi-sandbox-guard] $*"; }

# Trusted absolute paths — do NOT resolve security-critical tools via $PATH.
# Pin before any ambient PATH work; keep readonly where zsh permits.
typeset -r SANDBOX_EXEC="/usr/bin/sandbox-exec"
typeset -r GIT_BIN="/usr/bin/git"
typeset -r SH_BIN="/bin/sh"
typeset -r RM_BIN="/bin/rm"
typeset -r GREP_BIN="/usr/bin/grep"
typeset -r AWK_BIN="/usr/bin/awk"
typeset -r TRUE_BIN="/usr/bin/true"
typeset -r ID_BIN="/usr/bin/id"
typeset -r DSCL_BIN="/usr/bin/dscl"
typeset -r SHASUM_BIN="/usr/bin/shasum"
typeset -r STAT_BIN="/usr/bin/stat"

# Git repository/config selectors are launch-boundary inputs: if inherited, they
# can make `git rev-parse` resolve PROJECT or ACTIVE_HOOKS against a different
# repository/config than the directory the operator launched from. Clear only
# discovery/config selectors; ordinary identity and transport settings remain
# available to the sandboxed Pi process.
unset GIT_DIR GIT_WORK_TREE GIT_COMMON_DIR
unset GIT_CEILING_DIRECTORIES GIT_DISCOVERY_ACROSS_FILESYSTEM
unset GIT_CONFIG GIT_CONFIG_SYSTEM GIT_CONFIG_GLOBAL GIT_CONFIG_NOSYSTEM
unset GIT_CONFIG_PARAMETERS GIT_CONFIG_COUNT
for _PI_GIT_ENV_NAME in ${(k)parameters}; do
  case "$_PI_GIT_ENV_NAME" in
    GIT_CONFIG_KEY_*|GIT_CONFIG_VALUE_*) unset "$_PI_GIT_ENV_NAME" ;;
  esac
done
unset _PI_GIT_ENV_NAME

# Sanitize PATH before any remaining external lookups. Keep Homebrew + system
# bins so trusted Pi resolution still works; drop ambient hostile entries.
PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

# Homebrew versioned Node formulae do not link `node` into /opt/homebrew/bin.
# Pi uses `#!/usr/bin/env node`, so add one trusted Node bin directory without
# consulting ambient PATH. Zsh's (N) qualifier drops unmatched glob patterns.
typeset -a NODE_CANDIDATES
NODE_CANDIDATES=(
  /opt/homebrew/bin/node
  /usr/local/bin/node
  /usr/bin/node
  /opt/homebrew/opt/node/bin/node
  /usr/local/opt/node/bin/node
  /opt/homebrew/opt/node@*/bin/node(N)
  /usr/local/opt/node@*/bin/node(N)
)
for NODE_CANDIDATE in "${NODE_CANDIDATES[@]}"; do
  if [ -x "$NODE_CANDIDATE" ] && [ ! -d "$NODE_CANDIDATE" ]; then
    NODE_BIN_DIR="${NODE_CANDIDATE:A:h}"
    PATH="$NODE_BIN_DIR:$PATH"
    break
  fi
done
unset NODE_CANDIDATE NODE_CANDIDATES
export PATH

# Derive login identity from the kernel credential (/usr/bin/id), never ambient USER.
LOGIN_USER="$("$ID_BIN" -un 2>/dev/null || true)"
typeset -r LOGIN_USER
if [ -n "$LOGIN_USER" ]; then
  USER="$LOGIN_USER"
  export USER
fi

# Bind HOME to the login user's real macOS home before deriving config/profile
# paths. A repo-local env or wrapper must not make Seatbelt params point at a
# fake home and thereby miss real credential/config paths.
REAL_HOME=""
if [ -n "$LOGIN_USER" ]; then
  REAL_HOME="$("$DSCL_BIN" . -read "/Users/$LOGIN_USER" NFSHomeDirectory 2>/dev/null | "$AWK_BIN" '{print $2; exit}' || true)"
fi
if [ -n "$REAL_HOME" ] && [ -d "$REAL_HOME" ]; then
  HOME="$REAL_HOME"
  export HOME
fi
typeset -r REAL_HOME

# HOME is now the kernel-derived real home (above). Canonicalize it HERE, before any
# executable resolution, because the write-root check needs it: HOME_CANON proper is
# not computed until the sandbox-argument stage, long after the launch target is
# chosen. Same value, computed earlier; the later assignment is left untouched so
# nothing downstream changes behavior.
typeset -r HOME_CANON_EARLY="$(cd -P "$HOME" 2>/dev/null && pwd -P || print -r -- "$HOME")"

# Git's XDG config location also affects core.hooksPath. Pin it only for the
# launch-boundary Git probes so an inherited XDG_CONFIG_HOME cannot redirect
# project or hook discovery, while the sandboxed application keeps its normal
# XDG environment.
typeset -r PI_GIT_XDG_CONFIG_HOME="$HOME/.config"

# Defaults only when unset (protected launcher may have pinned readonly values).
: "${PI_SANDBOX:=1}"
: "${PI_EXECUTABLE_KEY:=pi}"
: "${PI_SANDBOX_TRANSPARENT:=0}"
: "${PI_SANDBOX_INSTALL_DIR:=$HOME/.local/bin}"
: "${PI_SANDBOX_PROFILE:=$PI_SANDBOX_INSTALL_DIR/pi-sandbox.sb}"

# Protected transparent shim: never honor ambient PI_EXECUTABLE_CONFIG (repo-
# controlled config selection). Pin to trusted host state under real HOME.
if [ "$PI_SANDBOX_TRANSPARENT" = "1" ]; then
  PI_EXECUTABLE_CONFIG="$HOME/.config/pi-sandbox-guard/executables.conf"
else
  : "${PI_EXECUTABLE_CONFIG:=$HOME/.config/pi-sandbox-guard/executables.conf}"
fi

typeset -ga PI_SANDBOX_CMD
PI_SANDBOX_CMD=()

# Trusted absolute prefixes for AMBIENT Pi executable selection: the PI_EXECUTABLE
# env var, and auto-resolution from the sanitized PATH. Both are attacker-reachable
# without touching host state (a project .envrc/Makefile/npm script can export the
# env var), so they stay pinned to a fixed path shape.
#
# This list is a PATH-SHAPE CONVENTION, not a privilege boundary. On a standard
# Apple-Silicon host /opt/homebrew/bin, /opt/homebrew/lib/node_modules, and
# /opt/homebrew/Cellar are all owned by the unprivileged install user — the same uid
# the sandbox contains — so matching this list does not prove a path is unwritable.
# The load-bearing properties are (a) Seatbelt write containment, and (b) for
# non-ambient selection, an operator-recorded binding (see resolve_bound_executable).
# Do not extend this list to chase install layouts: bind instead.
trusted_executable_prefix() {
  case "$1" in
    /opt/homebrew/bin/*|/usr/local/bin/*|/usr/bin/*|/bin/* \
    |/opt/homebrew/lib/node_modules/@earendil-works/pi-coding-agent/* \
    |/usr/local/lib/node_modules/@earendil-works/pi-coding-agent/*)
      return 0
      ;;
  esac
  return 1
}

# Seatbelt write roots, evaluated against a CANDIDATE EXECUTABLE path.
#
# The profile grants file-write* to PROJECT, TMPDIR, /private/tmp, ~/.pi/agent,
# ~/.npm, ~/.cache, and ~/Library/Caches. An executable living under any of those is
# rewritable by the sandboxed agent itself, which turns one confined session into
# persistence across every later launch. A bound path is exempt from path-shape
# rules, so this is the check that keeps "exempt" from meaning "unchecked".
#
# PROJECT/TMPDIR are resolved later than this function is defined, so callers pass
# them in when known; absent values are simply not matched.
executable_under_sandbox_write_root() {
  local target="$1" home_canon="$2" project="$3" tmpdir="$4"
  [ -n "$target" ] || return 1

  case "$target" in
    /private/tmp/*|/tmp/*|/var/tmp/*|/private/var/tmp/*) return 0 ;;
  esac
  # The Darwin per-user temp dir is the value that becomes -D TMPDIR=..., and it is
  # shaped /var/folders/<xx>/<...>/T/... (canonically /private/var/folders/...). Deny it
  # by SHAPE as well as by the ambient TMPDIR value below: matching only $TMPDIR would
  # let a caller unset or repoint TMPDIR to slip a target through this check, and this
  # runs before canonical_safe_tmpdir has vetted anything.
  case "$target" in
    /var/folders/*/T/*|/private/var/folders/*/T/*) return 0 ;;
  esac
  if [ -n "$home_canon" ]; then
    case "$target" in
      "$home_canon"/.pi/agent/*|"$home_canon"/.npm/*|"$home_canon"/.cache/* \
      |"$home_canon"/Library/Caches/*) return 0 ;;
    esac
  fi
  [ -n "$project" ] && case "$target" in "$project"/*) return 0 ;; esac
  [ -n "$tmpdir" ] && case "$target" in "$tmpdir"/*) return 0 ;; esac
  return 1
}

canonical_path() {
  print -r -- "${1:A}"
}

resolve_active_hooks() {
  local project="$1"
  local raw="" resolved=""

  if XDG_CONFIG_HOME="$PI_GIT_XDG_CONFIG_HOME" "$GIT_BIN" -C "$project" rev-parse --git-dir >/dev/null 2>&1; then
    raw="$(XDG_CONFIG_HOME="$PI_GIT_XDG_CONFIG_HOME" "$GIT_BIN" -C "$project" rev-parse --path-format=absolute --git-path hooks 2>/dev/null || true)"
    if [ -z "$raw" ]; then
      raw="$(XDG_CONFIG_HOME="$PI_GIT_XDG_CONFIG_HOME" "$GIT_BIN" -C "$project" rev-parse --git-path hooks 2>/dev/null || true)"
    fi
  else
    raw="$project/.git/hooks"
  fi

  if [ -z "$raw" ] || [[ "$raw" == *$'\n'* || "$raw" == *$'\r'* ]]; then
    emit "cannot resolve the active Git hooks path; refusing."
    return 1
  fi

  if [[ "$raw" == /* ]]; then
    resolved="${raw:A}"
  else
    resolved="$(cd -P "$project" 2>/dev/null && print -r -- "${raw:A}")" || {
      emit "cannot canonicalize active Git hooks path '$raw'; refusing."
      return 1
    }
  fi

  # ACTIVE_HOOKS is a deny subtree. Refuse values broad enough to make the
  # project or a shared writable root unusable; this also catches symlinked
  # hooks paths that resolve to a project ancestor.
  case "$resolved" in
    ""|"/"|"/Users"|"/Volumes"|"/tmp"|"/private/tmp"|"/private"|"/var" \
    |"/private/var"|"/var/tmp"|"/private/var/tmp"|"/System"|"/Library" \
    |"/Applications"|"/usr"|"/bin"|"/sbin"|"/opt"|"$HOME")
      emit "refusing unsafe active Git hooks path '$resolved' (broad/system root)."
      return 1
      ;;
  esac
  case "$project" in
    "$resolved"|"$resolved"/*)
      emit "refusing active Git hooks path '$resolved' because it contains the project boundary."
      return 1
      ;;
  esac

  print -r -- "$resolved"
}

config_value_for_key() {
  local key="$1"
  [ -f "$PI_EXECUTABLE_CONFIG" ] || return 1

  "$AWK_BIN" -F= -v key="$key" '
    /^[[:space:]]*($|#)/ { next }
    {
      name=$1
      sub(/^[[:space:]]+/, "", name)
      sub(/[[:space:]]+$/, "", name)
      if (name == key) {
        sub(/^[^=]*=/, "", $0)
        sub(/^[[:space:]]+/, "", $0)
        sub(/[[:space:]]+$/, "", $0)
        if ($0 ~ /^".*"$/ || $0 ~ /^\047.*\047$/) {
          sub(/^["\047]/, "", $0)
          sub(/["\047]$/, "", $0)
        }
        print $0
        found=1
        exit
      }
    }
    END { if (!found) exit 1 }
  ' "$PI_EXECUTABLE_CONFIG" 2>/dev/null
}

resolve_command_outside_shim_dir() {
  local command_name="$1"
  local shim_dir=""
  local path_dir path_dir_canon candidate

  if [[ "$command_name" == */* ]]; then
    print -r -- "$(canonical_path "$command_name")"
    return 0
  fi

  if [ -n "${PI_SANDBOX_SHIM_PATH:-}" ]; then
    shim_dir="$(canonical_path "${PI_SANDBOX_SHIM_PATH:h}")"
  fi

  for path_dir in "${(@s/:/)PATH}"; do
    [ -n "$path_dir" ] || path_dir="."
    path_dir_canon="$(canonical_path "$path_dir")"
    if [ -n "$shim_dir" ] && [ "$path_dir_canon" = "$shim_dir" ]; then
      continue
    fi
    candidate="$path_dir/$command_name"
    if [ -x "$candidate" ] && [ ! -d "$candidate" ]; then
      candidate="$(canonical_path "$candidate")"
      if "$GREP_BIN" -q "pi-sandbox-guard" "$candidate" 2>/dev/null; then
        continue
      fi
      if trusted_executable_prefix "$candidate"; then
        print -r -- "$candidate"
        return 0
      fi
    fi
  done

  return 1
}

verify_existing_confinement() {
  local home_probe="$HOME/.pi-sandbox-guard-home-probe.$$"
  local ext_probe="$HOME/.pi/agent/extensions/.pi-sandbox-guard-probe.$$"
  local project="${PI_SANDBOX_PROJECT_BOUNDARY:-}"
  local active_hooks="${PI_SANDBOX_ACTIVE_HOOKS_BOUNDARY:-}"
  local project_probe hooks_probe

  if [ -z "$project" ] || [ ! -d "$project" ]; then
    emit "existing confinement probe failed: recorded project boundary is unavailable."
    return 1
  fi
  project_probe="$project/.pi-sandbox-guard-project-probe.$$"
  if ! "$SH_BIN" -c 'echo x > "$1"' _ "$project_probe" >/dev/null 2>&1; then
    emit "existing confinement probe failed: recorded project boundary is not writable."
    return 1
  fi
  if ! "$RM_BIN" -f "$project_probe" >/dev/null 2>&1; then
    emit "existing confinement probe failed: could not remove project probe."
    return 1
  fi

  if [ -z "$active_hooks" ]; then
    emit "existing confinement probe failed: recorded active-hooks boundary is unavailable."
    return 1
  fi
  hooks_probe="$active_hooks/.pi-sandbox-guard-hook-probe.$$"
  if "$SH_BIN" -c 'mkdir -p "$1" && echo x > "$2"' _ "$active_hooks" "$hooks_probe" >/dev/null 2>&1; then
    "$RM_BIN" -f "$hooks_probe" 2>/dev/null || true
    emit "existing confinement probe failed: active-hooks write was allowed."
    return 1
  fi

  if "$SH_BIN" -c 'echo x > "$1"' _ "$home_probe" >/dev/null 2>&1; then
    "$RM_BIN" -f "$home_probe" 2>/dev/null || true
    emit "existing confinement probe failed: home write was allowed."
    return 1
  fi

  if "$SH_BIN" -c 'mkdir -p "$1" && echo x > "$2"' _ "$HOME/.pi/agent/extensions" "$ext_probe" >/dev/null 2>&1; then
    "$RM_BIN" -f "$ext_probe" 2>/dev/null || true
    emit "existing confinement probe failed: Pi extensions write was allowed."
    return 1
  fi

  if [ -d "$HOME/.ssh" ] && "$SH_BIN" -c 'ls "$1" >/dev/null' _ "$HOME/.ssh" >/dev/null 2>&1; then
    emit "existing confinement probe failed: ~/.ssh read was allowed."
    return 1
  fi

  return 0
}

# Own-shim nested re-entry: require the profile digest marker planted by the
# outer protected shim, plus behavioral probes. The digest is world-readable
# and is not an authentication secret; the probes are the enforcement evidence.
# Generic CODEX/SANDBOX markers alone are never treated as equivalent policy.
own_policy_reentry() {
  local expected="$1"
  [ "$PI_SANDBOX_TRANSPARENT" = "1" ] || return 1
  [ -n "${PI_SANDBOX_SHIM_ACTIVE:-}" ] || return 1
  [ -n "$expected" ] || return 1
  [ -n "${PI_SANDBOX_PROFILE_DIGEST:-}" ] || return 1
  [ "$PI_SANDBOX_PROFILE_DIGEST" = "$expected" ] || return 1
  verify_existing_confinement || return 1
  return 0
}

# Shared validation for any absolute executable target, whatever selected it.
# Everything here is source-independent: existence, executability, not-a-directory,
# not this guard's own shim (anti-recursion), and not inside a Seatbelt write root.
# The trusted-prefix test is deliberately NOT here — it is applied only to ambient
# sources by their own callers.
validate_executable_target() {
  local resolved="$1"
  [ -n "$resolved" ] || return 1
  if [ ! -x "$resolved" ] || [ -d "$resolved" ]; then
    return 1
  fi
  # A guard script (the shim itself, or a copy of it) would re-enter and loop.
  if "$GREP_BIN" -q "pi-sandbox-guard" "$resolved" 2>/dev/null; then
    return 1
  fi
  if executable_under_sandbox_write_root \
       "$resolved" "${HOME_CANON_EARLY:-}" "" ""; then
    return 1
  fi
  return 0
}

resolve_configured_executable() {
  local configured="$1" resolved=""
  if [[ "$configured" == */* ]]; then
    case "$configured" in
      /*) ;;
      *) return 1 ;;
    esac
    resolved="$(canonical_path "$configured")"
    validate_executable_target "$resolved" || return 1
    # AMBIENT source (env var): keep the path-shape restriction. An operator-recorded
    # binding goes through resolve_bound_executable instead, which is exempt.
    if ! trusted_executable_prefix "$resolved"; then
      return 1
    fi
    print -r -- "$resolved"
    return 0
  fi

  resolve_command_outside_shim_dir "$configured"
}

# Operator-recorded binding: an absolute path written to the pinned config by a
# deliberate `npm run bind` run. EXEMPT from trusted_executable_prefix, because
# no fixed path shape can describe the real install surface — Homebrew's Cellar,
# npm user prefixes, nvm/fnm/volta/asdf/mise version dirs, pnpm/bun/yarn global
# roots, and Nix store paths are all legitimate and all differently shaped.
#
# What replaces the path shape:
#   * the value comes from host state under real HOME, never from the environment
#     (the protected shim ignores an ambient PI_EXECUTABLE_CONFIG entirely), and
#   * validate_executable_target still rejects the shim and Seatbelt write roots.
#
# This is a NON-AMBIENT HOST PIN, not integrity: a same-uid attacker outside the
# sandbox who can edit this config can equally edit the shim or the Pi install
# itself. It defends against project-controlled environment and against a confined
# Pi session retargeting its own next launch — not against host compromise.
resolve_bound_executable() {
  local configured="$1" resolved=""
  case "$configured" in
    /*) ;;
    *) return 1 ;;
  esac
  resolved="$(canonical_path "$configured")"
  validate_executable_target "$resolved" || return 1
  print -r -- "$resolved"
}

# Resolve the interpreter for a bound Node entry point.
#
# WHY THIS IS NOT LEFT TO THE SHEBANG: the launch line execs the resolved target
# directly, so a `#!/usr/bin/env node` script resolves `node` from the SANITIZED
# PATH built above — which lists only Homebrew and system bins. On a host whose only
# Node comes from nvm/fnm/volta/asdf/mise there is no `node` there at all, so a
# perfectly bound Pi would still fail to start, AFTER resolution reported success.
# Recording the interpreter is only meaningful if it becomes argv[0] of the launch,
# which is what PI_LAUNCH_VECTOR below does.
#
# The recorded interpreter is validated exactly like the executable (absolute,
# executable, not a directory, not the shim, not under a Seatbelt write root). A
# user-writable node is trusted-by-record: the operator named it. That is the same
# bargain as the bound executable, and is documented as such.
resolve_bound_interpreter() {
  local configured="$1" resolved=""
  case "$configured" in
    /*) ;;
    *) return 1 ;;
  esac
  resolved="$(canonical_path "$configured")"
  validate_executable_target "$resolved" || return 1
  print -r -- "$resolved"
}

# Decide the launch vector for a resolved target.
#
# PI_LAUNCH_VECTOR is the array the launcher execs after the sandbox prefix. Two
# shapes, chosen by what the target actually is rather than by configuration:
#
#   native executable / wrapper script with a resolvable interpreter
#       -> (target)                       [shebang handled by the kernel as today]
#   Node entry point (#!/usr/bin/env node) WITH a recorded interpreter
#       -> (interpreter target)           [no PATH lottery for `node`]
#
# A Node entry point with NO recorded interpreter keeps today's behavior rather than
# failing: on a Homebrew/system-Node host the sanitized PATH does resolve `node`, and
# breaking those working hosts to enforce a new record would be a regression. Doctor
# reports the missing record; the launch only hard-fails if the shebang then cannot
# be satisfied, which is the pre-existing failure mode and not one this adds.
build_launch_vector() {
  local target="$1" interpreter="$2"
  typeset -ga PI_LAUNCH_VECTOR
  PI_LAUNCH_VECTOR=("$target")
  [ -n "$interpreter" ] || return 0

  # Only prepend the interpreter for something that actually needs one: a `node`
  # shebang. Prepending it to a native binary would try to parse ELF/Mach-O as JS.
  local first_line=""
  first_line="$(head -c 128 "$target" 2>/dev/null | head -1 || true)"
  case "$first_line" in
    '#!'*[[:space:]]node|'#!'*[[:space:]]node[[:space:]]*|'#!'*/node|'#!'*/node[[:space:]]*)
      PI_LAUNCH_VECTOR=("$interpreter" "$target")
      ;;
  esac
}

resolve_pi_executable() {
  local configured="" resolved="" shim_canon="" target_canon=""
  local configured_source="" bound="" interpreter="" bound_interpreter=""

  # SOURCE PRECEDENCE, and why each source gets the rules it gets:
  #   1. PI_EXECUTABLE (env)  — AMBIENT. A project .envrc/Makefile/npm script can set
  #      it, so it keeps the trusted-prefix restriction.
  #   2. pi= in the pinned config — OPERATOR-RECORDED. Exempt from path shape.
  #   3. auto-resolution from the sanitized PATH — AMBIENT-ish (PATH is sanitized, but
  #      no operator named the result), so it keeps the trusted-prefix restriction.
  #
  # The config key is read with a FIXED name in transparent mode. PI_EXECUTABLE_KEY is
  # caller-settable (launchers/pi defaults it to ${0:t}), so honoring it here while the
  # config also holds a node= record would let a wrapper export PI_EXECUTABLE_KEY=node
  # and launch the interpreter AS Pi — skipping Pi's own tool/extension layer entirely.
  # Interpreter records therefore live under a key the executable lookup cannot select.
  if [ -n "${PI_EXECUTABLE:-}" ]; then
    configured="$PI_EXECUTABLE"
    configured_source="env"
  elif [ "$PI_SANDBOX_TRANSPARENT" = "1" ]; then
    bound="$(config_value_for_key "pi" || true)"
    [ -n "$bound" ] && configured_source="bound"
  else
    configured="$(config_value_for_key "$PI_EXECUTABLE_KEY" || true)"
    if [ -z "$configured" ] && [ "$PI_EXECUTABLE_KEY" != "pi" ]; then
      configured="$(config_value_for_key "pi" || true)"
    fi
    [ -n "$configured" ] && configured_source="config"
  fi

  if [ "$PI_SANDBOX_TRANSPARENT" = "1" ]; then
    case "$configured_source" in
      env)
        resolved="$(resolve_configured_executable "$configured" || true)"
        if [ -z "$resolved" ]; then
          emit "PI_EXECUTABLE='$configured' is not an accepted ambient override."
          emit "  Ambient overrides must sit in a fixed trusted prefix. To use an"
          emit "  install elsewhere, record it once from the repo checkout:"
          emit "    npm run bind -- --pi <abs-path>"
          exit 1
        fi
        ;;
      bound)
        resolved="$(resolve_bound_executable "$bound" || true)"
        if [ -z "$resolved" ]; then
          emit "recorded Pi binding is no longer usable: '$bound'"
          emit "  It must be an absolute path to an existing executable, not this shim,"
          emit "  and not inside a sandbox-writable root. Re-record it:"
          emit "  npm run bind -- --detect   (or -- --pi <abs-path>), from the repo checkout"
          exit 1
        fi
        ;;
      *)
        resolved="$(resolve_command_outside_shim_dir "pi" || true)"
        if [ -z "$resolved" ]; then
          emit "cannot auto-resolve the real Pi executable outside the shim path."
          emit "  Auto-resolution only searches fixed trusted prefixes, which do not"
          emit "  cover Homebrew's Cellar, npm user prefixes, nvm/fnm/volta/asdf/mise,"
          emit "  pnpm/bun/yarn globals, or Nix. Record your install once:"
          emit "    npm run bind -- --detect      (from the repo checkout)"
          exit 1
        fi
        ;;
    esac

    [ -n "${PI_SANDBOX_SHIM_PATH:-}" ] && shim_canon="$(canonical_path "$PI_SANDBOX_SHIM_PATH")"
    target_canon="$(canonical_path "$resolved")"
    if [ -n "$shim_canon" ] && [ "$target_canon" = "$shim_canon" ]; then
      emit "configured Pi executable resolves to this shim ($target_canon); refusing recursive launch."; exit 1
    fi
    if [ ! -x "$target_canon" ] || [ -d "$target_canon" ]; then
      emit "resolved Pi executable is not executable: $target_canon"; exit 1
    fi

    # Interpreter record: read from a key the executable lookup cannot reach.
    bound_interpreter="$(config_value_for_key "node" || true)"
    if [ -n "$bound_interpreter" ]; then
      interpreter="$(resolve_bound_interpreter "$bound_interpreter" || true)"
      if [ -z "$interpreter" ]; then
        emit "recorded interpreter is no longer usable: '$bound_interpreter'"
        emit "  Re-record it from the repo checkout:"
        # Both operands, deliberately: this branch is reached only when the
        # recorded interpreter is already unusable, and `--pi` alone re-derives
        # node by detection — which is what just failed.
        emit "    npm run bind -- --detect   (or -- --pi <abs-path> --node <abs-path>)"
        exit 1
      fi
    fi

    PI_EXECUTABLE="$target_canon"
    PI_INTERPRETER="$interpreter"
    build_launch_vector "$target_canon" "$interpreter"
    return 0
  fi

  PI_EXECUTABLE="${configured:-pi}"
  PI_INTERPRETER=""
  build_launch_vector "${configured:-pi}" ""
}

# Canonicalize TMPDIR and refuse values that would widen Seatbelt writes.
# Accept only the normal owned Darwin per-user temp path and /private/tmp.
canonical_safe_tmpdir() {
  local raw="${1:-/tmp}"
  local canon owner
  local home_canon="${HOME_CANON:-}"
  local project_canon="${PROJECT:-}"

  if [ ! -d "$raw" ]; then
    emit "refusing TMPDIR '$raw' (not a directory)."
    return 1
  fi

  canon="$(cd -P "$raw" 2>/dev/null && pwd -P)" || {
    emit "cannot resolve TMPDIR '$raw'; refusing."
    return 1
  }

  # Hard refuse broad roots and HOME itself (never widen writes to / or $HOME).
  case "$canon" in
    ""|"/"|"/Users"|"/Users/"|"/Volumes"|"/Volumes/"|"/tmp"|"/private" \
    |"/var"|"/private/var"|"/var/tmp"|"/private/var/tmp"|"/var/folders"|"/private/var/folders" \
    |"/etc"|"/private/etc"|"/usr"|"/bin"|"/sbin"|"/opt"|"/System"|"/Library"|"/Applications")
      emit "refusing unsafe TMPDIR '$canon' (broad/system root)."
      return 1
      ;;
  esac

  if [ -n "$home_canon" ]; then
    case "$canon" in
      "$home_canon"|"$home_canon"/*)
        emit "refusing unsafe TMPDIR '$canon' (HOME or under HOME)."
        return 1
        ;;
    esac
    # Ancestor of HOME (e.g. /Users) would make HOME writable via subpath.
    case "$home_canon" in
      "$canon"|"$canon"/*)
        emit "refusing unsafe TMPDIR '$canon' (ancestor of HOME)."
        return 1
        ;;
    esac
  fi

  # Refuse using the project root itself as TMPDIR (unexpected / redundant widen
  # surface). A temp dir that merely *contains* a project (common for tests and
  # scratch checkouts under $TMPDIR) remains acceptable.
  if [ -n "$project_canon" ] && [ "$canon" = "$project_canon" ]; then
    emit "refusing unsafe TMPDIR '$canon' (project root)."
    return 1
  fi

  # Allowlist: exact /private/tmp, or Darwin per-user temp .../T[/...].
  case "$canon" in
    /private/tmp)
      print -r -- "$canon"
      return 0
      ;;
    /private/var/folders/*/*/*)
      if [[ "$canon" =~ ^/private/var/folders/[^/]+/[^/]+/T(/.*)?$ ]]; then
        owner="$("$STAT_BIN" -f '%Su' "$canon" 2>/dev/null || true)"
        if [ -z "$LOGIN_USER" ] || [ -z "$owner" ]; then
          emit "refusing TMPDIR '$canon' (could not verify owner/login identity)."
          return 1
        fi
        if [ "$owner" != "$LOGIN_USER" ]; then
          emit "refusing TMPDIR '$canon' (not owned by login user '$LOGIN_USER')."
          return 1
        fi
        print -r -- "$canon"
        return 0
      fi
      ;;
  esac

  emit "refusing unexpected TMPDIR '$canon' (not Darwin per-user temp or /private/tmp)."
  return 1
}

# Focused self-test hooks (no Pi launch). Used by test/shim.mjs only.
if [ "${PI_SANDBOX_SELFTEST:-}" = "tmpdir" ]; then
  HOME_CANON="$(cd -P "$HOME" 2>/dev/null && pwd -P || print -r -- "$HOME")"
  if [ -n "${PI_PROJECT:-}" ]; then
    PROJECT="$(cd -P "$PI_PROJECT" 2>/dev/null && pwd -P || print -r -- "$PI_PROJECT")"
  else
    PROJECT=""
  fi
  canonical_safe_tmpdir "${TMPDIR:-/tmp}" || exit 1
  exit 0
fi

if [ "${PI_SANDBOX_SELFTEST:-}" = "resolve" ]; then
  # Optional config path for resolution unit tests (not honored by the real launcher).
  if [ -n "${PI_SANDBOX_SELFTEST_CONFIG:-}" ]; then
    PI_EXECUTABLE_CONFIG="$PI_SANDBOX_SELFTEST_CONFIG"
  fi
  # Transparent resolution is the protected-shim path under test.
  PI_SANDBOX_TRANSPARENT=1
  resolve_pi_executable
  # Default output stays the resolved executable so existing callers are unaffected.
  # PI_SANDBOX_SELFTEST_VECTOR=1 prints the full launch vector, one element per line,
  # which is the only way to observe interpreter prepending without launching Pi.
  if [ "${PI_SANDBOX_SELFTEST_VECTOR:-}" = "1" ]; then
    printf '%s\n' "${PI_LAUNCH_VECTOR[@]}"
  else
    print -r -- "$PI_EXECUTABLE"
  fi
  exit 0
fi

if [ "${PI_SANDBOX_SELFTEST:-}" = "active-hooks" ]; then
  [ -n "${PI_PROJECT:-}" ] || {
    emit "PI_PROJECT is required for active-hooks selftest."
    exit 1
  }
  SELFTEST_PROJECT="$(cd -P "$PI_PROJECT" 2>/dev/null && pwd -P)" || exit 1
  resolve_active_hooks "$SELFTEST_PROJECT" || exit 1
  exit 0
fi

resolve_pi_executable

# Minimal, non-breaking resource guard. NO -u (process cap) — it broke fork() at
# low values. Core dumps off; file-size ~2GB. CPU cap is opt-in only (PI_RLIMIT_CPU).
ulimit -c 0 2>/dev/null || true
ulimit -f 4194304 2>/dev/null || true
[ -n "${PI_RLIMIT_CPU:-}" ] && { ulimit -t "$PI_RLIMIT_CPU" 2>/dev/null || true; }

# npm must not need to READ ~/.npmrc (sandbox denies it); point userconfig at /dev/null.
# (Private registries/auth via ~/.npmrc require an unsandboxed direct Pi run.)
export NPM_CONFIG_USERCONFIG="/dev/null"
unset SSH_AUTH_SOCK GPG_AGENT_INFO

if [ "$PI_SANDBOX" = "0" ]; then
  emit "PI_SANDBOX=0 — OS sandbox BYPASSED for this run (guard extension still active)."
  return 0 2>/dev/null || true
fi

PROFILE="$PI_SANDBOX_PROFILE"
EXPECTED_PROFILE_DIGEST=""
if [ -f "$PROFILE" ] && [ -x "$SHASUM_BIN" ]; then
  EXPECTED_PROFILE_DIGEST="$("$SHASUM_BIN" -a 256 "$PROFILE" 2>/dev/null | "$AWK_BIN" '{print $1; exit}' || true)"
fi

ACTUAL_CONFINEMENT=0
if [ -x "$SANDBOX_EXEC" ] && ! "$SANDBOX_EXEC" -p '(version 1)(allow default)' "$TRUE_BIN" >/dev/null 2>&1; then
  ACTUAL_CONFINEMENT=1
fi

# Own-shim re-entry: profile digest coincidence check + behavioral probes.
# Do not trust SHIM_ACTIVE/digest alone, and never treat generic sandbox env
# markers as equivalent confinement.
if [ "$ACTUAL_CONFINEMENT" = "1" ]; then
  if own_policy_reentry "$EXPECTED_PROFILE_DIGEST"; then
    emit "existing pi-sandbox-guard confinement detected; skipping nested wrap."
    PI_SANDBOX_CMD=()
    return 0 2>/dev/null || true
  fi
  if [ "$PI_SANDBOX_TRANSPARENT" = "1" ]; then
    if [ -n "${PI_SANDBOX_SHIM_ACTIVE:-}" ] || [ -n "${PI_SANDBOX_PROFILE_DIGEST:-}" ]; then
      emit "nested profile digest mismatch or confinement probes failed; refusing."
      exit 1
    fi
    if [ -n "${CODEX_SANDBOX:-}" ] || [ -n "${SANDBOX_PROFILE:-}" ] || [ -n "${SECCOMP:-}" ]; then
      emit "unknown parent sandbox (marker env without own profile digest); refusing."
      exit 1
    fi
    emit "sandbox_apply unavailable and no verified own-shim confinement; refusing."
    exit 1
  fi
  emit "sandbox_apply unavailable here (nested context?); refusing. Run the real Pi binary directly to bypass."; exit 1
fi

# Transparent PATH shims: generic sandbox-looking env markers without confinement
# fall through to normal sandbox setup. Markers alone never grant pass-through.
if [ -n "${CODEX_SANDBOX:-}" ] || [ -n "${SANDBOX_PROFILE:-}" ] || [ -n "${SECCOMP:-}" ]; then
  if [ "$PI_SANDBOX_TRANSPARENT" = "1" ]; then
    emit "sandbox marker env set but no active confinement detected; applying sandbox."
  else
    emit "running inside an existing sandbox; refusing nested wrap. Run the real Pi binary directly for guard-only."; exit 1
  fi
fi

# Leaked own-shim marker without confinement: do not skip wrap.
if [ "$PI_SANDBOX_TRANSPARENT" = "1" ] && { [ -n "${PI_SANDBOX_SHIM_ACTIVE:-}" ] || [ -n "${PI_SANDBOX_PROFILE_DIGEST:-}" ]; }; then
  emit "PI_SANDBOX_SHIM_ACTIVE/PROFILE_DIGEST set but no active confinement detected; applying sandbox."
fi

# fail-closed prerequisites (absolute path; do not trust $PATH)
if [ ! -x "$SANDBOX_EXEC" ]; then
  emit "$SANDBOX_EXEC not found; refusing to launch. Run the real Pi binary directly for guard-only."; exit 1
fi
if [ ! -f "$PROFILE" ]; then
  emit "sandbox profile missing ($PROFILE); refusing to launch. Run the real Pi binary directly to bypass."; exit 1
fi
if [ -z "$EXPECTED_PROFILE_DIGEST" ]; then
  emit "cannot compute sandbox profile digest for $PROFILE; refusing to launch."; exit 1
fi

# Project boundary, in priority order:
#   1. explicit PI_PROJECT (you said exactly where)
#   2. git toplevel (so launching from a subdir makes the WHOLE repo writable)
#   3. the current directory ($PWD) — supports brand-new / not-yet-git dirs, so the
#      agent can `git init` / scaffold a fresh project. The cwd is what you intend
#      to work in; making it writable is correct.
# In all cases we then REFUSE only genuinely dangerous boundaries (broad roots) —
# that is the real safety property, not "must be a git repo".
PROJECT_VIA="explicit"
if [ -n "${PI_PROJECT:-}" ]; then
  PROJECT="$PI_PROJECT"
else
  PROJECT="$(XDG_CONFIG_HOME="$PI_GIT_XDG_CONFIG_HOME" "$GIT_BIN" rev-parse --show-toplevel 2>/dev/null || true)"
  if [ -n "$PROJECT" ]; then
    PROJECT_VIA="git-toplevel"
  else
    PROJECT="$PWD"
    PROJECT_VIA="cwd (non-git)"
  fi
fi
PROJECT="$(cd -P "$PROJECT" 2>/dev/null && pwd -P)" || {
  emit "cannot resolve project dir '$PROJECT'; refusing."; exit 1; }

# Refuse dangerous boundaries (the actual safety check). A fresh empty project dir
# is fine; broad roots, system prefixes, and credential/home subtrees are not.
# This matters more now that a non-git cwd falls back to $PWD: ANY directory you
# launch from would otherwise become writable. We therefore refuse, for every
# resolution mode (explicit / git / cwd):
#   - broad roots and the home dir itself
#   - system prefixes (/etc, /usr, /bin, /sbin, /System, /Library, /Applications,
#     /opt, /private, /var) — both raw and canonicalized (/etc -> /private/etc)
#   - sensitive home subtrees (~/.ssh, ~/.aws, ~/.config, ~/.docker, ~/.gnupg,
#     ~/.kube, ~/Desktop, ~/Documents, ~/Downloads, ~/Library)
# Canonicalize HOME for an accurate comparison (handles symlinked home).
HOME_CANON="$(cd -P "$HOME" 2>/dev/null && pwd -P || echo "$HOME")"
INSTALL_DIR_CANON="$(cd -P "$PI_SANDBOX_INSTALL_DIR" 2>/dev/null && pwd -P || echo "$PI_SANDBOX_INSTALL_DIR")"
case "$INSTALL_DIR_CANON" in
  "$PROJECT"|"$PROJECT"/*)
    emit "refusing unsafe boundary '$PROJECT' because it contains the sandbox guard install dir '$INSTALL_DIR_CANON'."
    emit "cd into a project directory or set PI_PROJECT=<dir>; call the real Pi binary directly to bypass."; exit 1 ;;
esac
#
# NOTE on what is and isn't listed:
#  - System prefixes (/etc, /usr, /bin, /sbin, /System, /Library, /Applications,
#    /opt) are root-owned; the user can't write them even if the sandbox allowed
#    it. Listed anyway as belt-and-suspenders / clear refusal — you'd never launch
#    a project there.
#  - We deliberately do NOT blanket-refuse /private/* or /var/* because the legit
#    per-user temp dirs live there (/private/tmp/..., /private/var/folders/...);
#    a project under temp is harmless (temp is already a writable root). We refuse
#    only the sensitive canonical /etc form (/private/etc).
#  - The high-value refusals are USER-OWNED sensitive subtrees — above all ~/.ssh
#    (the profile read-denies it, but as a PROJECT boundary it would become
#    WRITE-allowed, enabling a malicious authorized_keys). ~/Library, ~/Desktop,
#    ~/Documents, ~/Downloads are also refused as accidental over-broad launches.
case "$PROJECT" in
  ""|"/"|"$HOME"|"$HOME_CANON"|"/Users"|"/Users/"|"/Volumes"|"/Volumes/"|"/tmp"|"/private/tmp" \
  |"/etc"|"/etc/"*|"/private/etc"|"/private/etc/"* \
  |"/usr"|"/usr/"*|"/bin"|"/bin/"*|"/sbin"|"/sbin/"*|"/opt"|"/opt/"* \
  |"/System"|"/System/"*|"/Library"|"/Library/"*|"/Applications"|"/Applications/"* \
  |"/private"|"/var"|"/private/var"|"/var/tmp"|"/private/var/tmp" \
  |"$HOME_CANON/.ssh"|"$HOME_CANON/.ssh/"* \
  |"$HOME_CANON/.aws"|"$HOME_CANON/.aws/"* \
  |"$HOME_CANON/.config"|"$HOME_CANON/.config/"* \
  |"$HOME_CANON/.docker"|"$HOME_CANON/.docker/"* \
  |"$HOME_CANON/.gnupg"|"$HOME_CANON/.gnupg/"* \
  |"$HOME_CANON/.kube"|"$HOME_CANON/.kube/"* \
  |"$HOME_CANON/Library"|"$HOME_CANON/Library/"* \
  |"$HOME_CANON/Desktop"|"$HOME_CANON/Desktop/"* \
  |"$HOME_CANON/Documents"|"$HOME_CANON/Documents/"* \
  |"$HOME_CANON/Downloads"|"$HOME_CANON/Downloads/"*)
    emit "refusing unsafe boundary '$PROJECT' (broad/system/credential path)."
    emit "cd into a project directory or set PI_PROJECT=<dir>; call the real Pi binary directly to bypass."; exit 1 ;;
esac

ACTIVE_HOOKS="$(resolve_active_hooks "$PROJECT")" || exit 1
TMPDIR_CANON="$(canonical_safe_tmpdir "${TMPDIR:-/tmp}")" || exit 1

# Re-check the launch target now that PROJECT and TMPDIR are actually known.
#
# resolve_pi_executable runs far earlier (it must: the launch target is needed before
# any of this), so its write-root check could only match fixed shapes. PROJECT is
# discovered here — from git, PI_PROJECT, or $PWD — and the profile grants file-write*
# to all of it. Without this second pass, an executable bound INSIDE the project would
# be rewritable by the very session it launches: one confined run edits the binary, and
# every later launch executes that edit with the agent's network and project access,
# skipping Pi's own tool layer. The same applies to a TMPDIR that is not the standard
# Darwin per-user path.
#
# Both elements of the launch vector are checked: an attacker-controlled interpreter is
# as good as an attacker-controlled script.
for _pi_launch_element in "${PI_LAUNCH_VECTOR[@]}"; do
  if executable_under_sandbox_write_root \
       "$_pi_launch_element" "$HOME_CANON" "$PROJECT" "$TMPDIR_CANON"; then
    emit "refusing to launch '$_pi_launch_element': it is inside a sandbox-writable root"
    emit "  (project '$PROJECT' or temp '$TMPDIR_CANON'). The sandboxed agent could"
    emit "  rewrite it and persist into every later launch. Record an install outside"
    # Name both operands and do NOT offer --detect here: the refused element may be
    # the recorded interpreter, and both --detect and a bare --pi re-derive node via
    # detect_node, which takes the first PATH hit with no write-root filter — so
    # either would re-record the same unsafe path and fail identically next launch.
    emit "  the project: npm run bind -- --pi <abs-path> --node <abs-path>"
    exit 1
  fi
done
unset _pi_launch_element

emit "OS sandbox ON. Project [$PROJECT_VIA]: $PROJECT"
emit "  active Git hooks denied: $ACTIVE_HOOKS"
emit "  also writable: $TMPDIR_CANON, /private/tmp, ~/.pi/agent (minus config/auth/trust/extensions), ~/.npm, ~/.cache, ~/Library/Caches"

# Record the applied profile and behavioral boundaries for nested re-entry.
# These values are not secrets; nested verification probes their enforcement.
PI_SANDBOX_PROFILE_DIGEST="$EXPECTED_PROFILE_DIGEST"
PI_SANDBOX_PROJECT_BOUNDARY="$PROJECT"
PI_SANDBOX_ACTIVE_HOOKS_BOUNDARY="$ACTIVE_HOOKS"
export PI_SANDBOX_PROFILE_DIGEST PI_SANDBOX_PROJECT_BOUNDARY PI_SANDBOX_ACTIVE_HOOKS_BOUNDARY

PI_SANDBOX_CMD=(
  "$SANDBOX_EXEC"
  -D "PROJECT=$PROJECT"
  -D "HOME=$HOME"
  -D "TMPDIR=$TMPDIR_CANON"
  -D "ACTIVE_HOOKS=$ACTIVE_HOOKS"
  -f "$PROFILE"
)
