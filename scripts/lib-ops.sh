#!/usr/bin/env bash
# lib-ops.sh — shared helpers for deploy/status/hook ops scripts.
# Sourced only (not executed). Bash 3.2 compatible. Space-safe quoting.
#
# Does not read auth/credentials. Does not mutate ~/.pi or ~/.local/bin by itself.

# shellcheck disable=SC2034
# Callers may use these after sourcing.

ops_die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
ops_say() { printf '%s\n' "$*"; }
ops_warn() { printf 'Warning: %s\n' "$*" >&2; }

# State/provenance files are line-oriented key=value records. Values containing
# CR/LF can inject a second record that later rollback/status code treats as
# authoritative, so reject them at the CLI boundary instead of inventing a
# second serialization format.
ops_require_single_line() {
  local label="$1" value="$2"
  case "$value" in
    *$'\n'*|*$'\r'*) ops_die "$label must not contain newline characters" ;;
  esac
}

# SHA-256 of a file. Empty string if unreadable.
ops_hash_file() {
  local f="$1"
  if [ ! -f "$f" ]; then
    printf ''
    return 0
  fi
  # Prefer shasum -a 256 (macOS); fall back to sha256sum (Linux CI).
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$f" 2>/dev/null | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$f" 2>/dev/null | awk '{print $1}'
  else
    ops_die "neither shasum nor sha256sum found"
  fi
}

# Require two existing files to have identical SHA-256 digests.
ops_require_same_hash() {
  local label="$1" a="$2" b="$3"
  local ha hb
  [ -f "$a" ] || ops_die "missing file for hash check ($label): $a"
  [ -f "$b" ] || ops_die "missing file for hash check ($label): $b"
  ha="$(ops_hash_file "$a")"
  hb="$(ops_hash_file "$b")"
  [ -n "$ha" ] || ops_die "could not hash $a ($label)"
  [ -n "$hb" ] || ops_die "could not hash $b ($label)"
  if [ "$ha" != "$hb" ]; then
    ops_die "hash mismatch ($label): $a ($ha) != $b ($hb)"
  fi
}

# Git short sha + clean/DIRTY from REPO_ROOT (env or arg).
ops_git_meta() {
  local root="${1:-${REPO_ROOT:-.}}"
  local sha state
  sha="$(cd "$root" && git rev-parse --short HEAD 2>/dev/null || echo nogit)"
  state="clean"
  if ! ( cd "$root" && git diff --quiet && git diff --cached --quiet ) 2>/dev/null; then
    state="DIRTY"
  fi
  printf '%s %s\n' "$sha" "$state"
}

# Shared release identity: <utc>-<shortsha>-<pidhex>
# Stable for one deploy:all invocation when RELEASE_ID is pre-set by the caller.
ops_make_release_id() {
  local root="${1:-${REPO_ROOT:-.}}"
  local sha now rnd
  sha="$(cd "$root" && git rev-parse --short HEAD 2>/dev/null || echo nogit)"
  now="$(date -u '+%Y%m%dT%H%M%SZ')"
  rnd="$(printf '%04x' "$$" 2>/dev/null || echo 0000)"
  printf '%s-%s-%s\n' "$now" "$sha" "$rnd"
}

# Read a key=value line from a stamp file (first match). Empty if missing.
ops_stamp_get() {
  local file="$1" key="$2"
  [ -f "$file" ] || { printf ''; return 0; }
  # Avoid sourcing (injection). Match ^key=
  awk -F= -v k="$key" '$1==k {print substr($0, length(k)+2); exit}' "$file" 2>/dev/null || true
}

# Encode one shell string as a JSON string literal. Callers print the returned
# value directly, including its surrounding quotes.
#
# Uses jq (already a hard dependency) rather than python3: /usr/bin/python3 is a
# Command Line Tools shim that can be absent on a clean macOS host, which would
# abort deploy for nothing more than quoting a status field.
ops_json_quote() {
  jq -Rn --arg s "$1" '$s' | tr -d '\n'
}

# Default destinations (read-only helpers; callers decide mutation).
ops_default_guard_dest() {
  printf '%s\n' "${HOME}/.pi/agent/extensions/pi-sandbox-guard"
}

ops_default_launchers_dest() {
  printf '%s\n' "${HOME}/.local/bin"
}

# Fixed and host-derived roots that the Seatbelt profile can make writable.
# PROJECT is caller-supplied because it changes per launch; active Pi/OMP state
# roots are checked by the launcher after runtime state resolution.
ops_path_is_known_sandbox_write_root() {
  local path="$1" home="${2:-$HOME}" project="${3:-}"
  case "$path" in
    /private/tmp/*|/tmp/*|/var/tmp/*|/private/var/tmp/* \
    |/var/folders/*/T/*|/private/var/folders/*/T/* \
    |"$home"/.pi/*|"$home"/.omp/*|"$home"/.omp-*/*|"$home"/.omp.*/*|"$home"/.omp_*/* \
    |"$home"/.npm/*|"$home"/.cache/*|"$home"/Library/Caches/*)
      return 0
      ;;
  esac
  if [ -n "$project" ]; then
    case "$path" in
      "$project"|"$project"/*) return 0 ;;
    esac
  fi
  return 1
}
