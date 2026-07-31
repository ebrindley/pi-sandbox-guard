#!/usr/bin/env bash
#
# deploy-launchers.sh — install the protected pi shim, the SBPL profile, the
# preamble, and any extra launchers into ~/.local/bin, backing up existing copies.
#
# Source of truth: this repo (launchers/, sandbox/). Deployed copies are artifacts.
# Mirrors deploy-local.sh: validate, back up, install, verify.
#
# The protected `pi` shim is the only launcher this repo installs by default.
# Custom wrappers (a local model server, a per-provider preset, …) live OUTSIDE
# the repo and are opted in explicitly with --extra-launchers. They are linted
# BEFORE any file is installed and the deploy refuses as a whole if one fails:
# a malformed wrapper that calls the real Pi binary instead of the sibling shim
# silently bypasses Seatbelt, so "install best-effort and warn" is not safe.
#
# Usage:
#   scripts/deploy-launchers.sh [--dest <dir>] [--dry-run]
#                               [--release-id <id>] [--state-file <path>]
#                               [--extra-launchers <dir>]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib-ops.sh
. "$REPO_ROOT/scripts/lib-ops.sh"

DEST="$(ops_default_launchers_dest)"
DRY_RUN=0
RELEASE_ID="${RELEASE_ID:-}"
STATE_FILE=""
EXTRA_DIRS=()

say() { ops_say "$@"; }
die() { ops_die "$@"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --dest)
      [ $# -ge 2 ] || die "--dest requires a directory"
      DEST="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --release-id)
      [ $# -ge 2 ] || die "--release-id requires a value"
      RELEASE_ID="$2"; shift 2 ;;
    --state-file)
      [ $# -ge 2 ] || die "--state-file requires a path"
      STATE_FILE="$2"; shift 2 ;;
    --extra-launchers)
      [ $# -ge 2 ] || die "--extra-launchers requires a directory"
      EXTRA_DIRS+=("$2"); shift 2 ;;
    *) die "unknown arg: $1" ;;
  esac
done

ops_require_single_line "--dest" "$DEST"
ops_require_single_line "--release-id" "$RELEASE_ID"
ops_require_single_line "--state-file" "$STATE_FILE"

PROFILE_SRC="$REPO_ROOT/sandbox/pi-sandbox.sb"
PREAMBLE_SRC="$REPO_ROOT/sandbox/pi-sandbox-preamble.zsh"

for f in "$PROFILE_SRC" "$PREAMBLE_SRC"; do
  [ -f "$f" ] || die "missing source: $f"
done

# --- Launcher set: the first-party protected shim, plus opted-in extras. ---
# Parallel arrays (bash 3.2 has no associative arrays): NAMES[i] installs from SRCS[i].
LAUNCHER_NAMES=(pi)
LAUNCHER_SRCS=("$REPO_ROOT/launchers/pi")
[ -f "$REPO_ROOT/launchers/pi" ] || die "missing launcher source: launchers/pi"

# `pi` is reserved: an extra directory supplying its own `pi` would replace the
# protected shim with an unvetted file — the exact bypass this repo exists to stop.
# Duplicate basenames across extra dirs are refused rather than silently last-wins.
for dir in ${EXTRA_DIRS+"${EXTRA_DIRS[@]}"}; do
  [ -d "$dir" ] || die "--extra-launchers: not a directory: $dir"
  for src in "$dir"/*; do
    [ -e "$src" ] || continue            # empty dir: the glob stays literal
    name="$(basename "$src")"
    case "$name" in
      .*|*.md|*.bak.*|*.tmp.*) continue ;;   # docs/backups/temp are not launchers
    esac
    [ -L "$src" ] && die "--extra-launchers: refusing symlink (install real files only): $src"
    [ -f "$src" ] || die "--extra-launchers: not a regular file: $src"
    [ "$name" = "pi" ] && die "--extra-launchers: 'pi' is reserved for the protected shim: $src"
    # The provenance stamp records names as a comma-separated line, so a name
    # containing a comma/newline (or shell-hostile characters) would be re-parsed
    # as two launchers and make `status` verify the wrong paths. Restrict to a
    # conservative command-name charset instead of quoting around the problem.
    case "$name" in
      *[!A-Za-z0-9._-]*) die "--extra-launchers: launcher name must match [A-Za-z0-9._-]: $src" ;;
    esac
    for existing in "${LAUNCHER_NAMES[@]}"; do
      [ "$existing" = "$name" ] && die "--extra-launchers: duplicate launcher name '$name': $src"
    done
    LAUNCHER_NAMES+=("$name")
    LAUNCHER_SRCS+=("$src")
  done
done

# --- 0. sandbox-exec present? ---
command -v sandbox-exec >/dev/null 2>&1 || die "sandbox-exec not found; this profile needs macOS Seatbelt"

# --- 0b. Lint every launcher SOURCE before any mutation (fail-closed) ---
# A wrapper that execs the real Pi binary instead of the sibling shim runs
# UNSANDBOXED. Validating only after install would leave a bad file on PATH
# during a mid-install failure, so the whole set is gated here first.
say "[deploy-launchers] linting ${#LAUNCHER_NAMES[@]} launcher source(s) before install"
node "$REPO_ROOT/scripts/check-launchers.mjs" --sources "${LAUNCHER_SRCS[@]}" >/dev/null \
  || die "launcher source lint failed; nothing installed"

# --- 1. validate the profile compiles, applies, and enforces its boundary
# BEFORE installing. The live probes live in scripts/test-sandbox-profile.sh so
# there is ONE source of truth shared with `npm run test:sandbox-profile`.
# Real installs always force STRICT: a deploy must not proceed on an
# unvalidated profile. Dry-run allows non-strict skip so nested sandboxes /
# Linux hosts can still exercise provenance + install planning without mutation.
if [ "$DRY_RUN" -eq 1 ]; then
  say "[deploy-launchers] dry-run: validating SBPL profile (non-strict; skip if unusable)"
  if ! bash "$REPO_ROOT/scripts/test-sandbox-profile.sh" "$PROFILE_SRC"; then
    die "profile validation failed; dry-run abort"
  fi
else
  say "[deploy-launchers] validating SBPL profile via scripts/test-sandbox-profile.sh"
  PI_SANDBOX_PROFILE_STRICT=1 bash "$REPO_ROOT/scripts/test-sandbox-profile.sh" "$PROFILE_SRC" \
    || die "profile validation failed; not installing"
fi

if [ -z "$RELEASE_ID" ]; then
  RELEASE_ID="$(ops_make_release_id "$REPO_ROOT")"
fi
set -- $(ops_git_meta "$REPO_ROOT")
GIT_SHA="$1"
GIT_STATE="$2"
STAMP="$(date '+%Y%m%d%H%M%S')"

# Read the outgoing stamp's name history BEFORE write_provenance overwrites it.
# Union of what it had ever seen plus what it currently claims, so a name retired
# two deploys ago is still remembered. Empty on a first-ever deploy.
DEST_STAMP="$DEST/.pi-sandbox-launchers-version"
PRIOR_NAMES_SEEN=""
if [ -f "$DEST_STAMP" ]; then
  PRIOR_NAMES_SEEN="$(
    { ops_stamp_get "$DEST_STAMP" launcher_names_seen 2>/dev/null || true
      ops_stamp_get "$DEST_STAMP" launcher_names 2>/dev/null || true
    } | tr ',' '\n' | sed '/^$/d' | sort -u | paste -sd, -
  )"
fi

write_provenance() {
  local out="$1"
  {
    echo "deployed_at=$(date '+%Y-%m-%dT%H:%M:%S%z')"
    echo "release_id=$RELEASE_ID"
    echo "component=launchers"
    echo "git_sha=$GIT_SHA"
    echo "git_state=$GIT_STATE"
    echo "hash_algo=sha256"
    echo "hash_profile=$(ops_hash_file "$PROFILE_SRC")"
    echo "hash_preamble=$(ops_hash_file "$PREAMBLE_SRC")"
    # Record the installed set (names + hashes) so `status` can detect a stale
    # extra launcher left behind on PATH after it stops being deployed.
    echo "launcher_names=$(IFS=,; echo "${LAUNCHER_NAMES[*]}")"
    # Carry forward every name this dest has EVER had deployed. status uses this
    # to spot a wrapper that was dropped from the deploy set but is still
    # callable on PATH. Without it, status could only compare against the current
    # set and would have to treat every unknown executable in the (shared) dest
    # as a suspect — which produced ten false "stale?" reports for unrelated
    # tools sharing that directory and taught the reader to ignore drift.
    # PRIOR_NAMES_SEEN is captured BEFORE this function runs, because the file it
    # reads from is the same file this function overwrites.
    echo "launcher_names_seen=$(
      { printf '%s\n' "${LAUNCHER_NAMES[@]}"
        printf '%s\n' "${PRIOR_NAMES_SEEN//,/$'\n'}"
      } | sed '/^$/d' | sort -u | paste -sd, -
    )"
    prov_i=0
    while [ "$prov_i" -lt "${#LAUNCHER_NAMES[@]}" ]; do
      echo "hash_launcher_${LAUNCHER_NAMES[$prov_i]}=$(ops_hash_file "${LAUNCHER_SRCS[$prov_i]}")"
      prov_i=$((prov_i + 1))
    done
    echo "analyzer_provenance=local-file-integrity-only; upstream not attested"
  } > "$out"
}

if [ "$DRY_RUN" -eq 1 ]; then
  say "[deploy-launchers] dry-run OK; would install to $DEST"
  PROV_TMP="$(mktemp "${TMPDIR:-/tmp}/pi-launchers-prov-XXXXXX")"
  write_provenance "$PROV_TMP"
  say "[deploy-launchers] dry-run provenance:"
  sed 's/^/         /' "$PROV_TMP"
  if [ -n "$STATE_FILE" ]; then
    {
      echo "component=launchers"
      echo "dry_run=1"
      echo "dest=$DEST"
      echo "release_id=$RELEASE_ID"
      echo "backup_root="
    } > "$STATE_FILE"
  fi
  rm -f "$PROV_TMP"
  exit 0
fi

# --- 2. back up + install ---
ROLLBACK_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/pi-launchers-rollback-XXXXXX")"
ROLLBACK_PATHS=()
ROLLBACK_BACKUPS=()
ROLLBACK_EXISTED=()
MUTATION_STARTED=0
COMMITTED=0

prepare_rollback() {
  local dst="$1" idx backup existed
  idx="${#ROLLBACK_PATHS[@]}"
  backup="$ROLLBACK_ROOT/$idx"
  if [ -e "$dst" ]; then
    cp -p "$dst" "$backup"
    existed="1"
  else
    existed="0"
  fi
  ROLLBACK_PATHS+=("$dst")
  ROLLBACK_BACKUPS+=("$backup")
  ROLLBACK_EXISTED+=("$existed")
}

finish_or_rollback() {
  rollback_status=$?
  local i dst backup existed
  if [ "$rollback_status" -ne 0 ] && [ "$MUTATION_STARTED" -eq 1 ] && [ "$COMMITTED" -eq 0 ]; then
    ops_warn "launcher install failed; restoring all touched destinations"
    i=$((${#ROLLBACK_PATHS[@]} - 1))
    while [ "$i" -ge 0 ]; do
      dst="${ROLLBACK_PATHS[$i]}"
      backup="${ROLLBACK_BACKUPS[$i]}"
      existed="${ROLLBACK_EXISTED[$i]}"
      if [ "$existed" = "1" ]; then
        cp -p "$backup" "$dst" \
          || ops_warn "rollback failed for $dst; restore manually from $backup"
      else
        rm -f "$dst" \
          || ops_warn "rollback could not remove newly installed $dst"
      fi
      i=$((i - 1))
    done
  fi
  rm -rf "$ROLLBACK_ROOT" 2>/dev/null || true
  exit "$rollback_status"
}
trap finish_or_rollback EXIT

mkdir -p "$DEST"
BACKUP_LIST=""
install_file() {
  local src="$1" name="$2" mode="$3"
  local dst="$DEST/$name"
  local tmp="$DEST/.$name.tmp.$$"
  local bak=""
  prepare_rollback "$dst"
  MUTATION_STARTED=1
  if [ -e "$dst" ] && ! cmp -s "$src" "$dst"; then
    bak="$dst.bak.$STAMP.$$"
    cp -p "$dst" "$bak"
    say "[deploy-launchers] backed up existing $name -> $(basename "$bak")"
    if [ -z "$BACKUP_LIST" ]; then
      BACKUP_LIST="$bak"
    else
      BACKUP_LIST="$BACKUP_LIST|$bak"
    fi
  fi
  cp "$src" "$tmp"
  chmod "$mode" "$tmp"
  mv "$tmp" "$dst"
  ops_require_same_hash "installed $name" "$src" "$dst"
  say "[deploy-launchers] installed $name"
}

install_file "$PROFILE_SRC"  "pi-sandbox.sb"            644
install_file "$PREAMBLE_SRC" "pi-sandbox-preamble.zsh"  644
i=0
while [ "$i" -lt "${#LAUNCHER_NAMES[@]}" ]; do
  install_file "${LAUNCHER_SRCS[$i]}" "${LAUNCHER_NAMES[$i]}" 755
  i=$((i + 1))
done

PI_SANDBOX_DEPLOYED_ROOT="$DEST" PI_SANDBOX_CHECK_DEPLOYED=1 \
  node "$REPO_ROOT/scripts/check-launchers.mjs" >/dev/null \
  || die "installed launcher guardrail check failed"

# --- 3. provenance stamp ---
prepare_rollback "$DEST/.pi-sandbox-launchers-version"
MUTATION_STARTED=1
write_provenance "$DEST/.pi-sandbox-launchers-version"

if [ -n "$STATE_FILE" ]; then
  {
    echo "component=launchers"
    echo "dry_run=0"
    echo "dest=$DEST"
    echo "release_id=$RELEASE_ID"
    echo "backup_list=$BACKUP_LIST"
  } > "$STATE_FILE"
fi

COMMITTED=1
say ""
say "[deploy-launchers] DONE. Protected pi shim and launchers installed."
say "[deploy-launchers] release_id=$RELEASE_ID"
say "[deploy-launchers] Ensure $DEST is earlier on PATH than the real Pi binary."
say "[deploy-launchers] installed launchers: ${LAUNCHER_NAMES[*]}"
say "[deploy-launchers] Run 'pi' from inside a project; call the real Pi binary directly to bypass."
