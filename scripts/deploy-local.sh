#!/usr/bin/env bash
#
# deploy-local.sh — build a repo-independent, self-contained copy of pi-sandbox-guard
# into Pi's auto-discovery dir (~/.pi/agent/extensions/pi-sandbox-guard/).
#
# After deploy, Pi loads the guard from the deployed COPY — the git repo can be
# moved or deleted and Pi stays guarded. The repo remains the source of truth;
# the deploy dir is a built artifact. Redeploy = re-run this script.
#
# Design (packaging review):
#   - Preserve the repo's src/ + vendor/ layout so guard-core.mjs's relative
#     `../vendor/...` path keeps resolving. (Flattening it would break the path.)
#   - index.ts is a one-line shim re-exporting ./src/index.mjs — Pi auto-discovers
#     .ts only, but its jiti loader imports the sibling .mjs fine. No TS port (drift trap).
#   - HARD-CHECK runtime deps (bash/jq/awk) on the guard's sanitized PATH;
#     refuse to deploy if missing (a "deployed but blocks all bash" install is a bad
#     outcome). Override with --force-degraded for explicit testing only.
#   - Atomic: build in a temp dir, verify, then swap into place. Never leave a
#     half-written extension dir that Pi might load.
#   - Stamp .deployed-version with release_id + git sha + dirty + component hashes.
#   - Vendor hash is local-file integrity only; no upstream provenance is claimed.
#
# Usage:
#   scripts/deploy-local.sh [--force-degraded] [--dest <dir>]
#                           [--dry-run] [--skip-tests] [--release-id <id>]
#                           [--state-file <path>]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib-ops.sh
. "$REPO_ROOT/scripts/lib-ops.sh"

DEST_DEFAULT="$(ops_default_guard_dest)"
DEST="$DEST_DEFAULT"
BACKUP_ROOT="$HOME/.pi/agent/extension-backups"
FORCE_DEGRADED=0
DRY_RUN=0
SKIP_TESTS=0
RELEASE_ID="${RELEASE_ID:-}"
STATE_FILE=""

# Sanitized PATH must match guard-core.mjs's SAFE_PATH (helpers resolve here).
SAFE_PATH="/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin"
# Must match guard-core.mjs's REQUIRED_HELPERS. python3 is NOT here: path
# canonicalization uses the guard's own pinned node (GUARD_NODE), so requiring a
# possibly-absent Command Line Tools python3 would abort deploy for nothing.
REQUIRED_HELPERS=(bash jq awk)

say() { ops_say "$@"; }
die() { ops_die "$@"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --force-degraded) FORCE_DEGRADED=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    --skip-tests) SKIP_TESTS=1; shift ;;
    --dest)
      [ $# -ge 2 ] || die "--dest requires a directory"
      DEST="$2"; shift 2 ;;
    --release-id)
      [ $# -ge 2 ] || die "--release-id requires a value"
      RELEASE_ID="$2"; shift 2 ;;
    --state-file)
      [ $# -ge 2 ] || die "--state-file requires a path"
      STATE_FILE="$2"; shift 2 ;;
    *) die "Unknown arg: $1" ;;
  esac
done

ops_require_single_line "--dest" "$DEST"
ops_require_single_line "--release-id" "$RELEASE_ID"
ops_require_single_line "--state-file" "$STATE_FILE"

[ "$(basename "$DEST")" = "pi-sandbox-guard" ] \
  || die "--dest must point to a directory named pi-sandbox-guard (got: $DEST)"

if [ "$DEST" != "$DEST_DEFAULT" ]; then
  BACKUP_ROOT="$(dirname "$DEST")/.pi-sandbox-guard-backups"
fi

# --- 0. Sanity: required source files exist ---
SRC_CORE="$REPO_ROOT/src/guard-core.mjs"
SRC_ADAPTER="$REPO_ROOT/src/index.mjs"
SRC_VENDOR="$REPO_ROOT/vendor/validate-bash-command.sh"
for f in "$SRC_CORE" "$SRC_ADAPTER" "$SRC_VENDOR"; do
  [ -f "$f" ] || die "missing source file: $f"
done

# --- 1. Hard-check runtime deps on the sanitized PATH (refuse by default) ---
say "[deploy] checking runtime helpers on sanitized PATH ($SAFE_PATH)"
missing=()
for h in "${REQUIRED_HELPERS[@]}"; do
  PATH="$SAFE_PATH" command -v "$h" >/dev/null 2>&1 || missing+=("$h")
done
if [ "${#missing[@]}" -gt 0 ]; then
  if [ "$FORCE_DEGRADED" -eq 1 ]; then
    say "[deploy] WARNING: missing helpers (${missing[*]}); --force-degraded set, continuing."
    say "[deploy] NOTE: the guard will BLOCK ALL bash at runtime until these are present."
  else
    die "missing required helpers on sanitized PATH: ${missing[*]}
   The guard would block ALL bash commands at runtime. Install them, or pass
   --force-degraded to deploy anyway (explicit testing only)."
  fi
fi

# --- 2. Source gate: run the repo test suite before deploying ---
if [ "$SKIP_TESTS" -eq 1 ]; then
  say "[deploy] skipping repo test suite (--skip-tests)"
elif [ "$DRY_RUN" -eq 1 ]; then
  # Dry-run still needs a cheap syntax/static gate, not a full suite install path.
  # Full suite remains the real deploy gate; dry-run verifies artifact build only.
  say "[deploy] dry-run: skipping full test suite (artifact preflight still runs)"
else
  say "[deploy] running repo test suite (source gate)"
  ( cd "$REPO_ROOT" && npm test >/dev/null ) \
    || die "repo tests failed; refusing to deploy"
  say "[deploy] source tests passed"
fi

# --- 3. Build the artifact in a temp dir (atomic; swap in only after verify) ---
# A live install stages beside DEST so the final mv is a same-filesystem rename
# on Linux as well as macOS. Dry-runs retain an ordinary temp stage and do not
# create directories under the requested destination.
DEST_PARENT="$(dirname "$DEST")"
if [ "$DRY_RUN" -eq 1 ]; then
  STAGE="$(mktemp -d "${TMPDIR:-/tmp}/pi-sandbox-guard-deploy-XXXXXX")"
else
  mkdir -p "$DEST_PARENT"
  STAGE="$(mktemp -d "$DEST_PARENT/.pi-sandbox-guard-stage-XXXXXX")"
fi
BACKUP=""
MUTATION_STARTED=0
COMMITTED=0
STAGE_INSTALLED=0
rollback() {
  status=$?
  if [ "$status" -ne 0 ] && [ "$MUTATION_STARTED" -eq 1 ] && [ "$COMMITTED" -eq 0 ]; then
    if [ "$STAGE_INSTALLED" -eq 1 ] && [ -e "$DEST" ]; then
      rm -rf "$DEST" 2>/dev/null || true
    fi
    if [ -n "$BACKUP" ] && [ -e "$BACKUP" ] && [ ! -e "$DEST" ]; then
      mv "$BACKUP" "$DEST" 2>/dev/null || true
    fi
  fi
  rm -rf "$STAGE" 2>/dev/null || true
  exit "$status"
}
trap rollback EXIT
mkdir -p "$STAGE/src" "$STAGE/vendor"
cp "$SRC_CORE" "$STAGE/src/guard-core.mjs"
cp "$SRC_ADAPTER" "$STAGE/src/index.mjs"
cp "$SRC_VENDOR" "$STAGE/vendor/validate-bash-command.sh"
chmod +x "$STAGE/vendor/validate-bash-command.sh"

# Fail loudly if the staged copy drifted from source (copy/FS glitch).
ops_require_same_hash "guard-core.mjs" "$SRC_CORE" "$STAGE/src/guard-core.mjs"
ops_require_same_hash "index.mjs" "$SRC_ADAPTER" "$STAGE/src/index.mjs"
ops_require_same_hash "vendor/validate-bash-command.sh" "$SRC_VENDOR" "$STAGE/vendor/validate-bash-command.sh"

# One-line .ts shim: Pi auto-discovers .ts; its loader imports the sibling .mjs.
cat > "$STAGE/index.ts" <<'TS'
// pi-sandbox-guard — deployed extension entry (auto-discovered by Pi).
// Pi globs *.ts for discovery; its jiti loader imports the .mjs adapter below.
// This is a self-contained COPY: it does not reference the source git repo.
export { default } from "./src/index.mjs";
TS

# Provenance stamp: release_id + git + local component hashes (not upstream claims).
if [ -z "$RELEASE_ID" ]; then
  RELEASE_ID="$(ops_make_release_id "$REPO_ROOT")"
fi
set -- $(ops_git_meta "$REPO_ROOT")
GIT_SHA="$1"
GIT_DIRTY="$2"
PI_VERSION="$(pi --version 2>/dev/null | head -1 || echo 'unknown')"
{
  echo "deployed_at=$(date '+%Y-%m-%dT%H:%M:%S%z')"
  echo "release_id=$RELEASE_ID"
  echo "component=guard"
  echo "git_sha=$GIT_SHA"
  echo "git_state=$GIT_DIRTY"
  echo "pi_version=$PI_VERSION"
  echo "repo_root=$REPO_ROOT"
  echo "hash_index_mjs=$(ops_hash_file "$STAGE/src/index.mjs")"
  echo "hash_guard_core_mjs=$(ops_hash_file "$STAGE/src/guard-core.mjs")"
  echo "hash_vendor_sh=$(ops_hash_file "$STAGE/vendor/validate-bash-command.sh")"
  echo "hash_algo=sha256"
  echo "vendor_provenance=local-file-integrity-only; upstream not attested"
} > "$STAGE/.deployed-version"

# --- 4. Verify the STAGED copy actually works (preflight on the artifact path) ---
say "[deploy] verifying staged artifact (preflight on deployed copy)"
PREFLIGHT_OUT="$(STAGE_PATH="$STAGE" node -e "
  import { pathToFileURL } from 'node:url';
  import(pathToFileURL(process.env.STAGE_PATH + '/src/guard-core.mjs').href).then(m=>m.preflight()).then(r=>{
    console.log(JSON.stringify(r));
    process.exit(r.ok ? 0 : 3);
  }).catch(e=>{ console.error(e); process.exit(4); });
")" || {
  if [ "$FORCE_DEGRADED" -eq 1 ]; then
    say "[deploy] staged preflight not ok ($PREFLIGHT_OUT); --force-degraded, continuing."
  else
    die "staged artifact preflight failed: $PREFLIGHT_OUT"
  fi
}
say "[deploy] staged preflight: $PREFLIGHT_OUT"

# Functional check: staged copy blocks a catastrophic command, allows a benign one.
say "[deploy] verifying staged copy block/allow behavior"
STAGE_PATH="$STAGE" node -e "
  import { pathToFileURL } from 'node:url';
  import(pathToFileURL(process.env.STAGE_PATH + '/src/guard-core.mjs').href).then(async m=>{
    const tmp=process.env.TMPDIR||'/tmp';
    const blk=await m.analyzeCommand('rm -rf /',{cwd:tmp,timeoutMs:6000});
    const alw=await m.analyzeCommand('ls -la',{cwd:tmp,timeoutMs:6000});
    if(blk.decision!=='block') { console.error('FAIL: rm -rf / not blocked:',blk.decision); process.exit(5); }
    if(alw.decision!=='allow') { console.error('FAIL: ls not allowed:',alw.decision); process.exit(6); }
    console.log('staged behavior OK: rm -rf / =>',blk.decision,'| ls -la =>',alw.decision);
  }).catch(e=>{ console.error(e); process.exit(7); });
" || die "staged behavior check failed"

if [ "$DRY_RUN" -eq 1 ]; then
  say "[deploy] dry-run OK; would install to $DEST"
  say "[deploy] dry-run provenance:"
  sed 's/^/         /' "$STAGE/.deployed-version"
  if [ -n "$STATE_FILE" ]; then
    {
      echo "component=guard"
      echo "dry_run=1"
      echo "dest=$DEST"
      echo "release_id=$RELEASE_ID"
      echo "backup="
    } > "$STATE_FILE"
  fi
  # Leave STAGE cleanup to trap with status 0.
  exit 0
fi

# --- 5. Swap into place atomically ---
say "[deploy] installing to $DEST"
MUTATION_STARTED=1
if [ -e "$DEST" ]; then
  mkdir -p "$BACKUP_ROOT"
  BACKUP="$BACKUP_ROOT/pi-sandbox-guard.bak.$(date '+%Y%m%d%H%M%S').$$"
  mv "$DEST" "$BACKUP"
  say "[deploy] previous install moved to $BACKUP"
fi
mv "$STAGE" "$DEST"
STAGE_INSTALLED=1
chmod +x "$DEST/vendor/validate-bash-command.sh" 2>/dev/null || true

# Post-install integrity: installed hashes must still match source.
ops_require_same_hash "installed guard-core.mjs" "$SRC_CORE" "$DEST/src/guard-core.mjs"
ops_require_same_hash "installed index.mjs" "$SRC_ADAPTER" "$DEST/src/index.mjs"
ops_require_same_hash "installed vendor" "$SRC_VENDOR" "$DEST/vendor/validate-bash-command.sh"

if [ -n "$STATE_FILE" ]; then
  {
    echo "component=guard"
    echo "dry_run=0"
    echo "dest=$DEST"
    echo "release_id=$RELEASE_ID"
    echo "backup=$BACKUP"
  } > "$STATE_FILE"
fi
COMMITTED=1
trap - EXIT

say ""
say "[deploy] DONE. pi-sandbox-guard deployed to:"
say "         $DEST"
say "[deploy] release_id=$RELEASE_ID"
say "[deploy] provenance:"
sed 's/^/         /' "$DEST/.deployed-version"
say ""
say "[deploy] Pi will auto-discover it on next launch."
say "[deploy] Verify load with:  pi --list-models  (look for no load errors)"
