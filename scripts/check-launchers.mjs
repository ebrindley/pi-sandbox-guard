#!/usr/bin/env node
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const home = process.env.HOME || homedir();

// `--sources <path>...` lints arbitrary launcher files (used by deploy-launchers.sh
// to gate BEFORE installing anything). Without it, the repo's own launchers/ dir is
// linted: the protected `pi` shim plus any example wrappers shipped here.
const sourcesFlagIndex = process.argv.indexOf('--sources');
const explicitSources =
  sourcesFlagIndex === -1 ? [] : process.argv.slice(sourcesFlagIndex + 1).filter((a) => !a.startsWith('--'));

const sourcePiPath = join(repoRoot, 'launchers', 'pi');
const sourcePreamblePath = join(repoRoot, 'sandbox', 'pi-sandbox-preamble.zsh');
const sourceProfilePath = join(repoRoot, 'sandbox', 'pi-sandbox.sb');
const checkDeployed =
  process.argv.includes('--deployed') || process.env.PI_SANDBOX_CHECK_DEPLOYED === '1';

const deployedRoot = process.env.PI_SANDBOX_DEPLOYED_ROOT || join(home, '.local', 'bin');
const deployedPiPath = join(deployedRoot, 'pi');
const deployedOmpPath = join(deployedRoot, 'omp');
const deployedPreamblePath = join(deployedRoot, 'pi-sandbox-preamble.zsh');
const deployedProfilePath = join(deployedRoot, 'pi-sandbox.sb');

// Prefixes accepted for pre-sandbox helper resolution. `/tmp`, `$HOME/bin`, and
// friends are deliberately absent: an absolute path is NOT the security property.
//
// CALIBRATION — do not restate this list as a root-ownership guarantee. On a standard
// Apple-Silicon host, /opt/homebrew/bin is `<install-user>:admin drwxrwxr-x`, i.e.
// owned and writable by the same unprivileged user the sandbox contains; the same is
// true of /opt/homebrew/lib/node_modules and /opt/homebrew/Cellar. Only the /usr and
// /bin entries are genuinely root-owned (and SIP-protected). So this list is a
// path-shape convention that keeps ambient, attacker-settable inputs to a small fixed
// surface — it is not proof a helper cannot be replaced. The real controls are
// Seatbelt write containment and, for the Pi executable specifically, an
// operator-recorded binding (scripts/bind-executable.sh).
const TRUSTED_BIN_PREFIXES = ['/usr/bin', '/bin', '/usr/sbin', '/sbin', '/usr/local/bin', '/opt/homebrew/bin'];

// Homebrew keeps versioned formulae under <prefix>/opt/<formula@version>/bin, which is
// not a fixed string we can enumerate. Same calibration as above: accepted by shape,
// not because it is root-owned.
const TRUSTED_BIN_PATTERNS = [/^\/opt\/homebrew\/opt\/[^/]+\/bin$/, /^\/usr\/local\/opt\/[^/]+\/bin$/];

// Pre-sandbox helpers must be in a trusted prefix AND non-trampolining. Interpreters,
// shells, env/xargs, task runners, and similar binaries can execute an arbitrary
// second command even when their own path is trusted.
const SAFE_PREFLIGHT_HELPERS = new Set([
  'curl',
  'wget',
  'jq',
  'grep',
  'sed',
  'lsof',
  'stat',
  'shasum',
  'test',
  'true',
  'false',
]);

function isTrustedBinDir(dir) {
  return TRUSTED_BIN_PREFIXES.includes(dir) || TRUSTED_BIN_PATTERNS.some((re) => re.test(dir));
}

function isTrustedBinPath(path) {
  return path.startsWith('/') && isTrustedBinDir(dirname(path));
}

function isSafePreflightHelper(path) {
  return isTrustedBinPath(path) && SAFE_PREFLIGHT_HELPERS.has(basename(path));
}

function read(path) {
  try {
    return readFileSync(path, 'utf8');
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    fail(`could not read ${path}: ${reason}`);
    return '';
  }
}

function fail(message) {
  console.error(`Error: ${message}`);
  process.exitCode = 1;
}

// Example wrappers shipped in launchers/ (everything except the `pi` shim itself
// and documentation). Kept as discovery so adding an example needs no lint edit.
function repoExampleLaunchers() {
  const dir = join(repoRoot, 'launchers');
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((name) => name !== 'pi' && !name.startsWith('.') && !name.endsWith('.md'))
    .map((name) => join(dir, name));
}

// Launcher names recorded by the last deploy, so --deployed re-checks extras that
// came from --extra-launchers. Falls back to `pi` when no stamp is present.
function deployedLauncherNames() {
  const stamp = join(deployedRoot, '.pi-sandbox-launchers-version');
  if (!existsSync(stamp)) return ['pi'];
  const line = read(stamp)
    .split('\n')
    .find((l) => l.startsWith('launcher_names='));
  if (!line) return ['pi'];
  return line.slice('launcher_names='.length).split(',').filter(Boolean);
}

function stripFullLineComments(content, marker) {
  return content
    .split('\n')
    .filter((line) => !line.trimStart().startsWith(marker))
    .join('\n');
}

function stripTrailingShellComment(line) {
  let quote = '';
  let escaped = false;
  for (let i = 0; i < line.length; i += 1) {
    const char = line[i];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (char === '\\' && quote !== "'") {
      escaped = true;
      continue;
    }
    if (quote) {
      if (char === quote) quote = '';
      continue;
    }
    if (char === '"' || char === "'") {
      quote = char;
    } else if (char === '#' && (i === 0 || /\s/.test(line[i - 1]))) {
      return line.slice(0, i).trimEnd();
    }
  }
  return line;
}

function normalizeWhitespace(content) {
  return content.replace(/\s+/g, ' ').trim();
}

// A custom wrapper's security contract. Applies to first-party launchers in this
// repo AND to anything opted in via --extra-launchers: a wrapper that execs the
// real Pi binary directly, or reaches a helper through ambient PATH, runs outside
// the Seatbelt boundary.
function checkLauncher(path, { required }) {
  if (!existsSync(path)) {
    if (required) {
      fail(`missing expected launcher: ${path}`);
    }
    return;
  }

  const raw = read(path);
  const content = stripFullLineComments(raw, '#');
  if (!raw.startsWith('#!/bin/zsh -f')) {
    fail(`${path} does not use the trusted /bin/zsh -f interpreter`);
  }
  // This is intentionally a small fail-closed wrapper language, not a partial
  // shell parser. Arbitrary zsh has too many command-position forms to prove safe
  // with boundary regexes. Each non-comment statement must match one supported
  // form below; unsupported control flow/evaluation is rejected before install.
  const lines = content
    .split('\n')
    .map((line) => stripTrailingShellComment(line).trim())
    .filter(Boolean);
  for (const line of lines) {
    if (/`|\$\(|<\(|>\(/.test(line)) {
      fail(`${path} uses command/process substitution outside the supported wrapper contract: ${line}`);
    }
  }

  // Any PATH assignment must list only trusted prefixes (see TRUSTED_BIN_PREFIXES —
  // a path-shape convention, not a root-ownership claim). An absolute
  // but agent-writable component (PATH="/tmp:/usr/bin") would let /tmp/curl run
  // before Seatbelt applies, so absoluteness alone is not sufficient. zsh also
  // exposes PATH as the `path` array, so both spellings are checked.
  // An EMPTY component is NOT dropped: zsh resolves `PATH=/usr/bin::/bin`,
  // a leading `:`, or a trailing `:` against the CURRENT DIRECTORY, so an empty
  // field is exactly the agent-writable component this check exists to reject.
  // Verified: `PATH=":/usr/bin" zsh -f -c curl` runs ./curl from the cwd.
  //
  // The value is `*` not `+`: a WHOLLY empty assignment (`PATH=`, `PATH=""`,
  // `PATH=''`) must be inspected too. Verified: `PATH="" zsh -f -c modelcheck`
  // runs ./modelcheck. A `+` quantifier skipped the line entirely, so the most
  // permissive spelling was the one that escaped the check.
  const declarationPrefix = String.raw`(?:(?:(?:typeset|local)\s+(?:-\w+\s+)*)|(?:readonly|export)\s+)?`;
  const pathComponents = [];
  const pathAssignmentPattern = new RegExp(
    String.raw`^\s*${declarationPrefix}PATH=(["']?)([^"'\n]*)\1`,
    'gm',
  );
  for (const match of content.matchAll(pathAssignmentPattern)) {
    pathComponents.push(...match[2].split(':'));
  }
  // Whitespace-split of the zsh `path=(...)` array form: empties here are just
  // padding inside the parens, not path entries, so they ARE dropped.
  const pathArrayPattern = new RegExp(
    String.raw`^\s*${declarationPrefix}path=\(([^)]*)\)`,
    'gm',
  );
  for (const match of content.matchAll(pathArrayPattern)) {
    pathComponents.push(...match[1].split(/\s+/).filter(Boolean));
  }
  for (const component of pathComponents) {
    const bare = component.replace(/^["']|["']$/g, '');
    if (bare === '') {
      fail(`${path} has an empty PATH component, which zsh resolves against the current directory`);
    } else if (bare.includes('$')) {
      fail(`${path} interpolates a variable into PATH (${bare}); pin trusted absolute prefixes`);
    } else if (!isTrustedBinDir(bare)) {
      fail(`${path} sets PATH component '${bare}', which is not a trusted system prefix`);
    }
  }

  const assignmentPattern = new RegExp(
    '^' +
      declarationPrefix +
      "([A-Za-z_][A-Za-z0-9_]*)=(\"([^\"]*)\"|'([^']*)'|[A-Za-z0-9_./:@%+,${}-]+)$",
  );
  const trustedHelperVars = new Set();
  let shimAssignments = 0;
  for (const line of lines) {
    const match = assignmentPattern.exec(line);
    if (!match) continue;
    const name = match[1];
    const value = match[3] ?? match[4] ?? match[2];
    if (name === 'PI_SHIM') {
      shimAssignments += 1;
      if (match[2] !== '"${0:A:h}/pi"') {
        fail(`${path} assigns PI_SHIM=${match[2]}; only the sibling form "\${0:A:h}/pi" is allowed`);
      }
    }
    if (name.endsWith('_BIN')) {
      if (!isSafePreflightHelper(value)) {
        fail(
          `${path} assigns ${name}='${value}'; pre-sandbox helpers must be trusted and non-trampolining`,
        );
      }
      trustedHelperVars.add(name);
    }
  }

  const safeArg = String.raw`(?:"[^"]*"|'[^']*'|[^\s;&|(){}<>` + '`' + String.raw`]+)`;
  const safeArgs = String.raw`(?:\s+${safeArg})*`;
  const helperVariableCall = new RegExp(
    String.raw`^(if\s+!\s+)?(?:"\$([A-Z][A-Z0-9_]*_BIN)"|'\$([A-Z][A-Z0-9_]*_BIN)'|\$([A-Z][A-Z0-9_]*_BIN))(${safeArgs})(\s+>/dev/null(?:\s+2>&1)?|\s+2>/dev/null)?(; then)?$`,
  );
  const absoluteHelperCall = new RegExp(
    String.raw`^(if\s+!\s+)?(?:"(/[^"]+)"|'(/[^']+)'|(/[^\s;&|(){}<>` + '`' + String.raw`]+))(${safeArgs})(\s+>/dev/null(?:\s+2>&1)?|\s+2>/dev/null)?(; then)?$`,
  );
  const protectedExec = new RegExp(String.raw`^exec\s+"\$PI_SHIM"${safeArgs}$`);
  let protectedExecs = 0;

  for (const line of lines) {
    if (
      line === 'set -euo pipefail' ||
      line === 'then' ||
      line === 'else' ||
      line === 'fi' ||
      /^exit\s+[0-9]+$/.test(line) ||
      /^print(?:\s+-u2)?\s+(?:"[^"]*"|'[^']*')$/.test(line) ||
      /^if\s+\[\s+[^;&|<>()\[\]]*\s+\]; then$/.test(line) ||
      /^(?:(?:typeset\s+-\w+\s+)?path=\([^)]*\))$/.test(line) ||
      assignmentPattern.test(line)
    ) {
      continue;
    }
    if (protectedExec.test(line)) {
      protectedExecs += 1;
      continue;
    }
    const variableCall = helperVariableCall.exec(line);
    if (variableCall) {
      const name = variableCall[2] || variableCall[3] || variableCall[4];
      if (!trustedHelperVars.has(name)) {
        fail(`${path} invokes $${name} without a trusted literal ${name}=... assignment`);
      }
      if (Boolean(variableCall[1]) !== line.endsWith('; then')) {
        fail(`${path} has a malformed helper conditional: ${line}`);
      }
      continue;
    }
    const absoluteCall = absoluteHelperCall.exec(line);
    if (absoluteCall) {
      const target = absoluteCall[2] || absoluteCall[3] || absoluteCall[4];
      if (basename(target) === 'pi') {
        fail(`${path} invokes Pi directly instead of the sibling protected shim: ${line}`);
        continue;
      }
      if (!isSafePreflightHelper(target)) {
        fail(`${path} invokes unsafe absolute helper '${target}' before the protected shim`);
      }
      if (Boolean(absoluteCall[1]) !== line.endsWith('; then')) {
        fail(`${path} has a malformed helper conditional: ${line}`);
      }
      continue;
    }
    fail(`${path} contains an unsupported pre-sandbox statement: ${line}`);
  }
  if (shimAssignments === 0 || protectedExecs === 0) {
    fail(`${path} does not hand off to the sibling protected pi shim via PI_SHIM="\${0:A:h}/pi"`);
  }
}

function checkPiShim(path, { required }) {
  if (!existsSync(path)) {
    if (required) {
      fail(`missing protected pi shim: ${path}`);
    }
    return;
  }

  const raw = read(path);
  const content = stripFullLineComments(raw, '#');
  if (!raw.startsWith('#!/bin/zsh -f')) {
    fail(`${path} does not use the trusted /bin/zsh -f interpreter`);
  }
  if (content.includes('PI_SANDBOX_PREAMBLE')) {
    fail(`${path} accepts an ambient PI_SANDBOX_PREAMBLE override`);
  }
  if (!content.includes('PI_SANDBOX=1')) {
    fail(`${path} does not force sandbox mode before sourcing the preamble`);
  }
  if (!content.includes('PI_SANDBOX_RUNTIME="${0:A:t}"')) {
    fail(`${path} does not derive runtime identity from the canonical launcher basename`);
  }
  if (!content.includes('pi|omp)')) {
    fail(`${path} does not restrict runtime identity to the closed pi/omp set`);
  }
  if (!content.includes('PI_EXECUTABLE_KEY="$PI_SANDBOX_RUNTIME"')) {
    fail(`${path} does not pin the executable binding key to runtime identity`);
  }
  if (!content.includes('PI_SANDBOX_PROFILE="$PI_SANDBOX_INSTALL_DIR/pi-sandbox.sb"')) {
    fail(`${path} does not pin the sandbox profile to the launcher install dir`);
  }
  if (!content.includes('--extension "$PI_SANDBOX_GUARD_EXTENSION"')) {
    fail(`${path} does not inject the shared guard extension explicitly`);
  }
  if (!content.includes('is_runtime_command "$PI_SANDBOX_RUNTIME" "$@"')) {
    fail(`${path} does not keep agent-only extension flags out of runtime administrative commands`);
  }
  if (!content.includes('export OMP_PROFILE=')) {
    fail(`${path} does not mirror OMP --profile into the pre-sandbox state boundary`);
  }
  if (!content.includes('executable_under_sandbox_write_root')) {
    fail(`${path} does not validate the pinned guard Node against active writable roots`);
  }
}


function checkPreamble(path, { required }) {
  if (!existsSync(path)) {
    if (required) {
      fail(`missing sandbox preamble: ${path}`);
    }
    return;
  }

  const preamble = stripFullLineComments(read(path), '#');
  if (!preamble.includes('sandbox-exec')) {
    fail(`${path} does not invoke sandbox-exec`);
  }
  if (!preamble.includes('pi-sandbox.sb')) {
    fail(`${path} does not reference pi-sandbox.sb`);
  }
  if (!preamble.includes('resolve_active_hooks')) {
    fail(`${path} does not resolve the effective Git hooks path`);
  }
  if (!preamble.includes('rev-parse --path-format=absolute --git-path hooks')) {
    fail(`${path} does not resolve core.hooksPath/worktree hooks through Git`);
  }
  for (const selector of ['GIT_DIR', 'GIT_WORK_TREE', 'GIT_CONFIG_COUNT']) {
    if (!new RegExp(`^\\s*unset\\s+[^\\n]*\\b${selector}\\b`, 'm').test(preamble)) {
      fail(`${path} does not scrub ambient ${selector} before Git boundary resolution`);
    }
  }
  if (!preamble.includes('XDG_CONFIG_HOME="$PI_GIT_XDG_CONFIG_HOME" "$GIT_BIN"')) {
    fail(`${path} does not pin XDG_CONFIG_HOME for Git boundary resolution`);
  }
  if (!preamble.includes('-D "ACTIVE_HOOKS=$ACTIVE_HOOKS"')) {
    fail(`${path} does not pass ACTIVE_HOOKS to sandbox-exec`);
  }
  for (const parameter of ['PI_AGENT_STATE', 'OMP_AGENT_STATE', 'OMP_STATE_ROOT', 'OMP_BASE_ROOT']) {
    if (!preamble.includes(`-D "${parameter}=$${parameter}"`)) {
      fail(`${path} does not pass ${parameter} to sandbox-exec`);
    }
  }
  if (!preamble.includes('PI_SANDBOX_RUNTIME_ACTIVE')) {
    fail(`${path} does not bind nested re-entry to the active runtime`);
  }
  if (!preamble.includes('unused_root="/private/tmp/pi-sandbox-guard-unused"')) {
    fail(`${path} gives inactive runtime parameters a new HOME write root`);
  }
  // Node must be resolved from trusted absolute candidates, never ambient PATH.
  // Checked as a property (every candidate is under a trusted prefix, and at least
  // one versioned-Homebrew form is covered) rather than by pinning one host's exact
  // glob string, which failed on Intel Macs and on any reformatting of the list.
  const nodeCandidates = [...preamble.matchAll(/^\s*(\/[^\s#]*\/node(?:@\*)?(?:\/bin\/node)?(?:\(N\))?)\s*$/gm)].map(
    (m) => m[1],
  );
  if (nodeCandidates.length === 0) {
    fail(`${path} does not pin absolute Node candidates (ambient PATH node resolution)`);
  }
  // Homebrew keeps versioned formulae under <prefix>/opt/ (Apple Silicon
  // /opt/homebrew/opt, Intel /usr/local/opt), so both are trusted roots here.
  const trustedNodeRoots = [...TRUSTED_BIN_PREFIXES, '/opt/homebrew/opt', '/usr/local/opt'];
  for (const candidate of nodeCandidates) {
    if (!trustedNodeRoots.some((prefix) => candidate.startsWith(`${prefix}/`))) {
      fail(`${path} lists untrusted Node candidate '${candidate}'`);
    }
  }
  if (!nodeCandidates.some((candidate) => candidate.includes('node@'))) {
    fail(`${path} does not support trusted versioned Homebrew Node installs (node@*)`);
  }
  if (!preamble.includes('[ -z "$LOGIN_USER" ] || [ -z "$owner" ]')) {
    fail(`${path} does not fail closed when TMPDIR ownership cannot be verified`);
  }
  if (
    !preamble.includes('PI_SANDBOX_PROJECT_BOUNDARY') ||
    !preamble.includes('PI_SANDBOX_ACTIVE_HOOKS_BOUNDARY')
  ) {
    fail(`${path} does not behaviorally verify nested project/hooks boundaries`);
  }
}

function checkProfile(path, { required }) {
  if (!existsSync(path)) {
    if (required) {
      fail(`missing sandbox profile: ${path}`);
    }
    return;
  }

  const profile = normalizeWhitespace(stripFullLineComments(read(path), ';'));
  const requiredWriteDeny = '(deny file-write*)';
  const requiredWriteDenyFragments = [
    '(subpath (string-append (param "PROJECT") "/.git/hooks"))',
    '(subpath (param "ACTIVE_HOOKS"))',
    `(require-all
       (subpath (string-append (param "PROJECT") "/.git/modules"))
       (regex #"/hooks(/|$)"))`,
    '(subpath (string-append (param "PI_AGENT_STATE") "/extensions"))',
    '(literal (string-append (param "PI_AGENT_STATE") "/settings.json"))',
    '(literal (string-append (param "PI_AGENT_STATE") "/auth.json"))',
    '(literal (string-append (param "PI_AGENT_STATE") "/trust.json"))',
    '(subpath (string-append (param "HOME") "/.pi/agent/extensions"))',
    '(literal (string-append (param "HOME") "/.pi/agent/settings.json"))',
    '(literal (string-append (param "HOME") "/.pi/agent/auth.json"))',
    '(literal (string-append (param "HOME") "/.pi/agent/trust.json"))',
    `(require-all
       (subpath (param "PI_AGENT_STATE"))
       (regex #"/.*prompt[^/]*\\.md$"))`,
    `(require-all
       (subpath (string-append (param "HOME") "/.pi/agent"))
       (regex #"/.*prompt[^/]*\\.md$"))`,
    '(subpath (string-append (param "OMP_AGENT_STATE") "/extensions"))',
    '(subpath (string-append (param "OMP_AGENT_STATE") "/hooks"))',
    '(subpath (string-append (param "OMP_AGENT_STATE") "/tools"))',
    '(literal (string-append (param "OMP_AGENT_STATE") "/config.yml"))',
    '(subpath (string-append (param "OMP_STATE_ROOT") "/plugins"))',
    `(require-all
       (subpath (string-append (param "OMP_STATE_ROOT") "/wt"))
       (regex #"/hooks(/|$)"))`,
    '(subpath (string-append (param "HOME") "/.ssh"))',
    '(subpath (string-append (param "HOME") "/.aws"))',
    '(subpath (string-append (param "HOME") "/.docker"))',
    '(subpath (string-append (param "HOME") "/.gnupg"))',
    '(subpath (string-append (param "HOME") "/.kube"))',
    '(subpath (string-append (param "HOME") "/.config/gh"))',
    '(subpath (string-append (param "HOME") "/.config/gcloud"))',
    '(literal (string-append (param "HOME") "/.git-credentials"))',
    '(literal (string-append (param "HOME") "/.config/git/credentials"))',
    '(literal (string-append (param "HOME") "/.netrc"))',
    '(literal (string-append (param "HOME") "/.npmrc"))',
    '(subpath (string-append (param "HOME") "/.secrets"))',
  ];
  // Hooks subtrees denied above; git init / submodule-init minimum re-allowed:
  // default hooks dir node + *.sample, plus submodule hooks dir nodes + *.sample.
  // Active hooks (and non-sample names) stay denied. ACTIVE_HOOKS is not re-allowed.
  const requiredGitHooksReallowBlock = `
    (allow file-write*
      (literal (string-append (param "PROJECT") "/.git/hooks"))
      (require-all
        (subpath (string-append (param "PROJECT") "/.git/hooks"))
        (regex #"/\\.git/hooks/[^/]*\\.sample$"))
      (require-all
        (subpath (string-append (param "PROJECT") "/.git/modules"))
        (regex #"/hooks$"))
      (require-all
        (subpath (string-append (param "PROJECT") "/.git/modules"))
        (regex #"/hooks/[^/]*\\.sample$"))
      (require-all
        (subpath (string-append (param "OMP_STATE_ROOT") "/wt"))
        (regex #"/hooks$"))
      (require-all
        (subpath (string-append (param "OMP_STATE_ROOT") "/wt"))
        (regex #"/hooks/[^/]*\\.[^/]+$")))
  `;
  const requiredCredentialReadDenyBlock = `
    (deny file-read*
      (subpath (string-append (param "HOME") "/.ssh"))
      (literal (string-append (param "HOME") "/.aws/credentials"))
      (literal (string-append (param "HOME") "/.aws/config"))
      (literal (string-append (param "HOME") "/.docker/config.json"))
      (literal (string-append (param "HOME") "/.kube/config"))
      (subpath (string-append (param "HOME") "/.gnupg"))
      (subpath (string-append (param "HOME") "/.config/gh"))
      (literal (string-append (param "HOME") "/.netrc"))
      (literal (string-append (param "HOME") "/.git-credentials"))
      (literal (string-append (param "HOME") "/.config/git/credentials"))
      (literal (string-append (param "HOME") "/.npmrc"))
      (subpath (string-append (param "HOME") "/.secrets"))
      (subpath (string-append (param "HOME") "/.config/gcloud"))
      (literal (string-append (param "HOME") "/.pi/agent/security-events.log"))
      (regex #"/\\.env($|\\.)"))
  `;

  if (!profile.includes('(param "ACTIVE_HOOKS")')) {
    fail(`${path} is missing the required ACTIVE_HOOKS parameter reference`);
  }
  if (!profile.includes(normalizeWhitespace('(subpath (param "ACTIVE_HOOKS"))'))) {
    fail(`${path} is missing the ACTIVE_HOOKS write-deny (effective active hooks directory)`);
  }
  if (!profile.includes(normalizeWhitespace(requiredWriteDeny))) {
    fail(`${path} is missing the blanket file-write deny`);
  }
  if (profile.includes(normalizeWhitespace('(subpath (param "OMP_STATE_ROOT"))'))) {
    fail(`${path} broadly allows the whole OMP state root instead of a positive runtime allowlist`);
  }
  for (const fragment of [
    '(subpath (string-append (param "OMP_AGENT_STATE") "/sessions"))',
    '(literal (string-append (param "OMP_AGENT_STATE") "/agent.db"))',
    '(literal (string-append (param "OMP_AGENT_STATE") "/agent.db-journal"))',
    '(subpath (string-append (param "OMP_STATE_ROOT") "/logs"))',
    '(subpath (string-append (param "OMP_STATE_ROOT") "/wt"))',
  ]) {
    if (!profile.includes(normalizeWhitespace(fragment))) {
      fail(`${path} is missing required OMP runtime allow: ${normalizeWhitespace(fragment)}`);
    }
  }
  for (const fragment of requiredWriteDenyFragments) {
    if (!profile.includes(normalizeWhitespace(fragment))) {
      fail(`${path} is missing required write-deny fragment: ${normalizeWhitespace(fragment)}`);
    }
  }
  if (!profile.includes(normalizeWhitespace(requiredGitHooksReallowBlock))) {
    fail(`${path} is missing the git-hooks re-allow block (dir node + *.sample for git init / submodule init)`);
  }
  if (!profile.includes(normalizeWhitespace(requiredCredentialReadDenyBlock))) {
    fail(`${path} is missing the credential file-read deny block`);
  }
}

if (explicitSources.length > 0) {
  // Pre-install gate: each path is either the protected shim or a custom wrapper.
  for (const path of explicitSources) {
    if (basename(path) === 'pi' || basename(path) === 'omp') {
      checkPiShim(path, { required: true });
    } else {
      checkLauncher(path, { required: true });
    }
  }
} else {
  checkPiShim(sourcePiPath, { required: true });
  // Example wrappers shipped in launchers/ must satisfy the same contract they
  // document, so a copied example is a safe starting point.
  for (const path of repoExampleLaunchers()) {
    checkLauncher(path, { required: true });
  }
  checkPreamble(sourcePreamblePath, { required: true });
  checkProfile(sourceProfilePath, { required: true });
}

if (checkDeployed) {
  // Verify every launcher the provenance stamp says was installed, so an extra
  // wrapper deployed via --extra-launchers is re-checked in place.
  const deployedNames = deployedLauncherNames();
  const deployedPaths = [deployedPiPath, deployedPreamblePath, deployedProfilePath];
  if (!deployedPaths.some((path) => existsSync(path))) {
    fail(`--deployed requested but no deployed launcher artifacts found under ${deployedRoot}`);
  }
  checkPiShim(deployedPiPath, { required: true });
  checkPiShim(deployedOmpPath, { required: true });
  for (const name of deployedNames) {
    if (name === 'pi' || name === 'omp') continue;
    checkLauncher(join(deployedRoot, name), { required: true });
  }
  checkPreamble(deployedPreamblePath, { required: true });
  checkProfile(deployedProfilePath, { required: true });
}

if (process.exitCode) {
  process.exit(process.exitCode);
}

console.log('OK: launchers call the protected shim and preserve sandbox guardrails.');
