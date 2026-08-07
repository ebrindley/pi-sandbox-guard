// shim.mjs — regression tests for the protected `pi` PATH shim.
//
// These tests copy the launcher, preamble, and Seatbelt profile into a temporary
// install dir. They exercise target-resolution, TMPDIR policy, config pinning,
// and nested own-shim re-entry behavior.

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  copyFileSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, '..');
const preamble = join(repo, 'sandbox', 'pi-sandbox-preamble.zsh');
const profile = join(repo, 'sandbox', 'pi-sandbox.sb');
const launcher = join(repo, 'launchers', 'pi');

let pass = 0;
let fail = 0;
let skipped = 0;
const results = [];

function check(name, fn) {
  try {
    fn();
    pass++;
    results.push(`  ok   ${name}`);
  } catch (err) {
    fail++;
    results.push(`  FAIL ${name}\n         ${err.message}`);
  }
}

function nativeCheck(name, fn) {
  if (!SANDBOX_APPLY_OK) {
    skipped++;
    results.push(`  skip ${name} (sandbox-exec cannot apply in this environment)`);
    return;
  }
  check(name, fn);
}

function policyIdFor(profilePath) {
  return createHash('sha256').update(readFileSync(profilePath)).digest('hex');
}

function canApplySandbox() {
  const r = spawnSync('/usr/bin/sandbox-exec', ['-p', '(version 1)(allow default)', '/usr/bin/true'], {
    encoding: 'utf8',
  });
  return r.status === 0;
}

const SANDBOX_APPLY_OK = canApplySandbox();

// Every scratch directory this suite creates, removed on exit. Registered in one
// place so a new fixture cannot silently start leaking: `fixture()` is called by
// most cases, so "the OS clears tmpdir eventually" is not good enough — a single
// run of this file created 38 directories, and they accumulated for weeks.
const tempDirs = [];
function trackTemp(dir) {
  tempDirs.push(dir);
  return dir;
}
process.on('exit', () => {
  for (const dir of tempDirs) {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      /* best effort: a leftover temp dir must never fail the suite */
    }
  }
});

function fixture() {
  const root = trackTemp(mkdtempSync(join(tmpdir(), 'pi-sandbox-shim-')));
  const shimDir = join(root, 'shim');
  const realDir = join(root, 'real');
  const hostileDir = join(root, 'hostile');
  mkdirSync(shimDir);
  mkdirSync(realDir);
  mkdirSync(hostileDir);

  const shim = join(shimDir, 'pi');
  copyFileSync(launcher, shim);
  chmodSync(shim, 0o755);
  const ompShim = join(shimDir, 'omp');
  copyFileSync(launcher, ompShim);
  chmodSync(ompShim, 0o755);
  const guardExtensionDir = join(shimDir, 'pi-sandbox-guard-extension');
  mkdirSync(guardExtensionDir);
  writeFileSync(join(guardExtensionDir, 'index.ts'), 'export default function () {}\n');
  const preambleCopy = join(shimDir, 'pi-sandbox-preamble.zsh');
  copyFileSync(preamble, preambleCopy);
  const profileCopy = join(shimDir, 'pi-sandbox.sb');
  copyFileSync(profile, profileCopy);

  // Fixture "real pi" lives outside trusted prefixes; used for refusal cases.
  const real = join(realDir, 'pi');
  writeFileSync(
    real,
    '#!/bin/zsh -f\nprint -u2 -- EVIL_OR_FIXTURE_PI\nprint -r -- "REAL_PI active=${PI_SANDBOX_SHIM_ACTIVE:-} args=$*"\n',
  );
  chmodSync(real, 0o755);

  return { root, shimDir, realDir, hostileDir, shim, ompShim, real, profileCopy, preambleCopy };
}

function baseEnv(fx, extraEnv = {}) {
  return {
    ...process.env,
    CODEX_SANDBOX: undefined,
    SANDBOX_PROFILE: undefined,
    SECCOMP: undefined,
    HOME: fx.root,
    PATH: `${fx.shimDir}:${fx.realDir}:/usr/bin:/bin:/usr/sbin:/sbin`,
    PI_EXECUTABLE: undefined,
    OMP_EXECUTABLE: undefined,
    PI_EXECUTABLE_CONFIG: join(fx.root, 'missing.conf'),
    PI_CONFIG_DIR: undefined,
    PI_PROFILE: undefined,
    OMP_PROFILE: undefined,
    PI_PROJECT: undefined,
    PI_SANDBOX_SHIM_ACTIVE: undefined,
    PI_SANDBOX_PROFILE_DIGEST: undefined,
    PI_SANDBOX_RUNTIME_ACTIVE: undefined,
    PI_SANDBOX_PROJECT_BOUNDARY: undefined,
    PI_SANDBOX_ACTIVE_HOOKS_BOUNDARY: undefined,
    PI_SANDBOX_AGENT_STATE_BOUNDARY: undefined,
    PI_SANDBOX_TRANSPARENT: undefined,
    PI_SANDBOX_PROFILE: undefined,
    PI_SANDBOX_SELFTEST: undefined,
    PI_SANDBOX_SELFTEST_CONFIG: undefined,
    PI_SANDBOX_SHIM_PATH: undefined,
    ZDOTDIR: fx.root,
    ...extraEnv,
  };
}

function runShim(fx, extraEnv = {}, args = ['hello']) {
  return spawnSync(fx.shim, args, {
    encoding: 'utf8',
    env: baseEnv(fx, extraEnv),
  });
}

function runOmpShim(fx, extraEnv = {}, args = ['hello']) {
  return spawnSync(fx.ompShim, args, {
    encoding: 'utf8',
    env: baseEnv(fx, {
      PI_EXECUTABLE: undefined,
      OMP_EXECUTABLE: TRUSTED_ECHO,
      ...extraEnv,
    }),
  });
}

function runNestedShim(fx, extraEnv = {}, args = ['nested-ok']) {
  const activeHooks = join(repo, '.githooks');
  return spawnSync(
    '/usr/bin/sandbox-exec',
    [
      '-D', `PROJECT=${repo}`,
      '-D', `HOME=${process.env.HOME}`,
      '-D', `TMPDIR=${realpathSync(tmpdir())}`,
      '-D', `ACTIVE_HOOKS=${activeHooks}`,
      '-D', `PI_AGENT_STATE=${process.env.HOME}/.pi/agent`,
      '-D', `OMP_AGENT_STATE=${process.env.HOME}/.pi-sandbox-guard-unused/omp-agent`,
      '-D', `OMP_STATE_ROOT=${process.env.HOME}/.pi-sandbox-guard-unused/omp-state`,
      '-D', `OMP_BASE_ROOT=${process.env.HOME}/.pi-sandbox-guard-unused/omp-base`,
      '-f', fx.profileCopy,
      fx.shim,
      ...args,
    ],
    {
      encoding: 'utf8',
      env: baseEnv(fx, {
        PI_EXECUTABLE: TRUSTED_ECHO,
        PI_SANDBOX_SHIM_ACTIVE: '1',
        PI_SANDBOX_RUNTIME_ACTIVE: 'pi',
        PI_SANDBOX_PROFILE_DIGEST: policyIdFor(fx.profileCopy),
        PI_SANDBOX_PROJECT_BOUNDARY: repo,
        PI_SANDBOX_ACTIVE_HOOKS_BOUNDARY: activeHooks,
        PI_SANDBOX_AGENT_STATE_BOUNDARY: `${process.env.HOME}/.pi/agent`,
        ...extraEnv,
      }),
    },
  );
}

/** Trusted absolute target used for successful resolution (/bin/echo). */
const TRUSTED_ECHO = '/bin/echo';
// A second distinct trusted binary, so a test can tell "resolved the executable" from
// "resolved the interpreter" by which path comes back.
const TRUSTED_TRUE = '/usr/bin/true';

function runSelftest(fx, selftest, extraEnv = {}) {
  return spawnSync('/bin/zsh', ['-f', '-c', `source ${JSON.stringify(fx.preambleCopy)}`], {
    encoding: 'utf8',
    env: baseEnv(fx, {
      PI_SANDBOX_SELFTEST: selftest,
      PI_SANDBOX_SHIM_PATH: fx.shim,
      PI_SANDBOX_INSTALL_DIR: fx.shimDir,
      PI_SANDBOX_PROFILE: fx.profileCopy,
      PI_PROJECT: fx.root,
      ...extraEnv,
    }),
  });
}

function runTmpdirSelftest(fx, tmpdirValue, extraEnv = {}) {
  return runSelftest(fx, 'tmpdir', {
    TMPDIR: tmpdirValue,
    ...extraEnv,
  });
}

function runResolveSelftest(fx, extraEnv = {}) {
  return runSelftest(fx, 'resolve', extraEnv);
}

function runActiveHooksSelftest(fx, project, extraEnv = {}) {
  return runSelftest(fx, 'active-hooks', { PI_PROJECT: project, ...extraEnv });
}

// --- resolution / hostile PATH ---

check('auto-resolution rejects untrusted PATH candidates', () => {
  const fx = fixture();
  writeFileSync(
    fx.real,
    '#!/bin/zsh -f\nprint -u2 -- EVIL_PI_RAN\nexit 77\n',
  );
  chmodSync(fx.real, 0o755);

  // Ambient PATH prefers the untrusted fixture binary; preamble must not select it.
  const r = runResolveSelftest(fx, {
    PATH: `${fx.realDir}:${fx.hostileDir}:/usr/bin:/bin`,
    PI_EXECUTABLE: undefined,
  });

  assert.doesNotMatch(r.stderr + r.stdout, /EVIL_PI_RAN/);
  if (r.status === 0) {
    // May resolve a trusted Homebrew/system pi; never the fixture path.
    const resolved = (r.stdout || '').trim();
    assert.notEqual(resolved, fx.real);
    assert.match(resolved, /^\/(opt\/homebrew|usr\/local|usr|bin)\//);
  } else {
    assert.match(r.stderr, /cannot auto-resolve the real Pi executable outside the shim path/);
  }
});

check('hostile PATH does not execute ambient awk/true before confinement', () => {
  const fx = fixture();
  const evilAwk = join(fx.hostileDir, 'awk');
  const evilTrue = join(fx.hostileDir, 'true');
  writeFileSync(evilAwk, '#!/bin/zsh -f\nprint -u2 -- EVIL_AWK_RAN\nexit 99\n');
  writeFileSync(evilTrue, '#!/bin/zsh -f\nprint -u2 -- EVIL_TRUE_RAN\nexit 99\n');
  chmodSync(evilAwk, 0o755);
  chmodSync(evilTrue, 0o755);

  const r = runShim(fx, {
    PATH: `${fx.hostileDir}:${fx.shimDir}:/usr/bin:/bin`,
    PI_EXECUTABLE: TRUSTED_ECHO,
  }, ['path-ok']);

  assert.doesNotMatch(r.stderr, /EVIL_AWK_RAN|EVIL_TRUE_RAN/);
  if (r.status === 0) {
    assert.match(r.stdout, /path-ok/);
  } else {
    assert.match(r.stderr, /refusing|cannot resolve|sandbox/);
  }
});

check('USER spoofing does not select another account home for identity', () => {
  const fx = fixture();
  const r = runResolveSelftest(fx, {
    USER: 'nobody',
    LOGNAME: 'nobody',
    PI_EXECUTABLE: TRUSTED_ECHO,
  });
  assert.equal(r.status, 0, r.stderr);
  assert.equal((r.stdout || '').trim(), TRUSTED_ECHO);
  assert.doesNotMatch(r.stderr, /\/Users\/nobody/);
});

// --- config pin + absolute prefix ---

check('repo-controlled ambient PI_EXECUTABLE_CONFIG is ignored by protected launcher', () => {
  const fx = fixture();
  const ambient = join(fx.root, 'repo-controlled.conf');
  // Would select untrusted fixture binary if ambient config were honored.
  writeFileSync(ambient, `pi=${fx.real}\n`);

  const r = runShim(fx, {
    PI_EXECUTABLE_CONFIG: ambient,
    PI_EXECUTABLE: undefined,
  }, ['--version']);

  // Must not execute the fixture binary selected only via ambient config.
  assert.doesNotMatch(r.stderr + r.stdout, /EVIL_OR_FIXTURE_PI|REAL_PI/);
  if (r.status !== 0) {
    // Ambient ignored -> auto-resolve of host pi or nested refuse / resolve failure.
    assert.match(
      r.stderr,
      /cannot auto-resolve the real Pi executable|cannot resolve configured Pi executable|refusing|sandbox_apply unavailable/,
    );
  }
});

// --- selection-boundary contract -------------------------------------------
// The two selection sources are deliberately NOT symmetric, and these tests pin
// that asymmetry because it is the whole security argument for the binding:
//
//   PI_EXECUTABLE (env)  is AMBIENT — a project .envrc/Makefile/npm script can set
//                        it — so it stays restricted to fixed trusted path shapes.
//   pi= in the config    is OPERATOR-RECORDED under real $HOME (and the protected
//                        shim ignores an ambient PI_EXECUTABLE_CONFIG entirely), so
//                        it is exempt from path shape.
//
// A refactor that routes both through one gate would silently make ambient input as
// powerful as a recorded binding. The fixture binary below sits OUTSIDE every trusted
// prefix, which is exactly what makes it a usable probe for the difference.

// A bindable target must be outside the trusted prefixes AND outside every Seatbelt
// write root. The shared `fixture()` root cannot serve here: it lives under the Darwin
// per-user temp dir, which the profile grants file-write* to, so a binding there is
// correctly refused. `~/.local/share` mirrors where a real version-manager or user-prefix
// install actually sits — unprivileged, unenumerable by any fixed prefix, not agent-writable.
// This writes under real $HOME, which makes removal especially important, but it
// uses the same trackTemp registry as the tmpdir fixtures — one cleanup path, so
// there is no second handler to forget.
function bindableDir() {
  mkdirSync(join(homedir(), '.local', 'share'), { recursive: true });
  return trackTemp(mkdtempSync(join(homedir(), '.local', 'share', 'pi-sandbox-bindable-')));
}
function bindableTarget() {
  const target = join(bindableDir(), 'pi');
  writeFileSync(target, '#!/bin/zsh -f\nprint -r -- BOUND_PI_RAN\n');
  chmodSync(target, 0o755);
  return target;
}
check('recorded config binding outside trusted prefixes is ACCEPTED (bind exemption)', () => {
  const fx = fixture();
  const bound = bindableTarget();
  const config = join(fx.root, 'executables.conf');
  writeFileSync(config, `pi=${bound}\n`);
  const r = runResolveSelftest(fx, {
    PI_EXECUTABLE: undefined,
    PI_SANDBOX_SELFTEST_CONFIG: config,
  });
  // This is the point of the binding: an install that no fixed prefix describes
  // (Cellar, npm user prefix, nvm/volta/mise, pnpm/bun, Nix) still launches.
  assert.equal(r.status, 0, r.stderr);
  assert.equal((r.stdout || '').trim(), bound);
});

check('config absolute target under trusted prefix is accepted by resolver', () => {
  const fx = fixture();
  const config = join(fx.root, 'executables.conf');
  writeFileSync(config, `pi=${TRUSTED_ECHO}\n`);
  const r = runResolveSelftest(fx, {
    PI_EXECUTABLE: undefined,
    PI_SANDBOX_SELFTEST_CONFIG: config,
  });
  assert.equal(r.status, 0, r.stderr);
  assert.equal((r.stdout || '').trim(), TRUSTED_ECHO);
});

check('env absolute target outside trusted prefixes is STILL refused', () => {
  const fx = fixture();
  const r = runResolveSelftest(fx, { PI_EXECUTABLE: fx.real });
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /not an accepted ambient override/);
  // The remedy must be named, or the user's next move is to weaken something —
  // and it must be a command that actually exists (there is no `pi-sandbox-bind`
  // binary; binding runs from the checkout).
  assert.match(r.stderr, /npm run bind/);
});

check('env cannot borrow the exemption granted to a recorded binding', () => {
  // Same path, two sources: accepted as a recording, refused as ambient env. If this
  // ever passes for env, the source separation has collapsed.
  const fx = fixture();
  const bound = bindableTarget();
  const config = join(fx.root, 'executables.conf');
  writeFileSync(config, `pi=${bound}\n`);
  const viaConfig = runResolveSelftest(fx, {
    PI_EXECUTABLE: undefined,
    PI_SANDBOX_SELFTEST_CONFIG: config,
  });
  const viaEnv = runResolveSelftest(fx, {
    PI_EXECUTABLE: bound,
    PI_SANDBOX_SELFTEST_CONFIG: config,
  });
  assert.equal(viaConfig.status, 0, viaConfig.stderr);
  assert.notEqual(viaEnv.status, 0, 'ambient env must not gain the binding exemption');
  assert.match(viaEnv.stderr, /not an accepted ambient override/);
});

check('relative config target is refused', () => {
  const fx = fixture();
  const config = join(fx.root, 'executables.conf');
  writeFileSync(config, 'pi=./fake-pi\n');
  const r = runResolveSelftest(fx, {
    PI_EXECUTABLE: undefined,
    PI_SANDBOX_SELFTEST_CONFIG: config,
  });
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /recorded Pi binding is no longer usable/);
});

check('config target resolving to the shim is refused', () => {
  const fx = fixture();
  const config = join(fx.root, 'executables.conf');
  writeFileSync(config, `pi=${fx.shim}\n`);
  const r = runResolveSelftest(fx, {
    PI_EXECUTABLE: undefined,
    PI_SANDBOX_SELFTEST_CONFIG: config,
  });
  assert.notEqual(r.status, 0);
  assert.match(
    r.stderr,
    /recorded Pi binding is no longer usable|refusing recursive launch/,
  );
});

check('a recorded binding inside a Seatbelt write root is refused', () => {
  // The bind exemption drops the path-shape rule, so this is what stops it from
  // meaning "unchecked". An executable the sandboxed agent can rewrite would turn one
  // confined session into persistence across every later launch. The fixture root is
  // under the Darwin per-user temp dir, which the profile grants file-write* to.
  const fx = fixture();
  const config = join(fx.root, 'executables.conf');
  writeFileSync(config, `pi=${fx.real}\n`);
  const r = runResolveSelftest(fx, {
    PI_EXECUTABLE: undefined,
    PI_SANDBOX_SELFTEST_CONFIG: config,
    // Point TMPDIR elsewhere: the deny must come from the path's own shape, not from
    // whatever the caller happens to have TMPDIR set to.
    TMPDIR: '/private/tmp',
  });
  assert.notEqual(r.status, 0, 'a write-root executable must never be launchable');
  assert.match(r.stderr, /recorded Pi binding is no longer usable/);
});

check('launch vector prepends a recorded interpreter for a node-shebang target', () => {
  // This is the whole point of recording an interpreter: without it the shebang would
  // resolve `node` from the shim's sanitized PATH, which has no entry for a
  // version-manager Node, so a correctly bound Pi would still fail to start.
  const fx = fixture();
  const dir = bindableDir();
  const script = join(dir, 'pi-cli.js');
  writeFileSync(script, '#!/usr/bin/env node\nconsole.log("x");\n');
  chmodSync(script, 0o755);
  const config = join(fx.root, 'executables.conf');
  writeFileSync(config, `pi=${script}\nnode=${TRUSTED_TRUE}\n`);
  const r = runResolveSelftest(fx, {
    PI_EXECUTABLE: undefined,
    PI_SANDBOX_SELFTEST_CONFIG: config,
    PI_SANDBOX_SELFTEST_VECTOR: '1',
  });
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual((r.stdout || '').trim().split('\n'), [TRUSTED_TRUE, script]);
});

check('launch vector does NOT prepend an interpreter to a native binary', () => {
  // Prepending node to a Mach-O binary would try to parse it as JavaScript. The
  // decision must come from the target's shebang, not from the record existing.
  const fx = fixture();
  const config = join(fx.root, 'executables.conf');
  writeFileSync(config, `pi=${TRUSTED_ECHO}\nnode=${TRUSTED_TRUE}\n`);
  const r = runResolveSelftest(fx, {
    PI_EXECUTABLE: undefined,
    PI_SANDBOX_SELFTEST_CONFIG: config,
    PI_SANDBOX_SELFTEST_VECTOR: '1',
  });
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual((r.stdout || '').trim().split('\n'), [TRUSTED_ECHO]);
});

check('a node-shebang target with no recorded interpreter keeps shebang launch', () => {
  // Not a failure: on a Homebrew/system-Node host the sanitized PATH does resolve
  // `node`. Breaking those working hosts to force a new record would be a regression.
  const fx = fixture();
  const dir = bindableDir();
  const script = join(dir, 'pi-cli.js');
  writeFileSync(script, '#!/usr/bin/env node\nconsole.log("x");\n');
  chmodSync(script, 0o755);
  const config = join(fx.root, 'executables.conf');
  writeFileSync(config, `pi=${script}\n`);
  const r = runResolveSelftest(fx, {
    PI_EXECUTABLE: undefined,
    PI_SANDBOX_SELFTEST_CONFIG: config,
    PI_SANDBOX_SELFTEST_VECTOR: '1',
  });
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual((r.stdout || '').trim().split('\n'), [script]);
});

check('a recorded interpreter that vanished fails closed', () => {
  const fx = fixture();
  const config = join(fx.root, 'executables.conf');
  writeFileSync(config, `pi=${TRUSTED_ECHO}\nnode=/opt/homebrew/bin/node-gone-away\n`);
  const r = runResolveSelftest(fx, {
    PI_EXECUTABLE: undefined,
    PI_SANDBOX_SELFTEST_CONFIG: config,
  });
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /recorded Node interpreter is no longer usable/);
});

check('ambient PI_EXECUTABLE_KEY is rejected instead of selecting another config key', () => {
  const fx = fixture();
  const config = join(fx.root, 'executables.conf');
  writeFileSync(config, `pi=${TRUSTED_ECHO}\nnode=${TRUSTED_TRUE}\n`);
  const r = runResolveSelftest(fx, {
    PI_EXECUTABLE: undefined,
    PI_SANDBOX_SELFTEST_CONFIG: config,
    PI_EXECUTABLE_KEY: 'node',
  });
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /executable key\/runtime mismatch/);
});

check('ambient preamble override is ignored', () => {
  const fx = fixture();
  const malicious = join(fx.root, 'malicious-preamble.zsh');
  writeFileSync(malicious, 'print -u2 MALICIOUS_PREAMBLE_RAN\nexit 42\n');
  const r = runShim(fx, {
    PI_EXECUTABLE: TRUSTED_ECHO,
    PI_SANDBOX_PREAMBLE: malicious,
  }, ['preamble-ok']);
  assert.doesNotMatch(r.stderr, /MALICIOUS_PREAMBLE_RAN/);
  if (r.status === 0) {
    assert.match(r.stdout, /preamble-ok/);
  } else {
    assert.notEqual(r.status, 42);
  }
});

check('ambient sandbox profile override is ignored', () => {
  const fx = fixture();
  const r = runShim(fx, {
    PI_EXECUTABLE: TRUSTED_ECHO,
    PI_SANDBOX_PROFILE: join(fx.root, 'missing-profile.sb'),
  }, ['profile-ok']);
  if (r.status === 0) {
    assert.match(r.stdout, /profile-ok/);
  } else {
    assert.doesNotMatch(r.stderr, /missing-profile\.sb/);
  }
});

// --- nested policy ---

check('leaked active marker without confinement does not bypass sandbox setup', () => {
  const fx = fixture();
  const r = runShim(
    fx,
    {
      PI_EXECUTABLE: TRUSTED_ECHO,
      PI_SANDBOX_SHIM_ACTIVE: '1',
    },
    ['must-wrap'],
  );

  if (SANDBOX_APPLY_OK) {
    assert.equal(r.status, 0, r.stderr);
    assert.match(
      r.stderr,
      /no active confinement detected; applying sandbox|OS sandbox ON/,
    );
    assert.match(r.stdout, /must-wrap/);
  } else {
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /nested profile digest mismatch|refusing|sandbox_apply unavailable/);
  }
});

check('generic CODEX/SANDBOX markers are not treated as own policy', () => {
  for (const marker of ['CODEX_SANDBOX', 'SANDBOX_PROFILE', 'SECCOMP']) {
    const fx = fixture();
    const r = runShim(
      fx,
      {
        PI_EXECUTABLE: TRUSTED_ECHO,
        [marker]: '1',
      },
      ['must-wrap'],
    );

    if (SANDBOX_APPLY_OK) {
      assert.equal(r.status, 0, `${marker}: ${r.stderr}`);
      assert.match(
        r.stderr,
        /sandbox marker env set but no active confinement detected; applying sandbox|OS sandbox ON/,
        `${marker} should fall through to sandbox setup`,
      );
      assert.match(r.stdout, /must-wrap/);
    } else {
      assert.notEqual(r.status, 0, `${marker} must fail closed under parent sandbox`);
      assert.match(
        r.stderr,
        /unknown parent sandbox|refusing|sandbox_apply unavailable|policy/,
        `${marker} must not grant pass-through`,
      );
    }
  }
});

nativeCheck('nested profile mismatch refuses without a matching digest', () => {
  const fx = fixture();
  const r = runNestedShim(fx, {
    PI_SANDBOX_PROFILE_DIGEST: 'deadbeef-not-a-real-profile-digest',
  }, ['nope']);

  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /nested profile digest mismatch|refusing/);
});

nativeCheck('own-shim re-entry requires matching digest and behavioral boundaries', () => {
  const fx = fixture();
  const r = runNestedShim(fx, {}, ['reentry-ok']);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stderr, /existing pi-sandbox-guard confinement detected; skipping nested wrap/);
  assert.match(r.stdout, /reentry-ok/);
});

nativeCheck('matching digest without boundary markers refuses nested pass-through', () => {
  const fx = fixture();
  const r = runNestedShim(fx, {
    PI_SANDBOX_PROJECT_BOUNDARY: undefined,
    PI_SANDBOX_ACTIVE_HOOKS_BOUNDARY: undefined,
  }, ['no-boundary']);
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /recorded (project|active-hooks) boundary is unavailable|refusing/);
});

nativeCheck('cross-runtime nested re-entry fails closed', () => {
  const fx = fixture();
  const r = runNestedShim(fx, {
    PI_SANDBOX_RUNTIME_ACTIVE: 'omp',
  }, ['cross-runtime']);
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /nested profile digest mismatch|confinement probes failed|refusing/);
});

// --- TMPDIR policy (selftest hook; no full Seatbelt apply required) ---

check('TMPDIR=/ is refused', () => {
  const fx = fixture();
  const r = runTmpdirSelftest(fx, '/');
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /refusing unsafe TMPDIR|broad\/system root|ancestor of HOME/);
});

check('TMPDIR=$HOME is refused', () => {
  const fx = fixture();
  const homeProbe = spawnSync('/usr/bin/id', ['-un'], { encoding: 'utf8' });
  const login = (homeProbe.stdout || '').trim();
  assert.ok(login, 'id -un must work');
  const dscl = spawnSync(
    '/usr/bin/dscl',
    ['.', '-read', `/Users/${login}`, 'NFSHomeDirectory'],
    { encoding: 'utf8' },
  );
  const match = /NFSHomeDirectory:\s*(\S+)/.exec(dscl.stdout || '');
  const realHome = match ? match[1] : process.env.HOME;
  assert.ok(realHome && realHome.startsWith('/'), `real home resolved: ${realHome}`);

  const r = runTmpdirSelftest(fx, realHome);
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /refusing unsafe TMPDIR|HOME/);
});

check('safe Darwin per-user TMPDIR is accepted', () => {
  const fx = fixture();
  const darwinTmp = tmpdir();
  const r = runTmpdirSelftest(fx, darwinTmp);
  assert.equal(r.status, 0, r.stderr);
  const out = (r.stdout || '').trim();
  assert.match(out, /^\/private\/var\/folders\/[^/]+\/[^/]+\/T/);
});

check('safe /private/tmp TMPDIR is accepted', () => {
  const fx = fixture();
  const r = runTmpdirSelftest(fx, '/private/tmp');
  assert.equal(r.status, 0, r.stderr);
  assert.equal((r.stdout || '').trim(), '/private/tmp');
});

// --- active Git hooks path ---

check('default active hooks path resolves to .git/hooks', () => {
  const fx = fixture();
  const project = join(fx.root, 'project-default-hooks');
  mkdirSync(project);
  assert.equal(spawnSync('/usr/bin/git', ['init', '-q', project]).status, 0);

  const r = runActiveHooksSelftest(fx, project);
  assert.equal(r.status, 0, r.stderr);
  assert.equal((r.stdout || '').trim(), join(realpathSync(project), '.git', 'hooks'));
});

check('core.hooksPath resolves relative to the project', () => {
  const fx = fixture();
  const project = join(fx.root, 'project-custom-hooks');
  mkdirSync(project);
  assert.equal(spawnSync('/usr/bin/git', ['init', '-q', project]).status, 0);
  assert.equal(
    spawnSync('/usr/bin/git', ['-C', project, 'config', 'core.hooksPath', '.githooks']).status,
    0,
  );

  const r = runActiveHooksSelftest(fx, project);
  assert.equal(r.status, 0, r.stderr);
  assert.equal((r.stdout || '').trim(), join(realpathSync(project), '.githooks'));
});

check('ambient Git repository/config selectors cannot poison active hooks resolution', () => {
  const fx = fixture();
  const project = join(fx.root, 'project-clean-hooks');
  const poisoned = join(fx.root, 'project-poisoned-hooks');
  mkdirSync(project);
  mkdirSync(poisoned);
  const poisonedXdg = join(fx.root, 'poisoned-xdg');
  mkdirSync(join(poisonedXdg, 'git'), { recursive: true });
  assert.equal(spawnSync('/usr/bin/git', ['init', '-q', project]).status, 0);
  assert.equal(spawnSync('/usr/bin/git', ['init', '-q', poisoned]).status, 0);
  assert.equal(
    spawnSync('/usr/bin/git', ['-C', project, 'config', 'core.hooksPath', '.githooks']).status,
    0,
  );
  writeFileSync(join(poisonedXdg, 'git', 'config'), '[core]\n\thooksPath = /private/tmp/xdg-poison-hooks\n');

  const r = runActiveHooksSelftest(fx, project, {
    GIT_DIR: join(poisoned, '.git'),
    GIT_WORK_TREE: poisoned,
    GIT_CONFIG_COUNT: '1',
    GIT_CONFIG_KEY_0: 'core.hooksPath',
    GIT_CONFIG_VALUE_0: '/private/tmp/poison-hooks',
    XDG_CONFIG_HOME: poisonedXdg,
  });
  assert.equal(r.status, 0, r.stderr);
  assert.equal((r.stdout || '').trim(), join(realpathSync(project), '.githooks'));
});

check('broad core.hooksPath is refused', () => {
  const fx = fixture();
  const project = join(fx.root, 'project-broad-hooks');
  mkdirSync(project);
  assert.equal(spawnSync('/usr/bin/git', ['init', '-q', project]).status, 0);
  assert.equal(
    spawnSync('/usr/bin/git', ['-C', project, 'config', 'core.hooksPath', '/private/tmp']).status,
    0,
  );

  const r = runActiveHooksSelftest(fx, project);
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /refusing unsafe active Git hooks path/i);
});

check('core.hooksPath resolving to HOME is refused', () => {
  const fx = fixture();
  const project = trackTemp(mkdtempSync(join(tmpdir(), 'pi-hooks-project-outside-home-')));
  const realHome = process.env.HOME;
  assert.ok(realHome && realHome.startsWith('/'), `real HOME resolved: ${realHome}`);
  assert.equal(spawnSync('/usr/bin/git', ['init', '-q', project]).status, 0);
  assert.equal(
    spawnSync('/usr/bin/git', ['-C', project, 'config', 'core.hooksPath', realHome]).status,
    0,
  );

  const r = runActiveHooksSelftest(fx, project);
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /refusing unsafe active Git hooks path/i);
});

// --- full apply path when host allows sandbox-exec ---

// nativeCheck owns the skip bookkeeping, so adding a native test here cannot leave the
// skip list and the skip COUNT disagreeing (a hand-maintained else-branch already had
// four tests and three skip lines).
nativeCheck('full launch applies sandbox with trusted PI_EXECUTABLE', () => {
  const fx = fixture();
  const r = runShim(fx, { PI_EXECUTABLE: TRUSTED_ECHO }, ['full-ok']);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stderr, /OS sandbox ON/);
  assert.match(r.stdout, /full-ok/);
});

nativeCheck('full launch refuses TMPDIR=/ before Seatbelt', () => {
  const fx = fixture();
  const r = runShim(fx, { PI_EXECUTABLE: TRUSTED_ECHO, TMPDIR: '/' }, ['x']);
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /refusing unsafe TMPDIR|broad\/system root|ancestor of HOME/);
});

nativeCheck('full launch refuses a launch target inside the resolved PROJECT', () => {
  // Resolution cannot catch this: PROJECT is discovered from git/PI_PROJECT/$PWD long
  // AFTER the launch target is chosen, and the profile grants file-write* to all of it.
  // So the target must be re-checked once PROJECT is known — otherwise one confined
  // session rewrites the binary and every later launch executes that edit with the
  // agent's network and project access.
  //
  // Driven through PI_EXECUTABLE with a TRUSTED-PREFIX path so the ambient rules pass and
  // the PROJECT check is unambiguously what refuses: /bin is a trusted prefix, so
  // PROJECT=/bin makes /bin/echo both trusted-by-shape and inside a write root.
  const fx = fixture();
  const r = runShim(fx, { PI_EXECUTABLE: TRUSTED_ECHO, PI_PROJECT: '/bin' }, ['x']);
  assert.notEqual(r.status, 0, 'a target inside PROJECT must never launch');
  assert.match(r.stderr, /inside a sandbox-writable root|refusing unsafe boundary/);
});

nativeCheck('full launch still succeeds when the target is outside PROJECT', () => {
  // The control for the check above: it must refuse targets inside PROJECT without
  // refusing ordinary launches. Without this, "refuse everything" would pass.
  const fx = fixture();
  const proj = bindableDir();
  const r = runShim(fx, { PI_EXECUTABLE: TRUSTED_ECHO, PI_PROJECT: proj }, ['outside-ok']);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /outside-ok/);
});

nativeCheck('shared launcher selects OMP and injects the protected extension', () => {
  const fx = fixture();
  const r = runOmpShim(fx, {}, ['omp-ok']);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stderr, /Runtime \[omp\]/);
  assert.match(r.stdout, /--extension/);
  assert.match(r.stdout, /pi-sandbox-guard-extension\/index\.ts/);
  assert.match(r.stdout, /omp-ok/);
});

nativeCheck('Pi administrative commands do not receive agent-only extension flags', () => {
  const fx = fixture();
  const r = runShim(fx, { PI_EXECUTABLE: TRUSTED_ECHO }, ['auth', '--help']);
  assert.equal(r.status, 0, r.stderr);
  assert.doesNotMatch(r.stdout, /--extension/);
  assert.match(r.stdout, /auth --help/);
});

nativeCheck('OMP administrative commands do not receive agent-only extension flags', () => {
  const fx = fixture();
  const r = runOmpShim(fx, {}, ['stats']);
  assert.equal(r.status, 0, r.stderr);
  assert.doesNotMatch(r.stdout, /--extension/);
  assert.match(r.stdout, /stats/);
});

nativeCheck('OMP ACP agent command keeps the required extension', () => {
  const fx = fixture();
  const r = runOmpShim(fx, {}, ['acp']);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /--extension/);
  assert.match(r.stdout, /acp/);
});

nativeCheck('OMP agent commands that reject extensions fail closed', () => {
  const fx = fixture();
  const r = runOmpShim(fx, {}, ['cleanse']);
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /does not accept the required guard extension/);
  assert.equal((r.stdout || '').trim(), '', 'unsupported agent command must not reach real OMP');
});

nativeCheck('OMP CLI profile selects the matching sandbox state root', () => {
  const fx = fixture();
  const r = runOmpShim(fx, {}, ['--profile', 'work', 'profile-ok']);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stderr, /OMP state: .*\/\.omp\/profiles\/work/);
  assert.match(r.stdout, /--profile work/);
  assert.match(r.stdout, /--extension/);
});

nativeCheck('OMP leading --profile=<name> selects the matching sandbox state root', () => {
  const fx = fixture();
  const r = runOmpShim(fx, {}, ['--profile=work', 'profile-ok']);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stderr, /OMP state: .*\/\.omp\/profiles\/work/);
  assert.match(r.stdout, /--profile=work/);
});

check('OMP refuses late or duplicate profile flags before launch', () => {
  for (const args of [
    ['--system-prompt', '--profile', 'work'],
    ['--profile', 'work', '--profile=other', 'profile-no'],
  ]) {
    const fx = fixture();
    const r = runOmpShim(fx, {}, args);
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /requires --profile to be the first argument and specified once/);
    assert.equal((r.stdout || '').trim(), '', 'ambiguous profile arguments must not reach real OMP');
  }
});

check('bound Pi executable inside relocated Pi state is classified writable', () => {
  const fx = fixture();
  const alternate = join(homedir(), '.pi', 'alternate-agent');
  const target = join(alternate, 'bin', 'pi');
  const r = runSelftest(fx, 'write-root', {
    PI_CODING_AGENT_DIR: alternate,
    PI_SANDBOX_SELFTEST_TARGET: target,
  });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /writable/);
});

check('bound OMP executable inside alternate OMP state is classified writable', () => {
  const fx = fixture();
  const stateRoot = join(homedir(), '.omp-work');
  const target = join(stateRoot, 'natives', 'omp');
  const r = runSelftest(fx, 'write-root', {
    PI_SANDBOX_RUNTIME: 'omp',
    PI_EXECUTABLE_KEY: 'omp',
    PI_CONFIG_DIR: '.omp-work',
    PI_SANDBOX_SELFTEST_TARGET: target,
  });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /writable/);
});

nativeCheck('guard Node binding inside PROJECT is refused before launch', () => {
  const fx = fixture();
  const project = bindableDir();
  const node = join(project, 'guard-node');
  copyFileSync(TRUSTED_TRUE, node);
  chmodSync(node, 0o755);
  writeFileSync(join(fx.shimDir, 'pi-sandbox-guard-extension', '.guard-node'), `${node}\n`);

  const r = runShim(
    fx,
    { PI_EXECUTABLE: TRUSTED_ECHO, PI_PROJECT: project },
    ['x'],
  );
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /guard Node.*sandbox-writable root/i);
});

check('OMP agent-dir override outside its state root is refused', () => {
  const fx = fixture();
  const r = runOmpShim(fx, {
    PI_CODING_AGENT_DIR: '/private/tmp/omp-agent-outside-root',
  });
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /does not support relocating PI_CODING_AGENT_DIR/);
});

check('Pi agent-dir relocation into the canonical extension tree is refused', () => {
  const fx = fixture();
  const r = runShim(fx, {
    PI_EXECUTABLE: TRUSTED_ECHO,
    PI_CODING_AGENT_DIR: join(homedir(), '.pi', 'agent', 'extensions'),
  });
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /cannot be the default agent root's parent or descendant/);
});

check('Pi agent-dir relocation outside ~/.pi is refused', () => {
  const fx = fixture();
  const r = runShim(fx, {
    PI_EXECUTABLE: TRUSTED_ECHO,
    PI_CODING_AGENT_DIR: '/private/tmp/pi-agent-outside-root',
  });
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /requires PI_CODING_AGENT_DIR to stay under ~\/\.pi/);
  assert.equal((r.stdout || '').trim(), '', 'unsupported Pi state must not reach real Pi');
});

console.log(results.join('\n'));
console.log(`\n${pass} passed, ${fail} failed, ${skipped} skipped`);
console.log(`sandbox_apply_ok=${SANDBOX_APPLY_OK}`);
process.exit(fail === 0 ? 0 : 1);
