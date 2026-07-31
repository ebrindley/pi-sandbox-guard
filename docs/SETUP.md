# Full setup & host environment

This documents the complete runtime environment so the configuration is
reproducible. It covers install order, environment trust, deploy commands, local
testing, and the parts that live **outside** the deploy scripts.

## Components

| Component | Where it lives | In this repo? |
|---|---|---|
| Guard extension | `~/.pi/agent/extensions/pi-sandbox-guard/` | yes (`src/`); via `npm run deploy` / `deploy:all` |
| Seatbelt profile + preamble | `~/.local/bin/pi-sandbox.{sb,…}` | yes (`sandbox/`); via `npm run deploy:launchers` / `deploy:all` |
| Protected `pi` shim | `~/.local/bin/pi` | yes (`launchers/pi`); via `npm run deploy:launchers` / `deploy:all` |
| Custom launchers (optional) | `~/.local/bin/` | **no**. Keep yours outside this repo; opt in with `--extra-launchers` (template: `launchers/example-custom`) |
| Executable config | `~/.config/pi-sandbox-guard/executables.conf` | optional example (`config/executables.example.conf`) |
| Pi (`@earendil-works/pi-coding-agent`) | global npm | **no** (install separately) |

## Security model (setup implications)

1. **Seatbelt is the primary out-of-project write boundary.** Always install the
   protected launchers for production-like use; the analyzer alone is not enough.
2. **PROJECT is writable on purpose.** Setup does not make the working tree
   read-only. Review agent diffs before unsandboxed git/build.
3. **Host environment is trusted; project env is not.** Launch from a real user
   account with a normal home directory. Do not point the shim at
   repo-controlled executable config or ambient hostile `PATH`/`TMPDIR`/`USER`.
   Note that `PI_PROJECT` and `PI_EXECUTABLE` are privileged overrides, and the
   first *defines* the write boundary, so a project-supplied value (an approved
   `.envrc`, for instance) is a real escalation. Set them yourself or not at all.
4. **Provider tokens are not isolated per tool** by this install. Denying writes
   to `auth.json` is tamper-resistance, not a credential broker.

Full model: [SECURITY.md](../SECURITY.md) and [ARCHITECTURE.md](ARCHITECTURE.md).

## Clean-machine install order

```bash
# prerequisites (manual, host-specific):
#   - install Pi by ANY method (see "Which Pi installs are supported" below)
#   - ensure /bin/zsh exists and bash, jq, awk are on PATH (all ship with macOS 15+)
#   - macOS with /usr/bin/sandbox-exec for the OS sandbox layer

# The short version, and all you need on a clean machine:
git clone https://github.com/ebrindley/pi-sandbox-guard.git && cd pi-sandbox-guard && npm run setup

# `npm run setup` is steps 1-3 below, accepting the detected Pi install without
# prompting. Run them separately when you want to review the detected install or
# redo one step on its own.

# 1. deploy the bash filter + Seatbelt profile + protected pi shim
npm run deploy:all

# 2. record which Pi install the shim should launch (once per machine)
npm run bind

# 3. confirm a plain `pi` resolves to the shim, not the real Pi
npm run check:path

# 4. optional: confirm installed copies match this checkout
npm run status

# 5. optional: install your own wrappers from OUTSIDE this repo
npm run deploy:launchers -- --extra-launchers ~/my-pi-launchers

# 6. run from a project directory
cd /some/git/repo && pi   # a repo, OR a fresh dir to scaffold (git init etc.)
```

### Deployment commands

| Script | Purpose |
|---|---|
| `npm run setup:hooks` | Explicit `core.hooksPath=.githooks` for **this** repo; **not** via package `prepare` on install |
| `npm run deploy:all` | Preflight guard + launchers, shared release identity, partial-failure handling |
| `npm run status` | Read-only drift check (source vs installed hashes / identity); does not read auth |

Component-only deployment remains available through `npm run deploy` and
`npm run deploy:launchers`. Package installation does not mutate Git hook
configuration.

The deploy builds a **self-contained copy** into Pi's auto-discovery directory,
verifies that deployed copy, then swaps it into place atomically and writes a
`.deployed-version` stamp (git sha + dirty flag + file hashes + Pi version). So
**the git repo can be moved or deleted and Pi stays guarded**: the repo is the
source of truth, the deploy dir is a built artifact. `pi install file:/path/to/repo`
is deliberately NOT used: it would record the repo path in Pi's settings, coupling
the install to the repo.

## Protection boundary

The default protected entrypoint is a `pi` shim installed earlier on
`PATH`, for example in `~/.local/bin`. In normal shell use, `pi` resolves to that
shim, the shim applies the macOS Seatbelt profile, and then it execs the real Pi
binary. Custom wrappers installed next to it call that sibling shim directly, so
they do not depend on ambient `PATH` ordering after launch.

Treat this as secure-by-default shell behavior, not impossible-to-bypass global
enforcement. A command that calls the real Pi binary directly, such as
`/opt/homebrew/bin/pi`, or a GUI/service launch path that does not include the
shim directory before the real Pi directory, can bypass the shim. Keep
`~/.local/bin` earlier on `PATH` for interactive shells, and point any executable
config at the real Pi binary rather than back at the shim.

### Environment trust at launch

Before Seatbelt applies, the preamble/shim:

- sanitized / pinned pre-sandbox **PATH** for security-critical tools
- system-derived **identity** / real `HOME` (not ambient `USER` spoofing)
- validated **TMPDIR** (reject broad roots / `$HOME` / project wideners)
- **config** pinned to trusted host paths (not repo-controlled ambient overrides)
- **strict nested** handling (own-shim re-entry with probes; unknown parent
  sandboxes fail closed)

See [ARCHITECTURE.md](ARCHITECTURE.md) for detail. Do not launch from unsafe roots (`$HOME`,
`~/Downloads`, `/`, …); the shim refuses those project boundaries.

## Which Pi installs are supported

**All of them, after one `npm run bind`.** Auto-detection alone covers only npm
installs made *into* a Homebrew or `/usr/local` prefix, because it searches a fixed
list of trusted path shapes. That list cannot describe the real world:

| Install method | Where `pi` actually lands | Auto-detected |
|---|---|---|
| `npm i -g` with `prefix=/opt/homebrew` | `/opt/homebrew/lib/node_modules/…` | yes |
| `npm i -g` with `prefix=/usr/local` | `/usr/local/lib/node_modules/…` | yes |
| `brew install pi-coding-agent` | `/opt/homebrew/Cellar/…/libexec/…` | no; bind |
| `npm i -g` (default sudo-free prefix) | `~/.npm-global/lib/node_modules/…` | no; bind |
| nvm / fnm / volta / asdf / mise | version-numbered dirs under `$HOME` | no; bind |
| pnpm / bun / yarn global | manager-specific global root | no; bind |
| Nix | `/nix/store/…` | no; bind |

```bash
npm run bind                 # detect, confirm, record
npm run bind -- --show       # what is recorded now
npm run bind -- --check      # still valid? (exit 3 if stale)
npm run bind -- --pi /abs/path/to/pi [--node /abs/path/to/node]
```

Binding records an absolute path in `~/.config/pi-sandbox-guard/executables.conf`.
Re-run it after an upgrade that moves the path (a Node version bump under
nvm/volta/mise, or a `brew upgrade`); a stale binding **fails closed** with the
recorded path and the command to fix it, rather than silently falling back.

**Not supported, deliberately:** `npx`/`bunx` and other transient runs, whose path
changes per invocation, so there is nothing stable to record. Docker and Linux are out
of scope entirely (`sandbox-exec` is macOS-only).

### Why a recorded path is trusted when an environment variable is not

A recorded binding is exempt from the trusted-prefix list. Two different sources,
two different rules, on purpose:

- **`pi=` in the pinned config** is *operator-recorded host state*. The protected shim
  reads it from a path under the real home directory and ignores an ambient
  `PI_EXECUTABLE_CONFIG` entirely, and the Seatbelt profile does not grant writes
  there, so a confined Pi session cannot repoint its own next launch.
- **`PI_EXECUTABLE`** is *ambient*: a project `.envrc`, `Makefile`, or npm lifecycle
  script can set it. It therefore keeps the trusted-prefix restriction.

```bash
# still works for a trusted-prefix path, still refused for anything else:
PI_EXECUTABLE=/opt/homebrew/bin/pi pi --version
```

**What binding is not:** it is a *non-ambient host pin*, not an integrity control. A
same-uid attacker outside the sandbox who can rewrite this config can equally rewrite
the shim or the Pi install itself. Note also that the trusted-prefix list is a
path-shape convention rather than a privilege boundary: on a standard Apple-Silicon
host `/opt/homebrew/bin`, `/opt/homebrew/lib/node_modules`, and `/opt/homebrew/Cellar`
are all owned by the unprivileged install user. What the shim does still enforce for
any source: absolute path, exists and is executable, is not the shim itself (that
would loop), and is **not inside a Seatbelt write root**. An executable the sandboxed
agent could rewrite would turn one confined session into persistence across every
later launch.

If the resolved Pi is a `#!/usr/bin/env node` script, bind records the interpreter too
and the launch becomes `<node> <cli.js>`. Without that record the shebang resolves
`node` from the shim's sanitized PATH, which has no entry for a version-manager
Node, so binding is what makes those installs work at all.

## Environment configuration

All config is host-trusted env, never read from the target repo:

| Var | Meaning | Default |
|---|---|---|
| `POLICY_RM_SAFE_ROOTS` | Extra `:`-separated roots under which `rm -rf` is permitted | — |
| `PI_EXECUTABLE` | Override the real Pi executable used by sandbox launchers | from config, else PATH auto-detect outside the shim dir |
| `PI_EXECUTABLE_CONFIG` | Path to executable config | `~/.config/pi-sandbox-guard/executables.conf` (pinned/trusted by hardened shim) |
| `PI_EXECUTABLE_KEY` | Config key for the executable lookup | launcher basename, usually `pi` |
| `PI_SANDBOX_PROFILE` | Ignored by the protected shim; the profile is pinned to the shim install dir | `~/.local/bin/pi-sandbox.sb` |
| `PI_PROJECT` | Explicit project write boundary for the OS sandbox | git top-level, else `$PWD` |
| `PI_RLIMIT_CPU` | Optional CPU seconds limit for sandboxed Pi process tree | unset |

`PI_EXECUTABLE` is a privileged host override (see the section above). Ambient values
must resolve to a trusted system/Pi prefix; executable config files are the portable
way to configure non-default installs. Relative executable paths are refused.

`PI_PROJECT` is privileged in the same way: it **defines** the Seatbelt write
boundary, so whatever it names becomes writable. The shim refuses broad, system, and
credential paths for every resolution mode (see [ARCHITECTURE.md](ARCHITECTURE.md)), but it
cannot tell a legitimate wide project root from an attacker's choice of some other
valuable directory. Treat it the way you treat `PI_EXECUTABLE`: it must come from you,
not from a project you are inspecting. A `direnv`/`.envrc` you approved in an
untrusted repo can set it, so do not approve one that does.

Analyzer security events are written under `~/.pi/agent/security-events.log` so they
survive the Seatbelt layer. A repo-controlled security-log path env var is
intentionally not supported.

## After each agent session

1. Review `git status` / diffs (and submodule / worktree pointers).
2. Only then run unsandboxed `git`, builds, or deploys.
3. Remember: Seatbelt does not protect integrity *inside* PROJECT; it limits
   *out-of-project* writes and selected credential paths.

## Testing: local only, by design

**This repository has no hosted CI, and that is deliberate.** There is no
`.github/workflows/` directory. Two reasons:

1. The security boundary is **macOS Seatbelt**. A Linux runner cannot compile or
   apply an SBPL profile, so the portable subset it could run would be green while
   saying nothing about the property that matters. A badge like that is worse than
   no badge, because it invites the assumption that the guard was verified.
2. Hosted macOS runners bill at ~10x Linux, for a single-maintainer personal tool
   whose only real deployment target is the maintainer's own Mac.

The gate is therefore local and must run on macOS:

```sh
npm test                          # full suite, ~140s
npm run test:fast                 # ~12s: adapter, degraded, shim, launcher lint, SBPL
npm run test:analyzer             # ~128s: smoke + 369-case corpus
npm run test:sandbox-profile      # SBPL compile + live apply probes only
```

`npm test` covers the in-tree analyzer, the characterization corpus, the adapter,
degraded-mode behavior, the shim, the fail-closed launcher lint, and a live
Seatbelt profile compile/apply. It needs `/usr/bin/sandbox-exec`.

### The pre-push gate is tiered

`npm run setup:hooks` installs a pre-push hook that scales the checks to the risk
of what is being pushed:

| Push | Gate | Cost |
|---|---|---|
| Any branch, analyzer untouched | `npm run test:fast` | ~12s |
| Range touches `src/` or `test/corpus/` | `npm test` | ~140s |
| New remote ref (no base to diff) | `npm test` | ~140s |
| `main` / `master` | `npm test` | ~140s |
| Branch deletion | skipped | — |

Two reasons for this shape. **It gates every branch, not just `main`,** because
changes land here by squash-merging a PR, and GitHub does that server-side, so no
local push to `main` ever happens and a `main`-only gate would never fire on the
workflow actually in use. **It is tiered** because ~128s of the ~140s total is the
analyzer path (`test/corpus.mjs` runs 369 cases), and those stages only
characterize `src/` and `test/corpus/`; running them for a docs edit
buys nothing while making the gate annoying enough to invite habitual skipping,
which is the real failure mode.

Override in an emergency: `SKIP_PREPUSH_TESTS=1 git push`.

Optional local-only checks belong in an executable, gitignored
`.githooks/pre-push.local`, which runs first and blocks the push on a non-zero
exit, that is where maintainer-specific private tooling goes, so a fork never
inherits a gate it cannot satisfy.

**If you fork this:** run `npm test` on a Mac before trusting a change to
`sandbox/`, `launchers/`, or `scripts/deploy-*.sh`. Nothing in this repo will run
those checks for you.

## Local git hooks (this repository)

This **development repository** can use `.githooks/pre-push` as a local-first
test gate. That is **developer ergonomics for this repo**, not part of the
Seatbelt boundary applied to arbitrary agent projects.

- Prefer **explicit** setup (`npm run setup:hooks` when present, else
  `git config core.hooksPath .githooks`).
- Package install does **not** silently rewrite `core.hooksPath` in unrelated
  consumer repositories.
- The hook needs only **bash, git, and npm**, the same tools required to work on
  this repo at all. It gates **every** push, tiering by risk; see
  [The pre-push gate is tiered](#the-pre-push-gate-is-tiered) above for the table.
  Emergency bypass: `SKIP_PREPUSH_TESTS=1 git push`.
- To add local validation without editing the tracked hook, drop an executable
  `.githooks/pre-push.local`. It runs first, receives the ref lines on stdin, and
  blocks the push on a non-zero exit. It is gitignored, so it stays out of clones
  and forks; when absent or non-executable it is skipped.

## What is intentionally NOT in the repo

- **`~/.pi/agent/auth.json`, `settings.json`, `trust.json`, `sessions/`**: host
  state and credentials (and the sandbox denies writing them from inside the
  profile; that is not full token isolation).
- **Any live link to the analyzer's origin project**: not a dependency, submodule,
  or third-party copy we track, so there is no sync or update-from-upstream workflow.
  `src/validate-bash-command.sh` is a self-contained MIT script **owned and
  maintained in this repository** (it began as an adaptation of an earlier
  MIT-licensed analyzer by the same author, since diverged). Deploy stamps
  therefore record local file integrity only, they make no parity claim against
  any external tree. Fix analyzer gaps here, and record any verdict change in
  `test/corpus/corpus.json` and
  [`ARCHITECTURE.md`](ARCHITECTURE.md#known-analyzer-gaps).

