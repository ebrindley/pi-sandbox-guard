# pi-sandbox-guard

**Keeps the [Pi coding agent](https://pi.dev) from writing outside your project**
(bar temp dirs and tool caches — see the boundary table below).

macOS-only. Uses Seatbelt (`sandbox-exec`) — the same OS sandbox Chrome, VS Code,
and Codex CLI use — so there is no container, no VM, and no Docker on your Mac.

Agents wander. Pi edited a file outside the project I was working in and I did
not notice for a while. The usual macOS answers are Docker or a VM, both heavy
for something you launch twenty times a day.

This uses the sandbox already built into macOS instead. Writes and deletes
outside your project are refused by the kernel, so a wrong path fails instead of
landing.

## Install

```bash
git clone https://github.com/ebrindley/pi-sandbox-guard.git
cd pi-sandbox-guard && npm run setup
```

That is the whole install. It deploys the bash filter, the Seatbelt profile, and
a protected `pi` shim, records which Pi to launch, and finally checks that a
plain `pi` actually resolves to the shim — if `~/.local/bin` is missing from your
`PATH` or sits after the real Pi, setup fails and tells you what to add where.

Then work as usual:

```bash
cd /path/to/your/project && pi
```

You should see `OS sandbox ON. Project [...]` at startup. That line is how you
know you are protected. If it is missing, re-run `npm run check:path` from this
checkout.

## What it does and does not do

| | |
|---|---|
| Writes outside the project | **Blocked at the kernel**, apart from an explicit allow-list: the project, `$TMPDIR` / `/private/tmp`, `~/.pi/agent` runtime state (its config, `auth.json`, and installed extensions are re-denied), and the `~/.npm`, `~/.cache`, `~/Library/Caches` tool caches. Everything else is denied. |
| Reads of selected credential paths | **Denied:** `~/.ssh`, `~/.aws/{credentials,config}`, `~/.docker/config.json`, `~/.kube/config`, `~/.gnupg`, `~/.config/{gh,gcloud}`, Git credential stores (`~/.git-credentials`, `~/.config/git/credentials`), `~/.netrc`, `~/.npmrc`, `~/.secrets`, and `.env` files. Other paths—including `~/.aws/sso/`—remain readable; this is not a general confidentiality boundary. |
| Tampering with Pi's own config / auth / installed extensions | **Denied** (the agent cannot disable this guard). |
| Git-hook persistence | Active hook trees are **write-denied**. |
| Catastrophic literal bash (`rm -rf /`, `curl \| sh`, `dd` to devices, fork bombs) | **Blocked or confirm-prompted** by the bash filter. |
| Files **inside** your project | **Not protected** — the agent edits code, that is the point. Review diffs. |
| Credentials already in your shell env (`GITHUB_TOKEN`, `HF_TOKEN`, …) | **Not protected.** They are inherited by the agent and the network is open, so `git push --force`, `gh repo delete`, and token-authenticated API calls all still work. Use a VM if you need this. |
| Network egress | **Not restricted.** |
| Dynamically assembled commands (`eval "$VAR"`) | **Not caught** by the filter — static analysis only. Seatbelt still confines the writes. |

Two layers, and the weaker one is not the fail-safe:

1. **Seatbelt OS sandbox** ([`docs/SANDBOX.md`](docs/SANDBOX.md)) — the **primary**
   boundary. Catches what the filter cannot: dynamic exec, mutated input,
   non-bash writes *outside the project*, subprocess escapes outside the
   project. `PROJECT` itself stays writable by design (see the table above).
2. **The bash filter** — a pre-execution policy hook on Pi's `bash` tool. Good
   error messages and confirm prompts; it sees only the literal command string
   and can be bypassed by dynamic exec.

Full model and known gaps: [SECURITY.md](SECURITY.md),
[KNOWN_ANALYZER_GAPS.md](KNOWN_ANALYZER_GAPS.md).

> **Support:** personal project, maintained for my own use and shared as-is under
> MIT. **Bug reports and feature requests via [issues](../../issues) are welcome;
> external pull requests are not accepted** — see
> [CONTRIBUTING.md](CONTRIBUTING.md). Forking is explicitly permitted by the MIT
> license. Security issues go through a [private advisory](../../security/advisories/new),
> not a public issue.

## Prerequisites

macOS (Apple Silicon or Intel):

- **Pi** (`@earendil-works/pi-coding-agent`) installed and on `PATH`.
- **Node ≥ 18**, plus `bash` + `jq` + `awk` on the system PATH
  (`/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin`) — all three ship with
  macOS 15+. The bash filter preflights these and **blocks all bash** if any is
  missing. Path canonicalization uses the guard's own Node binary
  (`process.execPath`), so no separate interpreter is required.
- **`/usr/bin/sandbox-exec`** (built into macOS) — required for the OS sandbox.
- `/bin/zsh` — required by the protected launcher, not by the Node extension.
- Any **model provider** Pi supports; this guard is provider-independent.

## Install details

`npm run setup` is the three steps below, run in order. Use them directly if you
want to redo one on its own:

```bash
npm run deploy:all      # bash filter + Seatbelt profile + protected `pi` shim
npm run bind            # record which Pi install the shim launches
npm run check:path      # confirm a plain `pi` resolves to the shim, not the real Pi
npm run status          # optional: verify installed copies + report the binding
```

`check:path` is the one that catches an otherwise silent failure: `status` compares
installed file hashes, so it can report everything OK while an earlier `PATH` entry
means `pi` never reaches the shim.

`deploy:all` runs the test suite first, validates the Seatbelt profile by
**applying it live** (it refuses to install an unenforceable profile), backs up
anything it replaces, and stamps provenance. The two components can also be
installed separately with `npm run deploy` (filter only — **not** sufficient on
its own) and `npm run deploy:launchers` (Seatbelt + shim).

`bind` is a separate step because *which* Pi to launch is host-local state, not a
deployed artifact. `npm run setup` accepts the detected install automatically;
run `npm run bind` on its own to review the choice interactively, or pass
`--pi`/`--node` to set it explicitly — see
[Recording the Pi install](#recording-the-pi-install).

Pi auto-discovers the extension on the next launch. Details:
[`docs/SETUP.md`](docs/SETUP.md).

### Installing from npm

The package is on npm as `@ebrindley/pi-sandbox-guard`, but installing it as a
dependency does not switch the guard on: the OS sandbox lives in a `pi` shim on
your `PATH`, which only `npm run setup` (or `deploy:launchers`) puts there. The
same applies to `pi install npm:@ebrindley/pi-sandbox-guard`, which loads the
bash filter alone. Filter-only is a real mode and better than nothing, but it is
**not** the kernel boundary this README describes, so the guard says
`FILTER-ONLY: could not verify …` at startup when it cannot confirm the shim.
Clone and run `npm run setup` for the full guard.

### Custom launchers

Only the protected `pi` shim is installed by default. If you wrap Pi with your own
flags — a local model server, a per-provider preset — keep those wrappers
**outside this repo** and opt in explicitly:

```bash
npm run deploy:launchers -- --extra-launchers ~/my-pi-launchers
```

Start from [`launchers/example-custom`](launchers/example-custom), which documents
the contract. Every wrapper is linted **before anything is installed** and the
deploy is refused as a whole if one fails — a wrapper that execs the real Pi
binary instead of the sibling shim would run completely unsandboxed, so
best-effort installation is not safe here. The name `pi` is reserved, and
symlinks are refused.

Repo git hooks are opt-in (`npm run setup:hooks`); installing the package never
rewrites a consumer repository's Git configuration.

### Protection boundary

The intended default is a protected `pi` entrypoint earlier on `PATH`, such as
`~/.local/bin/pi`, which wraps the real Pi executable with the macOS Seatbelt
sandbox. That makes normal shell use secure by default: running `pi`, or a
launcher installed next to that shim, goes through Seatbelt.

This is not a universal system-wide enforcement mechanism. Anything that calls
the real Pi binary directly, such as `/opt/homebrew/bin/pi`, or launches Pi from
a GUI or service environment that bypasses `~/.local/bin`, can bypass the shim.
The Seatbelt profile is the kernel boundary once applied; the PATH entrypoint is
the convenience layer that makes applying it hard to forget during normal shell
use.

### Recording the Pi install

The protected `pi` shim auto-detects the real Pi binary only from trusted system
install prefixes (`/opt/homebrew/bin`, `/usr/local/bin`, `/usr/bin`, `/bin`) with
the shim directory removed. That covers an `npm i -g` into a Homebrew or
`/usr/local` prefix and little else. Everything else — Homebrew's own formula
(`Cellar/…/libexec`), npm's sudo-free user prefix, nvm/fnm/volta/asdf/mise,
pnpm/bun/yarn global, Nix — needs one deliberate recording:

```bash
npm run bind                 # detect, confirm, record
npm run bind -- --show       # what is recorded now
npm run bind -- --check      # still valid? (exit 3 if stale)
npm run bind -- --pi /abs/path/to/pi [--node /abs/path/to/node]
```

Run it once per machine, from an unsandboxed shell. `npm run status` reports the
binding, and re-record after anything that moves the install (a Node version
switch, a `brew upgrade`) — a stale binding fails closed with the recorded path
and the command to fix it.

The protected shim reads the binding from `~/.config/pi-sandbox-guard/executables.conf`
under its own derived home, and only from there. `bind` and `status` accept
`PI_SANDBOX_CONFIG_DIR` as a testing seam, and both follow an ambient `HOME`; with
either redirected they operate on a file the shim will not read. Leave both unset for
a real install.

Resolution order is: trusted `PI_EXECUTABLE` env override, then the recorded
binding in `~/.config/pi-sandbox-guard/executables.conf`, then trusted-prefix PATH
auto-detection outside the shim directory. For a shim named `pi`, do not configure
`pi=pi`; that points the shim back at itself.

**Why a recorded path is trusted when an env var is not:** the config is
*operator-recorded host state* — read from under the real home directory, and not
writable under the Seatbelt profile, so a confined Pi session cannot repoint its
own next launch. `PI_EXECUTABLE` is *ambient* (a project `.envrc`, `Makefile`, or
npm lifecycle script can set it), so it keeps the trusted-prefix restriction. This
is a **non-ambient host pin, not an integrity control**: a same-uid attacker
outside the sandbox who can rewrite the config can equally rewrite the shim
itself. Note also that the trusted-prefix list is a path-shape convention rather
than a privilege boundary — on a standard Apple-Silicon host, every allowlisted
`/opt/homebrew` path is owned by the unprivileged install user.

Regardless of source, the shim still requires the target to be absolute, existing
and executable, not the shim itself, and **not inside a Seatbelt write root**. The
shim also pins its preamble and Seatbelt profile to files installed next to it;
ambient `PI_SANDBOX_PREAMBLE` and `PI_SANDBOX_PROFILE` are not honored.

Full detail, including the per-install-method table and the `#!/usr/bin/env node`
interpreter case: [`docs/SETUP.md`](docs/SETUP.md).

## How the analyzer filter works

```
Pi tool_call(bash)  ──▶  index.mjs (adapter)  ──▶  guard-core.mjs  ──▶  bash validate-bash-command.sh
                                                          │                     (analyzes command STRING,
   { block, reason } ◀── map decision ◀── allow/ask/block │                      never executes it)
```

- **Input** is delivered to the analyzer on **stdin only**, as
  `{"tool_input":{"command":"…"}}`. The candidate command is never placed on a
  shell command line, so the guard cannot be command-injected by the very input
  it is inspecting.
- **Decision** is taken from the analyzer's **exit code only** (0=allow,
  1=ask/confirm, 2=block). `stderr` is treated as human-readable display text and
  is **never** parsed to derive the verdict.
- **Anything unexpected fails closed** (blocks): timeout, spawn error, unknown
  exit code, killed-by-signal, oversized command, missing analyzer, or invalid
  execution directory. Empty bash invocations are treated as no-ops.

This path improves UX and catches many catastrophic **literal** forms. It does
**not** replace Seatbelt.

## Hardening (guard extension + launcher direction)

Each guard item below closes a specific failure that adversarial review found in an
earlier revision; none is speculative hardening. This was self-review, not an
external audit.
Launcher/Seatbelt items are the containment track (see
[docs/SANDBOX.md](docs/SANDBOX.md)).

| Risk | Mitigation |
|---|---|
| Command injection into the guard | `spawn('/bin/bash', [script])` + command via **stdin only**; never `ctx.exec`/shell strings |
| Repo-local `jq`/`awk` hijack | Subprocess runs with a **fixed trusted `PATH`**, not the ambient/project PATH; the canonicalizer's Node is pinned to an absolute path, so it is not resolved through any PATH at all |
| Repo `.env` disarming the guard (`CLAUDE_ALLOW_RM_RF=1`) | **No `process.env` passthrough**; only an allow-listed, host-supplied `trustedPolicyEnv` reaches the subprocess |
| Pi has no hard kill → hung agent | Adapter-owned **timeout → SIGTERM the process *group* → SIGKILL** → block |
| Fragile `decision:reason` parsing | Decision = **exit code only**; stderr is display-only |
| Relative-path fail-open (`cd /tmp && rm -rf .`) | Subprocess `cwd` set to the **bash tool's intended cwd** |
| Missing deps silently weaken analysis | **Functional preflight**: each helper (`bash`/`jq`/`awk`) is *executed* (no-op probe) on the trusted PATH, and the pinned Node is probed separately — a present-but-broken helper is caught at load, not per-command; degrade to **block all bash** if any fails |
| ANSI-C quoted command words (`$'rm' -rf /`) evade the analyzer | **Reveal-only probe**: the original command is always analyzed as-is; ANSI-C spans are also decoded — emitted as single-quoted literals (bash-faithful) so the revealed verb reaches the analyzer without decoded data becoming syntax — and the **worst verdict wins**. Closes direct command-word cases; executor operands (`xargs 'rm'`) reduce to a quoted utility word, which the analyzer now treats as the ask tier, see [KNOWN_ANALYZER_GAPS.md](./KNOWN_ANALYZER_GAPS.md) |
| Windows (no bash) | Detected at preflight → **block all bash**, no fragile WSL spawning |
| Oversized command | Commands > **32 KB** are blocked before reaching the analyzer (matches analyzer's own size cap) |
| Pre-sandbox PATH / identity / TMPDIR / config | Launcher preamble: absolute trusted tools, system identity, validated TMPDIR, host-pinned config (containment track) |
| Nested unknown sandboxes | Fail closed unless own-shim re-entry proves expected policy + confinement probes |
| Git hook / hooksPath / submodule / worktree persistence | Active hooks write-denial direction in Seatbelt; still **review diffs** before unsandboxed git/build |

## Deploy (local, repo-independent)

The canonical local install builds a **self-contained copy** into Pi's
auto-discovery directory (`~/.pi/agent/extensions/pi-sandbox-guard/`). After
deploying, Pi loads the guard from that copy — **the git repo can be moved or
deleted and Pi stays guarded.** The repo is the source of truth; the deploy dir
is a built artifact.

```bash
npm run deploy          # scripts/deploy-local.sh  (guard extension only)
npm run deploy:launchers  # Seatbelt profile + protected pi shim
npm run deploy:all      # coordinated preflight + shared release identity
npm run status          # read-only drift check (no auth state)
```

The guard deploy script: runs the test suite as a source gate, **hard-checks** the
runtime helpers (`bash`/`jq`/`awk`) on the sanitized PATH and refuses
to deploy if any are missing (pass `--force-degraded` to override for testing),
builds the artifact in a temp dir, verifies the **deployed copy** (preflight +
a block/allow behavior check), then swaps it into place atomically and writes a
`.deployed-version` provenance stamp (git sha + dirty flag + file hashes + Pi
version). Pi auto-discovers it on next launch.

Deployed layout (preserves the repo's `src/`+`vendor/` so the analyzer path
resolves without referencing the repo):

```
~/.pi/agent/extensions/pi-sandbox-guard/
  index.ts        # one-line shim: re-exports ./src/index.mjs (Pi discovers .ts)
  src/index.mjs   # the Pi adapter
  src/guard-core.mjs
  vendor/validate-bash-command.sh
  .deployed-version
```

> **Non-goal:** `pi install file:/path/to/repo` is intentionally NOT used — it
> records the repo path in Pi's settings, coupling the install to the repo. The
> drop-in deploy above is what keeps it repo-independent.

## Test

No dependencies, no build step — runs on Node ≥18 directly:

```bash
npm test          # smoke + corpus + adapter + degraded + shim + launcher + live SBPL profile checks
npm run preflight # prints { ok, platform, missing, scriptPresent }
```

### Testing note

**There is no hosted CI.** This repository deliberately has no GitHub Actions
workflow: it is a macOS-only tool whose security boundary is Seatbelt, and a
Linux runner cannot exercise that boundary at all. Rather than advertise a green
Linux badge that proves nothing about the actual guard, the gate is local:

```sh
npm test        # analyzer + corpus + adapter + degraded mode + launcher lint
                # + live SBPL profile compile/apply on the machine that runs Pi
```

`npm run setup:hooks` wires that into a **tiered** pre-push hook: `npm run
test:fast` (~12s) on any branch push, escalating to the full `npm test` (~140s)
when the range touches the analyzer (`src/`, `vendor/`, `test/corpus/`) or targets
`main`. Run it on a Mac; the SBPL portion needs `/usr/bin/sandbox-exec` and cannot
be faked elsewhere. Details: [`docs/SETUP.md`](docs/SETUP.md).

### Golden corpus

`test/corpus/corpus.json` is a **characterization corpus**: 369
`{command, cwd, expected-verdict}` cases pinning the full guard path (in-tree
analyzer + guard-level hardening) — catastrophic forms and chains, quoting
variants, cwd-sensitive relative/absolute cases, the ask tier, and benign
false-positive shapes. A gap narrow enough to pin as one command is recorded with
`expectFail: true`; the runner **fails when that gap stops reproducing**, so a fix
cannot land unnoticed. Broad classes like fully dynamic execution cannot be pinned
that way and are held by characterization cases instead. A change to any behavior
the corpus covers shows up as an explicit verdict diff here. Behavior it does not
cover — `python3 evil.py` and other script-file interpreter forms, for instance —
can change silently: this is 369 chosen cases, not an exhaustive contract.

## Configuration

All config is host-trusted env (never read from the target repo):

| Var | Meaning | Default |
|---|---|---|
| `POLICY_RM_SAFE_ROOTS` | Extra `:`-separated roots under which `rm -rf` is permitted | — |
| `PI_EXECUTABLE` | Override the real Pi executable used by sandbox launchers | from config, else PATH auto-detect outside the shim dir |
| `PI_EXECUTABLE_CONFIG` | Path to executable config | `~/.config/pi-sandbox-guard/executables.conf` (pinned/trusted by hardened shim) |
| `PI_EXECUTABLE_KEY` | Config key for the executable lookup | launcher basename, usually `pi` |
| `PI_SANDBOX_PROFILE` | Ignored by the protected shim; the profile is pinned to the shim install dir | `~/.local/bin/pi-sandbox.sb` |
| `PI_PROJECT` | Explicit project write boundary for the OS sandbox | git top-level, else `$PWD` |
| `PI_RLIMIT_CPU` | Optional CPU seconds limit for sandboxed Pi process tree | unset |

`PI_EXECUTABLE` is a privileged host override. Ambient `PI_EXECUTABLE` values
must resolve to a trusted system/Pi prefix; executable config files are the
portable way to configure non-default installs. Relative executable paths are
refused.

`PI_PROJECT` is also a privileged host override: it **defines** the Seatbelt
write boundary, so whatever it names becomes writable. The shim refuses broad,
system, and credential paths for every resolution mode (see
[docs/SANDBOX.md](docs/SANDBOX.md)), but it cannot tell a legitimate wide project
root from an attacker's choice of some other valuable directory. Treat it the way
you treat `PI_EXECUTABLE`: it must come from you, not from a project you are
inspecting. A `direnv`/`.envrc` you approved in an untrusted repo can set it, so
do not approve one that does.

Analyzer security events are written under `~/.pi/agent/security-events.log` so
they survive the Seatbelt layer. A repo-controlled security-log path env var is
intentionally not supported.

## Security model & limitations

**Primary boundary:** macOS Seatbelt out-of-project write containment (+ selected
credential path denies). **Secondary:** best-effort bash string analysis for UX.
This is not a VM, network sandbox, process isolator, or complete confidentiality
boundary. Known limits, stated plainly:

### Deliberate scope

1. **PROJECT is writable.** Neither layer guarantees working-tree integrity.
   Review diffs before unsandboxed git/build. Committed state may be recoverable;
   secrets and uncommitted work are not.
2. **Open network.** No egress allowlist today.
3. **No general confidentiality.** Most project files remain readable.
4. **Provider tokens in-process.** `auth.json` write-deny is tamper-resistance
   for stored auth, not per-tool secret isolation. Isolation needs Pi/upstream
   architecture or a broker/VM.
5. **No process-count cap.** Optional CPU ulimit only.

### Soft / structural limits

6. **Mutable-input ordering (soft boundary).** Pi lets later `tool_call` handlers
   mutate `event.input.command` with **no re-validation**. If another extension
   rewrites the command *after* this guard runs, the analyzer is bypassed.
   Register this guard **last**. This guard never mutates `event.input`.
   *Seatbelt still confines out-of-project writes.*
7. **Static analysis only.** Fully dynamic execution (`eval "$var"`, `"$cmd"`,
   or a destructive command assembled at runtime and not literally present) is
   out of scope for the analyzer. Literal `xargs rm` / `parallel rm` /
   `find -exec rm` forms are classified at the ask tier. Seatbelt backstops
   *write* blast radius outside PROJECT, not integrity inside it.
8. **Confirm semantics.** The `ask` tier relies on `ctx.ui.confirm`. With no UI,
   `ask` always blocks.
9. **Analyzer-level gaps.** See [KNOWN_ANALYZER_GAPS.md](./KNOWN_ANALYZER_GAPS.md).
10. **Hook / submodule / worktree persistence.** Active-hook denials reduce
    plant-and-escape via git hooks; residual risk remains for project-controlled
    scripts and config. Always review before unsandboxed execution.

### Fixed or mitigated here (not "everything is solved")

Examples of **repo-local** hardening (distinct from structural limits above):
stdin-only analyzer I/O, fixed analyzer PATH, no ambient policy env passthrough,
deploy-time Seatbelt probes, extensions/`auth.json` write-denies, broad PROJECT
root refusal, pre-sandbox PATH/identity/TMPDIR/config direction, nested policy
fail-closed direction. Analyzer `expectFail` gaps and open network remain.

**Degraded mode.** When the guard is unavailable (missing analyzer, missing helper
binaries, or win32), the adapter **blocks all bash commands** unconditionally.
A partial "block destructive commands only" regex was tried and removed: any such
regex is a denylist, and adversarial review kept finding forms it missed, so the
only defensible degraded behavior is to block everything. Degraded mode does
**not** replace a missing Seatbelt install.

## Provenance

`vendor/validate-bash-command.sh` is this project’s **in-tree shell analyzer**,
MIT-licensed, owned and maintained here. It originally entered the repo as a
snapshot of an earlier MIT-licensed analyzer by the same author, written for
unrelated tooling. That earlier work is provenance only — not a dependency,
submodule, or sync source. Analyzer fixes land in this repo; see
[`vendor/README.md`](vendor/README.md). A future maintainability track may add
local AST/tree-sitter fast-path classification for **performance** — that is
**not** a security boundary. Containment and credential architecture work come
first.

## Contributing

Bug reports and feature requests via [issues](../../issues) are welcome —
especially a command the guard gets wrong in either direction. External pull
requests are not accepted; forking is explicitly permitted. See
[CONTRIBUTING.md](CONTRIBUTING.md) and [.github/SUPPORT.md](.github/SUPPORT.md).

Security issues go through a
[private advisory](../../security/advisories/new), not a public issue.

## License

MIT
