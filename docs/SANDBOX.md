# OS Sandbox Layer (macOS Seatbelt)

This is the **primary out-of-project write boundary** under the
[pi-sandbox-guard](../README.md) stack. The bash analyzer / guard extension is a
**UX and best-effort filter** *inside* Pi (clear block/ask messages on literal
catastrophic bash). This Seatbelt layer is the **kernel fail-safe** *around* Pi:
even if the analyzer is bypassed (dynamic exec, mutated `event.input`, an
analyzer gap, or a bug), the kernel still confines **writes** from Pi and its
subprocesses to a small boundary and denies reads of selected high-value host
credential paths.

Pi has **no built-in sandbox** by design (its own `security.md` says isolation
"needs to come from the operating system or a virtualization/container
boundary"). So we wrap the launcher in macOS Seatbelt (`sandbox-exec`), the same
mechanism Chrome, VS Code, Codex CLI, and Claude Code use.

> **Deprecation exposure:** Apple marks `sandbox-exec` as deprecated, but it
> remains functional and load-bearing for the tools above. If Apple ever removes
> it, the successor path is likely the Containerization / app-sandbox tooling;
> deploy-time probes should fail loudly rather than silently installing a
> non-functional profile.

## Role of each layer

| | Guard extension (analyzer) | Seatbelt sandbox |
|---|---|---|
| Role | Best-effort UX filter on `bash` tool strings | **Primary** out-of-project write boundary |
| Understands intent (`rm -rf /`), nice messages, ask-to-confirm | ✅ | ❌ (raw EPERM) |
| Catches **dynamic / obfuscated** exec (`eval`, `$'rm'`, `xargs rm`) | partial / no | ✅ for *write* blast radius |
| Survives a **mutated `event.input`** / another extension | ❌ | ✅ |
| Confines **non-bash** writes (Pi `edit`/`write`, subprocesses) | ❌ | ✅ |
| Confines **raw FS blast radius** outside the project | no | ✅ |
| Guarantees integrity of files **inside** PROJECT | ❌ | ❌ (PROJECT is writable by design) |
| Fork bomb / resource exhaustion | detects some literals | ❌ (no process-count cap) |
| Network / general confidentiality | ❌ | ❌ (deliberate) |

Neither replaces the other. The analyzer reduces operator friction; Seatbelt is
the containment airbag. **Do not treat a green analyzer verdict as a security
proof.**

## PROJECT is intentionally writable

The project root is a **write-allowed** Seatbelt parameter so the agent can edit
source. That is a product requirement, not a hole we forgot to close.

**Neither layer guarantees current-repository integrity.** Inside PROJECT the
agent may rewrite code, delete uncommitted work, plant scripts, or alter git
metadata that remains writable. Committed history may still be recoverable;
**secrets and uncommitted work are not.** Review agent-produced diffs before any
**unsandboxed** git, build, test, or deploy step that would execute
project-controlled content (hooks, `package.json` scripts, Makefiles, etc.).

## Out of scope (not claimed)

| Concern | Why |
|---|---|
| General confidentiality | Most project files remain readable; only selected host paths and `.env` are read-denied |
| Provider-token secrecy from Pi / tool children | Tokens needed in-process; see [SECURITY.md](../SECURITY.md) — needs broker/VM/upstream, not only `auth.json` write-deny |
| Open network | `web_search` / local model servers / package installs require it; no egress allowlist today |
| Process availability | No process-count cap; optional `PI_RLIMIT_CPU` only |

## Files

| Repo path | Deploys to | Role |
|---|---|---|
| `sandbox/pi-sandbox.sb` | `~/.local/bin/pi-sandbox.sb` | SBPL profile (the boundary) |
| `sandbox/pi-sandbox-preamble.zsh` | `~/.local/bin/pi-sandbox-preamble.zsh` | Shared preamble: boundary calc, fail-closed checks, builds the `sandbox-exec` argv |
| `launchers/pi` | `~/.local/bin/pi` | Protected PATH entrypoint that wraps the real Pi binary |
| `launchers/example-custom` | (template; not auto-installed) | Documented contract for custom wrappers opted in via `--extra-launchers` |
| `scripts/deploy-launchers.sh` | — | Validates the profile, backs up originals, installs, stamps provenance |

## Deploy

```bash
# Coordinated path:
npm run deploy:all
npm run status            # read-only drift / release-identity check

# Two-step path (current package.json scripts):
npm run deploy            # guard extension -> ~/.pi/agent/extensions/
npm run deploy:launchers  # shim + profile -> ~/.local/bin
```

`deploy:launchers` **validates before installing** (and refuses on any failure)
by delegating to `scripts/test-sandbox-profile.sh` (forced real run, never
skipped): the profile must compile and apply; an in-project write must be
allowed; active-hook writes must be denied while routine `.git/config` stays
writable; a write to the real home dir must be denied; `~/.pi/agent/sessions`
writable but `settings.json` / `auth.json` / `trust.json` / prompt files /
`extensions/` writes denied; `~/.ssh` and project `.env` reads denied; a project
`.pem` read allowed (no over-restriction). It backs up any existing launcher to
`*.bak.<timestamp>` and writes `~/.local/bin/.pi-sandbox-launchers-version` (git
sha + dirty flag + profile hash).

The same live probes are available standalone via
`npm run test:sandbox-profile` (and as part of `npm test` on macOS). On a host
without `sandbox-exec` they **skip** with exit 0 so portable CI stays green;
set `PI_SANDBOX_PROFILE_STRICT=1` to force a real run (the deploy path always
does).

### Deployment operations

The coordinated deploy, status/drift, and **explicit** repo git-hook setup
commands are:

- `npm run deploy:all` — preflight both artifacts, one shared release identity,
  partial-failure reporting / safe rollback where possible
- `npm run status` — read-only source vs installed hash / identity check (no
  auth state)
- Explicit hook setup (e.g. `npm run setup:hooks`) — **replaces** relying on
  package `prepare` to mutate `core.hooksPath` on install

Component-only deployment remains available through `deploy` and
`deploy:launchers` (see [SETUP.md](SETUP.md)).

## The boundary

**Writable:**
- the **project**, resolved in priority order: `PI_PROJECT` if set → else
  `git rev-parse --show-toplevel` (so launching from a subdir makes the whole repo
  writable) → else the current directory `$PWD`. The `$PWD` fallback means a
  **brand-new, not-yet-git directory works** — the agent can `git init` and
  scaffold a fresh project. Only genuinely broad roots are refused (see below).
- `$TMPDIR` (canonical, validated) and `/private/tmp`
- `~/.pi/agent` **except** `settings.json`, `auth.json`, `trust.json`,
  any `*prompt*.md`, `extensions/` (so the sandboxed Pi cannot tamper with
  config/auth/trust/prompt state or **disable the guard**)
- `~/.npm`, `~/.cache`, `~/Library/Caches` (so npm/pip/uv/playwright work)
- a narrow `/dev` set (`null`, `tty`, `stdout`, `stderr`, `fd/1`, `fd/2`, `ttys*`)

**Read-denied** (everything else is readable, including all project files except
as listed):
- `~/.ssh`, `~/.aws/{credentials,config}`, `~/.docker/config.json`,
  `~/.kube/config`, `~/.gnupg`, `~/.config/{gh,gcloud}`, Git credential stores
  (`~/.git-credentials`, `~/.config/git/credentials`), `~/.netrc`, `~/.npmrc`,
  `~/.secrets`
- `.env` files anywhere (the one project-wide secret deny)
- `~/.pi/agent/security-events.log` — the analyzer logs the **full text** of
  every flagged command there; appending still works but the sandboxed process
  cannot read the history back

**Write-re-denied after the PROJECT allow** (symlink defense; last-match-wins):
credential subtrees (`~/.ssh`, `~/.aws`, `~/.docker`, `~/.gnupg`, `~/.kube`,
`~/.config/{gh,gcloud}`) plus the poisonable single files `~/.git-credentials`,
`~/.config/git/credentials`, `~/.netrc`, `~/.npmrc`, and `~/.secrets` — a write
there would arm a credential-exfil vector for the next unsandboxed run.

Also re-denied: **active git hook trees** used for persistence/escape. The whole
project tree is writable, so without this the agent could plant a hook that later
runs **outside** the sandbox on the next unsandboxed `git` in the repo. The
implementation denies the
**effective active hooks directory**, not only the default
`PROJECT/.git/hooks`:

- default `PROJECT/.git/hooks` (active names; inert `*.sample` re-allowed for
  `git init`)
- `core.hooksPath` targets such as `PROJECT/.githooks` when that is the active
  hooks path (**ACTIVE_HOOKS** parameter)
- linked worktree and submodule metadata hooks under paths such as
  `PROJECT/.git/modules/**/hooks` when they are part of the active hooks surface

`.git/config` remains writable for routine `git remote` / tracking use. That
means residual risk remains if config can repoint hooks or aliases in ways the
profile does not yet cover — see **Persistence risks** below. Git run *through*
the protected `pi` shim stays confined regardless; the danger is the **next
unsandboxed** host `git`/build.

**Network:** not restricted — `web_search`/`web_fetch` and any local model server
must work. Filesystem write-containment is the high-value
layer; an outbound allowlist is a separate product decision.

**Resource limits:** conservative `ulimit` (file size ~2 GB, core off; optional
`PI_RLIMIT_CPU`). No process-count cap — it broke `fork()` at low values.

## Environment trust and pre-sandbox hardening

The protected launcher/preamble is the **environment trust root**. Before
`sandbox-exec` applies, a hostile ambient environment must not redefine what
"safe" means. Implemented hardening:

| Area | Intent |
|---|---|
| **PATH** | No ambient PATH execution for security-critical pre-sandbox tools; pin absolute trusted paths; sanitize PATH without breaking trusted Homebrew Pi resolution |
| **Identity** | Derive login home/identity from system sources (`/usr/bin/id`, directory services), not ambient `USER` spoofing |
| **TMPDIR** | Canonicalize and validate before passing to Seatbelt; reject `TMPDIR=/`, `TMPDIR=$HOME`, project roots, and other wideners; accept normal Darwin per-user temp and `/private/tmp` |
| **Config** | Pin executable config to trusted host state (`~/.config/pi-sandbox-guard/…`); refuse repo-controlled ambient `PI_EXECUTABLE_CONFIG`; apply trusted-prefix rules to absolute paths from config |
| **Nested handling** | Transparent own-shim re-entry only with a matching profile digest plus behavioral boundary probes; generic `CODEX_SANDBOX` / `SANDBOX_*` markers alone are **not** equivalent policy — unknown parent sandboxes fail closed |
| **Active hooks** | Deny effective active hooks trees (see above), including hooksPath / worktree / submodule surfaces as integrated |

Trust model summary: **host install + protected shim + Seatbelt profile** are
trusted; **PROJECT contents and ambient repo env** are not.

## Fail-closed behavior

The protected `pi` shim **refuses to start** (rather than running Pi
unprotected) when:
- `sandbox-exec` or the profile is missing
- the project boundary resolves to a **broad/unsafe root**: `/`, `$HOME`,
  `/Users`, `/Volumes`, `/tmp`, `/private/tmp`, system prefixes, or sensitive
  home subtrees such as `~/.ssh`, `~/.aws`, `~/.config`, `~/.docker`, `~/.gnupg`,
  `~/.kube`, `~/Library`, `~/Desktop`, `~/Documents`, or `~/Downloads`
- the project boundary would contain the sandbox install directory itself
- nested re-entry cannot prove expected confinement (strict nested handling)

When the transparent `pi` shim is re-entered from an **already correctly
confined** own-shim session (e.g. a subagent invoking `pi` again through PATH),
it may pass through to the real Pi instead of double-wrapping. Explicit
non-transparent launchers retain fail-closed nested-sandbox behavior. Unknown
parent sandboxes are not trusted by env marker alone.

A non-git directory is **not** refused — it falls back to `$PWD` (so new projects
work). Refusal is strictly about over-broad boundaries, not "is this a repo".

### Bypass

The protected shim intentionally pins its preamble/profile and forces sandbox mode
so a repo-local environment cannot disable it before launch. To run without the OS
sandbox, call the real Pi binary directly, such as `/opt/homebrew/bin/pi`; the
guard extension may still load, but the Seatbelt layer is bypassed.

## Persistence risks (hooks, submodules, worktrees)

Even with active-hook write denials, treat the following as **live operational
risks**, not fully solved problems:

1. **Planted content inside PROJECT** — scripts, CI configs, build files, and
   source that run later **outside** Seatbelt when *you* invoke unsandboxed tools.
2. **`core.hooksPath` / git config** — writable `.git/config` can still influence
   future unsandboxed git behavior; ACTIVE_HOOKS denial reduces but does not
   eliminate all git-mediated persistence designs.
3. **Submodules and linked worktrees** — additional hook and metadata paths exist
   under `.git/modules/**` and worktree git dirs; profile coverage is aimed at
   those surfaces, but operators should still inspect submodule/worktree changes.
4. **Unsandboxed follow-up commands** — `git commit`/`push`, `npm install`,
   `make`, IDE tasks, and CI on a developer machine execute project-controlled
   code without this Seatbelt profile.

**Rule:** after an agent session, **review the diff** (and submodule/worktree
pointers) before running unsandboxed git or builds. Prefer running those steps
only on reviewed state. Committed history helps recovery; uncommitted secrets do
not.

## Known limitations (need an unsandboxed direct Pi run)

- **Private npm registries / auth** — `~/.npmrc` is read-denied and
  `NPM_CONFIG_USERCONFIG=/dev/null` is set, so public npm works but private
  registries/tokens/proxies do not.
- **git over SSH** — `~/.ssh` is read-denied, so `git push`/`pull` over SSH fails.
  The launcher also clears `SSH_AUTH_SOCK` before exec. HTTPS git works.
- **Project `.env` reads** — denied even inside the project. Tools that load
  `.env` at runtime won't see it under the sandbox.
- **Writing outside the project** — by design. If a task legitimately needs to
  write elsewhere, set `PI_PROJECT` to a wider safe project root or call the real
  Pi binary directly for an unsandboxed run.
- **Network and general reads are intentionally not blocked.** The sandbox
  denies selected credential reads and confines writes; it is not a complete
  confidentiality boundary or outbound-network control.
- **Provider tokens in the Pi process** — write-denying `auth.json` stops
  *tampering* with stored auth from inside the sandbox; it does **not** hide
  tokens already loaded by Pi or tool children. See [SECURITY.md](../SECURITY.md).

## What is fixed vs structural

| Class | Examples |
|---|---|
| **Repo-local / fixable here** | Broad PROJECT root refusal, extensions write-deny, selected credential read/write denies, active hooks subtree denials, preamble PATH/identity/TMPDIR hardening, deploy-time profile probes |
| **Structural / upstream** | Static analyzer gaps (`eval`, runtime-assembled commands, …), Pi extension mutation order, provider credential architecture |
| **Deliberate scope** | PROJECT writable, open network, no process-count cap, no VM |

## Verification (proven live)

Via a sandboxed launcher against a local model, in a git project whose path
contains a space:
- in-project write **succeeds**; write to `$HOME` is **kernel-denied**
  ("Operation not permitted") — and a plain `echo > $HOME/file` is *not* something
  the analyzer would flag, demonstrating the layers are complementary
- `settings.json` / `extensions/` tamper denied; `~/.ssh` read denied
- home canary untouched; zero spurious EPERM warnings

To re-verify the profile alone at any time, run `npm run test:sandbox-profile`
(the standalone, non-installing form of the deploy-time probes; the deploy path
runs the same script). `npm run deploy:launchers` runs it as its pre-install gate.
