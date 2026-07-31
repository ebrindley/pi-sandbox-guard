# Architecture

How [pi-sandbox-guard](../README.md) is built, what each layer guarantees, and
where each one fails. Two layers, and the weaker one is not the fail-safe:

1. **The bash filter** ([layer 1](#layer-1-the-bash-filter)) is a pre-execution
   policy hook on Pi's `bash` tool. Good error messages and confirm prompts; it
   sees only the literal command string and can be bypassed by dynamic exec.
2. **The Seatbelt OS sandbox** ([layer 2](#layer-2-the-seatbelt-os-sandbox)) is
   the **primary** boundary. Catches what the filter cannot: dynamic exec,
   mutated input, non-bash writes outside the project, subprocess escapes.

Pi has **no built-in sandbox** by design (its own `security.md` says isolation
"needs to come from the operating system or a virtualization/container
boundary"). So we wrap the launcher in macOS Seatbelt (`sandbox-exec`), the same
mechanism Chrome, VS Code, Codex CLI, and Claude Code use.

> **Deprecation exposure:** Apple marks `sandbox-exec` as deprecated, but it
> remains functional and load-bearing for the tools above. If Apple ever removes
> it, the successor path is likely the Containerization / app-sandbox tooling;
> deploy-time probes should fail loudly rather than silently installing a
> non-functional profile.

Scope and non-goals: [SECURITY.md](../SECURITY.md). Install and host setup:
[SETUP.md](SETUP.md).

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

---

# Layer 1: the bash filter

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

**Degraded mode.** When the guard is unavailable (missing analyzer, missing helper
binaries, or win32), the adapter **blocks all bash commands** unconditionally.
A partial "block destructive commands only" regex was tried and removed: any such
regex is a denylist, and adversarial review kept finding forms it missed, so the
only defensible degraded behavior is to block everything. Degraded mode does
**not** replace a missing Seatbelt install.

## Guard hardening

Each item closes a specific failure that adversarial review found in an earlier
revision; none is speculative hardening. This was self-review, not an external
audit. The launcher/Seatbelt containment track is
[layer 2](#layer-2-the-seatbelt-os-sandbox).

| Risk | Mitigation |
|---|---|
| Command injection into the guard | `spawn('/bin/bash', [script])` + command via **stdin only**; never `ctx.exec`/shell strings |
| Repo-local `jq`/`awk` hijack | Subprocess runs with a **fixed trusted `PATH`**, not the ambient/project PATH; the canonicalizer's Node is pinned to an absolute path, so it is not resolved through any PATH at all |
| Repo `.env` disarming the guard (`CLAUDE_ALLOW_RM_RF=1`) | **No `process.env` passthrough**; only an allow-listed, host-supplied `trustedPolicyEnv` reaches the subprocess |
| Pi has no hard kill → hung agent | Adapter-owned **timeout → SIGTERM the process *group* → SIGKILL** → block |
| Fragile `decision:reason` parsing | Decision = **exit code only**; stderr is display-only |
| Relative-path fail-open (`cd /tmp && rm -rf .`) | Subprocess `cwd` set to the **bash tool's intended cwd** |
| Missing deps silently weaken analysis | **Functional preflight**: each helper (`bash`/`jq`/`awk`) is *executed* (no-op probe) on the trusted PATH, and the pinned Node is probed separately, so a present-but-broken helper is caught at load, not per-command; degrade to **block all bash** if any fails |
| ANSI-C quoted command words (`$'rm' -rf /`) evade the analyzer | **Reveal-only probe**: the original command is always analyzed as-is; ANSI-C spans are also decoded and emitted as single-quoted literals (bash-faithful), so the revealed verb reaches the analyzer without decoded data becoming syntax, and the **worst verdict wins**. Closes direct command-word cases; executor operands (`xargs 'rm'`) reduce to a quoted utility word, which the analyzer treats as the ask tier. See [Known analyzer gaps](#known-analyzer-gaps) |
| Windows (no bash) | Detected at preflight → **block all bash**, no fragile WSL spawning |
| Oversized command | Commands > **32 KB** are blocked before reaching the analyzer (matches analyzer's own size cap) |

## Known analyzer gaps

Fail-open (or otherwise notable) verdicts in this repository's
`validate-bash-command.sh`, and what the guard layer does about each.

**Where the corpus keeps this honest:** a gap pinned with `expectFail: true`
in [`test/corpus/corpus.json`](../test/corpus/corpus.json) also pins its current real
verdict, and the corpus runner **fails `npm test` the moment that verdict moves in
either direction**, so a fix cannot land unnoticed. Updating the prose here is
still a human step; the runner asks for it, it cannot force it. (That
mechanism exists because an earlier version of this section kept describing an
already-fixed gap as open.)

That tripwire covers the gaps narrow enough to pin as a single command. The
broad classes below (fully dynamic execution most of all) cannot be pinned that
way, because there is no one command whose changed verdict would prove the class
closed. Those are held by the characterization cases and by review, not by an
automatic tripwire. Read a status here as documented intent, not as a
machine-verified claim.

Status legend:

- **OPEN (fail-open)**: the analyzer allows something it should block, and no
  guard-level mitigation covers it. The OS sandbox layer is the backstop.
- **MITIGATED**: the analyzer-level gap still exists, but the guard closes it
  before/around the analyzer.
- **FIXED**: kept as history so the corpus case documents the regression test.

### 0. Backslash-newline line continuations: MITIGATED (guard-level probe)

**Analyzer status:** fail-open. **Guard status:** blocked.

Bash removes `\<newline>` line continuations *before* tokenization, so
`r\<newline>m -rf /` runs as `rm -rf /`. The analyzer does not preprocess these
(independent of ANSI-C; plain reassembly slips past too). The guard adds a
reveal-only probe variant that strips continuations and analyzes the result,
worst-of merged. It composes with the ANSI-C probe (`$'r'\<newline>m -rf /` is
caught). Continuation removal is context-free in bash, so the transform is
exact and corpus-pinned; benign multi-line commands (`git commit \<newline> -m …`)
stay allowed.

### 1. ANSI-C quoted command words: MITIGATED (guard-level probe)

**Analyzer status:** still fail-open on raw `$'...'` as a *command word*.
**Guard status:** blocked for direct command words and for executor operands
that reduce to a quoted utility (see the FIXED history under gap 3).

ANSI-C quoting (`$'...'`) lets the shell assemble a command word at parse time.
The analyzer does not normalize ANSI-C quoted command words natively, so it
allows:

```bash
$'rm' -rf /
$'r'$'m' -rf /
$'\x72\x6d' -rf /
```

**Mitigation:** `guard-core.mjs` runs a *reveal-only* ANSI-C probe. The original
command is always analyzed as-is; when it contains `$'...'` spans, a decoded
variant is analyzed too and the **worst verdict wins**. Each decoded span is
emitted as a **single-quoted literal**, which keeps a revealed command word
(`$'rm'` → `'rm'`, `$'r'm` → `'r'm`) visible to the analyzer while neutralizing
decoded `;`/`|`/`&` so they can't fake a command chain (`echo $'; rm -rf /'`
stays a benign echo). The scanner is context-aware:

- `$(...)`/backtick substitutions re-enter command context even inside double
  quotes, so `echo "$($'rm' -rf /)"` is revealed;
- nested `shell -c "…"` payloads are reparsed by the inner shell, so
  `bash -c "$'rm' -rf /"` and the escaped-dollar form `bash -c "\$'rm' -rf /"`
  are revealed;
- decoded **newlines are preserved** (not stripped): as a `shell -c` argument a
  decoded newline is a real command separator in the inner shell
  (`bash -c $'echo ok\nrm -rf /'` runs the `rm`), so the probe must expose the
  second line. The cost is that a plain multiline `echo $'a\nrm -rf /'` may be
  over-flagged: a deliberate reveal-only trade (never fail open > avoid false
  asks).

A probe inaccuracy can therefore only over-block, never fail open. Covered by
corpus cases and `test/smoke.mjs`.

Other quoting variants (`'rm' -rf /`, `"rm" -rf /`, `\rm -rf /`) are handled by
the analyzer natively, and are corpus-pinned.

**Executor operands:** the probe reduces `xargs $'rm'` to `xargs 'rm'`. The
analyzer now treats quoted executor utility words the same as unquoted ones
(warn tier), so that composition is closed. See the gap 3 FIXED history.

### 2. `shred`, `truncate`, and builtin-redirect writes to critical paths: FIXED

Previously the analyzer's device/critical-path rules keyed on a closed verb set
(`dd`, `mkfs`, `wipefs`, `rm`, `mv`, `cp`, …) and a single redirect form
(`> /dev/sd[a-z]`), so these were **allowed**:

```bash
shred /dev/sda          # was ALLOWED: raw device destruction
truncate -s 0 /etc/passwd   # was ALLOWED: critical file truncation
: > /etc/passwd         # was ALLOWED, builtin redirect, no command word
```

**Fix (analyzer):**

- `shred` is in the device-destroy verb group with `wipefs`/`blkdiscard`/… and
  requires a `/dev/` operand (`shred /tmp/x` stays allow).
- `truncate` and `shred` are in the critical-directory verb list with `rm`/`mv`/`cp`
  (`truncate -s 0 /etc/passwd` blocks; project-relative truncate stays allow).
  Path-qualified commands, quoted paths, grouped commands, literal shell
  payloads, and command substitutions are regression-pinned.
- Quote-aware extraction of output redirect targets (`>`, `>>`, `>|`, `>&file`,
  `&>`, fd-prefixed) whose lexically normalized target is a critical root
  (`/etc`, `/usr`, …) or raw block device node. Quoted operators used as data
  stay allowed.

Corpus-pinned (malicious + benign controls).

### 3. Fully dynamic execution: OPEN by design

The analyzer operates on the literal command string only. Destructive intent
assembled at runtime is not statically detectable:

```bash
eval "$PAYLOAD"
cmd="rm -rf /"; $cmd
```

This is a fundamental constraint of static analysis, documented in both the
analyzer and this file. Note the analyzer does better than a blanket
out-of-scope: `xargs rm` has an explicit warn rule (**ask** tier, corpus-pinned),
and quoted forms (`xargs 'rm'`, `parallel 'rm'`, `find . -exec 'rm' …`) now match
the same tier via quote-aware utility-word checks.

**ANSI-C reconstructed via outer-shell quote removal in a nested `shell -c`
(OPEN, fail-open, accepted static-analysis boundary).** The analyzer recurses
into `shell -c` payloads and even resolves the single-quote-escape idiom for a
*plain* verb, `bash -c 'r'\''m'\'' -rf /'` blocks. What slips past is the idiom
reassembling an **ANSI-C** span for the inner shell to decode:

```bash
bash -c 'r'\''m'\'' -rf /'      # BLOCKED , analyzer resolves the reassembled `rm`
bash -c '$'\''rm'\'' -rf /'     # ALLOWED , reassembles `$'rm'`; inner shell decodes it, analyzer does not
```

The guard's ANSI-C probe cannot help: the `$'rm'` bytes are **not contiguous** in
the source, they are reconstructed by outer-shell quote removal, so there is no
`$'...'` span for the probe to decode. (Contiguous forms ARE covered:
`bash -c "$'rm' -rf /"` and `bash -c "\$'rm' -rf /"` both block.) Closing this
needs the analyzer to decode ANSI-C on reassembled `shell -c` operands, the same
dynamic-assembly class as `eval` (gap 3), and is backstopped by the OS sandbox.

Corpus pins this with `expectFail: true` / `actual: "allow"` so a future fix
surfaces as a test failure asking for a deliberate corpus + docs update.

**Executor + quoted command word, FIXED.** Executor warn-rules previously
matched only an *unquoted* command word, so a quoted verb slipped past:

```bash
echo /etc/passwd | xargs 'rm'      # now ASK (same as unquoted xargs rm)
echo /etc/passwd | xargs $'rm'     # now ASK (probe -> xargs 'rm')
parallel 'rm' ::: /etc/passwd      # now ASK
find . -exec 'rm' -rf {} \;        # now ASK (find /etc … still BLOCK via path rule)
```

The analyzer tokenizes with the quote-aware lexer and treats the utility word
after `xargs` / `parallel` / `find -exec` like a dequoted `rm` (warn tier).
Protected-path find forms remain block-tier. Benign controls (`xargs echo`,
`find . -exec echo`, `parallel echo`) stay allow.

### 4. Protected path as first operand: FIXED (regression-pinned)

An earlier snapshot of the analyzer allowed `rm /etc/passwd` and `mv /etc /tmp/etc.bak`
because the critical-directory regex required a preceding field. The current
snapshot blocks both. Kept here because the corpus pins the fixed behavior
(`rm /etc/passwd` → block, `mv /etc /tmp/etc.bak` → block, `sudo` variants
included) so a future analyzer change cannot silently reintroduce it.

### 5. Literal interpreter payloads: FIXED (v3.15); dynamic payloads remain OPEN

**Literal payloads (FIXED / regression-pinned).** The analyzer previously allowed
destructive intent expressed only inside a language runtime one-liner, the
command word was `python3`/`node`/`perl`/`ruby`/`awk`, so shell-level `rm`/`chmod`
rules never saw the body. v3.15 adds a conservative scan of *literal* code
strings for:

| Form | Example |
|---|---|
| `python` / `python3` `-c` | `python3 -c 'shutil.rmtree("/etc")'` |
| `node` `-e` / `--eval` | `node -e 'require("fs").rmSync("/",{recursive:true})'` |
| `perl` / `ruby` `-e` | `perl -e 'unlink "/etc/passwd"'` |
| `awk` program with `system()` | `awk 'BEGIN{system("rm -rf /")}'` |

Verdicts:

- **BLOCK** when a dangerous filesystem/process API clearly targets a protected
  root or device (`/`, `/etc`, `/dev`, …), including shell catastrophe strings
  inside `os.system` / `system()`.
- **ASK** for dangerous APIs without a protected target
  (`os.remove("/tmp/x")`, `shutil.rmtree("build")`), command-execution APIs
  (`os.system(cmd)`, `child_process.exec`, `awk system("echo hi")`), process-kill
  / fork shapes, and ambiguous dynamic evaluation (`eval(x)`,
  `exec(open("f").read())`).
- **ALLOW** for ordinary one-liners: `print` / `console.log`, JSON parse, version
  checks, safe math. Mere *mentions* of an API name inside a string
  (`print("os.system is a name")`) stay allowed; only CALL shapes trip the scan.

Corpus-pinned across malicious and benign forms.

**Dynamic interpreter behavior (still OPEN by design).** The scan only sees
bytes present on the command line. These remain out of scope (sandbox-backstopped),
same fundamental limit as gap 3:

```bash
python3 -c "$CODE"                 # payload is a shell variable
node -e "$(cat payload.js)"        # payload from command substitution
python3 evil.py                    # code lives in a file, not the argv string
python3 -c "exec(bytes.fromhex(h))"  # intent assembled only at runtime
```

Closing the dynamic class would require runtime interception or full program
analysis, not a static argv string matcher. Do not re-label these as FIXED when
only the literal path is covered.

### What the gaps add up to

pi-sandbox-guard is a **best-effort guard** at this layer, not an airtight
barrier, even when the analyzer is fully healthy. It significantly raises the bar
for accidental catastrophic commands and handles the common explicit patterns
well. It does not constitute a security boundary against a determined or informed
adversary, that is what
[layer 2](#layer-2-the-seatbelt-os-sandbox) is for.

Open gaps should be fixed in this repository's
`src/validate-bash-command.sh`; the corpus turns a change to any behavior it
covers into an explicit verdict diff.

---

# Layer 2: the Seatbelt OS sandbox

This is the **primary out-of-project write boundary**. Even if the filter above
is bypassed (dynamic exec, mutated `event.input`, an analyzer gap, or a bug), the
kernel still confines **writes** from Pi and its subprocesses to a small boundary
and denies reads of selected high-value host credential paths.

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
| Provider-token secrecy from Pi / tool children | Tokens needed in-process; see [SECURITY.md](../SECURITY.md), needs broker/VM/upstream, not only `auth.json` write-deny |
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

- `npm run deploy:all`, preflight both artifacts, one shared release identity,
  partial-failure reporting / safe rollback where possible
- `npm run status`, read-only source vs installed hash / identity check (no
  auth state)
- Explicit hook setup (e.g. `npm run setup:hooks`), **replaces** relying on
  package `prepare` to mutate `core.hooksPath` on install

Component-only deployment remains available through `deploy` and
`deploy:launchers` (see [SETUP.md](SETUP.md)).

## The boundary

**Writable:**
- the **project**, resolved in priority order: `PI_PROJECT` if set → else
  `git rev-parse --show-toplevel` (so launching from a subdir makes the whole repo
  writable) → else the current directory `$PWD`. The `$PWD` fallback means a
  **brand-new, not-yet-git directory works**, the agent can `git init` and
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
- `~/.pi/agent/security-events.log`, the analyzer logs the **full text** of
  every flagged command there; appending still works but the sandboxed process
  cannot read the history back

**Write-re-denied after the PROJECT allow** (symlink defense; last-match-wins):
credential subtrees (`~/.ssh`, `~/.aws`, `~/.docker`, `~/.gnupg`, `~/.kube`,
`~/.config/{gh,gcloud}`) plus the poisonable single files `~/.git-credentials`,
`~/.config/git/credentials`, `~/.netrc`, `~/.npmrc`, and `~/.secrets`, a write
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
profile does not yet cover, see **Persistence risks** below. Git run *through*
the protected `pi` shim stays confined regardless; the danger is the **next
unsandboxed** host `git`/build.

**Network:** not restricted, `web_search`/`web_fetch` and any local model server
must work. Filesystem write-containment is the high-value
layer; an outbound allowlist is a separate product decision.

**Resource limits:** conservative `ulimit` (file size ~2 GB, core off; optional
`PI_RLIMIT_CPU`). No process-count cap, it broke `fork()` at low values.

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
| **Nested handling** | Transparent own-shim re-entry only with a matching profile digest plus behavioral boundary probes; generic `CODEX_SANDBOX` / `SANDBOX_*` markers alone are **not** equivalent policy, unknown parent sandboxes fail closed |
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

A non-git directory is **not** refused, it falls back to `$PWD` (so new projects
work). Refusal is strictly about over-broad boundaries, not "is this a repo".

### Bypass

The protected shim intentionally pins its preamble/profile and forces sandbox mode
so a repo-local environment cannot disable it before launch. To run without the OS
sandbox, call the real Pi binary directly, such as `/opt/homebrew/bin/pi`; the
guard extension may still load, but the Seatbelt layer is bypassed.

## Persistence risks (hooks, submodules, worktrees)

Even with active-hook write denials, treat the following as **live operational
risks**, not fully solved problems:

1. **Planted content inside PROJECT**, scripts, CI configs, build files, and
   source that run later **outside** Seatbelt when *you* invoke unsandboxed tools.
2. **`core.hooksPath` / git config**, writable `.git/config` can still influence
   future unsandboxed git behavior; ACTIVE_HOOKS denial reduces but does not
   eliminate all git-mediated persistence designs.
3. **Submodules and linked worktrees**, additional hook and metadata paths exist
   under `.git/modules/**` and worktree git dirs; profile coverage is aimed at
   those surfaces, but operators should still inspect submodule/worktree changes.
4. **Unsandboxed follow-up commands**, `git commit`/`push`, `npm install`,
   `make`, IDE tasks, and CI on a developer machine execute project-controlled
   code without this Seatbelt profile.

**Rule:** after an agent session, **review the diff** (and submodule/worktree
pointers) before running unsandboxed git or builds. Prefer running those steps
only on reviewed state. Committed history helps recovery; uncommitted secrets do
not.

## Known limitations (need an unsandboxed direct Pi run)

- **Private npm registries / auth**: `~/.npmrc` is read-denied and
  `NPM_CONFIG_USERCONFIG=/dev/null` is set, so public npm works but private
  registries/tokens/proxies do not.
- **git over SSH**: `~/.ssh` is read-denied, so `git push`/`pull` over SSH fails.
  The launcher also clears `SSH_AUTH_SOCK` before exec. HTTPS git works.
- **Project `.env` reads**: denied even inside the project. Tools that load
  `.env` at runtime won't see it under the sandbox.
- **Writing outside the project**: by design. If a task legitimately needs to
  write elsewhere, set `PI_PROJECT` to a wider safe project root or call the real
  Pi binary directly for an unsandboxed run.
- **Network and general reads are intentionally not blocked.** The sandbox
  denies selected credential reads and confines writes; it is not a complete
  confidentiality boundary or outbound-network control.
- **Provider tokens in the Pi process**: write-denying `auth.json` stops
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
  ("Operation not permitted"), and a plain `echo > $HOME/file` is *not* something
  the analyzer would flag, demonstrating the layers are complementary
- `settings.json` / `extensions/` tamper denied; `~/.ssh` read denied
- home canary untouched; zero spurious EPERM warnings

To re-verify the profile alone at any time, run `npm run test:sandbox-profile`
(the standalone, non-installing form of the deploy-time probes; the deploy path
runs the same script). `npm run deploy:launchers` runs it as its pre-install gate.
