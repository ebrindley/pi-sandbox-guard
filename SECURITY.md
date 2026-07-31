# Security Policy

Please report suspected bypasses or security issues privately before opening a
public issue. Include the command, launcher, operating system version, Pi
version, and whether the macOS Seatbelt layer was active.

Private reporting channel: open a
[private security advisory](https://github.com/ebrindley/pi-sandbox-guard/security/advisories/new).
That is the only private channel — no email address is published, so please do
not go looking for one. Do not include secrets in the initial report.

If that link does not offer you a reporting form, private reporting is not
enabled on the repository yet: please open a **public issue containing no
exploit detail** — just say you have a private report to make — and it will be
enabled so you can file properly.

This is a personal project with a single maintainer and no bug bounty. Reports
are acknowledged on a best-effort basis; reporters are credited in release notes
on request. Public issues are for bugs — including wrong verdicts — while a
reliable way to make the guard allow something catastrophic, or to disarm it,
belongs in an advisory.

## What this project is

This project is a **macOS Seatbelt write-containment boundary** around Pi, plus a
**best-effort, UX-oriented bash analyzer** that blocks obviously destructive
commands with clear messages. It is **not** a VM, network sandbox, process
isolator, or general confidentiality boundary.

Primary boundary: **out-of-project filesystem writes** (and selected host
credential-path denies) via Seatbelt. The analyzer improves operator experience
and catches some catastrophic literal bash forms; it is **not** the fail-safe.

How both layers work, their invariants, and known analyzer gaps:
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Explicit non-goals (current scope)

The following are **outside current scope** by design, not unfinished checkboxes:

| Concern | Status |
|---|---|
| General confidentiality of project data / agent context | Out of scope |
| Provider-token secrecy from the Pi process and tool children | Out of scope (see below) |
| Outbound network restriction | Out of scope (network remains open) |
| Process availability / fork bombs / resource exhaustion caps | Out of scope (optional CPU ulimit only) |
| Integrity of the current working tree under `PROJECT` | Out of scope (PROJECT is intentionally writable) |
| Integrity of the Node interpreter itself, on filter-only installs | Out of scope (see below) |

**The Node interpreter is trusted, and that trust is not re-verified.** The
analyzer canonicalizes paths using `process.execPath` — the absolute path of the
Node binary already running the guard. Pinning it absolutely prevents *shadowing*
(no PATH entry or repo-local `node` can win a lookup, because there is no lookup),
but it does not make the file immutable. If Node lives somewhere the agent can
write, that file can be replaced after startup and later canonicalizations would
run the replacement — which could report attacker-chosen paths and cause a
destructive command to be misclassified as safe.

Seatbelt narrows this but does not by itself close it. `PROJECT` is not the only
writable root: the profile also allows writes under `TMPDIR`, `/private/tmp`,
`~/.pi/agent`, `~/.npm`, `~/.cache`, and `~/Library/Caches`. A Node installed
under any of those — a version manager or corepack shim in `~/.cache`, for
instance — remains replaceable by the sandboxed agent.

**Two conditions, and which one applies depends on your deployment:**

- *With Seatbelt* — Node must live outside *every* writable root listed in
  `sandbox/pi-sandbox.sb`. Location is what contains the swap here, because the
  profile is what denies the write. A user-cache or project-local install fails
  this; a Homebrew install under `/opt/homebrew` passes, since that is outside
  every writable root.
- *Filter-only (no Seatbelt)* — location buys nothing, because nothing is denying
  writes. Only **ownership** helps: the Node binary and every directory on its
  path must not be writable by the account the agent runs as. macOS ships no
  `node`, and a default Homebrew install on Apple Silicon is *user*-owned
  (`/opt/homebrew` belongs to the installing user, not root), so the common setup
  does **not** satisfy this. Install Node to a root-owned location, or run under
  Seatbelt.

Applying the sandbox profile is not on its own a mitigation for this concern, and
neither is an absolute path.

Re-hashing or re-resolving the interpreter per invocation would not close it
either: the check and the exec remain distinct moments.

**Provider tokens and per-tool secret isolation** cannot be solved by denying
`~/.pi/agent/auth.json` writes alone. Pi (and tool children) typically need
provider credentials in-process. True per-tool isolation requires **Pi/upstream
architecture** (e.g. a credential broker) or a **stronger isolation boundary**
(VM/container with separate identity). Documenting a file deny as "tokens are
safe" would be false confidence.

## Project integrity

`PROJECT` (git toplevel, `PI_PROJECT`, or cwd) is **intentionally writable** so
the agent can edit code. **Neither Seatbelt nor the analyzer guarantees
current-repository integrity.** The agent may delete or rewrite uncommitted work,
poison tracked files, or leave malicious diffs.

- **Committed state** may be recoverable via git history (if already committed
  and reachable).
- **Secrets and uncommitted work** are not recoverable from this guard.
- **Operational rule:** review agent-modified diffs before running unsandboxed
  `git`, build, or deploy commands that would execute project-controlled hooks,
  scripts, or binaries outside the Seatbelt boundary.

## Reporting expectations

When reporting, distinguish:

1. **Repo-local defects** (bugs in this guard/shim/profile that should be fixed
   here).
2. **Structural / upstream limits** (static analysis gaps, Pi extension ordering,
   provider credential loading).
3. **Deliberate scope** (open network, PROJECT writability, no VM).

Do not treat "the analyzer allowed X" alone as a complete failure if Seatbelt
still confined the write blast radius — and do not treat Seatbelt confinement as
proof that secrets or repo integrity were preserved.
