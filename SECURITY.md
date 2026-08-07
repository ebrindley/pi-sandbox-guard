# Security Policy

Please report suspected bypasses or security issues privately before opening a
public issue. Include the command, launcher, operating system version, runtime
(`pi` or `omp`) and version, and whether the macOS Seatbelt layer was active.

Private reporting channel: open a
[private security advisory](https://github.com/ebrindley/pi-sandbox-guard/security/advisories/new).
That is the only private channel. No email address is published, so please do
not go looking for one. Do not include secrets in the initial report.

If that link does not offer you a reporting form, private reporting is not
enabled on the repository yet: please open a **public issue containing no
exploit detail**. Just say you have a private report to make, and it will be
enabled so you can file properly.

This is a personal project with a single maintainer and no bug bounty. Reports
are acknowledged on a best-effort basis; reporters are credited in release notes
on request. Public issues are for bugs, including wrong verdicts, while a
reliable way to make the guard allow something catastrophic, or to disarm it,
belongs in an advisory.

## What this project is

This project is a **macOS Seatbelt write-containment boundary** around Pi and
Oh My Pi (OMP), plus a
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
| Provider-token secrecy from the agent process and tool children | Out of scope (see below) |
| Outbound network restriction | Out of scope (network remains open) |
| Process availability / fork bombs / resource exhaustion caps | Out of scope (optional CPU ulimit only) |
| Integrity of the current working tree under `PROJECT` | Out of scope (PROJECT is intentionally writable) |
| Integrity of the Node interpreter itself, on filter-only installs | Out of scope (see below) |

**The Node interpreter is trusted; its contents are not re-verified.** A
deployed analyzer canonicalizes paths using the absolute Node path written to
its `.guard-node` binding during deployment. Source-tree use falls back to
`process.execPath`. This distinction is required because compiled OMP reports
its application binary as `process.execPath`. Pinning Node absolutely prevents *shadowing*
(no PATH entry or repo-local `node` can win a lookup, because there is no lookup),
but it does not make the file immutable. If Node lives somewhere the agent can
write, that file can be replaced after startup and later canonicalizations would
run the replacement, which could report attacker-chosen paths and cause a
destructive command to be misclassified as safe.

The protected launcher rejects a pinned Node path under its active `PROJECT`,
`TMPDIR`, Pi/OMP state, or the fixed writable cache roots. Filter-only use has
no launcher check. `PROJECT` is not the only
writable root: the profile also allows writes under `TMPDIR`, `/private/tmp`,
active Pi/OMP runtime state, `~/.npm`, `~/.cache`, and `~/Library/Caches`. A Node installed
under any of those, such as a version manager or corepack shim in `~/.cache`,
remains replaceable by the sandboxed agent.

**Two conditions, and which one applies depends on your deployment:**

- *With the protected launcher*: Node must live outside every active writable
  root. Deployment rejects fixed unsafe roots and launch re-checks dynamic roots.
  A user-cache or project-local install fails this; a Homebrew install under
  `/opt/homebrew` passes.
- *Filter-only (no Seatbelt)*: location buys nothing, because nothing is denying
  writes. Only **ownership** helps: the Node binary and every directory on its
  path must not be writable by the account the agent runs as. macOS ships no
  `node`, and a default Homebrew install on Apple Silicon is *user*-owned
  (`/opt/homebrew` belongs to the installing user, not root), so the common setup
  does **not** satisfy this. Install Node to a root-owned location, or run under
  Seatbelt.

Applying the sandbox profile without the protected launcher is not on its own a
mitigation for this concern, and neither is an absolute path.

Re-hashing or re-resolving the interpreter per invocation would not close it
either: the check and the exec remain distinct moments.

**OMP mixed database limitation.** OMP stores operational data and credentials
together in `agent.db`. Normal OMP operation requires that database and its
SQLite sidecars remain writable, so this guard cannot provide Pi-style
file-level auth tamper resistance for OMP. OMP plugins, extensions, hooks, tools,
prompts, rules, and file-based configuration remain read-only in protected mode.

**Provider tokens and per-tool secret isolation** cannot be solved by denying
`~/.pi/agent/auth.json` writes alone. Agents and tool children typically need
provider credentials in-process. True per-tool isolation requires **upstream
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
still confined the write blast radius. Do not treat Seatbelt confinement as
proof that secrets or repo integrity were preserved.
