# pi-sandbox-guard

**Keeps [Pi](https://pi.dev) and [Oh My Pi](https://omp.sh) from writing outside your project**
(bar temp dirs and tool caches; see Scope below).

macOS-only. Uses Seatbelt (`sandbox-exec`), the same OS sandbox Chrome, VS Code,
and Codex CLI use, so there is no container, no VM, and no Docker on your Mac.

Agents wander. Pi edited a file outside the project I was working in and I did
not notice for a while. The usual macOS answers are Docker or a VM, both heavy.

This uses the sandbox already built into macOS instead. Writes and deletes
outside your project are refused by the kernel, so a wrong path fails instead of
landing.

## Install

```bash
git clone https://github.com/ebrindley/pi-sandbox-guard.git && cd pi-sandbox-guard && npm run setup
```

That deploys one bash filter, one Seatbelt profile, and the same protected launcher
as both `pi` and `omp`. It records installed runtimes and checks PATH ordering.
Pi is required; OMP is optional. Install OMP's official binary outside
`~/.local/bin` so that directory remains reserved for the protected shims.

## Use

```bash
cd /path/to/your/project && pi
# or
cd /path/to/your/project && omp
```

For an OMP profile, put the selector first: `omp --profile work`.

You should see `OS sandbox ON. Runtime [...]` at startup. That line is how you
know you are protected. If it is missing, run `npm run check:path` from the
checkout.

## Scope

Writes and deletes outside your project are blocked at the kernel, bar an
allow-list (temp dirs, tool caches, and agent runtime state). Pi config/auth and
both agents' extensions stay protected. OMP gets a positive state allowlist:
sessions and operational databases work, while plugins, hooks, tools, prompts,
rules, and configuration remain read-only. OMP's `agent.db` mixes runtime and
auth data, so it remains writable; this is an explicit OMP limitation.
Selected credential paths are read-denied.

**Not protected:** files inside your project (the agent edits code, so review
diffs), network egress, and credentials already in your shell env. `git push
--force` and `gh repo delete` still work. Use a VM if you need those.

Full boundary table, the two layers and how they fail, and known analyzer gaps:
[SECURITY.md](SECURITY.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Requirements

macOS 15+ only, Apple Silicon or Intel. Pi is required and installed separately;
OMP's official prebuilt binary is optional. Any provider the selected agent supports.

Other install paths, custom launchers, per-install-method notes, env config, and
testing: [docs/SETUP.md](docs/SETUP.md).

## Support

Personal project, shared as-is under MIT. **Bug reports and feature requests via
[issues](../../issues) are welcome; external pull requests are not accepted.**
See [CONTRIBUTING.md](CONTRIBUTING.md). Forking is explicitly permitted. Security
issues go through a [private advisory](../../security/advisories/new), not a
public issue.

## License

MIT
