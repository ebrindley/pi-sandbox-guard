# pi-sandbox-guard

Deprecated. Use [Agent Guard 0.2.1](https://github.com/ebrindley/AgentGuard/releases/tag/v0.2.1)
for Pi and Oh My Pi on macOS. See its
[installation and migration guide](https://github.com/ebrindley/AgentGuard/blob/main/docs/OPERATIONS.md#moving-from-pi-sandbox-guard).

```sh
/bin/zsh -c "$(/usr/bin/curl -fsSL https://github.com/ebrindley/AgentGuard/releases/latest/download/install.sh)"
```

Agent Guard installs, updates, checks and removes the guard. It preserves Pi's
project-based policy, carries over executable bindings and recorded wrappers,
and retains the migrated files for recovery. Guard List applies to OpenCode only.

Do not run this repository's deploy scripts after migration: they overwrite
Agent Guard's Pi files. To return to this guard, run `agent-guard uninstall`
first, then follow the recovery instructions or install from the final
[v0.1.0 tag](https://github.com/ebrindley/pi-sandbox-guard/tree/v0.1.0).

The legacy instructions below are retained for recovery.

---

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
allow-list (temp dirs, tool caches, and agent runtime state). Pi config/auth,
user package stores, system prompts and skills stay protected, as do both
agents' extensions. Pi theme files remain writable. OMP gets a positive state allowlist:
sessions and operational databases work, while plugins, hooks, tools, prompts,
rules, and configuration remain read-only. OMP's `agent.db` mixes runtime and
auth data, so it remains writable; this is an explicit OMP limitation.
Selected credential paths are read-denied.

Pi package maintenance and edits to global system prompts, skills or
`models.json` require an operator session outside the guard. Use the real Pi
binary for package maintenance, then return to the protected launcher. Packages
must already be installed: startup/reload cannot install missing packages into
the protected stores. Reads and use of existing resources still work; saving
model/theme choices to `settings.json` was already restricted.

Project agent config is write-protected too: any `.pi` or `.omp` folder in
your project, plus the extension, plugin, hook, and tool folders OMP loads from
`.claude`, `.codex`, `.gemini`, and `.opencode`. Agents cannot create, edit,
or delete them, because they run at the next start. Edit them yourself.
Plain context files such as `AGENTS.md` and skills in `.agents` stay editable.
The launcher refuses to start inside any of these protected folders, and
refuses a symlinked `.pi`/`.omp` layout that would leave the config writable.

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
