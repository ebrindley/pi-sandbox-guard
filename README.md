# pi-sandbox-guard

**Keeps the [Pi coding agent](https://pi.dev) from writing outside your project**
(bar temp dirs and tool caches — see Scope below).

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
git clone https://github.com/ebrindley/pi-sandbox-guard.git && cd pi-sandbox-guard && npm run setup
```

That is the whole install. It deploys the bash filter, the Seatbelt profile, and a
protected `pi` shim, records which Pi to launch, and checks that a plain `pi`
resolves to the shim — if `~/.local/bin` is missing from your `PATH` or sits after
the real Pi, setup fails and tells you what to add where.

## Use

```bash
cd /path/to/your/project && pi
```

You should see `OS sandbox ON. Project [...]` at startup. That line is how you
know you are protected. If it is missing, run `npm run check:path` from the
checkout.

## Scope

Writes and deletes outside your project are blocked at the kernel, bar an
allow-list (temp dirs, tool caches, and Pi's own runtime state — its config,
auth, and installed extensions stay denied, so Pi cannot disable this guard).
Selected credential paths are read-denied.

**Not protected:** files inside your project (the agent edits code — review
diffs), network egress, and credentials already in your shell env — `git push
--force` and `gh repo delete` still work. Use a VM if you need those.

Full boundary table, the two layers and how they fail, and known analyzer gaps:
[SECURITY.md](SECURITY.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Requirements

Nothing to install beyond Pi itself. macOS 15+ only, Apple Silicon or Intel. Any
model provider Pi supports.

Other install paths, custom launchers, per-install-method notes, env config, and
testing: [docs/SETUP.md](docs/SETUP.md).

## Support

Personal project, shared as-is under MIT. **Bug reports and feature requests via
[issues](../../issues) are welcome; external pull requests are not accepted** —
see [CONTRIBUTING.md](CONTRIBUTING.md). Forking is explicitly permitted. Security
issues go through a [private advisory](../../security/advisories/new), not a
public issue.

## License

MIT
