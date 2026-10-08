# pi-sandbox-guard

Deprecated. Use [Agent Guard](https://github.com/ebrindley/AgentGuard)
0.2.1 or later for Pi and Oh My Pi on macOS. This repository is retained for
legacy recovery.

## Migrate to Agent Guard

Quit Pi and OMP, then follow the
[installation and migration guide](https://github.com/ebrindley/AgentGuard/blob/main/docs/OPERATIONS.md#moving-from-pi-sandbox-guard)
from Terminal outside an agent session or sandbox.

Agent Guard installs, updates, checks and removes the guard. It preserves Pi's
project-based policy, carries over executable bindings and recorded wrappers,
and retains migrated files for recovery. Guard List applies to OpenCode only.

Do not run this repository's deploy scripts after migration: they overwrite
Agent Guard's Pi files.

## Recover the legacy guard

Run `agent-guard uninstall` before restoring pi-sandbox-guard. It copies the
retired files to `~/Agent Guard/pi-sandbox-guard-legacy/` and prints restoration
steps; it does not restore the old guard automatically.

Use those instructions or the
[final v0.1.0 documentation](https://github.com/ebrindley/pi-sandbox-guard/blob/v0.1.0/README.md)
for legacy installation, requirements and limitations. To obtain that version:

```sh
git clone --branch v0.1.0 https://github.com/ebrindley/pi-sandbox-guard.git
```

## License

[MIT](LICENSE). For current support, use
[Agent Guard](https://github.com/ebrindley/AgentGuard).
