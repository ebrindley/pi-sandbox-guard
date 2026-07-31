# Contributing to pi-sandbox-guard

Thank you for your interest in this project.

## Issues are welcome

Bug reports and feature requests through [GitHub Issues](../../issues) are
encouraged. The more specific the reproduction, the better — for a guard, the
most useful report is usually a **command string plus the verdict you expected**
(allow / ask / block) and the verdict you got.

Especially valuable:

- **A false negative** — a genuinely dangerous command the guard allows.
- **A false positive** — an ordinary command that asks or blocks. These matter as
  much as false negatives: a guard that asks too often trains people to click
  through, which is worse than not asking at all.
- **A bypass of a documented protection.** Check
  [Known analyzer gaps](docs/ARCHITECTURE.md#known-analyzer-gaps) first — some gaps
  are known and documented rather than unnoticed.

## Pull requests are not accepted

External pull requests are disabled on this repository. This is not a judgment
about the quality of any individual contribution — it is the maintenance model
that works for a single author on a security-sensitive tool, where every change
needs a threat-model argument and adversarial review before it lands.

If you'd like a change:

- **Open an issue** describing the problem and your suggested approach. I may
  implement it directly.
- **Fork the repository** and maintain your own version. The MIT license
  explicitly permits this, and for a guard whose policy decisions are inherently
  opinionated, a fork is often the right answer.

This policy may relax over time. If it changes, this file will be updated.

## Security issues

Do **not** open a public issue for a vulnerability. Use a
[private security advisory](../../security/advisories/new) and see
[SECURITY.md](SECURITY.md).

The line between "bug" and "vulnerability" here: a false positive is a bug, and
so is a false negative on a command that is merely destructive to your own
project. A reliable way to make the guard allow something catastrophic — or to
disarm it entirely — is a vulnerability. When unsure, use the private advisory.

## If you fork

Two things worth knowing:

- The analyzer's verdicts are pinned by `test/corpus/corpus.json` (369 cases).
  Run `npm test` after any change to it; a changed verdict shows up as a
  corpus failure, which is the intended tripwire.
- `npm run setup:hooks` installs a tiered pre-push gate: `npm run test:fast`
  (~12s) on any branch push, escalating to the full `npm test` (~140s) when the
  pushed range touches `src/` or `test/corpus/`, when the remote ref
  is new, or when the target is `main`. It needs only bash, git, and npm — no tool
  you don't already have. Bypass with `SKIP_PREPUSH_TESTS=1 git push`; extend it
  locally with an executable, gitignored `.githooks/pre-push.local`.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#known-analyzer-gaps) records
  deliberate, documented gaps. Closing one is welcome in your fork, but check that
  it does not trade a rare bypass for a common false positive.
