# vendor/

## `validate-bash-command.sh`

Shell analyzer that classifies bash command strings before execution. The guard
adapter runs it in a locked-down subprocess; it never executes the candidate
command.

### Ownership

**This repository owns and maintains this script.** It is not vendored from an
upstream that we track — despite living in `vendor/` — so there is no sync,
re-vendor, or update-from-upstream workflow. Fix analyzer gaps **here**, record
any verdict change in `test/corpus/corpus.json` and `KNOWN_ANALYZER_GAPS.md`, and
deploy from this tree.

The directory name is historical: the script began as an adaptation of an earlier
MIT-licensed bash-command analyzer by the same author, written for unrelated
tooling. That earlier work is inspiration only — not a dependency, package, or
submodule — and this copy has diverged substantially since.

Deploy stamps therefore record local file integrity only (`upstream not
attested`); they make no parity claim against any external tree.

### License

MIT, matching the rest of the project (`SPDX-License-Identifier: MIT` in the
script header; the repository `LICENSE` and `package.json` are also MIT).
