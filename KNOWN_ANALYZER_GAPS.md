# Known Analyzer Gaps

Fail-open (or otherwise notable) verdicts in this repository's
`validate-bash-command.sh`, and what the guard layer does about each.

**Where the corpus keeps this file honest:** a gap pinned with `expectFail: true`
in [`test/corpus/corpus.json`](test/corpus/corpus.json) also pins its current real
verdict, and the corpus runner **fails `npm test` the moment that verdict moves in
either direction** — so a fix cannot land unnoticed. Updating the prose here is
still a human step; the runner asks for it, it cannot force it. (That
mechanism exists because an earlier version of this file kept describing an
already-fixed gap as open.)

That tripwire covers the gaps narrow enough to pin as a single command. The
broad classes below — fully dynamic execution most of all — cannot be pinned that
way, because there is no one command whose changed verdict would prove the class
closed. Those are held by the characterization cases and by review, not by an
automatic tripwire. Read a status here as documented intent, not as a
machine-verified claim.

Status legend:

- **OPEN (fail-open)** — the analyzer allows something it should block, and no
  guard-level mitigation covers it. The OS sandbox layer is the backstop.
- **MITIGATED** — the analyzer-level gap still exists, but the guard closes it
  before/around the analyzer.
- **FIXED** — kept as history so the corpus case documents the regression test.

---

## 0. Backslash-newline line continuations — MITIGATED (guard-level probe)

**Analyzer status:** fail-open. **Guard status:** blocked.

Bash removes `\<newline>` line continuations *before* tokenization, so
`r\<newline>m -rf /` runs as `rm -rf /`. The analyzer does not preprocess these
(independent of ANSI-C — plain reassembly slips past too). The guard adds a
reveal-only probe variant that strips continuations and analyzes the result,
worst-of merged. It composes with the ANSI-C probe (`$'r'\<newline>m -rf /` is
caught). Continuation removal is context-free in bash, so the transform is
exact — corpus-pinned, benign multi-line commands (`git commit \<newline> -m …`)
stay allowed.

## 1. ANSI-C quoted command words — MITIGATED (guard-level probe)

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
  over-flagged — a deliberate reveal-only trade (never fail open > avoid false
  asks).

A probe inaccuracy can therefore only over-block, never fail open. Covered by
corpus cases and `test/smoke.mjs`.

Other quoting variants (`'rm' -rf /`, `"rm" -rf /`, `\rm -rf /`) are handled by
the analyzer natively — corpus-pinned.

**Executor operands:** the probe reduces `xargs $'rm'` to `xargs 'rm'`. The
analyzer now treats quoted executor utility words the same as unquoted ones
(warn tier), so that composition is closed — see the gap 3 FIXED history.

## 2. `shred`, `truncate`, and builtin-redirect writes to critical paths — FIXED

Previously the analyzer's device/critical-path rules keyed on a closed verb set
(`dd`, `mkfs`, `wipefs`, `rm`, `mv`, `cp`, …) and a single redirect form
(`> /dev/sd[a-z]`), so these were **allowed**:

```bash
shred /dev/sda          # was ALLOWED — raw device destruction
truncate -s 0 /etc/passwd   # was ALLOWED — critical file truncation
: > /etc/passwd         # was ALLOWED — builtin redirect, no command word
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

## 3. Fully dynamic execution — OPEN by design

The analyzer operates on the literal command string only. Destructive intent
assembled at runtime is not statically detectable:

```bash
eval "$PAYLOAD"
cmd="rm -rf /"; $cmd
```

This is a fundamental constraint of static analysis, documented in both the
analyzer and the README. Note the analyzer does better than a blanket
out-of-scope: `xargs rm` has an explicit warn rule (**ask** tier, corpus-pinned),
and quoted forms (`xargs 'rm'`, `parallel 'rm'`, `find . -exec 'rm' …`) now match
the same tier via quote-aware utility-word checks.

**ANSI-C reconstructed via outer-shell quote removal in a nested `shell -c`
(OPEN, fail-open — accepted static-analysis boundary).** The analyzer recurses
into `shell -c` payloads and even resolves the single-quote-escape idiom for a
*plain* verb — `bash -c 'r'\''m'\'' -rf /'` blocks. What slips past is the idiom
reassembling an **ANSI-C** span for the inner shell to decode:

```bash
bash -c 'r'\''m'\'' -rf /'      # BLOCKED  — analyzer resolves the reassembled `rm`
bash -c '$'\''rm'\'' -rf /'     # ALLOWED  — reassembles `$'rm'`; inner shell decodes it, analyzer does not
```

The guard's ANSI-C probe cannot help: the `$'rm'` bytes are **not contiguous** in
the source — they are reconstructed by outer-shell quote removal — so there is no
`$'...'` span for the probe to decode. (Contiguous forms ARE covered:
`bash -c "$'rm' -rf /"` and `bash -c "\$'rm' -rf /"` both block.) Closing this
needs the analyzer to decode ANSI-C on reassembled `shell -c` operands — the same
dynamic-assembly class as `eval` (gap 3) — and is backstopped by the OS sandbox.

Corpus pins this with `expectFail: true` / `actual: "allow"` so a future fix
surfaces as a test failure asking for a deliberate corpus + docs update.

**Executor + quoted command word — FIXED.** Executor warn-rules previously
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

## 4. Protected path as first operand — FIXED (regression-pinned)

An earlier vendored snapshot allowed `rm /etc/passwd` and `mv /etc /tmp/etc.bak`
because the critical-directory regex required a preceding field. The current
snapshot blocks both. Kept here because the corpus pins the fixed behavior
(`rm /etc/passwd` → block, `mv /etc /tmp/etc.bak` → block, `sudo` variants
included) so a future analyzer change cannot silently reintroduce it.

## 5. Literal interpreter payloads — FIXED (v3.15); dynamic payloads remain OPEN

**Literal payloads (FIXED / regression-pinned).** The analyzer previously allowed
destructive intent expressed only inside a language runtime one-liner — the
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
analysis — not a static argv string matcher. Do not re-label these as FIXED when
only the literal path is covered.

---

## Implications

pi-sandbox-guard is a **best-effort guard**, not an airtight barrier, even when
the analyzer is fully healthy. It significantly raises the bar for accidental
catastrophic commands and handles the common explicit patterns well. It does
not constitute a security boundary against a determined or informed adversary —
that is what the [OS sandbox layer](docs/SANDBOX.md) is for.

Open gaps should be fixed in this repository's
`vendor/validate-bash-command.sh`; the corpus turns a change to any behavior it
covers into an explicit verdict diff.
