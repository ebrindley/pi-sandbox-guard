// guard-core.mjs
//
// Harness-agnostic core for pi-sandbox-guard.
//
// Responsibility: given a candidate bash command string, run the in-tree,
// adversarially-hardened `validate-bash-command.sh` analyzer in a locked-down
// subprocess and return a normalized decision. This module knows NOTHING about
// Pi or Claude Code — adapters map its Decision onto their host contract.
//
// Every design choice here implements a review finding:
//   - spawn (not a shell string)            -> no command injection into the guard
//   - command delivered via STDIN only      -> never as an argv/shell token
//   - sanitized env + fixed PATH            -> repo-local jq/python3 cannot hijack;
//                                              repo .env cannot set CLAUDE_ALLOW_RM_RF
//   - own timeout -> process-GROUP kill      -> Pi has no hard kill; reap bash + children
//   - exit code is the ONLY decision signal -> stderr is human text, never parsed for verdict
//   - anything unexpected -> DENY (fail closed)
//   - preflight deps on the sanitized PATH  -> missing bash/jq/awk => guard unavailable
//
// Decision contract (stable; adapters depend on it):
//   { decision: 'allow' | 'ask' | 'block', reason: string, meta: {...} }

import { spawn } from 'node:child_process';
import { existsSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));

/** Absolute path to the in-tree analyzer script, a sibling of this module. */
export const ANALYZER_SCRIPT = join(__dirname, 'validate-bash-command.sh');

/**
 * Fixed, trusted PATH for the analyzer subprocess. A repo-local `./bin/jq` or
 * `node_modules/.bin/awk` must NOT be able to shadow the real helpers the
 * analyzer shells out to. Order: system dirs first, Homebrew last.
 *
 * Every helper resolved through this PATH is an OS-provided tool on a supported
 * macOS (bash, awk, and — since macOS 15 — Apple's own /usr/bin/jq). Path
 * canonicalization does NOT go through here: see GUARD_NODE below.
 */
const SAFE_PATH = '/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin';

/**
 * Absolute path to the Node binary the analyzer uses for path canonicalization.
 *
 * This is `process.execPath` — the interpreter already running this guard — not a
 * PATH lookup. Two reasons:
 *   1. Correctness: node is frequently installed somewhere SAFE_PATH does not
 *      list (nvm/fnm/mise shims, versioned Homebrew kegs such as
 *      /opt/homebrew/opt/node@24/bin). Resolving `node` off SAFE_PATH would fail
 *      preflight on those machines and fail the guard CLOSED on every command.
 *   2. Security: it cannot be SHADOWED — no PATH entry or repo-local `node` can
 *      win a lookup, because there is no lookup. That is strictly stronger than
 *      the PATH resolution it replaces.
 *
 * The bound, stated precisely: absoluteness prevents shadowing. It does NOT make
 * the binary trustworthy, and startup trust does not extend forward in time. If
 * Pi is launched by a node under a path the agent can write, that file can be
 * REPLACED after startup, and every later canonicalization runs the replacement —
 * which could return attacker-chosen "safe" paths and misclassify a destructive
 * operand. This is a genuine TOCTOU on the interpreter pathname, not merely a
 * restatement of "the guard trusts its own interpreter".
 *
 * Why it is nonetheless the right pin, and what actually contains it:
 *   - It is strictly better than the SAFE_PATH lookup it replaces, which was
 *     vulnerable to the same swap PLUS shadowing by any earlier PATH entry.
 *   - Under Seatbelt, containment is about WHERE node lives: the profile allows
 *     writes under TMPDIR, /private/tmp, ~/.pi/agent, ~/.npm, ~/.cache and
 *     ~/Library/Caches as well as PROJECT, so a node under any of those (a
 *     version-manager or corepack shim, say) is still replaceable.
 *   - Filter-only, location buys nothing (nothing denies writes) — only OWNERSHIP
 *     does. Note Homebrew on Apple Silicon is user-owned, so the common
 *     /opt/homebrew node does NOT qualify there. See SECURITY.md.
 *   - Recorded in SECURITY.md rather than papered over here; re-resolving or
 *     hashing the interpreter per invocation would not close it either (the check
 *     and the exec are still distinct moments).
 * Passed to the analyzer as GUARD_NODE; the script invokes "$GUARD_NODE" directly.
 */
const GUARD_NODE = process.execPath;

/**
 * Helpers the analyzer resolves via SAFE_PATH. Missing any => guard cannot run
 * => fail closed. Node is NOT here: it is pinned absolutely via GUARD_NODE and
 * probed separately (a PATH lookup would defeat the point).
 */
const REQUIRED_HELPERS = ['bash', 'jq', 'awk'];

/** Decision severity for worst-of merging: block > ask > allow. Immutable. */
export const SEVERITY = Object.freeze({ allow: 0, ask: 1, block: 2 });

/**
 * Policy keys the core accepts from caller-supplied trustedPolicyEnv.
 * Frozen and intentionally minimal: only what the adapter documents and
 * forwards. Disarm / dead-surface keys (CLAUDE_ALLOW_RM_RF*,
 * CLAUDE_BASH_GUARD_*, CLAUDE_SECURITY_LOG, etc.) are never accepted.
 */
export const ALLOWED_POLICY_KEYS = Object.freeze(['POLICY_RM_SAFE_ROOTS']);

/** @type {ReadonlySet<string>} */
const ALLOWED_POLICY_KEY_SET = new Set(ALLOWED_POLICY_KEYS);

/**
 * Keys that must NEVER reach the analyzer, even if a caller tries to smuggle
 * them through trustedPolicyEnv. Documented for tests and review.
 */
export const DISARM_POLICY_KEYS = Object.freeze([
  'CLAUDE_ALLOW_RM_RF',
  'CLAUDE_ALLOW_RM_RF_SCOPE',
  'CLAUDE_BASH_GUARD_MAX_BYTES',
  'CLAUDE_BASH_GUARD_MAX_RM_SEGMENTS',
  'CLAUDE_BASH_GUARD_MAX_RM_OPERANDS',
  'CLAUDE_SECURITY_LOG',
  'POLICY_SECURITY_LOG',
  // Analyzer-native name: only set by our POLICY_* mapping, never accepted raw.
  'CLAUDE_RM_SAFE_ROOTS',
]);

const DEFAULTS = Object.freeze({
  timeoutMs: 2000,
  killGraceMs: 200,
  // Defensive cap that MUST stay in lockstep with the analyzer's own
  // internal cap (currently 32768 bytes). Above 32 KB the analyzer takes cheap
  // shortcuts that can still return 'allow' for large benign-looking text, so
  // we pre-reject here to guarantee consistent semantics. When the analyzer cap
  // changes, update this constant to match — they are not independent.
  maxCommandBytes: 32 * 1024, // 32768 — matches analyzer internal cap (FIX 4)
  // Independent capture caps for analyzer stdout/stderr. Exceeding either
  // kills the process group and fail-closes; retained reason text is further
  // truncated (REASON_CAPTURE_CHARS) so memory stays O(cap), never unbounded.
  maxStdoutBytes: 64 * 1024,
  maxStderrBytes: 64 * 1024,
});

/** Max chars retained from each stream for the human reason string. */
const REASON_CAPTURE_CHARS = 4000;

/**
 * @typedef {'allow'|'ask'|'block'} DecisionKind
 * @typedef {Object} Decision
 * @property {DecisionKind} decision
 * @property {string} reason          Human-readable; safe to show a user. Never parsed.
 * @property {Object} meta
 * @property {number|null} meta.exitCode
 * @property {string|null} meta.signal
 * @property {boolean} meta.timedOut
 * @property {boolean} meta.failClosed Whether this verdict came from a fail-safe path.
 */

/**
 * Build the locked-down environment for the subprocess.
 *
 * SECURITY: we deliberately do NOT forward process.env. A target repo that sets
 * CLAUDE_ALLOW_RM_RF=1 (in .env / direnv / shell profile) must not be able to
 * disarm the guard. Only an explicit, caller-supplied trustedPolicyEnv — sourced
 * from the host's own trusted config, never from the project — is allowed through,
 * and only for keys in ALLOWED_POLICY_KEYS (adapter-supported surface only).
 *
 * @param {Record<string,string>} [trustedPolicyEnv]
 * @param {string} [home]
 */
function buildEnv(trustedPolicyEnv = {}, home = process.env.HOME || '') {
  const env = { PATH: SAFE_PATH, HOME: home };
  if (trustedPolicyEnv && typeof trustedPolicyEnv === 'object') {
    for (const [k, v] of Object.entries(trustedPolicyEnv)) {
      if (ALLOWED_POLICY_KEY_SET.has(k) && typeof v === 'string') env[k] = v;
    }
  }
  // Map our POLICY_* names onto the names the analyzer script reads today, so
  // the adapter can speak POLICY_* without us forking the script yet. Callers
  // cannot inject CLAUDE_RM_SAFE_ROOTS directly (not in ALLOWED_POLICY_KEYS).
  if (env.POLICY_RM_SAFE_ROOTS) {
    env.CLAUDE_RM_SAFE_ROOTS = env.POLICY_RM_SAFE_ROOTS;
  }
  // Set LAST, unconditionally: the canonicalizer the analyzer must use. Assigned
  // after the trustedPolicyEnv merge so no caller can substitute a different
  // interpreter (GUARD_NODE is not in ALLOWED_POLICY_KEYS either — belt and braces).
  env.GUARD_NODE = GUARD_NODE;
  return env;
}

/**
 * Filter trustedPolicyEnv to the allow-listed keys only. Exported so tests can
 * prove disarm / dead-surface keys are dropped without inspecting subprocess env.
 *
 * @param {Record<string,string>} [trustedPolicyEnv]
 * @returns {Record<string,string>}
 */
export function filterTrustedPolicyEnv(trustedPolicyEnv = {}) {
  const out = {};
  if (!trustedPolicyEnv || typeof trustedPolicyEnv !== 'object') return out;
  for (const [k, v] of Object.entries(trustedPolicyEnv)) {
    if (ALLOWED_POLICY_KEY_SET.has(k) && typeof v === 'string') out[k] = v;
  }
  return out;
}

/**
 * Functional preflight probes: each helper is actually EXECUTED, not just
 * resolved with `command -v`. A present-but-broken helper (e.g. the macOS
 * /usr/bin/python3 stub that errors when Command Line Tools are missing, or a
 * corrupt jq) would pass a presence check, then fail on every real analysis —
 * fail-closed per command with a generic message instead of the loud DEGRADED
 * banner. Executing a no-op catches that at load time.
 */
const HELPER_PROBES = {
  bash: ['-c', ':'],
  jq: ['-n', 'true'],
  awk: ['BEGIN{}'],
};

/**
 * Pseudo-helper name reported in `missing` when the pinned GUARD_NODE binary
 * fails its probe. Not a SAFE_PATH lookup — see GUARD_NODE.
 */
const GUARD_NODE_HELPER = 'node(GUARD_NODE)';

/** Per-helper probe timeout. Generous: this runs once at load, not per command. */
const PREFLIGHT_PROBE_TIMEOUT_MS = 10_000;

/**
 * Preflight: is the guard runnable at all?
 * Checks the analyzer script exists and every required helper EXECUTES a no-op
 * successfully on the SAFE_PATH (not the ambient PATH). Returns a structured
 * result; callers decide how to fail (a destructive-command guard should fail
 * CLOSED — block).
 *
 * @param {Object} [testOverrides]  TEST-ONLY seam. `path` replaces SAFE_PATH for
 *   the probe spawns so tests can present a broken helper; `nodeBin` replaces the
 *   pinned GUARD_NODE binary so tests can present a broken/absent interpreter.
 *   Production callers must never pass either (the analyzer subprocess always uses
 *   SAFE_PATH, and GUARD_NODE is always process.execPath).
 * @param {string} [testOverrides.path]
 * @param {string} [testOverrides.nodeBin]
 * @returns {Promise<{ok: boolean, missing: string[], scriptPresent: boolean, platform: string}>}
 */
export async function preflight(testOverrides = {}) {
  const probePath = testOverrides.path ?? SAFE_PATH;
  const probeNodeBin = testOverrides.nodeBin ?? GUARD_NODE;
  const platform = process.platform;
  const scriptPresent = existsSync(ANALYZER_SCRIPT);

  if (platform === 'win32') {
    // No bash/awk by default; do not attempt fragile WSL spawning.
    return {
      ok: false,
      missing: [...REQUIRED_HELPERS, GUARD_NODE_HELPER],
      scriptPresent,
      platform,
    };
  }

  // GUARD_NODE is probed alongside the PATH helpers but resolved ABSOLUTELY, so a
  // test `path` override must not affect it — an absolute binary cannot be
  // shadowed by PATH, and pretending otherwise would make the probe meaningless.
  const probeTargets = [
    ...REQUIRED_HELPERS.map((helper) => ({ helper, bin: helper, args: HELPER_PROBES[helper] })),
    { helper: GUARD_NODE_HELPER, bin: probeNodeBin, args: ['-e', ''] },
  ];

  const probeResults = await Promise.all(
    probeTargets.map(
      ({ helper, bin, args }) =>
        new Promise((resolve) => {
          let settled = false;
          const finish = (ok) => {
            if (settled) return;
            settled = true;
            resolve({ helper, ok });
          };
          let p;
          try {
            p = spawn(bin, args, {
              env: { PATH: probePath },
              stdio: 'ignore',
            });
          } catch {
            finish(false);
            return;
          }
          const timer = setTimeout(() => {
            try {
              p.kill('SIGKILL');
            } catch {
              /* already gone */
            }
            finish(false);
          }, PREFLIGHT_PROBE_TIMEOUT_MS);
          p.on('error', () => {
            clearTimeout(timer);
            finish(false);
          });
          p.on('close', (code) => {
            clearTimeout(timer);
            finish(code === 0);
          });
        }),
    ),
  );
  const missing = probeResults.filter((r) => !r.ok).map((r) => r.helper);

  return { ok: scriptPresent && missing.length === 0, missing, scriptPresent, platform };
}

// ---------------------------------------------------------------------------
// ANSI-C quote normalization probe (reveal-only)
// ---------------------------------------------------------------------------
//
// The analyzer does not normalize ANSI-C quoted command words, so
// `$'rm' -rf /` and `$'r'$'m' -rf /` are documented fail-opens (see
// docs/ARCHITECTURE.md). We mitigate at the guard level WITHOUT rewriting the
// analyzer's input: the ORIGINAL command is always analyzed as-is, and when the
// command contains ANSI-C spans we ALSO analyze a decoded probe string, taking
// the WORST of the two verdicts. A decoder bug can therefore only produce a
// false positive (spurious ask/block), never a fail-open — same philosophy as
// the adapter's worst-of-cwd merge.

/**
 * Decode one ANSI-C ($'...') span body per bash semantics.
 * @param {string} s      Full command string.
 * @param {number} start  Index of the first char AFTER the opening `$'`.
 * @returns {{decoded: string, end: number}}  end = index after the closing quote
 *   (or s.length when unterminated — bash treats the rest as span content).
 */
function decodeAnsiCSpan(s, start) {
  let out = '';
  let i = start;
  while (i < s.length) {
    const ch = s[i];
    if (ch === "'") return { decoded: out, end: i + 1 };
    if (ch !== '\\') {
      out += ch;
      i++;
      continue;
    }
    // Escape sequence.
    const e = s[i + 1];
    if (e === undefined) {
      out += '\\';
      i++;
      continue;
    }
    const SIMPLE = {
      a: '\x07',
      b: '\b',
      e: '\x1b',
      E: '\x1b',
      f: '\f',
      n: '\n',
      r: '\r',
      t: '\t',
      v: '\v',
      '\\': '\\',
      "'": "'",
      '"': '"',
      '?': '?',
    };
    if (e in SIMPLE) {
      out += SIMPLE[e];
      i += 2;
      continue;
    }
    if (e === 'x') {
      const m = /^[0-9a-fA-F]{1,2}/.exec(s.slice(i + 2));
      if (m) {
        out += String.fromCharCode(parseInt(m[0], 16));
        i += 2 + m[0].length;
        continue;
      }
      out += '\\x';
      i += 2;
      continue;
    }
    if (e === 'u' || e === 'U') {
      const width = e === 'u' ? 4 : 8;
      const m = new RegExp(`^[0-9a-fA-F]{1,${width}}`).exec(s.slice(i + 2));
      if (m) {
        const cp = parseInt(m[0], 16);
        try {
          out += String.fromCodePoint(cp);
        } catch {
          // out-of-range code point: keep the raw escape (worst-of merge makes
          // any inaccuracy escalate-only)
          out += `\\${e}${m[0]}`;
        }
        i += 2 + m[0].length;
        continue;
      }
      out += `\\${e}`;
      i += 2;
      continue;
    }
    if (e >= '0' && e <= '7') {
      const m = /^[0-7]{1,3}/.exec(s.slice(i + 1));
      out += String.fromCharCode(parseInt(m[0], 8) & 0xff);
      i += 1 + m[0].length;
      continue;
    }
    if (e === 'c' && s[i + 2] !== undefined) {
      out += String.fromCharCode(s.toUpperCase().charCodeAt(i + 2) & 0x1f);
      i += 3;
      continue;
    }
    // Unknown escape: bash keeps the backslash and the char.
    out += '\\' + e;
    i += 2;
  }
  return { decoded: out, end: s.length };
}

/** Depth beyond which the probe stops descending into nested substitutions.
 * The analyzer already caps command-substitution depth (ask/block on
 * deep nesting), so the ORIGINAL-command verdict covers pathological nesting;
 * this guard just bounds probe recursion so a `$(` flood can't overflow. */
const ANSI_PROBE_MAX_DEPTH = 40;

/**
 * Wrap a decoded ANSI-C payload as a POSIX single-quoted literal, so it becomes
 * exactly one shell word carrying the decoded bytes as data. Embedded single
 * quotes are escaped with the standard '\'' idiom. This is what makes the probe
 * reveal-only: decoded content can never act as shell syntax in the probe.
 * @param {string} s
 * @returns {string}
 */
function singleQuote(s) {
  return "'" + s.replaceAll("'", "'\\''") + "'";
}

/**
 * Remove backslash-newline line continuations, which bash elides BEFORE
 * tokenization — so `r\<newline>m -rf /` runs as `rm -rf /`. The analyzer
 * analyzer does not preprocess these, so it misses the reassembled command
 * (independent of ANSI-C: plain `r\<newline>m` slips past too). Used to build a
 * reveal-only probe variant. Unconditional in bash (context-free), so this is
 * exact, not heuristic. Returns null when there is nothing to strip.
 * @param {string} s
 * @returns {string|null}
 */
function stripLineContinuations(s) {
  if (!s.includes('\\')) return null;
  const stripped = s.replace(/\\\r?\n/g, '');
  return stripped === s ? null : stripped;
}

/**
 * Build the reveal-only probe: the command with every ANSI-C ($'...') span
 * decoded wherever bash would actually treat it as ANSI-C. Returns null when
 * the command has no ANSI-C spans that were decoded.
 *
 * Context model (matches bash where it matters for command detection):
 *  - COMMAND context (top level, and inside $()/`` `` `` substitutions): $'...'
 *    IS ANSI-C and is decoded; ", $(, `` ` ``, ' and \ shift context.
 *  - DOUBLE-QUOTE context: $'...' is NOT ANSI-C at the outer shell. It is still
 *    decoded, for two reasons: (a) a command substitution nested in double
 *    quotes — `"$( ... )"` or `` "`...`" `` — re-enters COMMAND context, and
 *    (b) a nested `shell -c "…"` payload is reparsed in command context by the
 *    inner shell. Both were fail-opens (`echo "$($'rm' -rf /)"`,
 *    `bash -c "$'rm' -rf /"`).
 *  - SINGLE-QUOTE: fully literal until the closing '.
 *
 * Every decoded span — in either context — is emitted as a single-quoted word.
 * Single-quoting neutralizes `;`, `|`, `&`, etc. (they cannot become syntax the
 * analyzer misreads), which is why `echo $'; rm -rf /'` stays a benign echo.
 * Newlines are the ONE character single-quoting cannot neutralize for this
 * analyzer: it splits on raw newlines regardless of quoting. We deliberately
 * PRESERVE decoded newlines rather than strip them, because when the span is a
 * nested `shell -c` argument the inner shell DOES treat the decoded newline as a
 * real separator (`bash -c $'echo ok\nrm -rf /'` runs the rm). Preserving means
 * a benign multiline `echo $'a\nb'` may be over-flagged, but reveal-only ranks
 * never-fail-open above avoiding false asks — an inaccuracy can only add a false
 * ask/block, never turn a block into an allow. (Embedded double quotes ARE
 * stripped in the double-quote path only, so decoded data cannot prematurely
 * close the outer quote.)
 *
 * Heredocs and arithmetic are not modeled. Any divergence from bash's real
 * parse is acceptable in ONE direction only: the probe is merged worst-of with
 * the original-command verdict, so an inaccuracy can add a false ask/block but
 * can never turn a block into an allow.
 *
 * @param {string} command
 * @returns {string|null}
 */
export function ansiCProbe(command) {
  if (typeof command !== 'string') return null;
  let i = 0;
  let found = false;

  // Scan one context starting at command[i]. `terminator` is the char that ends
  // this context (')' for $() subs, '`' for backtick subs, '"' for double
  // quotes) or null for the top level (ends at EOF). `mode` is 'cmd' or 'dq'.
  // Advances the shared cursor `i` past the terminator. Returns decoded text.
  function scan(mode, terminator, depth) {
    let out = '';
    let parenDepth = 0; // only meaningful for a $() sub (terminator === ')')
    while (i < command.length) {
      const ch = command[i];

      // End of this context.
      if (terminator === ')' && ch === ')' && parenDepth === 0) {
        out += ch;
        i++;
        return out;
      }
      if (terminator === '`' && ch === '`') {
        out += ch;
        i++;
        return out;
      }
      if (terminator === '"' && mode === 'dq' && ch === '"') {
        out += ch;
        i++;
        return out;
      }

      // In DOUBLE-QUOTE context, `\$` is the one escape bash still resolves — it
      // yields a literal `$` at the OUTER shell but, inside a nested `shell -c`
      // payload, the inner shell then sees `$'...'` and runs it as ANSI-C
      // (`bash -c "\$'rm' -rf /"` deletes files). So treat `\$'` here as an
      // ANSI-C span, not an inert escape (a real bypass). Handled before
      // the generic backslash-copy below.
      if (mode === 'dq' && ch === '\\' && command[i + 1] === '$' && command[i + 2] === "'") {
        const { decoded, end } = decodeAnsiCSpan(command, i + 3);
        out += singleQuote(decoded.replaceAll('"', ''));
        i = end;
        found = true;
        continue;
      }

      // Backslash escape: copy the pair verbatim (probe never needs to resolve
      // shell escaping — it only reveals ANSI-C command words).
      if (ch === '\\' && command[i + 1] !== undefined) {
        out += command.slice(i, i + 2);
        i += 2;
        continue;
      }

      // Command substitution — re-enters COMMAND context in BOTH modes.
      if (ch === '$' && command[i + 1] === '(' && depth < ANSI_PROBE_MAX_DEPTH) {
        out += '$(';
        i += 2;
        out += scan('cmd', ')', depth + 1);
        continue;
      }
      if (ch === '`' && depth < ANSI_PROBE_MAX_DEPTH) {
        out += '`';
        i++;
        out += scan('cmd', '`', depth + 1);
        continue;
      }

      if (mode === 'cmd') {
        // Track subshell/group parens so `$( (subshell) )` doesn't terminate early.
        if (terminator === ')' && ch === '(') {
          parenDepth++;
          out += ch;
          i++;
          continue;
        }
        if (terminator === ')' && ch === ')' && parenDepth > 0) {
          parenDepth--;
          out += ch;
          i++;
          continue;
        }
        // ANSI-C span. Emit the decoded bytes as a SINGLE-QUOTED literal so the
        // probe preserves bash's real semantics: $'...' produces data occupying
        // one quoted word — bash never re-parses it for metacharacters. Raw
        // injection would corrupt token boundaries (e.g. `echo $'; rm -rf /'`, a
        // benign echo, would look like `echo ; rm -rf /`). Wrapping keeps a
        // decoded command word like $'rm' -> 'rm' visible to the analyzer, which
        // detects single-quoted dangerous tokens natively.
        if (ch === '$' && command[i + 1] === "'") {
          const { decoded, end } = decodeAnsiCSpan(command, i + 2);
          out += singleQuote(decoded);
          i = end;
          found = true;
          continue;
        }
        // Single quote: literal run.
        if (ch === "'") {
          out += ch;
          i++;
          while (i < command.length && command[i] !== "'") {
            out += command[i];
            i++;
          }
          if (i < command.length) {
            out += command[i];
            i++;
          }
          continue;
        }
        // Double quote: enter dq context.
        if (ch === '"') {
          out += ch;
          i++;
          out += scan('dq', '"', depth);
          continue;
        }
        out += ch;
        i++;
        continue;
      }

      // mode === 'dq': at the OUTER shell $'...' is literal here. But a nested
      // `shell -c "…"` payload is reparsed in command context by the inner
      // shell, where $'...' IS ANSI-C (e.g. `bash -c "$'rm' -rf /"`). Emit a
      // single-quoted word IN PLACE (still inside the outer double quotes). Two
      // readers see the right thing:
      //   - plain double-quoted use (no recursion): single quotes are literal
      //     inside "…", so it stays benign data (`echo "$'; rm -rf /'"` → allow).
      //   - shell -c recursion: the analyzer re-analyzes the double-quoted
      //     PAYLOAD as a command string, where the single quotes become active
      //     and reveal the verb (`bash -c "$'rm' -rf /"` → 'rm' → block).
      // A literal double quote in decoded data IS stripped (it cannot be a
      // destructive verb char) so it can't prematurely close the outer quote;
      // newlines are preserved (see ansiCProbe header — they can be real
      // separators once the inner shell reparses the payload). Reveal-only +
      // worst-of merge means any imprecision only over-blocks.
      if (ch === '$' && command[i + 1] === "'") {
        const { decoded, end } = decodeAnsiCSpan(command, i + 2);
        out += singleQuote(decoded.replaceAll('"', ''));
        i = end;
        found = true;
        continue;
      }
      out += ch;
      i++;
    }
    return out;
  }

  const result = scan('cmd', null, 0);
  return found ? result : null;
}

/**
 * Analyze one candidate command. Never throws — every failure path resolves to a
 * fail-closed Decision (block) so a crash in the guard cannot become an allow.
 *
 * Reveal-only hardening: the ORIGINAL command is always analyzed as-is. We also
 * analyze normalized "probe" variants that undo transformations bash performs
 * before the analyzer's patterns would see them — line-continuation removal and
 * ANSI-C quote decoding — and take the WORST verdict. Each transform is either
 * exact (line continuations are context-free in bash) or emitted as inert
 * single-quoted data (ANSI-C), so a probe inaccuracy can only escalate (false
 * ask/block), never fail open. Probes compose: line continuations are stripped
 * first, then ANSI-C is revealed, so `$'r'\<newline>m -rf /` is caught.
 *
 * @param {string} command       The exact command string the tool would run.
 * @param {Object} [opts]
 * @param {string} [opts.cwd]     CWD the bash tool will actually execute in. Critical:
 *                                relative-path analysis (`rm -rf build`, `cd /tmp && rm -rf .`)
 *                                is judged against THIS cwd, not the extension's dir.
 * @param {number} [opts.timeoutMs]
 * @param {number} [opts.maxStdoutBytes]  Cap on captured analyzer stdout (bytes).
 * @param {number} [opts.maxStderrBytes]  Cap on captured analyzer stderr (bytes).
 * @param {Record<string,string>} [opts.trustedPolicyEnv]
 * @param {string} [opts.home]
 * @returns {Promise<Decision>}
 */
export async function analyzeCommand(command, opts = {}) {
  // Cheap fail-closed guards run BEFORE the JS-side probe scan: an oversized,
  // empty, or non-string input must be rejected without scanning/copying a
  // large string in-process (the 32 KB cap is a defensive DoS guard and must
  // stay cheap). analyzeCommandRaw fail-closes all three, so just delegate.
  if (
    typeof command !== 'string' ||
    command.length === 0 ||
    Buffer.byteLength(command, 'utf8') > DEFAULTS.maxCommandBytes
  ) {
    return analyzeCommandRaw(command, opts);
  }

  // Build reveal-only probe variants. Order matters: strip line continuations
  // first (bash elides them pre-tokenization), THEN reveal ANSI-C on both the
  // raw and the continuation-stripped forms, so combined evasions are caught.
  // Dedupe so we never analyze the same string twice.
  const variants = new Set();
  const noCont = stripLineContinuations(command);
  for (const base of noCont === null ? [command] : [command, noCont]) {
    const probe = ansiCProbe(base);
    if (probe !== null) variants.add(probe);
  }
  if (noCont !== null) variants.add(noCont);
  variants.delete(command); // original is analyzed separately, below

  if (variants.size === 0) return analyzeCommandRaw(command, opts);

  const list = [...variants];
  const [original, ...revealedVerdicts] = await Promise.all([
    analyzeCommandRaw(command, opts),
    ...list.map((v) => analyzeCommandRaw(v, opts)),
  ]);
  // Worst-of merge (block > ask > allow). Prefer the ORIGINAL command's verdict
  // on ties so user-facing reasons reference the command as typed.
  let worst = original;
  for (const v of revealedVerdicts) {
    if (SEVERITY[v.decision] > SEVERITY[worst.decision]) worst = v;
  }
  if (worst === original) return original;
  return {
    ...worst,
    reason: `${worst.reason} (detected via shell-normalization probe of: ${command.slice(0, 200)})`,
    meta: { ...worst.meta, normalizationProbe: true },
  };
}

/**
 * Single-pass analysis of one exact command string (no probe expansion).
 * @param {string} command
 * @param {Parameters<typeof analyzeCommand>[1]} [opts]
 * @returns {Promise<Decision>}
 */
async function analyzeCommandRaw(command, opts = {}) {
  const timeoutMs = opts.timeoutMs ?? DEFAULTS.timeoutMs;
  const maxStdoutBytes = opts.maxStdoutBytes ?? DEFAULTS.maxStdoutBytes;
  const maxStderrBytes = opts.maxStderrBytes ?? DEFAULTS.maxStderrBytes;
  const env = buildEnv(opts.trustedPolicyEnv, opts.home);

  if (typeof command !== 'string' || command.length === 0) {
    return failClosed('Empty or non-string command — denied as fail-safe.', {
      exitCode: null,
      signal: null,
      timedOut: false,
    });
  }
  if (Buffer.byteLength(command, 'utf8') > DEFAULTS.maxCommandBytes) {
    return failClosed('Command exceeds size cap — denied as fail-safe.', {
      exitCode: null,
      signal: null,
      timedOut: false,
    });
  }
  // FIX 3: cwd MUST be a caller-supplied string path to an EXISTING DIRECTORY.
  // Falling back to process.cwd() produces WRONG relative-path verdicts — `rm -rf
  // build` with an unknown cwd would be analyzed against the extension's own
  // directory, not the target project, and could be allowed. The caller (adapter)
  // is responsible for passing the actual bash-tool execution directory.
  //
  // It is not enough to check existsSync: a path that exists but is a FILE (e.g.
  // "/etc/hosts") passes existsSync, then spawn({cwd}) throws ENOTDIR — which
  // would escape as an unhandled rejection. We require an actual directory here,
  // inside try/catch so a stat race/permission error also fails closed.
  let cwdIsDir = false;
  if (typeof opts.cwd === 'string' && opts.cwd.length > 0) {
    try {
      cwdIsDir = statSync(opts.cwd).isDirectory();
    } catch {
      cwdIsDir = false;
    }
  }
  if (!cwdIsDir) {
    return failClosed(
      'Guard cwd unknown or not a directory — cannot analyze relative paths safely.',
      { exitCode: null, signal: null, timedOut: false },
    );
  }
  const cwd = opts.cwd;
  if (!existsSync(ANALYZER_SCRIPT)) {
    return failClosed('Guard analyzer missing — denied as fail-safe.', {
      exitCode: null,
      signal: null,
      timedOut: false,
    });
  }

  // Build the stdin envelope the analyzer script expects: {tool_input:{command}}.
  // We construct it in Node (no jq on the adapter side) and pipe it in. The
  // command never appears as an argv token — only on stdin.
  const envelope = JSON.stringify({ tool_input: { command } });

  return new Promise((resolve) => {
    let settled = false;
    const done = (d) => {
      if (settled) return;
      settled = true;
      resolve(d);
    };

    // detached:true => child gets its own process group; we can kill the WHOLE
    // group (bash + jq + python3 + awk children) with process.kill(-pid).
    // Belt-and-suspenders: spawn can throw SYNCHRONOUSLY (e.g. ENOTDIR if cwd is
    // not a directory — though we now validate that above, and EACCES/EMFILE).
    // A synchronous throw here would escape the Promise executor as a rejection,
    // so we catch and fail closed.
    let child;
    try {
      child = spawn('/bin/bash', [ANALYZER_SCRIPT], {
        cwd,
        env,
        stdio: ['pipe', 'pipe', 'pipe'],
        detached: true,
      });
    } catch (err) {
      done(
        failClosed(`Guard failed to spawn (${err.code || err.message}) — denied as fail-safe.`, {
          exitCode: null,
          signal: null,
          timedOut: false,
        }),
      );
      return;
    }

    // Bounded capture: only REASON_CAPTURE_CHARS retained per stream for the
    // human reason; byte counters enforce independent hard caps. Exceeding a
    // cap kills the process group and fail-closes (no unbounded string growth).
    let stderr = '';
    let stdout = '';
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let killTimer = null;
    let overflowed = false;

    const killGroup = (signal) => {
      // FIX 2: guard against child.pid being falsy (spawn failed before the OS
      // assigned a pid). process.kill(-undefined) / process.kill(NaN) on Linux
      // signals the caller's OWN process group — catastrophic on the Pi.
      if (typeof child.pid === 'number') {
        try {
          process.kill(-child.pid, signal);
        } catch {
          try {
            child.kill(signal);
          } catch {
            /* already gone */
          }
        }
      } else {
        // pid unknown — best-effort direct kill, no group kill
        try {
          child.kill(signal);
        } catch {
          /* already gone */
        }
      }
    };

    const failClosedOverflow = (stream) => {
      if (overflowed || settled) return;
      overflowed = true;
      clearTimeout(timer);
      if (killTimer) clearTimeout(killTimer);
      // SIGTERM the group, then SIGKILL if it lingers — same path as timeout.
      killGroup('SIGTERM');
      killTimer = setTimeout(() => killGroup('SIGKILL'), DEFAULTS.killGraceMs);
      done(
        failClosed(
          `Guard ${stream} exceeded capture cap — denied as fail-safe.`,
          {
            exitCode: null,
            signal: 'SIGTERM',
            timedOut: false,
            outputOverflow: true,
          },
        ),
      );
    };

    /**
     * Append a chunk into a bounded reason buffer and count raw bytes toward
     * the independent stream cap. Returns false if the hard cap was exceeded
     * (caller should stop; failClosedOverflow already scheduled).
     * @param {'stdout'|'stderr'} stream
     * @param {Buffer|string} b
     * @returns {boolean}
     */
    const captureChunk = (stream, b) => {
      if (overflowed || settled) return false;
      const buf = Buffer.isBuffer(b) ? b : Buffer.from(String(b), 'utf8');
      if (stream === 'stdout') {
        if (stdoutBytes + buf.length > maxStdoutBytes) {
          failClosedOverflow('stdout');
          return false;
        }
        stdoutBytes += buf.length;
        if (stdout.length < REASON_CAPTURE_CHARS) {
          stdout += buf.toString('utf8').slice(0, REASON_CAPTURE_CHARS - stdout.length);
        }
      } else {
        if (stderrBytes + buf.length > maxStderrBytes) {
          failClosedOverflow('stderr');
          return false;
        }
        stderrBytes += buf.length;
        if (stderr.length < REASON_CAPTURE_CHARS) {
          stderr += buf.toString('utf8').slice(0, REASON_CAPTURE_CHARS - stderr.length);
        }
      }
      return true;
    };

    const timer = setTimeout(() => {
      // SIGTERM the group, then SIGKILL if it lingers.
      killGroup('SIGTERM');
      killTimer = setTimeout(() => killGroup('SIGKILL'), DEFAULTS.killGraceMs);
      done(
        failClosed('Guard timed out — denied as fail-safe.', {
          exitCode: null,
          signal: 'SIGTERM',
          timedOut: true,
        }),
      );
    }, timeoutMs);

    child.on('error', (err) => {
      clearTimeout(timer);
      // FIX 2: if the main timeout already fired and set killTimer, clear it
      // now. Without this the orphaned killTimer fires process.kill(-child.pid)
      // where child.pid may be undefined → process.kill(NaN) on Linux signals
      // our OWN process group.
      if (killTimer) clearTimeout(killTimer);
      done(
        failClosed(`Guard failed to start (${err.code || err.message}) — denied as fail-safe.`, {
          exitCode: null,
          signal: null,
          timedOut: false,
        }),
      );
    });

    if (child.stdout) {
      child.stdout.on('data', (b) => {
        captureChunk('stdout', b);
      });
      // Like stdin, an async 'error' on a read stream (e.g. EPIPE on the child
      // dying mid-read) would otherwise be an unhandled error event -> host crash.
      // Swallow it; child.on('close'/'error') or the timeout drives the verdict.
      child.stdout.on('error', () => {});
    }
    if (child.stderr) {
      child.stderr.on('data', (b) => {
        captureChunk('stderr', b);
      });
      child.stderr.on('error', () => {});
    }

    child.on('close', (code, signal) => {
      clearTimeout(timer);
      if (killTimer) clearTimeout(killTimer);
      if (settled) return; // timeout / overflow already resolved

      const reason = (stderr.trim() || stdout.trim()).slice(0, REASON_CAPTURE_CHARS);
      const meta = { exitCode: code, signal, timedOut: false, failClosed: false };

      // EXIT CODE IS THE ONLY DECISION SIGNAL. stderr is display text only.
      switch (code) {
        case 0:
          done({ decision: 'allow', reason: reason || 'Allowed.', meta });
          return;
        case 1:
          // Analyzer "warn" tier. Pi has no warn; the adapter decides whether to
          // notify+allow or escalate. We surface it as 'ask' so the adapter can
          // choose; a pure-warn caller can downgrade. Default reason carried.
          done({
            decision: 'ask',
            reason: reason || 'Command flagged for confirmation.',
            meta,
          });
          return;
        case 2:
          done({ decision: 'block', reason: reason || 'Command blocked by guard.', meta });
          return;
        default:
          // Unknown exit, signal kill we didn't initiate, etc. => fail closed.
          done(
            failClosed(
              `Guard exited unexpectedly (code=${code}, signal=${signal}) — denied as fail-safe.`,
              { exitCode: code, signal, timedOut: false },
            ),
          );
      }
    });

    // FIX 1: Node stream write errors (EPIPE and friends) fire as an async
    // 'error' EVENT on child.stdin — they do NOT throw synchronously. Without
    // this listener the unhandled error event becomes an uncaughtException and
    // crashes the host process. We swallow it here: EPIPE is not a decision
    // signal (the child already exited and its 'close' event carries the real
    // verdict). Do NOT resolve the promise from this handler — let 'close',
    // 'error' on the child process, or the timeout drive the decision.
    if (child.stdin) {
      child.stdin.on('error', () => {
        // intentional no-op: EPIPE / write-after-end are benign here;
        // child.on('close') or child.on('error') will resolve the promise.
      });
    }

    // Pipe the envelope and close stdin so `cat` in the script returns.
    try {
      child.stdin.write(envelope);
      child.stdin.end();
    } catch (err) {
      clearTimeout(timer);
      killGroup('SIGKILL');
      done(
        failClosed(`Guard stdin write failed (${err.code || err.message}) — denied as fail-safe.`, {
          exitCode: null,
          signal: null,
          timedOut: false,
        }),
      );
    }
  });
}

/**
 * @param {string} reason
 * @param {{exitCode:number|null,signal:string|null,timedOut:boolean,outputOverflow?:boolean}} m
 * @returns {Decision}
 */
function failClosed(reason, m) {
  return {
    decision: 'block',
    reason,
    meta: { ...m, failClosed: true },
  };
}
