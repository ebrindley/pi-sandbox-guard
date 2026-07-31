// index.mjs — Pi extension entry point for pi-sandbox-guard.
//
// A best-effort, fail-closed PRE-EXECUTION guard for the `bash` tool. It is NOT
// a sandbox: Pi allows later handlers to mutate event.input with no
// re-validation, so this is authoritative only if it runs last and nothing
// rewrites the command afterward (documented limitation — see README).
//
// Maps the harness-agnostic core Decision onto Pi's { block, reason } contract.

import { statSync } from 'node:fs';
import { analyzeCommand, preflight, SEVERITY } from './guard-core.mjs';

/**
 * Collect the DISTINCT, existing-directory cwd candidates for a tool call.
 * Pi may surface the execution directory on event.input.cwd, event.cwd, or
 * ctx.cwd, and event.input is model-mutable — so we do NOT trust any single one
 * as authoritative. We analyze against ALL of them and take the worst verdict
 * (see analyzeWorstCwd), which is fail-safe whichever one bash actually uses.
 * Non-string and non-directory candidates are dropped here; if that leaves
 * none, the caller passes undefined and the core fail-closes.
 */
function candidateCwds(event, ctx) {
  const raw = [event?.input?.cwd, event?.cwd, ctx && ctx.cwd];
  const seen = new Set();
  const dirs = [];
  for (const c of raw) {
    if (typeof c !== 'string' || c.length === 0 || seen.has(c)) continue;
    seen.add(c);
    try {
      if (statSync(c).isDirectory()) dirs.push(c);
    } catch {
      // missing / not a dir / no perms -> ignore this candidate
    }
  }
  return dirs;
}

/**
 * Trusted policy env, sourced from the HOST process — NOT from the target repo.
 * (The core further filters this to an allow-list of keys, so anything not on
 * that list is dropped even if we pass it.) Only POLICY_RM_SAFE_ROOTS is a real,
 * supported knob today. We do NOT forward disarm keys (CLAUDE_ALLOW_RM_RF*),
 * analyzer-native aliases, or dead surfaces (security-log path, bash-guard max
 * bytes): the core allow-list is the single source of truth.
 *
 * POLICY_ASK_FALLBACK is intentionally NOT read. Without an interactive
 * confirm UI, ask verdicts always deny. A silent headless allow path is not
 * supported — ambient env (including host profiles) must not weaken the guard.
 */
function trustedPolicyEnv() {
  const env = {};
  if (process.env.POLICY_RM_SAFE_ROOTS) env.POLICY_RM_SAFE_ROOTS = process.env.POLICY_RM_SAFE_ROOTS;
  return env;
}

/**
 * Announce filter-only operation when the protected shim's launch marker is
 * absent. This is a MISINSTALL DIAGNOSTIC, not a security control:
 *
 *   - The shim exports PI_SANDBOX_PROFILE_DIGEST in the same code path that
 *     applies the Seatbelt profile (sandbox/pi-sandbox-preamble.zsh), and the
 *     launcher execs Pi under `sandbox-exec`, so on the supported path the
 *     marker and real confinement travel together.
 *   - The marker is ambient, so a project .envrc/Makefile can set it and
 *     silence this line, and a stale exported value can outlive the shim
 *     session that produced it. ABSENCE OF THIS WARNING IS THEREFORE NOT PROOF
 *     OF CONFINEMENT. The preamble's own re-entry check deliberately refuses to
 *     trust this digest without behavioral probes; we cannot probe from here.
 *   - Wording says "could not verify" rather than "not detected" because an
 *     unrelated but valid Seatbelt profile would also lack this marker.
 *
 * Warn, never block: filter-only is a documented, legitimate deployment mode
 * (`npm run deploy` without launchers, or a Pi-package install). A missing OS
 * sandbox does not make a healthy analyzer unusable, which is the distinct
 * condition that DEGRADED covers below.
 */
function warnIfUnverifiedSandbox() {
  if (process.env.PI_SANDBOX_PROFILE_DIGEST) return;
  // eslint-disable-next-line no-console
  console.error(
    '[pi-sandbox-guard] FILTER-ONLY: could not verify launch through the protected ' +
      'Seatbelt shim. The bash filter is active; this guard is not applying an OS ' +
      'sandbox, so assume out-of-project writes are uncontained unless you know one ' +
      'is in place by other means. For the full guard, run `npm run deploy:launchers` ' +
      'and `npm run bind` from a pi-sandbox-guard checkout, then launch via the ' +
      '`pi` shim on PATH (startup prints "OS sandbox ON").',
  );
}

/**
 * Pi extension default export.
 * @param {import('./pi-types').ExtensionAPI} pi
 */
export default function (pi) {
  warnIfUnverifiedSandbox();

  // Preflight once at load. If the guard cannot run, we do NOT silently allow:
  // we flip into block-all-bash mode and announce it loudly.
  /** @type {null | Awaited<ReturnType<typeof preflight>>} */
  let health = null;
  const ready = preflight()
    .then((h) => {
      health = h;
      if (!h.ok) {
        const why =
          h.platform === 'win32'
            ? 'unsupported platform (win32, no bash)'
            : !h.scriptPresent
              ? 'analyzer script missing'
              : `missing helpers: ${h.missing.join(', ')}`;
        // eslint-disable-next-line no-console
        console.error(
          `[pi-sandbox-guard] DEGRADED: ${why}. All bash commands will be BLOCKED until fixed.`,
        );
      }
    })
    .catch(() => {
      health = { ok: false, missing: [], scriptPresent: false, platform: process.platform };
    });

  pi.on('tool_call', async (event, ctx) => {
    // Only gate the bash tool. Everything else passes through untouched.
    const isBash =
      typeof pi.isToolCallEventType === 'function'
        ? pi.isToolCallEventType('bash', event)
        : event.toolName === 'bash';
    if (!isBash) return;

    const command = event?.input?.command;
    if (typeof command !== 'string') {
      return {
        block: true,
        reason: '[pi-sandbox-guard] Malformed bash command payload; blocked as fail-safe.',
      };
    }
    // Allow a genuinely empty bash invocation through — it is a no-op. The core
    // also fail-closes on empties if they ever reach it, so this is belt-and-
    // suspenders for the common case.
    if (command.trim().length === 0) return;

    await ready;

    // Guard unavailable (missing analyzer, missing helpers, or win32): BLOCK ALL
    // bash unconditionally. A partial-regex allowlist has been proved to miss real
    // catastrophic commands (find -delete, shred, truncate, wipefs, ANSI-C quoted
    // rm, …). A bricked agent is visible and recoverable; a silently-allowed
    // `shred /dev/sda` is not.
    if (!health || !health.ok) {
      const why = !health
        ? 'preflight failed'
        : health.platform === 'win32'
          ? 'unsupported platform (win32, no bash)'
          : !health.scriptPresent
            ? 'analyzer script missing'
            : `missing helpers: ${health.missing.join(', ')}`;
      return {
        block: true,
        reason: `[pi-sandbox-guard] Guard unavailable (${why}); all bash commands are blocked until the guard is restored.`,
      };
    }

    // Determine the cwd(s) the bash tool might execute in, for correct
    // relative-path analysis. We do NOT trust event.input.cwd as authoritative
    // (event.input is model-mutable, and a wrong cwd could turn a catastrophic
    // `rm -rf .` into an allowed one). Instead we analyze against EVERY distinct
    // candidate directory and take the WORST verdict — fail-safe regardless of
    // which one bash truly uses. If there are no valid candidates we pass
    // undefined and the core fail-closes (block).
    const cwds = candidateCwds(event, ctx);

    // Defense-in-depth: the core is contracted never to throw, but if it ever
    // does (or a future change regresses that), a throw here would escape into
    // Pi's loop. Catch and fail closed.
    let verdict;
    try {
      if (cwds.length === 0) {
        verdict = await analyzeCommand(command, {
          cwd: undefined, // core fail-closes
          trustedPolicyEnv: trustedPolicyEnv(),
          home: process.env.HOME,
        });
      } else {
        const verdicts = await Promise.all(
          cwds.map((cwd) =>
            analyzeCommand(command, {
              cwd,
              trustedPolicyEnv: trustedPolicyEnv(),
              home: process.env.HOME,
            }),
          ),
        );
        // Worst-of: pick the highest-severity verdict (block > ask > allow).
        verdict = verdicts.reduce((worst, v) =>
          SEVERITY[v.decision] > SEVERITY[worst.decision] ? v : worst,
        );
      }
    } catch {
      return { block: true, reason: '[pi-sandbox-guard] Guard errored; blocked as fail-safe.' };
    }

    switch (verdict.decision) {
      case 'allow':
        return; // allow

      case 'block':
        return { block: true, reason: `[pi-sandbox-guard] ${verdict.reason}` };

      case 'ask': {
        // No-UI / headless: always deny. There is no silent allow path and no
        // ambient env knob (POLICY_ASK_FALLBACK is not honored) that can turn
        // ask into allow without an interactive confirm.
        const canConfirm = ctx && ctx.ui && typeof ctx.ui.confirm === 'function';
        if (!canConfirm) {
          return {
            block: true,
            reason: `[pi-sandbox-guard] ${verdict.reason} (no interactive confirm available; blocked)`,
          };
        }
        // Wrap confirm so a UI error fails closed rather than propagating an
        // uncaught rejection into Pi's event loop.
        try {
          const ok = await ctx.ui.confirm(
            'Potentially dangerous command',
            `${verdict.reason}\n\nAllow it to run?`,
          );
          return ok ? undefined : { block: true, reason: '[pi-sandbox-guard] Declined by user.' };
        } catch {
          return {
            block: true,
            reason: '[pi-sandbox-guard] Confirmation UI failed; blocked as fail-safe.',
          };
        }
      }

      default:
        // Unreachable; core only emits allow/ask/block. Fail closed anyway.
        return { block: true, reason: '[pi-sandbox-guard] Unknown verdict — blocked as fail-safe.' };
    }
  });
}
