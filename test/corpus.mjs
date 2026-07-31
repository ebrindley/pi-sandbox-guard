// corpus.mjs — golden characterization corpus runner.
//
// Run: node test/corpus.mjs
//
// Executes every case in test/corpus/corpus.json through analyzeCommand() (the
// full guard path: the in-tree analyzer + guard-level hardening like the ANSI-C
// reveal-only probe) and diffs the verdicts against the recorded expectations.
//
// Why this exists: the analyzer is owned and maintained in this repository.
// Editing or rewriting it, or adding guard-level mitigation, MUST show up as an
// explicit verdict diff here, never as a silent behavior change.
//
// expectFail semantics (known gaps): a case marked expectFail is EXPECTED to
// mismatch its recorded expectation.
//   - still mismatching  -> reported as a known gap, does NOT fail the run
//   - now MATCHING       -> fails the run as a fixed gap: update the
//     corpus entry (drop expectFail) and KNOWN_ANALYZER_GAPS.md together, so
//     the docs can never silently go stale again.

import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir, homedir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { analyzeCommand, preflight } from '../src/guard-core.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CORPUS_PATH = join(__dirname, 'corpus', 'corpus.json');

function loadCorpus() {
  const raw = JSON.parse(readFileSync(CORPUS_PATH, 'utf8'));
  assert.ok(Array.isArray(raw.cases) && raw.cases.length > 0, 'corpus has no cases');
  for (const [i, c] of raw.cases.entries()) {
    assert.equal(typeof c.command, 'string', `case ${i}: command must be a string`);
    assert.ok(
      (c.expect && ['allow', 'ask', 'block'].includes(c.expect)) ||
        (c.expectNot && ['allow', 'ask', 'block'].includes(c.expectNot)),
      `case ${i} (${c.command}): needs expect or expectNot of allow|ask|block`,
    );
    if (c.expectFail) {
      assert.ok(
        ['allow', 'ask', 'block'].includes(c.actual),
        `case ${i} (${c.command}): expectFail requires "actual" of allow|ask|block (its current real verdict)`,
      );
      // An `actual` that already satisfies `expect`/`expectNot` is contradictory
      // (the case both is and isn't a gap). Reject it.
      const actualMatches = c.expect ? c.actual === c.expect : c.actual !== c.expectNot;
      assert.ok(
        !actualMatches,
        `case ${i} (${c.command}): "actual" (${c.actual}) already satisfies the expectation — not a gap; remove expectFail/actual`,
      );
    }
  }
  return raw.cases;
}

async function main() {
  const pf = await preflight();
  if (!pf.ok) {
    // Without a healthy analyzer every verdict is a fail-closed block and the
    // corpus would be meaningless noise. Fail loudly instead of pseudo-passing.
    console.error(
      `corpus: guard preflight unhealthy (missing=[${pf.missing.join(',')}] scriptPresent=${pf.scriptPresent}); cannot characterize verdicts.`,
    );
    process.exit(1);
  }

  // Scratch dirs: {TMP} is a plain temp dir, {REPO} is a scratch git repo (so
  // repo-root-derived safe roots are exercised deterministically).
  //
  // {REPO} must live OUTSIDE the analyzer's tmp-family safe roots (/tmp,
  // /private/tmp, /var/folders): on Linux tmpdir() is /tmp, so a scratch repo
  // there gets tmp-safe-root treatment and absolute-path rm verdicts flip from
  // block to allow, diverging from the recorded (repo-root-only) expectations.
  // HOME is not a safe root on any platform, so verdicts are stable there.
  const TMP = mkdtempSync(join(tmpdir(), 'guard-corpus-tmp-'));
  const REPO = mkdtempSync(join(homedir(), '.guard-corpus-repo-'));
  execFileSync('git', ['init', '-q', REPO]);
  mkdirSync(join(REPO, 'build'), { recursive: true });
  writeFileSync(join(REPO, 'build', 'artifact.txt'), 'x\n');

  const resolvePlaceholders = (s) => s.replaceAll('{TMP}', TMP).replaceAll('{REPO}', REPO);

  const cases = loadCorpus();
  let pass = 0;
  let fail = 0;
  let knownGaps = 0;
  const lines = [];

  for (const c of cases) {
    const command = resolvePlaceholders(c.command);
    const cwd = resolvePlaceholders(c.cwd || '{TMP}');
    const v = await analyzeCommand(command, { cwd, timeoutMs: 5000, home: process.env.HOME });

    // Platform-conditional expectation: some vendored-analyzer verdicts are
    // genuinely OS-dependent (e.g. the /Users/* blanket catastrophic rule only
    // exists for macOS home layouts; /home has no equivalent). expectOn
    // overrides expect for the named process.platform.
    const expect = (c.expectOn && c.expectOn[process.platform]) || c.expect;
    const matches = expect ? v.decision === expect : v.decision !== c.expectNot;
    const wanted = expect ? expect : `not ${c.expectNot}`;

    if (c.expectFail) {
      // A documented gap MUST pin its current actual verdict via `actual`. We
      // fail whenever the live verdict differs from `actual` — in EITHER
      // direction — so any movement (gap fixed to the wanted verdict, OR the gap
      // shifting to some third verdict) forces the corpus and
      // KNOWN_ANALYZER_GAPS.md to be updated. Matching `wanted` while also equal
      // to `actual` would be a contradictory entry, caught by loadCorpus().
      if (typeof c.actual !== 'string') {
        fail++;
        lines.push(
          `  FAIL [${v.decision.padEnd(5)}] ${c.command}\n` +
            `         expectFail case is missing the required "actual" field (its\n` +
            `         current real verdict). Add "actual": "${v.decision}".`,
        );
        continue;
      }
      if (v.decision === c.actual) {
        knownGaps++;
        lines.push(
          `  gap  [${v.decision.padEnd(5)}] ${c.command}  (documented gap; wanted ${wanted})`,
        );
      } else {
        fail++;
        const verb = matches ? 'appears FIXED' : 'has CHANGED';
        lines.push(
          `  FAIL [${v.decision.padEnd(5)}] ${c.command}\n` +
            `         documented gap ${verb}: pinned actual="${c.actual}", now "${v.decision}".\n` +
            `         Update this corpus entry (adjust/remove expectFail + actual)\n` +
            `         and KNOWN_ANALYZER_GAPS.md in the same change.`,
        );
      }
      continue;
    }

    if (matches) {
      pass++;
    } else {
      fail++;
      lines.push(
        `  FAIL [${v.decision.padEnd(5)}] ${c.command}\n` +
          `         wanted ${wanted}, got ${v.decision} (${v.reason.slice(0, 160)})${c.note ? `\n         note: ${c.note}` : ''}`,
      );
    }
  }

  rmSync(TMP, { recursive: true, force: true });
  rmSync(REPO, { recursive: true, force: true });

  if (lines.length) console.log(lines.join('\n'));
  console.log(
    `\ncorpus: ${pass} matched, ${knownGaps} known gaps (expected), ${fail} FAILED of ${cases.length} cases`,
  );
  process.exit(fail === 0 ? 0 : 1);
}

main();
