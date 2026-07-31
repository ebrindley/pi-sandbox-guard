// degraded.mjs — proves the adapter BLOCKS ALL bash when the guard is unhealthy.
//
// We can't change process.platform in-process, so we force preflight to report
// the analyzer missing: copy src/ into a temp dir WITHOUT vendor/, import that
// isolated copy, and assert that even a benign command is blocked.
//
// Run: node test/degraded.mjs

import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, copyFileSync, existsSync, writeFileSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname } from 'node:path';
import { preflight } from '../src/guard-core.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const srcDir = join(here, '..', 'src');

let pass = 0;
let fail = 0;
const results = [];

async function check(name, fn) {
  try {
    await fn();
    pass++;
    results.push(`  ok   ${name}`);
  } catch (err) {
    fail++;
    results.push(`  FAIL ${name}\n         ${err.message}`);
  }
}

async function main() {
  // Build an isolated copy: <tmp>/src/{index,guard-core,pi-types.d}.mjs but NO
  // <tmp>/vendor/, so guard-core's VENDORED_SCRIPT path does not exist ->
  // preflight scriptPresent=false -> health.ok=false -> degraded block-all.
  const root = mkdtempSync(join(tmpdir(), 'pi-sandbox-guard-degraded-'));
  mkdirSync(join(root, 'src'));
  for (const f of ['index.mjs', 'guard-core.mjs']) {
    copyFileSync(join(srcDir, f), join(root, 'src', f));
  }
  assert.equal(existsSync(join(root, 'vendor')), false, 'temp must NOT have vendor/');

  const mod = await import(pathToFileURL(join(root, 'src', 'index.mjs')).href);
  const calls = [];
  mod.default({
    isToolCallEventType: (n, e) => n === 'bash' && e.toolName === 'bash',
    on: (t, h) => {
      if (t === 'tool_call') calls.push(h);
    },
  });
  const handler = calls[0];

  await check('degraded: benign `echo hi` is BLOCKED (block-all)', async () => {
    const r = await handler({ toolName: 'bash', input: { command: 'echo hi', cwd: tmpdir() } }, {});
    assert.ok(r && r.block === true, `expected block, got ${JSON.stringify(r)}`);
    assert.match(r.reason, /Guard unavailable/i);
  });

  await check('degraded: `ls` is BLOCKED (no command escapes)', async () => {
    const r = await handler({ toolName: 'bash', input: { command: 'ls', cwd: tmpdir() } }, {});
    assert.ok(r && r.block === true, `expected block, got ${JSON.stringify(r)}`);
  });

  await check('degraded: non-bash tool still passes through', async () => {
    const r = await handler({ toolName: 'read', input: { path: '/etc/hosts' } }, {});
    assert.equal(r, undefined);
  });

  // --- Functional preflight: present-but-BROKEN helpers must be reported ---
  // A `command -v`-style presence check would pass these; executing the no-op
  // probe must not. Originally a regression for the macOS python3 CLT-stub
  // failure mode; canonicalization now uses the pinned GUARD_NODE interpreter,
  // so `jq` stands in as the present-but-broken PATH helper.
  await check('preflight: present-but-broken helper -> reported missing', async () => {
    const binDir = mkdtempSync(join(tmpdir(), 'pi-sandbox-guard-brokenbin-'));
    // Broken jq: exists, is executable, exits nonzero on any invocation.
    // Other helpers resolve from the real system dirs.
    writeFileSync(join(binDir, 'jq'), '#!/bin/sh\nexit 1\n');
    chmodSync(join(binDir, 'jq'), 0o755);
    const pf = await preflight({ path: `${binDir}:/usr/bin:/bin:/usr/sbin:/sbin` });
    assert.ok(pf.missing.includes('jq'), `broken jq not detected: ${JSON.stringify(pf)}`);
    assert.equal(pf.ok, false);
  });

  await check('preflight: helper absent from PATH -> reported missing', async () => {
    const emptyDir = mkdtempSync(join(tmpdir(), 'pi-sandbox-guard-emptybin-'));
    const pf = await preflight({ path: emptyDir });
    // Nothing resolves on PATH. GUARD_NODE is pinned ABSOLUTELY, so it is
    // deliberately unaffected by a PATH override and must NOT appear here —
    // that immunity is the reason for the design.
    assert.deepEqual([...pf.missing].sort(), ['awk', 'bash', 'jq']);
    assert.equal(pf.ok, false);
  });

  // --- GUARD_NODE: the pinned canonicalizer is probed independently of PATH ---
  await check('preflight: broken GUARD_NODE -> reported missing', async () => {
    const binDir = mkdtempSync(join(tmpdir(), 'pi-sandbox-guard-brokennode-'));
    const fakeNode = join(binDir, 'node');
    writeFileSync(fakeNode, '#!/bin/sh\nexit 1\n');
    chmodSync(fakeNode, 0o755);
    const pf = await preflight({ nodeBin: fakeNode });
    assert.ok(
      pf.missing.includes('node(GUARD_NODE)'),
      `broken GUARD_NODE not detected: ${JSON.stringify(pf)}`,
    );
    assert.equal(pf.ok, false);
  });

  await check('preflight: absent GUARD_NODE -> reported missing', async () => {
    const pf = await preflight({ nodeBin: join(tmpdir(), 'pi-sandbox-guard-no-such-node') });
    assert.ok(
      pf.missing.includes('node(GUARD_NODE)'),
      `absent GUARD_NODE not detected: ${JSON.stringify(pf)}`,
    );
    assert.equal(pf.ok, false);
  });

  // Degraded mode must remain fail-closed for ask-tier commands too (no silent
  // headless allow, and no path that re-opens bash while the guard is down).
  await check('degraded: ask-tier command is BLOCKED (no headless allow)', async () => {
    const r = await handler(
      { toolName: 'bash', input: { command: 'rm -rf $HOME', cwd: tmpdir() } },
      {},
    );
    assert.ok(r && r.block === true, `expected block, got ${JSON.stringify(r)}`);
    assert.match(r.reason, /Guard unavailable/i);
  });

  console.log(results.join('\n'));
  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}

main();
