// adapter.mjs — tests the Pi adapter (index.mjs) decision mapping with a fake
// Pi API/ctx, so we cover paths the core-only smoke test cannot:
//   - degraded mode blocks ALL bash (FIX 1)
//   - confirm() throwing fails closed (FIX 2)
//   - ask declined -> block; ask accepted -> allow
//   - non-bash tool passes through; empty command passes through
//
// Run: node test/adapter.mjs

import assert from 'node:assert/strict';
import { tmpdir } from 'node:os';

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

/**
 * Load index.mjs and capture its registered tool_call handler.
 * A dummy shim marker keeps the load-time filter-only diagnostic out of this
 * suite's output; the warning itself is asserted explicitly further down.
 */
async function loadHandler() {
  const calls = [];
  const pi = {
    isToolCallEventType: (n, e) => n === 'bash' && e.toolName === 'bash',
    on: (t, h) => {
      if (t === 'tool_call') calls.push(h);
    },
  };
  const prev = process.env.PI_SANDBOX_PROFILE_DIGEST;
  process.env.PI_SANDBOX_PROFILE_DIGEST = 'test-suite-nonempty';
  const mod = await import('../src/index.mjs');
  try {
    mod.default(pi);
  } finally {
    if (prev === undefined) delete process.env.PI_SANDBOX_PROFILE_DIGEST;
    else process.env.PI_SANDBOX_PROFILE_DIGEST = prev;
  }
  assert.equal(calls.length, 1, 'expected exactly one tool_call handler');
  return calls[0];
}

function bashEvent(command, cwd = tmpdir()) {
  return { toolName: 'bash', input: { command, cwd } };
}

/**
 * Load index.mjs with a FRESH module instance (cache-busting query) under a
 * given PI_SANDBOX_PROFILE_DIGEST, capturing stderr written during load.
 * A fresh instance is required because the filter-only warning fires once, at
 * module factory time.
 */
async function loadCapturingStderr(digest, tag) {
  const prev = process.env.PI_SANDBOX_PROFILE_DIGEST;
  if (digest === undefined) delete process.env.PI_SANDBOX_PROFILE_DIGEST;
  else process.env.PI_SANDBOX_PROFILE_DIGEST = digest;

  const lines = [];
  const origError = console.error;
  console.error = (...args) => lines.push(args.join(' '));
  const calls = [];
  try {
    const mod = await import(`../src/index.mjs?filter-only=${tag}`);
    mod.default({
      isToolCallEventType: (n, e) => n === 'bash' && e.toolName === 'bash',
      on: (t, h) => {
        if (t === 'tool_call') calls.push(h);
      },
    });
  } finally {
    console.error = origError;
    if (prev === undefined) delete process.env.PI_SANDBOX_PROFILE_DIGEST;
    else process.env.PI_SANDBOX_PROFILE_DIGEST = prev;
  }
  return { stderr: lines.join('\n'), handler: calls[0] };
}

async function main() {
  const handler = await loadHandler();

  await check('non-bash tool -> pass through (undefined)', async () => {
    const r = await handler({ toolName: 'read', input: { path: '/etc/hosts' } }, {});
    assert.equal(r, undefined);
  });

  await check('empty command -> pass through (no-op)', async () => {
    const r = await handler(bashEvent('   '), {});
    assert.equal(r, undefined);
  });

  await check('benign command (healthy) -> allow', async () => {
    const r = await handler(bashEvent('ls -la'), {});
    assert.equal(r, undefined);
  });

  await check('catastrophic command (healthy) -> block', async () => {
    const r = await handler(bashEvent('rm -rf /'), {});
    assert.ok(r && r.block === true, `expected block, got ${JSON.stringify(r)}`);
  });

  // Filter-only diagnostic: the shim's launch marker is absent, so the guard
  // announces that it could not verify OS-sandbox confinement. It must WARN
  // ONLY — filter-only is a documented deployment mode, so bash keeps working.
  await check('no shim marker -> one FILTER-ONLY warning, still non-blocking', async () => {
    const { stderr, handler: h } = await loadCapturingStderr(undefined, 'absent');
    const hits = stderr.split('\n').filter((l) => l.includes('FILTER-ONLY'));
    assert.equal(hits.length, 1, `expected exactly one FILTER-ONLY line, got ${hits.length}`);
    assert.match(stderr, /could not verify/, 'must not claim positive detection');
    const r = await h(bashEvent('ls -la'), {});
    assert.equal(r, undefined, 'benign bash must still be allowed (warn, not block)');
  });

  // Marker present -> silence. This documents that the signal is ambient and
  // therefore silenceable; absence of the warning is NOT proof of confinement.
  await check('shim marker present -> no FILTER-ONLY warning', async () => {
    const { stderr } = await loadCapturingStderr('deadbeef', 'present');
    assert.ok(!stderr.includes('FILTER-ONLY'), `expected silence, got: ${stderr}`);
  });

  // FIX 2: confirm() that throws must fail closed (block), not escape.
  await check('FIX2: ask + confirm throws -> block (fail-closed)', async () => {
    const ctx = {
      ui: {
        confirm: async () => {
          throw new Error('UI exploded');
        },
      },
    };
    // rm -rf $HOME is an analyzer "ask" (unresolvable expansion).
    const r = await handler(bashEvent('rm -rf $HOME'), ctx);
    assert.ok(r && r.block === true, `expected block, got ${JSON.stringify(r)}`);
    assert.match(r.reason, /Confirmation UI failed/i);
  });

  await check('ask + confirm declines -> block', async () => {
    const ctx = { ui: { confirm: async () => false } };
    const r = await handler(bashEvent('rm -rf $HOME'), ctx);
    assert.ok(r && r.block === true, `expected block, got ${JSON.stringify(r)}`);
  });

  await check('ask + confirm accepts -> allow', async () => {
    const ctx = { ui: { confirm: async () => true } };
    const r = await handler(bashEvent('rm -rf $HOME'), ctx);
    assert.equal(r, undefined);
  });

  await check('ask + no UI -> always block (no silent allow path)', async () => {
    const r = await handler(bashEvent('rm -rf $HOME'), {});
    assert.ok(r && r.block === true, `expected block, got ${JSON.stringify(r)}`);
    assert.match(r.reason, /no interactive confirm available/i);
  });

  await check('ask + ui without confirm function -> block (no-UI deny)', async () => {
    // notify-only ui must not open a silent allow path.
    const ctx = { ui: { notify: () => {} } };
    const r = await handler(bashEvent('rm -rf $HOME'), ctx);
    assert.ok(r && r.block === true, `expected block, got ${JSON.stringify(r)}`);
    assert.match(r.reason, /no interactive confirm available/i);
  });

  // FIX 1 degraded block-all is exercised for real in test/degraded.mjs (it
  // imports an isolated copy of src/ without vendor/ so preflight reports the
  // analyzer missing). Here we confirm malformed bash payloads fail closed.
  await check('malformed command payload -> block (fail-closed)', async () => {
    const r = await handler({ toolName: 'bash', input: {} }, {});
    assert.ok(r && r.block === true, `expected block, got ${JSON.stringify(r)}`);
  });

  // FIX (review, high): a cwd that exists but is a FILE must fail closed (block),
  // not throw spawn ENOTDIR out of the handler.
  await check('cwd is a file -> block (no throw)', async () => {
    let r;
    try {
      r = await handler(bashEvent('ls -la', '/etc/hosts'), {});
    } catch (e) {
      assert.fail(`handler threw instead of blocking: ${e.message}`);
    }
    assert.ok(r && r.block === true, `expected block, got ${JSON.stringify(r)}`);
  });

  // FIX (review, medium): contradictory cwds must take the WORST verdict. The
  // repro: `rm -rf .` with input.cwd=/tmp (a safe root -> ask) but ctx.cwd=/
  // (catastrophic -> block). Even with confirm()->true, the block from `/` wins.
  await check('worst-of-cwd: input.cwd=/tmp vs ctx.cwd=/ -> block wins', async () => {
    const ctx = { cwd: '/', ui: { confirm: async () => true } };
    const event = { toolName: 'bash', input: { command: 'rm -rf .', cwd: '/tmp' }, cwd: '/' };
    const r = await handler(event, ctx);
    assert.ok(r && r.block === true, `expected block (catastrophic cwd wins), got ${JSON.stringify(r)}`);
  });

  // INVARIANT (Tier 1b): the policy boundary must NEVER be defined by
  // model-influenced input alone. event.input is model-mutable, so a model that
  // supplies a benign-looking input.cwd MUST NOT be able to downgrade a verdict
  // that a genuine execution directory (ctx.cwd) would produce. This is the
  // pi-sandbox-guard analog of Codex CVE-2025-59532 (model-supplied cwd was
  // treated as the sandbox writable root -> arbitrary write). candidateCwds
  // analyzes ALL distinct real directories and takes the worst, so the trusted
  // ctx.cwd verdict cannot be masked by a crafted input.cwd. Here `rm -rf .`
  // under ctx.cwd=/ is catastrophic; input.cwd=/tmp is the model's attempt to
  // relocate the boundary to a safe root. The block from `/` must still win even
  // though confirm()->true would allow the /tmp reading.
  await check('boundary invariant: model-supplied input.cwd cannot downgrade the trusted-cwd verdict', async () => {
    const ctx = { cwd: '/', ui: { confirm: async () => true } };
    // Only input.cwd is model-benign here; the real ctx.cwd=/ is catastrophic.
    const event = { toolName: 'bash', input: { command: 'rm -rf .', cwd: '/tmp' }, cwd: undefined };
    const r = await handler(event, ctx);
    assert.ok(
      r && r.block === true,
      `model-supplied input.cwd downgraded the verdict — boundary was taken from model input! got ${JSON.stringify(r)}`,
    );
  });

  // POLICY_ASK_FALLBACK=allow must NOT open a headless allow path. Load an
  // isolated copy of the adapter with the env var set; ask + no UI still blocks.
  await check('POLICY_ASK_FALLBACK=allow is ignored — no-UI ask still blocks', async () => {
    const { mkdtempSync, mkdirSync, copyFileSync, existsSync } = await import('node:fs');
    const { join, dirname } = await import('node:path');
    const { fileURLToPath, pathToFileURL } = await import('node:url');
    const here = dirname(fileURLToPath(import.meta.url));
    const repoRoot = join(here, '..');
    const root = mkdtempSync(join(tmpdir(), 'pi-sandbox-guard-askfb-'));
    mkdirSync(join(root, 'src'));
    mkdirSync(join(root, 'vendor'));
    copyFileSync(join(repoRoot, 'src', 'index.mjs'), join(root, 'src', 'index.mjs'));
    copyFileSync(join(repoRoot, 'src', 'guard-core.mjs'), join(root, 'src', 'guard-core.mjs'));
    copyFileSync(
      join(repoRoot, 'vendor', 'validate-bash-command.sh'),
      join(root, 'vendor', 'validate-bash-command.sh'),
    );
    assert.ok(existsSync(join(root, 'vendor', 'validate-bash-command.sh')));

    const prev = process.env.POLICY_ASK_FALLBACK;
    process.env.POLICY_ASK_FALLBACK = 'allow';
    try {
      const mod = await import(pathToFileURL(join(root, 'src', 'index.mjs')).href);
      const calls = [];
      mod.default({
        isToolCallEventType: (n, e) => n === 'bash' && e.toolName === 'bash',
        on: (t, h) => {
          if (t === 'tool_call') calls.push(h);
        },
      });
      const h = calls[0];
      const r = await h({ toolName: 'bash', input: { command: 'rm -rf $HOME', cwd: tmpdir() } }, {});
      assert.ok(r && r.block === true, `expected block under POLICY_ASK_FALLBACK=allow, got ${JSON.stringify(r)}`);
      assert.match(r.reason, /no interactive confirm available/i);
    } finally {
      if (prev === undefined) delete process.env.POLICY_ASK_FALLBACK;
      else process.env.POLICY_ASK_FALLBACK = prev;
    }
  });

  console.log(results.join('\n'));
  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}

main();
