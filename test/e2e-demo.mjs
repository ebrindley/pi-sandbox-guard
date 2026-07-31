// e2e-demo.mjs — live end-to-end demonstration of the guard through the Pi
// adapter, against a real temp project directory. Not part of `npm test`; run
// manually: node test/e2e-demo.mjs
//
// Builds a realistic target project, simulates the Pi runtime, drives the real
// tool_call handler over a set of commands an agent might issue, and prints the
// verdict for each — then proves the project is untouched (the guard analyzes,
// it never executes).

import { mkdtempSync, mkdirSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import mod from '../src/index.mjs';

const proj = mkdtempSync(join(tmpdir(), 'e2e-target-'));
mkdirSync(join(proj, 'src'));
mkdirSync(join(proj, 'node_modules'));
writeFileSync(join(proj, 'src', 'app.js'), 'console.log(1)\n');
writeFileSync(join(proj, 'keepme.txt'), 'important\n');

const calls = [];
mod({
  isToolCallEventType: (n, e) => n === 'bash' && e.toolName === 'bash',
  on: (t, h) => {
    if (t === 'tool_call') calls.push(h);
  },
});
const handler = calls[0];
await new Promise((r) => setTimeout(r, 150)); // let preflight settle

const ctxDecline = { cwd: proj, ui: { confirm: async () => false, notify: () => {} } };
const ctxHeadless = { cwd: proj };

const verdictOf = (r) => (r === undefined ? 'ALLOW' : r && r.block ? 'BLOCK' : '??');

// fork-bomb literal assembled from parts so it is not present verbatim anywhere.
const forkBomb = [':()', '{ :', '|:& };:'].join('');

const scenarios = [
  ['benign build', 'npm run build', ctxHeadless, 'ALLOW'],
  ['list files', 'ls -la src/', ctxHeadless, 'ALLOW'],
  ['clean node_modules (relative, in-proj)', 'rm -rf node_modules', ctxHeadless, 'ALLOW'],
  ['CATASTROPHIC root wipe', 'rm -rf /', ctxHeadless, 'BLOCK'],
  ['CATASTROPHIC home wipe (ask->declined)', 'rm -rf $HOME', ctxDecline, 'BLOCK'],
  ['fork bomb', forkBomb, ctxHeadless, 'BLOCK'],
  ['mkfs a disk', 'mkfs.ext4 /dev/sda1', ctxHeadless, 'BLOCK'],
  ['dd over raw disk', 'dd if=/dev/zero of=/dev/sda', ctxHeadless, 'BLOCK'],
  ['compound ending in rm /', 'cd /tmp && echo hi && rm -rf /', ctxHeadless, 'BLOCK'],
];

console.log('LIVE E2E — target project:', proj);
console.log('-'.repeat(78));
let mismatches = 0;
for (const [label, command, ctx, expect] of scenarios) {
  const r = await handler({ toolName: 'bash', input: { command, cwd: proj } }, ctx);
  const v = verdictOf(r);
  const flag = v === expect ? ' ' : 'X';
  if (v !== expect) mismatches++;
  const shown = command.length > 34 ? command.slice(0, 31) + '...' : command;
  console.log(`${flag} ${v.padEnd(6)} (exp ${expect.padEnd(6)}) | ${label.padEnd(40)} | ${shown}`);
}
console.log('-'.repeat(78));

const intact =
  existsSync(join(proj, 'keepme.txt')) &&
  existsSync(join(proj, 'src', 'app.js')) &&
  existsSync(join(proj, 'node_modules'));
console.log('project intact after analysis (guard never executed anything):', intact);
console.log(mismatches === 0 && intact ? '\nE2E OK: all verdicts as expected, no side effects.' : `\nE2E FAILED: ${mismatches} verdict mismatch(es).`);
process.exit(mismatches === 0 && intact ? 0 : 1);
