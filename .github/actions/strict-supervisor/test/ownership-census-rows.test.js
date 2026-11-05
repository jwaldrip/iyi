import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { OwnershipObserver } from '../src/ownership.js';

const python = process.env.PYTHON || 'python3';
const probe = fileURLToPath(new URL('../src/process_identity.py', import.meta.url));

// PID 0 (kernel_task on Darwin) and PID 1 (launchd, or init on Linux) are valid census rows.
// Darwin's kern.proc census self-check requires PID 1; the observer must accept both.

test('the real batch helper lists PID 1 in its census, and the observer census accepts it', t => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ownership-census-rows-'));
  const observer = new OwnershipObserver(python, probe, { tempRoot, graceSec: 0.1 });
  t.after(() => { observer.close(); fs.rmSync(tempRoot, { recursive: true, force: true }); });
  const reply = JSON.parse(execFileSync(python, [probe, '--batch'], {
    input: JSON.stringify({ pids: [], census: true }), encoding: 'utf8', timeout: 10000,
  }));
  assert.equal(reply.census.error, undefined, reply.census.error);
  assert.ok(reply.census.rows.some(row => row[0] === 1), 'PID 1 is listed');
  const rows = observer.census();
  assert.ok(rows.has(1), 'the observer census keeps PID 1');
  assert.equal(observer.failure, null);
});

test('a Darwin-shaped census with PIDs 0 and 1 parses through the observer without a census error', t => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ownership-census-fixture-'));
  const helper = path.join(tempRoot, 'fixture-helper.mjs');
  // Stands in for process_identity.py --batch: it answers the same request shape with Darwin-like rows.
  fs.writeFileSync(helper, `import fs from 'node:fs';
const request = JSON.parse(fs.readFileSync(0, 'utf8'));
const identities = Object.fromEntries(request.pids.map(pid => [String(pid), { status: 'LIVE', pid, birth: '1.000001', ppid: 1, state: 'S' }]));
process.stdout.write(JSON.stringify({ census: { rows: [[0, 0, 'S', null], [1, 0, 'Ss', '1.000001'], [42, 1, 'S', '2.000002']] }, identities }));
`);
  const observer = new OwnershipObserver(process.execPath, helper, { tempRoot, graceSec: 0.1 });
  t.after(() => { observer.close(); fs.rmSync(tempRoot, { recursive: true, force: true }); });
  const rows = observer.census();
  assert.deepEqual([...rows.keys()].sort((a, b) => a - b), [0, 1, 42]);
  assert.equal(rows.get(42), 1);
  assert.equal(observer.failure, null);
});

test('a census row that is not a process identity is still refused', t => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ownership-census-bad-'));
  const helper = path.join(tempRoot, 'bad-helper.mjs');
  fs.writeFileSync(helper, `process.stdout.write(JSON.stringify({ census: { rows: [[-3, 0, 'S', '1.000001']] }, identities: {} }));\n`);
  const observer = new OwnershipObserver(process.execPath, helper, { tempRoot, graceSec: 0.1 });
  t.after(() => { observer.close(); fs.rmSync(tempRoot, { recursive: true, force: true }); });
  assert.throws(() => observer.census(), /invalid census row/);
});
