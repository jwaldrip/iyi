import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { OwnershipObserver } from '../src/ownership.js';

// The fixture is a real subprocess: exercise readSnapshot, not an overridden census adapter.
for (const scenario of [
  { name: 'child precedes parent', rows: [[102, 101, '1', '2.000000'], [101, 99, '1', '1.000000']], adopted: true },
  { name: 'zombie parent retains its committed identity', rows: [[102, 101, '1', '2.000000'], [101, 99, 'Z', '1.000000']], adopted: true },
  { name: 'parent missing', rows: [[102, 101, '1', '2.000000']], adopted: false },
  { name: 'parent birth changed', rows: [[102, 101, '1', '3.000000'], [101, 99, '1', '2.000000']], adopted: false },
  { name: 'equal births', rows: [[102, 101, '1', '1.000000'], [101, 99, '1', '1.000000']], adopted: false },
  { name: 'child older than parent', rows: [[102, 101, '1', '0.999999'], [101, 99, '1', '1.000000']], adopted: false },
  { name: 'later row born before call', rows: [[101, 99, '1', '1.000000'], [102, 101, '1', '2.000000']], start: 2000001, adopted: true },
  { name: 'later row born at call start', rows: [[101, 99, '1', '1.000000'], [102, 101, '1', '2.000000']], start: 2000000, adopted: false },
  { name: 'later row born after call start', rows: [[101, 99, '1', '1.000000'], [102, 101, '1', '2.000000']], start: 1999999, adopted: false },
  { name: 'later row without call start', rows: [[101, 99, '1', '1.000000'], [102, 101, '1', '2.000000']], adopted: false },
]) {
  test(`edge rule: ${scenario.name}`, async t => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ownership-edge-'));
    const helper = path.join(dir, 'helper.mjs');
    const data = path.join(dir, 'reply.json');
    fs.writeFileSync(helper, `import fs from 'node:fs';\nconst req = JSON.parse(fs.readFileSync(0, 'utf8'));\nconst c = JSON.parse(fs.readFileSync(${JSON.stringify(data)}, 'utf8'));\nconst identities = Object.fromEntries(req.pids.map(pid => [pid, {status:'LIVE', pid, ppid:99, state:'1', birth:'1.000000'}]));\nconsole.log(JSON.stringify({identities, census:c}));\n`);
    fs.writeFileSync(data, JSON.stringify({ rows: [[101, 99, '1', '1.000000']], call_start_wall_us: 3000000 }));
    const observer = new OwnershipObserver(process.execPath, helper, { tempRoot: dir, graceSec: 0 });
    t.after(() => { observer.close(); fs.rmSync(dir, { recursive: true, force: true }); });
    observer.register({ pid: 101, unit: 'edge', native_attempt: 1 }, 99);
    clearInterval(observer.timer); observer.timer = null;
    const census = { rows: scenario.rows };
    if (scenario.start !== undefined) census.call_start_wall_us = scenario.start;
    fs.writeFileSync(data, JSON.stringify(census));
    observer.observe();
    assert.equal(observer.stages.get(101).owned.has(102), scenario.adopted);
    if (!scenario.adopted) {
      assert.ok(observer.taintReasons.some(reason => reason === 'ambiguous ancestry: 101 -> 102'));
      const signals = [];
      observer.signal = pid => signals.push(pid);
      observer.probeOne = pid => ({ status: 'ABSENT', pid });
      await observer.recover();
      assert.ok(!signals.includes(102), 'unproven child must never be signalled');
    } else assert.deepEqual(observer.taintReasons, []);
  });
}
