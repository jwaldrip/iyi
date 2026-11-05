import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { OwnershipObserver } from '../src/ownership.js';
import { simulatedObserver, entry } from './simulated-observer.js';

const python = process.env.PYTHON || 'python3';
const probe = fileURLToPath(new URL('../src/process_identity.py', import.meta.url));

// W-scale churn: the stage launches children in waves. Each child lives about 150 ms, and the
// stage reaps every child it has launched, so the observer sees hundreds of short-lived
// processes come and go under one stage.
const stageCode = `import subprocess,time
live=[]
for wave in range(16):
    for _ in range(25):
        live.append(subprocess.Popen(['sleep','0.15']))
    time.sleep(0.06)
    live=[k for k in live if k.poll() is None]
for k in live:
    k.wait()`;
const controllerCode = `import subprocess,sys,time
stage=subprocess.Popen([sys.executable,'-u','-c',${JSON.stringify(stageCode)}])
print(stage.pid,flush=True)
stage.wait()
print('DONE',flush=True)
time.sleep(300)`;

function lineQueue(reader) {
  const queued = [], waiting = [];
  reader.on('line', value => {
    if (waiting.length) waiting.shift()(value); else queued.push(value);
  });
  return () => (queued.length ? Promise.resolve(queued.shift()) : new Promise(resolve => waiting.push(resolve)));
}

test('W-scale churn: children that exit after being identified leave the proof resolved', async () => {
  const controller = spawn(python, ['-u', '-c', controllerCode], { stdio: ['ignore', 'pipe', 'inherit'] });
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ownership-churn-'));
  const reader = createInterface({ input: controller.stdout });
  const nextLine = lineQueue(reader);
  const observer = new OwnershipObserver(python, probe, { tempRoot, graceSec: 0.1 });
  try {
    const root = Number(await nextLine());
    observer.register({ pid: root, unit: 'churn', native_attempt: 1 }, controller.pid);
    let finished = false;
    nextLine().then(() => { finished = true; });
    const limit = Date.now() + 60000;
    while (!finished && Date.now() < limit) {
      observer.observe();
      await new Promise(resolve => setTimeout(resolve, 20));
    }
    assert.equal(finished, true, 'the stage finished its churn');
    observer.observe();
    const report = await observer.recover();
    assert.deepEqual(report.taint_reasons, []);
    assert.equal(report.recovery.survivors.length + report.recovery.replaced.length + report.recovery.unverifiable.length, 0);
    assert.equal(report.proof_resolved, true);
    assert.ok(report.recovery.absent.length >= 50, `children identified and retired: ${report.recovery.absent.length}`);
    assert.equal(observer.stages.size, 0);
  } finally {
    controller.kill('SIGKILL');
    reader.close();
    observer.close();
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test('an exited identity leaves the per-poll list, keeps its outcome in the record, and is never probed again', async t => {
  const f = simulatedObserver(t, { graceSec: 1, budgetMs: 5000 });
  f.processes.delete(102);
  f.observer.observe();
  const stage = f.observer.stages.get(101);
  assert.equal(stage.active.has(102), false);
  assert.equal(stage.records.find(identity => identity.pid === 102).outcome, 'absent');
  const probes = [];
  const point = f.observer.point;
  f.observer.point = (pid, timeout, fresh) => { probes.push(pid); return point(pid, timeout, fresh); };
  f.observer.observe();
  assert.equal(probes.includes(102), false, 'the exited identity is not probed on later polls');
  assert.ok(probes.includes(101), 'the live stage root is still probed');
  const report = await f.observer.recover();
  assert.equal(report.proof_resolved, true);
  entry(report, 'absent', 102);
  entry(report, 'terminated', 101);
});

test('a PID reused after its owner exited is adopted as a new identity, never mistaken for the old one', t => {
  const f = simulatedObserver(t, { graceSec: 1, budgetMs: 5000 });
  f.processes.delete(102);
  f.observer.observe();
  f.processes.set(102, { birth: '2002', ppid: 101, state: 'S' });
  f.observer.observe();
  const stage = f.observer.stages.get(101);
  assert.equal(stage.active.get(102).birth, '2002');
  assert.deepEqual(stage.records.filter(identity => identity.pid === 102).map(identity => [identity.birth, identity.outcome]),
    [['1002', 'absent'], ['2002', null]]);
  assert.equal(f.observer.failure, null);
});

test('a candidate seen in the census whose identity cannot be bound is unresolved, not ignored', async t => {
  const f = simulatedObserver(t, { graceSec: 1, budgetMs: 5000 });
  const census = f.observer.census;
  f.observer.census = timeout => new Map([...census(timeout), [103, 102]]);
  const point = f.observer.point;
  f.observer.point = (pid, timeout, fresh) => (pid === 103
    ? { status: 'UNKNOWN', pid, reason: 'exited between its census row and its identity read' }
    : point(pid, timeout, fresh));
  f.observer.observe();
  assert.equal(f.observer.stages.get(101).active.has(103), false);
  assert.match(f.observer.taintReasons.join(' '), /identity unavailable: 103/);
  const report = await f.observer.recover();
  assert.equal(report.proof_resolved, false);
});
