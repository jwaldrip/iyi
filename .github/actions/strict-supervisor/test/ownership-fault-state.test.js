import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { OwnershipObserver } from '../src/ownership.js';

// All PIDs, clocks and signals in these tests belong to this in-memory adapter.
function fixture(t, { graceSec = 1, budgetMs = 5000 } = {}) {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ownership-fault-'));
  const observer = new OwnershipObserver('unused', 'unused', { tempRoot, graceSec, budgetMs });
  const processes = new Map([
    [101, { birth: '1001', ppid: 99, state: 'S' }],
    [102, { birth: '1002', ppid: 101, state: 'S' }],
  ]);
  let clock = 0;
  let outage = false;
  const signals = [];
  observer.now = () => clock;
  observer.sleep = async ms => { clock += ms; };
  observer.census = () => {
    if (outage) throw new Error('injected census outage');
    return new Map([...processes].filter(([, p]) => !p.unknown).map(([pid, p]) => [pid, p.ppid]));
  };
  observer.censusRow = pid => {
    const p = processes.get(pid);
    if (!p || p.unknown) return undefined;
    return { identity: { status: 'LIVE', pid, birth: p.birth, ppid: p.ppid, state: p.state }, index: [...processes.keys()].indexOf(pid) };
  };
  observer.censusStartWallUs = () => Number.MAX_SAFE_INTEGER;
  observer.point = pid => {
    const p = processes.get(pid);
    if (!p) return { status: 'ABSENT', pid };
    if (p.unknown) return { status: 'UNKNOWN', pid, reason: 'injected identity outage' };
    return { status: 'LIVE', pid, ...p };
  };
  observer.signal = (pid, signal) => {
    signals.push({ pid, signal, at: clock });
    if (signal === 'SIGKILL' || !processes.get(pid)?.stubborn) processes.delete(pid);
  };
  observer.register({ pid: 101, unit: 'run3/acme', native_attempt: 2 }, 99);
  observer.observe();
  t.after(() => { observer.close(); fs.rmSync(tempRoot, { recursive: true, force: true }); });
  return { observer, processes, signals, outage(value) { outage = value; }, now() { return clock; } };
}

function entry(report, bucket, pid) {
  const value = report.recovery[bucket].find(item => item.pid === pid);
  assert.ok(value, `missing ${pid} from ${bucket}`);
  assert.equal(value.root_pid, 101);
  assert.equal(value.unit, 'run3/acme');
  assert.equal(value.native_attempt, 2);
  return value;
}

test('census outage recovers committed identities but leaves durable sticky taint and restart refusal', async t => {
  const f = fixture(t);
  f.outage(true);
  const report = await f.observer.recover();
  assert.equal(report.proof_resolved, false);
  assert.match(report.taint_reasons.join(' '), /observer failed.*census outage/);
  entry(report, 'terminated', 101);
  entry(report, 'terminated', 102);
  assert.deepEqual(f.signals.map(s => s.pid).sort(), [101, 102]);
  const journal = fs.readFileSync(path.join(f.observer.directory, 'ownership.jsonl'), 'utf8');
  assert.match(journal, /"event":"unresolved"/);
  assert.match(journal, /"event":"recovery-report"/);
  f.outage(false);
  assert.equal((await f.observer.recover()).proof_resolved, false);
  assert.throws(() => new OwnershipObserver('unused', 'unused', { tempRoot: path.dirname(f.observer.directory), context: { invocation: 'different', artifacts: 'elsewhere' } }));
});

test('unavailable identity is not signaled and does not block another identity', async t => {
  const f = fixture(t);
  f.outage(true);
  f.processes.get(101).unknown = true;
  const report = await f.observer.recover();
  assert.equal(report.proof_resolved, false);
  entry(report, 'unverifiable', 101);
  entry(report, 'terminated', 102);
  assert.deepEqual(f.signals.map(s => s.pid), [102]);
});

test('recycled PID before TERM is not signaled or adopted', async t => {
  const f = fixture(t);
  f.processes.get(101).birth = '9001';
  f.outage(true);
  const report = await f.observer.recover();
  assert.equal(report.proof_resolved, false);
  assert.equal(entry(report, 'replaced', 101).birth, '1001');
  entry(report, 'terminated', 102);
  assert.deepEqual(f.signals.map(s => s.pid), [102]);
});

test('recycled PID between TERM and KILL is never escalated', async t => {
  const f = fixture(t);
  f.outage(true);
  f.processes.get(101).stubborn = true;
  const signal = f.observer.signal;
  f.observer.signal = (pid, sig) => {
    signal(pid, sig);
    if (pid === 101 && sig === 'SIGTERM') f.processes.get(pid).birth = '9001';
  };
  const report = await f.observer.recover();
  assert.equal(entry(report, 'replaced', 101).birth, '1001');
  assert.deepEqual(f.signals.filter(s => s.pid === 101).map(s => s.signal), ['SIGTERM']);
  entry(report, 'terminated', 102);
});

test('live reparented worker anchors late child, but recycled former parent cannot', async t => {
  const f = fixture(t);
  f.processes.delete(101);
  f.processes.get(102).ppid = 1;
  f.processes.set(103, { birth: '1003', ppid: 102, state: 'S' });
  f.processes.set(101, { birth: '9001', ppid: 99, state: 'S' });
  f.processes.set(104, { birth: '1004', ppid: 101, state: 'S' });
  f.observer.observe();
  const owned = f.observer.stages.get(101).owned;
  assert.ok(owned.has(103));
  assert.equal(owned.has(104), false);
  const report = await f.observer.recover();
  entry(report, 'replaced', 101);
  entry(report, 'terminated', 102);
  entry(report, 'terminated', 103);
  assert.equal(f.signals.some(s => s.pid === 104 || s.pid === 101), false);
});

test('journal failure never promotes a candidate and preserves prior recovery authority', async t => {
  const f = fixture(t);
  f.processes.set(103, { birth: '1003', ppid: 102, state: 'S' });
  const record = f.observer.record.bind(f.observer);
  f.observer.record = value => {
    if (value.event === 'observed' && value.pid === 103 || value.event === 'unresolved') throw new Error('injected fsync failure');
    record(value);
  };
  f.observer.observe();
  assert.equal(f.observer.stages.get(101).owned.has(103), false);
  f.outage(true);
  const report = await f.observer.recover();
  assert.equal(report.proof_resolved, false);
  entry(report, 'terminated', 101);
  entry(report, 'terminated', 102);
  assert.equal(f.signals.some(s => s.pid === 103), false);
  assert.throws(() => new OwnershipObserver('unused', 'unused', { tempRoot: path.dirname(f.observer.directory) }));
});

test('concurrent recovery joins and preserves one TERM and full grace', async t => {
  const f = fixture(t);
  f.processes.get(101).stubborn = true;
  const [a, b] = await Promise.all([
    f.observer.recover(),
    f.observer.resolve({ pid: 101, unit: 'run3/acme', native_attempt: 2, grace_sec: 1 }),
  ]);
  assert.equal(a.proof_resolved, true);
  assert.equal(b.proof_resolved, true);
  const rootSignals = f.signals.filter(s => s.pid === 101);
  assert.deepEqual(rootSignals.map(s => s.signal), ['SIGTERM', 'SIGKILL']);
  assert.ok(rootSignals[1].at - rootSignals[0].at >= 1000);
  const again = await f.observer.resolve({ pid: 101, unit: 'run3/acme', native_attempt: 2, grace_sec: 1 });
  assert.equal(again.proof_resolved, true);
  assert.equal(f.signals.filter(s => s.pid === 101).length, 2);
});

test('budget exhaustion never accelerates KILL and later recovery does not restart grace', async t => {
  const f = fixture(t, { graceSec: 1, budgetMs: 400 });
  f.processes.get(101).stubborn = true;
  const first = await f.observer.recover();
  assert.equal(first.proof_resolved, false);
  entry(first, 'survivors', 101);
  assert.deepEqual(f.signals.filter(s => s.pid === 101).map(s => s.signal), ['SIGTERM']);
  const second = await f.observer.recover();
  assert.equal(second.proof_resolved, false);
  entry(second, 'survivors', 101);
  assert.deepEqual(f.signals.filter(s => s.pid === 101).map(s => s.signal), ['SIGTERM']);
  const third = await f.observer.recover();
  assert.equal(third.proof_resolved, false);
  const signals = f.signals.filter(s => s.pid === 101);
  assert.deepEqual(signals.map(s => s.signal), ['SIGTERM', 'SIGKILL']);
  assert.ok(signals[1].at - signals[0].at >= 1000);
});

test('unverifiable former parent cannot authorize an unrelated child', async t => {
  const f = fixture(t);
  f.processes.get(101).unknown = true;
  f.processes.set(104, { birth: '1004', ppid: 101, state: 'S' });
  f.observer.observe();
  assert.equal(f.observer.stages.get(101).owned.has(104), false);
  const report = await f.observer.recover();
  entry(report, 'unverifiable', 101);
  entry(report, 'terminated', 102);
  assert.equal(f.signals.some(s => s.pid === 104), false);
});
