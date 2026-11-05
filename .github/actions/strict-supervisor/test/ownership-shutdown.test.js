import test from 'node:test';
import assert from 'node:assert/strict';
import { simulatedObserver, tick, entry } from './simulated-observer.js';

test('recovery is single-flight: concurrent callers share one flight, one TERM and one grace period', async t => {
  const f = simulatedObserver(t, { graceSec: 1 });
  f.processes.get(101).stubborn = true;
  const first = f.observer.recover();
  const second = f.observer.recover();
  assert.equal(second, first);
  const [a, b] = await Promise.all([first, second]);
  assert.equal(a.proof_resolved, true);
  assert.equal(b.proof_resolved, true);
  assert.deepEqual(f.signals.filter(s => s.pid === 101).map(s => s.signal), ['SIGTERM', 'SIGKILL']);
});

test('recovery stops at the shared shutdown deadline instead of starting a fresh budget', async t => {
  const f = simulatedObserver(t, { graceSec: 1, budgetMs: 5000 });
  f.processes.get(101).stubborn = true;
  const deadline = f.now() + 300;
  const report = await f.observer.recover({ deadline });
  assert.equal(report.proof_resolved, false);
  entry(report, 'survivors', 101);
  assert.deepEqual(f.signals.filter(s => s.pid === 101).map(s => s.signal), ['SIGTERM']);
  assert.ok(f.signals.every(s => s.at < deadline), 'no signal at or after the shared deadline');
  assert.equal(f.now(), deadline);
});

test('a late recovery continuation never probes or signals after the unresolved report and close', async t => {
  const f = simulatedObserver(t, { graceSec: 1, budgetMs: 5000 });
  f.processes.get(101).stubborn = true;
  const parked = [];
  f.observer.sleep = () => new Promise(resolve => parked.push(resolve));
  const probes = [];
  const point = f.observer.point;
  f.observer.point = (pid, timeout) => { probes.push(pid); return point(pid, timeout); };
  const recovering = f.observer.recover();
  await tick();
  assert.equal(parked.length, 1, 'recovery is waiting in its grace period');

  const report = f.observer.abort('ownership recovery unresolved at the shutdown deadline');
  assert.equal(report.proof_resolved, false);
  entry(report, 'survivors', 101);
  const recorded = f.journal();
  assert.match(recorded, /"event":"unresolved"/);
  assert.match(recorded, /"event":"recovery-report"/);
  await assert.rejects(f.observer.resolve({ pid: 101, unit: 'run3/acme', native_attempt: 2 }), /finalizing/);

  f.observer.close();
  const signalsAtClose = f.signals.length;
  const probesAtClose = probes.length;
  for (const resume of parked) resume();
  const late = await recovering;
  assert.equal(late.proof_resolved, false);
  assert.equal(f.signals.length, signalsAtClose);
  assert.equal(probes.length, probesAtClose);
  assert.equal(f.journal(), recorded, 'nothing is journaled after the unresolved report');

  assert.equal((await f.observer.recover()).proof_resolved, false);
  assert.equal(probes.length, probesAtClose, 'a recovery requested after close does not probe');
});

test('closing during an in-flight recovery records it unresolved before the journal closes', async t => {
  const f = simulatedObserver(t, { graceSec: 1, budgetMs: 5000 });
  f.processes.get(101).stubborn = true;
  const parked = [];
  f.observer.sleep = () => new Promise(resolve => parked.push(resolve));
  const recovering = f.observer.recover();
  await tick();
  const signalsBeforeClose = f.signals.length;
  f.observer.close();
  const recorded = f.journal();
  assert.match(recorded, /"event":"unresolved"/);
  assert.match(recorded, /"event":"recovery-report"/);
  for (const resume of parked) resume();
  assert.equal((await recovering).proof_resolved, false);
  assert.equal(f.signals.length, signalsBeforeClose);
  assert.equal(f.journal(), recorded);
});
