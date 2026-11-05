import test from 'node:test';
import assert from 'node:assert/strict';
import { simulatedObserver, entry, PROBE_COST_MS } from './simulated-observer.js';

test('observe probes committed identities before it takes the census', t => {
  const f = simulatedObserver(t);
  const log = [];
  const point = f.observer.point;
  const census = f.observer.census;
  f.observer.point = (pid, timeout) => { log.push(`point:${pid}`); return point(pid, timeout); };
  f.observer.census = timeout => { log.push('census'); return census(timeout); };
  f.observer.observe();
  const beforeCensus = log.slice(0, log.indexOf('census'));
  assert.ok(beforeCensus.includes('point:101'));
  assert.ok(beforeCensus.includes('point:102'));
});

test('a census that times out cannot starve committed probes or the signals they justify', async t => {
  const f = simulatedObserver(t, { graceSec: 1, budgetMs: 4000 });
  const point = f.observer.point;
  // A probe window below its real cost fails, as a starved probe would.
  f.observer.point = (pid, timeout) => (timeout < PROBE_COST_MS ? { status: 'UNKNOWN', pid, reason: 'probe window starved' } : point(pid, timeout));
  const windows = [];
  f.observer.census = timeout => {
    windows.push(timeout);
    f.advance(timeout);
    throw new Error('ps timed out');
  };
  const report = await f.observer.recover();
  assert.equal(report.proof_resolved, false);
  entry(report, 'terminated', 101);
  entry(report, 'terminated', 102);
  assert.deepEqual(f.signals.map(s => [s.pid, s.signal, s.at]), [[101, 'SIGTERM', 0], [102, 'SIGTERM', 0]]);
  assert.equal(windows[0], 2000, 'census takes at most half of the remaining budget');
  const taint = report.taint_reasons.join(' ');
  assert.match(taint, /observer failed: ps timed out/);
  assert.doesNotMatch(taint, /identity unavailable/);
});
