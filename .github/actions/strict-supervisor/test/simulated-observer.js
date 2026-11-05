import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { OwnershipObserver } from '../src/ownership.js';

// A real identity probe takes this long. A window shorter than this fails the
// way a starved probe does, so starvation is observable in simulated time.
export const PROBE_COST_MS = 20;

export const tick = () => new Promise(resolve => setImmediate(resolve));

// Every PID, clock, probe and signal below belongs to this in-memory adapter.
// Process 101 is the stage root and 102 is its child, owned from the start.
export function simulatedObserver(t, { graceSec = 1, budgetMs = 5000 } = {}) {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ownership-sim-'));
  const observer = new OwnershipObserver('unused', 'unused', { tempRoot, graceSec, budgetMs });
  const processes = new Map([
    [101, { birth: '1001', ppid: 99, state: 'S' }],
    [102, { birth: '1002', ppid: 101, state: 'S' }],
  ]);
  let clock = 0;
  const signals = [];
  observer.now = () => clock;
  observer.sleep = async ms => { clock += ms; };
  observer.census = () => new Map([...processes].filter(([, p]) => !p.unknown).map(([pid, p]) => [pid, p.ppid]));
  // The census row of a PID, from the same map as census(). Its index is the map's order, as the kernel's row order is.
  observer.censusRow = pid => {
    const p = processes.get(pid);
    if (!p || p.unknown) return undefined;
    return { identity: { status: 'LIVE', pid, birth: p.birth, ppid: p.ppid, state: p.state }, index: [...processes.keys()].indexOf(pid) };
  };
  // Every simulated birth precedes the call, so only the row order decides the edge rule.
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
  // No real interval: every observation in these tests is driven explicitly.
  clearInterval(observer.timer);
  observer.timer = null;
  observer.observe();
  t.after(() => { observer.close(); fs.rmSync(tempRoot, { recursive: true, force: true }); });
  return {
    observer,
    processes,
    signals,
    now: () => clock,
    advance(ms) { clock += ms; },
    journal() {
      const file = path.join(observer.directory, 'ownership.jsonl');
      return fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : null;
    },
  };
}

export function entry(report, bucket, pid) {
  const value = report.recovery[bucket].find(item => item.pid === pid);
  assert.ok(value, `missing ${pid} from ${bucket}`);
  return value;
}
