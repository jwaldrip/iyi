import test from 'node:test';
import assert from 'node:assert/strict';
import { missingRecall } from './recall-check.js';

test('recall checker reports a certainly alive process missing from a completed poll', () => {
  const spawns = [{ pid: 17, spawn_ns: 0, lifetime_ns: 200_000_000 }, { pid: 18, spawn_ns: 0, lifetime_ns: 200_000_000 }];
  const polls = [{ start_ns: 30_000_000, end_ns: 40_000_000, committed: [17] }];
  assert.deepEqual(missingRecall(spawns, polls).map(item => item.pid), [18]);
  polls[0].committed.push(18);
  assert.deepEqual(missingRecall(spawns, polls), []);
});
