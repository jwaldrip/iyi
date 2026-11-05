import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { StrictSupervisor } from '../src/supervisor.js';

// Filesystem access with one injected fault. Every other call is the real
// filesystem. Opens and renames are recorded so the test can see which path
// the index was written through.
function faultyIo({ failWrite = false, failFsync = false, calls = [] } = {}) {
  return {
    ...fs,
    openSync(file, flags, mode) { calls.push({ op: 'open', file }); return fs.openSync(file, flags, mode); },
    writeSync(...args) { if (failWrite) throw new Error('injected write failure'); return fs.writeSync(...args); },
    fsyncSync(fd) { if (failFsync) throw new Error('injected fsync failure'); return fs.fsyncSync(fd); },
    renameSync(from, to) { calls.push({ op: 'rename', from, to }); return fs.renameSync(from, to); },
  };
}

function supervisorFor(dir, io) {
  const supervisor = new StrictSupervisor({ artifactsDir: dir, indexPath: path.join(dir, 'receipt-index.json'), fileIo: io });
  supervisor.context = { invocation_id: 'inv-atomic', execution_kind: 'native' };
  return supervisor;
}

function receipt(id) {
  return { request: { request_id: `r${id}` }, ack: { artifact_id: id, verified: true } };
}

function withDirectory(run) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'receipt-index-'));
  try { run(dir, path.join(dir, 'receipt-index.json')); }
  finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

test('a failed fsync leaves the prior receipt index intact and no temporary file behind', () => withDirectory((dir, index) => {
  const healthy = supervisorFor(dir, fs);
  healthy.entries.push(receipt(1));
  healthy.saveIndex(null);
  const prior = fs.readFileSync(index, 'utf8');

  const failing = supervisorFor(dir, faultyIo({ failFsync: true }));
  failing.entries.push(receipt(2));
  assert.throws(() => failing.saveIndex(null), /injected fsync failure/);
  assert.equal(fs.readFileSync(index, 'utf8'), prior);
  assert.deepEqual(fs.readdirSync(dir), ['receipt-index.json']);
}));

test('a failed write leaves the prior receipt index intact and no temporary file behind', () => withDirectory((dir, index) => {
  const healthy = supervisorFor(dir, fs);
  healthy.entries.push(receipt(1));
  healthy.saveIndex(null);
  const prior = fs.readFileSync(index, 'utf8');

  const failing = supervisorFor(dir, faultyIo({ failWrite: true }));
  failing.entries.push(receipt(2));
  assert.throws(() => failing.saveIndex(null), /injected write failure/);
  assert.equal(fs.readFileSync(index, 'utf8'), prior);
  assert.deepEqual(fs.readdirSync(dir), ['receipt-index.json']);
}));

test('saveIndex replaces the index by rename in the same directory and never reopens it for writing', () => withDirectory((dir, index) => {
  const calls = [];
  const supervisor = supervisorFor(dir, faultyIo({ calls }));
  supervisor.entries.push(receipt(1));
  supervisor.saveIndex(null);
  supervisor.entries.push(receipt(2));
  supervisor.saveIndex(0);

  assert.equal(calls.some(call => call.op === 'open' && call.file === index), false);
  const renames = calls.filter(call => call.op === 'rename');
  assert.equal(renames.length, 2);
  for (const rename of renames) {
    assert.equal(rename.to, index);
    assert.equal(path.dirname(rename.from), dir);
  }
  const saved = JSON.parse(fs.readFileSync(index, 'utf8'));
  assert.equal(saved.entries.length, 2);
  assert.equal(saved.exit_code, 0);
  assert.deepEqual(fs.readdirSync(dir), ['receipt-index.json']);
}));
