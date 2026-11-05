import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { StrictSupervisor } from '../src/supervisor.js';

const python = process.env.PYTHON || 'python3';
let counter = 0;

// A stand-in controller. It registers a PID that does not exist, which fails the observer at
// once and starts shutdown. Then it behaves as its mode says when SIGTERM arrives: 'persist'
// exits cleanly after persistSec, and 'stubborn' ignores SIGTERM until it is killed.
function controllerCode({ invocationId, mode, persistSec, marker }) {
  const stubborn = mode === 'stubborn';
  return [
    'import json, os, signal, sys, time',
    'flag = []',
    `stubborn = ${JSON.stringify(stubborn)}`,
    'if stubborn:',
    '    signal.signal(signal.SIGTERM, signal.SIG_IGN)',
    'else:',
    '    signal.signal(signal.SIGTERM, lambda *_: flag.append(True))',
    'request = {"event": "ownership-register", "protocol_version": 1, "request_id": "register-1",',
    `           "invocation_id": ${JSON.stringify(invocationId)}, "unit": "stub", "native_attempt": 1, "pid": 999999999}`,
    'os.write(3, (json.dumps(request) + "\\n").encode())',
    'data = b""',
    'while not data.endswith(b"\\n"):',
    '    part = os.read(4, 1)',
    '    if not part:',
    '        break',
    '    data += part',
    'if stubborn:',
    '    while True:',
    '        time.sleep(0.05)',
    'while not flag:',
    '    time.sleep(0.05)',
    `time.sleep(${Number(persistSec)})`,
    `open(${JSON.stringify(marker)}, "w").write("persisted")`,
    'sys.exit(0)',
  ].join('\n');
}

function supervisorFor(tempRoot, { mode, persistSec = 0, budgetSec, marker }) {
  const invocationId = `stop-${process.pid}-${++counter}`;
  const context = Object.freeze({
    invocation_id: invocationId, execution_kind: 'synthetic', repository: 'jwaldrip/iyi', run_id: '1', run_attempt: '1',
    job_id: '1', job_key: 'validation', p_sha: 'p', w_sha: 'w', c_sha: 'c', fixture_sha256: 'f',
  });
  const supervisor = new StrictSupervisor({
    mode: 'validation-only', pythonPath: python, graceSec: 1, finalizationAllocSec: budgetSec,
    ownershipTempRoot: tempRoot, artifactsDir: path.join(tempRoot, 'artifacts'),
  });
  const code = controllerCode({ invocationId, mode, persistSec, marker });
  supervisor.establishContext = async () => context;
  supervisor.buildChildArgs = () => ['-c', code];
  return supervisor;
}

function tempDir(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ownership-stop-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

test('a controller still persisting after SIGTERM is not SIGKILLed before the shared shutdown deadline', async t => {
  const dir = tempDir(t);
  const marker = path.join(dir, 'persisted');
  // Persisting takes 6.5 s after SIGTERM. The old 5 s kill timer would have stopped it first.
  const supervisor = supervisorFor(dir, { mode: 'persist', persistSec: 6.5, budgetSec: 12, marker });
  const result = await supervisor.run();
  assert.equal(fs.existsSync(marker), true, 'the controller finished persisting its unit');
  assert.equal(result.exitCode, 0);
  assert.equal(result.signal, null);
  const index = JSON.parse(fs.readFileSync(result.envelopePath, 'utf8'));
  assert.equal(index.controller_signal, null);
  assert.deepEqual(index.controller_signals.map(sent => sent.signal), ['SIGTERM']);
  const taint = index.ownership_recovery.taint_reasons.join(' ');
  assert.match(taint, /ownership control failed/);
  assert.doesNotMatch(taint, /SIGKILL/);
});

test('a controller that ignores SIGTERM is killed at the shared deadline and recorded as the supervisor\'s kill', async t => {
  const dir = tempDir(t);
  const marker = path.join(dir, 'persisted');
  const supervisor = supervisorFor(dir, { mode: 'stubborn', budgetSec: 8, marker });
  const started = performance.now();
  const result = await supervisor.run();
  const elapsedMs = performance.now() - started;
  assert.equal(result.signal, 'SIGKILL');
  assert.equal(result.exitCode, null);
  assert.ok(elapsedMs >= 7000, `the controller was killed before the shared deadline (${Math.round(elapsedMs)} ms)`);
  assert.equal(fs.existsSync(marker), false);
  const index = JSON.parse(fs.readFileSync(result.envelopePath, 'utf8'));
  assert.equal(index.controller_signal, 'SIGKILL');
  assert.equal(index.controller_signal_sent_by, 'supervisor');
  assert.deepEqual(index.controller_signals.map(sent => sent.signal), ['SIGTERM', 'SIGKILL']);
  const taint = index.ownership_recovery.taint_reasons.join(' ');
  assert.match(taint, /controller stopped by supervisor SIGKILL/);
  assert.doesNotMatch(taint, /terminated by SIGKILL/);
});

test('a shutdown budget that does not cover the stage grace is refused before any controller starts', async t => {
  const dir = tempDir(t);
  const supervisor = supervisorFor(dir, { mode: 'persist', budgetSec: 0.5, marker: path.join(dir, 'unused') });
  await assert.rejects(supervisor.run(), /invalid ownership timing/);
  assert.equal(fs.existsSync(path.join(dir, 'strict-supervisor-ownership')), false);
});
