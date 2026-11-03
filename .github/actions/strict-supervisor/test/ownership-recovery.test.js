import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { OwnershipObserver } from '../src/ownership.js';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { startSentinel } from './sentinel-helper.js';

const python = process.env.PYTHON || 'python3';
const probe = fileURLToPath(new URL('../src/process_identity.py', import.meta.url));
const program = `import os,subprocess,sys,time
stage=subprocess.Popen([sys.executable,'-c',"import os,subprocess,sys,time; os.read(0,1); p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(300)'],start_new_session=True); print(p.pid,flush=True); time.sleep(300)"],stdin=subprocess.PIPE,stdout=subprocess.PIPE,start_new_session=True,text=True)
print(stage.pid,flush=True)
sys.stdin.read(1)
stage.stdin.write('x'); stage.stdin.flush()
print(stage.stdout.readline().strip(),flush=True)
time.sleep(300)
`;

function lines(reader) {
  const queue = [], pending = [];
  reader.on('line', value => {
    if (pending.length) pending.shift()(Number(value)); else queue.push(Number(value));
  });
  return () => queue.length ? Promise.resolve(queue.shift()) : new Promise(resolve => pending.push(resolve));
}

test('crashed controller recovery terminates observed separate sessions, not a sentinel', async () => {
  const controller = spawn(python, ['-u', '-c', program], { stdio: ['pipe', 'pipe', 'inherit'] });
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ownership-real-'));
  const reader = createInterface({ input: controller.stdout });
  const next = lines(reader);
  const observer = new OwnershipObserver(python, probe, { tempRoot, graceSec: 0.1 });
  const sentinel = await startSentinel(python, observer);
  let stage, grandchild;
  try {
    await sentinel.challenge();
    stage = await next();
    observer.register({ pid: stage, unit: 'run3', native_attempt: 1 }, controller.pid);
    controller.stdin.write('x');
    grandchild = await next();
    observer.observe();
    assert.ok(observer.stages.get(stage).owned.has(grandchild));
    controller.kill('SIGKILL');
    await once(controller, 'exit');
    await observer.recover();
    assert.equal(observer.stages.size, 0);
    await sentinel.challenge();
  } finally {
    reader.close();
    controller.kill('SIGKILL');
    await sentinel.stop();
    observer.close();
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test('census outage leaves ownership unresolved and never signals by guess', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ownership-real-'));
  const observer = new OwnershipObserver(python, probe, { tempRoot, graceSec: 0.1 });
  try {
    observer.census = () => { throw new Error('injected census outage'); };
    assert.throws(() => observer.register({ pid: 123, unit: 'run1', native_attempt: 1 }, process.pid), /census outage/);
    assert.equal(observer.stages.size, 0);
  } finally { observer.close(); fs.rmSync(tempRoot, { recursive: true, force: true }); }
});
