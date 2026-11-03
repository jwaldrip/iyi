import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { OwnershipObserver } from '../src/ownership.js';

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

async function line(reader) {
  const [value] = await once(reader, 'line');
  return Number(value);
}

test('crashed controller recovery terminates observed separate sessions, not a sentinel', async () => {
  const controller = spawn(python, ['-u', '-c', program], { stdio: ['pipe', 'pipe', 'inherit'] });
  const sentinel = spawn(python, ['-c', 'import time; time.sleep(300)'], { stdio: 'ignore' });
  const reader = createInterface({ input: controller.stdout });
  const observer = new OwnershipObserver(python, probe);
  let stage, grandchild;
  try {
    stage = await line(reader);
    observer.register({ pid: stage, unit: 'run3', native_attempt: 1 }, controller.pid);
    controller.stdin.write('x');
    grandchild = await line(reader);
    observer.observe();
    assert.ok(observer.stages.get(stage).owned.has(grandchild));
    controller.kill('SIGKILL');
    await once(controller, 'exit');
    await observer.recover();
    assert.equal(observer.stages.size, 0);
    assert.doesNotThrow(() => process.kill(sentinel.pid, 0));
  } finally {
    reader.close();
    controller.kill('SIGKILL');
    sentinel.kill('SIGKILL');
    observer.close();
  }
});

test('census outage leaves ownership unresolved and never signals by guess', async () => {
  const observer = new OwnershipObserver(python, probe);
  try {
    observer.census = () => { throw new Error('injected census outage'); };
    assert.throws(() => observer.register({ pid: 123, unit: 'run1', native_attempt: 1 }, process.pid), /census outage/);
    assert.equal(observer.stages.size, 0);
  } finally { observer.close(); }
});
