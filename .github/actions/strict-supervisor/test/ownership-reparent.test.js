import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { OwnershipObserver } from '../src/ownership.js';

const python = process.env.PYTHON || 'python3';
const probe = fileURLToPath(new URL('../src/process_identity.py', import.meta.url));
const workerCode = `import signal,subprocess,sys,time
def birth(sig,frame):
 p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(300)'],start_new_session=True)
 print(p.pid,flush=True)
signal.signal(signal.SIGUSR1,birth)
sys.stdin.read(1)
print('READY',flush=True)
time.sleep(300)`;
const stageCode = `import subprocess,sys
p=subprocess.Popen([sys.executable,'-u','-c',${JSON.stringify(workerCode)}],start_new_session=True,stdin=subprocess.PIPE,stdout=sys.stdout)
print(p.pid,flush=True)
p.stdin.write(b'x'); p.stdin.flush()
sys.stdin.read(1)`;
const controllerCode = `import subprocess,sys,time
p=subprocess.Popen([sys.executable,'-u','-c',${JSON.stringify(stageCode)}],start_new_session=True,stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
print(p.pid,flush=True)
print(p.stdout.readline().strip(),flush=True)
print(p.stdout.readline().strip(),flush=True)
sys.stdin.read(1); p.stdin.write('x'); p.stdin.flush(); p.wait()
print('STAGE_EXITED',flush=True)
print(p.stdout.readline().strip(),flush=True)
time.sleep(300)`;

// Queue lines before requesting them so bursty child output cannot lose a line.
function lines(stream) {
  const queue = [], pending = [];
  createInterface({ input: stream }).on('line', value => {
    if (pending.length) pending.shift()(value); else queue.push(value);
  });
  return () => queue.length ? Promise.resolve(queue.shift()) : new Promise(resolve => pending.push(resolve));
}

test('observer follows a still-identified worker after reparenting', async () => {
  const controller = spawn(python, ['-u', '-c', controllerCode], { stdio: ['pipe', 'pipe', 'inherit'] });
  const sentinel = spawn(python, ['-c', 'import time; time.sleep(300)'], { stdio: 'ignore' });
  const next = lines(controller.stdout);
  const observer = new OwnershipObserver(python, probe);
  try {
    const root = Number(await next());
    const worker = Number(await next());
    assert.equal(await next(), 'READY');
    observer.register({ pid: root, unit: 'run3', native_attempt: 1 }, controller.pid);
    observer.observe();
    assert.ok(observer.stages.get(root).owned.has(worker));
    controller.stdin.write('x');
    assert.equal(await next(), 'STAGE_EXITED');
    observer.observe();
    process.kill(worker, 'SIGUSR1');
    const grandchild = Number(await next());
    observer.observe();
    assert.ok(observer.stages.get(root).owned.has(grandchild));
    controller.kill('SIGKILL');
    await once(controller, 'exit');
    await observer.recover();
    assert.doesNotThrow(() => process.kill(sentinel.pid, 0));
  } finally {
    controller.kill('SIGKILL');
    sentinel.kill('SIGKILL');
    observer.close();
  }
});
