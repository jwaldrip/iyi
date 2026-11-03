import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { OwnershipObserver } from '../src/ownership.js';

const python = process.env.PYTHON || 'python3';
const probe = fileURLToPath(new URL('../src/process_identity.py', import.meta.url));
const childCode = `import signal,time
signal.signal(signal.SIGTERM,signal.SIG_IGN)
print('ready',flush=True)
time.sleep(300)`;
const controllerCode = `import subprocess,sys,time
p=subprocess.Popen([sys.executable,'-u','-c',${JSON.stringify(childCode)}],start_new_session=True,stdout=subprocess.PIPE,text=True)
p.stdout.readline()
print(p.pid,flush=True)
time.sleep(300)`;

test('recovery escalates a TERM-ignoring owned process after grace', async () => {
  const controller = spawn(python, ['-u', '-c', controllerCode], { stdio: ['ignore', 'pipe', 'inherit'] });
  const sentinel = spawn(python, ['-c', 'import time; time.sleep(300)'], { stdio: 'ignore' });
  const reader = createInterface({ input: controller.stdout });
  const observer = new OwnershipObserver(python, probe);
  try {
    const [text] = await once(reader, 'line');
    const pid = Number(text);
    observer.register({ pid, unit: 'run1', native_attempt: 1 }, controller.pid);
    await observer.resolve({ pid, unit: 'run1', native_attempt: 1, grace_sec: 0.1 });
    assert.equal(observer.stages.size, 0);
    assert.doesNotThrow(() => process.kill(sentinel.pid, 0));
  } finally {
    controller.kill('SIGKILL');
    sentinel.kill('SIGKILL');
    reader.close();
    observer.close();
  }
});
