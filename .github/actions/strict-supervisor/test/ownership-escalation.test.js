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
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ownership-real-'));
  const reader = createInterface({ input: controller.stdout });
  const ready = once(reader, 'line');
  const observer = new OwnershipObserver(python, probe, { tempRoot, graceSec: 0.1 });
  const sentinel = await startSentinel(python, observer);
  try {
    await sentinel.challenge();
    const [text] = await ready;
    const pid = Number(text);
    observer.register({ pid, unit: 'run1', native_attempt: 1 }, controller.pid);
    await observer.resolve({ pid, unit: 'run1', native_attempt: 1, grace_sec: 0.1 });
    assert.equal(observer.stages.size, 0);
    await sentinel.challenge();
  } finally {
    controller.kill('SIGKILL');
    await sentinel.stop();
    reader.close();
    observer.close();
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});
