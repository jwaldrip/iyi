import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { OwnershipObserver } from '../src/ownership.js';

const python = process.env.PYTHON || 'python3';
const actual = fileURLToPath(new URL('../src/process_identity.py', import.meta.url));
const old = fileURLToPath(new URL('./fixtures/two-read-census-helper.py', import.meta.url));
const stageCode = `import subprocess,sys,time
sys.stdin.read(1)
p=subprocess.Popen(['/usr/bin/top','-l','3','-s','1','-n','0'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
print(p.pid,flush=True)
p.wait()
time.sleep(30)`;
const controllerCode = `import subprocess,sys
p=subprocess.Popen([sys.executable,'-u','-c',${JSON.stringify(stageCode)}],stdin=subprocess.PIPE,stdout=sys.stdout)
print(p.pid,flush=True)
sys.stdin.read(1); p.stdin.write(b'x'); p.stdin.flush()
p.wait()`;

for (const [name, helper, control] of [['sysctl', actual, false], ['two-read control', old, true]]) {
  test(`setuid top: ${name}`, { skip: process.platform !== 'darwin', timeout: 30000 }, async () => {
    assert.equal(createHash('sha256').update(fs.readFileSync(old)).digest('hex'), '315881ca28bfde39af2690fca86728b2cb44386001fc1090bc8ef7d266f56a10');
    for (const file of ['/usr/bin/top', '/bin/ps']) {
      const st = fs.statSync(file);
      assert.equal(st.uid, 0, `${file} owner`);
      assert.ok(st.mode & 0o4000, `${file} must be setuid`);
    }
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'setuid-census-'));
    const observer = new OwnershipObserver(python, helper, { tempRoot: root, graceSec: 0.1 });
    const controller = spawn(python, ['-u', '-c', controllerCode], { stdio: ['pipe', 'pipe', 'inherit'] });
    const lines = createInterface({ input: controller.stdout });
    const queue = [], waiters = [];
    lines.on('line', line => waiters.length ? waiters.shift()(line) : queue.push(line));
    const next = () => queue.length ? Promise.resolve(queue.shift()) : new Promise(resolve => waiters.push(resolve));
    let top;
    try {
      const stage = Number(await next());
      observer.register({ pid: stage, unit: 'setuid', native_attempt: 1 }, controller.pid);
      clearInterval(observer.timer); observer.timer = null;
      controller.stdin.write('x');
      top = Number(await next());
      const deadline = Date.now() + 2500;
      while (Date.now() < deadline && !(control ? observer.taintReasons.some(s => s === `identity unavailable: ${top}`) : observer.stages.get(stage).owned.has(top))) {
        observer.observe();
        await new Promise(resolve => setTimeout(resolve, 20));
      }
      if (control) assert.ok(observer.taintReasons.includes(`identity unavailable: ${top}`), `control did not catch top ${top}: ${observer.taintReasons}`);
      else assert.ok(observer.stages.get(stage).owned.has(top), 'top must be adopted');
      const report = await observer.recover();
      if (control) assert.equal(report.proof_resolved, false);
      else {
        assert.deepEqual(report.taint_reasons, []);
        assert.equal(report.proof_resolved, true);
        assert.ok([...report.recovery.terminated, ...report.recovery.absent].some(item => item.pid === top));
      }
    } finally {
      // The control deliberately cannot own top; let its bounded invocation exit naturally.
      if (top && control) await new Promise(resolve => setTimeout(resolve, 3500));
      controller.kill('SIGKILL');
      lines.close();
      observer.close();
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
}
