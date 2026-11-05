import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { OwnershipObserver } from '../src/ownership.js';
import { startSentinel } from './sentinel-helper.js';
import { missingRecall } from './recall-check.js';

const python = process.env.PYTHON || 'python3';
const probe = fileURLToPath(new URL('../src/process_identity.py', import.meta.url));
// All output is JSON lines. The only times claimed as lifetimes are minimum sleeps
// directly performed by the named process; other process classes carry zero.
const orphan = `import json,subprocess,time
p=subprocess.Popen(['/bin/sleep','120'])
print(json.dumps({'kind':'spawn','pid':p.pid,'spawn_ns':time.monotonic_ns(),'lifetime_ns':120000000000,'class':'grandchild'}),flush=True)
time.sleep(1)`;
const driver = `import json,subprocess,sys,threading,time
sys.stdin.read(1)
def launch(args,kind,lifetime=0,**kw):
 p=subprocess.Popen(args,**kw)
 print(json.dumps({'kind':'spawn','pid':p.pid,'spawn_ns':time.monotonic_ns(),'lifetime_ns':lifetime,'class':kind}),flush=True)
 return p
def churn():
 live=[]
 for wave in range(40):
  for n in range(25): live.append(launch(['/bin/sleep','0.15'],'churn',150000000))
  time.sleep(.06)
  live=[p for p in live if p.poll() is None]
 for p in live: p.wait()
def chains():
 launch(['/bin/bash','-c','for i in $(seq 200); do sh -c /usr/bin/true; done'],'chains').wait()
def servers():
 for i in range(10): launch(['/bin/bash','-c','/bin/sleep 5 & s=$!; /bin/sleep 0.3; kill $s; wait $s'],'server').wait()
def psloop():
 end=time.monotonic()+6
 while time.monotonic()<end:
  launch(['/bin/ps','-axo','pid=,pgid='],'ps',stdout=subprocess.DEVNULL).wait(); time.sleep(.02)
def execs():
 for i in range(20): launch(['/bin/sh','-c','exec /bin/sleep 0.3'],'exec',300000000).wait()
threads=[threading.Thread(target=f) for f in (churn,chains,servers,psloop,execs)]
for t in threads: t.start()
top=launch(['/usr/bin/top','-l','3','-s','1','-n','0'],'top',2000000000,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
i=launch([sys.executable,'-u','-c',${JSON.stringify(orphan)}],'intermediate',1000000000)
for t in threads: t.join()
top.wait(); i.wait()
print(json.dumps({'kind':'done'}),flush=True)
time.sleep(300)`;
const controller = `import subprocess,sys
p=subprocess.Popen([sys.executable,'-u','-c',${JSON.stringify(driver)}],stdin=subprocess.PIPE,stdout=sys.stdout)
print(p.pid,flush=True)
sys.stdin.read(1); p.stdin.write(b'x'); p.stdin.flush(); p.wait()`;

test('hosted W workload retains owned identities through churn and orphaning', { skip: process.platform !== 'darwin', timeout: 120000 }, async () => {
  for (const file of ['/bin/ps', '/usr/bin/top']) {
    const stat = fs.statSync(file);
    assert.equal(stat.uid, 0);
    assert.ok(stat.mode & 0o4000, `${file} is setuid`);
  }
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'w-census-'));
  const observer = new OwnershipObserver(python, probe, { tempRoot: root, graceSec: 0.1 });
  const sentinel = await startSentinel(python, observer);
  const proc = spawn(python, ['-u', '-c', controller], { stdio: ['pipe', 'pipe', 'inherit'] });
  const reader = createInterface({ input: proc.stdout });
  const queue = [], pending = [], spawns = [], polls = [];
  let done = false;
  reader.on('line', line => {
    if (/^\d+$/.test(line)) { if (pending.length) pending.shift()(Number(line)); else queue.push(Number(line)); return; }
    const entry = JSON.parse(line);
    if (entry.kind === 'spawn') spawns.push(entry);
    if (entry.kind === 'done') done = true;
  });
  const next = () => queue.length ? Promise.resolve(queue.shift()) : new Promise(resolve => pending.push(resolve));
  const original = observer.readSnapshot.bind(observer);
  let last;
  observer.readSnapshot = (...args) => { const snap = original(...args); last = snap; return snap; };
  try {
    const stage = await next();
    observer.register({ pid: stage, unit: 'w-churn', native_attempt: 1 }, proc.pid);
    clearInterval(observer.timer); observer.timer = null;
    proc.stdin.write('x');
    const deadline = Date.now() + 90000;
    while (!done && Date.now() < deadline) {
      observer.observe();
      const c = last.call;
      if (c && c.startNs !== null && c.endNs !== null) polls.push({ start_ns: c.startNs, end_ns: c.endNs, committed: observer.stages.get(stage).records.map(r => r.pid) });
      await new Promise(resolve => setTimeout(resolve, 20));
    }
    assert.ok(done, 'driver finished');
    observer.observe();
    const journalPath = path.join(observer.directory, 'ownership.jsonl');
    const report = await observer.recover();
    const journal = fs.readFileSync(journalPath, 'utf8').trim().split('\n').map(JSON.parse);
    assert.deepEqual(report.taint_reasons, []);
    assert.equal(report.proof_resolved, true);
    for (const key of ['replaced', 'unverifiable', 'survivors']) assert.deepEqual(report.recovery[key], []);
    assert.equal(observer.stages.size, 0);
    assert.deepEqual(missingRecall(spawns, polls), []);
    const observed = journal.filter(e => e.event === 'observed');
    const top = spawns.find(s => s.class === 'top');
    assert.ok(top && observed.some(e => e.pid === top.pid), 'setuid top committed');
    const intermediate = spawns.find(s => s.class === 'intermediate');
    const grandchild = spawns.find(s => s.class === 'grandchild');
    assert.ok(intermediate && grandchild);
    assert.ok(journal.findIndex(e => e.event === 'observed' && e.pid === grandchild.pid) < journal.findIndex(e => e.event === 'retired' && e.pid === intermediate.pid));
    assert.ok(report.recovery.terminated.some(e => e.pid === grandchild.pid));
    assert.ok(journal.some(e => e.event === 'signaled' && e.pid === grandchild.pid && e.signal === 'SIGTERM'));
    const current = observer.point(grandchild.pid, 5000, true);
    const grandchildIdentity = observed.find(e => e.pid === grandchild.pid);
    assert.ok(current.status === 'ABSENT' || (current.status === 'LIVE' && current.birth !== grandchildIdentity.birth));
    const committed = new Map();
    for (const e of journal) {
      if (e.event === 'registered' || e.event === 'observed') {
        if (e.event === 'observed') {
          assert.ok(committed.has(e.parent), `parent ${e.parent} committed first`);
          assert.ok(Number(e.birth) > Number(committed.get(e.parent)), 'child younger than parent');
        }
        assert.ok(e.pid !== process.pid && e.pid !== proc.pid);
        committed.set(e.pid, e.birth);
      } else if (e.event === 'signaled') assert.equal(committed.get(e.pid), e.birth);
    }
    await sentinel.challenge();
    const maxCall = Math.max(0, ...polls.map(p => p.end_ns - p.start_ns));
    const maxGap = Math.max(0, ...polls.slice(1).map((p, i) => p.start_ns - polls[i].end_ns));
    const unseen = spawns.filter(s => s.class === 'churn' && !observed.some(e => e.pid === s.pid)).length;
    console.log(`polls=${polls.length} longest_census_ns=${maxCall} longest_gap_ns=${maxGap} churn_unadopted=${unseen}`);
  } finally {
    proc.kill('SIGKILL');
    reader.close();
    await sentinel.stop();
    observer.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
});
