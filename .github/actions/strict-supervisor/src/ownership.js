import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

// This observer cannot prove absence of forks that start and reparent entirely
// between observations. It never represents a failed observation as quiescence.
export class OwnershipObserver {
  constructor(python, identityScript) {
    this.python = python;
    this.identityScript = identityScript;
    this.directory = fs.mkdtempSync(path.join(os.tmpdir(), 'strict-ownership-'));
    this.fd = fs.openSync(path.join(this.directory, 'ownership.jsonl'), 'ax', 0o600);
    this.stages = new Map();
    this.failure = null;
    this.timer = null;
  }
  record(value) {
    fs.writeSync(this.fd, JSON.stringify(value) + '\n');
    fs.fsyncSync(this.fd);
  }
  census() {
    const text = execFileSync('/bin/ps', ['-axo', 'pid=,ppid=,stat='], { encoding: 'utf8', timeout: 5000 });
    const rows = new Map();
    for (const line of text.split('\n')) {
      if (!line.trim()) continue;
      const match = /^\s*(\d+)\s+(\d+)\s+(\S+)\s*$/.exec(line);
      if (!match) throw new Error('unparseable process census');
      if (!match[3].startsWith('Z')) rows.set(Number(match[1]), Number(match[2]));
    }
    if (!rows.size) throw new Error('empty process census');
    return rows;
  }
  identity(pid) {
    const value = execFileSync(this.python, [this.identityScript, String(pid)], { encoding: 'utf8', timeout: 5000 }).trim();
    if (!/^\d+(?:\.\d{6})?$/.test(value)) throw new Error('invalid process birth identity');
    return value;
  }
  register(req, controllerPid) {
    if (this.failure) throw new Error(this.failure);
    if (!Number.isSafeInteger(req.pid) || req.pid <= 1 || this.stages.has(req.pid)) throw new Error('invalid or duplicate stage PID');
    const rows = this.census();
    if (rows.get(req.pid) !== controllerPid) throw new Error('gated process is not a direct controller child');
    const birth = this.identity(req.pid);
    const stage = { pid: req.pid, unit: req.unit, attempt: req.native_attempt, owned: new Map([[req.pid, birth]]) };
    this.record({ event: 'registered', pid: req.pid, birth, unit: req.unit, attempt: req.native_attempt });
    this.stages.set(req.pid, stage);
    if (!this.timer) this.timer = setInterval(() => {
      try { this.observe(); } catch (e) {
        this.failure = `observer failed: ${e.message}`;
        try { this.record({ event: 'observer-failed', reason: this.failure }); } catch { /* already failed closed */ }
        clearInterval(this.timer); this.timer = null;
      }
    }, 250);
  }
  observe() {
    if (this.failure) throw new Error(this.failure);
    const rows = this.census();
    for (const stage of this.stages.values()) {
      // Check identities before following ancestry, including after reparenting.
      for (const [pid, birth] of stage.owned) {
        if (rows.has(pid) && this.identity(pid) !== birth) throw new Error(`recycled owned PID ${pid}`);
      }
      let changed = true;
      while (changed) {
        changed = false;
        for (const [pid, parent] of rows) {
          if (stage.owned.has(parent) && !stage.owned.has(pid)) {
            const birth = this.identity(pid);
            stage.owned.set(pid, birth);
            this.record({ event: 'observed', root: stage.pid, pid, parent, birth });
            changed = true;
          }
        }
      }
    }
    return rows;
  }
  async resolve(req) {
    if (this.failure) throw new Error(this.failure);
    const stage = this.stages.get(req.pid);
    if (!stage || stage.unit !== req.unit || stage.attempt !== req.native_attempt) throw new Error('unknown stage');
    const grace = Number(req.grace_sec);
    if (!Number.isFinite(grace) || grace < 0 || grace > 30) throw new Error('invalid grace');
    const signal = (sig) => {
      const rows = this.observe();
      for (const [pid, birth] of stage.owned) {
        if (!rows.has(pid)) continue;
        if (this.identity(pid) !== birth) throw new Error(`recycled owned PID ${pid}`);
        try {
          process.kill(pid, sig);
          this.record({ event: 'signaled', pid, birth, signal: sig });
        } catch (e) { if (e.code !== 'ESRCH') throw e; }
      }
    };
    signal('SIGTERM');
    const deadline = Date.now() + grace * 1000;
    let rows;
    while (true) {
      rows = this.observe();
      if (![...stage.owned.keys()].some(pid => rows.has(pid))) break;
      if (Date.now() >= deadline) { signal('SIGKILL'); break; }
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    const killDeadline = Date.now() + 5000;
    while (true) {
      rows = this.observe();
      if (![...stage.owned.keys()].some(pid => rows.has(pid))) break;
      if (Date.now() >= killDeadline) throw new Error('owned processes remain after recovery');
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    this.record({ event: 'resolved', pid: stage.pid, unit: stage.unit, attempt: stage.attempt });
    this.stages.delete(req.pid);
    if (!this.stages.size && this.timer) { clearInterval(this.timer); this.timer = null; }
  }
  async recover() {
    if (this.failure) throw new Error(this.failure);
    for (const stage of [...this.stages.values()]) {
      await this.resolve({ pid: stage.pid, unit: stage.unit, native_attempt: stage.attempt, grace_sec: 5 });
    }
  }
  close() {
    clearInterval(this.timer);
    fs.closeSync(this.fd);
  }
}
