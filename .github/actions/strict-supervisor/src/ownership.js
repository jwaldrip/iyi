import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { execFileSync } from 'node:child_process';
import { sanitizeEnvironment } from './env.js';

const emptyBuckets = () => ({ terminated: [], absent: [], replaced: [], unverifiable: [], survivors: [] });

// Polling cannot see a fork and reparent entirely between observations. A
// point probe followed by kill is also not an atomic identity-bound signal.
export class OwnershipObserver {
  constructor(python, identityScript, options = {}) {
    this.python = python;
    this.identityScript = identityScript;
    this.graceSec = options.graceSec ?? 30;
    this.budgetMs = options.budgetMs ?? 45000;
    if (!Number.isFinite(this.graceSec) || this.graceSec < 0 || this.graceSec > 30 ||
        !Number.isFinite(this.budgetMs) || this.budgetMs <= 0) throw new Error('invalid ownership timing');
    this.onFailure = options.onFailure;
    this.stages = new Map();
    this.completed = new Map();
    this.taintReasons = [];
    this.failure = null;
    this.timer = null;
    // The one in-flight recovery. Every caller joins it and shares its deadline.
    this.recovering = null;
    // Set once when recovery is cancelled. A cancelled observer never probes or signals again.
    this.aborted = null;
    this.closed = false;
    this.directory = path.join(options.tempRoot || os.tmpdir(), 'strict-supervisor-ownership');
    // mkdir is the exclusive host-wide claim. An incomplete claim is quarantine.
    fs.mkdirSync(this.directory, { mode: 0o700 });
    const parent = fs.openSync(path.dirname(this.directory), 'r');
    try { fs.fsyncSync(parent); } finally { fs.closeSync(parent); }
    this.fd = fs.openSync(path.join(this.directory, 'ownership.jsonl'), 'ax', 0o600);
    this.record({ event: 'active', context: options.context || {}, grace_sec: this.graceSec });
    const dirfd = fs.openSync(this.directory, 'r');
    try { fs.fsyncSync(dirfd); } finally { fs.closeSync(dirfd); }
  }

  record(value) {
    if (this.closed) throw new Error('ownership journal is closed');
    const data = Buffer.from(JSON.stringify(value) + '\n');
    let written = 0;
    while (written < data.length) {
      const count = fs.writeSync(this.fd, data, written, data.length - written);
      if (!count) throw new Error('short ownership journal write');
      written += count;
    }
    fs.fsyncSync(this.fd);
  }

  fail(reason) {
    const text = String(reason);
    const first = !this.failure;
    const isNew = !this.taintReasons.includes(text);
    if (isNew) this.taintReasons.push(text);
    if (first) this.failure = text;
    try { if (isNew) this.record({ event: 'unresolved', reason: text }); } catch (e) {
      const persistence = `ownership persistence failed: ${e.message}`;
      if (!this.taintReasons.includes(persistence)) this.taintReasons.push(persistence);
    }
    if (first && this.onFailure) {
      try { this.onFailure(text); } catch { /* the durable active record still blocks reuse */ }
    }
  }

  // Recovery may act only while the observer is live. Abort and close both end it for good.
  live() { return this.aborted === null && !this.closed; }

  busy() {
    return this.live() && (this.recovering !== null || [...this.stages.values()].some(stage => stage.flight !== null));
  }

  persistReport(report) {
    try { this.record({ event: 'recovery-report', report }); }
    catch (e) { this.fail(`ownership persistence failed: ${e.message}`); }
  }

  census(timeout = 5000) {
    const text = execFileSync('/bin/ps', ['-axo', 'pid=,ppid=,stat='], { encoding: 'utf8', timeout, env: sanitizeEnvironment() });
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

  point(pid, timeout = 5000) {
    try {
      const text = execFileSync(this.python, [this.identityScript, String(pid)], { encoding: 'utf8', timeout, env: sanitizeEnvironment() });
      const value = JSON.parse(text);
      if (value.pid !== pid || !['LIVE', 'ABSENT', 'UNKNOWN'].includes(value.status)) throw new Error('invalid point observation');
      if (value.status === 'LIVE' && (!/^\d+(?:\.\d{6})?$/.test(value.birth) || !Number.isSafeInteger(value.ppid) || value.ppid < 0 || typeof value.state !== 'string' || !value.state)) throw new Error('invalid live identity');
      return value;
    } catch (e) { return { status: 'UNKNOWN', pid, reason: e.message }; }
  }

  register(req, controllerPid) {
    if (this.failure) throw new Error(this.failure);
    if (!this.live()) throw new Error('ownership observer is finalizing');
    try {
      if (!Number.isSafeInteger(req.pid) || req.pid <= 1 || this.stages.has(req.pid)) throw new Error('invalid or duplicate stage PID');
      const rows = this.census();
      const root = this.point(req.pid);
      if (rows.get(req.pid) !== controllerPid || root.status !== 'LIVE' || root.state === 'Z' || root.ppid !== controllerPid) throw new Error('gated process identity or parent unavailable');
      const stage = { pid: req.pid, unit: req.unit, attempt: req.native_attempt, graceSec: this.graceSec, owned: new Map(), flight: null, outcomes: new Map() };
      const identity = { pid: req.pid, birth: root.birth, root_pid: req.pid, unit: req.unit, native_attempt: req.native_attempt, termAt: null, killed: false };
      this.record({ event: 'registered', ...this.entry(identity), grace_sec: stage.graceSec });
      stage.owned.set(identity.pid, identity);
      this.stages.set(stage.pid, stage);
      if (!this.timer) this.timer = setInterval(() => {
        try { this.observe(); } catch (e) { this.fail(`observer failed: ${e.message}`); }
      }, 250);
    } catch (e) { this.fail(`registration failed: ${e.message}`); throw e; }
  }

  entry(identity) {
    return { pid: identity.pid, birth: identity.birth, root_pid: identity.root_pid, unit: identity.unit, native_attempt: identity.native_attempt };
  }
  now() { return performance.now(); }
  signal(pid, sig) {
    if (!this.live()) throw new Error('ownership observer is finalizing');
    process.kill(pid, sig);
  }
  sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

  // Committed identities are probed first, each with its own window. The census
  // runs second, and its outage taints the observer without stopping the probes.
  observe(timeout = 5000, censusTimeout = 5000) {
    if (!this.live()) return new Map();
    const deadline = this.now() + timeout;
    const left = () => Math.max(1, Math.min(5000, Math.floor(deadline - this.now())));
    const anchorsByStage = new Map();
    for (const stage of this.stages.values()) {
      const anchors = new Set();
      for (const identity of stage.owned.values()) {
        const current = this.point(identity.pid, left());
        if (current.status === 'UNKNOWN') { this.fail(`identity unavailable: ${identity.pid}`); continue; }
        if (current.status === 'LIVE' && current.birth !== identity.birth) { this.fail(`recycled owned PID ${identity.pid}`); continue; }
        if (current.status === 'LIVE' && current.state !== 'Z') anchors.add(identity.pid);
      }
      anchorsByStage.set(stage, anchors);
    }
    const rows = this.census(Math.min(censusTimeout, left()));
    for (const [stage, anchors] of anchorsByStage) {
      let changed = true;
      while (changed) {
        changed = false;
        for (const [pid, parent] of rows) {
          if (!anchors.has(parent) || stage.owned.has(pid)) continue;
          const candidate = this.point(pid, left());
          const parentIdentity = stage.owned.get(parent);
          const currentParent = this.point(parent, left());
          if (candidate.status !== 'LIVE' || candidate.state === 'Z' || candidate.ppid !== parent || currentParent.status !== 'LIVE' || currentParent.state === 'Z' || currentParent.birth !== parentIdentity.birth) {
            this.fail(`ambiguous ancestry: ${parent} -> ${pid}`); continue;
          }
          const identity = { pid, birth: candidate.birth, root_pid: stage.pid, unit: stage.unit, native_attempt: stage.attempt, termAt: null, killed: false };
          try { this.record({ event: 'observed', ...this.entry(identity), parent }); }
          catch (e) { this.fail(`ownership persistence failed: ${e.message}`); continue; }
          stage.owned.set(pid, identity);
          anchors.add(pid);
          changed = true;
        }
      }
    }
    return rows;
  }

  report(stages, buckets) {
    return { proof_resolved: !this.failure && buckets.replaced.length === 0 && buckets.unverifiable.length === 0 && buckets.survivors.length === 0,
      taint_reasons: [...this.taintReasons], grace_sec: stages.length === 1 ? stages[0].graceSec : this.graceSec, recovery: buckets };
  }

  // Identities without a recorded outcome are survivors: the stage did not prove them gone.
  bucketsFor(stage, buckets) {
    for (const identity of stage.owned.values()) buckets[stage.outcomes.get(identity.pid) || 'survivors'].push(this.entry(identity));
    return buckets;
  }

  unresolvedReport() {
    const stages = [...this.stages.values()];
    const buckets = emptyBuckets();
    for (const stage of stages) this.bucketsFor(stage, buckets);
    for (const report of this.completed.values()) for (const key of Object.keys(buckets)) buckets[key].push(...report.recovery[key]);
    const report = this.report(stages, buckets);
    report.proof_resolved = false;
    report.taint_reasons = [...this.taintReasons];
    return report;
  }

  async stageRecovery(stage, deadline) {
    const outcomes = new Map();
    stage.outcomes = outcomes;
    const remaining = () => Math.max(1, Math.floor(deadline - this.now()));
    const window = () => Math.min(5000, remaining());
    while (this.live() && this.now() < deadline) {
      // Committed identities first. Each probe gets its own window, which a census never shortens.
      for (const identity of stage.owned.values()) {
        if (!this.live() || outcomes.has(identity.pid) || this.now() >= deadline) continue;
        let current = this.point(identity.pid, window());
        if (current.status === 'ABSENT' || (current.status === 'LIVE' && current.birth === identity.birth && current.state === 'Z')) {
          outcomes.set(identity.pid, identity.termAt === null ? 'absent' : 'terminated'); continue;
        }
        if (current.status === 'UNKNOWN') { this.fail(`identity unavailable: ${identity.pid}`); outcomes.set(identity.pid, 'unverifiable'); continue; }
        if (current.birth !== identity.birth) { this.fail(`recycled owned PID ${identity.pid}`); outcomes.set(identity.pid, 'replaced'); continue; }
        const sig = identity.termAt === null ? 'SIGTERM' : (!identity.killed && this.now() - identity.termAt >= stage.graceSec * 1000 ? 'SIGKILL' : null);
        if (!sig) continue;
        current = this.point(identity.pid, window());
        if (current.status === 'ABSENT' || (current.status === 'LIVE' && current.birth === identity.birth && current.state === 'Z')) { outcomes.set(identity.pid, identity.termAt === null ? 'absent' : 'terminated'); continue; }
        if (current.status === 'UNKNOWN') { this.fail(`identity unavailable before ${sig}: ${identity.pid}`); outcomes.set(identity.pid, 'unverifiable'); continue; }
        if (current.birth !== identity.birth) { this.fail(`recycled owned PID ${identity.pid}`); outcomes.set(identity.pid, 'replaced'); continue; }
        if (this.now() >= deadline) continue;
        try {
          this.signal(identity.pid, sig);
          const monotonicMs = this.now();
          if (sig === 'SIGTERM') identity.termAt = monotonicMs; else identity.killed = true;
          try { this.record({ event: 'signaled', ...this.entry(identity), signal: sig, monotonic_ms: monotonicMs }); }
          catch (e) { this.fail(`ownership persistence failed: ${e.message}`); }
        } catch (e) {
          if (e.code === 'ESRCH') continue;
          this.fail(`signal ${sig} failed for ${identity.pid}: ${e.message}`);
          outcomes.set(identity.pid, 'unverifiable');
        }
      }
      // Census second. It may use at most half of what remains, so the next probe pass keeps a share of the budget.
      if (this.live() && this.now() < deadline) {
        try { this.observe(window(), Math.min(5000, Math.max(1, Math.floor(remaining() / 2)))); }
        catch (e) { this.fail(`observer failed: ${e.message}`); }
      }
      if (!this.live() || [...stage.owned.keys()].every(pid => outcomes.has(pid))) break;
      if (this.now() < deadline) await this.sleep(Math.min(100, Math.max(1, deadline - this.now())));
    }
    // Cancelled: abort has already recorded the unresolved outcome, so nothing more is written.
    if (!this.live()) return this.report([stage], this.bucketsFor(stage, emptyBuckets()));
    const buckets = this.bucketsFor(stage, emptyBuckets());
    if (buckets.survivors.length) this.fail(`recovery budget exhausted for stage ${stage.pid}`);
    const report = this.report([stage], buckets);
    this.persistReport(report);
    report.proof_resolved = report.proof_resolved && !this.failure;
    report.taint_reasons = [...this.taintReasons];
    if (report.proof_resolved) {
      try { this.record({ event: 'resolved', root_pid: stage.pid, unit: stage.unit, native_attempt: stage.attempt }); }
      catch (e) { this.fail(`ownership persistence failed: ${e.message}`); report.proof_resolved = false; report.taint_reasons = [...this.taintReasons]; }
      if (report.proof_resolved) {
        this.stages.delete(stage.pid);
        this.completed.set(JSON.stringify([stage.pid, stage.unit, stage.attempt]), report);
      }
    }
    if (!this.stages.size && this.timer) { clearInterval(this.timer); this.timer = null; }
    return report;
  }

  async resolve(req, { deadline } = {}) {
    if (!this.live()) throw new Error('ownership observer is finalizing');
    if (req.grace_sec !== undefined && Number(req.grace_sec) !== this.graceSec) { this.fail('grace does not match registered configuration'); throw new Error('grace does not match registered configuration'); }
    const completed = this.completed.get(JSON.stringify([req.pid, req.unit, req.native_attempt]));
    if (completed) return { ...completed, proof_resolved: !this.failure, taint_reasons: [...this.taintReasons] };
    const stage = this.stages.get(req.pid);
    if (!stage || stage.unit !== req.unit || stage.attempt !== req.native_attempt) { this.fail('unknown stage'); throw new Error('unknown stage'); }
    if (!stage.flight) {
      // A caller without a shared deadline gets this stage its own budget.
      const end = deadline ?? this.now() + this.budgetMs;
      stage.flight = Promise.resolve().then(() => this.stageRecovery(stage, end)).catch(e => {
        this.fail(`recovery failed for stage ${stage.pid}: ${e.message}`);
        const buckets = { terminated: [], absent: [], replaced: [], unverifiable: [], survivors: [...stage.owned.values()].map(identity => this.entry(identity)) };
        const result = this.report([stage], buckets);
        if (this.live()) this.persistReport(result);
        result.taint_reasons = [...this.taintReasons];
        return result;
      }).finally(() => { stage.flight = null; });
    }
    return stage.flight;
  }

  // Single-flight: concurrent callers join the in-flight recovery and share its deadline.
  recover({ deadline } = {}) {
    if (!this.recovering) {
      const end = deadline ?? this.now() + this.budgetMs;
      this.recovering = this.recoverStages(end).finally(() => { this.recovering = null; });
    }
    return this.recovering;
  }

  async recoverStages(deadline) {
    if (!this.live()) return this.unresolvedReport();
    const stages = [...this.stages.values()];
    const reports = await Promise.all(stages.map(stage => this.resolve({ pid: stage.pid, unit: stage.unit, native_attempt: stage.attempt }, { deadline })));
    // Cancelled while stages were winding down: abort has already recorded the outcome.
    if (!this.live()) return this.unresolvedReport();
    const buckets = emptyBuckets();
    for (const report of reports) for (const key of Object.keys(buckets)) buckets[key].push(...report.recovery[key]);
    const result = this.report(stages, buckets);
    this.persistReport(result);
    result.proof_resolved = result.proof_resolved && !this.failure;
    result.taint_reasons = [...this.taintReasons];
    return result;
  }

  // Cancels recovery and records the unresolved outcome before returning. From here on
  // no probe or signal runs, and the caller may close the observer.
  abort(reason) {
    const text = String(reason);
    if (this.aborted === null) this.aborted = text;
    clearInterval(this.timer);
    this.timer = null;
    this.fail(text);
    const report = this.unresolvedReport();
    this.persistReport(report);
    return report;
  }

  close() {
    if (this.closed) return;
    // A recovery still in flight is cancelled and recorded as unresolved before the journal closes.
    if (this.busy()) this.abort('ownership observer closed while recovery was in flight');
    this.closed = true;
    clearInterval(this.timer);
    this.timer = null;
    fs.closeSync(this.fd);
    if (!this.failure && !this.stages.size) {
      fs.unlinkSync(path.join(this.directory, 'ownership.jsonl'));
      fs.rmdirSync(this.directory);
      const parent = fs.openSync(path.dirname(this.directory), 'r');
      try { fs.fsyncSync(parent); } finally { fs.closeSync(parent); }
    }
  }
}
