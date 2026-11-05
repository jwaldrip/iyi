import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { execFileSync } from 'node:child_process';
import { sanitizeEnvironment } from './env.js';

const emptyBuckets = () => ({ terminated: [], absent: [], replaced: [], unverifiable: [], survivors: [] });
const BIRTH = /^\d+(?:\.\d{6})?$/;

// The helper's answer for one PID. Anything it cannot vouch for is UNKNOWN, never absence.
function normalizeObservation(value, pid) {
  if (!value || value.pid !== pid || !['LIVE', 'ABSENT', 'UNKNOWN'].includes(value.status)) {
    return { status: 'UNKNOWN', pid, reason: 'invalid observation' };
  }
  if (value.status === 'LIVE' && (!BIRTH.test(String(value.birth)) || !Number.isSafeInteger(value.ppid) ||
      value.ppid < 0 || typeof value.state !== 'string' || !value.state)) {
    return { status: 'UNKNOWN', pid, reason: 'invalid live identity' };
  }
  return value;
}

// A census row carries the identity of its process, read by the same helper call that listed it.
function observationFromRow([pid, ppid, state, birth]) {
  if (birth === null) return { status: 'UNKNOWN', pid, reason: 'identity unreadable' };
  return normalizeObservation({ status: 'LIVE', pid, birth, ppid, state }, pid);
}

// A birth as microseconds since the epoch, for ordering. A simulated birth may have no fraction.
function birthMicros(birth) {
  const [sec, frac = ''] = String(birth).split('.');
  return Number(sec) * 1e6 + Number(frac.padEnd(6, '0'));
}

// A helper-reported integer, or null when it is absent or not a whole non-negative number.
function wholeNumber(value) { return Number.isSafeInteger(value) && value >= 0 ? value : null; }

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
    // The current poll's helper reply. It exists only around synchronous poll code.
    this.snapshot = null;
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

  // One helper call per poll: the census and the identity of each requested PID. When
  // the call fails as a whole, every requested PID is UNKNOWN and the census is an error.
  readSnapshot(pids, timeout) {
    const snapshot = { census: new Map(), rows: new Map(), call: { startWallUs: null, startNs: null, endNs: null }, censusError: null, identities: new Map() };
    let reply;
    try {
      reply = JSON.parse(execFileSync(this.python, [this.identityScript, '--batch'], {
        input: JSON.stringify({ pids, census: true }), encoding: 'utf8', timeout, env: sanitizeEnvironment(),
      }));
    } catch (e) {
      snapshot.censusError = `process census unavailable: ${e.message}`;
      for (const pid of pids) snapshot.identities.set(pid, { status: 'UNKNOWN', pid, reason: snapshot.censusError });
      return snapshot;
    }
    const replyOk = Boolean(reply) && typeof reply === 'object' && Boolean(reply.census) && typeof reply.census === 'object' &&
      Boolean(reply.identities) && typeof reply.identities === 'object';
    if (!replyOk) {
      snapshot.censusError = 'process census unavailable: invalid reply';
    } else if (reply.census.error) {
      snapshot.censusError = `process census unavailable: ${reply.census.error}`;
    } else if (!Array.isArray(reply.census.rows)) {
      snapshot.censusError = 'process census unavailable: invalid census';
    } else {
      // The call's own clock readings, from the same reply as the rows. They bound when each row was read.
      snapshot.call = { startWallUs: wholeNumber(reply.census.call_start_wall_us), startNs: wholeNumber(reply.census.call_start_ns), endNs: wholeNumber(reply.census.call_end_ns) };
      for (const [index, row] of reply.census.rows.entries()) {
        // Census rows are every listed process, so PID 0 (kernel_task on Darwin) and PID 1 (launchd or init) are valid rows.
        if (!Array.isArray(row) || row.length !== 4 || !Number.isSafeInteger(row[0]) || row[0] < 0) {
          snapshot.censusError = 'process census unavailable: invalid census row';
          break;
        }
        const [pid, ppid, state] = row;
        // An unreadable process may be a child of an anchor, so the census cannot be trusted.
        if (ppid === null) { snapshot.censusError = `process census incomplete: unreadable process ${pid}`; break; }
        if (!Number.isSafeInteger(ppid) || ppid < 0 || typeof state !== 'string' || !state) {
          snapshot.censusError = 'process census unavailable: invalid census row';
          break;
        }
        // Each PID names one row in one reply. A repeated PID cannot be bound to one parent edge.
        if (snapshot.rows.has(pid)) { snapshot.censusError = 'process census unavailable: duplicate census row'; break; }
        const identity = observationFromRow(row);
        // A zombie is no census parent or child. Its row still anchors the edge rule, and its identity stays readable.
        snapshot.rows.set(pid, { identity, index });
        if (!state.startsWith('Z')) snapshot.census.set(pid, ppid);
        snapshot.identities.set(pid, identity);
      }
    }
    const observed = new Map(replyOk
      ? Object.entries(reply.identities).map(([key, value]) => [Number(key), normalizeObservation(value, Number(key))])
      : []);
    for (const pid of pids) snapshot.identities.set(pid, observed.get(pid) || { status: 'UNKNOWN', pid, reason: 'identity not observed' });
    return snapshot;
  }

  census(timeout = 5000) {
    const snapshot = this.snapshot || this.readSnapshot([], timeout);
    if (snapshot.censusError) throw new Error(snapshot.censusError);
    return snapshot.census;
  }

  // The poll's census row for a PID, zombies included, from the same reply as census().
  censusRow(pid) {
    return this.pollSnapshot().rows.get(pid);
  }

  // The helper's wall-clock start of the census call in microseconds, or null when it did not say.
  censusStartWallUs() {
    return this.pollSnapshot().call.startWallUs;
  }

  // A row is bound only inside a poll, so every row read comes from one reply.
  pollSnapshot() {
    if (!this.snapshot) throw new Error('census read outside a poll');
    if (this.snapshot.censusError) throw new Error(this.snapshot.censusError);
    return this.snapshot;
  }

  // A read inside a poll is served from the poll's snapshot. A fresh read goes to the helper,
  // as the read that decides a signal must.
  point(pid, timeout = 5000, fresh = false) {
    const snapshot = this.snapshot;
    if (!fresh && snapshot && snapshot.identities.has(pid)) return snapshot.identities.get(pid);
    return this.probeOne(pid, timeout);
  }

  probeOne(pid, timeout = 5000) {
    try {
      const text = execFileSync(this.python, [this.identityScript, String(pid)], { encoding: 'utf8', timeout, env: sanitizeEnvironment() });
      return normalizeObservation(JSON.parse(text), pid);
    } catch (e) { return { status: 'UNKNOWN', pid, reason: e.message }; }
  }

  // Runs one synchronous poll against one helper call. A poll nested inside another shares its snapshot.
  withSnapshot(pids, timeout, poll) {
    if (this.snapshot) return poll();
    this.snapshot = this.readSnapshot(pids, timeout);
    try { return poll(); } finally { this.snapshot = null; }
  }

  activePids() { return [...this.stages.values()].flatMap(stage => [...stage.active.keys()]); }

  register(req, controllerPid) {
    if (this.failure) throw new Error(this.failure);
    if (!this.live()) throw new Error('ownership observer is finalizing');
    try {
      if (!Number.isSafeInteger(req.pid) || req.pid <= 1 || this.stages.has(req.pid)) throw new Error('invalid or duplicate stage PID');
      const { rows, root } = this.withSnapshot([req.pid], 5000, () => ({ rows: this.census(), root: this.point(req.pid) }));
      if (rows.get(req.pid) !== controllerPid || root.status !== 'LIVE' || root.state === 'Z' || root.ppid !== controllerPid) throw new Error('gated process identity or parent unavailable');
      const stage = { pid: req.pid, unit: req.unit, attempt: req.native_attempt, graceSec: this.graceSec, owned: new Map(), active: new Map(), records: [], flight: null };
      const identity = { pid: req.pid, birth: root.birth, root_pid: req.pid, unit: req.unit, native_attempt: req.native_attempt, termAt: null, killed: false, outcome: null };
      this.record({ event: 'registered', ...this.entry(identity), grace_sec: stage.graceSec });
      this.adopt(stage, identity);
      this.stages.set(stage.pid, stage);
      if (!this.timer) this.timer = setInterval(() => {
        try { this.observe(); } catch (e) { this.fail(`observer failed: ${e.message}`); }
      }, 250);
    } catch (e) { this.fail(`registration failed: ${e.message}`); throw e; }
  }

  // Every identity ever bound to a stage stays in its record. Only the live ones are polled.
  adopt(stage, identity) {
    stage.records.push(identity);
    stage.owned.set(identity.pid, identity);
    stage.active.set(identity.pid, identity);
  }

  // Ends an identity's polling with its outcome. The record keeps it, and the journal says so.
  retire(stage, identity, outcome) {
    identity.outcome = outcome;
    if (stage.active.get(identity.pid) === identity) stage.active.delete(identity.pid);
    try { this.record({ event: 'retired', ...this.entry(identity), outcome }); }
    catch (e) { this.fail(`ownership persistence failed: ${e.message}`); }
  }

  // A PID absent, or a zombie with the recorded birth, has exited. A process cannot exit twice.
  exited(identity, current) {
    return current.status === 'ABSENT' || (current.status === 'LIVE' && current.birth === identity.birth && current.state === 'Z');
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

  // One poll: one helper call covers every active identity and the census.
  observe(timeout = 5000, censusTimeout = 5000) {
    if (!this.live()) return new Map();
    return this.withSnapshot(this.activePids(), timeout, () => this.observeNow(timeout, censusTimeout));
  }

  // The edge rule. A census row Y that is not yet owned is adopted only when its owned parent P
  // (a) has a row in the same reply with P's committed birth, (b) was born before Y in microseconds,
  // and (c) either lists Y before P or Y was born before the call started. Anything else is ambiguous.
  // Returns true when Y was adopted.
  bindChild(stage, pid, parent) {
    const child = this.censusRow(pid);
    if (!child || child.identity.status !== 'LIVE') { this.fail(`identity unavailable: ${pid}`); return false; }
    const ambiguous = () => { this.fail(`ambiguous ancestry: ${parent} -> ${pid}`); return false; };
    const parentRow = this.censusRow(parent);
    const parentIdentity = stage.active.get(parent);
    const candidate = child.identity;
    if (candidate.state === 'Z' || candidate.ppid !== parent) return ambiguous();
    if (!parentRow || parentRow.identity.status !== 'LIVE' || parentRow.identity.birth !== parentIdentity.birth) return ambiguous();
    if (birthMicros(parentIdentity.birth) >= birthMicros(candidate.birth)) return ambiguous();
    const startUs = this.censusStartWallUs();
    if (!(child.index < parentRow.index || (startUs !== null && birthMicros(candidate.birth) < startUs))) return ambiguous();
    const identity = { pid, birth: candidate.birth, root_pid: stage.pid, unit: stage.unit, native_attempt: stage.attempt, termAt: null, killed: false, outcome: null };
    try { this.record({ event: 'observed', ...this.entry(identity), parent }); }
    catch (e) { this.fail(`ownership persistence failed: ${e.message}`); return false; }
    this.adopt(stage, identity);
    return true;
  }

  // Committed identities are read first, each with its own window. The census comes second,
  // and its outage taints the observer without stopping the identity reads already made.
  observeNow(timeout, censusTimeout) {
    const deadline = this.now() + timeout;
    const left = () => Math.max(1, Math.min(5000, Math.floor(deadline - this.now())));
    const anchorsByStage = new Map();
    for (const stage of this.stages.values()) {
      const anchors = new Set();
      for (const identity of [...stage.active.values()]) {
        const current = this.point(identity.pid, left());
        if (current.status === 'UNKNOWN') { this.fail(`identity unavailable: ${identity.pid}`); continue; }
        if (this.exited(identity, current)) { this.retire(stage, identity, identity.termAt === null ? 'absent' : 'terminated'); continue; }
        if (current.birth !== identity.birth) { this.fail(`recycled owned PID ${identity.pid}`); this.retire(stage, identity, 'replaced'); continue; }
        anchors.add(identity.pid);
      }
      anchorsByStage.set(stage, anchors);
    }
    const rows = this.census(Math.min(censusTimeout, left()));
    for (const [stage, anchors] of anchorsByStage) {
      let changed = true;
      while (changed) {
        changed = false;
        for (const [pid, parent] of rows) {
          if (!anchors.has(parent) || stage.active.has(pid)) continue;
          if (!this.bindChild(stage, pid, parent)) continue;
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

  // Every identity in the record is bucketed by its outcome. One without an outcome is still live, so it is a survivor.
  bucketsFor(stage, buckets) {
    for (const identity of stage.records) buckets[identity.outcome || 'survivors'].push(this.entry(identity));
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
    const remaining = () => Math.max(1, Math.floor(deadline - this.now()));
    const probeWindow = () => Math.min(5000, remaining());
    // A new pass decides afresh whether an unverifiable identity is still unknown.
    for (const identity of stage.records) if (identity.outcome === 'unverifiable') identity.outcome = null;
    const decided = new Set();
    const pending = () => [...stage.active.values()].some(identity => !decided.has(identity));
    while (this.live() && this.now() < deadline && pending()) {
      this.withSnapshot(this.activePids(), probeWindow(), () => this.recoveryPass(stage, deadline, decided, probeWindow, remaining));
      if (!this.live() || !pending()) break;
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

  // One synchronous recovery pass over the stage's live identities, then one census.
  recoveryPass(stage, deadline, decided, probeWindow, remaining) {
    for (const identity of [...stage.active.values()]) {
      if (!this.live() || decided.has(identity) || this.now() >= deadline) continue;
      let current = this.point(identity.pid, probeWindow());
      if (this.exited(identity, current)) { this.retire(stage, identity, identity.termAt === null ? 'absent' : 'terminated'); continue; }
      if (current.status === 'UNKNOWN') { this.fail(`identity unavailable: ${identity.pid}`); this.markUnverifiable(identity, decided); continue; }
      if (current.birth !== identity.birth) { this.fail(`recycled owned PID ${identity.pid}`); this.retire(stage, identity, 'replaced'); continue; }
      const sig = identity.termAt === null ? 'SIGTERM' : (!identity.killed && this.now() - identity.termAt >= stage.graceSec * 1000 ? 'SIGKILL' : null);
      if (!sig) continue;
      // The read that decides a signal is fresh, never the poll's snapshot.
      current = this.point(identity.pid, probeWindow(), true);
      if (this.exited(identity, current)) { this.retire(stage, identity, identity.termAt === null ? 'absent' : 'terminated'); continue; }
      if (current.status === 'UNKNOWN') { this.fail(`identity unavailable before ${sig}: ${identity.pid}`); this.markUnverifiable(identity, decided); continue; }
      if (current.birth !== identity.birth) { this.fail(`recycled owned PID ${identity.pid}`); this.retire(stage, identity, 'replaced'); continue; }
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
        this.markUnverifiable(identity, decided);
      }
    }
    // Census second. It may use at most half of what remains, so the next probe pass keeps a share of the budget.
    if (this.live() && this.now() < deadline) {
      try { this.observe(probeWindow(), Math.min(5000, Math.max(1, Math.floor(remaining() / 2)))); }
      catch (e) { this.fail(`observer failed: ${e.message}`); }
    }
  }

  markUnverifiable(identity, decided) {
    identity.outcome = 'unverifiable';
    decided.add(identity);
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
        const result = this.report([stage], this.bucketsFor(stage, emptyBuckets()));
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
