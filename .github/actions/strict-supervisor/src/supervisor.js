import { spawn, execFileSync } from 'node:child_process';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { sanitizeEnvironment, redactSecrets } from './env.js';
import { IMMUTABLE_BINDING_FIELDS, validateRequest, writeIpcAck, createIpcReader } from './ipc.js';
import { uploadAndVerifyPayload } from './artifact-adapter.js';
import { OwnershipObserver } from './ownership.js';

const WORKSPACE_ACTION_SRC = path.resolve('.github/actions/strict-supervisor/src');
const ACTION_SRC = fs.existsSync(WORKSPACE_ACTION_SRC) ? WORKSPACE_ACTION_SRC : path.resolve('src');
const CONTEXT_FIELDS = ['invocation_id', 'execution_kind', 'repository', 'run_id', 'run_attempt', 'job_id', 'job_key', 'p_sha', 'w_sha', 'c_sha', 'fixture_sha256'];
const EMITTER_DIGEST = `import ast,hashlib,sys\nt=ast.parse(open(sys.argv[1],encoding='utf8').read())\nx=[n.value for n in t.body if isinstance(n,ast.Assign) and any(isinstance(a,ast.Name) and a.id=='FAKE_STAGE_EMITTER_SOURCE' for a in n.targets)]\nassert len(x)==1\ns=ast.literal_eval(x[0]); assert isinstance(s,str)\nprint(hashlib.sha256(s.encode('utf8')).hexdigest())`;

function sha(dir) {
  return execFileSync('git', ['-C', dir, 'rev-parse', 'HEAD'], { encoding: 'utf8', env: sanitizeEnvironment() }).trim();
}

// All shutdown waits share one monotonic deadline. Timing out is a failure,
// not evidence that a controller or one of its descendants has exited.
async function beforeDeadline(promise, deadline, label) {
  const remaining = Math.max(0, deadline - performance.now());
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`${label} timed out`)), remaining); }),
    ]);
  } finally { clearTimeout(timer); }
}

export class StrictSupervisor {
  constructor(options = {}) {
    Object.assign(this, options);
    this.parentEnv = options.parentEnv || process.env;
    this.pythonPath = options.pythonPath || 'python3';
    this.artifactsDir = path.resolve(options.artifactsDir || 'strict-proof-artifacts');
    this.mode = options.mode || 'strict';
    this.requests = [];
    this.acks = [];
    this.ownershipAcks = [];
    this.entries = [];
    this.seenRequestIds = new Set();
    this.lastSnapshotSequence = 0;
    this.failedVerifications = 0;
  }
  async resolveArtifactClient() {
    if (!this.artifactClient) {
      const artifactModule = await import('@actions/artifact');
      this.artifactClient = new artifactModule.DefaultArtifactClient();
    }
    return this.artifactClient;
  }
  async establishContext() {
    const env = this.parentEnv;
    if (!['strict', 'validation-only'].includes(this.mode)) throw new Error('invalid mode');
    if (!/^[A-Za-z0-9_-]{1,80}$/.test(this.invocationId || '')) throw new Error('invalid invocation id');
    if (!/^[1-9][0-9]*$/.test(String(this.jobId || '')) || !this.jobKey || this.jobKey !== env.GITHUB_JOB) throw new Error('invalid job identity');
    if (!env.GITHUB_REPOSITORY || !/^[1-9][0-9]*$/.test(env.GITHUB_RUN_ID || '') || !/^[1-9][0-9]*$/.test(env.GITHUB_RUN_ATTEMPT || '') || !env.RUNNER_NAME || !env.GITHUB_TOKEN) throw new Error('missing platform identity');
    const pSha = sha(this.p), wSha = sha(this.w), cSha = sha(process.cwd());
    if (pSha !== this.pSha || wSha !== this.wSha || cSha !== this.cSha) throw new Error('actual source revision does not match expected tuple');
    if (this.mode === 'strict' && (String(this.graceSec || '30') !== '30' || String(this.driverLimitSec || '2100') !== '2100')) throw new Error('strict timing changes are not authorized');
    const url = `${env.GITHUB_API_URL || 'https://api.github.com'}/repos/${env.GITHUB_REPOSITORY}/actions/runs/${env.GITHUB_RUN_ID}/attempts/${env.GITHUB_RUN_ATTEMPT}/jobs?per_page=100`;
    let next = url, matches = [];
    while (next) {
      const response = await fetch(next, { headers: { authorization: `Bearer ${env.GITHUB_TOKEN}`, accept: 'application/vnd.github+json', 'user-agent': 'strict-proof-supervisor' } });
      if (!response.ok) throw new Error(`job lookup failed: HTTP ${response.status}`);
      const body = await response.json();
      if (!Array.isArray(body.jobs)) throw new Error('invalid job lookup');
      matches.push(...body.jobs.filter(j => String(j.id) === String(this.jobId) && j.status === 'in_progress' && j.runner_name === env.RUNNER_NAME));
      const link = response.headers.get('link') || '';
      next = /<([^>]+)>;\s*rel="next"/.exec(link)?.[1] || null;
    }
    if (matches.length !== 1) throw new Error('job lookup missing or ambiguous');
    if (!matches[0].started_at || matches[0].started_at !== this.jobStartTime) throw new Error('job start does not match platform');
    const fixture = this.mode === 'validation-only' ? execFileSync(this.pythonPath, ['-c', EMITTER_DIGEST, path.resolve('proof/remote_strict_fixtures.py')], { encoding: 'utf8', env: sanitizeEnvironment(env) }).trim() : null;
    return Object.freeze({ invocation_id: this.invocationId, execution_kind: this.mode === 'validation-only' ? 'synthetic' : 'native', repository: env.GITHUB_REPOSITORY, run_id: env.GITHUB_RUN_ID, run_attempt: env.GITHUB_RUN_ATTEMPT, job_id: String(this.jobId), job_key: this.jobKey, p_sha: pSha, w_sha: wSha, c_sha: cSha, fixture_sha256: fixture });
  }
  buildChildArgs() {
    const script = this.mode === 'validation-only' ? 'proof/remote_strict_validation.py' : 'proof/remote_strict_controller.py';
    const args = [script, '--p', this.p, '--w', this.w, '--compiler', this.compiler, '--artifacts-dir', this.artifactsDir,
      '--job-start-time', String(this.jobStartTime), '--host-job-limit-sec', String(this.hostJobLimitSec || '21600'), '--payload-budget-sec', String(this.payloadBudgetSec || '19800'), '--finalization-alloc-sec', String(this.finalizationAllocSec || '1800'), '--driver-limit-sec', String(this.driverLimitSec || '2100'), '--grace-sec', String(this.graceSec ?? '30'), '--min-disk-gib', String(this.minDiskGib || '20.0'), '--ipc-req-fd', '3', '--ipc-ack-fd', '4', '--p-sha', this.context.p_sha, '--w-sha', this.context.w_sha, '--c-sha', this.context.c_sha, '--invocation-id', this.context.invocation_id, '--job-id', this.context.job_id, '--job-key', this.context.job_key];
    args.push('--repository', this.context.repository, '--run-id', this.context.run_id, '--run-attempt', this.context.run_attempt);
    if (this.mode === 'validation-only') {
      if (!['success', 'failed-plan', 'failed-pin', 'divergence', 'cleanup-failure', 'ownership-crash', 'ownership-census-outage'].includes(this.validationCase) || !this.caseDataDir) throw new Error('invalid validation case');
      args.push('--case', this.validationCase, '--case-data-dir', this.caseDataDir);
    } else args.push('--mode', 'strict');
    return args;
  }
  async handleRequest(req, ackStream) {
    let ack;
    try {
      if (!req || req.protocol_version !== 1 || typeof req.request_id !== 'string' || !req.request_id || req.invocation_id !== this.context.invocation_id || this.seenRequestIds.has(req.request_id)) throw new Error('invalid or replayed request');
      this.seenRequestIds.add(req.request_id);
      if (req.event === 'ownership-register' || req.event === 'ownership-resolve') {
        if (typeof req.unit !== 'string' || !req.unit || !Number.isSafeInteger(req.native_attempt) || req.native_attempt < 1) throw new Error('invalid stage association');
        if (this.stopping && req.event === 'ownership-register') throw new Error('ownership registration refused during shutdown');
        const result = req.event === 'ownership-register'
          ? await this.ownership.register(req, this.childProcess.pid)
          : await this.ownership.resolve(req);
        if (req.event === 'ownership-resolve' && (!result || typeof result.proof_resolved !== 'boolean')) throw new Error('invalid ownership resolution result');
        ack = { ...req, event: `${req.event}-ack`, verified: req.event === 'ownership-register' ? !this.ownership.failure : result.proof_resolved };
        if (result) ack.ownership_result = result;
        if (!ack.verified) this.failedVerifications++;
      } else {
        const validation = validateRequest(req);
        if (!validation.valid) throw new Error(validation.error);
        for (const field of CONTEXT_FIELDS) if (req[field] !== this.context[field]) throw new Error(`context mismatch: ${field}`);
        if (req.snapshot_sequence <= this.lastSnapshotSequence) throw new Error('non-increasing snapshot sequence');
        this.lastSnapshotSequence = req.snapshot_sequence;
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'strict-upload-'));
        let receipt;
        try {
          const copy = path.join(dir, path.basename(req.archive_path));
          execFileSync(this.pythonPath, [path.join(ACTION_SRC, 'seal_copy.py'), this.artifactsDir, req.archive_path, copy, String(req.archive_bytes), req.archive_sha256], { timeout: 30000, env: sanitizeEnvironment(this.parentEnv) });
          receipt = await uploadAndVerifyPayload({ ...req, archive_path: copy }, await this.resolveArtifactClient());
        } finally { fs.rmSync(dir, { recursive: true, force: true }); }
        const binding = Object.fromEntries(IMMUTABLE_BINDING_FIELDS.map(field => [field, req[field]]));
        ack = { ...binding, event: 'persistence-ack', ...receipt };
        if (!ack.verified || !ack.artifact_id || ack.downloaded_sha256 !== req.archive_sha256 || ack.downloaded_bytes !== req.archive_bytes) throw new Error('artifact readback mismatch');
        this.requests.push(req);
        this.acks.push(ack);
        this.entries.push({ request: req, ack });
        this.saveIndex(null);
      }
    } catch (err) {
      this.failedVerifications++;
      if (req?.event === 'ownership-register' || req?.event === 'ownership-resolve') {
        this.ownership.fail(`ownership control failed: ${redactSecrets(String(err.message))}`);
      }
      ack = { ...req, event: `${req?.event || 'invalid'}-ack`, verified: false, error: redactSecrets(String(err.message)) };
    }
    try {
      await writeIpcAck(ackStream, ack);
      if (req?.event === 'ownership-register' || req?.event === 'ownership-resolve') this.ownershipAcks.push(ack);
    } catch (err) {
      this.ownership.fail(`ACK write failed: ${redactSecrets(String(err.message))}`);
      throw err;
    }
  }
  saveIndex(exitCode) {
    const ownership = this.ownership ? fs.readFileSync(path.join(this.ownership.directory, 'ownership.jsonl'), 'utf8').split('\n').filter(Boolean).map(line => {
      try { return JSON.parse(line); }
      catch {
        this.ownership.fail('unparseable ownership journal');
        return { event: 'unparseable-journal', raw: line };
      }
    }) : [];
    if (this.ownership?.failure && this.ownershipRecovery) {
      this.ownershipRecovery.proof_resolved = false;
      this.ownershipRecovery.taint_reasons = [...this.ownership.taintReasons];
    }
    const data = JSON.stringify({ invocation_id: this.context.invocation_id, execution_kind: this.context.execution_kind, exit_code: exitCode, controller_signal: this.controllerSignal || null, entries: this.entries, ownership_control_acks: this.ownershipAcks, ownership_ledger: this.ownership?.directory || this.guardRefusal?.ledger || null, ownership_guard_refusal: this.guardRefusal || null, ownership_journal: ownership, ownership_recovery: this.ownershipRecovery || null }, null, 2) + '\n';
    const fd = fs.openSync(this.indexPath, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_TRUNC | fs.constants.O_NOFOLLOW, 0o600);
    try { fs.writeFileSync(fd, data); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  }
  async run() {
    this.context = await this.establishContext();
    this.indexPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'strict-index-')), 'receipt-index.json');
    this.saveIndex(null);
    const graceSec = Number(this.graceSec ?? 30);
    const finalizationSec = Number(this.finalizationAllocSec ?? 1800);
    if (!Number.isFinite(graceSec) || graceSec < 0 || graceSec > 30 ||
        (this.mode === 'strict' && graceSec !== 30) ||
        !Number.isFinite(finalizationSec) || finalizationSec <= 0) throw new Error('invalid ownership timing');
    const budgetMs = Math.min(45000, finalizationSec * 1000);
    let child, recoveryPromise, shutdownDeadline, controllerStopTimer;
    let streamFailure = null;
    let notifyFailure;
    const failed = new Promise(resolve => { notifyFailure = resolve; });
    const startRecovery = () => {
      if (!shutdownDeadline) shutdownDeadline = performance.now() + budgetMs;
      if (!recoveryPromise) {
        recoveryPromise = Promise.resolve().then(() => this.ownership.recover());
        // Attach a rejection handler immediately, even if the controller has
        // not exited yet. The finalizer still observes the original rejection.
        recoveryPromise.catch(() => {});
      }
      return recoveryPromise;
    };
    const onFailure = reason => {
      this.stopping = true;
      if (!streamFailure) streamFailure = new Error(reason);
      if (child && child.exitCode === null && child.signalCode === null) {
        child.kill('SIGTERM');
        controllerStopTimer ||= setTimeout(() => {
          if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
        }, Math.min(5000, budgetMs));
      }
      startRecovery();
      notifyFailure();
    };
    const childArgs = this.buildChildArgs();
    const tempRoot = fs.realpathSync('/tmp');
    const guardPath = path.join(tempRoot, 'strict-supervisor-ownership');
    try {
      this.ownership = new OwnershipObserver(this.pythonPath, path.join(ACTION_SRC, 'process_identity.py'), {
        context: this.context, graceSec, budgetMs, onFailure, tempRoot,
      });
    } catch (err) {
      if (err.code !== 'EEXIST' || err.path !== guardPath) throw err;
      this.guardRefusal = { reason: 'existing-ownership-guard', ledger: guardPath, controller_spawned: false };
      this.failedVerifications++;
      this.saveIndex(null);
      return { exitCode: null, signal: null, outcome: 'REFUSED', envelopePath: this.indexPath, receiptIndexPath: this.indexPath, totalRequests: 0, failedVerifications: this.failedVerifications };
    }
    child = spawn(this.pythonPath, childArgs, { stdio: ['inherit', 'inherit', 'inherit', 'pipe', 'pipe'], env: sanitizeEnvironment(this.parentEnv) });
    this.childProcess = child;
    let requestChain = Promise.resolve();
    const onStreamFailure = e => {
      if (!streamFailure) streamFailure = e;
      this.ownership.fail(`controller IPC failed: ${redactSecrets(String(e.message))}`);
    };
    child.stdio[3].on('error', onStreamFailure);
    child.stdio[4].on('error', onStreamFailure);
    const requestEnd = new Promise(resolve => {
      child.stdio[3].once('end', resolve);
      child.stdio[3].once('error', resolve);
    });
    createIpcReader(child.stdio[3], req => {
      requestChain = requestChain.then(() => this.handleRequest(req, child.stdio[4])).catch(onStreamFailure);
    });
    let crashTimer = null;
    let crashDeadline = null;
    let crashObserved = null;
    if (this.mode === 'validation-only' && ['ownership-crash', 'ownership-census-outage'].includes(this.validationCase)) {
      crashDeadline = setTimeout(() => {
        streamFailure = new Error('synthetic crash readiness not observed');
        child.kill('SIGKILL');
      }, 120000);
      crashTimer = setInterval(() => {
        try {
          if (fs.readFileSync(path.join(this.caseDataDir, 'ownership-ready'), 'utf8') !== 'ready\n') return;
          const match = /^child:([1-9]\d*)\ngrandchild:([1-9]\d*)\n$/.exec(fs.readFileSync(path.join(this.caseDataDir, 'ownership-pids'), 'utf8'));
          if (!match) throw new Error('invalid crash fixture process list');
          const pids = [Number(match[1]), Number(match[2])];
          this.ownership.observe();
          if (![...this.ownership.stages.values()].some(stage => pids.every(pid => stage.owned.has(pid)))) return;
          crashObserved = pids;
          clearInterval(crashTimer);
          if (this.validationCase === 'ownership-census-outage') {
            this.ownership.census = () => { throw new Error('synthetic permanent census outage'); };
            this.ownership.fail('synthetic permanent census outage');
          } else child.kill('SIGKILL');
        } catch (err) {
          if (err.code !== 'ENOENT') {
            streamFailure = err;
            clearInterval(crashTimer);
            this.ownership.fail(`observer failed: ${redactSecrets(String(err.message))}`);
          }
        }
      }, 100);
    }
    const forward = signal => { if (child.exitCode === null) child.kill(signal); };
    const onInt = () => forward('SIGINT'), onTerm = () => forward('SIGTERM');
    process.on('SIGINT', onInt); process.on('SIGTERM', onTerm);
    let code = null, signal = null;
    const exited = new Promise(resolve => {
      child.once('error', error => resolve({ code: null, signal: null, error }));
      child.once('exit', (code, signal) => resolve({ code, signal }));
    });
    try {
      // A failed observer starts recovery immediately, without waiting for
      // the controller to request resolution or release its pipe writers.
      let status = await Promise.race([exited, failed.then(() => null)]);
      if (!status) {
        try { status = await beforeDeadline(exited, shutdownDeadline, 'controller exit'); }
        catch (err) { onStreamFailure(err); status = { code: null, signal: null, error: err }; }
      }
      ({ code, signal } = status);
      this.controllerSignal = signal;
      if (status.error || signal) this.ownership.fail(`controller ${status.error ? `error: ${status.error.message}` : `terminated by ${signal}`}`);
      this.stopping = true;
      startRecovery();
      const settle = async (promise, label) => {
        try { return await beforeDeadline(promise, shutdownDeadline, label); }
        catch (err) {
          this.failedVerifications++;
          if (!streamFailure) streamFailure = err;
          this.ownership.fail(`${label} failed: ${redactSecrets(String(err.message))}`);
          return null;
        }
      };
      let result = await settle(recoveryPromise, 'ownership recovery');
      await settle(requestEnd, 'controller IPC EOF');
      await settle(requestChain, 'controller request drain');
      // A rejected recovery must not prevent a further attempt to reclaim
      // committed identities within the remaining shutdown budget.
      if (!result) result = await settle(this.ownership.recover(), 'final ownership recovery');
      this.ownershipRecovery = result || {
        proof_resolved: false, taint_reasons: ['recovery result unavailable'], grace_sec: graceSec,
        recovery: { terminated: [], absent: [], replaced: [], unverifiable: [],
          survivors: [...this.ownership.stages.values()].flatMap(stage => [...stage.owned.values()].map(identity => this.ownership.entry(identity))) },
      };
      if (this.ownership.failure) {
        this.ownershipRecovery.proof_resolved = false;
        this.ownershipRecovery.taint_reasons = [...this.ownership.taintReasons];
      }
      if (crashObserved) this.ownershipRecovery.observed_pids = crashObserved;
      if (!this.ownershipRecovery.proof_resolved) this.failedVerifications++;
      try {
        this.ownership.persistReport({ controller: { code, signal }, result: this.ownershipRecovery, entries: this.entries });
        if (this.ownership.failure) {
          this.ownershipRecovery.proof_resolved = false;
          this.ownershipRecovery.taint_reasons = [...this.ownership.taintReasons];
          this.failedVerifications++;
        }
        this.saveIndex(code);
      } catch (err) {
        this.failedVerifications++;
        this.ownership.fail(`failure report persistence failed: ${redactSecrets(String(err.message))}`);
      }
    } finally {
      clearInterval(crashTimer);
      clearTimeout(crashDeadline);
      clearTimeout(controllerStopTimer);
      process.removeListener('SIGINT', onInt); process.removeListener('SIGTERM', onTerm);
      this.ownership.close();
    }
    if (streamFailure) this.failedVerifications++;
    let outcome = code === 5 || code === 77 ? 'REFUSED' : 'FAIL';
    if (code === 0 && this.failedVerifications === 0 && !this.ownership.failure && this.ownershipRecovery?.proof_resolved === true) {
      const terminal = this.entries.filter(e => e.request.snapshot_kind === 'terminal-envelope' && e.ack.verified);
      try {
        const completion = JSON.parse(execFileSync(this.pythonPath, [path.join(ACTION_SRC, 'seal_copy.py'), '--read-completion', this.artifactsDir], { encoding: 'utf8', maxBuffer: 4 * 1024 * 1024, timeout: 5000, env: sanitizeEnvironment(this.parentEnv) }));
        if (terminal.length === 1 && completion.overall_status === 'PASS' &&
            completion.invocation_id === this.context.invocation_id &&
            completion.chain_id === terminal[0].request.chain_id &&
            completion.terminal_receipt &&
            Object.keys(terminal[0].ack).every(key => completion.terminal_receipt[key] === terminal[0].ack[key]) &&
            Object.keys(completion.terminal_receipt).length === Object.keys(terminal[0].ack).length) outcome = 'PASS';
      } catch { /* missing or invalid completion is failure */ }
    }
    return { exitCode: code, signal, outcome, envelopePath: this.indexPath, receiptIndexPath: this.indexPath, totalRequests: this.entries.length, failedVerifications: this.failedVerifications };
  }
}
