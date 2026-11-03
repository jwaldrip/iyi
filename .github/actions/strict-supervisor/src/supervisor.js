import { spawn, execFileSync } from 'node:child_process';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { sanitizeEnvironment, redactSecrets } from './env.js';
import { IMMUTABLE_BINDING_FIELDS, validateRequest, writeIpcAck, createIpcReader } from './ipc.js';
import { uploadAndVerifyPayload } from './artifact-adapter.js';
import { OwnershipObserver } from './ownership.js';

const ACTION_SRC = path.resolve('.github/actions/strict-supervisor/src');
const CONTEXT_FIELDS = ['invocation_id', 'execution_kind', 'repository', 'run_id', 'run_attempt', 'job_id', 'job_key', 'p_sha', 'w_sha', 'c_sha', 'fixture_sha256'];
const EMITTER_DIGEST = `import ast,hashlib,sys\nt=ast.parse(open(sys.argv[1],encoding='utf8').read())\nx=[n.value for n in t.body if isinstance(n,ast.Assign) and any(isinstance(a,ast.Name) and a.id=='FAKE_STAGE_EMITTER_SOURCE' for a in n.targets)]\nassert len(x)==1\ns=ast.literal_eval(x[0]); assert isinstance(s,str)\nprint(hashlib.sha256(s.encode('utf8')).hexdigest())`;

function sha(dir) {
  return execFileSync('git', ['-C', dir, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
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
    const fixture = this.mode === 'validation-only' ? execFileSync(this.pythonPath, ['-c', EMITTER_DIGEST, path.resolve('proof/remote_strict_fixtures.py')], { encoding: 'utf8' }).trim() : null;
    return Object.freeze({ invocation_id: this.invocationId, execution_kind: this.mode === 'validation-only' ? 'synthetic' : 'strict', repository: env.GITHUB_REPOSITORY, run_id: env.GITHUB_RUN_ID, run_attempt: env.GITHUB_RUN_ATTEMPT, job_id: String(this.jobId), job_key: this.jobKey, p_sha: pSha, w_sha: wSha, c_sha: cSha, fixture_sha256: fixture });
  }
  buildChildArgs() {
    const script = this.mode === 'validation-only' ? 'proof/remote_strict_validation.py' : 'proof/remote_strict_controller.py';
    const args = [script, '--p', this.p, '--w', this.w, '--compiler', this.compiler, '--artifacts-dir', this.artifactsDir,
      '--job-start-time', String(this.jobStartTime), '--host-job-limit-sec', String(this.hostJobLimitSec || '21600'), '--payload-budget-sec', String(this.payloadBudgetSec || '19800'), '--finalization-alloc-sec', String(this.finalizationAllocSec || '1800'), '--driver-limit-sec', String(this.driverLimitSec || '2100'), '--grace-sec', String(this.graceSec || '30'), '--min-disk-gib', String(this.minDiskGib || '20.0'), '--ipc-req-fd', '3', '--ipc-ack-fd', '4', '--p-sha', this.context.p_sha, '--w-sha', this.context.w_sha, '--c-sha', this.context.c_sha, '--invocation-id', this.context.invocation_id, '--job-id', this.context.job_id, '--job-key', this.context.job_key];
    if (this.mode === 'validation-only') {
      if (!['success', 'failed-plan', 'failed-pin', 'divergence', 'cleanup-failure'].includes(this.validationCase) || !this.caseDataDir) throw new Error('invalid validation case');
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
        if (req.event === 'ownership-register') this.ownership.register(req, this.childProcess.pid);
        else await this.ownership.resolve(req);
        ack = { ...req, event: `${req.event}-ack`, verified: true };
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
          execFileSync(this.pythonPath, [path.join(ACTION_SRC, 'seal_copy.py'), this.artifactsDir, req.archive_path, copy, String(req.archive_bytes), req.archive_sha256], { timeout: 30000 });
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
      ack = { ...req, event: `${req?.event || 'invalid'}-ack`, verified: false, error: redactSecrets(String(err.message)) };
    }
    await writeIpcAck(ackStream, ack);
  }
  saveIndex(exitCode) {
    const data = JSON.stringify({ invocation_id: this.context.invocation_id, execution_kind: this.context.execution_kind, exit_code: exitCode, entries: this.entries }, null, 2) + '\n';
    const fd = fs.openSync(this.indexPath, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_TRUNC | fs.constants.O_NOFOLLOW, 0o600);
    try { fs.writeFileSync(fd, data); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  }
  async run() {
    this.context = await this.establishContext();
    this.indexPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'strict-index-')), 'receipt-index.json');
    this.saveIndex(null);
    this.ownership = new OwnershipObserver(this.pythonPath, path.join(ACTION_SRC, 'process_identity.py'));
    const childArgs = this.buildChildArgs();
    const child = spawn(this.pythonPath, childArgs, { stdio: ['inherit', 'inherit', 'inherit', 'pipe', 'pipe'], env: sanitizeEnvironment(this.parentEnv) });
    this.childProcess = child;
    let requestChain = Promise.resolve();
    let streamFailure = null;
    child.stdio[3].on('error', e => { streamFailure = e; });
    child.stdio[4].on('error', e => { streamFailure = e; });
    createIpcReader(child.stdio[3], req => { requestChain = requestChain.then(() => this.handleRequest(req, child.stdio[4])); });
    const forward = signal => { if (child.exitCode === null) child.kill(signal); };
    const onInt = () => forward('SIGINT'), onTerm = () => forward('SIGTERM');
    process.on('SIGINT', onInt); process.on('SIGTERM', onTerm);
    let code, signal;
    try {
      ({ code, signal } = await new Promise((resolve, reject) => { child.once('error', reject); child.once('exit', (code, signal) => resolve({code, signal})); }));
      try { await requestChain; await this.ownership.recover(); } catch (e) { this.failedVerifications++; streamFailure = e; }
    } finally {
      process.removeListener('SIGINT', onInt); process.removeListener('SIGTERM', onTerm);
      this.ownership.close();
    }
    if (streamFailure) this.failedVerifications++;
    let outcome = code === 5 || code === 77 ? 'REFUSED' : 'FAIL';
    if (code === 0 && this.failedVerifications === 0) {
      const terminal = this.entries.filter(e => e.request.snapshot_kind === 'terminal-envelope' && e.ack.verified);
      try {
        const completion = JSON.parse(fs.readFileSync(path.join(this.artifactsDir, 'controller-completion.json'), 'utf8'));
        if (terminal.length === 1 && completion.overall_status === 'PASS' && completion.invocation_id === this.context.invocation_id && JSON.stringify(completion.terminal_receipt) === JSON.stringify(terminal[0].ack)) outcome = 'PASS';
      } catch { /* missing or invalid completion is failure */ }
    }
    this.saveIndex(code);
    return { exitCode: code, signal, outcome, envelopePath: this.indexPath, receiptIndexPath: this.indexPath, totalRequests: this.entries.length, failedVerifications: this.failedVerifications };
  }
}
