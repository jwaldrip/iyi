/**
 * Strict Supervisor
 *
 * Runs as the parent Node24 process in GitHub Actions:
 * 1. Sanitizes child environment (strips tokens, results URLs, secrets).
 * 2. Spawns Python C with dedicated extra file descriptors:
 *    - fd3: Request pipe (child -> supervisor)
 *    - fd4: Ack pipe (supervisor -> child)
 * 3. Handles incremental archive uploads via @actions/artifact 6.3.1.
 * 4. Downloads by exact ID, validates inner payload bytes & SHA-256 before ACK.
 * 5. Disallows stdout protocol control and raw credential exposure.
 */

import { spawn } from 'node:child_process';
import path from 'node:path';
import fs from 'node:fs';
import { sanitizeEnvironment, redactSecrets } from './env.js';
import { validateRequest, writeIpcAck, createIpcReader } from './ipc.js';
import { uploadAndVerifyPayload } from './artifact-adapter.js';

export class StrictSupervisor {
  constructor(options = {}) {
    this.p = options.p;
    this.w = options.w;
    this.compiler = options.compiler;
    this.artifactsDir = options.artifactsDir || 'strict-proof-artifacts';
    this.jobStartTime = options.jobStartTime;
    this.hostJobLimitSec = options.hostJobLimitSec || '21600';
    this.payloadBudgetSec = options.payloadBudgetSec || '19800';
    this.finalizationAllocSec = options.finalizationAllocSec || '1800';
    this.driverLimitSec = options.driverLimitSec || '2100';
    this.graceSec = options.graceSec || '30';
    this.minDiskGib = options.minDiskGib || '20.0';
    this.pSha = options.pSha;
    this.wSha = options.wSha;
    this.cSha = options.cSha;
    this.mode = options.mode || 'strict';
    this.pythonPath = options.pythonPath || 'python3';
    this.controllerPath = options.controllerPath || 'proof/remote_strict_controller.py';
    this.artifactClient = options.artifactClient || null;
    this.parentEnv = options.parentEnv || process.env;

    this.requests = [];
    this.acks = [];
    this.failedVerifications = 0;
    this.childProcess = null;
    this.childExitCode = null;
    this.childSignal = null;
  }

  async resolveArtifactClient() {
    if (this.artifactClient) {
      return this.artifactClient;
    }
    try {
      const artifactModule = await import('@actions/artifact');
      this.artifactClient = new artifactModule.DefaultArtifactClient();
      return this.artifactClient;
    } catch (err) {
      throw new Error(`Failed to load @actions/artifact: ${err.message}`);
    }
  }

  buildChildArgs() {
    const args = [
      this.controllerPath,
      '--p', this.p,
      '--w', this.w,
      '--compiler', this.compiler,
      '--artifacts-dir', this.artifactsDir,
      '--job-start-time', this.jobStartTime,
      '--host-job-limit-sec', String(this.hostJobLimitSec),
      '--payload-budget-sec', String(this.payloadBudgetSec),
      '--finalization-alloc-sec', String(this.finalizationAllocSec),
      '--driver-limit-sec', String(this.driverLimitSec),
      '--grace-sec', String(this.graceSec),
      '--min-disk-gib', String(this.minDiskGib),
      '--ipc-req-fd', '3',
      '--ipc-ack-fd', '4',
    ];

    if (this.pSha) args.push('--p-sha', this.pSha);
    if (this.wSha) args.push('--w-sha', this.wSha);
    if (this.cSha) args.push('--c-sha', this.cSha);
    if (this.mode) args.push('--mode', this.mode);

    return args;
  }

  async handleRequest(rawReq, ackStream) {
    this.requests.push(rawReq);

    const validation = validateRequest(rawReq);
    if (!validation.valid) {
      this.failedVerifications++;
      const negativeAck = {
        request_id: rawReq?.request_id || 'unknown',
        repository: rawReq?.repository || '',
        run_id: rawReq?.run_id || '',
        run_attempt: rawReq?.run_attempt || '',
        job_id: rawReq?.job_id || '',
        p_sha: rawReq?.p_sha || '',
        w_sha: rawReq?.w_sha || '',
        c_sha: rawReq?.c_sha || '',
        chain_id: rawReq?.chain_id || '',
        unit: rawReq?.unit || '',
        native_attempt: rawReq?.native_attempt || 0,
        snapshot_sequence: rawReq?.snapshot_sequence || 0,
        artifact_id: null,
        downloaded_sha256: null,
        downloaded_bytes: null,
        verified: false,
        error: `Supervisor request validation rejected: ${validation.error}`,
      };
      this.acks.push(negativeAck);
      await writeIpcAck(ackStream, negativeAck);
      return;
    }

    try {
      const client = await this.resolveArtifactClient();
      const receipt = await uploadAndVerifyPayload(rawReq, client);

      if (!receipt.verified) {
        this.failedVerifications++;
      }

      const ack = {
        request_id: rawReq.request_id,
        repository: rawReq.repository,
        run_id: rawReq.run_id,
        run_attempt: rawReq.run_attempt,
        job_id: rawReq.job_id,
        p_sha: rawReq.p_sha,
        w_sha: rawReq.w_sha,
        c_sha: rawReq.c_sha,
        chain_id: rawReq.chain_id,
        unit: rawReq.unit,
        native_attempt: rawReq.native_attempt,
        snapshot_sequence: rawReq.snapshot_sequence,
        artifact_id: receipt.artifact_id,
        downloaded_sha256: receipt.downloaded_sha256,
        downloaded_bytes: receipt.downloaded_bytes,
        verified: receipt.verified,
        error: receipt.error,
      };

      this.acks.push(ack);
      await writeIpcAck(ackStream, ack);
    } catch (err) {
      this.failedVerifications++;
      const errorAck = {
        request_id: rawReq.request_id,
        repository: rawReq.repository,
        run_id: rawReq.run_id,
        run_attempt: rawReq.run_attempt,
        job_id: rawReq.job_id,
        p_sha: rawReq.p_sha,
        w_sha: rawReq.w_sha,
        c_sha: rawReq.c_sha,
        chain_id: rawReq.chain_id,
        unit: rawReq.unit,
        native_attempt: rawReq.native_attempt,
        snapshot_sequence: rawReq.snapshot_sequence,
        artifact_id: null,
        downloaded_sha256: null,
        downloaded_bytes: null,
        verified: false,
        error: `Unexpected supervisor error during upload/verify: ${redactSecrets(err.message)}`,
      };
      this.acks.push(errorAck);
      await writeIpcAck(ackStream, errorAck);
    }
  }

  async run() {
    const sanitizedEnv = sanitizeEnvironment(this.parentEnv);
    const childArgs = this.buildChildArgs();

    return new Promise((resolve, reject) => {
      // Spawn child with dedicated fd3 (read from child) and fd4 (write to child)
      // stdio[0]=stdin, stdio[1]=stdout, stdio[2]=stderr, stdio[3]=pipe, stdio[4]=pipe
      let child;
      try {
        child = spawn(this.pythonPath, childArgs, {
          stdio: ['inherit', 'inherit', 'inherit', 'pipe', 'pipe'],
          env: sanitizedEnv,
        });
      } catch (err) {
        return reject(new Error(`Failed to spawn controller process: ${err.message}`));
      }

      this.childProcess = child;

      // Handle termination signals cleanly
      const forwardSignal = (sig) => {
        if (child && !child.killed) {
          try {
            child.kill(sig);
          } catch {
            // Process may already be dead
          }
        }
      };

      const sigintHandler = () => forwardSignal('SIGINT');
      const sigtermHandler = () => forwardSignal('SIGTERM');

      process.on('SIGINT', sigintHandler);
      process.on('SIGTERM', sigtermHandler);

      let requestChain = Promise.resolve();

      const reqStream = child.stdio[3];
      const ackStream = child.stdio[4];

      createIpcReader(reqStream, (req) => {
        requestChain = requestChain.then(() => this.handleRequest(req, ackStream));
      });

      child.on('error', (err) => {
        cleanupListeners();
        reject(err);
      });

      child.on('close', async (code, signal) => {
        cleanupListeners();
        this.childExitCode = code;
        this.childSignal = signal;

        // Ensure all queued IPC requests have been handled and acknowledged
        try {
          await requestChain;
        } catch (err) {
          console.error(`Error draining supervisor request queue: ${err.message}`);
        }

        try {
          if (!ackStream.destroyed) ackStream.end();
        } catch {
          // Stream already closed
        }

        const envelopePath = path.join(this.artifactsDir, 'controller_envelope.json');
        let outcome = 'FAIL';
        if (code === 0 && this.failedVerifications === 0) {
          outcome = 'PASS';
        } else if (code === 77) {
          outcome = 'REFUSED';
        } else if (this.failedVerifications > 0) {
          outcome = 'UNVERIFIED_PERSISTENCE';
        }

        resolve({
          exitCode: code,
          signal,
          outcome,
          envelopePath: fs.existsSync(envelopePath) ? envelopePath : null,
          totalRequests: this.requests.length,
          failedVerifications: this.failedVerifications,
        });
      });

      function cleanupListeners() {
        process.removeListener('SIGINT', sigintHandler);
        process.removeListener('SIGTERM', sigtermHandler);
      }
    });
  }
}
