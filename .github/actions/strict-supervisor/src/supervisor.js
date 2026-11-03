/**
 * Strict Supervisor
 *
 * Runs as the parent Node24 process in GitHub Actions:
 * 1. Sanitizes child environment (strips tokens, results URLs, secrets).
 * 2. Spawns Python C with dedicated extra file descriptors:
 *    - fd3: Request pipe (child -> supervisor)
 *    - fd4: Ack pipe (supervisor -> child)
 * 3. Handles incremental archive uploads via @actions/artifact 6.3.1 with bounded timeouts.
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
    this.seenRequestIds = new Set();
    this.seenSequences = new Set();
    this.lastSnapshotSequence = 0;
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
      '--host-job-limit-sec', String(this.hostJobLimitSec),
      '--payload-budget-sec', String(this.payloadBudgetSec),
      '--finalization-alloc-sec', String(this.finalizationAllocSec),
      '--driver-limit-sec', String(this.driverLimitSec),
      '--grace-sec', String(this.graceSec),
      '--min-disk-gib', String(this.minDiskGib),
      '--ipc-req-fd', '3',
      '--ipc-ack-fd', '4',
    ];

    if (this.jobStartTime) {
      args.push('--job-start-time', String(this.jobStartTime));
    }
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
        chain_id: rawReq?.chain_id !== undefined ? rawReq.chain_id : null,
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
      try {
        await writeIpcAck(ackStream, negativeAck);
      } catch (err) {
        console.error(`Failed to write negative ACK: ${err.message}`);
      }
      return;
    }

    // Duplicate / replay prevention
    if (this.seenRequestIds.has(rawReq.request_id)) {
      this.failedVerifications++;
      const dupAck = {
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
        error: `Duplicate or replay request rejected: request_id '${rawReq.request_id}' has already been processed`,
      };
      this.acks.push(dupAck);
      try {
        await writeIpcAck(ackStream, dupAck);
      } catch (err) {
        console.error(`Failed to write duplicate ACK: ${err.message}`);
      }
      return;
    }

    if (this.seenSequences.has(rawReq.snapshot_sequence) || rawReq.snapshot_sequence <= this.lastSnapshotSequence) {
      this.failedVerifications++;
      const seqAck = {
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
        error: `Duplicate or non-increasing snapshot_sequence rejected: sequence ${rawReq.snapshot_sequence} (last seen: ${this.lastSnapshotSequence})`,
      };
      this.acks.push(seqAck);
      try {
        await writeIpcAck(ackStream, seqAck);
      } catch (err) {
        console.error(`Failed to write sequence ACK: ${err.message}`);
      }
      return;
    }

    this.seenRequestIds.add(rawReq.request_id);
    this.seenSequences.add(rawReq.snapshot_sequence);
    this.lastSnapshotSequence = rawReq.snapshot_sequence;

    try {
      const client = await this.resolveArtifactClient();
      const uploadPromise = uploadAndVerifyPayload(rawReq, client);
      const timeoutPromise = new Promise((_, rej) =>
        setTimeout(() => rej(new Error('uploadAndVerifyPayload timed out after 45s')), 45000)
      );
      const receipt = await Promise.race([uploadPromise, timeoutPromise]);

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
      try {
        await writeIpcAck(ackStream, errorAck);
      } catch (writeErr) {
        console.error(`Failed to write error ACK: ${writeErr.message}`);
      }
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

      reqStream.on('error', (err) => {
        console.error(`IPC reqStream error: ${err.message}`);
      });
      ackStream.on('error', (err) => {
        console.error(`IPC ackStream error: ${err.message}`);
      });

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

        // Bounded queue drain (maximum 15 seconds)
        try {
          const timeoutPromise = new Promise((_, rej) =>
            setTimeout(() => rej(new Error('Supervisor request queue drain timed out after 15s')), 15000)
          );
          await Promise.race([requestChain, timeoutPromise]);
        } catch (err) {
          console.error(`Error draining supervisor request queue: ${err.message}`);
          this.failedVerifications++;
        }

        try {
          if (!ackStream.destroyed) ackStream.end();
        } catch {
          // Stream already closed
        }

        let outcome = 'FAIL';
        if (code === 0 && this.failedVerifications === 0) {
          outcome = 'PASS';
        } else if (code === 5 || code === 77) {
          outcome = 'REFUSED';
        } else if (this.failedVerifications > 0) {
          outcome = 'UNVERIFIED_PERSISTENCE';
        }

        const envelopePath = path.join(this.artifactsDir, 'controller_envelope.json');
        if (!fs.existsSync(envelopePath)) {
          try {
            fs.mkdirSync(this.artifactsDir, { recursive: true });
            const fallbackEnvelope = {
              outcome,
              exit_code: code,
              signal,
              failed_verifications: this.failedVerifications,
              total_requests: this.requests.length,
              timestamp_iso: new Date().toISOString(),
            };
            fs.writeFileSync(envelopePath, JSON.stringify(fallbackEnvelope, null, 2) + '\n');
          } catch {
            // Ignore error writing fallback envelope
          }
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
