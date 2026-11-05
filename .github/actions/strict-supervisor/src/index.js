/**
 * Entrypoint for strict-supervisor GitHub Action
 *
 * Runs on Node 24 runtime (`runs.using: node24`).
 * Encapsulates credentials, sets up fd3/fd4 IPC pipes, and coordinates
 * incremental artifact upload/readback verification with Python C.
 */

import fs from 'node:fs';
import { StrictSupervisor } from './supervisor.js';

async function resolveCore() {
  try {
    return await import('@actions/core');
  } catch {
    return {
      getInput: (name, options) => {
        const envKey = `INPUT_${name.replace(/ /g, '_').toUpperCase()}`;
        const val = process.env[envKey] || '';
        if (options?.required && !val) {
          throw new Error(`Input required and not supplied: ${name}`);
        }
        return val;
      },
      setOutput: (name, value) => {
        const outputFile = process.env.GITHUB_OUTPUT;
        if (outputFile) {
          fs.appendFileSync(outputFile, `${name}=${value}\n`);
        }
      },
      setFailed: (message) => {
        process.exitCode = 1;
        console.error(`::error::${message}`);
      },
      info: (msg) => console.log(msg),
      warning: (msg) => console.warn(`::warning::${msg}`),
      error: (msg) => console.error(`::error::${msg}`),
    };
  }
}

export async function runAction() {
  const core = await resolveCore();

  try {
    const p = core.getInput('p', { required: true });
    const w = core.getInput('w', { required: true });
    const compiler = core.getInput('compiler', { required: true });
    const artifactsDir = core.getInput('artifacts_dir') || 'strict-proof-artifacts';
    const jobStartTime = core.getInput('job_start_time', { required: true });
    const hostJobLimitSec = core.getInput('host_job_limit_sec') || '21600';
    const payloadBudgetSec = core.getInput('payload_budget_sec') || '19800';
    const finalizationAllocSec = core.getInput('finalization_alloc_sec') || '1800';
    const driverLimitSec = core.getInput('driver_limit_sec') || '2100';
    const graceSec = core.getInput('grace_sec') || '30';
    const minDiskGib = core.getInput('min_disk_gib') || '20.0';
    const pSha = core.getInput('p_sha') || null;
    const wSha = core.getInput('w_sha') || null;
    const cSha = core.getInput('c_sha') || null;
    const mode = core.getInput('mode') || 'strict';
    const pythonPath = core.getInput('python_path') || 'python3';
    const invocationId = core.getInput('invocation_id', { required: true });
    const jobId = core.getInput('job_id', { required: true });
    const jobKey = core.getInput('job_key', { required: true });
    const validationCase = core.getInput('validation_case');
    const caseDataDir = core.getInput('case_data_dir');

    core.info('================================================================================');
    core.info('LAUNCHING STRICT SUPERVISOR (Node24)');
    core.info(`Mode: ${mode}`);
    core.info(`Job Start Anchor: ${jobStartTime}`);
    core.info(`Driver Limit: ${driverLimitSec}s + Grace: ${graceSec}s`);
    core.info('================================================================================');

    const supervisor = new StrictSupervisor({
      p,
      w,
      compiler,
      artifactsDir,
      jobStartTime,
      hostJobLimitSec,
      payloadBudgetSec,
      finalizationAllocSec,
      driverLimitSec,
      graceSec,
      minDiskGib,
      pSha,
      wSha,
      cSha,
      mode,
      pythonPath,
      invocationId, jobId, jobKey, validationCase, caseDataDir,
    });

    const result = await supervisor.run();

    core.setOutput('outcome', result.outcome);
    if (result.envelopePath) {
      core.setOutput('envelope_path', result.envelopePath);
      core.setOutput('receipt_index_path', result.receiptIndexPath);
    }

    if (result.exitCode !== 0 || result.failedVerifications > 0 || result.outcome !== 'PASS') {
      const errDetail = `Controller exited with code ${result.exitCode}` +
        (result.failedVerifications > 0 ? ` (${result.failedVerifications} unverified persistence requests)` : '');
      core.setFailed(errDetail);
      process.exitCode = result.exitCode || 1;
      return;
    }

    core.info(`Strict supervisor completed successfully: outcome=${result.outcome}`);
  } catch (err) {
    core.setFailed(`Strict supervisor execution failure: ${err.message}`);
    process.exitCode = 1;
  }
}

