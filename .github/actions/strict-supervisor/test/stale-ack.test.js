/**
 * Test: Stale & Mismatched ACK Rejection
 *
 * Verifies that ACKs with mismatched identifiers (stale request_id, mismatched
 * chain_id, unit, attempt, sequence, hash, or byte count) or verified=false
 * are strictly detected and rejected.
 */

import test from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { validateAck, validateRequest } from '../src/ipc.js';
import { StrictSupervisor } from '../src/supervisor.js';

const baseReq = {
  request_id: 'req-origin-101',
  repository: 'jwaldrip/iyi',
  run_id: '1234',
  run_attempt: '1',
  job_id: 'job-main',
  p_sha: '626463375298d357ffcb3223059f4d3adce6fb10',
  w_sha: 'b932ce0d97775c7061102a13db706f507dc84117',
  c_sha: '34ae13f8f8d82be5b2c9597a9df79eae5b6f7243',
  chain_id: 'chain-12345678',
  unit: 'stage_acme',
  native_attempt: 1,
  snapshot_sequence: 2,
  archive_path: '/tmp/test.tar',
  archive_bytes: 4096,
  archive_sha256: 'a'.repeat(64),
};

const validAck = {
  request_id: 'req-origin-101',
  repository: 'jwaldrip/iyi',
  run_id: '1234',
  run_attempt: '1',
  job_id: 'job-main',
  p_sha: '626463375298d357ffcb3223059f4d3adce6fb10',
  w_sha: 'b932ce0d97775c7061102a13db706f507dc84117',
  c_sha: '34ae13f8f8d82be5b2c9597a9df79eae5b6f7243',
  chain_id: 'chain-12345678',
  unit: 'stage_acme',
  native_attempt: 1,
  snapshot_sequence: 2,
  artifact_id: 12345,
  downloaded_sha256: 'a'.repeat(64),
  downloaded_bytes: 4096,
  verified: true,
  error: null,
};

test('Valid matching ACK passes validation', () => {
  const result = validateAck(validAck, baseReq);
  assert.strictEqual(result.valid, true);
});

test('Stale request_id in ACK is rejected', () => {
  const staleAck = { ...validAck, request_id: 'req-old-099' };
  const result = validateAck(staleAck, baseReq);
  assert.strictEqual(result.valid, false);
  assert.match(result.reason, /Mismatched binding field request_id/);
});

test('Mismatched chain_id in ACK is rejected', () => {
  const wrongChainAck = { ...validAck, chain_id: 'other-chain-999' };
  const result = validateAck(wrongChainAck, baseReq);
  assert.strictEqual(result.valid, false);
  assert.match(result.reason, /Mismatched binding field chain_id/);
});

test('Mismatched unit in ACK is rejected', () => {
  const wrongUnitAck = { ...validAck, unit: 'stage_other' };
  const result = validateAck(wrongUnitAck, baseReq);
  assert.strictEqual(result.valid, false);
  assert.match(result.reason, /Mismatched binding field unit/);
});

test('Mismatched snapshot_sequence in ACK is rejected', () => {
  const wrongSeqAck = { ...validAck, snapshot_sequence: 1 };
  const result = validateAck(wrongSeqAck, baseReq);
  assert.strictEqual(result.valid, false);
  assert.match(result.reason, /Mismatched binding field snapshot_sequence/);
});

test('Mismatched SHA256 in ACK is rejected', () => {
  const wrongShaAck = { ...validAck, downloaded_sha256: 'b'.repeat(64) };
  const result = validateAck(wrongShaAck, baseReq);
  assert.strictEqual(result.valid, false);
  assert.match(result.reason, /SHA256 mismatch/);
});

test('Mismatched byte count in ACK is rejected', () => {
  const wrongBytesAck = { ...validAck, downloaded_bytes: 4095 };
  const result = validateAck(wrongBytesAck, baseReq);
  assert.strictEqual(result.valid, false);
  assert.match(result.reason, /Byte count mismatch/);
});

test('ACK with verified=false is rejected', () => {
  const unverifiedAck = { ...validAck, verified: false, error: 'Upload failed' };
  const result = validateAck(unverifiedAck, baseReq);
  assert.strictEqual(result.valid, false);
  assert.match(result.reason, /Upload failed/);
});

test('ACK missing artifact_id is rejected', () => {
  const noIdAck = { ...validAck, artifact_id: null };
  const result = validateAck(noIdAck, baseReq);
  assert.strictEqual(result.valid, false);
  assert.match(result.reason, /missing valid artifact_id/);
});

test('validateRequest enforces non-empty fields, positive bytes, and valid sha256', () => {
  assert.strictEqual(validateRequest(baseReq).valid, true);

  const missingUnit = { ...baseReq, unit: '' };
  assert.strictEqual(validateRequest(missingUnit).valid, false);

  const negativeBytes = { ...baseReq, archive_bytes: -10 };
  assert.strictEqual(validateRequest(negativeBytes).valid, false);

  const invalidSha = { ...baseReq, archive_sha256: 'not-a-valid-sha' };
  assert.strictEqual(validateRequest(invalidSha).valid, false);
});

test('Supervisor returns negative ACK on missing local archive file', async () => {
  const supervisor = new StrictSupervisor({
    p: '/dummy/p',
    w: '/dummy/w',
    compiler: '/dummy/bin',
    jobStartTime: '2026-11-01T00:00:00Z',
  });

  const acksSent = [];
  const fakeAckStream = {
    destroyed: false,
    write: (line, enc, cb) => {
      acksSent.push(JSON.parse(line.trim()));
      cb();
    },
  };

  const reqNonExistent = {
    ...baseReq,
    archive_path: '/nonexistent/file_that_does_not_exist.tar',
  };

  await supervisor.handleRequest(reqNonExistent, fakeAckStream);

  assert.strictEqual(acksSent.length, 1);
  assert.strictEqual(acksSent[0].verified, false);
  assert.match(acksSent[0].error, /does not exist/);
  assert.strictEqual(supervisor.failedVerifications, 1);
});
