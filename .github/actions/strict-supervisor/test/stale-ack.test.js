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

test('Pre-pin plan snapshot with typed chain_id: null passes validateRequest', () => {
  const planReq = { ...baseReq, unit: 'plan', chain_id: null, snapshot_sequence: 1 };
  const result = validateRequest(planReq);
  assert.strictEqual(result.valid, true);
});

test('Pre-pin plan snapshot with string chain_id is rejected by validateRequest', () => {
  const planWithStr = { ...baseReq, unit: 'plan', chain_id: 'forged-chain-1234', snapshot_sequence: 1 };
  const result = validateRequest(planWithStr);
  assert.strictEqual(result.valid, false);
  assert.match(result.error, /Unit 'plan' requires typed chain_id: null/);
});

test('Pre-pin plan snapshot with sentinel forge chain_id is rejected by validateRequest', () => {
  const planWithSentinel = { ...baseReq, unit: 'plan', chain_id: 'nochain', snapshot_sequence: 1 };
  const result = validateRequest(planWithSentinel);
  assert.strictEqual(result.valid, false);
  assert.match(result.error, /Unit 'plan' requires typed chain_id: null/);
});

test('Pre-pin plan snapshot with empty string chain_id is rejected by validateRequest', () => {
  const planWithEmpty = { ...baseReq, unit: 'plan', chain_id: '', snapshot_sequence: 1 };
  const result = validateRequest(planWithEmpty);
  assert.strictEqual(result.valid, false);
  assert.match(result.error, /Unit 'plan' requires typed chain_id: null/);
});

test('Post-pin unit with chain_id: null is rejected by validateRequest', () => {
  const postPinNull = { ...baseReq, unit: 'pin', chain_id: null };
  const result = validateRequest(postPinNull);
  assert.strictEqual(result.valid, false);
  assert.match(result.error, /chain_id: null accepted only for unit plan/);
});

test('Post-pin unit with absent or empty chain_id is rejected by validateRequest', () => {
  const postPinEmpty = { ...baseReq, unit: 'pin', chain_id: '' };
  const resultEmpty = validateRequest(postPinEmpty);
  assert.strictEqual(resultEmpty.valid, false);
  assert.match(resultEmpty.error, /Missing required immutable field: chain_id/);

  const postPinAbsent = { ...baseReq, unit: 'pin' };
  delete postPinAbsent.chain_id;
  const resultAbsent = validateRequest(postPinAbsent);
  assert.strictEqual(resultAbsent.valid, false);
  assert.match(resultAbsent.error, /Missing required immutable field: chain_id/);
});

test('Post-pin unit with sentinel forge chain_id is rejected by validateRequest', () => {
  const postPinNochain = { ...baseReq, unit: 'pin', chain_id: 'nochain' };
  const result = validateRequest(postPinNochain);
  assert.strictEqual(result.valid, false);
  assert.match(result.error, /sentinel forge 'nochain' is forbidden/);

  const postPinNullStr = { ...baseReq, unit: 'pin', chain_id: 'null' };
  const resultNullStr = validateRequest(postPinNullStr);
  assert.strictEqual(resultNullStr.valid, false);
  assert.match(resultNullStr.error, /sentinel forge 'null' is forbidden/);
});

test('Valid matching ACK for pre-pin plan with chain_id: null passes validateAck', () => {
  const planReq = { ...baseReq, unit: 'plan', chain_id: null, snapshot_sequence: 1 };
  const planAck = { ...validAck, unit: 'plan', chain_id: null, snapshot_sequence: 1 };
  const result = validateAck(planAck, planReq);
  assert.strictEqual(result.valid, true);
});

test('Pre-pin plan ACK echoing string chain_id (expected null) is rejected by validateAck', () => {
  const planReq = { ...baseReq, unit: 'plan', chain_id: null, snapshot_sequence: 1 };
  const planAckStr = { ...validAck, unit: 'plan', chain_id: 'forged-string-chain', snapshot_sequence: 1 };
  const result = validateAck(planAckStr, planReq);
  assert.strictEqual(result.valid, false);
  assert.match(result.reason, /Mismatched binding field chain_id: expected null/);
});

test('Post-pin unit ACK echoing chain_id: null (expected string) is rejected by validateAck', () => {
  const postPinAckNull = { ...validAck, chain_id: null };
  const result = validateAck(postPinAckNull, baseReq);
  assert.strictEqual(result.valid, false);
  assert.match(result.reason, /Mismatched binding field chain_id: expected chain-12345678, got null/);
});

test('Supervisor rejects duplicate request_id replay with negative ACK', async () => {
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

  // First attempt fails at upload because file does not exist, but is validated and registered
  const req1 = { ...baseReq, request_id: 'replay-req-1', snapshot_sequence: 1, archive_path: '/nonexistent/a.tar' };
  await supervisor.handleRequest(req1, fakeAckStream);
  assert.strictEqual(acksSent.length, 1);
  assert.match(acksSent[0].error, /does not exist/);

  // Replaying the exact same request_id
  const replayReq = { ...baseReq, request_id: 'replay-req-1', snapshot_sequence: 2, archive_path: '/nonexistent/b.tar' };
  await supervisor.handleRequest(replayReq, fakeAckStream);
  assert.strictEqual(acksSent.length, 2);
  assert.strictEqual(acksSent[1].verified, false);
  assert.match(acksSent[1].error, /Duplicate or replay request rejected: request_id 'replay-req-1'/);
});

test('Supervisor rejects duplicate or non-increasing snapshot_sequence with negative ACK', async () => {
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

  const reqSeq2 = { ...baseReq, request_id: 'req-seq-2', snapshot_sequence: 2, archive_path: '/nonexistent/a.tar' };
  await supervisor.handleRequest(reqSeq2, fakeAckStream);

  // Sending lower snapshot_sequence
  const reqSeq1 = { ...baseReq, request_id: 'req-seq-1', snapshot_sequence: 1, archive_path: '/nonexistent/b.tar' };
  await supervisor.handleRequest(reqSeq1, fakeAckStream);
  assert.strictEqual(acksSent.length, 2);
  assert.strictEqual(acksSent[1].verified, false);
  assert.match(acksSent[1].error, /Duplicate or non-increasing snapshot_sequence rejected/);

  // Sending identical snapshot_sequence
  const reqSeq2Dup = { ...baseReq, request_id: 'req-seq-2-dup', snapshot_sequence: 2, archive_path: '/nonexistent/c.tar' };
  await supervisor.handleRequest(reqSeq2Dup, fakeAckStream);
  assert.strictEqual(acksSent.length, 3);
  assert.strictEqual(acksSent[2].verified, false);
  assert.match(acksSent[2].error, /Duplicate or non-increasing snapshot_sequence rejected/);
});
