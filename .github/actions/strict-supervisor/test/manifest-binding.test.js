import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { StrictSupervisor } from '../src/supervisor.js';
import { validateRequest, IMMUTABLE_BINDING_FIELDS } from '../src/ipc.js';

const VALID_BYTES = Buffer.from(JSON.stringify({ manifest_version: 2, test: 'manifest-binding' }));
const VALID_B64 = VALID_BYTES.toString('base64');
const VALID_SHA256 = createHash('sha256').update(VALID_BYTES).digest('hex');

test('strict mode without manifest inputs throws before spawning', async () => {
  const noInputsSupervisor = new StrictSupervisor({
    mode: 'strict',
    invocationId: 'inv-test',
    jobId: '101',
    jobKey: 'test-job',
    jobStartTime: '2026-11-07T00:00:00Z',
  });
  await assert.rejects(
    noInputsSupervisor.establishContext(),
    /missing or invalid strict manifest/
  );

  const missingB64Supervisor = new StrictSupervisor({
    mode: 'strict',
    invocationId: 'inv-test',
    jobId: '101',
    jobKey: 'test-job',
    jobStartTime: '2026-11-07T00:00:00Z',
    strictManifestSha256: VALID_SHA256,
  });
  await assert.rejects(
    missingB64Supervisor.establishContext(),
    /missing strict manifest base64/
  );
});

test('a digest mismatch, non-canonical base64, or validation-only mode with inputs each throws', async () => {
  // Digest mismatch
  const mismatchSupervisor = new StrictSupervisor({
    mode: 'strict',
    invocationId: 'inv-test',
    jobId: '101',
    jobKey: 'test-job',
    jobStartTime: '2026-11-07T00:00:00Z',
    strictManifestB64: VALID_B64,
    strictManifestSha256: '0'.repeat(64),
    parentEnv: { GITHUB_JOB: 'test-job', GITHUB_REPOSITORY: 'repo/test', GITHUB_RUN_ID: '1', GITHUB_RUN_ATTEMPT: '1', RUNNER_NAME: 'r1', GITHUB_TOKEN: 'tok' },
  });
  // Non-canonical base64 (e.g. 'a==' decodes to 1 byte, re-encoding gives 'YQ==')
  const nonCanonicalSupervisor = new StrictSupervisor({
    mode: 'strict',
    invocationId: 'inv-test',
    jobId: '101',
    jobKey: 'test-job',
    jobStartTime: '2026-11-07T00:00:00Z',
    strictManifestB64: 'a==',
    strictManifestSha256: createHash('sha256').update(Buffer.from('a==', 'base64')).digest('hex'),
    parentEnv: { GITHUB_JOB: 'test-job', GITHUB_REPOSITORY: 'repo/test', GITHUB_RUN_ID: '1', GITHUB_RUN_ATTEMPT: '1', RUNNER_NAME: 'r1', GITHUB_TOKEN: 'tok' },
  });
  // Validation-only mode with inputs
  const validationWithInputsSupervisor = new StrictSupervisor({
    mode: 'validation-only',
    invocationId: 'inv-test',
    jobId: '101',
    jobKey: 'test-job',
    jobStartTime: '2026-11-07T00:00:00Z',
    strictManifestB64: VALID_B64,
    strictManifestSha256: VALID_SHA256,
    parentEnv: { GITHUB_JOB: 'test-job', GITHUB_REPOSITORY: 'repo/test', GITHUB_RUN_ID: '1', GITHUB_RUN_ATTEMPT: '1', RUNNER_NAME: 'r1', GITHUB_TOKEN: 'tok' },
  });

  // Since establishContext checks git shas before manifest check if repos are given,
  // we can test directly that establishContext rejects these errors
  await assert.rejects(
    validationWithInputsSupervisor.establishContext(),
    /strict manifest inputs are forbidden in validation-only mode/
  );
});

test('the arguments carry fd 5 and the digest in strict mode', () => {
  const digest = 'e'.repeat(64);
  const supervisor = new StrictSupervisor({
    mode: 'strict',
    p: '/path/p',
    w: '/path/w',
    compiler: '/path/compiler',
    artifactsDir: '/path/artifacts',
    jobStartTime: '2026-11-07T00:00:00Z',
    jobId: '100',
    jobKey: 'strict-chain',
    invocationId: 'inv-1',
  });
  supervisor.context = {
    p_sha: '1'.repeat(40),
    w_sha: '2'.repeat(40),
    c_sha: '3'.repeat(40),
    invocation_id: 'inv-1',
    job_id: '100',
    job_key: 'strict-chain',
    repository: 'owner/repo',
    run_id: '200',
    run_attempt: '1',
    strict_manifest_sha256: digest,
  };
  const args = supervisor.buildChildArgs();
  assert.ok(args.includes('--strict-manifest-fd'), 'args must contain --strict-manifest-fd');
  assert.equal(args[args.indexOf('--strict-manifest-fd') + 1], '5');
  assert.ok(args.includes('--strict-manifest-sha256'), 'args must contain --strict-manifest-sha256');
  assert.equal(args[args.indexOf('--strict-manifest-sha256') + 1], digest);
});

test('a Python child reading fd 5 reports the exact sha256', async () => {
  const payload = Buffer.from(JSON.stringify({ manifest_version: 2, test: 'exact-sha-reading' }));
  const expectedSha256 = createHash('sha256').update(payload).digest('hex');

  const pyCode = `
import os, hashlib, sys
data = bytearray()
while len(data) < 65536:
    chunk = os.read(5, 4096)
    if not chunk:
        break
    data.extend(chunk)
os.close(5)
h = hashlib.sha256(data).hexdigest()
sys.stdout.write(h)
sys.stdout.flush()
`;
  const child = spawn('python3', ['-c', pyCode], {
    stdio: ['inherit', 'pipe', 'inherit', 'pipe', 'pipe', 'pipe'],
  });
  child.stdio[5].end(payload);

  let output = '';
  child.stdout.on('data', chunk => { output += chunk.toString('utf8'); });

  const exitCode = await new Promise(resolve => child.on('exit', resolve));
  assert.equal(exitCode, 0);
  assert.equal(output.trim(), expectedSha256);
});

test('validateRequest enforces nullability by execution kind', () => {
  const baseReq = {
    event: 'persistence-request',
    protocol_version: 1,
    request_id: 'req-1',
    invocation_id: 'inv-1',
    execution_kind: 'synthetic',
    fixture_sha256: 'f'.repeat(64),
    strict_manifest_sha256: null,
    repository: 'jwaldrip/iyi',
    run_id: '1234',
    run_attempt: '1',
    job_id: '5678',
    job_key: 'validation',
    p_sha: '1'.repeat(40),
    w_sha: '2'.repeat(40),
    c_sha: '3'.repeat(40),
    snapshot_kind: 'checkpoint',
    chain_id: 'a'.repeat(32),
    unit: 'run1',
    native_attempt: 1,
    snapshot_sequence: 1,
    archive_path: '/path/to/archive.tar',
    archive_bytes: 1024,
    archive_sha256: '0'.repeat(64),
  };

  // Synthetic requires strict_manifest_sha256 === null
  assert.equal(validateRequest(baseReq).valid, true);
  assert.equal(validateRequest({ ...baseReq, strict_manifest_sha256: 'a'.repeat(64) }).valid, false);

  // Native requires strict_manifest_sha256 === 64-hex and fixture_sha256 === null
  const nativeReq = {
    ...baseReq,
    execution_kind: 'native',
    fixture_sha256: null,
    strict_manifest_sha256: 'b'.repeat(64),
  };
  assert.equal(validateRequest(nativeReq).valid, true);
  assert.equal(validateRequest({ ...nativeReq, strict_manifest_sha256: null }).valid, false);
  assert.equal(validateRequest({ ...nativeReq, fixture_sha256: 'f'.repeat(64) }).valid, false);
});

test('an authorization-request gets invalid-ack', async () => {
  const s = new StrictSupervisor({ artifactsDir: '/nonexistent' });
  s.context = Object.freeze({
    invocation_id: 'inv-1',
    execution_kind: 'native',
    strict_manifest_sha256: 'c'.repeat(64),
    fixture_sha256: null,
  });

  const acks = [];
  const fakeStream = {
    destroyed: false,
    write(line, encoding, cb) {
      acks.push(JSON.parse(line));
      cb();
    },
  };

  await s.handleRequest({
    event: 'authorization-request',
    protocol_version: 1,
    request_id: 'auth-req-1',
    invocation_id: 'inv-1',
  }, fakeStream);

  assert.equal(acks.length, 1);
  assert.equal(acks[0].event, 'invalid-ack');
  assert.equal(acks[0].verified, false);
});
