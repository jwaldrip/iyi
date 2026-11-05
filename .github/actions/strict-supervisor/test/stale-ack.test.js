import test from 'node:test';
import assert from 'node:assert/strict';
import { validateAck, validateRequest, IMMUTABLE_BINDING_FIELDS } from '../src/ipc.js';
import { StrictSupervisor } from '../src/supervisor.js';

const request = {
  event: 'persistence-request', protocol_version: 1, request_id: 'request-1',
  invocation_id: 'inv-1', execution_kind: 'synthetic', fixture_sha256: 'f'.repeat(64),
  repository: 'jwaldrip/iyi', run_id: '1234', run_attempt: '1', job_id: '5678', job_key: 'validation',
  p_sha: '626463375298d357ffcb3223059f4d3adce6fb10',
  w_sha: 'b932ce0d97775c7061102a13db706f507dc84117',
  c_sha: '428b93c072bda138dd629645bf308e18861161cb',
  snapshot_kind: 'checkpoint', chain_id: 'a'.repeat(32), unit: 'run3_acme', native_attempt: 1,
  snapshot_sequence: 2, archive_path: '/nonexistent/archive.tar', archive_bytes: 4096,
  archive_sha256: 'b'.repeat(64),
};
const binding = Object.fromEntries(IMMUTABLE_BINDING_FIELDS.map(k => [k, request[k]]));
const ack = { ...binding, event: 'persistence-ack', verified: true, artifact_id: 123,
  downloaded_bytes: request.archive_bytes, downloaded_sha256: request.archive_sha256 };

test('valid request and complete typed receipt match', () => {
  assert.equal(validateRequest(request).valid, true);
  assert.equal(validateAck(ack, request).valid, true);
});

test('every receipt binding and the receipt type are checked', () => {
  for (const field of IMMUTABLE_BINDING_FIELDS) {
    const altered = { ...ack, [field]: typeof ack[field] === 'number' ? ack[field] + 1 : 'incorrect' };
    assert.equal(validateAck(altered, request).valid, false, field);
    const missing = { ...ack }; delete missing[field];
    assert.equal(validateAck(missing, request).valid, false, field);
  }
  for (const altered of [
    { event: 'other' }, { verified: false }, { artifact_id: null },
    { downloaded_bytes: 4095 }, { downloaded_sha256: 'c'.repeat(64) },
  ]) assert.equal(validateAck({ ...ack, ...altered }, request).valid, false);
});

test('plan and prechain failures alone allow typed null chain identity', () => {
  for (const [snapshot_kind, unit] of [['plan', 'plan'], ['prechain-failure', 'pin']]) {
    const req = { ...request, snapshot_kind, unit, chain_id: null };
    assert.equal(validateRequest(req).valid, true);
    const response = { ...ack, snapshot_kind, unit, chain_id: null };
    assert.equal(validateAck(response, req).valid, true);
    for (const invalid of ['', 'null', 'nochain', 'a'.repeat(32)]) {
      assert.equal(validateRequest({ ...req, chain_id: invalid }).valid, false);
      assert.equal(validateAck({ ...response, chain_id: invalid }, req).valid, false);
    }
  }
  for (const invalid of [null, '', 'null', 'nochain', 'x'.repeat(32), 'a'.repeat(31)]) {
    assert.equal(validateRequest({ ...request, chain_id: invalid }).valid, false);
  }
  assert.equal(validateRequest({ ...request, snapshot_kind: 'prechain-failure', unit: 'run1', chain_id: null }).valid, false);
});

test('request shape rejects invalid context, types, hashes, and archive metadata', () => {
  for (const change of [
    { event: 'other' }, { protocol_version: 2 }, { unit: '' }, { execution_kind: 'unknown' },
    { run_id: 1234 }, { job_id: 'job-name' }, { job_key: '' }, { invocation_id: '' },
    { fixture_sha256: null }, { p_sha: 'bad' }, { native_attempt: 0 }, { snapshot_sequence: 0 },
    { archive_path: '' }, { archive_bytes: -1 }, { archive_sha256: 'bad' },
  ]) assert.equal(validateRequest({ ...request, ...change }).valid, false, JSON.stringify(change));
});

function fakeSupervisor() {
  const s = new StrictSupervisor({ artifactsDir: '/nonexistent/owned-root' });
  s.context = Object.freeze(Object.fromEntries(['invocation_id', 'execution_kind', 'repository', 'run_id', 'run_attempt', 'job_id', 'job_key', 'p_sha', 'w_sha', 'c_sha', 'fixture_sha256'].map(k => [k, request[k]])));
  return s;
}
function sink() {
  const received = [];
  return { received, stream: { destroyed: false, write(line, encoding, cb) { received.push(JSON.parse(line)); cb(); } } };
}

test('wrong immutable context is rejected before upload', async () => {
  const supervisor = fakeSupervisor(), out = sink();
  let called = false;
  supervisor.resolveArtifactClient = async () => { called = true; throw new Error('unexpected upload'); };
  await supervisor.handleRequest({ ...request, job_id: '9999' }, out.stream);
  assert.equal(out.received[0].verified, false);
  assert.match(out.received[0].error, /context mismatch: job_id/);
  assert.equal(called, false);
});

// Each entry is the minimal change to the request. Every change must remain schema-valid on its own.
// native requests carry no emitter digest (ipc.js: native requires fixture_sha256 === null), so the
// execution_kind change carries that required companion. The lone flip is refused by the schema below.
const ALTERED_CONTEXT = [
  ['invocation_id', { invocation_id: 'inv-other' }],
  ['execution_kind', { execution_kind: 'native', fixture_sha256: null }],
  ['repository', { repository: 'jwaldrip/other' }],
  ['run_id', { run_id: '1235' }],
  ['run_attempt', { run_attempt: '2' }],
  ['job_id', { job_id: '9999' }],
  ['job_key', { job_key: 'other-job' }],
  ['p_sha', { p_sha: 'c'.repeat(40) }],
  ['w_sha', { w_sha: 'd'.repeat(40) }],
  ['c_sha', { c_sha: 'e'.repeat(40) }],
  ['fixture_sha256', { fixture_sha256: '1'.repeat(64) }],
];
test('a lone execution_kind flip is refused by the schema because a native request carries no digest', () => {
  assert.deepEqual(validateRequest({ ...request, execution_kind: 'native' }), { valid: false, error: 'Invalid fixture digest' });
  assert.deepEqual(validateRequest({ ...request, execution_kind: 'native', fixture_sha256: null }), { valid: true });
});
test('each immutable context field is checked on its own, and the clean tuple passes the context check', async () => {
  for (const [field, change] of ALTERED_CONTEXT) {
    const altered = { ...request, ...change };
    assert.equal(validateRequest(altered).valid, true, `${field} alteration must stay schema-valid`);
    const supervisor = fakeSupervisor(), out = sink();
    let uploads = 0;
    supervisor.resolveArtifactClient = async () => { uploads++; throw new Error('unexpected upload'); };
    await supervisor.handleRequest(altered, out.stream);
    assert.equal(out.received[0].verified, false, field);
    // invocation_id is compared before the context loop, so it refuses as an invalid request.
    if (field === 'invocation_id') assert.match(out.received[0].error, /^invalid or replayed request$/, field);
    else assert.equal(out.received[0].error, `context mismatch: ${field}`, field);
    assert.equal(uploads, 0, field);
  }
  const supervisor = fakeSupervisor(), out = sink();
  await supervisor.handleRequest(request, out.stream);
  assert.doesNotMatch(out.received[0].error, /context mismatch|invalid or replayed/);
});

test('missing archive fails, request replay and nonincreasing sequences are rejected', async () => {
  const supervisor = fakeSupervisor(), out = sink();
  await supervisor.handleRequest(request, out.stream);
  assert.equal(out.received[0].verified, false);
  await supervisor.handleRequest({ ...request, snapshot_sequence: 3 }, out.stream);
  assert.equal(out.received[1].verified, false);
  assert.match(out.received[1].error, /replay/);
  await supervisor.handleRequest({ ...request, request_id: 'new-1', snapshot_sequence: 1 }, out.stream);
  assert.equal(out.received[2].verified, false);
  assert.match(out.received[2].error, /non-increasing/);
  await supervisor.handleRequest({ ...request, request_id: 'new-2', snapshot_sequence: 2 }, out.stream);
  assert.equal(out.received[3].verified, false);
  assert.match(out.received[3].error, /non-increasing/);
});
