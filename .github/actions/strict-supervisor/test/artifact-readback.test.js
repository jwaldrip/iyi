import test from 'node:test';
import assert from 'node:assert/strict';
import { receiptFailure } from '../src/artifact-adapter.js';

const req = { archive_sha256: 'a'.repeat(64), archive_bytes: 10 };
const good = { verified: true, error: null, artifact_id: 7, downloaded_sha256: 'a'.repeat(64), downloaded_bytes: 10 };

test('a verified receipt matching the sealed payload has no failure', () => {
  assert.equal(receiptFailure(good, req), null);
});

// Negative control: before this change the publisher replaced every unverified
// receipt with the generic mismatch text, so this assertion fails on that code.
test('a failed receipt keeps the adapter error instead of a generic mismatch', () => {
  const failed = { ...good, verified: false, error: 'downloadArtifact failed for id=7: 503 Service Unavailable' };
  assert.equal(receiptFailure(failed, req), 'downloadArtifact failed for id=7: 503 Service Unavailable');
});

test('a failed receipt without an error still fails closed', () => {
  assert.equal(receiptFailure({ ...good, verified: false, error: null }, req), 'artifact readback not verified');
});

test('a verified receipt that does not match the sealed payload is a mismatch', () => {
  assert.equal(receiptFailure({ ...good, downloaded_sha256: 'b'.repeat(64) }, req), 'artifact readback mismatch');
  assert.equal(receiptFailure({ ...good, downloaded_bytes: 11 }, req), 'artifact readback mismatch');
  assert.equal(receiptFailure({ ...good, artifact_id: null }, req), 'artifact readback mismatch');
});
