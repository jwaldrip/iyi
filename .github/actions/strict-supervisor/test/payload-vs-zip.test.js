/**
 * Test: Verified Payload vs ZIP Metadata
 *
 * Verifies that artifact verification computes and validates the inner archive
 * (tar) payload bytes and SHA-256, and NEVER confuses it with the outer ZIP
 * container size or digest returned by GitHub Actions / Azure Blob storage.
 */

import test from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { uploadAndVerifyPayload } from '../src/artifact-adapter.js';

test('Payload verification hashes extracted inner tar, ignoring outer ZIP metadata', async () => {
  const tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'test-payload-zip-'));

  try {
    // 1. Create a dummy inner tar archive
    const innerTarContent = Buffer.from('TEST_TAR_CONTENT_FOR_STRICT_PROOFS_INNER_BYTES_12345');
    const innerTarPath = path.join(tempDir, 'proof-unit.tar');
    fs.writeFileSync(innerTarPath, innerTarContent);

    const innerBytes = innerTarContent.length;
    const innerSha256 = crypto.createHash('sha256').update(innerTarContent).digest('hex');

    // 2. Define outer ZIP metadata that intentionally differs from inner tar
    const outerZipBytes = innerBytes + 512; // Outer zip headers & framing
    const outerZipSha256 = crypto.createHash('sha256').update(Buffer.from('OUTER_ZIP_HEADER_DATA')).digest('hex');

    const req = {
      request_id: 'req-test-zip-1',
      repository: 'jwaldrip/iyi',
      run_id: '100',
      run_attempt: '1',
      job_id: 'job-1',
      p_sha: '626463375298d357ffcb3223059f4d3adce6fb10',
      w_sha: 'b932ce0d97775c7061102a13db706f507dc84117',
      c_sha: '34ae13f8f8d82be5b2c9597a9df79eae5b6f7243',
      chain_id: 'chain-test',
      unit: 'test_unit',
      native_attempt: 1,
      snapshot_sequence: 1,
      archive_path: innerTarPath,
      archive_bytes: innerBytes,
      archive_sha256: innerSha256,
    };

    // 3. Mock ArtifactClient simulating GitHub Actions backend
    const mockClient = {
      uploadArtifact: async (name, files, rootDir) => {
        assert.strictEqual(name.includes('test_unit'), true);
        assert.deepStrictEqual(files, [innerTarPath]);
        // Backend returns outer ZIP size and digest
        return {
          id: 4242,
          size: outerZipBytes,
          digest: outerZipSha256,
        };
      },
      downloadArtifact: async (id, options) => {
        assert.strictEqual(id, 4242);
        // SDK download extracts inner tar into download target directory
        const extractedPath = path.join(options.path, 'proof-unit.tar');
        fs.writeFileSync(extractedPath, innerTarContent);
        return {
          downloadPath: options.path,
        };
      },
    };

    const receipt = await uploadAndVerifyPayload(req, mockClient);

    // Assert that the receipt verified using the INNER tar payload, not outer ZIP metadata
    assert.strictEqual(receipt.verified, true);
    assert.strictEqual(receipt.artifact_id, 4242);
    assert.strictEqual(receipt.downloaded_bytes, innerBytes);
    assert.strictEqual(receipt.downloaded_sha256, innerSha256);
    assert.notStrictEqual(receipt.downloaded_bytes, outerZipBytes);
    assert.notStrictEqual(receipt.downloaded_sha256, outerZipSha256);
  } finally {
    await fs.promises.rm(tempDir, { recursive: true, force: true });
  }
});

test('Payload verification rejects corrupted downloaded inner payload', async () => {
  const tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'test-payload-corrupt-'));

  try {
    const innerTarContent = Buffer.from('ORIGINAL_UNALTERED_TAR_CONTENT');
    const innerTarPath = path.join(tempDir, 'corrupt-test.tar');
    fs.writeFileSync(innerTarPath, innerTarContent);

    const innerBytes = innerTarContent.length;
    const innerSha256 = crypto.createHash('sha256').update(innerTarContent).digest('hex');

    const req = {
      request_id: 'req-corrupt-1',
      repository: 'jwaldrip/iyi',
      run_id: '100',
      run_attempt: '1',
      job_id: 'job-1',
      p_sha: '626463375298d357ffcb3223059f4d3adce6fb10',
      w_sha: 'b932ce0d97775c7061102a13db706f507dc84117',
      c_sha: '34ae13f8f8d82be5b2c9597a9df79eae5b6f7243',
      chain_id: 'chain-test',
      unit: 'corrupt_unit',
      native_attempt: 1,
      snapshot_sequence: 1,
      archive_path: innerTarPath,
      archive_bytes: innerBytes,
      archive_sha256: innerSha256,
    };

    // Client downloads corrupted inner bytes
    const mockClient = {
      uploadArtifact: async () => ({ id: 9999, size: 5000, digest: 'some-zip-hash' }),
      downloadArtifact: async (id, options) => {
        const extractedPath = path.join(options.path, 'corrupt-test.tar');
        fs.writeFileSync(extractedPath, Buffer.from('ALTERED_TAMPERED_TAR_CONTENT'));
        return { downloadPath: options.path };
      },
    };

    const receipt = await uploadAndVerifyPayload(req, mockClient);

    assert.strictEqual(receipt.verified, false);
    assert.match(receipt.error, /Payload equality check failed/);
  } finally {
    await fs.promises.rm(tempDir, { recursive: true, force: true });
  }
});
