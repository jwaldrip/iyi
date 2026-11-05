/**
 * Artifact Persistence & Readback Verification Adapter
 *
 * Implements exact-ID upload and readback verification using @actions/artifact 6.3.1.
 * Critical invariant: Verifies downloaded INNER archive (tar) payload bytes and SHA256,
 * NOT outer ZIP metadata, before emitting a positive ACK.
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import os from 'node:os';

/**
 * Compute SHA256 of a local file
 */
export function computeFileSha256(filePath) {
  const hash = crypto.createHash('sha256');
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  const fd = fs.openSync(filePath, 'r');
  try {
    for (;;) {
      const count = fs.readSync(fd, buffer, 0, buffer.length, null);
      if (!count) break;
      hash.update(buffer.subarray(0, count));
    }
    return hash.digest('hex');
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Format a safe GitHub Actions artifact name from request fields
 */
export function formatArtifactName(req) {
  const safeChain = req.chain_id === null ? 'prepin' : String(req.chain_id).slice(0, 16).replace(/[^a-zA-Z0-9_-]/g, '_');
  const safeUnit = String(req.unit).replace(/[^a-zA-Z0-9_-]/g, '_');
  return `proof-${req.invocation_id}-${safeChain}-${safeUnit}-seq${req.snapshot_sequence}-att${req.native_attempt}`;
}

/**
 * Find matching file recursively in directory
 */
function findFileInDir(dir, targetName) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      const nested = findFileInDir(fullPath, targetName);
      if (nested) return nested;
    } else if (entry.isFile() && entry.name === targetName) {
      return fullPath;
    }
  }
  return null;
}

/**
 * Why a persistence receipt does not prove the sealed payload, or null when it does.
 * A failed receipt keeps the adapter's own error, which names the step that failed.
 */
export function receiptFailure(receipt, req) {
  if (!receipt.verified) return receipt.error || 'artifact readback not verified';
  if (!receipt.artifact_id || receipt.downloaded_sha256 !== req.archive_sha256 || receipt.downloaded_bytes !== req.archive_bytes) return 'artifact readback mismatch';
  return null;
}

/**
 * Download by exact artifact ID. The service can answer "No artifacts found" for a
 * finalized artifact for a short time, so only that error is retried, on the same ID.
 * Any other error, or a still-missing artifact after the last attempt, fails at once.
 */
export async function downloadWhenVisible(artifactClient, artifactId, dir, {
  attempts = 12,
  delayMs = 5000,
  sleep = ms => new Promise(resolve => setTimeout(resolve, ms)),
} = {}) {
  for (let attempt = 1; ; attempt++) {
    try {
      return await artifactClient.downloadArtifact(artifactId, { path: dir });
    } catch (err) {
      if (attempt >= attempts || !/No artifacts found for ID/.test(String(err?.message))) throw err;
      await sleep(delayMs);
    }
  }
}

/**
 * Execute upload, exact-ID readback, and payload equality check
 */
export async function uploadAndVerifyPayload(req, artifactClient) {
  // 1. Verify local sealed archive exists and matches request metadata BEFORE upload
  if (!fs.existsSync(req.archive_path)) {
    return {
      verified: false,
      error: `Local archive file does not exist: ${req.archive_path}`,
      artifact_id: null,
      downloaded_sha256: null,
      downloaded_bytes: null,
    };
  }

  const localStat = fs.statSync(req.archive_path);
  if (localStat.size !== req.archive_bytes) {
    return {
      verified: false,
      error: `Local archive byte count mismatch before upload: stat=${localStat.size}, expected=${req.archive_bytes}`,
      artifact_id: null,
      downloaded_sha256: null,
      downloaded_bytes: null,
    };
  }

  const localSha256 = computeFileSha256(req.archive_path);
  if (localSha256.toLowerCase() !== req.archive_sha256.toLowerCase()) {
    return {
      verified: false,
      error: `Local archive SHA256 mismatch before upload: computed=${localSha256}, expected=${req.archive_sha256}`,
      artifact_id: null,
      downloaded_sha256: null,
      downloaded_bytes: null,
    };
  }

  // 2. Upload artifact via SDK
  const artifactName = formatArtifactName(req);
  const files = [req.archive_path];
  const rootDir = path.dirname(req.archive_path);

  let uploadResponse;
  try {
    uploadResponse = await artifactClient.uploadArtifact(artifactName, files, rootDir, {
      retentionDays: 14,
    });
  } catch (err) {
    return {
      verified: false,
      error: `artifactClient.uploadArtifact failed: ${err.message}`,
      artifact_id: null,
      downloaded_sha256: null,
      downloaded_bytes: null,
    };
  }

  if (!uploadResponse || uploadResponse.id === undefined || uploadResponse.id === null) {
    return {
      verified: false,
      error: `uploadArtifact did not return an artifact id for ${artifactName}`,
      artifact_id: null,
      downloaded_sha256: null,
      downloaded_bytes: null,
    };
  }

  const artifactId = uploadResponse.id;

  // 3. Download by exact ID into fresh, isolated directory while job is running
  const downloadDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'strict-dl-'));
  try {
    const downloadResponse = await downloadWhenVisible(artifactClient, artifactId, downloadDir);

    const targetDir = downloadResponse?.downloadPath || downloadDir;
    const expectedFileName = path.basename(req.archive_path);
    const downloadedFilePath = findFileInDir(targetDir, expectedFileName);

    if (!downloadedFilePath) {
      return {
        verified: false,
        error: `Downloaded payload file '${expectedFileName}' not found in download target: ${targetDir}`,
        artifact_id: artifactId,
        downloaded_sha256: null,
        downloaded_bytes: null,
      };
    }

    // 4. Compute inner payload archive bytes and SHA-256 (NOT outer ZIP metadata)
    const dlStat = fs.statSync(downloadedFilePath);
    const downloaded_bytes = dlStat.size;
    const downloaded_sha256 = computeFileSha256(downloadedFilePath);

    // 5. Verify byte and hash equality against sealed request specification
    const bytesMatch = downloaded_bytes === req.archive_bytes;
    const shaMatch = downloaded_sha256.toLowerCase() === req.archive_sha256.toLowerCase();

    if (!bytesMatch || !shaMatch) {
      return {
        verified: false,
        error: `Payload equality check failed for artifact ${artifactId}: ` +
          `bytes=${downloaded_bytes} (expected ${req.archive_bytes}), ` +
          `sha256=${downloaded_sha256} (expected ${req.archive_sha256})`,
        artifact_id: artifactId,
        downloaded_sha256,
        downloaded_bytes,
      };
    }

    return {
      verified: true,
      error: null,
      artifact_id: artifactId,
      downloaded_sha256,
      downloaded_bytes,
    };
  } catch (err) {
    return {
      verified: false,
      error: `downloadArtifact failed for id=${artifactId}: ${err.message}`,
      artifact_id: artifactId,
      downloaded_sha256: null,
      downloaded_bytes: null,
    };
  } finally {
    // 6. Clean up temporary readback directory
    try {
      await fs.promises.rm(downloadDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup error of temp dir
    }
  }
}
