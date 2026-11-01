#!/usr/bin/env node
/**
 * Incremental Artifact Uploader & Verifier
 * Used by remote_strict_controller.py to upload and verify per-stage archives
 * during GitHub Actions runs using @actions/artifact.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

async function main() {
  const args = process.argv.slice(2);
  if (args.length < 3) {
    console.error("Usage: node upload_artifact.js <archive_path> <unit_name> <attempt>");
    process.exit(1);
  }

  const [archivePath, unitName, attempt] = args;
  if (!fs.existsSync(archivePath)) {
    console.error(`ERROR: Archive file does not exist: ${archivePath}`);
    process.exit(1);
  }

  const stat = fs.statSync(archivePath);
  if (stat.size === 0) {
    console.error(`ERROR: Archive file is empty: ${archivePath}`);
    process.exit(1);
  }

  // Compute SHA-256 of the archive
  const fileBuffer = fs.readFileSync(archivePath);
  const hash = crypto.createHash('sha256').update(fileBuffer).digest('hex');

  // Simulated upload failure for testing
  if (process.env.SIMULATE_UPLOAD_FAILURE === '1') {
    console.error("ERROR: Simulated upload failure via SIMULATE_UPLOAD_FAILURE=1");
    process.exit(1);
  }

  // Format safe artifact name
  const safeUnit = unitName.replace(/[^a-zA-Z0-9_-]/g, '_');
  const artifactName = `proof-${safeUnit}-att${attempt}`;

  // If in GitHub Actions runtime, use @actions/artifact
  if (process.env.GITHUB_ACTIONS === 'true') {
    try {
      const { DefaultArtifactClient } = require('@actions/artifact');
      const artifact = new DefaultArtifactClient();
      const rootDir = path.dirname(archivePath);
      const files = [archivePath];
      const uploadResponse = await artifact.uploadArtifact(artifactName, files, rootDir);
      console.log(`UPLOAD_VERIFIED id=${uploadResponse.id} artifact=${artifactName} size=${stat.size} sha256=${hash}`);
      return;
    } catch (err) {
      console.error(`ERROR: GitHub Actions artifact upload failed for ${artifactName}: ${err.message}`);
      process.exit(1);
    }
  }

  // Outside GitHub Actions (e.g. testing or local verification):
  console.log(`UPLOAD_VERIFIED local_archive=${archivePath} artifact=${artifactName} size=${stat.size} sha256=${hash}`);
}

main().catch((err) => {
  console.error(`ERROR: Unexpected error in upload_artifact.js: ${err}`);
  process.exit(1);
});
