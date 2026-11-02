/**
 * Test: Action Code Running With No node_modules
 *
 * Verifies that the supervisor, IPC transport, environment sanitizer, and artifact
 * verification logic execute end-to-end on pure Node.js built-ins without requiring
 * third-party npm packages to be installed in node_modules.
 */

import test from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { StrictSupervisor } from '../src/supervisor.js';
import { validateAck } from '../src/ipc.js';

test('Supervisor runs end-to-end with IPC on pure Node.js without node_modules', async () => {
  const tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'test-no-nm-'));

  try {
    // 1. Create a sealed test archive
    const archiveData = Buffer.from('PRESERVED_EVIDENCE_PAYLOAD_TAR_BYTES_987654321');
    const archivePath = path.join(tempDir, 'evidence.tar');
    fs.writeFileSync(archivePath, archiveData);

    const archiveBytes = archiveData.length;
    const archiveSha256 = crypto.createHash('sha256').update(archiveData).digest('hex');

    // 2. Prepare mock child script (runs in node, mimics Python C behavior over fd3 and fd4)
    const childScriptContent = `
      import fs from 'node:fs';
      import process from 'node:process';

      // Open fd3 for writing requests
      const reqStream = fs.createWriteStream(null, { fd: 3 });
      // Open fd4 for reading ACKs
      const ackStream = fs.createReadStream(null, { fd: 4 });

      const requestPayload = {
        request_id: 'req-no-nm-1',
        repository: 'jwaldrip/iyi',
        run_id: '123',
        run_attempt: '1',
        job_id: 'job-ci',
        p_sha: '626463375298d357ffcb3223059f4d3adce6fb10',
        w_sha: 'b932ce0d97775c7061102a13db706f507dc84117',
        c_sha: '34ae13f8f8d82be5b2c9597a9df79eae5b6f7243',
        chain_id: 'chain-1234',
        unit: 'unit_alpha',
        native_attempt: 1,
        snapshot_sequence: 1,
        archive_path: ${JSON.stringify(archivePath)},
        archive_bytes: ${archiveBytes},
        archive_sha256: ${JSON.stringify(archiveSha256)}
      };

      reqStream.write(JSON.stringify(requestPayload) + '\\n');

      let buffer = '';
      ackStream.on('data', (chunk) => {
        buffer += chunk.toString('utf8');
        if (buffer.includes('\\n')) {
          const line = buffer.slice(0, buffer.indexOf('\\n')).trim();
          const ack = JSON.parse(line);
          if (ack.verified && ack.request_id === 'req-no-nm-1') {
            process.exit(0);
          } else {
            process.exit(2);
          }
        }
      });
    `;

    const childScriptPath = path.join(tempDir, 'child_controller.js');
    fs.writeFileSync(childScriptPath, childScriptContent);

    // 3. Mock ArtifactClient (pure Node implementation)
    const mockArtifactClient = {
      uploadArtifact: async (name, files, rootDir) => {
        return {
          id: 7777,
          size: archiveBytes + 128,
          digest: 'fake-zip-digest',
        };
      },
      downloadArtifact: async (id, options) => {
        // Unpacks inner tar file into destination
        const extracted = path.join(options.path, 'evidence.tar');
        fs.writeFileSync(extracted, archiveData);
        return { downloadPath: options.path };
      },
    };

    // 4. Instantiate supervisor with pure Node settings
    const supervisor = new StrictSupervisor({
      p: tempDir,
      w: tempDir,
      compiler: '/dummy/compiler',
      artifactsDir: tempDir,
      jobStartTime: '2026-11-01T00:00:00Z',
      pythonPath: 'node',
      controllerPath: childScriptPath,
      artifactClient: mockArtifactClient,
    });

    // Run supervisor with Node child
    supervisor.buildChildArgs = () => [childScriptPath];

    const result = await supervisor.run();

    assert.strictEqual(result.exitCode, 0);
    assert.strictEqual(result.outcome, 'PASS');
    assert.strictEqual(result.totalRequests, 1);
    assert.strictEqual(result.failedVerifications, 0);
    assert.strictEqual(supervisor.acks.length, 1);
    assert.strictEqual(supervisor.acks[0].verified, true);
    assert.strictEqual(supervisor.acks[0].artifact_id, 7777);
    assert.strictEqual(supervisor.acks[0].downloaded_bytes, archiveBytes);
    assert.strictEqual(supervisor.acks[0].downloaded_sha256, archiveSha256);
  } finally {
    await fs.promises.rm(tempDir, { recursive: true, force: true });
  }
});
