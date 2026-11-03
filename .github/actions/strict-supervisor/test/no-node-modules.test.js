import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { StrictSupervisor } from '../src/supervisor.js';
import { validateAck } from '../src/ipc.js';

test('supervisor transports a typed receipt with an injected artifact client', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'strict-unit-'));
  try {
    const bytes = Buffer.from('sealed proof data');
    const archivePath = path.join(dir, 'evidence.tar');
    fs.writeFileSync(archivePath, bytes);
    const digest = crypto.createHash('sha256').update(bytes).digest('hex');
    const context = { invocation_id: 'test-inv', execution_kind: 'synthetic', repository: 'jwaldrip/iyi',
      run_id: '123', run_attempt: '1', job_id: '456', job_key: 'validation',
      p_sha: 'a'.repeat(40), w_sha: 'b'.repeat(40), c_sha: 'c'.repeat(40), fixture_sha256: 'd'.repeat(64) };
    const req = { ...context, event: 'persistence-request', protocol_version: 1, request_id: 'request-1',
      snapshot_kind: 'checkpoint', chain_id: 'e'.repeat(32), unit: 'run1', native_attempt: 1,
      snapshot_sequence: 1, archive_path: archivePath, archive_bytes: bytes.length, archive_sha256: digest };
    const client = {
      async uploadArtifact(name, files) {
        assert.match(name, /test-inv/);
        assert.deepEqual(fs.readFileSync(files[0]), bytes);
        return { id: 7777 };
      },
      async downloadArtifact(id, options) {
        assert.equal(id, 7777);
        fs.writeFileSync(path.join(options.path, 'evidence.tar'), bytes);
        return { downloadPath: options.path };
      },
    };
    const supervisor = new StrictSupervisor({ artifactsDir: dir, artifactClient: client });
    supervisor.context = Object.freeze(context);
    supervisor.indexPath = path.join(dir, 'index.json');
    const received = [];
    const ackStream = { destroyed: false, write(line, encoding, done) { received.push(JSON.parse(line)); done(); } };
    await supervisor.handleRequest(req, ackStream);
    assert.equal(received.length, 1);
    assert.equal(validateAck(received[0], req).valid, true);
    assert.equal(received[0].artifact_id, 7777);
    assert.equal(supervisor.failedVerifications, 0);
    assert.equal(JSON.parse(fs.readFileSync(supervisor.indexPath, 'utf8')).entries.length, 1);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
