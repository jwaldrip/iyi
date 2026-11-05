/**
 * Test: Distributable Bundle Execution
 *
 * Verifies that the built distributable bundle (dist/index.js) can execute
 * in an isolated environment without source node_modules.
 */

import test from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const actionRoot = path.resolve(__dirname, '..');
const distPath = path.join(actionRoot, 'dist', 'index.js');

test('Built dist/index.js runs in isolation without node_modules', async () => {
  assert.ok(fs.existsSync(distPath), 'dist/index.js must be built before testing');

  const tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'test-dist-bundle-'));
  try {
    const isolatedDistDir = path.join(tempDir, 'dist');
    // The bundle loads sibling files (sourcemap-register.cjs and chunks), so copy the whole directory.
    await fs.promises.cp(path.join(actionRoot, 'dist'), isolatedDistDir, { recursive: true });
    const isolatedDistFile = path.join(isolatedDistDir, 'index.js');

    // Verify that NO node_modules exists in tempDir
    assert.strictEqual(fs.existsSync(path.join(tempDir, 'node_modules')), false);

    // Module type comes from the copied dist/package.json, not a hand-written root manifest.
    const result = spawnSync(process.execPath, [isolatedDistFile], {
      cwd: tempDir,
      env: { PATH: process.env.PATH },
      encoding: 'utf8',
      timeout: 10000,
    });
    assert.strictEqual(result.error, undefined);
    assert.strictEqual(result.status, 1, `missing inputs must fail: ${result.stdout} ${result.stderr}`);
    assert.match(result.stdout + result.stderr, /Input required and not supplied: p/i);
  } finally {
    await fs.promises.rm(tempDir, { recursive: true, force: true });
  }
});
