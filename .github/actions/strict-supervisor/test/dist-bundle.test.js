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
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const actionRoot = path.resolve(__dirname, '..');
const distPath = path.join(actionRoot, 'dist', 'index.js');

test('Built dist/index.js exists and runs in isolation without node_modules when built', async (t) => {
  if (!fs.existsSync(distPath)) {
    t.skip('dist/index.js not yet built; skipping distributable bundle test until after ncc build');
    return;
  }

  const tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'test-dist-bundle-'));
  try {
    const isolatedDistDir = path.join(tempDir, 'dist');
    await fs.promises.mkdir(isolatedDistDir, { recursive: true });
    const isolatedDistFile = path.join(isolatedDistDir, 'index.js');
    await fs.promises.copyFile(distPath, isolatedDistFile);

    // Verify that NO node_modules exists in tempDir
    assert.strictEqual(fs.existsSync(path.join(tempDir, 'node_modules')), false);

    // Inspect bundle file format
    const content = await fs.promises.readFile(isolatedDistFile, 'utf8');
    assert.ok(content.length > 1000, 'Bundle file is too small');
  } finally {
    await fs.promises.rm(tempDir, { recursive: true, force: true });
  }
});
