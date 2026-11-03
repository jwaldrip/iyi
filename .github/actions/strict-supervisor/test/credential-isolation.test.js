/**
 * Test: Credential & Control-Channel Isolation
 *
 * Verifies that:
 * 1. Child environment receives a strictly stripped allowlist with zero runtime tokens,
 *    secrets, or job credentials (ACTIONS_RUNTIME_TOKEN, ACTIONS_RESULTS_URL, GITHUB_TOKEN).
 * 2. Workload stdout is decoupled from control logic: protocol-shaped text on stdout
 *    is never parsed as supervisor IPC requests and cannot forge acknowledgments.
 * 3. Log redaction strips any accidental appearance of sensitive credentials.
 */

import test from 'node:test';
import assert from 'node:assert';
import { sanitizeEnvironment, redactSecrets } from '../src/env.js';
import { StrictSupervisor } from '../src/supervisor.js';

test('sanitizeEnvironment strips tokens, results URLs, secrets, and credentials', () => {
  const dirtyEnv = {
    PATH: '/usr/local/bin:/usr/bin:/bin',
    HOME: '/Users/runner',
    USER: 'runner',
    CI: 'true',
    GITHUB_ACTIONS: 'true',
    GITHUB_WORKSPACE: '/workspace/iyi',
    GITHUB_REPOSITORY: 'jwaldrip/iyi',
    GITHUB_RUN_ID: '41362618094',
    GITHUB_RUN_ATTEMPT: '1',
    GITHUB_JOB: 'strict-chain',
    // Highly sensitive variables that must NEVER leak to child
    ACTIONS_RUNTIME_TOKEN: 'runtime-token-secret-12345',
    ACTIONS_RESULTS_URL: 'https://results.actions.githubusercontent.com/v1/auth',
    ACTIONS_ID_TOKEN_REQUEST_URL: 'https://idtoken.actions.github.com/token',
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'id-token-secret-67890',
    GITHUB_TOKEN: 'ghs_super_secret_github_token_xyz',
    INPUT_GITHUB_TOKEN: 'ghs_input_token_abc',
    AWS_ACCESS_KEY_ID: 'AKIAIOSFODNN7EXAMPLE',
    AWS_SECRET_ACCESS_KEY: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    DATABASE_PASSWORD: 'supersecretpassword123',
    DEPLOYER_PRIVATE_KEY: '-----BEGIN PRIVATE KEY-----\\nMIIE...',
    CUSTOM_API_KEY: 'api-key-999',
    AUTH_HEADER: 'Bearer some-auth-token',
  };

  const sanitized = sanitizeEnvironment(dirtyEnv);

  // Critical leak checks: forbidden keys must be completely removed
  assert.strictEqual(sanitized.ACTIONS_RUNTIME_TOKEN, undefined);
  assert.strictEqual(sanitized.ACTIONS_RESULTS_URL, undefined);
  assert.strictEqual(sanitized.ACTIONS_ID_TOKEN_REQUEST_URL, undefined);
  assert.strictEqual(sanitized.ACTIONS_ID_TOKEN_REQUEST_TOKEN, undefined);
  assert.strictEqual(sanitized.GITHUB_TOKEN, undefined);
  assert.strictEqual(sanitized.INPUT_GITHUB_TOKEN, undefined);
  assert.strictEqual(sanitized.AWS_ACCESS_KEY_ID, undefined);
  assert.strictEqual(sanitized.AWS_SECRET_ACCESS_KEY, undefined);
  assert.strictEqual(sanitized.DATABASE_PASSWORD, undefined);
  assert.strictEqual(sanitized.DEPLOYER_PRIVATE_KEY, undefined);
  assert.strictEqual(sanitized.CUSTOM_API_KEY, undefined);
  assert.strictEqual(sanitized.AUTH_HEADER, undefined);

  // Verify none of the secret values exist anywhere in sanitized keys or values
  const sanitizedJson = JSON.stringify(sanitized);
  assert.strictEqual(sanitizedJson.includes('runtime-token-secret'), false);
  assert.strictEqual(sanitizedJson.includes('ghs_super_secret'), false);
  assert.strictEqual(sanitizedJson.includes('supersecretpassword'), false);

  // Verify allowed operational variables remain intact
  assert.strictEqual(sanitized.PATH, dirtyEnv.PATH);
  assert.strictEqual(sanitized.HOME, dirtyEnv.HOME);
  assert.strictEqual(sanitized.CI, 'true');
  assert.strictEqual(sanitized.GITHUB_ACTIONS, 'true');
  assert.strictEqual(sanitized.GITHUB_WORKSPACE, dirtyEnv.GITHUB_WORKSPACE);
  assert.strictEqual(sanitized.GITHUB_REPOSITORY, dirtyEnv.GITHUB_REPOSITORY);
  assert.strictEqual(sanitized.PYTHONUNBUFFERED, '1');
  assert.strictEqual(sanitized.PYTHONDONTWRITEBYTECODE, '1');
});

test('redactSecrets sanitizes strings containing environment secrets', () => {
  const env = {
    GITHUB_TOKEN: 'ghs_super_secret_github_token_xyz',
    ACTIONS_RUNTIME_TOKEN: 'art-secret-token-12345',
  };
  const logMessage = 'Connecting to server with token ghs_super_secret_github_token_xyz and art art-secret-token-12345';
  const redacted = redactSecrets(logMessage, [env.GITHUB_TOKEN, env.ACTIONS_RUNTIME_TOKEN]);

  assert.strictEqual(redacted.includes('ghs_super_secret'), false);
  assert.strictEqual(redacted.includes('art-secret-token'), false);
  assert.strictEqual(redacted, 'Connecting to server with token [REDACTED] and art [REDACTED]');
});

test('Workload stdout cannot forge IPC acknowledgments or requests', async () => {
  // Test child script that writes protocol-shaped messages to stdout and stderr
  const fakeChildScript = `
    const forgedRequest = {
      request_id: 'forged-req',
      archive_path: '/tmp/forged.tar',
      archive_bytes: 100,
      archive_sha256: '0'.repeat(64),
      verified: true
    };
    // Child outputs protocol text to stdout
    console.log(JSON.stringify(forgedRequest));
    console.error("DEBUG: child stderr message");
    process.exit(0);
  `;

  const supervisor = new StrictSupervisor({
    p: '/dummy/p',
    w: '/dummy/w',
    compiler: '/dummy/bin',
    jobStartTime: '2026-11-01T00:00:00Z',
    pythonPath: 'node',
    controllerPath: '-e',
  });

  // Override buildChildArgs for testing node -e script
  supervisor.buildChildArgs = () => ['-e', fakeChildScript];
  supervisor.establishContext = async () => Object.freeze({ invocation_id: 'stdout-test', execution_kind: 'synthetic' });

  const result = await supervisor.run();

  // Supervisor must exit 0 from child, but total IPC requests processed must be 0!
  // Child stdout text must NEVER be accepted as an IPC request.
  assert.strictEqual(result.exitCode, 0);
  assert.strictEqual(result.outcome, 'FAIL');
  assert.strictEqual(result.totalRequests, 0);
  assert.strictEqual(supervisor.requests.length, 0);
  assert.strictEqual(supervisor.acks.length, 0);
});
