import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { StrictSupervisor } from '../src/supervisor.js';

// establishContext reads revisions with `git -C <dir> rev-parse HEAD`, so P and W are
// real repositories and C is the checkout these tests run in. The real method runs in
// every test. Only the GitHub job lookup (fetch) is replaced, and each refusal must
// happen before that lookup is ever made.
function commit(dir) {
  execFileSync('git', ['init', '-q', dir]);
  fs.writeFileSync(path.join(dir, 'README'), 'fixture\n');
  execFileSync('git', ['-C', dir, 'add', '-A']);
  execFileSync('git', ['-C', dir, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
    'commit', '-q', '-m', 'fixture']);
  return execFileSync('git', ['-C', dir, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
}
const P_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'establish-p-'));
const W_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'establish-w-'));
const P_SHA = commit(P_DIR);
const W_SHA = commit(W_DIR);
const C_SHA = execFileSync('git', ['-C', process.cwd(), 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
const STARTED = '2026-11-05T00:00:00Z';
const NEXT = '<https://api.example.test/next>; rel="next"';

function baseEnv() {
  return {
    GITHUB_JOB: 'validation', GITHUB_REPOSITORY: 'jwaldrip/iyi', GITHUB_RUN_ID: '1234',
    GITHUB_RUN_ATTEMPT: '1', RUNNER_NAME: 'runner-1', GITHUB_TOKEN: 'token-1',
    GITHUB_API_URL: 'https://api.example.test',
  };
}
function without(key) {
  const env = baseEnv();
  delete env[key];
  return env;
}
function job(overrides = {}) {
  return { id: 5678, status: 'in_progress', runner_name: 'runner-1', started_at: STARTED, ...overrides };
}
function supervisor({ env = baseEnv(), ...overrides } = {}) {
  return new StrictSupervisor({
    mode: 'strict', invocationId: 'inv-1', jobId: '5678', jobKey: 'validation', jobStartTime: STARTED,
    p: P_DIR, w: W_DIR, pSha: P_SHA, wSha: W_SHA, cSha: C_SHA, graceSec: '30', driverLimitSec: '2100',
    parentEnv: env, ...overrides,
  });
}

// Serves job-lookup pages in order; the last page repeats. Returns every request made.
async function withJobLookup(pages, fn) {
  const original = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url) => {
    calls.push(url);
    const page = pages[Math.min(calls.length - 1, pages.length - 1)];
    if (page.status) return { ok: false, status: page.status, headers: new Map(), json: async () => ({}) };
    return {
      ok: true, status: 200,
      headers: new Map(page.link ? [['link', page.link]] : []),
      json: async () => page.body,
    };
  };
  try {
    return await fn(calls);
  } finally {
    globalThis.fetch = original;
  }
}
const onePage = jobs => [{ body: { jobs } }];

test('positive control: a complete platform identity resolves the frozen context', async () => {
  const context = await withJobLookup(onePage([job()]), () => supervisor().establishContext());
  assert.equal(Object.isFrozen(context), true);
  assert.deepEqual({ ...context }, {
    invocation_id: 'inv-1', execution_kind: 'native', repository: 'jwaldrip/iyi', run_id: '1234',
    run_attempt: '1', job_id: '5678', job_key: 'validation', p_sha: P_SHA, w_sha: W_SHA, c_sha: C_SHA,
    fixture_sha256: null,
  });
});

const REVISION = /actual source revision does not match expected tuple/;
const TIMING = /strict timing changes are not authorized/;
const PLATFORM = /missing platform identity/;
const IDENTITY = /invalid job identity/;
const preLookupRefusals = [
  ['a mode outside strict and validation-only', { mode: 'native' }, /invalid mode/],
  ['an invocation id with unsafe characters', { invocationId: 'bad id!' }, /invalid invocation id/],
  ['a missing invocation id', { invocationId: '' }, /invalid invocation id/],
  ['a non-numeric job id', { jobId: 'job-9' }, IDENTITY],
  ['a job key that is not the platform job', { jobKey: 'other' }, IDENTITY],
  ['a missing GITHUB_TOKEN', { env: without('GITHUB_TOKEN') }, PLATFORM],
  ['a missing RUNNER_NAME', { env: without('RUNNER_NAME') }, PLATFORM],
  ['a non-numeric run id', { env: { ...baseEnv(), GITHUB_RUN_ID: 'run-1' } }, PLATFORM],
  ['a zero run attempt', { env: { ...baseEnv(), GITHUB_RUN_ATTEMPT: '0' } }, PLATFORM],
  ['P drifted from the expected revision', { pSha: '1'.repeat(40) }, REVISION],
  ['W drifted from the expected revision', { wSha: '1'.repeat(40) }, REVISION],
  ['C drifted from the expected revision', { cSha: '1'.repeat(40) }, REVISION],
  ['a changed strict grace period', { graceSec: '31' }, TIMING],
  ['a changed strict driver limit', { driverLimitSec: '2000' }, TIMING],
];
for (const [name, overrides, pattern] of preLookupRefusals) {
  test(`establishContext refuses ${name} before any job lookup`, async () => {
    await withJobLookup(onePage([job()]), async (calls) => {
      await assert.rejects(supervisor(overrides).establishContext(), pattern);
      assert.deepEqual(calls, []);
    });
  });
}

const lookupRefusals = [
  ['no in-progress job matches', onePage([job({ status: 'completed' })]), /job lookup missing or ambiguous/],
  ['the matching job ran on another runner', onePage([job({ runner_name: 'runner-2' })]), /job lookup missing or ambiguous/],
  ['two jobs match', onePage([job(), job()]), /job lookup missing or ambiguous/],
  ['a second match appears on a later page',
    [{ body: { jobs: [job()] }, link: NEXT }, { body: { jobs: [job()] } }], /job lookup missing or ambiguous/],
  ['the lookup returns HTTP 500', [{ status: 500 }], /job lookup failed: HTTP 500/],
  ['the lookup body has no job list', [{ body: {} }], /invalid job lookup/],
  ['the platform start time differs', onePage([job({ started_at: '2026-11-05T00:00:01Z' })]),
    /job start does not match platform/],
  ['the platform start time is absent', onePage([job({ started_at: null })]), /job start does not match platform/],
];
for (const [name, pages, pattern] of lookupRefusals) {
  test(`establishContext refuses when ${name}`, async () => {
    await withJobLookup(pages, async (calls) => {
      await assert.rejects(supervisor().establishContext(), pattern);
      assert.ok(calls.length >= 1, 'the refusal must come from the lookup, so the lookup must run');
    });
  });
}

test('positive control: the single match may sit on a later page and still resolves', async () => {
  const pages = [{ body: { jobs: [job({ id: 1 })] }, link: NEXT }, { body: { jobs: [job()] } }];
  const context = await withJobLookup(pages, () => supervisor().establishContext());
  assert.equal(context.job_id, '5678');
});
