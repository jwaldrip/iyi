import test from 'node:test';
import assert from 'node:assert/strict';
import { downloadWhenVisible } from '../src/artifact-adapter.js';

const notYet = () => new Error('No artifacts found for ID: 9');
const noSleep = async () => {};

// Each entry is either a successful download result or an Error to throw.
function fakeClient(outcomes) {
  const calls = [];
  return {
    calls,
    downloadArtifact: async (id, options) => {
      calls.push({ id, path: options.path });
      const next = outcomes.shift();
      if (next instanceof Error) throw next;
      return next;
    },
  };
}

test('a finalized artifact that is not yet visible is read on the same ID once it appears', async () => {
  const client = fakeClient([notYet(), notYet(), { downloadPath: '/d' }]);
  assert.deepEqual(await downloadWhenVisible(client, 9, '/d', { sleep: noSleep }), { downloadPath: '/d' });
  assert.equal(client.calls.length, 3);
  assert.ok(client.calls.every(call => call.id === 9 && call.path === '/d'));
});

// Negative control: the previous code made exactly one download call, so this
// retry test fails on that code.
test('any other download error is not retried', async () => {
  const client = fakeClient([new Error('ECONNRESET')]);
  await assert.rejects(downloadWhenVisible(client, 9, '/d', { sleep: noSleep }), /ECONNRESET/);
  assert.equal(client.calls.length, 1);
});

test('an artifact still missing after the last attempt fails with the service error', async () => {
  const client = fakeClient([notYet(), notYet(), notYet()]);
  await assert.rejects(downloadWhenVisible(client, 9, '/d', { attempts: 3, sleep: noSleep }), /No artifacts found for ID: 9/);
  assert.equal(client.calls.length, 3);
});

test('retries wait the configured delay between attempts', async () => {
  const waits = [];
  const client = fakeClient([notYet(), { downloadPath: '/d' }]);
  await downloadWhenVisible(client, 9, '/d', { delayMs: 250, sleep: async ms => { waits.push(ms); } });
  assert.deepEqual(waits, [250]);
});
