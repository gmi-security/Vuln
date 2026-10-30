import test from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {setImmediate as turn} from 'node:timers/promises';
import {trackPublicationClient, retryPublicationPreparation} from '../lib/db/publication-client.mjs';

function connection() {
  const client = new EventEmitter();
  const released = [], poolErrors = [];
  client.release = error => {
    released.push(error);
    client.on('error', error => poolErrors.push(error));
    if (error) setImmediate(() => client.emit('end'));
  };
  return {client, released, poolErrors};
}
const idleError = () => Object.assign(new Error('idle transaction expired'), {code:'25P03'});

test('disconnect between statements retains the first SQLSTATE and destroys the borrowed connection once', async () => {
  const {client, released} = connection(), owner = trackPublicationClient(client), first = idleError();
  assert.doesNotThrow(() => client.emit('error', first));
  assert.doesNotThrow(() => client.emit('error', new Error('Connection terminated unexpectedly')));
  assert.equal(owner.firstError(), first);
  owner.release(); owner.release();
  assert.deepEqual(released, [first]);
  assert.doesNotThrow(() => client.emit('error', new Error('closing transport')));
  await turn();
  assert.equal(client.listenerCount('error'), 1, 'only the pool owns the closed client');
  assert.equal(client.listenerCount('end'), 0);
});

test('healthy release returns ownership to the pool without retaining publication observers', () => {
  const {client, released, poolErrors} = connection(), owner = trackPublicationClient(client);
  owner.release(); owner.release();
  assert.deepEqual(released, [undefined]);
  assert.equal(client.listenerCount('error'), 1);
  assert.equal(client.listenerCount('end'), 0);
  client.emit('error', new Error('later pool failure'));
  assert.equal(poolErrors.length, 1);
  assert.equal(owner.firstError(), undefined);
});

test('query failure also destroys its connection even without an error event', async () => {
  const {client, released} = connection(), owner = trackPublicationClient(client), error = new Error('write failed');
  owner.release(error);
  assert.deepEqual(released, [error]);
  await turn();
  assert.equal(client.listenerCount('error'), 1);
});

test('private preparation retries the same operation after releasing a failed attempt', async t => {
  t.mock.timers.enable({apis:['setTimeout']});
  const events = []; let attempts = 0;
  const plan = Object.freeze({hash:'unchanged'});
  const pending = retryPublicationPreparation(async () => {
    events.push(['attempt', ++attempts, plan.hash]);
    if (attempts === 1) { events.push(['released']); throw idleError(); }
    return {generation:'resumed', checkpoint:500};
  }, ({delayMs}) => events.push(['retry', delayMs]));
  await turn();
  assert.equal(attempts, 1);
  t.mock.timers.tick(4999); await turn(); assert.equal(attempts, 1);
  t.mock.timers.tick(1);
  assert.deepEqual(await pending, {generation:'resumed', checkpoint:500});
  assert.deepEqual(events, [['attempt',1,'unchanged'],['released'],['retry',5000],['attempt',2,'unchanged']]);
});

test('persistent private interruption defers after bounded backoff instead of spinning or marking success', async t => {
  t.mock.timers.enable({apis:['setTimeout']});
  let attempts = 0; const delays = [];
  const pending = assert.rejects(retryPublicationPreparation(async () => { attempts++; throw idleError(); },
    ({delayMs}) => delays.push(delayMs)), error => error.code === 'platform-publication-deferred' && error.cause.code === '25P03');
  for (const ms of [5000,15000,60000]) { await turn(); t.mock.timers.tick(ms); }
  await pending;
  assert.equal(attempts, 4);
  assert.deepEqual(delays, [5000,15000,60000]);
});

for (const code of ['platform-writer-stale','platform-capture-changed','23514']) {
  test(`${code} stops private preparation without retrying or disguising the error`, async () => {
    let attempts = 0; const error = Object.assign(new Error('unsafe plan'), {code});
    await assert.rejects(retryPublicationPreparation(async () => { attempts++; throw error; }), e => e === error);
    assert.equal(attempts, 1);
  });
}
